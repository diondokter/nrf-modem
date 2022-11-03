#![no_std]

use crate::error::ErrorSource;
use core::cell::RefCell;
use cortex_m::interrupt::Mutex;
use linked_list_allocator::Heap;

mod at;
mod at_notifications;
mod cancellation;
mod dns;
mod dtls_socket;
mod error;
pub mod ffi;
mod gnss;
pub(crate) mod ip;
mod lte_link;
pub(crate) mod socket;
mod tcp_stream;
mod udp_socket;
pub(crate) mod waker_node_list;

pub use no_std_net;
pub use nrfxlib_sys;

pub use at::*;
pub use at_notifications::AtNotificationStream;
pub use cancellation::CancellationToken;
pub use dns::*;
pub use dtls_socket::*;
pub use error::Error;
pub use gnss::*;
pub use lte_link::LteLink;
pub use tcp_stream::*;
pub use udp_socket::*;

/// We need to wrap our heap so it's creatable at run-time and accessible from an ISR.
///
/// * The Mutex allows us to safely share the heap between interrupt routines
///   and the main thread - and nrfxlib will definitely use the heap in an
///   interrupt.
/// * The RefCell lets us share and object and mutate it (but not at the same
///   time)
/// * The Option is because the `linked_list_allocator::empty()` function is not
///   `const` yet and cannot be called here
///
type WrappedHeap = Mutex<RefCell<Option<Heap>>>;

//******************************************************************************
// Constants
//******************************************************************************

// None

//******************************************************************************
// Global Variables
//******************************************************************************

/// Our general heap.
///
/// We initialise it later with a static variable as the backing store.
static LIBRARY_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

/// Our transmit heap.

/// We initalise this later using a special region of shared memory that can be
/// seen by the Cortex-M33 and the modem CPU.
static TX_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

//******************************************************************************
// Macros
//******************************************************************************

// None

//******************************************************************************
// Public Functions and Impl on Public Types
//******************************************************************************

/// Start the NRF Modem library
pub async fn init(mode: SystemMode) -> Result<(), Error> {
    // The modem is only certified when the DC/DC converter is enabled and it isn't by default
    unsafe {
        (*nrf9160_pac::REGULATORS_NS::PTR)
            .dcdcen
            .modify(|_, w| w.dcdcen().enabled());
    }

    unsafe {
        /// Allocate some space in global data to use as a heap.
        static mut HEAP_MEMORY: [u32; 1024] = [0u32; 1024];
        let heap_start = HEAP_MEMORY.as_ptr() as *mut u8;
        let heap_size = HEAP_MEMORY.len() * core::mem::size_of::<u32>();
        cortex_m::interrupt::free(|cs| {
            *LIBRARY_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(heap_start, heap_size))
        });
    }

    // Tell nrf_modem what memory it can use.
    let params = nrfxlib_sys::nrf_modem_init_params {
        shmem: nrfxlib_sys::nrf_modem_shmem_cfg {
            ctrl: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_1 {
                // At start of shared memory (see memory.x)
                base: 0x2001_0000,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_04e8,
            },
            tx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_2 {
                // Follows on from control buffer
                base: 0x2001_04e8,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_2000,
            },
            rx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_3 {
                // Follows on from TX buffer
                base: 0x2001_24e8,
                // This is the amount specified in the NCS 1.5.1 release.
                size: 0x0000_2000,
            },
            // No trace info
            trace: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_4 { base: 0, size: 0 },
        },
        ipc_irq_prio: 0,
        fault_handler: Some(modem_fault_handler),
    };

    unsafe {
        // Use the same TX memory region as above
        cortex_m::interrupt::free(|cs| {
            *TX_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(
                params.shmem.tx.base as usize as *mut u8,
                params.shmem.tx.size as usize,
            ))
        });
    }

    // OK, let's start the library
    unsafe { nrfxlib_sys::nrf_modem_init(&params, nrfxlib_sys::nrf_modem_mode_NORMAL_MODE) }
        .into_result()?;

    // Initialize AT notifications
    at_notifications::initialize()?;

    // Turn off the modem
    let (modem_state,) =
        at_commands::parser::CommandParser::parse(at::send_at::<32>("AT+CFUN?").await?.as_bytes())
            .expect_identifier(b"+CFUN: ")
            .expect_int_parameter()
            .expect_identifier(b"\r\nOK\r\n")
            .finish()?;

    if modem_state != 0 {
        // The modem is still turned on (probably from a previous run). Let's turn it off
        at::send_at::<0>("AT+CFUN=0").await?;
    }

    if !mode.is_valid_config() {
        return Err(Error::InvalidSystemModeConfig);
    }

    let mut buffer = [0; 64];
    mode.create_at_command(&mut buffer)?;
    at::send_at_bytes::<0>(&buffer).await?;

    mode.setup_psm().await?;

    Ok(())
}

unsafe extern "C" fn modem_fault_handler(_info: *mut nrfxlib_sys::nrf_modem_fault_info) {
    #[cfg(feature = "defmt")]
    defmt::error!(
        "Modem fault - reason: {}, pc: {}",
        (*_info).reason,
        (*_info).program_counter
    );
}

/// You must call this when an EGU1 interrupt occurs.
pub fn application_irq_handler() {
    unsafe {
        nrfxlib_sys::nrf_modem_application_irq_handler();
        nrfxlib_sys::nrf_modem_os_event_notify();
        // Wake up all the waiting sockets
        critical_section::with(|cs| {
            crate::socket::WAKER_NODE_LIST
                .borrow_ref_mut(cs)
                .wake_all_and_reset(|_| {})
        });
    }
}

/// IPC code now lives outside `lib_modem`, so call our IPC handler function.
pub fn ipc_irq_handler() {
    unsafe {
        crate::ffi::nrf_ipc_irq_handler();
        nrfxlib_sys::nrf_modem_os_event_notify();
    }
}

/// Identifies which radios in the nRF9160 should be active
///
/// Based on: <https://infocenter.nordicsemi.com/index.jsp?topic=%2Fref_at_commands%2FREF%2Fat_commands%2Fmob_termination_ctrl_status%2Fcfun.html>
#[derive(Debug, Copy, Clone)]
pub struct SystemMode {
    pub lte_support: bool,
    pub lte_psm_support: bool,
    pub nbiot_support: bool,
    pub gnss_support: bool,
    pub preference: ConnectionPreference,
}

#[derive(Debug, Copy, Clone)]
pub enum ConnectionPreference {
    /// No preference. Initial system selection is based on history data and Universal Subscriber Identity Module (USIM)
    None = 0,
    /// LTE-M preferred
    Lte = 1,
    /// NB-IoT preferred
    Nbiot = 2,
    /// Network selection priorities override system priority, but if the same network or equal priority networks are found, LTE-M is preferred
    NetworkPreferenceWithLteFallback = 3,
    /// Network selection priorities override system priority, but if the same network or equal priority networks are found, NB-IoT is preferred
    NetworkPreferenceWithNbiotFallback = 4,
}

impl SystemMode {
    fn is_valid_config(&self) -> bool {
        if self.lte_psm_support && !self.lte_support {
            return false;
        }
        match self.preference {
            ConnectionPreference::None => true,
            ConnectionPreference::Lte => self.lte_support,
            ConnectionPreference::Nbiot => self.nbiot_support,
            ConnectionPreference::NetworkPreferenceWithLteFallback => {
                self.lte_support && self.nbiot_support
            }
            ConnectionPreference::NetworkPreferenceWithNbiotFallback => {
                self.lte_support && self.nbiot_support
            }
        }
    }

    fn create_at_command<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], Error> {
        at_commands::builder::CommandBuilder::create_set(buffer, true)
            .named("%XSYSTEMMODE")
            .with_int_parameter(self.lte_support as u8)
            .with_int_parameter(self.nbiot_support as u8)
            .with_int_parameter(self.gnss_support as u8)
            .with_int_parameter(self.preference as u8)
            .finish()
            .map_err(|e| Error::BufferTooSmall(Some(e)))
    }

    async fn setup_psm(&self) -> Result<(), Error> {
        if self.lte_support {
            if self.lte_psm_support {
                // Set Power Saving Mode (PSM)
                at::send_at::<0>("AT+CPSMS=1").await?;
            } else {
                // Turn off PSM
                at::send_at::<0>("AT+CPSMS=0").await?;
            }
        }
        Ok(())
    }
}

/// Enable GNSS on the nRF9160-DK (PCA10090NS)
///
/// Sends a AT%XMAGPIO command which activates the off-chip GNSS RF routing
/// switch when receiving signals between 1574 MHz and 1577 MHz.
///
/// Works on the nRF9160-DK (PCA10090NS) and Actinius Icarus. Other PCBs may
/// use different MAGPIO pins to control the GNSS switch.
pub async fn configure_gnss_on_pca10090ns() -> Result<(), Error> {
    #[cfg(feature = "defmt")]
    defmt::debug!("Configuring XMAGPIO pins for 1574-1577 MHz");

    // Configure the GNSS antenna. See `nrf/samples/nrf9160/gps/src/main.c`.
    crate::at::send_at::<0>("AT%XMAGPIO=1,0,0,1,1,1574,1577").await?;
    Ok(())
}
