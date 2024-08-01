#![no_std]
#![doc = include_str!("../README.md")]
// #![warn(missing_docs)]

use crate::error::ErrorSource;
use core::{
    cell::RefCell,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};
use critical_section::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
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
mod sms;
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
pub use sms::*;
pub use tcp_stream::*;
pub use udp_socket::*;

#[cfg(feature = "nrf9160")]
use nrf9160_pac as pac;

#[cfg(feature = "nrf9120")]
use nrf9120_pac as pac;

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

/// Our general heap.
///
/// We initialise it later with a static variable as the backing store.
static LIBRARY_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

/// Our transmit heap.

/// We initalise this later using a special region of shared memory that can be
/// seen by the Cortex-M33 and the modem CPU.
static TX_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

pub(crate) static MODEM_RUNTIME_STATE: RuntimeState = RuntimeState::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Start the NRF Modem library
pub async fn init(mode: SystemMode) -> Result<(), Error> {
    init_with_custom_layout(mode, Default::default()).await
}

/// Start the NRF Modem library with a manually specified memory layout
pub async fn init_with_custom_layout(
    mode: SystemMode,
    memory_layout: MemoryLayout,
) -> Result<(), Error> {
    if INITIALIZED.fetch_or(true, Ordering::SeqCst) {
        return Err(Error::ModemAlreadyInitialized);
    }

    const SHARED_MEMORY_RANGE: Range<u32> = 0x2000_0000..0x2002_0000;

    if !SHARED_MEMORY_RANGE.contains(&memory_layout.base_address) {
        return Err(Error::BadMemoryLayout);
    }
    
    if !SHARED_MEMORY_RANGE.contains(
        &(memory_layout.base_address
                + nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE
                + memory_layout.tx_area_size
                + memory_layout.rx_area_size
                + memory_layout.trace_area_size
                // Minus one, because this check should be inclusive
                - 1),
    ) {
        return Err(Error::BadMemoryLayout);
    }

    // The modem is only certified when the DC/DC converter is enabled and it isn't by default
    unsafe {
        (*pac::REGULATORS_NS::PTR)
            .dcdcen
            .modify(|_, w| w.dcdcen().enabled());
    }

    unsafe {
        /// Allocate some space in global data to use as a heap.
        static mut HEAP_MEMORY: [u32; 1024] = [0u32; 1024];
        let heap_start = HEAP_MEMORY.as_ptr() as *mut u8;
        let heap_size = HEAP_MEMORY.len() * core::mem::size_of::<u32>();
        critical_section::with(|cs| {
            *LIBRARY_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(heap_start, heap_size))
        });
    }

    // Tell nrf_modem what memory it can use.
    static PARAMS: grounded::uninit::GroundedCell<nrfxlib_sys::nrf_modem_init_params> =
        grounded::uninit::GroundedCell::uninit();

    let params = nrfxlib_sys::nrf_modem_init_params {
        shmem: nrfxlib_sys::nrf_modem_shmem_cfg {
            ctrl: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_1 {
                base: memory_layout.base_address,
                size: nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE,
            },
            tx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_2 {
                base: memory_layout.base_address + nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE,
                size: memory_layout.tx_area_size,
            },
            rx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_3 {
                base: memory_layout.base_address
                    + nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE
                    + memory_layout.tx_area_size,
                size: memory_layout.rx_area_size,
            },
            trace: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_4 {
                base: memory_layout.base_address
                    + nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE
                    + memory_layout.tx_area_size
                    + memory_layout.rx_area_size,
                size: memory_layout.trace_area_size,
            },
        },
        ipc_irq_prio: 1,
        fault_handler: Some(modem_fault_handler),
        dfu_handler: Some(modem_dfu_handler),
    };

    critical_section::with(|_| unsafe { PARAMS.get().write(params) });

    unsafe {
        // Use the same TX memory region as above
        critical_section::with(|cs| {
            *TX_ALLOCATOR.borrow(cs).borrow_mut() = Some(Heap::new(
                params.shmem.tx.base as usize as *mut u8,
                params.shmem.tx.size as usize,
            ))
        });
    }

    // OK, let's start the library
    unsafe { nrfxlib_sys::nrf_modem_init(PARAMS.get()) }.into_result()?;

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

/// The memory layout used by the modem library.
///
/// The full range needs to be in the lower 128k of ram.
/// This also contains the fixed [nrfxlib_sys::NRF_MODEM_SHMEM_CTRL_SIZE].
///
/// Nordic guide: https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.4.1/nrfxlib/nrf_modem/doc/architecture.html#shared-memory-configuration
pub struct MemoryLayout {
    /// The start of the memory area
    pub base_address: u32,
    /// The buffer size of the socket send operations, as well as sent AT commands and TLS certs
    pub tx_area_size: u32,
    /// The buffer size of the socket receive operations, as well as received AT commands, gnss messages and TLS certs
    pub rx_area_size: u32,
    /// The buffer size of the trace logs
    pub trace_area_size: u32,
}

impl Default for MemoryLayout {
    fn default() -> Self {
        Self {
            base_address: 0x2001_0000,
            tx_area_size: 0x2000,
            rx_area_size: 0x2000,
            // Trace is not implemented yet
            trace_area_size: 0,
        }
    }
}

unsafe extern "C" fn modem_fault_handler(_info: *mut nrfxlib_sys::nrf_modem_fault_info) {
    #[cfg(feature = "defmt")]
    defmt::error!(
        "Modem fault - reason: {}, pc: {}",
        (*_info).reason,
        (*_info).program_counter
    );
}

unsafe extern "C" fn modem_dfu_handler(_val: u32) {
    #[cfg(feature = "defmt")]
    defmt::trace!("Modem DFU handler");
}

/// IPC code now lives outside `lib_modem`, so call our IPC handler function.
pub fn ipc_irq_handler() {
    unsafe {
        crate::ffi::nrf_ipc_irq_handler();
    }
    cortex_m::asm::sev();
}

/// Identifies which radios in the nRF91* SiP should be active
///
/// Based on: <https://infocenter.nordicsemi.com/index.jsp?topic=%2Fref_at_commands%2FREF%2Fat_commands%2Fmob_termination_ctrl_status%2Fcfun.html>
#[derive(Debug, Copy, Clone)]
pub struct SystemMode {
    /// Enables the modem to connect to the LTE network
    pub lte_support: bool,
    /// Enables the PowerSavingMode. You want this enabled unless your sim/network doesn't support it
    pub lte_psm_support: bool,
    /// Enables the modem to connect to the NBiot network
    pub nbiot_support: bool,
    /// Enables the modem to receive gnss signals
    pub gnss_support: bool,
    /// Sets up the preference the modem will have for connecting to the mobile network
    pub preference: ConnectionPreference,
}

/// The preference the modem will have for connecting to the mobile network
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
#[cfg(feature = "nrf9160")]
pub async fn configure_gnss_on_pca10090ns() -> Result<(), Error> {
    #[cfg(feature = "defmt")]
    defmt::debug!("Configuring XMAGPIO pins for 1574-1577 MHz");

    // Configure the GNSS antenna. See `nrf/samples/nrf9160/gps/src/main.c`.
    crate::at::send_at::<0>("AT%XMAGPIO=1,0,0,1,1,1574,1577").await?;
    Ok(())
}

struct RuntimeState {
    state: embassy_sync::mutex::Mutex<CriticalSectionRawMutex, (bool, u16)>,
    error: AtomicBool,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            state: embassy_sync::mutex::Mutex::new((false, 0)),
            error: AtomicBool::new(false),
        }
    }

    pub(crate) async fn activate_gps(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.0 {
            return Err(Error::GnssAlreadyTaken);
        }

        ModemActivation::Gnss.act_on_modem().await?;

        state.0 = true;

        Ok(())
    }

    pub(crate) async fn deactivate_gps(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if !state.0 {
            panic!("Can't deactivate an inactive gps");
        }

        if state.1 == 0 {
            ModemDeactivation::Everything.act_on_modem().await?;
        } else {
            ModemDeactivation::OnlyGnss.act_on_modem().await?;
        }

        state.0 = false;

        Ok(())
    }

    pub(crate) fn deactivate_gps_blocking(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| Error::InternalRuntimeMutexLocked)?;

        if !state.0 {
            panic!("Can't deactivate an inactive gps");
        }

        if state.1 == 0 {
            ModemDeactivation::Everything.act_on_modem_blocking()?;
        } else {
            ModemDeactivation::OnlyGnss.act_on_modem_blocking()?;
        }

        state.0 = false;

        Ok(())
    }

    pub(crate) async fn activate_lte(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.1 == u16::MAX {
            return Err(Error::TooManyLteLinks);
        }

        if state.1 == 0 {
            ModemActivation::Lte.act_on_modem().await?;
        }

        state.1 += 1;

        Ok(())
    }

    pub(crate) async fn deactivate_lte(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.1 == 0 {
            panic!("Can't deactivate an inactive lte");
        }

        if state.1 == 1 {
            if state.0 {
                ModemDeactivation::OnlyLte
            } else {
                ModemDeactivation::Everything
            }
        } else {
            ModemDeactivation::Nothing
        }
        .act_on_modem()
        .await?;

        state.1 -= 1;

        Ok(())
    }

    pub(crate) fn deactivate_lte_blocking(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| Error::InternalRuntimeMutexLocked)?;

        if state.1 == 0 {
            panic!("Can't deactivate an inactive lte");
        }

        if state.1 == 1 {
            if state.0 {
                ModemDeactivation::OnlyLte
            } else {
                ModemDeactivation::Everything
            }
        } else {
            ModemDeactivation::Nothing
        }
        .act_on_modem_blocking()?;

        state.1 -= 1;

        Ok(())
    }

    pub(crate) fn set_error_active(&self) {
        self.error.store(true, Ordering::SeqCst);
    }

    pub(crate) fn get_error_active(&self) -> bool {
        self.error.load(Ordering::SeqCst)
    }

    pub(crate) async unsafe fn reset_runtime_state(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if self
            .error
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            ModemDeactivation::Everything.act_on_modem().await?;
            state.0 = false;
            state.1 = 0;
        }

        self.error.store(false, Ordering::SeqCst);

        Ok(())
    }
}

/// Returns true when the runtime has detected that its state may not represent the actual modem state.
/// This means that the modem may remain active while the runtime thinks it has turned it off.
///
/// This can be fixed using [reset_runtime_state]
pub fn has_runtime_state_error() -> bool {
    MODEM_RUNTIME_STATE.get_error_active()
}

/// Resets the runtime state by forcing the modem to be turned off and resetting the state back to 0.
///
/// ## Safety
///
/// This function may only be used when you've made sure that **no** active LteLinks instances and Gnss instances exist
pub async unsafe fn reset_runtime_state() -> Result<(), Error> {
    MODEM_RUNTIME_STATE.reset_runtime_state().await
}

enum ModemDeactivation {
    OnlyGnss,
    OnlyLte,
    Nothing,
    Everything,
}

impl ModemDeactivation {
    async fn act_on_modem(&self) -> Result<(), Error> {
        match self {
            ModemDeactivation::OnlyGnss => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling modem GNSS");

                at::send_at::<0>("AT+CFUN=30").await?;
            }
            ModemDeactivation::OnlyLte => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling modem LTE");

                // Turn off the network side of the modem
                at::send_at::<0>("AT+CFUN=20").await?;
                // Turn off the UICC
                at::send_at::<0>("AT+CFUN=40").await?;
            }
            ModemDeactivation::Nothing => {}
            ModemDeactivation::Everything => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling full modem");

                at::send_at::<0>("AT+CFUN=0").await?;
            }
        }

        Ok(())
    }

    fn act_on_modem_blocking(&self) -> Result<(), Error> {
        match self {
            ModemDeactivation::OnlyGnss => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling modem GNSS");

                at::send_at_blocking::<0>("AT+CFUN=30")?;
            }
            ModemDeactivation::OnlyLte => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling modem LTE");

                // Turn off the network side of the modem
                at::send_at_blocking::<0>("AT+CFUN=20")?;
                // Turn off the UICC
                at::send_at_blocking::<0>("AT+CFUN=40")?;
            }
            ModemDeactivation::Nothing => {}
            ModemDeactivation::Everything => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling full modem");

                at::send_at_blocking::<0>("AT+CFUN=0")?;
            }
        }

        Ok(())
    }
}

enum ModemActivation {
    Lte,
    Gnss,
}

impl ModemActivation {
    async fn act_on_modem(&self) -> Result<(), Error> {
        match self {
            ModemActivation::Gnss => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Enabling modem GNSS");

                at::send_at::<0>("AT+CFUN=31").await?;
            }
            ModemActivation::Lte => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Enabling modem LTE");

                // Set Ultra low power mode
                at::send_at::<0>("AT%XDATAPRFL=0").await?;
                // Set UICC low power mode
                at::send_at::<0>("AT+CEPPI=1").await?;
                // Activate LTE without changing GNSS
                at::send_at::<0>("AT+CFUN=21").await?;
            }
        }

        Ok(())
    }
}
