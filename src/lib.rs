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
#[cfg(feature = "embassy-net")]
pub mod embassy_net_modem;
pub(crate) mod embedded_io_macros;
#[cfg(feature = "embedded-nal-async")]
mod embedded_nal_async;
mod error;
pub mod ffi;
mod gnss;
pub(crate) mod ip;
mod lte_link;
mod sms;
/// Contains the core socket types and related functionality.
pub mod socket;
mod tcp_stream;
mod tls_stream;
mod udp_socket;
mod uicc_link;
pub(crate) mod waker_node_list;

pub use nrfxlib_sys;

pub use at::*;
pub use at_notifications::AtNotificationStream;
pub use cancellation::CancellationToken;
pub use dns::*;
pub use dtls_socket::*;
#[cfg(feature = "embedded-nal-async")]
pub use embedded_nal_async::*;
pub use error::Error;
pub use gnss::*;
pub use lte_link::LteLink;
pub use sms::*;
pub use socket::CipherSuite;
pub use socket::PeerVerification;
pub use tcp_stream::*;
pub use tls_stream::*;
pub use udp_socket::*;
pub use uicc_link::UiccLink;

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
///
/// We initalise this later using a special region of shared memory that can be
/// seen by the Cortex-M33 and the modem CPU.
static TX_ALLOCATOR: WrappedHeap = Mutex::new(RefCell::new(None));

pub(crate) static MODEM_RUNTIME_STATE: RuntimeState = RuntimeState::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Start the NRF Modem library
///
/// With the os_irq feature enabled, you need to specify the OS scheduled IRQ number.
/// The modem's IPC interrupt should be higher than the os irq. (IPC should pre-empt the executor)
pub async fn init(mode: SystemMode, #[cfg(feature = "os-irq")] os_irq: u8) -> Result<(), Error> {
    init_with_custom_layout(
        mode,
        Default::default(),
        #[cfg(feature = "os-irq")]
        os_irq,
    )
    .await
}

/// Common initialization code between [`init_with_custom_layout`] and
/// [`init_dect_with_custom_layout`]
async fn init_with_custom_layout_core(
    memory_layout: MemoryLayout,
    #[cfg(feature = "os-irq")] os_irq: u8,
) -> Result<(), Error> {
    if INITIALIZED.fetch_or(true, Ordering::SeqCst) {
        return Err(Error::ModemAlreadyInitialized);
    }

    #[cfg(feature = "os-irq")]
    ffi::OS_IRQ.store(os_irq, Ordering::Relaxed);

    const SHARED_MEMORY_RANGE: Range<u32> = 0x2000_0000..0x2002_0000;
    const CTRL_SIZE: u32 = if cfg!(feature = "dect") {
        nrfxlib_sys::NRF_MODEM_DECT_PHY_SHMEM_CTRL_SIZE
    } else {
        nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE
    };

    if !SHARED_MEMORY_RANGE.contains(&memory_layout.base_address) {
        return Err(Error::BadMemoryLayout);
    }

    if !SHARED_MEMORY_RANGE.contains(
        &(memory_layout.base_address
                + CTRL_SIZE
                + memory_layout.tx_area_size
                + memory_layout.rx_area_size
                + memory_layout.trace_area_size
                // Minus one, because this check should be inclusive
                - 1),
    ) {
        return Err(Error::BadMemoryLayout);
    }

    #[cfg(feature = "modem-trace")]
    if memory_layout.trace_area_size == 0 {
        return Err(Error::BadMemoryLayout);
    }

    // The modem is only certified when the DC/DC converter is enabled and it isn't by default
    unsafe {
        (*pac::REGULATORS_NS::PTR)
            .dcdcen
            .modify(|_, w| w.dcdcen().enabled());
    }

    unsafe {
        const HEAP_SIZE: usize = 1024;
        /// Allocate some space in global data to use as a heap.
        static mut HEAP_MEMORY: [u32; HEAP_SIZE] = [0u32; HEAP_SIZE];
        let heap_start = &raw mut HEAP_MEMORY;
        let heap_size = HEAP_SIZE * core::mem::size_of::<u32>();
        critical_section::with(|cs| {
            *LIBRARY_ALLOCATOR.borrow(cs).borrow_mut() =
                Some(Heap::new(heap_start.cast::<u8>(), heap_size))
        });
    }

    // Tell nrf_modem what memory it can use.
    static PARAMS: grounded::uninit::GroundedCell<nrfxlib_sys::nrf_modem_init_params> =
        grounded::uninit::GroundedCell::uninit();

    let params = nrfxlib_sys::nrf_modem_init_params {
        shmem: nrfxlib_sys::nrf_modem_shmem_cfg {
            ctrl: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_1 {
                base: memory_layout.base_address,
                size: CTRL_SIZE,
            },
            tx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_2 {
                base: memory_layout.base_address + CTRL_SIZE,
                size: memory_layout.tx_area_size,
            },
            rx: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_3 {
                base: memory_layout.base_address + CTRL_SIZE + memory_layout.tx_area_size,
                size: memory_layout.rx_area_size,
            },
            trace: nrfxlib_sys::nrf_modem_shmem_cfg__bindgen_ty_4 {
                base: memory_layout.base_address
                    + CTRL_SIZE
                    + memory_layout.tx_area_size
                    + memory_layout.rx_area_size,
                size: memory_layout.trace_area_size,
            },
        },
        ipc_irq_prio: 0,
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

    Ok(())
}

/// Start the NRF Modem library with a manually specified memory layout
///
/// With the os_irq feature enabled, you need to specify the OS scheduled IRQ number.
/// The modem's IPC interrupt should be higher than the os irq. (IPC should pre-empt the executor)
pub async fn init_with_custom_layout(
    mode: SystemMode,
    memory_layout: MemoryLayout,
    #[cfg(feature = "os-irq")] os_irq: u8,
) -> Result<(), Error> {
    init_with_custom_layout_core(
        memory_layout,
        #[cfg(feature = "os-irq")]
        os_irq,
    )
    .await?;

    // Start tracing
    #[cfg(feature = "modem-trace")]
    at::send_at::<0>("AT%XMODEMTRACE=1,2").await?;

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
    let command = mode.create_at_command(&mut buffer)?;
    at::send_at_bytes::<0>(command).await?;

    mode.setup_psm().await?;

    Ok(())
}

// FIXME: Probably length 1 suffices. And do we need the CS mutext? (actually I think all we do is
// single-threaded, but then we may need to create the static differently)
static DECT_EVENTS: embassy_sync::channel::Channel<CriticalSectionRawMutex, DectEventOuter, 4> =
    embassy_sync::channel::Channel::new();

// FIXME here and in DectEvent: I'd much rather just copy the few bytes around rather than
// repacking and copying; but that's optimization, and right now I want to get things to run.
//
// The whole API is internal anyway.
#[derive(Debug)]
struct DectEventOuter {
    time: u64,
    event: DectEvent,
}

#[derive(Debug)]
enum DectEvent {
    // Not relaying any fields we don't use yet; in particular, an init error would be instant
    // panic.
    Init,
    Activate,
    Configure,
    TimeGet,
    Completed,
}

extern "C" fn dect_event(arg: *const nrfxlib_sys::nrf_modem_dect_phy_event) {
    // SAFETY: Used only in this function
    let arg = unsafe { &*arg };
    defmt::trace!("Handler called: id {}, time {}", arg.id, arg.time);
    let event = match arg.id {
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_INIT => {
            // SAFETY: Checked the discriminator
            let init = unsafe { &arg.__bindgen_anon_1.init };
            defmt::trace!(
                "Init event: err {:#x} ({}), temp {}°C, voltage {}mV, temperature_limit {}°C",
                // FIXME: Best guess is that they internally use packed enums and we don't
                init.err,
                match init.err {
                    nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS => "success",
                    nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_ERR_NOT_ALLOWED =>
                        "not allowed",
                    nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_ERR_TEMP_HIGH =>
                        "temp high",
                    nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_ERR_PROD_LOCK =>
                        "prod lock",
                    _ => "unknown",
                },
                init.temp,
                init.voltage,
                init.temperature_limit
            );
            assert_eq!(
                init.err,
                nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS
            );
            DectEvent::Init
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_CONFIGURE => {
            // SAFETY: Checked the discriminator
            let activate = unsafe { &arg.__bindgen_anon_1.activate };
            assert_eq!(
                activate.err,
                nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS
            );
            DectEvent::Configure
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_ACTIVATE => {
            // SAFETY: Checked the discriminator
            let activate = unsafe { &arg.__bindgen_anon_1.activate };
            assert_eq!(
                activate.err,
                nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS
            );
            DectEvent::Activate
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_RSSI => {
            // SAFETY: Checked the discriminator
            let rssi = unsafe { &arg.__bindgen_anon_1.rssi };
            let meas = unsafe { core::slice::from_raw_parts(rssi.meas, rssi.meas_len as _) };
            defmt::info!(
                "RSSI handle {} start {} carrier {}; meas:",
                rssi.handle,
                rssi.meas_start_time,
                rssi.carrier,
            );
            defmt::info!("{:02x}", meas);
            // Doesn't go onto the queue, at least not *that* one where someone is waiting for
            // Completed.
            return;
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_COMPLETED => {
            // SAFETY: Checked the discriminator
            let op = unsafe { &arg.__bindgen_anon_1.op_complete };
            defmt::trace!(
                "Op completed: handle {} err {} temp {} voltage {}",
                op.handle,
                op.err,
                op.temp,
                op.voltage
            );
            // Go into different queue?
            DectEvent::Completed
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_TIME => {
            // SAFETY: Checked the discriminator
            let time_get = unsafe { &arg.__bindgen_anon_1.time_get };
            assert_eq!(
                time_get.err,
                nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS,
                "Never saw this fail"
            );
            DectEvent::TimeGet
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PCC => {
            let pcc = unsafe { &arg.__bindgen_anon_1.pcc };
            // SAFETY: It's from IPC so it's not poison; we can later decide whether to look at the
            // first 5 byte or later 10 byte, and do our own bitfield access.
            let header = unsafe { &pcc.hdr.type_2 };
            defmt::warn!("PCC start {} handle {} phy_type {} rssi2 {} snr {} transaction {} hdr st {} hdr {:02x}",
                pcc.stf_start_time,
                pcc.handle,
                pcc.phy_type,
                pcc.rssi_2,
                pcc.snr,
                pcc.transaction_id,
                pcc.header_status,
                header
                );
            return;
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PCC_ERROR => {
            defmt::warn!("PCC error, what do?");
            return;
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PDC => {
            let pcd = unsafe { &arg.__bindgen_anon_1.pdc };
            defmt::warn!("PDC handle {} trns {} data {:02x}",
                pcd.handle,
                pcd.transaction_id,
                unsafe { core::slice::from_raw_parts(pcd.data as *const u8, pcd.len) },
                );
            return;
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PDC_ERROR => {
            defmt::warn!("PDC error, what do?");
            return;
        }
        _ => {
            defmt::warn!("Event had no known handler");
            return;
        }
    };
    DECT_EVENTS
        .try_send(DectEventOuter {
            event,
            time: arg.time,
        })
        .ok()
        .expect("Queue is managed")
}

/// Start the NRF Modem library with a manually specified memory layout
///
/// With the os_irq feature enabled, you need to specify the OS scheduled IRQ number.
/// The modem's IPC interrupt should be higher than the os irq. (IPC should pre-empt the executor)
pub async fn init_dect_with_custom_layout(
    memory_layout: MemoryLayout,
    #[cfg(feature = "os-irq")] os_irq: u8,
) -> Result<DectInitialized, Error> {
    init_with_custom_layout_core(
        memory_layout,
        #[cfg(feature = "os-irq")]
        os_irq,
    )
    .await?;

    defmt::info!("Setting DECT handler");

    unsafe { nrfxlib_sys::nrf_modem_dect_phy_event_handler_set(Some(dect_event)) }.into_result()?;

    defmt::info!("Initializing DECT PHY");

    unsafe { nrfxlib_sys::nrf_modem_dect_phy_init() }.into_result()?;

    defmt::info!("Initialized.");

    let DectEventOuter {
        event: DectEvent::Init { .. },
        ..
    } = DECT_EVENTS.receive().await
    else {
        panic!("Sequence violation: Event before Init event");
    };

    // FIXME take parameters
    let params = nrfxlib_sys::nrf_modem_dect_phy_config_params {
        band_group_index: 0,
        harq_rx_process_count: 4,
        harq_rx_expiry_time_us: 1000000,
    };
    unsafe { nrfxlib_sys::nrf_modem_dect_phy_configure(&params) }.into_result()?;
    let DectEventOuter {
        event: DectEvent::Configure,
        ..
    } = DECT_EVENTS.receive().await
    else {
        panic!("Sequence violation");
    };

    // FIXME power hog? delay to runtime?
    let mode = nrfxlib_sys::nrf_modem_dect_phy_radio_mode_NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY;
    unsafe { nrfxlib_sys::nrf_modem_dect_phy_activate(mode) }.into_result()?;
    let DectEventOuter {
        event: DectEvent::Activate,
        ..
    } = DECT_EVENTS.receive().await
    else {
        panic!("Sequence violation");
    };

    Ok(DectInitialized(core::marker::PhantomData))
}

// FIXME: Is this Send? Better make it not so for the moment
//
// and store that we're in an operation so we can cancel if someone cancels a future
pub struct DectInitialized(core::marker::PhantomData<*const ()>);

impl DectInitialized {
    pub async fn time_get(&mut self) -> Result<u64, Error> {
        unsafe { nrfxlib_sys::nrf_modem_dect_phy_time_get() }.into_result()?;

        let DectEventOuter {
            event: DectEvent::TimeGet,
            time,
        } = DECT_EVENTS.receive().await
        else {
            panic!("Sequence violation");
        };

        Ok(time)
    }

    pub async fn rssi(&mut self, carrier: u16) -> Result<(), Error> {
        // Relevant DECT constant timing parameters are 1 frame = 10ms, each 10ms frame is composed
        // of 24 slots,

        // - Reporting interval is every 12 or 24 slots. This is consistent with the delta of
        //   starting times being precisely 691200 (24 slots = 10ms, on a 69.120MHz clock), or
        //   345600 (12 slots = 5ms).
        //
        // - Depending on the reporting interval there are 240 or 120 values, so single reading
        //   takes 2880 clock ticks, or 10 readings per slot, which corresponds to lowest number of
        //   ODFM symbols (for µ=1).
        //
        // - Requesting a duration of N gives 5*N readings. This is given in subslots, which for
        //   µ=1 is 2 subslots per slot, and thus matches 10 readings per slot, 5 per subslot.

        let params = nrfxlib_sys::nrf_modem_dect_phy_rssi_params {
            start_time: 0,
            handle: 1234567,
            carrier,
            duration: 48, // in subslots; 1 full report
            reporting_interval: nrfxlib_sys::nrf_modem_dect_phy_rssi_interval_NRF_MODEM_DECT_PHY_RSSI_INTERVAL_24_SLOTS, // 24 slots = 10ms
        };
        unsafe { nrfxlib_sys::nrf_modem_dect_phy_rssi(&params) }.into_result()?;

        let DectEventOuter {
            event: DectEvent::Completed,
            ..
        } = DECT_EVENTS.receive().await
        else {
            panic!("Sequence violation");
        };

        Ok(())
    }

    pub async fn rx(&mut self) -> Result<(), Error> {
        let params = unsafe {
            // FIXME: everything
            nrfxlib_sys::nrf_modem_dect_phy_rx(&nrfxlib_sys::nrf_modem_dect_phy_rx_params {
                start_time: 0,
                handle: 54321,
                network_id: 0x12345678, // like dect_shell defaults
                mode: nrfxlib_sys::nrf_modem_dect_phy_rx_mode_NRF_MODEM_DECT_PHY_RX_MODE_SINGLE_SHOT,
                rssi_interval: nrfxlib_sys::nrf_modem_dect_phy_rssi_interval_NRF_MODEM_DECT_PHY_RSSI_INTERVAL_OFF,
                link_id: nrfxlib_sys::nrf_modem_dect_phy_link_id {
                    short_network_id: 0,
                    short_rd_id: 0,
                },
                rssi_level: 0,
                carrier: 1665, // like dect_shell ping default
                // ~ 1 second
                duration: 70000000,
                filter: nrfxlib_sys::nrf_modem_dect_phy_rx_filter {
                    short_network_id: 0,
                    is_short_network_id_used: 0,
                    receiver_identity: 0,
                },
            })
        }
        .into_result()?;

        while let evt = DECT_EVENTS.receive().await {
            match evt {
                DectEventOuter {
                    event: DectEvent::Completed,
                    ..
                } => break, // FIXME success or error?
                _ => panic!("Sequence violation"),
            }
        }

        Ok(())
    }
}

/// Fetch traces from the modem
///
/// Make sure to enable the `modem-trace` feature. Call this function regularly
/// to ensure the trace buffer doesn't overflow.
///
/// `cb` will be called for every chunk of tracing data.
#[cfg(feature = "modem-trace")]
pub async fn fetch_traces(cb: impl AsyncFn(&[u8])) -> Result<(), Error> {
    let mut frags: *mut nrfxlib_sys::nrf_modem_trace_data = core::ptr::null_mut();
    let mut nfrags = 0;

    let res = unsafe {
        nrfxlib_sys::nrf_modem_trace_get(
            &mut frags,
            &mut nfrags,
            nrfxlib_sys::NRF_MODEM_OS_NO_WAIT as i32,
        )
    };

    if res != 0 {
        return Err(Error::NrfError(res as isize));
    }

    // SAFETY: if nrf_modem_trace_get returns 0, frags is a valid pointer to the start of an array of size nfrags.
    let frags = unsafe { core::slice::from_raw_parts(frags, nfrags) };
    for nrfxlib_sys::nrf_modem_trace_data { data, len } in frags {
        let data = unsafe { core::slice::from_raw_parts(*data as *mut u8, *len) };
        cb(data).await;
        unsafe {
            nrfxlib_sys::nrf_modem_trace_processed(*len);
        }
    }

    Ok(())
}

/// The memory layout used by the modem library.
///
/// The full range needs to be in the lower 128k of ram.
/// This also contains the fixed [nrfxlib_sys::NRF_MODEM_CELLULAR_SHMEM_CTRL_SIZE].
///
/// Nordic guide: <https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.4.1/nrfxlib/nrf_modem/doc/architecture.html#shared-memory-configuration>
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
            trace_area_size: if cfg!(feature = "modem-trace") {
                0x2000
            } else {
                0
            },
        }
    }
}

unsafe extern "C" fn modem_fault_handler(info: *mut nrfxlib_sys::nrf_modem_fault_info) {
    #[cfg(feature = "defmt")]
    defmt::panic!(
        "Modem fault - reason: {}, pc: {}",
        (*info).reason,
        (*info).program_counter
    );
    #[cfg(not(feature = "defmt"))]
    panic!(
        "Modem fault - reason: {}, pc: {}",
        (*info).reason,
        (*info).program_counter
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
    state: embassy_sync::mutex::Mutex<CriticalSectionRawMutex, RuntimeStateInner>,
    error: AtomicBool,
}

struct RuntimeStateInner {
    gps_active: bool,
    lte_link_count: u16,
    uicc_link_count: u16,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            state: embassy_sync::mutex::Mutex::new(RuntimeStateInner {
                gps_active: false,
                lte_link_count: 0,
                uicc_link_count: 0,
            }),
            error: AtomicBool::new(false),
        }
    }

    pub(crate) async fn activate_gps(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.gps_active {
            return Err(Error::GnssAlreadyTaken);
        }

        ModemActivation::Gnss.act_on_modem().await?;

        state.gps_active = true;

        Ok(())
    }

    pub(crate) async fn deactivate_gps(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if !state.gps_active {
            panic!("Can't deactivate an inactive gps");
        }

        if state.lte_link_count == 0 && state.uicc_link_count == 0 {
            ModemDeactivation::Everything.act_on_modem().await?;
        } else {
            ModemDeactivation::OnlyGnss.act_on_modem().await?;
        }

        state.gps_active = false;

        Ok(())
    }

    pub(crate) fn deactivate_gps_blocking(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| Error::InternalRuntimeMutexLocked)?;

        if !state.gps_active {
            panic!("Can't deactivate an inactive gps");
        }

        if state.lte_link_count == 0 && state.uicc_link_count == 0 {
            ModemDeactivation::Everything.act_on_modem_blocking()?;
        } else {
            ModemDeactivation::OnlyGnss.act_on_modem_blocking()?;
        }

        state.gps_active = false;

        Ok(())
    }

    pub(crate) async fn activate_lte(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.lte_link_count == u16::MAX {
            return Err(Error::TooManyLteLinks);
        }

        if state.lte_link_count == 0 {
            ModemActivation::Lte.act_on_modem().await?;
        }

        state.lte_link_count += 1;

        Ok(())
    }

    pub(crate) async fn deactivate_lte(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.lte_link_count == 0 {
            panic!("Can't deactivate an inactive lte");
        }

        if state.lte_link_count == 1 {
            if !state.gps_active && state.uicc_link_count == 0 {
                ModemDeactivation::Everything.act_on_modem().await?;
            } else {
                ModemDeactivation::OnlyLte.act_on_modem().await?;
                if state.uicc_link_count == 0 {
                    ModemDeactivation::OnlyUicc.act_on_modem().await?;
                }
            }
        }

        state.lte_link_count -= 1;

        Ok(())
    }

    pub(crate) fn deactivate_lte_blocking(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| Error::InternalRuntimeMutexLocked)?;

        if state.lte_link_count == 0 {
            panic!("Can't deactivate an inactive lte");
        }

        if state.lte_link_count == 1 {
            if !state.gps_active && state.uicc_link_count == 0 {
                ModemDeactivation::Everything.act_on_modem_blocking()?;
            } else {
                ModemDeactivation::OnlyLte.act_on_modem_blocking()?;
                if state.uicc_link_count == 0 {
                    ModemDeactivation::OnlyUicc.act_on_modem_blocking()?;
                }
            }
        }

        state.lte_link_count -= 1;

        Ok(())
    }

    pub(crate) async fn activate_uicc(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.uicc_link_count == u16::MAX {
            return Err(Error::TooManyUiccLinks);
        }

        if state.uicc_link_count == 0 {
            ModemActivation::Uicc.act_on_modem().await?;
        }

        state.uicc_link_count += 1;

        Ok(())
    }

    pub(crate) async fn deactivate_uicc(&self) -> Result<(), Error> {
        let mut state = self.state.lock().await;

        if state.uicc_link_count == 0 {
            panic!("Can't deactivate an inactive UICC");
        }

        if state.uicc_link_count == 1 {
            if state.gps_active || state.lte_link_count > 0 {
                ModemDeactivation::OnlyUicc
            } else {
                ModemDeactivation::Everything
            }
        } else {
            ModemDeactivation::Nothing
        }
        .act_on_modem()
        .await?;

        state.uicc_link_count -= 1;

        Ok(())
    }

    pub(crate) fn deactivate_uicc_blocking(&self) -> Result<(), Error> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| Error::InternalRuntimeMutexLocked)?;

        if state.uicc_link_count == 0 {
            panic!("Can't deactivate an inactive UICC");
        }

        if state.uicc_link_count == 1 {
            if state.gps_active || state.lte_link_count > 0 {
                ModemDeactivation::OnlyUicc
            } else {
                ModemDeactivation::Everything
            }
        } else {
            ModemDeactivation::Nothing
        }
        .act_on_modem_blocking()?;

        state.uicc_link_count -= 1;

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
            state.gps_active = false;
            state.lte_link_count = 0;
            state.uicc_link_count = 0;
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
    OnlyUicc,
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
                // Do not turn of UICC, let the caller do that.
            }
            ModemDeactivation::OnlyUicc => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling UICC");
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
                // Do not turn of UICC, let the caller do that.
            }
            ModemDeactivation::OnlyUicc => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Disabling UICC");
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
    Uicc,
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
            ModemActivation::Uicc => {
                #[cfg(feature = "defmt")]
                defmt::debug!("Enabling UICC");

                // Set UICC low power mode
                at::send_at::<0>("AT+CEPPI=1").await?;
                // Activate LTE without changing GNSS
                at::send_at::<0>("AT+CFUN=41").await?;
            }
        }

        Ok(())
    }
}
