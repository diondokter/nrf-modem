//! High-level wrappers around the DECT PHY.
//!
//! This implementation does *not* try to be friendly to highly concurrent operations; rather, it
//! aims for ease of use and getting things done.
//!
//! More elaborate versions (e.g. supporting concurrently enqueued actions using a preconfigured
//! list of handle slots, or more actions inside the interrupt) might be added later, or
//! independently (using [`nrfxlib_sys`] and working off [`crate::init_dect_with_custom_layout`]).

use nrf_modem::nrfxlib_sys;
use nrf_modem::{Error, ErrorSource, MemoryLayout, init_with_custom_layout_core};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    mutex::{Mutex, MutexGuard},
};

const _: () = const {
    assert!(
        nrfxlib_sys::nrf_modem_dect_phy_err_NRF_MODEM_DECT_PHY_SUCCESS == 0,
        "Constant for success switched and is now not aligned with Result niche optimization."
    )
};
#[derive(Debug, defmt::Format)]
pub struct PhyErr(core::num::NonZeroU16);
type PhyResult = Result<(), PhyErr>;

trait PhyResultExt {
    fn into_phy_result(self) -> PhyResult;
}

impl PhyResultExt for u16 {
    fn into_phy_result(self) -> PhyResult {
        match core::num::NonZeroU16::try_from(self) {
            Ok(v) => Err(PhyErr(v)),
            Err(_) => Ok(()),
        }
    }
}

/// Error type that encompasses both styles of errors returned by the libmodem APIs.
#[derive(Debug)]
pub enum MixedError {
    General(Error),
    Phy(PhyErr),
    UsageError,
}

impl From<Error> for MixedError {
    fn from(input: Error) -> Self {
        MixedError::General(input)
    }
}

impl From<PhyErr> for MixedError {
    fn from(input: PhyErr) -> Self {
        MixedError::Phy(input)
    }
}

// FIXME: What's a good length? Probably events can pile up, like "here's the last data and by the
// way the transaction is now complete". And do we need the CS mutex?
static DECT_EVENTS: embassy_sync::channel::Channel<CriticalSectionRawMutex, DectEventOuter, 4> =
    embassy_sync::channel::Channel::new();

#[derive(Debug, defmt::Format, Copy, Clone)]
#[non_exhaustive]
pub enum PccError {
    CrcError,
    UnexpectedEventDetails,
}

#[derive(Debug, defmt::Format, Copy, Clone)]
#[non_exhaustive]
pub enum PdcError {
    CrcError,
    OutOfSpace,
    // Maybe if it straddled the timeout? I did observe this when sender and recipient timeouts
    // could have lined up.
    NotReceived,
    PccError(PccError),
}

/// Details of a [`RecvResult`] that did result in data being received.
#[derive(Copy, Clone)]
pub struct RecvOk {
    pub pcc_time: u64,
    pub pcc_len: usize,
    pub pdc_len: Result<usize, PdcError>,
}

/// Result of a single receive operation.
///
/// This keeps a lock on the receive buffer, and must therefore be dropped before the next attempt
/// to perform any other operation.
pub struct RecvResult<'a> {
    data: MutexGuard<'static, CriticalSectionRawMutex, heapless::Vec<u8, 2400>>,
    indices: Result<RecvOk, PccError>,
    // This ensures that a .recv() result is used before the next attempt to receive something (as
    // that would panic around locking RECV_BUF).
    _phantom: core::marker::PhantomData<&'a mut ()>,
}

impl<'a> RecvResult<'a> {
    pub fn pcc_time(&self) -> Result<u64, PccError> {
        Ok(self.indices?.pcc_time)
    }
    pub fn pcc(&self) -> Result<&[u8], PccError> {
        Ok(&self.data[..self.indices?.pcc_len])
    }
    pub fn pdc(&self) -> Result<&[u8], PdcError> {
        let pcc_and_rest = self.indices.map_err(PdcError::PccError)?;
        let start = pcc_and_rest.pcc_len;
        let len = pcc_and_rest.pdc_len?;
        self.data.get(start..start + len).ok_or(PdcError::OutOfSpace)
    }
}

/// Resulting data slice of a single RSSI measurement.
///
/// This keeps a lock on the receive buffer, and must therefore be dropped before the next attempt
/// to perform any other operation.
pub struct RssiResult<'a>(
    MutexGuard<'static, CriticalSectionRawMutex, heapless::Vec<u8, 2400>>,
    core::ops::Range<usize>,
    // This ensures that a result is used before the next attempt to receive something (as
    // that would panic around locking RECV_BUF).
    core::marker::PhantomData<&'a mut ()>,
);

impl<'a> RssiResult<'a> {
    pub fn data(&self) -> &[u8] {
        &self.0[self.1.clone()]
    }
}

/// Kind of a bump allocator for data that doesn't fit in the events.
///
/// Might later be turned into a ring buffer if any methods support stream-processing multiple
/// events.
///
/// Sized 2400 somewhat arbitrarily because it could take 10 runs of RSSI data.
static RECVBUF: Mutex<CriticalSectionRawMutex, heapless::Vec<u8, 2400>> =
    Mutex::new(heapless::Vec::new());

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
    Completed(PhyResult),
    /// This is both the EVT_PCC_ERROR that really is just CRC error, or failures during processing
    /// of a PCC.
    PccError(PccError),
    /// PCC with time and length inside recvbuf
    // If we start doing multiple recvs, we can't just upgrade this to a range here and in PCD,
    // also not to Option<Range> in case it didn't fit, but need to stream it out through a ring
    // buffer with process-on-the-fly anyway.
    Pcc(u64, usize),
    PdcError,
    /// Length inside recvbuf
    Pdc(usize),
    Rssi(u64, Option<core::ops::Range<usize>>),
}

// FIXME: This is only pub while the DectPhy object doesn't have an init that calls the low-level
// init.
extern "C" fn dect_event(arg: *const nrfxlib_sys::nrf_modem_dect_phy_event) {
    let arg: &nrfxlib_sys::nrf_modem_dect_phy_event = unsafe { &*arg };

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
            // SAFETY: It is valid now, which is as long as we use it
            // Casting because it's not precisely a signed integer anyuway (and our buffer is just
            // bytes).
            let meas =
                unsafe { core::slice::from_raw_parts(rssi.meas as *const u8, rssi.meas_len as _) };
            defmt::trace!(
                "RSSI handle {} start {} carrier {}; {} measurements",
                rssi.handle,
                rssi.meas_start_time,
                rssi.carrier,
                meas.len(),
            );

            if let Ok(mut recvbuf) = RECVBUF.try_lock() {
                let start = recvbuf.len();
                if recvbuf.extend_from_slice(meas).is_ok() {
                    DectEvent::Rssi(rssi.meas_start_time, Some(start..(start + meas.len())))
                } else {
                    DectEvent::Rssi(rssi.meas_start_time, None)
                }
            } else {
                DectEvent::Rssi(rssi.meas_start_time, None)
            }
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
            DectEvent::Completed(op.err.into_phy_result())
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
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PCC => 'eventresult: {
            // SAFETY: Checked the discriminator
            let pcc = unsafe { &arg.__bindgen_anon_1.pcc };

            let header_len = match pcc.phy_type {
                0 => 5,
                1 => 10,
                _ => break 'eventresult DectEvent::PccError(PccError::UnexpectedEventDetails),
            };
            // SAFETY: As per struct details.
            // (Easier to pass this on as bytes and do our own field access later)
            let header = &unsafe { pcc.hdr.type_2 }[..header_len];
            defmt::trace!("PCC start {} handle {} phy_type {} rssi2 {} snr {} transaction {} hdr st {} hdr {:02x}",
                pcc.stf_start_time,
                pcc.handle,
                pcc.phy_type,
                pcc.rssi_2,
                pcc.snr,
                pcc.transaction_id,
                pcc.header_status,
                header
                );

            let mut recvbuf = RECVBUF
                .try_lock()
                .expect("Was checked when doing a request");

            assert_eq!(recvbuf.len(), 0);
            recvbuf
                .extend_from_slice(header)
                .expect("Length is small enough to always fit");
            DectEvent::Pcc(pcc.stf_start_time, header.len())
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PCC_ERROR => {
            DectEvent::PccError(PccError::CrcError)
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PDC => {
            // SAFETY: Checked the discriminator
            let pdc = unsafe { &arg.__bindgen_anon_1.pdc };
            // SAFETY: Implied by the C API
            let data = unsafe { core::slice::from_raw_parts(pdc.data as *const u8, pdc.len) };
            defmt::trace!(
                "PDC handle {} trns {} data {:02x}",
                pdc.handle,
                pdc.transaction_id,
                data,
            );

            let mut recvbuf = RECVBUF
                .try_lock()
                .expect("Was checked when doing a request");

            // Either it fits or it doesn't; the user will see when trying to access the buffer up
            // to it.
            // FIXME: Does it makes ense to store it as far as possible?
            let _ = recvbuf.extend_from_slice(data);
            DectEvent::Pdc(data.len())
        }
        nrfxlib_sys::nrf_modem_dect_phy_event_id_NRF_MODEM_DECT_PHY_EVT_PDC_ERROR => {
            DectEvent::PdcError
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
        .expect("Queue is managed")
}

pub struct DectPhy(());

impl DectPhy {
    /// Starts the NRF Modem library with a manually specified memory layout
    ///
    /// With the os_irq feature enabled, you need to specify the OS scheduled IRQ number.
    /// The modem's IPC interrupt should be higher than the os irq. (IPC should pre-empt the executor)
    pub async fn init_with_custom_layout(
        memory_layout: MemoryLayout,
        #[cfg(feature = "os-irq")] os_irq: u8,
    ) -> Result<Self, Error> {
        init_with_custom_layout_core(
            memory_layout,
            #[cfg(feature = "os-irq")]
            os_irq,
        )?;

        defmt::trace!("Setting DECT handler");

        // Note that unlike typical C callbacks, this callback setup takes no argument -- if it did, we
        // might consider abstracting here, by passing in the original function and accepting a
        // single-call indicrection instead of the extern "C" on the handler.

        unsafe { nrfxlib_sys::nrf_modem_dect_phy_event_handler_set(Some(dect_event)) }
            .into_result()?;

        defmt::trace!("Initializing DECT PHY");

        unsafe { nrfxlib_sys::nrf_modem_dect_phy_init() }.into_result()?;

        defmt::trace!("Initialization started.");

        let DectEventOuter {
            event: DectEvent::Init,
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
        let mode =
            nrfxlib_sys::nrf_modem_dect_phy_radio_mode_NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY;
        unsafe { nrfxlib_sys::nrf_modem_dect_phy_activate(mode) }.into_result()?;
        let DectEventOuter {
            event: DectEvent::Activate,
            ..
        } = DECT_EVENTS.receive().await
        else {
            panic!("Sequence violation");
        };

        Ok(Self(()))
    }

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

    /// Dual purpose:
    /// * Clear out message
    /// * Debug tool: This ensures that the panic won't happen in the ISR. (That'd be kind'a fine,
    ///   but it's easier debugging this way).
    fn clear_recvbuf(&mut self) {
        let mut recvbuf = RECVBUF.try_lock().expect(
            "Buffer in use; unsafe construction of DectPhy, or pending future was dropped.",
        );
        recvbuf.clear();
        drop(recvbuf);
    }

    pub async fn rssi(&mut self, carrier: u16) -> Result<(u64, RssiResult<'_>), MixedError> {
        self.clear_recvbuf();

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

        let mut result = None;

        loop {
            match DECT_EVENTS.receive().await.event {
                DectEvent::Rssi(start, range) => {
                    debug_assert!(result.is_none(), "Sequence violation");
                    result = Some((
                        start,
                        range.expect("We requested just one run, that fits in the receive buffer"),
                    ));
                }
                DectEvent::Completed(Ok(())) => {
                    break;
                }
                DectEvent::Completed(e) => e?,
                _ => panic!("Sequence violation"),
            }
        }

        let Some(result) = result else {
            // FIXME: Verify that it's an actual completion error that happens when requesting an
            // unsupported channel.
            panic!("Sequence violation");
        };

        Ok((
            result.0,
            RssiResult(
                RECVBUF
                    .try_lock()
                    .expect("Was checked before, and ISR users release this before returning"),
                result.1,
                core::marker::PhantomData,
            ),
        ))
    }

    // FIXME: heapless is not great for signature yet
    pub async fn rx(&mut self) -> Result<Option<RecvResult<'_>>, MixedError> {
        self.clear_recvbuf();

        unsafe {
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

        let mut pcc = None;
        let mut pdc = None;

        loop {
            match DECT_EVENTS.receive().await.event {
                DectEvent::Pcc(start, pcc_len) => {
                    debug_assert!(pcc.is_none(), "Sequence violation");
                    pcc = Some(Ok((start, pcc_len)));
                }
                DectEvent::PccError(e) => {
                    debug_assert!(pcc.is_none(), "Sequence violation");
                    pcc = Some(Err(e));
                }
                DectEvent::Pdc(pcd_len) => {
                    debug_assert!(pdc.is_none(), "Sequence violation");
                    pdc = Some(Ok(pcd_len));
                }
                DectEvent::PdcError => {
                    debug_assert!(pdc.is_none(), "Sequence violation");
                    pdc = Some(Err(PdcError::CrcError));
                }
                DectEvent::Completed(Ok(())) => {
                    break;
                }
                DectEvent::Completed(e) => e?,
                _ => panic!("Sequence violation"),
            }
        }

        let result = match (pcc, pdc) {
            (None, None) => return Ok(None),
            (Some(Err(e)), None) => Err(e),
            (Some(Ok((pcc_time, pcc_len))), None) => Ok(RecvOk { pcc_time, pcc_len, pdc_len: Err(PdcError::NotReceived) }),
            (Some(Ok((pcc_time, pcc_len))), Some(pdc_len)) => Ok(RecvOk { pcc_time, pcc_len, pdc_len }),
            _ => panic!("Sequence violation"),
        };

        Ok(Some(RecvResult {
            data: RECVBUF
                .try_lock()
                .expect("Was checked before, and ISR users release this before returning"),
            indices: result,
            _phantom: core::marker::PhantomData,
        }))
    }

    /// Transmit a message at the indicated time, or immediately if start_time is 0.
    ///
    /// The network_id influences scrambling. Pass in the full 32-bit network ID; this function
    /// picks it apart depending on the PCC length. Beware that this is required to be non-zero.
    pub async fn tx(
        &mut self,
        start_time: u64,
        channel: u16,
        network_id: u32,
        pcc: &[u8],
        pdc: &[u8],
    ) -> Result<(), MixedError> {
        let phy_type = match pcc.len() {
            5 => 0,
            10 => 1,
            _ => panic!("Not a valid header length"),
        };

        // The PHY function is documented to require this, and will indeed not transmit.
        //
        // But expressing this in the type would be odd (the full value is computed of parts where
        // it is not clear whose resposibility it is to not be zero) for practical deployments. (Is
        // it really the random lower 8 bits that need to special-case if the upper 24 are all-zero?)
        //
        // Handling this as an error seems to be most practical, as it won't take down the whole
        // system but will not go silently either.
        if network_id == 0 {
            return Err(MixedError::UsageError);
        }

        unsafe {
            // FIXME: everything
            nrfxlib_sys::nrf_modem_dect_phy_tx(&nrfxlib_sys::nrf_modem_dect_phy_tx_params {
                start_time,
                handle: 2468,
                // FIXME: Verify that libmodem or the network core does the >> 8 / & 0xff.
                //
                // (Probably: otherwise, the "must not be zero" can not be upheld).
                network_id,
                phy_type,
                lbt_rssi_threshold_max: 0, // see below
                carrier: channel,
                lbt_period: 0, // BIG FIXME
                // The object may be smaller than expected for phy_header, but then, phy_type tells
                // to only access the smaller struct fields anyway.
                phy_header: pcc.as_ptr() as _,
                bs_cqi: nrfxlib_sys::NRF_MODEM_DECT_PHY_BS_CQI_NOT_USED as _,
                // Missing `const` in C? They won't really write in there, will they?
                data: pdc.as_ptr() as *mut _,
                data_size: pdc.len() as _,
            })
        }
        .into_result()
        .map_err(MixedError::General)?;

        match DECT_EVENTS.receive().await {
            DectEventOuter {
                event: DectEvent::Completed(e),
                ..
            } => e.map_err(MixedError::Phy),
            _ => panic!("Sequence violation"),
        }
    }
}
