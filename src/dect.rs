//! High-level wrappers around the DECT PHY.

use crate::error::{Error, ErrorSource};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

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

// FIXME: This is only pub while the DectPhy object doesn't have an init that calls the low-level
// init.
pub extern "C" fn dect_event(arg: super::DectPhyEventWrapper<'_>) {
    let arg: &nrfxlib_sys::nrf_modem_dect_phy_event = arg.0;

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
            defmt::warn!(
                "PDC handle {} trns {} data {:02x}",
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

// FIXME: Do we need this to have all the properties? (I don't think anything would go wrong if it
// was sent, and Sync is not an issue anyway, but maybe at some point we want to enqueue parallel
// operations maybe).
pub struct DectPhy(core::marker::PhantomData<*const ()>);

impl DectPhy {
    // FIXME: This also kind'a needs the promise that our handler was configured, but worst that
    // can happen is that we starve for events.
    pub async fn new(_init_started: crate::DectPreinitialized) -> Result<Self, Error> {
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

        Ok(Self(Default::default()))
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
