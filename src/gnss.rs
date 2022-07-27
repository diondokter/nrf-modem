use crate::error::{Error, ErrorSource};
use core::{
    mem::{size_of, MaybeUninit},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    task::{Context, Poll},
};
use arrayvec::ArrayString;
use embassy::waitqueue::AtomicWaker;
use futures::Stream;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

static GNSS_WAKER: AtomicWaker = AtomicWaker::new();
static LAST_GNSS_EVENT: AtomicU32 = AtomicU32::new(0);
static GNSS_TAKEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn gnss_callback(event: i32) {
    #[cfg(feature = "defmt")]
    defmt::trace!("Gnss -> {}", GnssEventType::from(event as u32));

    LAST_GNSS_EVENT.fetch_or(1 << event as u32, Ordering::SeqCst);
    GNSS_WAKER.wake();
}

pub struct Gnss {}

impl Gnss {
    pub async fn new() -> Result<Self, Error> {
        if unsafe { !nrfxlib_sys::nrf_modem_is_initialized() } {
            return Err(Error::ModemNotInitialized);
        }

        #[cfg(feature = "defmt")]
        defmt::debug!("Enabling gnss");
        crate::at::send_at("AT+CFUN=31").await?;

        if GNSS_TAKEN.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst) != Ok(false)
        {
            return Err(Error::GnssAlreadyTaken);
        }

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_event_handler_set(Some(gnss_callback));
        }

        Ok(Gnss {})
    }

    pub fn start_single_fix(
        &mut self,
        config: GnssConfig,
    ) -> Result<impl Stream<Item = Result<GnssData, Error>>, Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!("Setting single fix");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_fix_interval_set(0)
                .into_result()
                .unwrap();
        }

        #[cfg(feature = "defmt")]
        defmt::debug!("Apply config");

        self.apply_config(config)?;

        #[cfg(feature = "defmt")]
        defmt::debug!("Starting gnss");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_start();
        }

        Ok(GnssDataIter::new(true))
    }

    fn apply_config(&mut self, config: GnssConfig) -> Result<(), Error> {
        unsafe {
            nrfxlib_sys::nrf_modem_gnss_elevation_threshold_set(config.elevation_threshold_angle)
                .into_result()?;
            nrfxlib_sys::nrf_modem_gnss_use_case_set(config.use_case.into()).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_fix_retry_set(config.fix_retry).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_nmea_mask_set(config.nmea_mask.into()).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_power_mode_set(u32::from(config.power_mode) as _)
                .into_result()?;
            nrfxlib_sys::nrf_modem_gnss_timing_source_set(u32::from(config.timing_source) as _)
                .into_result()?;
        }
        Ok(())
    }
}

impl Drop for Gnss {
    fn drop(&mut self) {
        unsafe {
            nrfxlib_sys::nrf_modem_at_printf(b"AT+CFUN=30".as_ptr());
        }

        GNSS_TAKEN.store(false, Ordering::SeqCst);
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NmeaMask {
    /// Enables Global Positioning System Fix Data.
    pub gga: bool,
    /// Enables Geographic Position Latitude/Longitude and time.
    pub gll: bool,
    /// Enables DOP and active satellites.
    pub gsa: bool,
    /// Enables Satellites in view.
    pub gsv: bool,
    /// Enables Recommended minimum specific GPS/Transit data.
    pub rmc: bool,
}

impl Default for NmeaMask {
    fn default() -> Self {
        Self {
            gga: true,
            gll: true,
            gsa: true,
            gsv: true,
            rmc: true,
        }
    }
}

impl From<NmeaMask> for u16 {
    fn from(mask: NmeaMask) -> Self {
        mask.gga
            .then(|| nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GGA_MASK as u16)
            .unwrap_or(0)
            | mask
                .gll
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GLL_MASK as u16)
                .unwrap_or(0)
            | mask
                .gsa
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GSA_MASK as u16)
                .unwrap_or(0)
            | mask
                .gsv
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GSV_MASK as u16)
                .unwrap_or(0)
            | mask
                .rmc
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_NMEA_RMC_MASK as u16)
                .unwrap_or(0)
    }
}

#[derive(IntoPrimitive, FromPrimitive, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
enum GnssEventType {
    #[default]
    None = 0,
    /// PVT event.
    Pvt = nrfxlib_sys::NRF_MODEM_GNSS_EVT_PVT,
    /// GNSS fix event.
    GnssFix = nrfxlib_sys::NRF_MODEM_GNSS_EVT_FIX,
    /// NMEA event.
    Nmea = nrfxlib_sys::NRF_MODEM_GNSS_EVT_NMEA,
    /// Need new APGS data event.
    AgpsRequest = nrfxlib_sys::NRF_MODEM_GNSS_EVT_AGPS_REQ,
    /// GNSS is blocked by LTE event.
    BlockedByLte = nrfxlib_sys::NRF_MODEM_GNSS_EVT_BLOCKED,
    /// GNSS is unblocked by LTE event.
    UnblockedByLte = nrfxlib_sys::NRF_MODEM_GNSS_EVT_UNBLOCKED,
    /// GNSS woke up in periodic mode.
    ///
    /// This event is sent when GNSS receiver is turned on in periodic mode. This happens when GNSS starts acquiring the next periodic fix but also when a scheduled download starts.
    PeriodicWakeup = nrfxlib_sys::NRF_MODEM_GNSS_EVT_PERIODIC_WAKEUP,
    /// GNSS enters sleep because fix retry timeout was reached in periodic or single fix mode.
    RetryTimeoutReached = nrfxlib_sys::NRF_MODEM_GNSS_EVT_SLEEP_AFTER_TIMEOUT,
    /// GNSS enters sleep because fix was achieved in periodic mode.
    SleepAfterFix = nrfxlib_sys::NRF_MODEM_GNSS_EVT_SLEEP_AFTER_FIX,
    /// Reference altitude for 3-satellite fix expired.
    ReferenceAltitudeExpired = nrfxlib_sys::NRF_MODEM_GNSS_EVT_REF_ALT_EXPIRED,
}

impl GnssEventType {
    pub fn get_from_bit_packed(container: u32) -> Self {
        let variants = [
            Self::ReferenceAltitudeExpired,
            Self::SleepAfterFix,
            Self::RetryTimeoutReached,
            Self::PeriodicWakeup,
            Self::UnblockedByLte,
            Self::BlockedByLte,
            Self::AgpsRequest,
            Self::Nmea,
            Self::GnssFix,
            Self::Pvt,
        ];

        for variant in variants {
            if container & (1 << variant as u32) != 0 {
                return variant;
            }
        }

        Self::None
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GnssConfig {
    /// Set below which elevation angle GNSS should stop tracking a satellite.
    ///
    /// Satellites with elevation angle less than the threshold are excluded from the estimation.
    ///
    /// Default value: 5 deg
    elevation_threshold_angle: u8,
    use_case: GnssUsecase,
    /// Retry time in seconds.
    ///
    /// Fix retry parameter controls the maximum time the GNSS receiver is allowed to run while trying to produce a valid PVT estimate.
    /// If the fix retry time is non-zero, the GNSS receiver is turned off after the fix retry time is up regardless of whether a valid PVT estimate was produced or not.
    /// If fix retry parameter is set to zero, the GNSS receiver is allowed to run indefinitely until a valid PVT estimate is produced.
    ///
    /// Default value: 60s
    fix_retry: u16,
    nmea_mask: NmeaMask,
    timing_source: GnssTimingSource,
    power_mode: GnssPowerSaveMode,
}

impl Default for GnssConfig {
    fn default() -> Self {
        Self {
            elevation_threshold_angle: 5,
            use_case: Default::default(),
            fix_retry: 60,
            nmea_mask: Default::default(),
            timing_source: Default::default(),
            power_mode: Default::default(),
        }
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
pub struct GnssUsecase {
    /// Low accuracy fixes allowed.
    ///
    /// The error in position calculation can be larger than in normal accuracy mode.
    /// In addition, GNSS might only use three satellites to determine a fix,
    /// while in normal accuracy mode at least four satellites are used.
    low_accuracy: bool,
    /// Disable scheduled downloads.
    ///
    /// By default, in periodic navigation mode, when GNSS determines it needs to download ephemerides or almanacs from the broadcast,
    /// the fix interval and fix retry parameters are temporarily ignored. GNSS will perform scheduled downloads until it has downloaded the data it needs,
    /// after which normal operation is resumed.
    ///
    /// When this bit is set, scheduled downloads are disabled.
    /// This is recommended when A-GPS is used to supply assistance data to the GNSS.
    /// It is also possible to use this option without A-GPS, but it should be noted that in that case GNSS will never get some data (for example ionospheric corrections),
    /// which may affect the accuracy.
    scheduled_downloads_disable: bool,
}

impl Default for GnssUsecase {
    fn default() -> Self {
        Self {
            low_accuracy: false,
            scheduled_downloads_disable: false,
        }
    }
}

impl From<GnssUsecase> for u8 {
    fn from(usecase: GnssUsecase) -> Self {
        nrfxlib_sys::NRF_MODEM_GNSS_USE_CASE_MULTIPLE_HOT_START as u8
            | usecase
                .low_accuracy
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_USE_CASE_LOW_ACCURACY as u8)
                .unwrap_or(0)
            | usecase
                .scheduled_downloads_disable
                .then(|| nrfxlib_sys::NRF_MODEM_GNSS_USE_CASE_SCHED_DOWNLOAD_DISABLE as u8)
                .unwrap_or(0)
    }
}

/// Used to select which sleep timing source GNSS uses.
///
/// Using TCXO instead of RTC during GNSS sleep periods might be beneficial when used with 1PPS.
/// When GNSS is not running all the time (periodic navigation or duty-cycling is used), 1PPS accuracy can be improved by using TCXO.
/// It may also improve sensitivity for periodic navigation when the fix interval is short.
///
/// *Note*: Use of TCXO significantly raises the idle current consumption.
#[derive(Debug, Clone, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
pub enum GnssTimingSource {
    #[default]
    Rtc = nrfxlib_sys::NRF_MODEM_GNSS_TIMING_SOURCE_RTC,
    Tcxo = nrfxlib_sys::NRF_MODEM_GNSS_TIMING_SOURCE_TCXO,
}

/// Use these values to select which power save mode GNSS should use.
///
/// This only affects continuous navigation mode.
///
/// When GNSS engages duty-cycled tracking, it only tracks for 20% of time and spends the rest of the time in sleep.
/// The different modes control how aggressively GNSS engages duty-cycled tracking, but the duty-cycling itself is the same with both modes.
#[derive(Debug, Clone, Default, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
pub enum GnssPowerSaveMode {
    #[default]
    Disabled = nrfxlib_sys::NRF_MODEM_GNSS_PSM_DISABLED,
    DutyCyclingPerformance = nrfxlib_sys::NRF_MODEM_GNSS_PSM_DUTY_CYCLING_PERFORMANCE,
    DutyCycling = nrfxlib_sys::NRF_MODEM_GNSS_PSM_DUTY_CYCLING_POWER,
}

#[derive(Debug, Clone, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
enum GnssDataType {
    PositionVelocityTime = nrfxlib_sys::NRF_MODEM_GNSS_DATA_PVT,
    Nmea = nrfxlib_sys::NRF_MODEM_GNSS_DATA_NMEA,
    Agps = nrfxlib_sys::NRF_MODEM_GNSS_DATA_AGPS_REQ,
}

#[derive(Debug, Clone)]
pub enum GnssData {
    PositionVelocityTime(nrfxlib_sys::nrf_modem_gnss_pvt_data_frame),
    Nmea(ArrayString<83>),
    Agps(nrfxlib_sys::nrf_modem_gnss_agps_data_frame),
}

impl GnssData {
    fn read_from_modem(data_type: GnssDataType) -> Result<Self, Error> {
        match data_type {
            GnssDataType::PositionVelocityTime => {
                let mut data = MaybeUninit::uninit();

                unsafe {
                    nrfxlib_sys::nrf_modem_gnss_read(
                        data.as_mut_ptr() as *mut _,
                        size_of::<nrfxlib_sys::nrf_modem_gnss_pvt_data_frame>() as i32,
                        data_type as u32 as _,
                    )
                    .into_result()?;
                    Ok(GnssData::PositionVelocityTime(data.assume_init()))
                }
            }
            GnssDataType::Nmea => {
                let mut data: MaybeUninit<nrfxlib_sys::nrf_modem_gnss_nmea_data_frame> = MaybeUninit::uninit();

                unsafe {
                    nrfxlib_sys::nrf_modem_gnss_read(
                        data.as_mut_ptr() as *mut _,
                        size_of::<nrfxlib_sys::nrf_modem_gnss_nmea_data_frame>() as i32,
                        data_type as u32 as _,
                    )
                    .into_result()?;

                    let data = data.assume_init().nmea_str;
                    let mut string_data = ArrayString::from_byte_string(&data)?;
                    string_data.truncate(string_data.as_bytes().iter().take_while(|b| **b != 0).count());
                    Ok(GnssData::Nmea(string_data))
                }
            }
            GnssDataType::Agps => {
                let mut data = MaybeUninit::uninit();

                unsafe {
                    nrfxlib_sys::nrf_modem_gnss_read(
                        data.as_mut_ptr() as *mut _,
                        size_of::<nrfxlib_sys::nrf_modem_gnss_agps_data_frame>() as i32,
                        data_type as u32 as _,
                    )
                    .into_result()?;
                    Ok(GnssData::Agps(data.assume_init()))
                }
            }
        }
    }
}

struct GnssDataIter {
    single_fix: bool,
    done: bool,
}

impl GnssDataIter {
    fn new(single_fix: bool) -> Self {
        LAST_GNSS_EVENT.store(0, Ordering::SeqCst);
        Self {
            single_fix,
            done: false,
        }
    }
}

impl Stream for GnssDataIter {
    type Item = Result<GnssData, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            #[cfg(feature = "defmt")]
            defmt::trace!("Gnss is done");

            return Poll::Ready(None);
        }

        let event_bits = LAST_GNSS_EVENT.load(Ordering::SeqCst);
        let event = GnssEventType::get_from_bit_packed(event_bits);

        #[cfg(feature = "defmt")]
        defmt::trace!("Gnss event: {}", event);

        let data = match event {
            GnssEventType::Pvt => Some(GnssData::read_from_modem(
                GnssDataType::PositionVelocityTime,
            )),
            GnssEventType::GnssFix if self.single_fix => {
                self.get_mut().done = true;
                Some(GnssData::read_from_modem(
                    GnssDataType::PositionVelocityTime,
                ))
            }
            GnssEventType::GnssFix => Some(GnssData::read_from_modem(
                GnssDataType::PositionVelocityTime,
            )),
            GnssEventType::Nmea => Some(GnssData::read_from_modem(GnssDataType::Nmea)),
            GnssEventType::AgpsRequest => Some(GnssData::read_from_modem(GnssDataType::Agps)),
            GnssEventType::RetryTimeoutReached | GnssEventType::SleepAfterFix
                if self.single_fix =>
            {
                self.get_mut().done = true;
                return Poll::Ready(None);
            }
            _ => None,
        };

        let left_over_event_bits = LAST_GNSS_EVENT.fetch_and(!(1 << event as u32), Ordering::SeqCst);

        if left_over_event_bits > 0 {
            cx.waker().wake_by_ref();
        } else {
            GNSS_WAKER.register(cx.waker());
        }

        match data {
            Some(data) => Poll::Ready(Some(data)),
            None => Poll::Pending,
        }
    }
}
