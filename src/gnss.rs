use crate::error::{Error, ErrorSource};
use arrayvec::{ArrayString, ArrayVec};
use core::{
    cell::RefCell,
    mem::{size_of, MaybeUninit},
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll},
};
use critical_section::Mutex;
use futures::{task::AtomicWaker, Stream};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

const MAX_NMEA_BURST_SIZE: usize = 5;

static GNSS_WAKER: AtomicWaker = AtomicWaker::new();
static GNSS_NOTICED_EVENTS: AtomicU32 = AtomicU32::new(0);
static GNSS_NMEA_STRINGS: Mutex<RefCell<ArrayVec<Result<GnssData, Error>, MAX_NMEA_BURST_SIZE>>> =
    Mutex::new(RefCell::new(ArrayVec::new_const()));

unsafe extern "C" fn gnss_callback(event: i32) {
    let event_type = GnssEventType::from(event as u32);

    #[cfg(feature = "defmt")]
    defmt::trace!("Gnss -> {}", event_type);

    if matches!(event_type, GnssEventType::Nmea) {
        critical_section::with(|cs| {
            GNSS_NMEA_STRINGS
                .borrow_ref_mut(cs)
                .try_push(GnssData::read_from_modem(GnssDataType::Nmea))
                .ok()
        });
    }

    GNSS_NOTICED_EVENTS.fetch_or(1 << event as u32, Ordering::SeqCst);

    GNSS_WAKER.wake();
}

/// A GNSS objects that controls the GPS of the modem.
///
/// There can only be one instance at a time.
pub struct Gnss {}

impl Gnss {
    /// Activate the GPS
    pub async fn new() -> Result<Self, Error> {
        if unsafe { !nrfxlib_sys::nrf_modem_is_initialized() } {
            return Err(Error::ModemNotInitialized);
        }

        crate::MODEM_RUNTIME_STATE.activate_gps().await?;

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_event_handler_set(Some(gnss_callback));
        }

        Ok(Gnss {})
    }

    /// Do a single GPS fix until a valid Position Velocity Time (PVT) is found.
    ///
    /// The `timeout_seconds` parameter controls the maximum time the GNSS receiver is allowed to run while trying to produce a valid PVT estimate.
    /// If the value is non-zero, the GNSS receiver is turned off after the time is up regardless of whether a valid PVT estimate was produced or not.
    /// If the value is set to zero, the GNSS receiver is allowed to run indefinitely until a valid PVT estimate is produced.
    /// A sane default value: 60s.
    pub fn start_single_fix(
        mut self,
        config: GnssConfig,
        timeout_seconds: u16,
    ) -> Result<GnssStream, Error> {
        #[cfg(feature = "defmt")]
        defmt::trace!("Setting single fix");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_fix_interval_set(0).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_fix_retry_set(timeout_seconds).into_result()?;
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Apply config");

        self.apply_config(config)?;

        #[cfg(feature = "defmt")]
        defmt::debug!("Starting gnss");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_start();
        }

        Ok(GnssStream::new(true, self))
    }

    pub fn start_continuous_fix(mut self, config: GnssConfig) -> Result<GnssStream, Error> {
        #[cfg(feature = "defmt")]
        defmt::trace!("Setting single fix");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_fix_interval_set(1)
                .into_result()
                .unwrap();
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Apply config");

        self.apply_config(config)?;

        #[cfg(feature = "defmt")]
        defmt::debug!("Starting gnss");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_start();
        }

        Ok(GnssStream::new(false, self))
    }

    pub fn start_periodic_fix(
        mut self,
        config: GnssConfig,
        period_seconds: u16,
    ) -> Result<GnssStream, Error> {
        #[cfg(feature = "defmt")]
        defmt::trace!("Setting single fix");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_fix_interval_set(period_seconds.max(10))
                .into_result()
                .unwrap();
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Apply config");

        self.apply_config(config)?;

        #[cfg(feature = "defmt")]
        defmt::debug!("Starting gnss");

        unsafe {
            nrfxlib_sys::nrf_modem_gnss_start();
        }

        Ok(GnssStream::new(false, self))
    }

    fn apply_config(&mut self, config: GnssConfig) -> Result<(), Error> {
        unsafe {
            nrfxlib_sys::nrf_modem_gnss_elevation_threshold_set(config.elevation_threshold_angle)
                .into_result()?;
            nrfxlib_sys::nrf_modem_gnss_use_case_set(config.use_case.into()).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_nmea_mask_set(config.nmea_mask.into()).into_result()?;
            nrfxlib_sys::nrf_modem_gnss_power_mode_set(u32::from(config.power_mode) as _)
                .into_result()?;
            nrfxlib_sys::nrf_modem_gnss_timing_source_set(u32::from(config.timing_source) as _)
                .into_result()?;
        }
        Ok(())
    }

    pub async fn deactivate(self) -> Result<(), Error> {
        core::mem::forget(self);
        let result = crate::MODEM_RUNTIME_STATE.deactivate_gps().await;

        if result.is_err() {
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }

        result
    }
}

impl Drop for Gnss {
    fn drop(&mut self) {
        #[cfg(feature = "defmt")]
        defmt::warn!(
            "Turning off GNSS synchronously. Use async function `deactivate` to avoid blocking and to get more guarantees that the modem is actually shut off."
        );

        if let Err(_e) = crate::MODEM_RUNTIME_STATE.deactivate_gps_blocking() {
            #[cfg(feature = "defmt")]
            defmt::error!("Could not turn off the gnss: {}", _e);
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }
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
            .then_some(nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GGA_MASK as u16)
            .unwrap_or(0)
            | mask
                .gll
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GLL_MASK as u16)
                .unwrap_or(0)
            | mask
                .gsa
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GSA_MASK as u16)
                .unwrap_or(0)
            | mask
                .gsv
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_NMEA_GSV_MASK as u16)
                .unwrap_or(0)
            | mask
                .rmc
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_NMEA_RMC_MASK as u16)
                .unwrap_or(0)
    }
}

#[derive(Copy, Clone, IntoPrimitive, FromPrimitive, Debug, Default)]
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
    pub elevation_threshold_angle: u8,
    pub use_case: GnssUsecase,
    pub nmea_mask: NmeaMask,
    pub timing_source: GnssTimingSource,
    pub power_mode: GnssPowerSaveMode,
}

impl Default for GnssConfig {
    fn default() -> Self {
        Self {
            elevation_threshold_angle: 5,
            use_case: Default::default(),
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
    pub low_accuracy: bool,
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
    pub scheduled_downloads_disable: bool,
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
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_USE_CASE_LOW_ACCURACY as u8)
                .unwrap_or(0)
            | usecase
                .scheduled_downloads_disable
                .then_some(nrfxlib_sys::NRF_MODEM_GNSS_USE_CASE_SCHED_DOWNLOAD_DISABLE as u8)
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

/// An enum containing all possible GNSS data types
#[derive(Debug, Clone)]
pub enum GnssData {
    /// A PVT value
    PositionVelocityTime(nrfxlib_sys::nrf_modem_gnss_pvt_data_frame),
    /// An NMEA string
    Nmea(ArrayString<83>),
    /// An assisted gps data frame
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
                let mut data: MaybeUninit<nrfxlib_sys::nrf_modem_gnss_nmea_data_frame> =
                    MaybeUninit::uninit();

                unsafe {
                    nrfxlib_sys::nrf_modem_gnss_read(
                        data.as_mut_ptr() as *mut _,
                        size_of::<nrfxlib_sys::nrf_modem_gnss_nmea_data_frame>() as i32,
                        data_type as u32 as _,
                    )
                    .into_result()?;

                    let data = data.assume_init().nmea_str;
                    let mut string_data = ArrayString::from_byte_string(&data)?;
                    string_data.truncate(
                        string_data
                            .as_bytes()
                            .iter()
                            .take_while(|b| **b != 0)
                            .count(),
                    );
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

/// An async stream of gnss data.
///
/// Implements the [futures::Stream] trait for polling.
pub struct GnssStream {
    single_fix: bool,
    done: bool,
    gnss: Option<Gnss>,
}

impl GnssStream {
    fn new(single_fix: bool, gnss: Gnss) -> Self {
        GNSS_NOTICED_EVENTS.store(0, Ordering::SeqCst);
        Self {
            single_fix,
            done: false,
            gnss: Some(gnss),
        }
    }

    pub async fn deactivate(self) -> Result<(), Error> {
        self.free().deactivate().await
    }

    /// Get back the gnss instance
    pub fn free(mut self) -> Gnss {
        self.gnss.take().unwrap()
    }
}

impl Stream for GnssStream {
    type Item = Result<GnssData, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            #[cfg(feature = "defmt")]
            defmt::trace!("Gnss is done");

            return Poll::Ready(None);
        }

        let event_bits = GNSS_NOTICED_EVENTS.load(Ordering::SeqCst);
        let event = GnssEventType::get_from_bit_packed(event_bits);

        let mut left_over_nmea_strings = false;

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
            GnssEventType::Nmea => critical_section::with(|cs| {
                let mut strings = GNSS_NMEA_STRINGS.borrow_ref_mut(cs);
                left_over_nmea_strings = strings.len() > 1;
                strings.pop_at(0)
            }),
            GnssEventType::AgpsRequest => Some(GnssData::read_from_modem(GnssDataType::Agps)),
            GnssEventType::RetryTimeoutReached | GnssEventType::SleepAfterFix
                if self.single_fix =>
            {
                self.get_mut().done = true;
                return Poll::Ready(None);
            }
            _ => None,
        };

        let left_over_event_bits = if !left_over_nmea_strings {
            GNSS_NOTICED_EVENTS.fetch_and(!(1 << event as u32), Ordering::SeqCst) != 0
        } else {
            true
        };

        if left_over_event_bits {
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

impl Drop for GnssStream {
    fn drop(&mut self) {
        unsafe {
            #[cfg(feature = "defmt")]
            defmt::debug!("Stopping gnss");

            nrfxlib_sys::nrf_modem_gnss_stop();
        }
    }
}
