//! Implementation of [UiccLink]
use crate::Error;

/// An object that keeps the UICC (Universal Integrated Circuit Card).
/// As long as there is an instance, the UICC will be kept on.
/// The drop function disables the UICC if there is no link left.
///
/// You can use this object to power on the UICC and interact with the SIM card,
/// without keeping other parts of the modem powered on.
/// If you already use LTE, you do not need to explicitly power on the UICC.
///
/// You do not need to create a UICC link for any of the structs in the crate to work.
/// However, you may need this if you are manually executing AT commands to interact with the SIM card.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UiccLink(());

impl UiccLink {
    /// Create a new instance
    pub async fn new() -> Result<Self, Error> {
        if unsafe { !nrfxlib_sys::nrf_modem_is_initialized() } {
            return Err(Error::ModemNotInitialized);
        }

        crate::MODEM_RUNTIME_STATE.activate_uicc().await?;

        Ok(Self(()))
    }

    /// Deactivates the UICC if it is no longer in use.
    ///
    /// This does the same as dropping the instance, but in an async manner.
    pub async fn deactivate(self) -> Result<(), Error> {
        core::mem::forget(self);
        let result = crate::MODEM_RUNTIME_STATE.deactivate_uicc().await;

        if result.is_err() {
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }

        result
    }
}

impl Drop for UiccLink {
    fn drop(&mut self) {
        #[cfg(feature = "defmt")]
        defmt::warn!(
            "Turning off UICC synchronously. Use async function `deactivate` to avoid blocking and to get more guarantees that the modem is actually shut off."
        );

        if let Err(_e) = crate::MODEM_RUNTIME_STATE.deactivate_uicc_blocking() {
            #[cfg(feature = "defmt")]
            defmt::error!("Could not turn off the UICC: {}", _e);
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }
    }
}
