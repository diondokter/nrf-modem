//! Implementation of [LteLink]

use crate::{at, at_notifications::AtNotificationStream, error::Error, CancellationToken};
use core::{mem, ops::ControlFlow, task::Poll};

/// An object that keeps the modem connected.
/// As long as there is an instance, the modem will be kept on.
/// The drop function disables the modem if there is no link left.
///
/// Everything will work even if the user doesn't use this directly.
/// Every API that requires a network connection uses this internally.
///
/// However, this can lead to inefficiencies.
/// For example, if you do a dns request and then make a socket to connect to the IP,
/// the link will fall away in between.
///
/// The user can prevent this by creating his own instance that the user only drops when all network tasks are done.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LteLink(());

impl LteLink {
    /// Create a new instance
    pub async fn new() -> Result<Self, Error> {
        if unsafe { !nrfxlib_sys::nrf_modem_is_initialized() } {
            return Err(Error::ModemNotInitialized);
        }

        crate::MODEM_RUNTIME_STATE.activate_lte().await?;

        Ok(LteLink(()))
    }

    /// While there is an instance of the LteLink, the modem is active.
    /// But that does not mean that there is access to the network.
    ///
    /// Call this function to wait until there is a connection.
    pub async fn wait_for_link(&self) -> Result<(), Error> {
        self.wait_for_link_with_cancellation(&Default::default())
            .await
    }

    /// While there is an instance of the LteLink, the modem is active.
    /// But that does not mean that there is access to the network.
    ///
    /// Call this function to wait until there is a connection.
    pub async fn wait_for_link_with_cancellation(
        &self,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        use futures::StreamExt;

        token.bind_to_current_task().await;

        // We're gonna be looking for notifications. And to make sure we don't miss one,
        // we already create the stream and register it.
        let notification_stream = AtNotificationStream::<64, 4>::new().await;
        futures::pin_mut!(notification_stream);
        notification_stream.as_mut().register().await;

        // Enable the notifications
        at::send_at::<0>("AT+CEREG=1").await?;

        token.as_result()?;

        // We won't get a notification if we're already connected.
        // So query the current status
        match Self::get_cereg_stat_control_flow(Self::parse_cereg(
            at::send_at::<64>("AT+CEREG?").await?.as_str(),
        )) {
            ControlFlow::Continue(_) => {}
            ControlFlow::Break(result) => return result,
        }

        token.as_result()?;

        // We are currently not connected, so lets wait for what the stream turns up
        let mut stream = notification_stream
            .map(|notif| Self::get_cereg_stat_control_flow(Self::parse_cereg(notif.as_str())));

        while let Some(cereg) = core::future::poll_fn(|cx| {
            if token.is_cancelled() {
                Poll::Ready(None)
            } else {
                stream.poll_next_unpin(cx)
            }
        })
        .await
        {
            match cereg {
                ControlFlow::Continue(_) => {
                    token.as_result()?;
                }
                ControlFlow::Break(result) => return result,
            }
        }

        token.as_result()?;

        unreachable!()
    }

    fn parse_cereg(string: &str) -> Result<i32, Error> {
        // We can expect two kinds of strings here.
        // The first is the response to our query that ends with 'OK'.
        // The second is the notification string.

        let cereg = at_commands::parser::CommandParser::parse(string.as_bytes())
            .expect_identifier(b"+CEREG:")
            .expect_int_parameter()
            .expect_int_parameter()
            .expect_identifier(b"\r\nOK\r\n")
            .finish()
            .map(|(_, stat)| stat);

        cereg
            .or_else(|_| {
                at_commands::parser::CommandParser::parse(string.as_bytes())
                    .expect_identifier(b"+CEREG:")
                    .expect_int_parameter()
                    .expect_identifier(b"\r\n")
                    .finish()
                    .map(|(stat,)| stat)
            })
            .map_err(|e| e.into())
    }

    fn get_cereg_stat_control_flow(stat: Result<i32, Error>) -> ControlFlow<Result<(), Error>, ()> {
        // Based on the stat number, we know that state of the connection
        match stat {
            Err(_) => ControlFlow::Continue(()),
            Ok(1) | Ok(5) => ControlFlow::Break(Ok(())),
            Ok(0) | Ok(2) | Ok(4) => ControlFlow::Continue(()),
            Ok(3) => ControlFlow::Break(Err(Error::LteRegistrationDenied)),
            Ok(90) => ControlFlow::Break(Err(Error::SimFailure)),
            _ => ControlFlow::Break(Err(Error::UnexpectedAtResponse)),
        }
    }

    /// Deactivates Lte. This does the same as dropping the instance, but in an async manner.
    pub async fn deactivate(self) -> Result<(), Error> {
        mem::forget(self);
        let result = crate::MODEM_RUNTIME_STATE.deactivate_lte().await;

        if result.is_err() {
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }

        result
    }
}

impl Drop for LteLink {
    fn drop(&mut self) {
        #[cfg(feature = "defmt")]
        defmt::warn!(
            "Turning off LTE synchronously. Use async function `deactivate` to avoid blocking and to get more guarantees that the modem is actually shut off."
        );

        if let Err(_e) = crate::MODEM_RUNTIME_STATE.deactivate_lte_blocking() {
            #[cfg(feature = "defmt")]
            defmt::error!("Could not turn off the lte: {}", _e);
            crate::MODEM_RUNTIME_STATE.set_error_active();
        }
    }
}
