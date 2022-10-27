//! Implementation of [LteLink]

use crate::{at, at_notifications::AtNotificationStream, error::Error};
use core::{
    mem,
    ops::ControlFlow,
    sync::atomic::{AtomicU32, Ordering},
};

static ACTIVE_LINKS: AtomicU32 = AtomicU32::new(0);

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
pub struct LteLink(());

impl Clone for LteLink {
    fn clone(&self) -> Self {
        ACTIVE_LINKS.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl LteLink {
    /// Create a new instance
    pub async fn new() -> Result<Self, Error> {
        if ACTIVE_LINKS.fetch_add(1, Ordering::SeqCst) == 0 {
            // We have to activate the modem
            #[cfg(feature = "defmt")]
            defmt::debug!("Enabling modem LTE");

            // Set Ultra low power mode
            crate::at::send_at::<0>("AT%XDATAPRFL=0").await?;
            // Set UICC low power mode
            crate::at::send_at::<0>("AT+CEPPI=1").await?;
            // Activate LTE without changing GNSS
            crate::at::send_at::<0>("AT+CFUN=21").await?;
        }

        Ok(LteLink(()))
    }

    /// While there is an instance, the modem is active.
    /// But that does not mean that there is access to the network.
    ///
    /// Call this function to wait until there is a connection.
    pub async fn wait_for_link(&self) -> Result<(), Error> {
        use futures::StreamExt;

        // We're gonna be looking for notifications. And to make sure we don't miss one,
        // we already create the stream and register it.
        let notification_stream = AtNotificationStream::<64, 4>::new().await;
        futures::pin_mut!(notification_stream);
        notification_stream.as_mut().register().await;

        // Enable the notifications
        at::send_at::<0>("AT+CEREG=1").await?;

        // We won't get a notification if we're already connected.
        // So query the current status
        match Self::get_cereg_stat_control_flow(Self::parse_cereg(
            at::send_at::<64>("AT+CEREG?").await?.as_str(),
        )) {
            ControlFlow::Continue(_) => {}
            ControlFlow::Break(result) => return result,
        }

        // We are currently not connected, so lets wait for what the stream turns up
        let mut stream = notification_stream
            .map(|notif| Self::get_cereg_stat_control_flow(Self::parse_cereg(notif.as_str())));

        while let Some(cereg) = stream.next().await {
            match cereg {
                ControlFlow::Continue(_) => {}
                ControlFlow::Break(result) => return result,
            }
        }

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

        if ACTIVE_LINKS.fetch_sub(1, Ordering::SeqCst) == 1 {
            // Turn off the network side of the modem
            crate::at::send_at::<0>("AT+CFUN=20").await?;
        }

        Ok(())
    }
}

impl Drop for LteLink {
    fn drop(&mut self) {
        if ACTIVE_LINKS.fetch_sub(1, Ordering::SeqCst) == 1 {
            #[cfg(feature = "defmt")]
            defmt::debug!(
                "Turning off LTE synchronously. Use async function `deactivate` to avoid blocking."
            );

            // Turn off the network side of the modem
            // We need to send this blocking because we don't have async drop yet
            crate::at::send_at_blocking::<0>("AT+CFUN=20").unwrap();
        }
    }
}
