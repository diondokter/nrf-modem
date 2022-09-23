use crate::{at, at_notifications, error::Error};
use core::{
    ops::ControlFlow,
    sync::atomic::{AtomicU32, Ordering},
};

static ACTIVE_LINKS: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, PartialEq, Eq)]
pub struct LteLink(());

impl Clone for LteLink {
    fn clone(&self) -> Self {
        ACTIVE_LINKS.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl LteLink {
    pub async fn new() -> Result<Self, Error> {
        if ACTIVE_LINKS.fetch_add(1, Ordering::SeqCst) == 0 {
            // We have to activate the modem
            #[cfg(feature = "defmt")]
            defmt::debug!("Enabling modem LTE");

            // Set Ultra low power mode
            crate::at::send_at("AT%XDATAPRFL=0").await?;
            // Set UICC low power mode
            crate::at::send_at("AT+CEPPI=1").await?;
            // Set Power Saving Mode (PSM)
            crate::at::send_at("AT+CPSMS=1").await?;
            // Activate LTE without changing GNSS
            crate::at::send_at("AT+CFUN=21").await?;
        }

        Ok(LteLink(()))
    }

    pub async fn wait_for_link(&self) -> Result<(), Error> {
        use futures::StreamExt;

        let notification_waiter = at_notifications::get_stream::<256, 4>()
            .filter_map(|notif| async move {
                match Self::get_cereg_stat_control_flow(Self::parse_cereg(notif.as_str())) {
                    ControlFlow::Continue(_) => None,
                    ControlFlow::Break(v) => Some(v),
                }
            })
            .take(1)
            .fold(Ok(()), |_, res| async { res });

        futures::join!(
            at::send_at("AT+CEREG=1"),
            at::send_at_notif("AT+CEREG?"),
            notification_waiter
        ).2
    }

    fn parse_cereg(string: &str) -> Result<i32, Error> {
        let cereg = at_commands::parser::CommandParser::parse(string.as_bytes())
            .expect_identifier(b"+CEREG:")
            .expect_int_parameter()
            .expect_int_parameter()
            .expect_identifier(b"\r\nOK\r\n")
            .finish()
            .map(|(_, stat)| stat);

        cereg.or_else(|_| {
            at_commands::parser::CommandParser::parse(string.as_bytes())
            .expect_identifier(b"+CEREG:")
            .expect_int_parameter()
            .expect_identifier(b"\r\n")
            .finish()
            .map(|(stat,)| stat)
        }).map_err(|e| e.into())
    }

    fn get_cereg_stat_control_flow(stat: Result<i32, Error>) -> ControlFlow<Result<(), Error>, ()> {
        match stat {
            Err(_) => ControlFlow::Continue(()),
            Ok(1) | Ok(5) => ControlFlow::Break(Ok(())),
            Ok(0) | Ok(2) | Ok(4) => ControlFlow::Continue(()),
            Ok(3) => ControlFlow::Break(Err(Error::LteRegistrationDenied)),
            Ok(90) => ControlFlow::Break(Err(Error::SimFailure)),
            _ => ControlFlow::Break(Err(Error::UnexpectedAtResponse)),
        }
    }
}

impl Drop for LteLink {
    fn drop(&mut self) {
        if ACTIVE_LINKS.fetch_sub(1, Ordering::SeqCst) == 1 {
            crate::at::send_at_blocking("AT+CFUN=20").unwrap();
        }
    }
}
