//! Helper utility to configure a specific modem context.

// Modified from embassy-rs:
// Licence: https://github.com/embassy-rs/embassy/blob/main/LICENSE-APACHE
// Source file: https://github.com/embassy-rs/embassy/blob/a8cb8a7fe1f594b765dee4cfc6ff3065842c7c6e/embassy-net-nrf91/src/context.rs

use core::net::IpAddr;
use core::str::FromStr;

use at_commands::builder::CommandBuilder;
use at_commands::parser::CommandParser;
use embassy_time::{Duration, Timer};
use heapless::Vec;

use crate::embassy_net_modem::CAP_SIZE;

/// Provides a higher level API for controlling a given context.
pub struct Control<'a> {
    control: super::Control<'a>,
    cid: u8,
}

/// Authentication parameters for the Packet Data Network (PDN).
pub struct PdnAuth<'a> {
    /// Desired authentication protocol.
    pub auth_prot: AuthProt,
    /// Credentials to connect to the network.
    pub auth: Option<(&'a [u8], &'a [u8])>,
}

/// Packet domain configuration to be applied to a context.
pub struct PdConfig<'a> {
    /// Desired Access Point Name (APN) to connect to. Set to None to keep the SIM defaults.
    pub apn: Option<&'a [u8]>,
    /// Desired authentication parameters, setting this to `None` will not
    /// execute the `+CGAUTH` AT command, keeping the defaults for this SIM.
    pub pdn_auth: Option<PdnAuth<'a>>,
    /// Packet Domain Protocol type.
    pub pdp_type: PdpType,
}

/// Which type of communication happens on this PDP
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PdpType {
    /// IPv4
    Ip,
    /// IPv6
    Ipv6,
    /// Dual IP stack
    Ipv4v6,
    /// Non-IP data
    NonIp,
}

// https://docs.nordicsemi.com/bundle/ref_at_commands/page/REF/at_commands/packet_domain/cgdcont_set.html
impl<'a> From<PdpType> for &'a str {
    fn from(val: PdpType) -> &'a str {
        match val {
            PdpType::Ip => "IP",
            PdpType::Ipv6 => "IPV6",
            PdpType::Ipv4v6 => "IPV4V6",
            PdpType::NonIp => "Non-IP",
        }
    }
}

/// Authentication protocol.
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AuthProt {
    /// No authentication.
    None = 0,
    /// PAP authentication.
    Pap = 1,
    /// CHAP authentication.
    Chap = 2,
}

/// Error returned by control.
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Not enough space for command.
    BufferTooSmall,
    /// Error parsing response from modem.
    AtParseError,
    /// Error parsing IP addresses.
    AddrParseError,
}

impl From<at_commands::parser::ParseError> for Error {
    fn from(_: at_commands::parser::ParseError) -> Self {
        Self::AtParseError
    }
}

/// Status of a given context.
#[derive(PartialEq, Debug)]
pub struct Status {
    /// Attached to APN or not.
    pub attached: bool,
    /// IP if assigned. Can be IPv4 or IPv6. In dual stack mode this will always be an IPv4 address.
    pub ip1: Option<IpAddr>,
    /// Second IP if assigned, happens in dual stack where this will always be an IPv6 address.
    pub ip2: Option<IpAddr>,
    /// Gateway if assigned.
    pub gateway: Option<IpAddr>,
    /// DNS servers if assigned. The modem can return a maximum of 2 DNS servers.
    pub dns: Vec<IpAddr, 2>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Status {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "attached: {}", self.attached);
        if let Some(ip1) = &self.ip1 {
            defmt::write!(f, ", ip1: {}", defmt::Debug2Format(&ip1));
        }
        if let Some(ip2) = &self.ip2 {
            defmt::write!(f, ", ip2: {}", defmt::Debug2Format(&ip2));
        }
    }
}

impl<'a> Control<'a> {
    /// Create a new instance of a control handle for a given context.
    ///
    /// Will wait for the modem to be initialized if not.
    ///
    /// `cid` indicates which PDP context to use, range 0-10.
    pub async fn new(control: super::Control<'a>, cid: u8) -> Self {
        Self { control, cid }
    }

    /// Perform a raw AT command
    pub async fn at_command(self, req: &[u8]) -> arrayvec::ArrayString<CAP_SIZE> {
        self.control.at_command(req).await
    }

    /// Configures the modem with the provided config.
    ///
    /// NOTE: This will disconnect the modem from any current APN and should not
    /// be called if the configuration has not been changed.
    ///
    /// After configuring, invoke [Self::enable] to activate the configuration.
    pub async fn configure(&self, config: &PdConfig<'_>, pin: Option<&[u8]>) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CFUN")
            .with_int_parameter(0)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;

        let mut op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGDCONT")
            .with_int_parameter(self.cid)
            .with_string_parameter::<&str>(config.pdp_type.into());
        if let Some(apn) = config.apn {
            op = op.with_string_parameter(apn);
        }
        let op = op.finish().map_err(|_| Error::BufferTooSmall)?;

        let n = self.control.at_command(op).await;
        // info!("RES1: {}", unsafe { core::str::from_utf8_unchecked(&buf[..n]) });
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;

        if let Some(pdn_auth) = &config.pdn_auth {
            let mut op = CommandBuilder::create_set(&mut cmd, true)
                .named("+CGAUTH")
                .with_int_parameter(self.cid)
                .with_int_parameter(pdn_auth.auth_prot as u8);
            if let Some((username, password)) = pdn_auth.auth {
                op = op
                    .with_string_parameter(username)
                    .with_string_parameter(password);
            }
            let op = op.finish().map_err(|_| Error::BufferTooSmall)?;

            let n = self.control.at_command(op).await;
            // info!("RES2: {}", unsafe { core::str::from_utf8_unchecked(&buf[..n]) });
            CommandParser::parse(n.as_bytes())
                .expect_identifier(b"OK")
                .finish()?;
        }

        if let Some(pin) = pin {
            let op = CommandBuilder::create_set(&mut cmd, true)
                .named("+CPIN")
                .with_string_parameter(pin)
                .finish()
                .map_err(|_| Error::BufferTooSmall)?;
            let _ = self.control.at_command(op).await;
            // Ignore ERROR which means no pin required
        }

        Ok(())
    }

    /// Attach to the PDN
    pub async fn attach(&self) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];
        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGATT")
            .with_int_parameter(1)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;
        Ok(())
    }

    /// Read current connectivity status for modem.
    pub async fn detach(&self) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];
        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGATT")
            .with_int_parameter(0)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;
        Ok(())
    }

    async fn attached(&self) -> Result<bool, Error> {
        let mut cmd: [u8; 256] = [0; 256];

        let op = CommandBuilder::create_query(&mut cmd, true)
            .named("+CGATT")
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        let (res,) = CommandParser::parse(n.as_bytes())
            .expect_identifier(b"+CGATT: ")
            .expect_int_parameter()
            .expect_identifier(b"\r\nOK")
            .finish()?;
        Ok(res == 1)
    }

    /// Read current connectivity status for modem.
    pub async fn status(&self) -> Result<Status, Error> {
        let mut cmd: [u8; 256] = [0; 256];

        let op = CommandBuilder::create_query(&mut cmd, true)
            .named("+CGATT")
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        let (res,) = CommandParser::parse(n.as_bytes())
            .expect_identifier(b"+CGATT: ")
            .expect_int_parameter()
            .expect_identifier(b"\r\nOK")
            .finish()?;
        let attached = res == 1;
        if !attached {
            return Ok(Status {
                attached,
                ip1: None,
                ip2: None,
                gateway: None,
                dns: Vec::new(),
            });
        }

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGPADDR")
            .with_int_parameter(self.cid)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        let (_, ip1, ip2) = CommandParser::parse(n.as_bytes())
            .expect_identifier(b"+CGPADDR: ")
            .expect_int_parameter()
            .expect_optional_string_parameter()
            .expect_optional_string_parameter()
            .expect_identifier(b"\r\nOK")
            .finish()?;

        let ip1 = if let Some(ip) = ip1 {
            let ip = IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?;
            Some(ip)
        } else {
            None
        };

        let ip2 = if let Some(ip) = ip2 {
            let ip = IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?;
            Some(ip)
        } else {
            None
        };

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGCONTRDP")
            .with_int_parameter(self.cid)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        let (_cid, _bid, _apn, _mask, gateway, dns1, dns2, _, _, _, _, _mtu) =
            CommandParser::parse(n.as_bytes())
                .expect_identifier(b"+CGCONTRDP: ")
                .expect_int_parameter()
                .expect_optional_int_parameter()
                .expect_optional_string_parameter()
                .expect_optional_string_parameter()
                .expect_optional_string_parameter()
                .expect_optional_string_parameter()
                .expect_optional_string_parameter()
                .expect_optional_int_parameter()
                .expect_optional_int_parameter()
                .expect_optional_int_parameter()
                .expect_optional_int_parameter()
                .expect_optional_int_parameter()
                .expect_identifier(b"\r\nOK")
                .finish()?;

        let gateway = if let Some(ip) = gateway {
            if ip.is_empty() {
                None
            } else {
                Some(IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?)
            }
        } else {
            None
        };

        let mut dns = Vec::new();
        if let Some(ip) = dns1 {
            dns.push(IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?)
                .unwrap();
        }

        if let Some(ip) = dns2 {
            dns.push(IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?)
                .unwrap();
        }

        Ok(Status {
            attached,
            ip1,
            ip2,
            gateway,
            dns,
        })
    }

    async fn wait_attached(&self) -> Result<Status, Error> {
        while !self.attached().await? {
            Timer::after(Duration::from_secs(1)).await;
        }
        let status = self.status().await?;
        Ok(status)
    }

    /// Disable modem
    pub async fn disable(&self) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CFUN")
            .with_int_parameter(0)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;

        Ok(())
    }

    /// Enable modem
    pub async fn enable(&self) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CFUN")
            .with_int_parameter(1)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;

        // Make modem survive PDN detaches
        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("%XPDNCFG")
            .with_int_parameter(1)
            .finish()
            .map_err(|_| Error::BufferTooSmall)?;
        let n = self.control.at_command(op).await;
        CommandParser::parse(n.as_bytes())
            .expect_identifier(b"OK")
            .finish()?;
        Ok(())
    }

    /// Run a control loop for this context, ensuring that reaattach is handled.
    pub async fn run<F: Fn(&Status)>(&self, reattach: F) -> Result<(), Error> {
        self.enable().await?;
        let status = self.wait_attached().await?;
        self.control.open_raw_socket().await;
        reattach(&status);

        loop {
            if !self.attached().await? {
                self.control.close_raw_socket().await;
                let status = self.wait_attached().await?;
                self.control.open_raw_socket().await;
                reattach(&status);
            }
            Timer::after(Duration::from_secs(10)).await;
        }
    }
}
