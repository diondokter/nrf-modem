//! Helper utility to configure a specific modem context.

// Modified from embassy-rs:
// Licence: https://github.com/embassy-rs/embassy/blob/main/LICENSE-APACHE
// Source file: https://github.com/embassy-rs/embassy/blob/a8cb8a7fe1f594b765dee4cfc6ff3065842c7c6e/embassy-net-nrf91/src/context.rs

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use at_commands::builder::CommandBuilder;
use at_commands::parser::CommandParser;
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embassy_time::{Duration, Timer};
use heapless::Vec;

use crate::{embassy_net_modem::CAP_SIZE, Error, LteLink};

const DNS_VEC_SIZE: usize = 2;

/// Provides a higher level API for controlling a given context.
pub struct Control<'a> {
    control: super::Control<'a>,
    cid: u8,
    lte_link: Mutex<CriticalSectionRawMutex, Option<LteLink>>,
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

/// Status of a given context.
#[derive(Debug, Clone)]
pub struct Status {
    /// Attached to APN or not.
    pub attached: bool,
    /// IPv4 link.
    pub ipv4_link: Option<LinkInfo<Ipv4Addr>>,
    /// IPv6 link.
    pub ipv6_link: Option<LinkInfo<Ipv6Addr>>,
}

#[derive(Debug, Clone)]
pub struct LinkInfo<AddrType: Clone> {
    /// IP if provided.
    pub ip: AddrType,
    /// Gateway if provided.
    pub gateway: Option<AddrType>,
    /// DNS servers if provided. The modem can return a maximum of 2 DNS servers.
    pub dns: Vec<AddrType, DNS_VEC_SIZE>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Status {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "attached: {}", self.attached);
        if let Some(ipv4_link) = &self.ipv4_link {
            defmt::write!(f, ", ipv4: {}", defmt::Debug2Format(&ipv4_link));
        }
        if let Some(ipv6_link) = &self.ipv6_link {
            defmt::write!(f, ", ipv6: {}", defmt::Debug2Format(&ipv6_link));
        }
    }
}

/// The detected kind of address for this +CGCONTRDP message
#[derive(Debug, Clone, PartialEq, Eq)]
enum CgcontrdpOutputKind {
    V4(CgcontrdpOutput<Ipv4Addr>),
    V6(CgcontrdpOutput<Ipv6Addr>),
}

// Output of parsing function.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CgcontrdpOutput<AddrType> {
    pub gateway: Option<AddrType>,
    pub dns: Vec<AddrType, DNS_VEC_SIZE>,
}

// Parse one +CGCONTRDP: message, without the leading "+CGCONTRDP:".
//
// The challenge here is that the first section can either be IPv4 or IPv6 according to the documentation.
// So we have to detect which IP version is used and ensure that all the values in this section use
// the same version.
fn parse_cgcontrdp_section(at_part: &str) -> Result<Option<CgcontrdpOutputKind>, Error> {
    let (_cid, _bid, _apn, _mask, gateway, dns1, dns2, _, _, _, _, _mtu) =
        CommandParser::parse(at_part.as_bytes())
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
            .finish()?;

    // None means we didn't read a valid address yet.
    let mut is_ipv4 = None;

    let gateway = if let Some(ip) = gateway {
        if ip.is_empty() {
            None
        } else {
            let parsed = IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?;
            match parsed {
                IpAddr::V4(_) => {
                    is_ipv4.replace(true);
                }
                IpAddr::V6(_) => {
                    is_ipv4.replace(false);
                }
            }
            Some(parsed)
        }
    } else {
        None
    };

    const {
        assert!(
            DNS_VEC_SIZE >= 2,
            "Vec holding the DNS must have a capacity of at least 2"
        )
    }
    let mut dns: Vec<IpAddr, DNS_VEC_SIZE> = Vec::new();
    if let Some(ip) = dns1 {
        if !ip.is_empty() {
            let parsed = IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?;
            match parsed {
                IpAddr::V4(_) => {
                    is_ipv4.replace(true);
                }
                IpAddr::V6(_) => {
                    is_ipv4.replace(false);
                }
            }
            // Won't panic as we never push more than 2 elements
            dns.push(parsed).unwrap();
        }
    }

    if let Some(ip) = dns2 {
        if !ip.is_empty() {
            let parsed = IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)?;
            match parsed {
                IpAddr::V4(_) => {
                    is_ipv4.replace(true);
                }
                IpAddr::V6(_) => {
                    is_ipv4.replace(false);
                }
            }
            // Won't panic as we never push more than 2 elements
            dns.push(parsed).unwrap();
        }
    }

    match is_ipv4 {
        // IPv4 addresses
        Some(true) => {
            let mut dns_out: Vec<_, DNS_VEC_SIZE> = Vec::new();
            for addr in dns.iter() {
                // push will never panic, both Vecs are the same size.
                dns_out.push(transform_to_v4(*addr)?).unwrap()
            }
            Ok(Some(CgcontrdpOutputKind::V4(CgcontrdpOutput {
                gateway: gateway.map(transform_to_v4).transpose()?,
                dns: dns_out,
            })))
        }
        // IPv6 addersses
        Some(false) => {
            let mut dns_out: Vec<_, DNS_VEC_SIZE> = Vec::new();
            for addr in dns.iter() {
                // push will never panic, both Vecs are the same size.
                dns_out.push(transform_to_v6(*addr)?).unwrap()
            }
            Ok(Some(CgcontrdpOutputKind::V6(CgcontrdpOutput {
                gateway: gateway.map(transform_to_v6).transpose()?,
                dns: dns_out,
            })))
        }
        // There was no address specified in any of the fields
        None => Ok(None),
    }
}

// Returns the inner IPv4 address or errors out if it isn't one.
fn transform_to_v4(ip: IpAddr) -> Result<Ipv4Addr, Error> {
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(Error::AddrParseError),
    }
}

// Returns the inner IPv6 address or errors out if it isn't one.
fn transform_to_v6(ip: IpAddr) -> Result<Ipv6Addr, Error> {
    match ip {
        IpAddr::V4(_) => Err(Error::AddrParseError),
        IpAddr::V6(ip) => Ok(ip),
    }
}

impl<'a> Control<'a> {
    /// Create a new instance of a control handle for a given context.
    ///
    /// Will wait for the modem to be initialized if not.
    ///
    /// `cid` indicates which PDP context to use, range 0-10.
    pub async fn new(control: super::Control<'a>, cid: u8) -> Self {
        Self {
            control,
            cid,
            lte_link: Mutex::new(None),
        }
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

        if let Some(link) = self.lte_link.lock().await.take() {
            link.deactivate().await?;
        }

        let mut op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGDCONT")
            .with_int_parameter(self.cid)
            .with_string_parameter::<&str>(config.pdp_type.into());
        if let Some(apn) = config.apn {
            op = op.with_string_parameter(apn);
        }
        let op = op.finish().map_err(|s| Error::BufferTooSmall(Some(s)))?;

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
            let op = op.finish().map_err(|s| Error::BufferTooSmall(Some(s)))?;

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
                .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
                ipv4_link: None,
                ipv6_link: None,
            });
        }

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGPADDR")
            .with_int_parameter(self.cid)
            .finish()
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
        let n = self.control.at_command(op).await;
        let (_, ip1, ip2) = CommandParser::parse(n.as_bytes())
            .expect_identifier(b"+CGPADDR: ")
            .expect_int_parameter()
            .expect_optional_string_parameter()
            .expect_optional_string_parameter()
            .expect_identifier(b"\r\nOK")
            .finish()?;

        let mut ipv4 = None;
        let mut ipv6 = None;

        // First position can be either IPv4 or IPv6.
        if let Some(ip) = ip1 {
            match IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)? {
                IpAddr::V4(ip) => {
                    let _ = ipv4.replace(ip);
                }
                IpAddr::V6(ip) => {
                    let _ = ipv6.replace(ip);
                }
            };
        }

        // According to Nordic's doc, the second IP should always be IPv6.
        if let Some(ip) = ip2 {
            match IpAddr::from_str(ip).map_err(|_| Error::AddrParseError)? {
                IpAddr::V4(_) => {
                    return Err(Error::AddrParseError);
                }
                IpAddr::V6(ip) => {
                    // We replace the pevious IP address, we don't cover the case where there was already one.
                    let _ = ipv6.replace(ip);
                }
            };
        }

        #[cfg(feature = "defmt")]
        defmt::debug!("IPv4: {:?}, IPv6: {:?}", ipv4, ipv6);

        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("+CGCONTRDP")
            .with_int_parameter(self.cid)
            .finish()
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
        let n = self.control.at_command(op).await;

        // In dual stack mode, the modem returns 2 `+CGCONTRDP:` lines, one for IPv4 and one for IPv6.
        // This is too long to be parsed by the at_commands crate so we split it.
        let mut sections = n.as_str().split("+CGCONTRDP: ");

        // Separators at the start or end of a string are neighbored by empty strings.
        // We consume the empty string.
        sections.next();

        let mut ipv4_link = ipv4.map(|ip| LinkInfo {
            ip,
            dns: Vec::new(),
            gateway: None,
        });

        let mut ipv6_link = ipv6.map(|ip| LinkInfo {
            ip,
            dns: Vec::new(),
            gateway: None,
        });

        // First section can either be IPv4 or IPv6. There should always be at least one +CGCONTRDP line.
        let section = sections.next().ok_or(Error::UnexpectedAtResponse)?;
        let output = parse_cgcontrdp_section(section)?;

        match output {
            Some(CgcontrdpOutputKind::V4(output)) => {
                ipv4_link = ipv4_link.map(|l| LinkInfo {
                    ip: l.ip,
                    gateway: output.gateway,
                    dns: output.dns,
                });
            }
            Some(CgcontrdpOutputKind::V6(output)) => {
                ipv6_link = ipv6_link.map(|l| LinkInfo {
                    ip: l.ip,
                    gateway: output.gateway,
                    dns: output.dns,
                });
            }
            None => {
                // No gateway or dns returned, we have nothing to add.
            }
        }

        // Second section means dual-stack, this should always be IPv6.
        if let Some(section) = sections.next() {
            let output = parse_cgcontrdp_section(section)?;

            match output {
                Some(CgcontrdpOutputKind::V4(_)) => {
                    return Err(Error::UnexpectedAtResponse);
                }
                Some(CgcontrdpOutputKind::V6(output)) => {
                    ipv6_link = ipv6_link.map(|l| LinkInfo {
                        ip: l.ip,
                        gateway: output.gateway,
                        dns: output.dns,
                    })
                }
                None => {
                    // No gateway or dns returned, we have nothing to add.
                }
            }
        }

        Ok(Status {
            attached,
            ipv4_link,
            ipv6_link,
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
        if let Some(link) = self.lte_link.lock().await.take() {
            link.deactivate().await?;
        };
        Ok(())
    }

    /// Enable modem
    pub async fn enable(&self) -> Result<(), Error> {
        let mut cmd: [u8; 256] = [0; 256];

        self.lte_link.lock().await.replace(LteLink::new().await?);

        // Make modem survive PDN detaches
        let op = CommandBuilder::create_set(&mut cmd, true)
            .named("%XPDNCFG")
            .with_int_parameter(1)
            .finish()
            .map_err(|s| Error::BufferTooSmall(Some(s)))?;
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
