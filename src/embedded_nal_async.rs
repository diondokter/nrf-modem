use crate::DnsQuery;

/// Modem struct implementing [`embedded-nal-async`] traits.
///
/// Only available with `feature = "embedded-nal-async"`.
///
/// NOTE: Reverse DNS lookups are not supported.
/// The `get_host_by_address()` function will always report an error.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ModemNal;

impl embedded_nal_async::Dns for ModemNal {
    type Error = crate::Error;

    async fn get_host_by_name(
        &self,
        hostname: &str,
        addr_type: embedded_nal_async::AddrType,
    ) -> Result<core::net::IpAddr, Self::Error> {
        let query = DnsQuery::new(hostname).with_address_type(addr_type.into());
        crate::dns::resolve_dns(query).await
    }

    async fn get_host_by_address(
        &self,
        _addr: core::net::IpAddr,
        _result: &mut [u8],
    ) -> Result<usize, Self::Error> {
        Err(crate::Error::ReverseDnsLookupNotSupported)
    }
}

impl embedded_nal_async::TcpConnect for ModemNal {
    type Error = crate::Error;

    type Connection<'a> = crate::TcpStream;

    async fn connect<'a>(
        &'a self,
        remote: core::net::SocketAddr,
    ) -> Result<Self::Connection<'a>, Self::Error> {
        crate::TcpStream::connect(remote).await
    }
}

impl From<embedded_nal_async::AddrType> for crate::dns::AddrType {
    fn from(value: embedded_nal_async::AddrType) -> Self {
        match value {
            embedded_nal_async::AddrType::Either => Self::Any,
            embedded_nal_async::AddrType::IPv4 => Self::V4,
            embedded_nal_async::AddrType::IPv6 => Self::V6,
        }
    }
}
