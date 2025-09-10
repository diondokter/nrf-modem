#[cfg(not(feature = "dns-async"))]
mod dns_blocking;

#[cfg(not(feature = "dns-async"))]
pub use dns_blocking::{
    get_host_by_name, get_host_by_name_with_cancellation, resolve_dns,
    resolve_dns_with_cancellation,
};

#[cfg(feature = "dns-async")]
mod dns_async;

#[cfg(feature = "dns-async")]
mod dns_cache;

#[cfg(feature = "dns-async")]
pub use dns_async::{
    get_host_by_name, get_host_by_name_with_cancellation, resolve_dns,
    resolve_dns_with_cancellation,
};

/// A DNS query.
///
/// Pass to [`resolve_dns()`] or [`resolve_dns_with_cancellation()`].
#[derive(Copy, Clone, Debug)]
pub struct DnsQuery<'a> {
    /// The hostname to resolve.
    hostname: &'a str,

    /// The desired address type.
    addr_type: AddrType,
}

impl<'a> DnsQuery<'a> {
    /// Create a new DNS query to resolve a given hostname.
    ///
    /// Does not restrict the address type to resolve.
    pub fn new(hostname: &'a str) -> Self {
        Self {
            hostname,
            addr_type: AddrType::Any,
        }
    }

    /// Set the address type of the query.
    ///
    /// Can be used to ask only for an IPv4 or IPv6 address.
    #[must_use = "this function returns a new query, it does not modify the existing one"]
    pub fn with_address_type(self, addr_type: AddrType) -> Self {
        let mut out = self;
        out.addr_type = addr_type;
        out
    }

    /// Get the hostname to resolve.
    pub fn hostname(&self) -> &'a str {
        self.hostname
    }

    /// Get the address type of the query.
    pub fn addr_type(&self) -> AddrType {
        self.addr_type
    }
}

/// The address type for a DNS query.
#[derive(Copy, Clone, Debug)]
pub enum AddrType {
    /// Resolve to an IPv4 or IPv6 address.
    Any,

    /// Resolve to an IPv4 address.
    V4,

    /// Resolve to an IPv6 address.
    V6,
}

impl AddrType {
    /// Check if the given IP address matches the address type.
    fn addr_matches(&self, addr: core::net::IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => matches!(addr, core::net::IpAddr::V4(_)),
            Self::V6 => matches!(addr, core::net::IpAddr::V6(_)),
        }
    }
}
