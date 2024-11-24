#[cfg(not(feature = "dns-async"))]
mod dns_blocking;

#[cfg(not(feature = "dns-async"))]
pub use dns_blocking::{get_host_by_name, get_host_by_name_with_cancellation};

#[cfg(feature = "dns-async")]
mod dns_async;

#[cfg(feature = "dns-async")]
mod dns_cache;

#[cfg(feature = "dns-async")]
pub use dns_async::{get_host_by_name, get_host_by_name_with_cancellation};
