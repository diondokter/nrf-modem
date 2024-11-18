use crate::{ip::NrfSockAddr, lte_link::LteLink, CancellationToken, Error};
use arrayvec::ArrayString;
use core::str::FromStr;
use no_std_net::{IpAddr, SocketAddr};

/// Get the IP address that corresponds to the given hostname.
///
/// The modem has an internal cache so this process may be really quick.
/// If the hostname is not known internally or if it has expired, then it has to be requested from a DNS server.
///
/// While this function is async, the actual DNS bit is blocking because the modem sadly has no async API for this.
///
/// The modem API is capable of setting the dns server, but that's not yet implemented in this wrapper.
pub async fn get_host_by_name(hostname: &str) -> Result<IpAddr, Error> {
    get_host_by_name_with_cancellation(hostname, &Default::default()).await
}

/// Get the IP address that corresponds to the given hostname.
///
/// The modem has an internal cache so this process may be really quick.
/// If the hostname is not known internally or if it has expired, then it has to be requested from a DNS server.
///
/// While this function is async, the actual DNS bit is blocking because the modem sadly has no async API for this.
///
/// The modem API is capable of setting the dns server, but that's not yet implemented in this wrapper.
pub async fn get_host_by_name_with_cancellation(
    hostname: &str,
    token: &CancellationToken,
) -> Result<IpAddr, Error> {
    #[cfg(feature = "defmt")]
    defmt::debug!("Resolving dns hostname for \"{}\"", hostname);

    // If we can parse the hostname as an IP address, then we can save a whole lot of trouble
    if let Ok(ip) = hostname.parse() {
        return Ok(ip);
    }

    // The modem only deals with ascii
    if !hostname.is_ascii() {
        return Err(Error::HostnameNotAscii);
    }

    token.bind_to_current_task().await;

    // Make sure we have a network connection
    let link = LteLink::new().await?;
    link.wait_for_link_with_cancellation(token).await?;

    let mut found_ip = None;

    unsafe {
        let hints = nrfxlib_sys::nrf_addrinfo {
            ai_family: nrfxlib_sys::NRF_AF_UNSPEC as _,
            ai_socktype: nrfxlib_sys::NRF_SOCK_STREAM as _,

            ai_flags: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: core::ptr::null_mut(),
            ai_canonname: core::ptr::null_mut(),
            ai_next: core::ptr::null_mut(),
        };

        let mut result: *mut nrfxlib_sys::nrf_addrinfo = core::ptr::null_mut();

        // A hostname should at most be 256 chars, but we have a null char as well, so we add one
        let mut hostname =
            ArrayString::<257>::from_str(hostname).map_err(|_| Error::HostnameTooLong)?;
        hostname.push('\0');

        let err = nrfxlib_sys::nrf_getaddrinfo(
            hostname.as_ptr() as *const core::ffi::c_char,
            core::ptr::null(),
            &hints as *const _,
            &mut result as *mut *mut _,
        ) as isize;

        let deactivation_result = link.deactivate().await;

        if err > 0 {
            return Err(Error::NrfError(err));
        } else if err == -1 {
            return Err(Error::NrfError(crate::ffi::get_last_error()));
        }

        if result.is_null() {
            return Err(Error::AddressNotFound);
        }

        if let Err(deactivation_error) = deactivation_result {
            nrfxlib_sys::nrf_freeaddrinfo(result);
            return Err(deactivation_error);
        }

        let mut result_iter = result;

        while !result_iter.is_null() && found_ip.is_none() {
            let address = (*result_iter).ai_addr;

            if (*address).sa_family == nrfxlib_sys::NRF_AF_INET as u16 {
                let dns_addr: &nrfxlib_sys::nrf_sockaddr_in =
                    &*(address as *const nrfxlib_sys::nrf_sockaddr_in);

                let socket_addr: SocketAddr = NrfSockAddr::from(*dns_addr).into();
                found_ip = Some(socket_addr.ip());
            } else if (*address).sa_family == nrfxlib_sys::NRF_AF_INET6 as u16 {
                let dns_addr: &nrfxlib_sys::nrf_sockaddr_in6 =
                    &*(address as *const nrfxlib_sys::nrf_sockaddr_in6);

                let socket_addr: SocketAddr = NrfSockAddr::from(*dns_addr).into();
                found_ip = Some(socket_addr.ip());
            }

            result_iter = (*result_iter).ai_next;
        }

        // The addrinfo is allocated somewhere so we have to make sure to free it
        nrfxlib_sys::nrf_freeaddrinfo(result);

        if let Some(found_ip) = found_ip {
            Ok(found_ip)
        } else {
            Err(Error::AddressNotFound)
        }
    }
}
