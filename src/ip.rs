use crate::socket::SocketFamily;
// use core::mem::size_of;
use no_std_net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use nrfxlib_sys::{nrf_sockaddr, nrf_sockaddr_in, nrf_sockaddr_in6};

pub enum NrfSockAddr {
    SockAddrIn(nrf_sockaddr_in),
    SockAddrIn6(nrf_sockaddr_in6),
}

impl From<SocketAddr> for NrfSockAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => nrf_sockaddr_in {
                // sin_len: size_of::<nrf_sockaddr_in>() as u8,
                sin_family: SocketFamily::Ipv4 as u16,
                sin_port: addr.port().to_be(),
                sin_addr: nrfxlib_sys::nrf_in_addr {
                    s_addr: u32::to_be((*addr.ip()).into()),
                },
            }
            .into(),
            SocketAddr::V6(addr) => nrf_sockaddr_in6 {
                // sin6_len: size_of::<nrf_sockaddr_in6>() as u8,
                sin6_family: SocketFamily::Ipv6 as u16,
                sin6_port: addr.port().to_be(),
                sin6_addr: nrfxlib_sys::nrf_in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                // sin6_flowinfo: 0,
                sin6_scope_id: 0,
            }
            .into(),
        }
    }
}

impl From<NrfSockAddr> for SocketAddr {
    fn from(addr: NrfSockAddr) -> Self {
        match addr {
            NrfSockAddr::SockAddrIn(val) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(val.sin_addr.s_addr.to_be()),
                val.sin_port.to_be(),
            )),
            NrfSockAddr::SockAddrIn6(val) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(val.sin6_addr.s6_addr),
                val.sin6_port.to_be(),
                0,
                0,
            )),
        }
    }
}

impl From<*const nrf_sockaddr> for NrfSockAddr {
    fn from(v: *const nrf_sockaddr) -> Self {
        const IPV4: u16 = SocketFamily::Ipv4 as u16;
        const IPV6: u16 = SocketFamily::Ipv6 as u16;

        unsafe {
            match (*v).sa_family {
                IPV4 => (*(v as *const nrf_sockaddr_in)).into(),
                IPV6 => (*(v as *const nrf_sockaddr_in6)).into(),
                family => unreachable!("Unknown family: {family}"),
            }
        }
    }
}

impl From<nrf_sockaddr_in6> for NrfSockAddr {
    fn from(v: nrf_sockaddr_in6) -> Self {
        Self::SockAddrIn6(v)
    }
}

impl From<nrf_sockaddr_in> for NrfSockAddr {
    fn from(v: nrf_sockaddr_in) -> Self {
        Self::SockAddrIn(v)
    }
}

impl NrfSockAddr {
    pub fn as_ptr(&self) -> *const nrf_sockaddr {
        match self {
            NrfSockAddr::SockAddrIn(val) => val as *const _ as *const _,
            NrfSockAddr::SockAddrIn6(val) => val as *const _ as *const _,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            NrfSockAddr::SockAddrIn(_) => core::mem::size_of::<nrf_sockaddr_in>(),
            NrfSockAddr::SockAddrIn6(_) => core::mem::size_of::<nrf_sockaddr_in6>(),
        }
    }
}
