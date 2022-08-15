use crate::{error::Error, ffi::get_last_error};
use core::sync::atomic::AtomicU32;
use core::future::Future;
use no_std_net::SocketAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};

static ACTIVE_SOCKETS: AtomicU32 = AtomicU32::new(0);

pub struct Socket {
    fd: i32,
}

impl Socket {
    pub fn create(
        family: SocketFamily,
        s_type: SocketType,
        protocol: SocketProtocol,
    ) -> Result<Self, Error> {
        let fd = unsafe {
            nrfxlib_sys::nrf_socket(
                family as u32 as i32,
                s_type as u32 as i32,
                protocol as u32 as i32,
            )
        };

        if fd == -1 {
            return Err(Error::NrfError(get_last_error()));
        }

        // Set the socket to non-blocking
        unsafe {
            let result = nrfxlib_sys::nrf_fcntl(fd, nrfxlib_sys::NRF_F_SETFL as _, nrfxlib_sys::NRF_O_NONBLOCK as _);

            if result == -1 {
                return Err(Error::NrfError(get_last_error()));
            }    
        }

        Ok(Socket { fd })
    }

    pub fn connect(&mut self, address: SocketAddr) -> impl Future<Output = Result<(), Error>> {
        core::future::poll_fn(|cx| {

        })
    }

}

impl Drop for Socket {
    fn drop(&mut self) {
        let e = unsafe { nrfxlib_sys::nrf_close(self.fd) };

        if e == -1 {
            Result::<(), _>::Err(Error::NrfError(get_last_error())).unwrap();
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum SocketFamily {
    Unspecified = nrfxlib_sys::NRF_AF_UNSPEC,
    Ipv4 = nrfxlib_sys::NRF_AF_INET,
    Ipv6 = nrfxlib_sys::NRF_AF_INET6,
    Raw = nrfxlib_sys::NRF_AF_PACKET,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum SocketType {
    Stream = nrfxlib_sys::NRF_SOCK_STREAM,
    Datagram = nrfxlib_sys::NRF_SOCK_DGRAM,
    Raw = nrfxlib_sys::NRF_SOCK_RAW,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum SocketProtocol {
    IP = nrfxlib_sys::NRF_IPPROTO_IP,
    Tcp = nrfxlib_sys::NRF_IPPROTO_TCP,
    Udp = nrfxlib_sys::NRF_IPPROTO_UDP,
    Ipv6 = nrfxlib_sys::NRF_IPPROTO_IPV6,
    Raw = nrfxlib_sys::NRF_IPPROTO_RAW,
    All = nrfxlib_sys::NRF_IPPROTO_ALL,
    Tls1v2 = nrfxlib_sys::NRF_SPROTO_TLS1v2,
    DTls1v2 = nrfxlib_sys::NRF_SPROTO_DTLS1v2,
}
