use crate::at;
use crate::waker_node_list::{WakerNode, WakerNodeList};
use crate::{error::Error, ffi::get_last_error};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Poll;
use core::{cell::RefCell, future::Future};
use embassy::blocking_mutex::CriticalSectionMutex;
use no_std_net::SocketAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};

static ACTIVE_SOCKETS: AtomicU32 = AtomicU32::new(0);

pub(crate) static WAKER_NODE_LIST: CriticalSectionMutex<RefCell<WakerNodeList<()>>> =
    CriticalSectionMutex::new(RefCell::new(WakerNodeList::new()));

#[derive(Debug, PartialEq, Eq)]
pub struct Socket {
    fd: i32,
}

impl Socket {
    pub async fn create(
        family: SocketFamily,
        s_type: SocketType,
        protocol: SocketProtocol,
    ) -> Result<Self, Error> {
        #[cfg(feature = "defmt")]
        defmt::trace!("Creating socket");

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
            let result = nrfxlib_sys::nrf_fcntl(
                fd,
                nrfxlib_sys::NRF_F_SETFL as _,
                nrfxlib_sys::NRF_O_NONBLOCK as _,
            );

            if result == -1 {
                return Err(Error::NrfError(get_last_error()));
            }
        }

        if ACTIVE_SOCKETS.fetch_add(1, Ordering::SeqCst) == 0 {
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

        Ok(Socket { fd })
    }

    pub async fn connect(&mut self, address: SocketAddr) -> Result<(), Error> {
        wait_for_lte().await?;

        ConnectFuture {
            fd: &self.fd,
            address,
            waker_node: None,
        }
        .await?;

        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let e = unsafe { nrfxlib_sys::nrf_close(self.fd) };

        if ACTIVE_SOCKETS.fetch_sub(1, Ordering::SeqCst) == 1 {
            crate::at::send_at_blocking("AT+CFUN=20").unwrap();
        }

        if e == -1 {
            Result::<(), _>::Err(Error::NrfError(get_last_error())).unwrap();
        }
    }
}

struct ConnectFuture<'s> {
    fd: &'s i32,
    address: SocketAddr,
    waker_node: Option<WakerNode<()>>,
}

impl<'s> Future for ConnectFuture<'s> {
    type Output = Result<(), Error>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        // Register our waker node
        WAKER_NODE_LIST.lock(|list| {
            let waker_node = self
                .waker_node
                .get_or_insert_with(|| WakerNode::new(None, cx.waker().clone()));
            waker_node.waker = cx.waker().clone();
            unsafe {
                list.borrow_mut().append_node(waker_node as *mut _);
            }
        });

        #[cfg(feature = "defmt")]
        defmt::trace!("Connecting socket {}", self.fd);

        let mut connect_result = match self.address {
            SocketAddr::V4(addr) => {
                let nrf_addr = nrfxlib_sys::nrf_sockaddr_in {
                    sin_len: size_of::<nrfxlib_sys::nrf_sockaddr_in>() as u8,
                    sin_family: SocketFamily::Ipv4 as u32 as i32,
                    sin_port: addr.port().to_be(), // Port must be in network order which is Big Endian
                    sin_addr: nrfxlib_sys::nrf_in_addr {
                        s_addr: (*addr.ip()).into(),
                    },
                };

                unsafe {
                    nrfxlib_sys::nrf_connect(
                        *self.fd,
                        &nrf_addr as *const nrfxlib_sys::nrf_sockaddr_in as *const _,
                        size_of::<nrfxlib_sys::nrf_sockaddr_in>() as u32,
                    )
                }
            }
            SocketAddr::V6(addr) => {
                let nrf_addr = nrfxlib_sys::nrf_sockaddr_in6 {
                    sin6_len: size_of::<nrfxlib_sys::nrf_sockaddr_in6>() as u8,
                    sin6_family: SocketFamily::Ipv6 as u32 as i32,
                    sin6_port: addr.port().to_be(), // Port must be in network order which is Big Endian
                    sin6_addr: nrfxlib_sys::nrf_in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_scope_id: addr.scope_id(),
                };

                unsafe {
                    nrfxlib_sys::nrf_connect(
                        *self.fd,
                        &nrf_addr as *const nrfxlib_sys::nrf_sockaddr_in6 as *const _,
                        size_of::<nrfxlib_sys::nrf_sockaddr_in6>() as u32,
                    )
                }
            }
        };

        const NRF_EINPROGRESS: i32 = nrfxlib_sys::NRF_EINPROGRESS as i32;

        if connect_result == -1 {
            connect_result = get_last_error();
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Connect result {}", connect_result);

        match connect_result {
            0 => Poll::Ready(Ok(())),
            NRF_EINPROGRESS => Poll::Pending,
            error => Poll::Ready(Err(Error::NrfError(error))),
        }
    }
}

impl<'s> Drop for ConnectFuture<'s> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| unsafe {
                list.borrow_mut().remove_node(waker_node as *mut _);
            });
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

async fn wait_for_lte() -> Result<(), Error> {
    loop {
        let answer = at::send_at("AT+CEREG?").await?;

        let (_, stat) = at_commands::parser::CommandParser::parse(answer.as_bytes())
            .expect_identifier(b"+CEREG:")
            .expect_int_parameter()
            .expect_int_parameter()
            .finish()?;

        match stat {
            1 | 5 => return Ok(()),
            0 | 2 | 4 => continue,
            3 => return Err(Error::LteRegistrationDenied),
            90 => return Err(Error::SimFailure),
            _ => return Err(Error::UnexpectedAtResponse),
        }
    }
}
