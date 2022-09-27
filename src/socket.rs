use crate::{
    error::Error,
    ffi::get_last_error,
    ip::NrfSockAddr,
    lte_link::LteLink,
    waker_node_list::{WakerNode, WakerNodeList},
};
use core::{cell::RefCell, future::Future, marker::PhantomData, ops::Neg, task::Poll};
use critical_section::Mutex;
use no_std_net::SocketAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub(crate) static WAKER_NODE_LIST: Mutex<RefCell<WakerNodeList<()>>> =
    Mutex::new(RefCell::new(WakerNodeList::new()));

#[derive(Debug, PartialEq, Eq)]
pub struct Socket {
    fd: i32,
    family: SocketFamily,
    link: LteLink,
}

impl Socket {
    pub async fn create(
        family: SocketFamily,
        s_type: SocketType,
        protocol: SocketProtocol,
    ) -> Result<Self, Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!(
            "Creating socket with family: {}, type: {}, protocol: {}",
            family as u32 as i32,
            s_type as u32 as i32,
            protocol as u32 as i32
        );

        let link = LteLink::new().await?;

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

        Ok(Socket { fd, family, link })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    pub async fn connect(&self, address: SocketAddr) -> Result<(), Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!(
            "Connecting socket {} to {:?}",
            self.fd,
            defmt::Debug2Format(&address)
        );

        self.link.wait_for_link().await?;

        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Connecting socket {}", self.fd);

            let address = NrfSockAddr::from(address);

            let mut connect_result = unsafe {
                nrfxlib_sys::nrf_connect(self.fd, address.as_ptr(), address.size() as u32)
            };

            const NRF_EINPROGRESS: i32 = nrfxlib_sys::NRF_EINPROGRESS as i32;
            const NRF_EALREADY: i32 = nrfxlib_sys::NRF_EALREADY as i32;
            const NRF_EISCONN: i32 = nrfxlib_sys::NRF_EISCONN as i32;

            if connect_result == -1 {
                connect_result = get_last_error();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Connect result {}", connect_result);

            match connect_result {
                0 => Poll::Ready(Ok(())),
                NRF_EISCONN => Poll::Ready(Ok(())),
                NRF_EINPROGRESS | NRF_EALREADY => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await?;

        Ok(())
    }

    pub async fn bind(&self, address: SocketAddr) -> Result<(), Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!(
            "Binding socket {} to {:?}",
            self.fd,
            defmt::Debug2Format(&address)
        );

        self.link.wait_for_link().await?;

        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Binding socket {}", self.fd);

            let address = NrfSockAddr::from(address);

            let mut bind_result =
                unsafe { nrfxlib_sys::nrf_bind(self.fd, address.as_ptr(), address.size() as u32) };

            const NRF_EINPROGRESS: i32 = nrfxlib_sys::NRF_EINPROGRESS as i32;
            const NRF_EALREADY: i32 = nrfxlib_sys::NRF_EALREADY as i32;
            const NRF_EISCONN: i32 = nrfxlib_sys::NRF_EISCONN as i32;

            if bind_result == -1 {
                bind_result = get_last_error();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Bind result {}", bind_result);

            match bind_result {
                0 => Poll::Ready(Ok(())),
                NRF_EISCONN => Poll::Ready(Ok(())),
                NRF_EINPROGRESS | NRF_EALREADY => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await?;

        Ok(())
    }

    pub async fn write(&self, buffer: &[u8]) -> Result<usize, Error> {
        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Sending with socket {}", self.fd);

            let mut send_result = unsafe {
                nrfxlib_sys::nrf_send(self.fd, buffer.as_ptr() as *const _, buffer.len() as u32, 0)
            };

            if send_result == -1 {
                send_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Send result {}", send_result);

            const NRF_EWOULDBLOCK: i32 = -(nrfxlib_sys::NRF_EWOULDBLOCK as i32);

            match send_result {
                bytes_sent @ 0.. => Poll::Ready(Ok(bytes_sent as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    pub async fn receive(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Receiving with socket {}", self.fd);

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recv(self.fd, buffer.as_ptr() as *mut _, buffer.len() as u32, 0)
            };

            if receive_result == -1 {
                receive_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Receive result {}", receive_result);

            const NRF_EWOULDBLOCK: i32 = -(nrfxlib_sys::NRF_EWOULDBLOCK as i32);

            match receive_result {
                bytes_received @ 0.. => Poll::Ready(Ok(bytes_received as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    pub async fn receive_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Receiving with socket {}", self.fd);

            // Big enough to store both ipv4 and ipv6
            let mut socket_addr_store =
                [0u8; core::mem::size_of::<nrfxlib_sys::nrf_sockaddr_in6>()];
            let socket_addr_ptr = socket_addr_store.as_mut_ptr() as *mut nrfxlib_sys::nrf_sockaddr;
            let mut socket_addr_len = 0u32;

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recvfrom(
                    self.fd,
                    buffer.as_ptr() as *mut _,
                    buffer.len() as u32,
                    0,
                    socket_addr_ptr,
                    &mut socket_addr_len as *mut u32,
                )
            };

            if receive_result == -1 {
                receive_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Receive result {}", receive_result);

            const NRF_EWOULDBLOCK: i32 = -(nrfxlib_sys::NRF_EWOULDBLOCK as i32);

            match receive_result {
                bytes_received @ 0.. => Poll::Ready(Ok((bytes_received as usize, {
                    unsafe { (*socket_addr_ptr).sa_family = self.family as u32 as i32 }
                    NrfSockAddr::from(socket_addr_ptr as *const _).into()
                }))),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    pub async fn send_to(&self, buffer: &[u8], address: SocketAddr) -> Result<usize, Error> {
        SocketFuture::new(|| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Sending with socket {}", self.fd);

            let addr = NrfSockAddr::from(address);

            let mut send_result = unsafe {
                nrfxlib_sys::nrf_sendto(
                    self.fd,
                    buffer.as_ptr() as *mut _,
                    buffer.len() as u32,
                    0,
                    addr.as_ptr(),
                    addr.size() as u32,
                )
            };

            if send_result == -1 {
                send_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Sending result {}", send_result);

            const NRF_EWOULDBLOCK: i32 = -(nrfxlib_sys::NRF_EWOULDBLOCK as i32);

            match send_result {
                bytes_received @ 0.. => Poll::Ready(Ok(bytes_received as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }
    pub fn set_option<'a>(&'a self, option: SocketOption<'a>) -> Result<(), SocketOptionError> {
        let length = option.get_length();

        let result = unsafe {
            nrfxlib_sys::nrf_setsockopt(
                self.fd,
                nrfxlib_sys::NRF_SOL_SECURE.try_into().unwrap(),
                option.get_name(),
                option.get_value(),
                length as u32,
            )
        };

        if result < 0 {
            Err(result.into())
        } else {
            Ok(())
        }
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

struct SocketFuture<R, O>
where
    R: FnMut() -> Poll<Result<O, Error>> + Unpin,
    O: Unpin,
{
    runner: R,
    waker_node: Option<WakerNode<()>>,
    _phantom: PhantomData<O>,
}

impl<R, O> SocketFuture<R, O>
where
    R: FnMut() -> Poll<Result<O, Error>> + Unpin,
    O: Unpin,
{
    fn new(runner: R) -> Self {
        Self {
            runner,
            waker_node: None,
            _phantom: PhantomData,
        }
    }
}

impl<R, O> Future for SocketFuture<R, O>
where
    R: FnMut() -> Poll<Result<O, Error>> + Unpin,
    O: Unpin,
{
    type Output = Result<O, Error>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        // Register our waker node
        critical_section::with(|cs| {
            let mut list = WAKER_NODE_LIST.borrow_ref_mut(cs);
            let waker_node = self
                .waker_node
                .get_or_insert_with(|| WakerNode::new(None, cx.waker().clone()));
            waker_node.waker = cx.waker().clone();
            unsafe {
                list.append_node(waker_node as *mut _);
            }
        });

        (self.runner)()
    }
}

impl<R, O> Drop for SocketFuture<R, O>
where
    R: FnMut() -> Poll<Result<O, Error>> + Unpin,
    O: Unpin,
{
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            critical_section::with(|cs| unsafe {
                WAKER_NODE_LIST
                    .borrow_ref_mut(cs)
                    .remove_node(waker_node as *mut _)
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

#[derive(Debug)]
pub enum SocketOption<'a> {
    TlsHostName(&'a str),
    TlsPeerVerify(nrfxlib_sys::nrf_sec_peer_verify_t),
    TlsSessionCache(nrfxlib_sys::nrf_sec_session_cache_t),
    TlsTagList(&'a [nrfxlib_sys::nrf_sec_tag_t]),
}
impl<'a> SocketOption<'a> {
    pub(crate) fn get_name(&self) -> i32 {
        match self {
            SocketOption::TlsHostName(_) => nrfxlib_sys::NRF_SO_SEC_HOSTNAME as i32,
            SocketOption::TlsPeerVerify(_) => nrfxlib_sys::NRF_SO_SEC_PEER_VERIFY as i32,
            SocketOption::TlsSessionCache(_) => nrfxlib_sys::NRF_SO_SEC_SESSION_CACHE as i32,
            SocketOption::TlsTagList(_) => nrfxlib_sys::NRF_SO_SEC_TAG_LIST as i32,
        }
    }

    pub(crate) fn get_value(&self) -> *const nrfxlib_sys::ctypes::c_void {
        match self {
            SocketOption::TlsHostName(s) => s.as_ptr() as *const nrfxlib_sys::ctypes::c_void,
            SocketOption::TlsPeerVerify(x) => x as *const _ as *const nrfxlib_sys::ctypes::c_void,
            SocketOption::TlsSessionCache(x) => x as *const _ as *const nrfxlib_sys::ctypes::c_void,
            SocketOption::TlsTagList(x) => x.as_ptr() as *const nrfxlib_sys::ctypes::c_void,
        }
    }

    pub(crate) fn get_length(&self) -> u32 {
        match self {
            SocketOption::TlsHostName(s) => s.len() as u32,
            SocketOption::TlsPeerVerify(x) => core::mem::size_of_val(x) as u32,
            SocketOption::TlsSessionCache(x) => core::mem::size_of_val(x) as u32,
            SocketOption::TlsTagList(x) => core::mem::size_of_val(x) as u32,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SocketOptionError {
    // The socket argument is not a valid file descriptor.
    InvalidFileDescriptor,
    // The send and receive timeout values are too big to fit into the timeout fields in the socket structure.
    TimeoutTooBig,
    // The specified option is invalid at the specified socket level or the socket has been shut down.
    InvalidOption,
    // The socket is already connected, and a specified option cannot be set while the socket is connected.
    AlreadyConnected,
    // The option is not supported by the protocol.
    UnsupportedOption,
    // The socket argument does not refer to a socket.
    NotASocket,
    // There was insufficient memory available for the operation to complete.
    OutOfMemory,
    // Insufficient resources are available in the system to complete the call.
    OutOfResources,
}

impl From<i32> for SocketOptionError {
    fn from(errno: i32) -> Self {
        match errno.abs() as u32 {
            nrfxlib_sys::NRF_EBADF => SocketOptionError::InvalidFileDescriptor,
            nrfxlib_sys::NRF_EINVAL => SocketOptionError::InvalidOption,
            nrfxlib_sys::NRF_EISCONN => SocketOptionError::AlreadyConnected,
            nrfxlib_sys::NRF_ENOPROTOOPT => SocketOptionError::UnsupportedOption,
            nrfxlib_sys::NRF_ENOTSOCK => SocketOptionError::NotASocket,
            nrfxlib_sys::NRF_ENOMEM => SocketOptionError::OutOfMemory,
            nrfxlib_sys::NRF_ENOBUFS => SocketOptionError::OutOfResources,
            _ => panic!("Unknown error code: {}", errno),
        }
    }
}
