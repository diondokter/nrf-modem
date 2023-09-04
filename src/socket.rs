use crate::{
    error::Error, ffi::get_last_error, ip::NrfSockAddr, lte_link::LteLink, CancellationToken,
};
use core::{
    cell::RefCell,
    ops::{Deref, Neg},
    sync::atomic::{AtomicU8, Ordering},
    task::{Poll, Waker},
};
use critical_section::Mutex;
use no_std_net::SocketAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};

// use 16 slots for wakers instead of 8, which is the max number of sockets allowed, so they
// are not overwritten when split into their rx/tx counterparts and run in separate tasks.
const WAKER_SLOTS: usize = (nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT * 2) as usize;
const WAKER_INIT: Option<(Waker, i32, SocketDirection)> = None;
#[allow(clippy::type_complexity)]
static SOCKET_WAKERS: Mutex<RefCell<[Option<(Waker, i32, SocketDirection)>; WAKER_SLOTS]>> =
    Mutex::new(RefCell::new([WAKER_INIT; WAKER_SLOTS]));

pub(crate) fn wake_sockets() {
    critical_section::with(|cs| {
        SOCKET_WAKERS
            .borrow_ref_mut(cs)
            .iter_mut()
            .for_each(|waker| {
                if let Some((waker, _, _)) = waker.take() {
                    waker.wake()
                }
            })
    });
}

fn register_socket_waker(waker: Waker, socket_fd: i32, socket_dir: SocketDirection) {
    critical_section::with(|cs| {
        // Get the wakers
        let mut wakers = SOCKET_WAKERS.borrow_ref_mut(cs);

        // Search for an empty spot or a spot that already stores the waker for the socket
        let empty_waker = wakers.iter_mut().find(|waker| {
            waker.is_none()
                || waker.as_ref().map(|(_, fd, dir)| (*fd, *dir)) == Some((socket_fd, socket_dir))
        });

        if let Some(empty_waker) = empty_waker {
            // In principle we should always have an empty spot and run this code
            *empty_waker = Some((waker, socket_fd, socket_dir));
        } else {
            // It shouldn't ever happen, but if there's no empty spot, we just evict the first socket
            // That socket will just reregister itself
            wakers
                .first_mut()
                .unwrap()
                .replace((waker, socket_fd, socket_dir))
                .unwrap()
                .0
                .wake();
        }
    });
}

/// Used as a identifier for wakers when a socket is split into RX/TX halves
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketDirection {
    RX = 0,
    TX = 1,
}

/// Internal socket implementation
#[derive(Debug)]
pub struct Socket {
    /// The file descriptor given by the modem lib
    fd: i32,
    /// The socket family (required to know when we need to decipher an incoming IP address)
    family: SocketFamily,
    /// The link this socket holds to keep the LTE alive.
    /// This is an option because when deactivating we need to take ownership of it.
    link: Option<LteLink>,
    /// Gets set to true when the socket has been split. This is relevant for the drop functions
    split: bool,
}

impl Socket {
    /// Create a new socket with the given parameters
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

        if unsafe { !nrfxlib_sys::nrf_modem_is_initialized() } {
            return Err(Error::ModemNotInitialized);
        }

        // Let's activate the modem
        let link = LteLink::new().await?;

        // Create the socket in the nrf-modem lib
        let fd = unsafe {
            nrfxlib_sys::nrf_socket(
                family as u32 as i32,
                s_type as u32 as i32,
                protocol as u32 as i32,
            )
        };

        // If the fd is -1, then there is an error in `errno`
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

        Ok(Socket {
            fd,
            family,
            link: Some(link),
            split: false,
        })
    }

    /// Get the nrf-modem file descriptor so the user can opt out of using this high level wrapper for things
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    pub async fn split(mut self) -> Result<(SplitSocketHandle, SplitSocketHandle), Error> {
        let index = SplitSocketHandle::get_new_spot();
        self.split = true;

        Ok((
            SplitSocketHandle {
                inner: Some(Socket {
                    fd: self.fd,
                    family: self.family,
                    link: Some(LteLink::new().await?),
                    split: true,
                }),
                index,
            },
            SplitSocketHandle {
                inner: Some(self),
                index,
            },
        ))
    }

    /// Connect to the given socket address.
    ///
    /// This calls the `nrf_connect` function and can be used for tcp streams, udp connections and dtls connections.
    ///
    /// ## Safety
    ///
    /// If the connect is cancelled, the socket may be in a weird state and should be dropped.
    pub async unsafe fn connect(
        &self,
        address: SocketAddr,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!(
            "Connecting socket {} to {:?}",
            self.fd,
            defmt::Debug2Format(&address)
        );

        token.bind_to_current_task().await;

        // Before we can connect, we need to make sure we have a working link.
        // It is possible this will never resolve, but it is up to the user to manage the timeouts.
        self.link
            .as_ref()
            .unwrap()
            .wait_for_link_with_cancellation(token)
            .await?;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Connecting socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            // Cast the address to something the nrf-modem understands
            let address = NrfSockAddr::from(address);

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::TX);

            // Do the connect call, this is non-blocking due to the socket setup
            let mut connect_result = unsafe {
                nrfxlib_sys::nrf_connect(self.fd, address.as_ptr(), address.size() as u32)
            } as isize;

            const NRF_EINPROGRESS: isize = nrfxlib_sys::NRF_EINPROGRESS as isize;
            const NRF_EALREADY: isize = nrfxlib_sys::NRF_EALREADY as isize;
            const NRF_EISCONN: isize = nrfxlib_sys::NRF_EISCONN as isize;

            if connect_result == -1 {
                connect_result = get_last_error();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Connect result {}", connect_result);

            match connect_result {
                // 0 when we have succesfully connected
                0 => Poll::Ready(Ok(())),
                // The socket was already connected
                NRF_EISCONN => Poll::Ready(Ok(())),
                // The socket is not yet connected
                NRF_EINPROGRESS | NRF_EALREADY => Poll::Pending,
                // Something else, this is likely an error
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await?;

        Ok(())
    }

    /// Bind the socket to a given address.
    ///
    /// This calls the `nrf_bind` function and can be used for udp sockets
    ///
    /// ## Safety
    ///
    /// If the bind is cancelled, the socket may be in a weird state and should be dropped.
    pub async unsafe fn bind(
        &self,
        address: SocketAddr,
        token: &CancellationToken,
    ) -> Result<(), Error> {
        #[cfg(feature = "defmt")]
        defmt::debug!(
            "Binding socket {} to {:?}",
            self.fd,
            defmt::Debug2Format(&address)
        );

        token.bind_to_current_task().await;

        // Before we can connect, we need to make sure we have a working link.
        // It is possible this will never resolve, but it is up to the user to manage the timeouts.
        self.link
            .as_ref()
            .unwrap()
            .wait_for_link_with_cancellation(token)
            .await?;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Binding socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            // Cast the address to something the nrf-modem understands
            let address = NrfSockAddr::from(address);

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::TX);

            // Do the bind call, this is non-blocking due to the socket setup
            let mut bind_result =
                unsafe { nrfxlib_sys::nrf_bind(self.fd, address.as_ptr(), address.size() as u32) }
                    as isize;

            const NRF_EINPROGRESS: isize = nrfxlib_sys::NRF_EINPROGRESS as isize;
            const NRF_EALREADY: isize = nrfxlib_sys::NRF_EALREADY as isize;
            const NRF_EISCONN: isize = nrfxlib_sys::NRF_EISCONN as isize;

            if bind_result == -1 {
                bind_result = get_last_error();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Bind result {}", bind_result);

            match bind_result {
                // 0 when we have succesfully connected
                0 => Poll::Ready(Ok(())),
                // The socket was already connected
                NRF_EISCONN => Poll::Ready(Ok(())),
                // The socket is not yet connected
                NRF_EINPROGRESS | NRF_EALREADY => Poll::Pending,
                // Something else, this is likely an error
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await?;

        Ok(())
    }

    /// Call the [nrfxlib_sys::nrf_send] in an async fashion
    pub async fn write(&self, buffer: &[u8], token: &CancellationToken) -> Result<usize, Error> {
        token.bind_to_current_task().await;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Sending with socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::TX);

            let mut send_result = unsafe {
                nrfxlib_sys::nrf_send(self.fd, buffer.as_ptr() as *const _, buffer.len(), 0)
            };

            if send_result == -1 {
                send_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Send result {}", send_result);

            const NRF_EWOULDBLOCK: isize = -(nrfxlib_sys::NRF_EWOULDBLOCK as isize);
            const NRF_ENOTCONN: isize = -(nrfxlib_sys::NRF_ENOTCONN as isize);

            match send_result {
                0 if !buffer.is_empty() => Poll::Ready(Err(Error::Disconnected)),
                NRF_ENOTCONN => Poll::Ready(Err(Error::Disconnected)),
                bytes_sent @ 0.. => Poll::Ready(Ok(bytes_sent as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    /// Call the [nrfxlib_sys::nrf_recv] in an async fashion
    pub async fn receive(
        &self,
        buffer: &mut [u8],
        token: &CancellationToken,
    ) -> Result<usize, Error> {
        token.bind_to_current_task().await;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Receiving with socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::RX);

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recv(self.fd, buffer.as_ptr() as *mut _, buffer.len(), 0)
            };

            if receive_result == -1 {
                receive_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Receive result {}", receive_result);

            const NRF_EWOULDBLOCK: isize = -(nrfxlib_sys::NRF_EWOULDBLOCK as isize);
            const NRF_ENOTCONN: isize = -(nrfxlib_sys::NRF_ENOTCONN as isize);

            match receive_result {
                0 if !buffer.is_empty() => Poll::Ready(Err(Error::Disconnected)),
                NRF_ENOTCONN => Poll::Ready(Err(Error::Disconnected)),
                bytes_received @ 0.. => Poll::Ready(Ok(bytes_received as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    /// Call the [nrfxlib_sys::nrf_recvfrom] in an async fashion
    pub async fn receive_from(
        &self,
        buffer: &mut [u8],
        token: &CancellationToken,
    ) -> Result<(usize, SocketAddr), Error> {
        token.bind_to_current_task().await;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Receiving with socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            // Big enough to store both ipv4 and ipv6
            let mut socket_addr_store =
                [0u8; core::mem::size_of::<nrfxlib_sys::nrf_sockaddr_in6>()];
            let socket_addr_ptr = socket_addr_store.as_mut_ptr() as *mut nrfxlib_sys::nrf_sockaddr;
            let mut socket_addr_len = 0u32;

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::RX);

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recvfrom(
                    self.fd,
                    buffer.as_ptr() as *mut _,
                    buffer.len(),
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

            const NRF_EWOULDBLOCK: isize = -(nrfxlib_sys::NRF_EWOULDBLOCK as isize);
            const NRF_ENOTCONN: isize = -(nrfxlib_sys::NRF_ENOTCONN as isize);

            match receive_result {
                0 if !buffer.is_empty() => Poll::Ready(Err(Error::Disconnected)),
                NRF_ENOTCONN => Poll::Ready(Err(Error::Disconnected)),
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

    /// Call the [nrfxlib_sys::nrf_sendto] in an async fashion
    pub async fn send_to(
        &self,
        buffer: &[u8],
        address: SocketAddr,
        token: &CancellationToken,
    ) -> Result<usize, Error> {
        token.bind_to_current_task().await;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Sending with socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            let addr = NrfSockAddr::from(address);

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::TX);

            let mut send_result = unsafe {
                nrfxlib_sys::nrf_sendto(
                    self.fd,
                    buffer.as_ptr() as *mut _,
                    buffer.len(),
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

            const NRF_EWOULDBLOCK: isize = -(nrfxlib_sys::NRF_EWOULDBLOCK as isize);
            const NRF_ENOTCONN: isize = -(nrfxlib_sys::NRF_ENOTCONN as isize);

            match send_result {
                0 if !buffer.is_empty() => Poll::Ready(Err(Error::Disconnected)),
                NRF_ENOTCONN => Poll::Ready(Err(Error::Disconnected)),
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
                length,
            )
        };

        if result < 0 {
            Err(result.into())
        } else {
            Ok(())
        }
    }

    /// Deactivates the socket and the LTE link.
    /// A normal drop will do the same thing, but blocking.
    pub async fn deactivate(mut self) -> Result<(), Error> {
        self.link.take().unwrap().deactivate().await?;
        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if !self.split {
            let e = unsafe { nrfxlib_sys::nrf_close(self.fd) };

            if e == -1 {
                Result::<(), _>::Err(Error::NrfError(get_last_error())).unwrap();
            }
        }
    }
}

impl PartialEq for Socket {
    fn eq(&self, other: &Self) -> bool {
        self.fd == other.fd
    }
}
impl Eq for Socket {}

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

#[allow(clippy::enum_variant_names)]
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

    pub(crate) fn get_value(&self) -> *const core::ffi::c_void {
        match self {
            SocketOption::TlsHostName(s) => s.as_ptr() as *const core::ffi::c_void,
            SocketOption::TlsPeerVerify(x) => x as *const _ as *const core::ffi::c_void,
            SocketOption::TlsSessionCache(x) => x as *const _ as *const core::ffi::c_void,
            SocketOption::TlsTagList(x) => x.as_ptr() as *const core::ffi::c_void,
        }
    }

    pub(crate) fn get_length(&self) -> u32 {
        match self {
            SocketOption::TlsHostName(s) => s.len() as u32,
            SocketOption::TlsPeerVerify(x) => core::mem::size_of_val(x) as u32,
            SocketOption::TlsSessionCache(x) => core::mem::size_of_val(x) as u32,
            SocketOption::TlsTagList(x) => core::mem::size_of_val(*x) as u32,
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
        match errno.unsigned_abs() {
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

#[allow(clippy::declare_interior_mutable_const)]
const ATOMIC_U8_INIT: AtomicU8 = AtomicU8::new(0);
static ACTIVE_SPLIT_SOCKETS: [AtomicU8; nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT as usize] =
    [ATOMIC_U8_INIT; nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT as usize];

pub struct SplitSocketHandle {
    inner: Option<Socket>,
    index: usize,
}

impl SplitSocketHandle {
    pub async fn deactivate(mut self) -> Result<(), Error> {
        let mut inner = self.inner.take().unwrap();

        if ACTIVE_SPLIT_SOCKETS[self.index].fetch_sub(1, Ordering::SeqCst) == 1 {
            // We were the last handle to drop so the inner socket isn't split anymore
            inner.split = false;
        }

        inner.deactivate().await?;

        Ok(())
    }

    fn get_new_spot() -> usize {
        for (index, count) in ACTIVE_SPLIT_SOCKETS.iter().enumerate() {
            if count
                .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return index;
            }
        }

        unreachable!("It should not be possible to have more splits than the maximum socket count");
    }
}

impl Deref for SplitSocketHandle {
    type Target = Socket;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl Drop for SplitSocketHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            if ACTIVE_SPLIT_SOCKETS[self.index].fetch_sub(1, Ordering::SeqCst) == 1 {
                // We were the last handle to drop so the inner socket isn't split anymore
                inner.split = false;
            }
        }
    }
}
