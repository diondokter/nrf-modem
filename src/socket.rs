use crate::{
    error::Error, ffi::get_last_error, ip::NrfSockAddr, lte_link::LteLink, CancellationToken,
};
use core::net::SocketAddr;
use core::{
    cell::RefCell,
    ops::{BitOr, BitOrAssign, Deref, Neg},
    sync::atomic::{AtomicU8, Ordering},
    task::{Poll, Waker},
};
use critical_section::Mutex;
use num_enum::{IntoPrimitive, TryFromPrimitive};

// use 16 slots for wakers instead of 8, which is the max number of sockets allowed, so they
// are not overwritten when split into their rx/tx counterparts and run in separate tasks.
const WAKER_SLOTS: usize = (nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT * 2) as usize;
const WAKER_INIT: Option<(Waker, i32, SocketDirection)> = None;
#[allow(clippy::type_complexity)]
static SOCKET_WAKERS: Mutex<RefCell<[Option<(Waker, i32, SocketDirection)>; WAKER_SLOTS]>> =
    Mutex::new(RefCell::new([WAKER_INIT; WAKER_SLOTS]));

fn wake_sockets(socket_fd: i32, socket_dir: SocketDirection) {
    critical_section::with(|cs| {
        SOCKET_WAKERS
            .borrow_ref_mut(cs)
            .iter_mut()
            .filter(|slot| {
                if let Some((_, fd, dir)) = slot {
                    *fd == socket_fd && dir.same_direction(socket_dir)
                } else {
                    false
                }
            })
            .for_each(|slot| {
                let (waker, _, _) = slot.take().unwrap();
                waker.wake();
            });
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

unsafe extern "C" fn socket_poll_callback(pollfd: *mut nrfxlib_sys::nrf_pollfd) {
    let pollfd = *pollfd;

    let mut direction = SocketDirection::Neither;

    if pollfd.revents as u32 & nrfxlib_sys::NRF_POLLIN != 0 {
        direction |= SocketDirection::In;
    }

    if pollfd.revents as u32 & nrfxlib_sys::NRF_POLLOUT != 0 {
        direction |= SocketDirection::Out;
    }

    if pollfd.revents as u32
        & (nrfxlib_sys::NRF_POLLERR | nrfxlib_sys::NRF_POLLHUP | nrfxlib_sys::NRF_POLLNVAL)
        != 0
    {
        direction |= SocketDirection::Either;
    }

    #[cfg(feature = "defmt")]
    defmt::trace!(
        "Socket poll callback. fd: {}, revents: {:X}, direction: {}",
        pollfd.fd,
        pollfd.revents,
        direction
    );

    wake_sockets(pollfd.fd, direction);
}

/// Used as a identifier for wakers when a socket is split into RX/TX halves
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum SocketDirection {
    /// Neither option
    Neither,
    /// RX
    In,
    /// TX
    Out,
    /// RX and/or TX
    Either,
}

impl BitOrAssign for SocketDirection {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitOr for SocketDirection {
    type Output = SocketDirection;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (SocketDirection::Neither, rhs) => rhs,
            (lhs, SocketDirection::Neither) => lhs,
            (SocketDirection::In, SocketDirection::In) => SocketDirection::In,
            (SocketDirection::Out, SocketDirection::Out) => SocketDirection::Out,
            (SocketDirection::In, SocketDirection::Out) => SocketDirection::Either,
            (SocketDirection::Out, SocketDirection::In) => SocketDirection::Either,
            (SocketDirection::Either, _) => SocketDirection::Either,
            (_, SocketDirection::Either) => SocketDirection::Either,
        }
    }
}

impl SocketDirection {
    fn same_direction(&self, other: Self) -> bool {
        match (self, other) {
            (SocketDirection::Neither, _) => false,
            (_, SocketDirection::Neither) => false,
            (SocketDirection::In, SocketDirection::In) => true,
            (SocketDirection::Out, SocketDirection::Out) => true,
            (SocketDirection::In, SocketDirection::Out) => false,
            (SocketDirection::Out, SocketDirection::In) => false,
            (_, SocketDirection::Either) => true,
            (SocketDirection::Either, _) => true,
        }
    }
}

/// A socket for network communication through the nRF modem.
///
/// This struct provides an async interface to the nRF modem's socket functionality,
/// supporting TCP, UDP, TLS, and DTLS protocols. The socket automatically manages
/// the LTE link lifetime and provides non-blocking async operations.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

        // Register the callback of the socket. This will be used to wake up the socket waker
        let poll_callback = nrfxlib_sys::nrf_modem_pollcb {
            callback: Some(socket_poll_callback),
            events: (nrfxlib_sys::NRF_POLLIN | nrfxlib_sys::NRF_POLLOUT) as _, // All events
            oneshot: false,
        };

        unsafe {
            let result = nrfxlib_sys::nrf_setsockopt(
                fd,
                nrfxlib_sys::NRF_SOL_SOCKET as _,
                nrfxlib_sys::NRF_SO_POLLCB as _,
                (&poll_callback as *const nrfxlib_sys::nrf_modem_pollcb).cast(),
                core::mem::size_of::<nrfxlib_sys::nrf_modem_pollcb>() as u32,
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

    /// Split the socket into two handles that can be used independently.
    ///
    /// This is useful for splitting a socket into separate read and write handles
    /// that can be used in different async tasks. Each handle maintains its own
    /// LTE link to keep the connection alive.
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
    /// This calls the [nrfxlib_sys::nrf_connect] function and can be used for tcp streams, udp connections and dtls connections.
    pub async fn connect(&self, address: SocketAddr) -> Result<(), Error> {
        unsafe {
            self.connect_with_cancellation(address, &Default::default())
                .await
        }
    }

    /// Connect to the given socket address.
    ///
    /// This calls the [nrfxlib_sys::nrf_connect] function and can be used for tcp streams, udp connections and dtls connections.
    ///
    /// ## Safety
    ///
    /// If the connect is cancelled, the socket may be in a weird state and should be dropped.
    pub async unsafe fn connect_with_cancellation(
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

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::Either);

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
    /// This calls the [nrfxlib_sys::nrf_bind] function and can be used for UDP sockets.
    pub async fn bind(&self, address: SocketAddr) -> Result<(), Error> {
        unsafe {
            self.bind_with_cancellation(address, &Default::default())
                .await
        }
    }

    /// Bind the socket to a given address.
    ///
    /// This calls the [nrfxlib_sys::nrf_bind] function and can be used for UDP sockets.
    ///
    /// ## Safety
    ///
    /// If the bind is cancelled, the socket may be in a weird state and should be dropped.
    pub async unsafe fn bind_with_cancellation(
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

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::Either);

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

    /// Write data to the socket.
    ///
    /// This calls the [nrfxlib_sys::nrf_send] function and can be used for TCP streams and dTLS connections.
    pub async fn write(&self, buffer: &[u8]) -> Result<usize, Error> {
        self.write_with_cancellation(buffer, &Default::default())
            .await
    }

    /// Write data to the socket with cancellation support.
    ///
    /// This calls the [nrfxlib_sys::nrf_send] function and can be used for TCP streams and dTLS connections.
    ///
    /// This operation can be cancelled using the provided [`CancellationToken`].
    pub async fn write_with_cancellation(
        &self,
        buffer: &[u8],
        token: &CancellationToken,
    ) -> Result<usize, Error> {
        token.bind_to_current_task().await;

        core::future::poll_fn(|cx| {
            #[cfg(feature = "defmt")]
            defmt::trace!("Sending with socket {}", self.fd);

            if token.is_cancelled() {
                return Poll::Ready(Err(Error::OperationCancelled));
            }

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::Out);

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

    /// Receive data from the socket.
    ///
    /// This calls the [nrfxlib_sys::nrf_recv] function and can be used for TCP streams and dTLS connections.
    pub async fn receive(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        self.receive_with_cancellation(buffer, &Default::default())
            .await
    }

    /// Receive data from the socket with cancellation support.
    ///
    /// This calls the [nrfxlib_sys::nrf_recv] function and can be used for TCP streams and dTLS connections.
    ///
    /// This operation can be cancelled using the provided [`CancellationToken`].
    pub async fn receive_with_cancellation(
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

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::In);

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recv(self.fd, buffer.as_mut_ptr() as *mut _, buffer.len(), 0)
            };

            if receive_result == -1 {
                receive_result = get_last_error().abs().neg();
            }

            #[cfg(feature = "defmt")]
            defmt::trace!("Receive result {}", receive_result);

            const NRF_EWOULDBLOCK: isize = -(nrfxlib_sys::NRF_EWOULDBLOCK as isize);
            const NRF_ENOTCONN: isize = -(nrfxlib_sys::NRF_ENOTCONN as isize);
            const NRF_EMSGSIZE: isize = -(nrfxlib_sys::NRF_EMSGSIZE as isize);

            match receive_result {
                0 if !buffer.is_empty() => Poll::Ready(Err(Error::Disconnected)),
                NRF_ENOTCONN => Poll::Ready(Err(Error::Disconnected)),
                NRF_EMSGSIZE => Poll::Ready(Err(Error::TlsPacketTooBig)),
                bytes_received @ 0.. => Poll::Ready(Ok(bytes_received as usize)),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    /// Receive data from the socket along with the sender's address.
    ///
    /// This calls the [nrfxlib_sys::nrf_recvfrom] function and can be used for UDP sockets.
    pub async fn receive_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        self.receive_from_with_cancellation(buffer, &Default::default())
            .await
    }

    /// Receive data from the socket along with the sender's address, with cancellation support.
    ///
    /// This calls the [nrfxlib_sys::nrf_recvfrom] function and can be used for UDP sockets.
    ///
    /// This operation can be cancelled using the provided [`CancellationToken`].
    pub async fn receive_from_with_cancellation(
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
            let mut socket_addr_len = socket_addr_store.len() as u32;

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::In);

            let mut receive_result = unsafe {
                nrfxlib_sys::nrf_recvfrom(
                    self.fd,
                    buffer.as_mut_ptr() as *mut _,
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
                    unsafe { (*socket_addr_ptr).sa_family = self.family as u16 }
                    NrfSockAddr::from(socket_addr_ptr as *const _).into()
                }))),
                NRF_EWOULDBLOCK => Poll::Pending,
                error => Poll::Ready(Err(Error::NrfError(error))),
            }
        })
        .await
    }

    /// Send data to a specific address through the socket.
    ///
    /// This calls the [nrfxlib_sys::nrf_sendto] function and can be used for UDP sockets.
    pub async fn send_to(&self, buffer: &[u8], address: SocketAddr) -> Result<usize, Error> {
        self.send_to_with_cancellation(buffer, address, &Default::default())
            .await
    }

    /// Send data to a specific address through the socket with cancellation support.
    ///
    /// This calls the [nrfxlib_sys::nrf_sendto] function and can be used for UDP sockets.
    ///
    /// This operation can be cancelled using the provided [`CancellationToken`].
    pub async fn send_to_with_cancellation(
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

            register_socket_waker(cx.waker().clone(), self.fd, SocketDirection::Out);

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

    /// Set a socket option.
    ///
    /// This calls the [nrfxlib_sys::nrf_setsockopt] function and provides access to various socket
    /// configuration options including timeouts, TLS settings, PDN binding, and protocol-specific
    /// options.
    ///
    /// See [`SocketOption`] for available options.
    pub fn set_option<'a>(&'a self, option: SocketOption<'a>) -> Result<(), SocketOptionError> {
        let length = option.get_length();

        let result = unsafe {
            nrfxlib_sys::nrf_setsockopt(
                self.fd,
                option.get_level(),
                option.get_name(),
                option.get_value(),
                length,
            )
        };

        if result == -1 {
            Err((get_last_error() as i32).into())
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
                panic!("{:?}", Error::NrfError(get_last_error()));
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

/// Socket address family.
///
/// Specifies the address family to use for the socket.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SocketFamily {
    /// Unspecified address family.
    Unspecified = nrfxlib_sys::NRF_AF_UNSPEC,
    /// IPv4 address family.
    Ipv4 = nrfxlib_sys::NRF_AF_INET,
    /// IPv6 address family.
    Ipv6 = nrfxlib_sys::NRF_AF_INET6,
    /// Raw packet interface.
    Raw = nrfxlib_sys::NRF_AF_PACKET,
}

/// Socket type.
///
/// Specifies the communication semantics for the socket.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SocketType {
    /// Stream socket (TCP).
    ///
    /// Provides sequenced, reliable, two-way, connection-based byte streams.
    Stream = nrfxlib_sys::NRF_SOCK_STREAM,
    /// Datagram socket (UDP).
    ///
    /// Provides connectionless, unreliable messages of a fixed maximum length.
    Datagram = nrfxlib_sys::NRF_SOCK_DGRAM,
    /// Raw socket.
    ///
    /// Provides raw network protocol access.
    Raw = nrfxlib_sys::NRF_SOCK_RAW,
}

/// Socket protocol.
///
/// Specifies the protocol to use with the socket.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SocketProtocol {
    /// Internet Protocol.
    IP = nrfxlib_sys::NRF_IPPROTO_IP,
    /// Transmission Control Protocol.
    Tcp = nrfxlib_sys::NRF_IPPROTO_TCP,
    /// User Datagram Protocol.
    Udp = nrfxlib_sys::NRF_IPPROTO_UDP,
    /// Internet Protocol Version 6.
    Ipv6 = nrfxlib_sys::NRF_IPPROTO_IPV6,
    /// Raw IP packets.
    Raw = nrfxlib_sys::NRF_IPPROTO_RAW,
    /// All protocols.
    All = nrfxlib_sys::NRF_IPPROTO_ALL,
    /// Transport Layer Security 1.2.
    Tls1v2 = nrfxlib_sys::NRF_SPROTO_TLS1v2,
    /// Datagram Transport Layer Security 1.2.
    DTls1v2 = nrfxlib_sys::NRF_SPROTO_DTLS1v2,
}

/// Socket configuration options.
///
/// These options can be set using [`Socket::set_option`] to configure various
/// aspects of socket behavior including timeouts, TLS settings, PDN binding,
/// and protocol-specific options.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum SocketOption<'a> {
    // NRF_SOL_SOCKET level options
    /// Non-zero requests reuse of local addresses in bind (protocol-specific).
    ReuseAddr(i32),
    /// Timeout value for socket receive and accept operations.
    ///
    /// Minimum supported resolution is 1 millisecond.
    ReceiveTimeout(nrfxlib_sys::nrf_timeval),
    /// Timeout value for socket send operation.
    ///
    /// Minimum supported resolution is 1 millisecond.
    SendTimeout(nrfxlib_sys::nrf_timeval),
    /// Bind this socket to a specific PDN ID.
    BindToPdn(i32),
    /// Send data on socket as part of exceptional event.
    ///
    /// Requires network support and PDN configuration with AT%EXCEPTIONALDATA.
    ExceptionalData(i32),
    /// Keep the socket open when its PDN connection is lost, or the device is set to flight mode.
    KeepOpen(i32),
    /// Release Assistance Indication (RAI).
    ///
    /// Values: NRF_RAI_NO_DATA, NRF_RAI_LAST, NRF_RAI_ONE_RESP, NRF_RAI_ONGOING, NRF_RAI_WAIT_MORE
    Rai(i32),

    // Protocol-level options
    /// Non-zero disables ICMP echo replies on both IPv4 and IPv6.
    SilenceAll(i32),
    /// Non-zero enables ICMP echo replies on IPv4.
    IpEchoReply(i32),
    /// Non-zero enables ICMP echo replies on IPv6.
    Ipv6EchoReply(i32),
    /// Non-zero delays IPv6 address refresh during power saving mode.
    Ipv6DelayedAddrRefresh(i32),
    /// Configure TCP server session inactivity timeout (0-135 seconds).
    TcpServerSessionTimeout(i32),

    // NRF_SOL_SECURE level options
    /// Set the hostname used for peer verification.
    TlsHostName(&'a str),
    /// Set the peer verification level.
    ///
    /// Values: 0 (disabled), 1 (optional), 2 (required)
    TlsPeerVerify(i32),
    /// Non-zero enables TLS session caching.
    TlsSessionCache(i32),
    /// Set/get the security tag associated with a socket.
    TlsTagList(&'a [nrfxlib_sys::nrf_sec_tag_t]),
    /// Set/get allowed cipher suite list.
    TlsCipherSuiteList(&'a [i32]),
    /// Set the role for the connection (client or server).
    ///
    /// Values: 0 (client), 1 (server)
    TlsRole(i32),
    /// Delete TLS session cache (write-only).
    TlsSessionCachePurge(i32),
    /// Set the DTLS handshake timeout.
    ///
    /// Values: 0 (no timeout), or specific timeout values
    DtlsHandshakeTimeout(i32),
    /// Set DTLS Connection ID setting.
    ///
    /// Values: 0 (disabled), 1 (supported), 2 (enabled)
    DtlsCid(i32),
    /// Save DTLS connection (write-only).
    DtlsConnSave(i32),
    /// Load DTLS connection (write-only).
    DtlsConnLoad(i32),
}
impl SocketOption<'_> {
    pub(crate) fn get_level(&self) -> i32 {
        match self {
            // NRF_SOL_SOCKET level
            SocketOption::ReuseAddr(_)
            | SocketOption::ReceiveTimeout(_)
            | SocketOption::SendTimeout(_)
            | SocketOption::BindToPdn(_)
            | SocketOption::ExceptionalData(_)
            | SocketOption::KeepOpen(_)
            | SocketOption::Rai(_) => nrfxlib_sys::NRF_SOL_SOCKET as i32,

            // Protocol levels
            SocketOption::SilenceAll(_) => nrfxlib_sys::NRF_IPPROTO_ALL as i32,
            SocketOption::IpEchoReply(_) => nrfxlib_sys::NRF_IPPROTO_IP as i32,
            SocketOption::Ipv6EchoReply(_) | SocketOption::Ipv6DelayedAddrRefresh(_) => {
                nrfxlib_sys::NRF_IPPROTO_IPV6 as i32
            }
            SocketOption::TcpServerSessionTimeout(_) => nrfxlib_sys::NRF_IPPROTO_TCP as i32,

            // NRF_SOL_SECURE level
            SocketOption::TlsHostName(_)
            | SocketOption::TlsPeerVerify(_)
            | SocketOption::TlsSessionCache(_)
            | SocketOption::TlsTagList(_)
            | SocketOption::TlsCipherSuiteList(_)
            | SocketOption::TlsRole(_)
            | SocketOption::TlsSessionCachePurge(_)
            | SocketOption::DtlsHandshakeTimeout(_)
            | SocketOption::DtlsCid(_)
            | SocketOption::DtlsConnSave(_)
            | SocketOption::DtlsConnLoad(_) => nrfxlib_sys::NRF_SOL_SECURE as i32,
        }
    }

    pub(crate) fn get_name(&self) -> i32 {
        match self {
            // NRF_SOL_SOCKET level
            SocketOption::ReuseAddr(_) => nrfxlib_sys::NRF_SO_REUSEADDR as i32,
            SocketOption::ReceiveTimeout(_) => nrfxlib_sys::NRF_SO_RCVTIMEO as i32,
            SocketOption::SendTimeout(_) => nrfxlib_sys::NRF_SO_SNDTIMEO as i32,
            SocketOption::BindToPdn(_) => nrfxlib_sys::NRF_SO_BINDTOPDN as i32,
            SocketOption::ExceptionalData(_) => nrfxlib_sys::NRF_SO_EXCEPTIONAL_DATA as i32,
            SocketOption::KeepOpen(_) => nrfxlib_sys::NRF_SO_KEEPOPEN as i32,
            SocketOption::Rai(_) => nrfxlib_sys::NRF_SO_RAI as i32,

            // Protocol-level options
            SocketOption::SilenceAll(_) => nrfxlib_sys::NRF_SO_SILENCE_ALL as i32,
            SocketOption::IpEchoReply(_) => nrfxlib_sys::NRF_SO_IP_ECHO_REPLY as i32,
            SocketOption::Ipv6EchoReply(_) => nrfxlib_sys::NRF_SO_IPV6_ECHO_REPLY as i32,
            SocketOption::Ipv6DelayedAddrRefresh(_) => {
                nrfxlib_sys::NRF_SO_IPV6_DELAYED_ADDR_REFRESH as i32
            }
            SocketOption::TcpServerSessionTimeout(_) => {
                nrfxlib_sys::NRF_SO_TCP_SRV_SESSTIMEO as i32
            }

            // NRF_SOL_SECURE level
            SocketOption::TlsHostName(_) => nrfxlib_sys::NRF_SO_SEC_HOSTNAME as i32,
            SocketOption::TlsPeerVerify(_) => nrfxlib_sys::NRF_SO_SEC_PEER_VERIFY as i32,
            SocketOption::TlsSessionCache(_) => nrfxlib_sys::NRF_SO_SEC_SESSION_CACHE as i32,
            SocketOption::TlsTagList(_) => nrfxlib_sys::NRF_SO_SEC_TAG_LIST as i32,
            SocketOption::TlsCipherSuiteList(_) => nrfxlib_sys::NRF_SO_SEC_CIPHERSUITE_LIST as i32,
            SocketOption::TlsRole(_) => nrfxlib_sys::NRF_SO_SEC_ROLE as i32,
            SocketOption::TlsSessionCachePurge(_) => {
                nrfxlib_sys::NRF_SO_SEC_SESSION_CACHE_PURGE as i32
            }
            SocketOption::DtlsHandshakeTimeout(_) => {
                nrfxlib_sys::NRF_SO_SEC_DTLS_HANDSHAKE_TIMEO as i32
            }
            SocketOption::DtlsCid(_) => nrfxlib_sys::NRF_SO_SEC_DTLS_CID as i32,
            SocketOption::DtlsConnSave(_) => nrfxlib_sys::NRF_SO_SEC_DTLS_CONN_SAVE as i32,
            SocketOption::DtlsConnLoad(_) => nrfxlib_sys::NRF_SO_SEC_DTLS_CONN_LOAD as i32,
        }
    }

    pub(crate) fn get_value(&self) -> *const core::ffi::c_void {
        match self {
            // NRF_SOL_SOCKET level
            SocketOption::ReuseAddr(x)
            | SocketOption::BindToPdn(x)
            | SocketOption::ExceptionalData(x)
            | SocketOption::KeepOpen(x)
            | SocketOption::Rai(x) => x as *const _ as *const core::ffi::c_void,
            SocketOption::ReceiveTimeout(x) | SocketOption::SendTimeout(x) => {
                x as *const _ as *const core::ffi::c_void
            }

            // Protocol-level options
            SocketOption::SilenceAll(x)
            | SocketOption::IpEchoReply(x)
            | SocketOption::Ipv6EchoReply(x)
            | SocketOption::Ipv6DelayedAddrRefresh(x)
            | SocketOption::TcpServerSessionTimeout(x) => x as *const _ as *const core::ffi::c_void,

            // NRF_SOL_SECURE level
            SocketOption::TlsHostName(s) => s.as_ptr() as *const core::ffi::c_void,
            SocketOption::TlsPeerVerify(x)
            | SocketOption::TlsSessionCache(x)
            | SocketOption::TlsRole(x)
            | SocketOption::TlsSessionCachePurge(x)
            | SocketOption::DtlsHandshakeTimeout(x)
            | SocketOption::DtlsCid(x)
            | SocketOption::DtlsConnSave(x)
            | SocketOption::DtlsConnLoad(x) => x as *const _ as *const core::ffi::c_void,
            SocketOption::TlsTagList(x) => x.as_ptr() as *const core::ffi::c_void,
            SocketOption::TlsCipherSuiteList(x) => x.as_ptr() as *const core::ffi::c_void,
        }
    }

    pub(crate) fn get_length(&self) -> u32 {
        match self {
            // NRF_SOL_SOCKET level
            SocketOption::ReuseAddr(x)
            | SocketOption::BindToPdn(x)
            | SocketOption::ExceptionalData(x)
            | SocketOption::KeepOpen(x)
            | SocketOption::Rai(x) => core::mem::size_of_val(x) as u32,
            SocketOption::ReceiveTimeout(x) | SocketOption::SendTimeout(x) => {
                core::mem::size_of_val(x) as u32
            }

            // Protocol-level options
            SocketOption::SilenceAll(x)
            | SocketOption::IpEchoReply(x)
            | SocketOption::Ipv6EchoReply(x)
            | SocketOption::Ipv6DelayedAddrRefresh(x)
            | SocketOption::TcpServerSessionTimeout(x) => core::mem::size_of_val(x) as u32,

            // NRF_SOL_SECURE level
            SocketOption::TlsHostName(s) => s.len() as u32,
            SocketOption::TlsPeerVerify(x)
            | SocketOption::TlsSessionCache(x)
            | SocketOption::TlsRole(x)
            | SocketOption::TlsSessionCachePurge(x)
            | SocketOption::DtlsHandshakeTimeout(x)
            | SocketOption::DtlsCid(x)
            | SocketOption::DtlsConnSave(x)
            | SocketOption::DtlsConnLoad(x) => core::mem::size_of_val(x) as u32,
            SocketOption::TlsTagList(x) => core::mem::size_of_val(*x) as u32,
            SocketOption::TlsCipherSuiteList(x) => core::mem::size_of_val(*x) as u32,
        }
    }
}

/// TLS peer verification level.
///
/// Controls whether and how the peer's TLS certificate is verified.
#[derive(Debug, Copy, Clone)]
pub enum PeerVerification {
    /// Peer verification is required. The connection will fail if verification fails.
    Enabled,
    /// Peer verification is optional. The connection proceeds even if verification fails.
    Optional,
    /// Peer verification is disabled. No verification is performed.
    Disabled,
}

impl PeerVerification {
    /// Convert the peer verification level to an integer value for use with socket options.
    pub fn as_integer(self) -> i32 {
        match self {
            PeerVerification::Enabled => 2,
            PeerVerification::Optional => 1,
            PeerVerification::Disabled => 0,
        }
    }
}

/// TLS cipher suites supported by the nRF9160 modem.
///
/// These are the allowed cipher suites for the nRF9160 modem.
/// For more information, see the [Nordic documentation](https://docs.nordicsemi.com/bundle/nrfxlib-apis-latest/page/group_nrf_socket_tls_cipher_suites.html).
#[repr(i32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum CipherSuite {
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 =
        nrfxlib_sys::NRF_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 as i32,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA =
        nrfxlib_sys::NRF_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA as i32,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 =
        nrfxlib_sys::NRF_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 as i32,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA =
        nrfxlib_sys::NRF_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA as i32,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = nrfxlib_sys::NRF_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA as i32,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 =
        nrfxlib_sys::NRF_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 as i32,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = nrfxlib_sys::NRF_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA as i32,
    TLS_PSK_WITH_AES_256_CBC_SHA = nrfxlib_sys::NRF_TLS_PSK_WITH_AES_256_CBC_SHA as i32,
    TLS_PSK_WITH_AES_128_CBC_SHA256 = nrfxlib_sys::NRF_TLS_PSK_WITH_AES_128_CBC_SHA256 as i32,
    TLS_PSK_WITH_AES_128_CBC_SHA = nrfxlib_sys::NRF_TLS_PSK_WITH_AES_128_CBC_SHA as i32,
    TLS_PSK_WITH_AES_128_CCM_8 = nrfxlib_sys::NRF_TLS_PSK_WITH_AES_128_CCM_8 as i32,
    TLS_EMPTY_RENEGOTIATIONINFO_SCSV = nrfxlib_sys::NRF_TLS_EMPTY_RENEGOTIATIONINFO_SCSV as i32,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =
        nrfxlib_sys::NRF_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as i32,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =
        nrfxlib_sys::NRF_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as i32,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =
        nrfxlib_sys::NRF_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as i32,
}

/// Errors that can occur when setting socket options.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SocketOptionError {
    /// The option could not be set when requested, try again.
    TryAgain,
    /// The socket argument is not a valid file descriptor.
    InvalidFileDescriptor,
    /// The socket option NRF_SO_RAI with value NRF_RAI_NO_DATA cannot be set on a socket that is not connected.
    DestinationAddressRequired,
    /// The send and receive timeout values are too big to fit into the timeout fields in the socket structure.
    TimeoutTooBig,
    /// The specified option is invalid at the specified socket level or the socket has been shut down.
    InvalidOption,
    /// The socket is already connected, and a specified option cannot be set while the socket is connected.
    AlreadyConnected,
    /// The option is not supported by the protocol.
    UnsupportedOption,
    /// The socket argument does not refer to a socket.
    NotASocket,
    /// There was insufficient memory available for the operation to complete.
    OutOfMemory,
    /// Insufficient resources are available in the system to complete the call.
    OutOfResources,
    /// The option is not supported with the current socket configuration.
    OperationNotSupported,
    /// Modem was shut down.
    ModemShutdown,
}

impl From<i32> for SocketOptionError {
    fn from(errno: i32) -> Self {
        match errno.unsigned_abs() {
            nrfxlib_sys::NRF_EAGAIN => SocketOptionError::TryAgain,
            nrfxlib_sys::NRF_EBADF => SocketOptionError::InvalidFileDescriptor,
            nrfxlib_sys::NRF_EDESTADDRREQ => SocketOptionError::DestinationAddressRequired,
            nrfxlib_sys::NRF_EINVAL => SocketOptionError::InvalidOption,
            nrfxlib_sys::NRF_EISCONN => SocketOptionError::AlreadyConnected,
            nrfxlib_sys::NRF_ENOPROTOOPT => SocketOptionError::UnsupportedOption,
            nrfxlib_sys::NRF_ENOTSOCK => SocketOptionError::NotASocket,
            nrfxlib_sys::NRF_ENOMEM => SocketOptionError::OutOfMemory,
            nrfxlib_sys::NRF_ENOBUFS => SocketOptionError::OutOfResources,
            nrfxlib_sys::NRF_EOPNOTSUPP => SocketOptionError::OperationNotSupported,
            nrfxlib_sys::NRF_ESHUTDOWN => SocketOptionError::ModemShutdown,
            _ => panic!("Unknown error code: {}", errno),
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const ATOMIC_U8_INIT: AtomicU8 = AtomicU8::new(0);
static ACTIVE_SPLIT_SOCKETS: [AtomicU8; nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT as usize] =
    [ATOMIC_U8_INIT; nrfxlib_sys::NRF_MODEM_MAX_SOCKET_COUNT as usize];

/// A handle to a split socket.
///
/// Created by calling [`Socket::split`]. This allows a socket to be split into
/// two handles that can be used independently in different async tasks (e.g., one
/// for reading and one for writing).
///
/// Each handle maintains its own LTE link and can be deactivated independently,
/// though the underlying socket is only closed when the last handle is dropped.
pub struct SplitSocketHandle {
    inner: Option<Socket>,
    index: usize,
}

impl SplitSocketHandle {
    /// Deactivates this socket handle and its LTE link.
    ///
    /// This will deactivate the LTE link associated with this handle. If this is the
    /// last remaining handle to the split socket, the underlying socket will also be closed.
    ///
    /// A normal drop will do the same thing, but blocking.
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
