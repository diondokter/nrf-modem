use crate::{
    error::Error,
    ffi::get_last_error,
    ip::NrfSockAddr,
    lte_link::LteLink,
    waker_node_list::{WakerNode, WakerNodeList},
};
use core::{cell::RefCell, future::Future, ops::Neg, task::Poll};
use embassy::blocking_mutex::CriticalSectionMutex;
use no_std_net::SocketAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub(crate) static WAKER_NODE_LIST: CriticalSectionMutex<RefCell<WakerNodeList<()>>> =
    CriticalSectionMutex::new(RefCell::new(WakerNodeList::new()));

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

        ConnectFuture {
            fd: &self.fd,
            address,
            waker_node: None,
        }
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

        BindFuture {
            fd: &self.fd,
            address,
            waker_node: None,
        }
        .await?;

        Ok(())
    }

    pub async fn write(&self, buffer: &[u8]) -> Result<usize, Error> {
        WriteFuture {
            fd: &self.fd,
            data: buffer,
            waker_node: None,
        }
        .await
    }

    pub async fn receive(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        ReceiveFuture {
            fd: &self.fd,
            data: buffer,
            waker_node: None,
        }
        .await
    }

    pub async fn receive_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        ReceiveFromFuture {
            fd: &self.fd,
            family: self.family,
            data: buffer,
            waker_node: None,
        }
        .await
    }

    pub async fn send_to(&self, buffer: &[u8], address: SocketAddr) -> Result<usize, Error> {
        SendToFuture {
            fd: &self.fd,
            data: buffer,
            address,
            waker_node: None,
        }
        .await
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

        let address = NrfSockAddr::from(self.address);

        let mut connect_result =
            unsafe { nrfxlib_sys::nrf_connect(*self.fd, address.as_ptr(), address.size() as u32) };

        const NRF_EINPROGRESS: i32 = nrfxlib_sys::NRF_EINPROGRESS as i32;
        const NRF_EISCONN: i32 = nrfxlib_sys::NRF_EISCONN as i32;

        if connect_result == -1 {
            connect_result = get_last_error();
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Connect result {}", connect_result);

        match connect_result {
            0 => Poll::Ready(Ok(())),
            NRF_EISCONN => Poll::Ready(Ok(())),
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

struct BindFuture<'s> {
    fd: &'s i32,
    address: SocketAddr,
    waker_node: Option<WakerNode<()>>,
}

impl<'s> Future for BindFuture<'s> {
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
        defmt::trace!("Binding socket {}", self.fd);

        let address = NrfSockAddr::from(self.address);

        let mut connect_result =
            unsafe { nrfxlib_sys::nrf_bind(*self.fd, address.as_ptr(), address.size() as u32) };

        const NRF_EINPROGRESS: i32 = nrfxlib_sys::NRF_EINPROGRESS as i32;
        const NRF_EISCONN: i32 = nrfxlib_sys::NRF_EISCONN as i32;

        if connect_result == -1 {
            connect_result = get_last_error();
        }

        #[cfg(feature = "defmt")]
        defmt::trace!("Bind result {}", connect_result);

        match connect_result {
            0 => Poll::Ready(Ok(())),
            NRF_EISCONN => Poll::Ready(Ok(())),
            NRF_EINPROGRESS => Poll::Pending,
            error => Poll::Ready(Err(Error::NrfError(error))),
        }
    }
}

impl<'s> Drop for BindFuture<'s> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| unsafe {
                list.borrow_mut().remove_node(waker_node as *mut _);
            });
        }
    }
}

struct WriteFuture<'s, 'd> {
    fd: &'s i32,
    data: &'d [u8],
    waker_node: Option<WakerNode<()>>,
}

impl<'s, 'd> Future for WriteFuture<'s, 'd> {
    type Output = Result<usize, Error>;

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
        defmt::trace!("Sending with socket {}", self.fd);

        let mut send_result = unsafe {
            nrfxlib_sys::nrf_send(
                *self.fd,
                self.data.as_ptr() as *const _,
                self.data.len() as u32,
                0,
            )
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
    }
}

impl<'s, 'd> Drop for WriteFuture<'s, 'd> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| unsafe {
                list.borrow_mut().remove_node(waker_node as *mut _);
            });
        }
    }
}

struct ReceiveFuture<'s, 'd> {
    fd: &'s i32,
    data: &'d mut [u8],
    waker_node: Option<WakerNode<()>>,
}

impl<'s, 'd> Future for ReceiveFuture<'s, 'd> {
    type Output = Result<usize, Error>;

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
        defmt::trace!("Receiving with socket {}", self.fd);

        let mut receive_result = unsafe {
            nrfxlib_sys::nrf_recv(
                *self.fd,
                self.data.as_ptr() as *mut _,
                self.data.len() as u32,
                0,
            )
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
    }
}

impl<'s, 'd> Drop for ReceiveFuture<'s, 'd> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| unsafe {
                list.borrow_mut().remove_node(waker_node as *mut _);
            });
        }
    }
}

struct ReceiveFromFuture<'s, 'd> {
    fd: &'s i32,
    family: SocketFamily,
    data: &'d mut [u8],
    waker_node: Option<WakerNode<()>>,
}

impl<'s, 'd> Future for ReceiveFromFuture<'s, 'd> {
    type Output = Result<(usize, SocketAddr), Error>;

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
        defmt::trace!("Receiving with socket {}", self.fd);

        // Big enough to store both ipv4 and ipv6
        let mut socket_addr_store = [0u8; core::mem::size_of::<nrfxlib_sys::nrf_sockaddr_in6>()];
        let socket_addr_ptr = socket_addr_store.as_mut_ptr() as *mut nrfxlib_sys::nrf_sockaddr;
        let mut socket_addr_len = 0u32;

        let mut receive_result = unsafe {
            nrfxlib_sys::nrf_recvfrom(
                *self.fd,
                self.data.as_ptr() as *mut _,
                self.data.len() as u32,
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
    }
}

impl<'s, 'd> Drop for ReceiveFromFuture<'s, 'd> {
    fn drop(&mut self) {
        if let Some(waker_node) = self.waker_node.as_mut() {
            WAKER_NODE_LIST.lock(|list| unsafe {
                list.borrow_mut().remove_node(waker_node as *mut _);
            });
        }
    }
}

struct SendToFuture<'s, 'd> {
    fd: &'s i32,
    data: &'d [u8],
    address: SocketAddr,
    waker_node: Option<WakerNode<()>>,
}

impl<'s, 'd> Future for SendToFuture<'s, 'd> {
    type Output = Result<usize, Error>;

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
        defmt::trace!("Sending with socket {}", self.fd);

        let addr = NrfSockAddr::from(self.address);

        let mut send_result = unsafe {
            nrfxlib_sys::nrf_sendto(
                *self.fd,
                self.data.as_ptr() as *mut _,
                self.data.len() as u32,
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
    }
}

impl<'s, 'd> Drop for SendToFuture<'s, 'd> {
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
