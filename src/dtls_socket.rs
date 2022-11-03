use crate::{
    dns,
    error::Error,
    socket::{Socket, SocketFamily, SocketOption, SocketProtocol, SocketType, SplitSocketHandle},
};

use no_std_net::SocketAddr;

pub struct DtlsSocket {
    inner: Socket,
}

macro_rules! impl_receive_from {
    () => {
        pub async fn receive_from<'buf>(
            &self,
            buf: &'buf mut [u8],
        ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
            let (received_len, addr) = self.socket().receive_from(buf).await?;
            Ok((&mut buf[..received_len], addr))
        }

        /// If a receive operation is going on, then it will be cancelled.
        /// The receive future will return [Error::OperationCancelled].
        ///
        /// This can be useful if you have a long-running task that is waiting on receiving data.
        pub fn cancel_receive(&self) {
            self.socket().cancel_receive();
        }
    };
}

macro_rules! impl_send {
    () => {
        pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
            self.socket().write(buf).await.map(|_| ())
        }
    };
}

impl DtlsSocket {
    pub async fn new(peer_verify: PeerVerification, security_tags: &[u32]) -> Result<Self, Error> {
        let inner = Socket::create(
            SocketFamily::Ipv4,
            SocketType::Datagram,
            SocketProtocol::DTls1v2,
        )
        .await?;
        inner.set_option(SocketOption::TlsPeerVerify(peer_verify.as_integer()))?;
        inner.set_option(SocketOption::TlsSessionCache(0))?;
        inner.set_option(SocketOption::TlsTagList(security_tags))?;

        Ok(DtlsSocket { inner })
    }

    pub async fn connect(&mut self, hostname: &str, port: u16) -> Result<(), Error> {
        self.inner.set_option(SocketOption::TlsHostName(hostname))?;

        let ip = dns::get_host_by_name(hostname).await?;

        let addr = SocketAddr::from((ip, port));

        self.inner.connect(addr).await?;

        Ok(())
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn split_owned(self) -> (OwnedDtlsReceiveSocket, OwnedDtlsSendSocket) {
        let (read_split, write_split) = self.inner.split();

        (
            OwnedDtlsReceiveSocket { socket: read_split },
            OwnedDtlsSendSocket {
                socket: write_split,
            },
        )
    }

    pub fn split(&self) -> (DtlsReceiveSocket<'_>, DtlsSendSocket<'_>) {
        (
            DtlsReceiveSocket { socket: self },
            DtlsSendSocket { socket: self },
        )
    }

    impl_receive_from!();
    impl_send!();

    /// Deactivates the socket and the LTE link.
    /// A normal drop will do the same thing, but blocking.
    pub async fn deactivate(self) -> Result<(), Error> {
        self.inner.deactivate().await?;
        Ok(())
    }
}

pub struct DtlsReceiveSocket<'a> {
    socket: &'a DtlsSocket,
}

impl<'a> DtlsReceiveSocket<'a> {
    fn socket(&self) -> &Socket {
        &self.socket.inner
    }

    impl_receive_from!();
}

pub struct DtlsSendSocket<'a> {
    socket: &'a DtlsSocket,
}

impl<'a> DtlsSendSocket<'a> {
    fn socket(&self) -> &Socket {
        &self.socket.inner
    }

    impl_send!();
}

pub struct OwnedDtlsReceiveSocket {
    socket: SplitSocketHandle,
}

impl OwnedDtlsReceiveSocket {
    fn socket(&self) -> &Socket {
        &self.socket
    }

    impl_receive_from!();
}

pub struct OwnedDtlsSendSocket {
    socket: SplitSocketHandle,
}

impl OwnedDtlsSendSocket {
    fn socket(&self) -> &Socket {
        &self.socket
    }

    impl_send!();
}

#[derive(Debug, Copy, Clone)]
pub enum PeerVerification {
    Enabled,
    Optional,
    Disabled,
}
impl PeerVerification {
    fn as_integer(self) -> u32 {
        match self {
            PeerVerification::Enabled => 2,
            PeerVerification::Optional => 1,
            PeerVerification::Disabled => 0,
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub enum Version {
    Dtls1v2,
}
