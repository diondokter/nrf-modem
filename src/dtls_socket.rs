use crate::{
    dns,
    error::Error,
    socket::{Socket, SocketFamily, SocketOption, SocketProtocol, SocketType, SplitSocketHandle},
    CancellationToken,
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
            self.receive_from_with_cancellation(buf, &Default::default())
                .await
        }

        pub async fn receive_from_with_cancellation<'buf>(
            &self,
            buf: &'buf mut [u8],
            token: &CancellationToken,
        ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
            let (received_len, addr) = self.socket().receive_from(buf, token).await?;
            Ok((&mut buf[..received_len], addr))
        }
    };
}

macro_rules! impl_send {
    () => {
        pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
            self.send_with_cancellation(buf, &Default::default()).await
        }

        pub async fn send_with_cancellation(
            &self,
            buf: &[u8],
            token: &CancellationToken,
        ) -> Result<(), Error> {
            self.socket().write(buf, token).await.map(|_| ())
        }
    };
}

impl DtlsSocket {
    pub async fn connect(
        hostname: &str,
        port: u16,
        peer_verify: PeerVerification,
        security_tags: &[u32],
    ) -> Result<Self, Error> {
        Self::connect_with_cancellation(
            hostname,
            port,
            peer_verify,
            security_tags,
            &Default::default(),
        )
        .await
    }

    pub async fn connect_with_cancellation(
        hostname: &str,
        port: u16,
        peer_verify: PeerVerification,
        security_tags: &[u32],
        token: &CancellationToken,
    ) -> Result<Self, Error> {
        let inner = Socket::create(
            SocketFamily::Ipv4,
            SocketType::Datagram,
            SocketProtocol::DTls1v2,
        )
        .await?;
        inner.set_option(SocketOption::TlsPeerVerify(peer_verify.as_integer()))?;
        inner.set_option(SocketOption::TlsSessionCache(0))?;
        inner.set_option(SocketOption::TlsTagList(security_tags))?;
        inner.set_option(SocketOption::TlsHostName(hostname))?;

        token.as_result()?;

        let ip = dns::get_host_by_name_with_cancellation(hostname, token).await?;
        let addr = SocketAddr::from((ip, port));

        unsafe {
            inner.connect(addr, token).await?;
        }

        Ok(DtlsSocket { inner })
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
