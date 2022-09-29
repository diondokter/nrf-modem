use crate::{
    dns,
    error::Error,
    socket::{Socket, SocketFamily, SocketOption, SocketProtocol, SocketType},
};

use no_std_net::SocketAddr;

pub struct DtlsSocket {
    socket: Socket,
}

impl DtlsSocket {
    pub async fn new(peer_verify: PeerVerification, security_tags: &[u32]) -> Result<Self, Error> {
        let socket = Socket::create(
            SocketFamily::Ipv4,
            SocketType::Datagram,
            SocketProtocol::DTls1v2,
        )
        .await?;
        socket.set_option(SocketOption::TlsPeerVerify(peer_verify.as_integer()))?;
        socket.set_option(SocketOption::TlsSessionCache(0))?;
        socket.set_option(SocketOption::TlsTagList(security_tags))?;

        Ok(DtlsSocket { socket })
    }

    pub async fn connect(&mut self, hostname: &str, port: u16) -> Result<(), Error> {
        self.socket
            .set_option(SocketOption::TlsHostName(hostname))?;

        let ip = dns::get_host_by_name(hostname).await?;

        let addr = SocketAddr::from((ip, port));

        self.socket.connect(addr).await?;

        Ok(())
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }

    pub fn split(&self) -> (DtlsReceiveSocket<'_>, DtlsSendSocket<'_>) {
        (
            DtlsReceiveSocket { socket: self },
            DtlsSendSocket { socket: self },
        )
    }

    pub async fn receive_from<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
        self.split().0.receive_from(buf).await
    }

    pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        self.split().1.send(buf).await
    }
}

pub struct DtlsReceiveSocket<'a> {
    socket: &'a DtlsSocket,
}

impl<'a> DtlsReceiveSocket<'a> {
    pub async fn receive_from<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
        let (received_len, addr) = self.socket.socket.receive_from(buf).await?;
        Ok((&mut buf[..received_len], addr))
    }
}

pub struct DtlsSendSocket<'a> {
    socket: &'a DtlsSocket,
}

impl<'a> DtlsSendSocket<'a> {
    pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        self.socket.socket.write(buf).await.map(|_| ())
    }
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
