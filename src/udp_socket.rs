use crate::{
    error::Error,
    socket::{Socket, SocketFamily, SocketProtocol, SocketType},
};
use no_std_net::{SocketAddr, ToSocketAddrs};

pub struct UdpSocket {
    inner: Socket,
}

impl UdpSocket {
    pub async fn bind(addr: impl ToSocketAddrs) -> Result<Self, Error> {
        let mut last_error = None;

        let addrs = addr.to_socket_addrs().unwrap();
        let mut socketv4 = None;
        let mut socketv6 = None;

        for addr in addrs {
            let socket = match addr {
                no_std_net::SocketAddr::V4(_) => match socketv4 {
                    Some(_) => &mut socketv4,
                    None => {
                        socketv4 = Some(
                            Socket::create(
                                SocketFamily::Ipv4,
                                SocketType::Datagram,
                                SocketProtocol::Udp,
                            )
                            .await?,
                        );
                        &mut socketv4
                    }
                },
                no_std_net::SocketAddr::V6(_) => match socketv6 {
                    Some(_) => &mut socketv6,
                    None => {
                        socketv6 = Some(
                            Socket::create(
                                SocketFamily::Ipv6,
                                SocketType::Datagram,
                                SocketProtocol::Udp,
                            )
                            .await?,
                        );
                        &mut socketv6
                    }
                },
            };

            match socket.as_mut().unwrap().bind(addr).await {
                Ok(_) => {
                    return Ok(UdpSocket {
                        inner: socket.take().unwrap(),
                    })
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.take().unwrap())
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    pub fn split(&self) -> (UdpReceiveSocket<'_>, UdpSendSocket<'_>) {
        (
            UdpReceiveSocket { socket: self },
            UdpSendSocket { socket: self },
        )
    }

    pub async fn receive_from<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
        self.split().0.receive_from(buf).await
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<(), Error> {
        self.split().1.send_to(buf, addr).await
    }
    pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        self.split().1.send(buf).await
    }
}

pub struct UdpReceiveSocket<'a> {
    socket: &'a UdpSocket,
}

impl<'a> UdpReceiveSocket<'a> {
    pub async fn receive_from<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut [u8], SocketAddr), Error> {
        let (received_len, addr) = self.socket.inner.receive_from(buf).await?;
        Ok((&mut buf[..received_len], addr))
    }
}

pub struct UdpSendSocket<'a> {
    socket: &'a UdpSocket,
}

impl<'a> UdpSendSocket<'a> {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<(), Error> {
        self.socket.inner.send_to(buf, addr).await.map(|_| ())
    }
    pub async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        self.socket.inner.send(buf).await.map(|_| ())
    }
}
