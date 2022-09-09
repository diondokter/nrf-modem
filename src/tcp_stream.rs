use crate::{
    error::Error,
    socket::{Socket, SocketFamily, SocketProtocol, SocketType},
};
use no_std_net::ToSocketAddrs;

pub struct TcpStream {
    inner: Socket,
}

impl TcpStream {
    pub async fn connect(addr: impl ToSocketAddrs) -> Result<Self, Error> {
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
                                SocketType::Stream,
                                SocketProtocol::Tcp,
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
                                SocketType::Stream,
                                SocketProtocol::Tcp,
                            )
                            .await?,
                        );
                        &mut socketv6
                    }
                },
            };

            match socket.as_mut().unwrap().connect(addr).await {
                Ok(_) => {
                    return Ok(TcpStream {
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

    pub fn split(&self) -> (TcpReadStream<'_>, TcpWriteStream<'_>) {
        (
            TcpReadStream { stream: self },
            TcpWriteStream { stream: self },
        )
    }

    pub async fn receive<'buf>(&self, buf: &'buf mut [u8]) -> Result<&'buf mut [u8], Error> {
        self.split().0.receive(buf).await
    }

    pub async fn receive_exact(&self, buf: &mut [u8]) -> Result<(), Error> {
        self.split().0.receive_exact(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> Result<(), Error> {
        self.split().1.write(buf).await
    }
}

pub struct TcpReadStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TcpReadStream<'a> {
    pub async fn receive<'buf>(&self, buf: &'buf mut [u8]) -> Result<&'buf mut [u8], Error> {
        let max_receive_len = 1024.min(buf.len());
        let received_bytes = self
            .stream
            .inner
            .receive(&mut buf[..max_receive_len])
            .await?;
        Ok(&mut buf[..received_bytes])
    }

    pub async fn receive_exact(&self, buf: &mut [u8]) -> Result<(), Error> {
        let mut received_bytes = 0;

        while received_bytes < buf.len() {
            received_bytes += self.receive(&mut buf[received_bytes..]).await?.len();
        }

        Ok(())
    }
}

pub struct TcpWriteStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TcpWriteStream<'a> {
    pub async fn write(&self, buf: &[u8]) -> Result<(), Error> {
        let mut written_bytes = 0;

        while written_bytes < buf.len() {
            // We can't write very huge chunks because then the socket can't process it all at once
            let max_write_len = 1024.min(buf.len() - written_bytes);
            written_bytes += self
                .stream
                .inner
                .write(&buf[written_bytes..][..max_write_len])
                .await?;
        }

        Ok(())
    }
}
