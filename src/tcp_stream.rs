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
                                SocketProtocol::IP,
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
                                SocketProtocol::Ipv6,
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

    pub fn try_read(&self, _buf: &mut [u8]) -> Result<usize, Error> {
        todo!()
    }

    pub fn try_write(&self, _buf: &[u8]) -> Result<usize, Error> {
        todo!()
    }
}
