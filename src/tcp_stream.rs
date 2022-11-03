use crate::{
    error::Error,
    socket::{Socket, SocketFamily, SocketProtocol, SocketType, SplitSocketHandle},
    CancellationToken,
};
use no_std_net::ToSocketAddrs;

/// A TCP stream that is connected to another endpoint
pub struct TcpStream {
    inner: Socket,
}

macro_rules! impl_receive {
    () => {
        /// Try fill the given buffer with the data that has been received. The written part of the
        /// buffer is returned.
        pub async fn receive<'buf>(&self, buf: &'buf mut [u8]) -> Result<&'buf mut [u8], Error> {
            self.receive_with_cancellation(buf, &Default::default())
                .await
        }

        /// Try fill the given buffer with the data that has been received. The written part of the
        /// buffer is returned.
        pub async fn receive_with_cancellation<'buf>(
            &self,
            buf: &'buf mut [u8],
            token: &CancellationToken,
        ) -> Result<&'buf mut [u8], Error> {
            let max_receive_len = 1024.min(buf.len());
            let received_bytes = self
                .socket()
                .receive(&mut buf[..max_receive_len], token)
                .await?;
            Ok(&mut buf[..received_bytes])
        }

        /// Fill the entire buffer with data that has been received. This will wait as long as necessary to fill up the
        /// buffer.
        ///
        /// If there's an error while receiving, then the error is returned as well as the part of the buffer that was
        /// partially filled with received data.
        pub async fn receive_exact<'buf>(
            &self,
            buf: &'buf mut [u8],
        ) -> Result<(), (Error, &'buf mut [u8])> {
            self.receive_exact_with_cancellation(buf, &Default::default())
                .await
        }

        /// Fill the entire buffer with data that has been received. This will wait as long as necessary to fill up the
        /// buffer.
        ///
        /// If there's an error while receiving, then the error is returned as well as the part of the buffer that was
        /// partially filled with received data.
        pub async fn receive_exact_with_cancellation<'buf>(
            &self,
            buf: &'buf mut [u8],
            token: &CancellationToken,
        ) -> Result<(), (Error, &'buf mut [u8])> {
            let mut received_bytes = 0;

            while received_bytes < buf.len() {
                match self
                    .receive_with_cancellation(&mut buf[received_bytes..], token)
                    .await
                {
                    Ok(received_data) => received_bytes += received_data.len(),
                    Err(e) => return Err((e.into(), &mut buf[..received_bytes])),
                }
            }

            Ok(())
        }
    };
}

macro_rules! impl_write {
    () => {
        /// Write the entire buffer to the stream
        pub async fn write(&self, buf: &[u8]) -> Result<(), Error> {
            self.write_with_cancellation(buf, &Default::default()).await
        }

        /// Write the entire buffer to the stream
        pub async fn write_with_cancellation(
            &self,
            buf: &[u8],
            token: &CancellationToken,
        ) -> Result<(), Error> {
            let mut written_bytes = 0;

            while written_bytes < buf.len() {
                // We can't write very huge chunks because then the socket can't process it all at once
                let max_write_len = 1024.min(buf.len() - written_bytes);
                written_bytes += self
                    .socket()
                    .write(&buf[written_bytes..][..max_write_len], token)
                    .await?;
            }

            Ok(())
        }
    };
}

impl TcpStream {
    /// Connect a TCP stream to the given address
    pub async fn connect(addr: impl ToSocketAddrs) -> Result<Self, Error> {
        Self::connect_with_cancellation(addr, &Default::default()).await
    }

    /// Connect a TCP stream to the given address
    pub async fn connect_with_cancellation(
        addr: impl ToSocketAddrs,
        token: &CancellationToken,
    ) -> Result<Self, Error> {
        let mut last_error = None;

        let addrs = addr.to_socket_addrs().unwrap();
        let mut socketv4 = None;
        let mut socketv6 = None;

        for addr in addrs {
            token.as_result()?;

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

            match unsafe { socket.as_mut().unwrap().connect(addr, token).await } {
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

    /// Get the raw underlying file descriptor for when you need to interact with the nrf libraries directly
    pub fn as_raw_fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    fn socket(&self) -> &Socket {
        &self.inner
    }

    /// Split the stream into an owned read and write half
    pub fn split_owned(self) -> (OwnedTcpReadStream, OwnedTcpWriteStream) {
        let (read_split, write_split) = self.inner.split();

        (
            OwnedTcpReadStream { stream: read_split },
            OwnedTcpWriteStream {
                stream: write_split,
            },
        )
    }

    /// Split the stream into a borrowed read and write half
    pub fn split(&self) -> (TcpReadStream<'_>, TcpWriteStream<'_>) {
        (
            TcpReadStream { stream: self },
            TcpWriteStream { stream: self },
        )
    }

    impl_receive!();
    impl_write!();

    /// Deactivates the socket and the LTE link.
    /// A normal drop will do the same thing, but blocking.
    pub async fn deactivate(self) -> Result<(), Error> {
        self.inner.deactivate().await?;
        Ok(())
    }
}

pub struct TcpReadStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TcpReadStream<'a> {
    fn socket(&self) -> &Socket {
        &self.stream.inner
    }

    impl_receive!();
}

pub struct TcpWriteStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TcpWriteStream<'a> {
    fn socket(&self) -> &Socket {
        &self.stream.inner
    }

    impl_write!();
}

pub struct OwnedTcpReadStream {
    stream: SplitSocketHandle,
}

impl OwnedTcpReadStream {
    fn socket(&self) -> &Socket {
        &self.stream
    }

    impl_receive!();

    /// Deactivates the socket and the LTE link.
    /// A normal drop will do the same thing, but blocking.
    pub async fn deactivate(self) -> Result<(), Error> {
        self.stream.deactivate().await?;
        Ok(())
    }
}

pub struct OwnedTcpWriteStream {
    stream: SplitSocketHandle,
}

impl OwnedTcpWriteStream {
    fn socket(&self) -> &Socket {
        &self.stream
    }

    impl_write!();

    /// Deactivates the socket and the LTE link.
    /// A normal drop will do the same thing, but blocking.
    pub async fn deactivate(self) -> Result<(), Error> {
        self.stream.deactivate().await?;
        Ok(())
    }
}
