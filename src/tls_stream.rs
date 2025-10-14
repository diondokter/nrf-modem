use crate::{
    dns,
    error::Error,
    socket::{
        CipherSuite, PeerVerification, Socket, SocketFamily, SocketOption, SocketProtocol,
        SocketType, SplitSocketHandle,
    },
    CancellationToken, LteLink,
};
use core::net::SocketAddr;

pub struct TlsStream {
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

impl TlsStream {
    /// Connect an encrypted TCP stream to the given address
    ///
    /// This function attempts to connect to the given `hostname` and `port` using the specified
    /// security parameters.
    ///
    /// - `hostname`: The hostname of the server to connect to.
    /// - `port`: The port number of the server to connect to.
    /// - `peer_verify`: The peer verification policy to apply. Determines how the connection verifies the server's identity.
    /// - `security_tags`: A slice of [security tag](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/modem_key_mgmt.html) identifiers containing security elements.
    /// - `ciphers`: An optional slice of IANA cipher suite identifiers to use for the connection. If `None`, the default set of ciphers is used.
    /// - `resume_sessions`: Enable TLS session tickets, managed by the modem.
    pub async fn connect(
        hostname: &str,
        port: u16,
        peer_verify: PeerVerification,
        security_tags: &[u32],
        ciphers: Option<&[CipherSuite]>,
        resume_sessions: bool,
    ) -> Result<Self, Error> {
        Self::connect_with_cancellation(
            hostname,
            port,
            peer_verify,
            security_tags,
            ciphers,
            resume_sessions,
            &Default::default(),
        )
        .await
    }

    /// Connect an encrypted TCP stream to the given address
    ///
    /// This function attempts to connect to the given `hostname` and `port` using the specified
    /// security parameters.
    ///
    /// - `hostname`: The hostname of the server to connect to.
    /// - `port`: The port number of the server to connect to.
    /// - `peer_verify`: The peer verification policy to apply. Determines how the connection verifies the server's identity.
    /// - `security_tags`: A slice of [security tag](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/modem_key_mgmt.html) identifiers containing security elements.
    /// - `ciphers`: An optional slice of IANA cipher suite identifiers to use for the connection. If `None`, the default set of ciphers is used.
    /// - `resume_sessions`: Enable TLS session tickets, managed by the modem.
    /// - `token`: A [`CancellationToken`] that can be used to cancel the connection attempt.
    pub async fn connect_with_cancellation(
        hostname: &str,
        port: u16,
        peer_verify: PeerVerification,
        security_tags: &[u32],
        ciphers: Option<&[CipherSuite]>,
        resume_sessions: bool,
        token: &CancellationToken,
    ) -> Result<Self, Error> {
        if security_tags.is_empty() {
            return Err(Error::NoSecurityTag);
        }

        let lte_link = LteLink::new().await?;

        let ip = dns::get_host_by_name_with_cancellation(hostname, token).await?;
        let addr = SocketAddr::from((ip, port));

        token.as_result()?;

        let family = match addr {
            SocketAddr::V4(_) => SocketFamily::Ipv4,
            SocketAddr::V6(_) => SocketFamily::Ipv6,
        };

        let socket = Socket::create(family, SocketType::Stream, SocketProtocol::Tls1v2).await?;
        socket.set_option(SocketOption::TlsPeerVerify(peer_verify.as_integer()))?;
        socket.set_option(SocketOption::TlsSessionCache(resume_sessions as _))?;
        socket.set_option(SocketOption::TlsTagList(security_tags))?;
        socket.set_option(SocketOption::TlsHostName(hostname))?;
        if let Some(ciphers) = ciphers {
            socket.set_option(SocketOption::TlsCipherSuiteList(unsafe {
                core::slice::from_raw_parts(ciphers.as_ptr() as *const i32, ciphers.len())
            }))?;
        }

        match unsafe { socket.connect_with_cancellation(addr, token).await } {
            Ok(_) => {
                lte_link.deactivate().await?;
                Ok(TlsStream { inner: socket })
            }
            Err(e) => {
                socket.deactivate().await?;
                lte_link.deactivate().await?;
                Err(e)
            }
        }
    }

    /// Get the raw underlying file descriptor for when you need to interact with the nrf libraries directly
    pub fn as_raw_fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    fn socket(&self) -> &Socket {
        &self.inner
    }

    /// Split the stream into an owned read and write half
    pub async fn split_owned(self) -> Result<(OwnedTlsReadStream, OwnedTlsWriteStream), Error> {
        let (read_split, write_split) = self.inner.split().await?;

        Ok((
            OwnedTlsReadStream { stream: read_split },
            OwnedTlsWriteStream {
                stream: write_split,
            },
        ))
    }

    /// Split the stream into an owned read and write half
    pub fn split(&self) -> (TlsReadStream<'_>, TlsWriteStream<'_>) {
        (
            TlsReadStream { socket: self },
            TlsWriteStream { socket: self },
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

crate::embedded_io_macros::impl_error_trait!(TlsStream, Error, <>);
crate::embedded_io_macros::impl_read_trait!(TlsStream, <>);
crate::embedded_io_macros::impl_write_trait!(TlsStream, <>);

/// A borrowed read half of an encrypted TCP stream
pub struct TlsReadStream<'a> {
    socket: &'a TlsStream,
}

impl TlsReadStream<'_> {
    fn socket(&self) -> &Socket {
        &self.socket.inner
    }

    impl_receive!();
}

crate::embedded_io_macros::impl_error_trait!(TlsReadStream<'a>, Error, <'a>);
crate::embedded_io_macros::impl_read_trait!(TlsReadStream<'a>, <'a>);

/// A borrowed write half of an encrypted TCP stream
pub struct TlsWriteStream<'a> {
    socket: &'a TlsStream,
}

impl TlsWriteStream<'_> {
    fn socket(&self) -> &Socket {
        &self.socket.inner
    }

    impl_write!();
}

crate::embedded_io_macros::impl_error_trait!(TlsWriteStream<'a>, Error, <'a>);
crate::embedded_io_macros::impl_write_trait!(TlsWriteStream<'a>, <'a>);

/// An owned read half of an acrypted TCP stream
pub struct OwnedTlsReadStream {
    stream: SplitSocketHandle,
}

impl OwnedTlsReadStream {
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

crate::embedded_io_macros::impl_error_trait!(OwnedTlsReadStream, Error, <>);
crate::embedded_io_macros::impl_read_trait!(OwnedTlsReadStream, <>);

/// An owned write half of an encrypted TCP stream
pub struct OwnedTlsWriteStream {
    stream: SplitSocketHandle,
}

impl OwnedTlsWriteStream {
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

crate::embedded_io_macros::impl_error_trait!(OwnedTlsWriteStream, Error, <>);
crate::embedded_io_macros::impl_write_trait!(OwnedTlsWriteStream, <>);
