use crate::{
    error::Error,
    socket::{Socket},
};
use no_std_net::ToSocketAddrs;

pub struct TcpStream {
    inner: Socket,
}

impl TcpStream {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
        todo!()
    }

    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        todo!()
    }

    pub fn try_write(&self, buf: &[u8]) -> Result<usize, Error> {
        todo!()
    }
}
