macro_rules! impl_error_trait {
    ($name:path, $error:path, <$($generics:lifetime),*>) => {
        impl<$($generics),*> embedded_io_async::ErrorType for $name {
            type Error = $error;
        }
    };
}

macro_rules! impl_write_trait {
    ($name:path, <$($generics:lifetime),*>) => {
        impl<$($generics),*> embedded_io_async::Write for $name {
            async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                Self::write(self, buf).await?;
                Ok(buf.len())
            }

            async fn flush(&mut self) -> Result<(), Self::Error> {
                // There's no ability to flush
                Ok(())
            }
        }
    };
}

macro_rules! impl_read_trait {
    ($name:path, <$($generics:lifetime),*>) => {
        impl<$($generics),*> embedded_io_async::Read for $name {
            async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                let read = self.receive(buf).await?;
                Ok(read.len())
            }
        }
    };
}

pub(crate) use impl_error_trait;
pub(crate) use impl_read_trait;
pub(crate) use impl_write_trait;
