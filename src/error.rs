#[derive(Debug, Clone)]
pub enum Error {
    ModemNotInitialized,
    GnssAlreadyTaken,
    NrfError(i32),
}

pub trait ErrorSource {
    fn into_result(self) -> Result<(), Error>;
}

impl ErrorSource for i32 {
    fn into_result(self) -> Result<(), Error> {
        if self == 0 {
            return Ok(());
        }

        Err(Error::NrfError(self))
    }
}
