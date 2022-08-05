use core::str::Utf8Error;

use at_commands::parser::ParseError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    ModemNotInitialized,
    GnssAlreadyTaken,
    NrfError(i32),
    BufferTooSmall(Option<usize>),
    OutOfMemory,
    AtParseError(ParseError),
    InvalidSystemModeConfig,
    StringNotNulTerminated,
    Utf8Error,
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

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::AtParseError(e)
    }
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self::Utf8Error
    }
}
