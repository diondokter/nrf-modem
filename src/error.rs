use core::str::Utf8Error;

use at_commands::parser::ParseError;

use crate::socket::SocketOptionError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    ModemNotInitialized,
    GnssAlreadyTaken,
    NrfError(isize),
    BufferTooSmall(Option<usize>),
    OutOfMemory,
    AtParseError(ParseError),
    InvalidSystemModeConfig,
    StringNotNulTerminated,
    Utf8Error,
    LteRegistrationDenied,
    SimFailure,
    UnexpectedAtResponse,
    HostnameNotAscii,
    HostnameTooLong,
    AddressNotFound,
    SocketOptionError(SocketOptionError),
    /// The ongoing operation has been cancelled by the user
    OperationCancelled,
    SmsNumberNotAscii,
    Disconnected,
}

pub trait ErrorSource {
    fn into_result(self) -> Result<(), Error>;
}

impl ErrorSource for isize {
    fn into_result(self) -> Result<(), Error> {
        if self == 0 {
            return Ok(());
        }

        Err(Error::NrfError(self))
    }
}
impl ErrorSource for i32 {
    fn into_result(self) -> Result<(), Error> {
        if self == 0 {
            return Ok(());
        }

        Err(Error::NrfError(self as isize))
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

impl From<SocketOptionError> for Error {
    fn from(e: SocketOptionError) -> Self {
        Self::SocketOptionError(e)
    }
}
