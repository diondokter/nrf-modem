use core::str::Utf8Error;

use at_commands::parser::ParseError;

use crate::socket::SocketOptionError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
/// The global error type of this crate
pub enum Error {
    /// An operation was tried for which the modem needs to be initialized, but the modem is not yet initialized
    ModemNotInitialized,
    /// There can only be one Gnss instance, yet a second was requested
    GnssAlreadyTaken,
    /// An unkown error occured. Check [nrf_errno.h](https://github.com/nrfconnect/sdk-nrfxlib/blob/main/nrf_modem/include/nrf_errno.h) to see what it means.
    ///
    /// Sometimes the sign is flipped, but ignore that and just look at the number.
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
    TooManyLteLinks,
    InternalRuntimeMutexLocked,
    /// The given memory layout falls outside of the acceptable range
    BadMemoryLayout,
    ModemAlreadyInitialized,
    #[cfg(feature = "dns-async")]
    DomainNameTooLong,
    #[cfg(feature = "dns-async")]
    DnsCacheOverflow,
    #[cfg(feature = "dns-async")]
    DnsHeaderBufferOverflow,
    #[cfg(feature = "dns-async")]
    DnsQuestionBufferOverflow,
    #[cfg(feature = "dns-async")]
    DnsSocketTimeout,
    #[cfg(feature = "dns-async")]
    DnsSocketError,
    #[cfg(feature = "dns-async")]
    DnsParseFailed,
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
