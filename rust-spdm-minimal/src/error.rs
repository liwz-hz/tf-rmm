use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmStatus {
    Success = 0,
    InvalidParameter = 0x80000001,
    InvalidStateLocal = 0x80000002,
    BufferFull = 0x80000004,
    BufferTooSmall = 0x80000003,
    VerifFail = 0x80000005,
    CryptoError = 0x80000006,
    NegotiationFail = 0x80000007,
    UnsupportedCap = 0x80000008,
    ErrorPeer = 0x80000009,
    BusyPeer = 0x8000000A,
    InvalidMsgSize = 0x8000000C,
    InvalidMsgField = 0x8000000D,
    InvalidSpdmVersion = 0x80000010,
    InvalidSpdmRequestCode = 0x80000011,
    InvalidSpdmResponseCode = 0x80000012,
    InvalidSpdmErrorCode = 0x80000013,
}

pub type SpdmResult<T = ()> = Result<T, SpdmStatus>;

impl From<SpdmStatus> for SpdmResult<()> {
    fn from(status: SpdmStatus) -> Self {
        if status == SpdmStatus::Success {
            Ok(())
        } else {
            Err(status)
        }
    }
}

impl From<SpdmResult<()>> for SpdmStatus {
    fn from(result: SpdmResult<()>) -> Self {
        match result {
            Ok(()) => SpdmStatus::Success,
            Err(status) => status,
        }
    }
}

pub fn is_error(status: u32) -> bool {
    status >= 0x80000000
}

impl fmt::Display for SpdmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpdmStatus::Success => write!(f, "Success"),
            SpdmStatus::InvalidParameter => write!(f, "InvalidParameter"),
            SpdmStatus::InvalidStateLocal => write!(f, "InvalidStateLocal"),
            SpdmStatus::BufferFull => write!(f, "BufferFull"),
            SpdmStatus::BufferTooSmall => write!(f, "BufferTooSmall"),
            SpdmStatus::VerifFail => write!(f, "VerifFail"),
            SpdmStatus::CryptoError => write!(f, "CryptoError"),
            SpdmStatus::NegotiationFail => write!(f, "NegotiationFail"),
            SpdmStatus::UnsupportedCap => write!(f, "UnsupportedCap"),
            SpdmStatus::ErrorPeer => write!(f, "ErrorPeer"),
            SpdmStatus::BusyPeer => write!(f, "BusyPeer"),
            SpdmStatus::InvalidMsgSize => write!(f, "InvalidMsgSize"),
            SpdmStatus::InvalidMsgField => write!(f, "InvalidMsgField"),
            SpdmStatus::InvalidSpdmVersion => write!(f, "InvalidSpdmVersion"),
            SpdmStatus::InvalidSpdmRequestCode => write!(f, "InvalidSpdmRequestCode"),
            SpdmStatus::InvalidSpdmResponseCode => write!(f, "InvalidSpdmResponseCode"),
            SpdmStatus::InvalidSpdmErrorCode => write!(f, "InvalidSpdmErrorCode"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_success() {
        let status = SpdmStatus::Success;
        let result: SpdmResult = status.into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_status_error_codes() {
        assert!(is_error(SpdmStatus::InvalidParameter as u32));
        assert!(is_error(SpdmStatus::CryptoError as u32));
        assert!(!is_error(SpdmStatus::Success as u32));
    }

    #[test]
    fn test_result_conversion() {
        let result: SpdmResult = Ok(());
        let status: SpdmStatus = result.into();
        assert_eq!(status, SpdmStatus::Success);
        
        let result2: SpdmResult = Err(SpdmStatus::VerifFail);
        let status2: SpdmStatus = result2.into();
        assert_eq!(status2, SpdmStatus::VerifFail);
    }

    #[test]
    fn test_generic_result() {
        let result: SpdmResult<u8> = Ok(42);
        assert_eq!(result.unwrap(), 42);
        
        let result2: SpdmResult<String> = Err(SpdmStatus::BufferTooSmall);
        assert!(result2.is_err());
    }

    #[test]
    fn test_new_status_codes() {
        assert!(is_error(SpdmStatus::BufferTooSmall as u32));
        assert!(is_error(SpdmStatus::InvalidSpdmVersion as u32));
        assert!(is_error(SpdmStatus::InvalidSpdmRequestCode as u32));
    }
}