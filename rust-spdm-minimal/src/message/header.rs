//! SPDM Message Header Definitions
//!
//! SPDM header structure (4 bytes):
//! - version: 1 byte (SPDM version 1.0, 1.1, 1.2, 1.3)
//! - request_response_code: 1 byte (message type)
//! - param1: 1 byte (first parameter)
//! - param2: 1 byte (second parameter)
//!
//! Bit 7 of request_response_code:
//! - 0: Response message
//! - 1: Request message

use crate::error::{SpdmStatus, SpdmResult};

/// SPDM Version encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SpdmVersion {
    /// SPDM 1.0
    V10 = 0x10,
    /// SPDM 1.1
    V11 = 0x11,
    /// SPDM 1.2 (default for tf-rmm)
    #[default]
    V12 = 0x12,
    /// SPDM 1.3
    V13 = 0x13,
}

impl SpdmVersion {
    /// Parse version from raw byte
    pub fn from_byte(byte: u8) -> SpdmResult<Self> {
        match byte {
            0x10 => Ok(SpdmVersion::V10),
            0x11 => Ok(SpdmVersion::V11),
            0x12 => Ok(SpdmVersion::V12),
            0x13 => Ok(SpdmVersion::V13),
            _ => Err(SpdmStatus::InvalidSpdmVersion),
        }
    }

    /// Convert to raw byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Get version number string (e.g., "1.2")
    pub fn version_string(self) -> &'static str {
        match self {
            SpdmVersion::V10 => "1.0",
            SpdmVersion::V11 => "1.1",
            SpdmVersion::V12 => "1.2",
            SpdmVersion::V13 => "1.3",
        }
    }
}

/// SPDM Request Codes (bit 7 = 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpdmRequestCode {
    /// GET_VERSION request
    GetVersion = 0x84,
    /// GET_CAPABILITIES request
    GetCapabilities = 0xE1,
    /// NEGOTIATE_ALGORITHMS request
    NegotiateAlgorithms = 0xE3,
    /// GET_DIGESTS request
    GetDigests = 0xF8,
    /// GET_CERTIFICATE request
    GetCertificate = 0xF9,
    /// CHALLENGE request
    Challenge = 0x83,
    /// GET_MEASUREMENTS request
    GetMeasurements = 0xE8,
    /// KEY_EXCHANGE request
    KeyExchange = 0xE4,
    /// FINISH request
    Finish = 0xE5,
    /// END_SESSION request
    EndSession = 0xF6,
    /// VENDOR_DEFINED_REQUEST
    VendorDefinedRequest = 0x70,
}

impl SpdmRequestCode {
    /// Parse request code from raw byte
    pub fn from_byte(byte: u8) -> SpdmResult<Self> {
        match byte {
            0x84 => Ok(SpdmRequestCode::GetVersion),
            0xE1 => Ok(SpdmRequestCode::GetCapabilities),
            0xE3 => Ok(SpdmRequestCode::NegotiateAlgorithms),
            0xF8 => Ok(SpdmRequestCode::GetDigests),
            0xF9 => Ok(SpdmRequestCode::GetCertificate),
            0x83 => Ok(SpdmRequestCode::Challenge),
            0xE8 => Ok(SpdmRequestCode::GetMeasurements),
            0xE4 => Ok(SpdmRequestCode::KeyExchange),
            0xE5 => Ok(SpdmRequestCode::Finish),
            0xF6 => Ok(SpdmRequestCode::EndSession),
            0x70 => Ok(SpdmRequestCode::VendorDefinedRequest),
            _ => Err(SpdmStatus::InvalidSpdmRequestCode),
        }
    }

    /// Convert to raw byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if byte is a valid request code (bit 7 = 1)
    pub fn is_request_code(byte: u8) -> bool {
        (byte & 0x80) != 0
    }
}

/// SPDM Response Codes (bit 7 = 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpdmResponseCode {
    /// VERSION response
    Version = 0x04,
    /// CAPABILITIES response
    Capabilities = 0x61,
    /// ALGORITHMS response
    Algorithms = 0x63,
    /// DIGESTS response
    Digests = 0x78,
    /// CERTIFICATE response
    Certificate = 0x79,
    /// CHALLENGE_AUTH response
    ChallengeAuth = 0x03,
    /// MEASUREMENTS response
    Measurements = 0x68,
    /// KEY_EXCHANGE_RSP response
    KeyExchangeRsp = 0x64,
    /// FINISH_RSP response
    FinishRsp = 0x65,
    /// END_SESSION_ACK response
    EndSessionAck = 0x56,
    /// VENDOR_DEFINED_RESPONSE
    VendorDefinedResponse = 0x50,
    /// ERROR response
    Error = 0x7F,
}

impl SpdmResponseCode {
    /// Parse response code from raw byte
    pub fn from_byte(byte: u8) -> SpdmResult<Self> {
        match byte {
            0x04 => Ok(SpdmResponseCode::Version),
            0x61 => Ok(SpdmResponseCode::Capabilities),
            0x63 => Ok(SpdmResponseCode::Algorithms),
            0x78 => Ok(SpdmResponseCode::Digests),
            0x79 => Ok(SpdmResponseCode::Certificate),
            0x03 => Ok(SpdmResponseCode::ChallengeAuth),
            0x68 => Ok(SpdmResponseCode::Measurements),
            0x64 => Ok(SpdmResponseCode::KeyExchangeRsp),
            0x65 => Ok(SpdmResponseCode::FinishRsp),
            0x56 => Ok(SpdmResponseCode::EndSessionAck),
            0x50 => Ok(SpdmResponseCode::VendorDefinedResponse),
            0x7F => Ok(SpdmResponseCode::Error),
            _ => Err(SpdmStatus::InvalidSpdmResponseCode),
        }
    }

    /// Convert to raw byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if byte is a valid response code (bit 7 = 0)
    pub fn is_response_code(byte: u8) -> bool {
        (byte & 0x80) == 0
    }
}

/// SPDM Error Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpdmErrorCode {
    /// Invalid request
    InvalidRequest = 0x01,
    /// Busy (retry later)
    Busy = 0x03,
    /// Unexpected request
    UnexpectedRequest = 0x04,
    /// Decrypt error
    DecryptError = 0x06,
    /// Request resynch
    RequestResynch = 0x07,
    /// Response not ready
    ResponseNotReady = 0x42,
    /// Vendor specific error
    VendorSpecificError = 0xFF,
}

impl SpdmErrorCode {
    /// Parse error code from raw byte
    pub fn from_byte(byte: u8) -> SpdmResult<Self> {
        match byte {
            0x01 => Ok(SpdmErrorCode::InvalidRequest),
            0x03 => Ok(SpdmErrorCode::Busy),
            0x04 => Ok(SpdmErrorCode::UnexpectedRequest),
            0x06 => Ok(SpdmErrorCode::DecryptError),
            0x07 => Ok(SpdmErrorCode::RequestResynch),
            0x42 => Ok(SpdmErrorCode::ResponseNotReady),
            0xFF => Ok(SpdmErrorCode::VendorSpecificError),
            _ => Err(SpdmStatus::InvalidSpdmErrorCode),
        }
    }

    /// Convert to raw byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// SPDM Message Header (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SpdmMessageHeader {
    /// SPDM version
    pub version: SpdmVersion,
    /// Request or Response code
    pub request_response_code: u8,
    /// First parameter
    pub param1: u8,
    /// Second parameter
    pub param2: u8,
}

impl SpdmMessageHeader {
    /// Create a new request header
    pub fn new_request(version: SpdmVersion, request_code: SpdmRequestCode, param1: u8, param2: u8) -> Self {
        Self {
            version,
            request_response_code: request_code.to_byte(),
            param1,
            param2,
        }
    }

    /// Create a new response header
    pub fn new_response(version: SpdmVersion, response_code: SpdmResponseCode, param1: u8, param2: u8) -> Self {
        Self {
            version,
            request_response_code: response_code.to_byte(),
            param1,
            param2,
        }
    }

    /// Check if this is a request message
    pub fn is_request(&self) -> bool {
        SpdmRequestCode::is_request_code(self.request_response_code)
    }

    /// Check if this is a response message
    pub fn is_response(&self) -> bool {
        SpdmResponseCode::is_response_code(self.request_response_code)
    }

    /// Get request code (if this is a request)
    pub fn get_request_code(&self) -> SpdmResult<SpdmRequestCode> {
        if self.is_request() {
            SpdmRequestCode::from_byte(self.request_response_code)
        } else {
            Err(SpdmStatus::InvalidSpdmRequestCode)
        }
    }

    /// Get response code (if this is a response)
    pub fn get_response_code(&self) -> SpdmResult<SpdmResponseCode> {
        if self.is_response() {
            SpdmResponseCode::from_byte(self.request_response_code)
        } else {
            Err(SpdmStatus::InvalidSpdmResponseCode)
        }
    }

    /// Encode header to 4 bytes
    pub fn encode(&self) -> [u8; 4] {
        [
            self.version.to_byte(),
            self.request_response_code,
            self.param1,
            self.param2,
        ]
    }

    /// Decode header from bytes
    pub fn decode(bytes: &[u8]) -> SpdmResult<Self> {
        if bytes.len() < 4 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let version = SpdmVersion::from_byte(bytes[0])?;
        
        Ok(Self {
            version,
            request_response_code: bytes[1],
            param1: bytes[2],
            param2: bytes[3],
        })
    }

    /// Size of SPDM header (always 4 bytes)
    pub const SIZE: usize = 4;
}

impl Default for SpdmMessageHeader {
    fn default() -> Self {
        Self {
            version: SpdmVersion::V12,
            request_response_code: SpdmRequestCode::GetVersion.to_byte(),
            param1: 0,
            param2: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdm_version_from_byte() {
        // Success cases
        assert_eq!(SpdmVersion::from_byte(0x10).unwrap(), SpdmVersion::V10);
        assert_eq!(SpdmVersion::from_byte(0x11).unwrap(), SpdmVersion::V11);
        assert_eq!(SpdmVersion::from_byte(0x12).unwrap(), SpdmVersion::V12);
        assert_eq!(SpdmVersion::from_byte(0x13).unwrap(), SpdmVersion::V13);

        // Failure case - invalid version
        assert!(SpdmVersion::from_byte(0x00).is_err());
        assert!(SpdmVersion::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_spdm_version_to_byte() {
        assert_eq!(SpdmVersion::V10.to_byte(), 0x10);
        assert_eq!(SpdmVersion::V11.to_byte(), 0x11);
        assert_eq!(SpdmVersion::V12.to_byte(), 0x12);
        assert_eq!(SpdmVersion::V13.to_byte(), 0x13);
    }

    #[test]
    fn test_spdm_version_string() {
        assert_eq!(SpdmVersion::V10.version_string(), "1.0");
        assert_eq!(SpdmVersion::V12.version_string(), "1.2");
    }

    #[test]
    fn test_spdm_request_code_from_byte() {
        // Success cases
        assert_eq!(SpdmRequestCode::from_byte(0x84).unwrap(), SpdmRequestCode::GetVersion);
        assert_eq!(SpdmRequestCode::from_byte(0xE1).unwrap(), SpdmRequestCode::GetCapabilities);
        assert_eq!(SpdmRequestCode::from_byte(0xE3).unwrap(), SpdmRequestCode::NegotiateAlgorithms);
        assert_eq!(SpdmRequestCode::from_byte(0xE4).unwrap(), SpdmRequestCode::KeyExchange);
        assert_eq!(SpdmRequestCode::from_byte(0xE5).unwrap(), SpdmRequestCode::Finish);
        assert_eq!(SpdmRequestCode::from_byte(0xF6).unwrap(), SpdmRequestCode::EndSession);
        assert_eq!(SpdmRequestCode::from_byte(0xF8).unwrap(), SpdmRequestCode::GetDigests);
        assert_eq!(SpdmRequestCode::from_byte(0xF9).unwrap(), SpdmRequestCode::GetCertificate);
        assert_eq!(SpdmRequestCode::from_byte(0x70).unwrap(), SpdmRequestCode::VendorDefinedRequest);

        // Failure case - response code (bit 7 = 0)
        assert!(SpdmRequestCode::from_byte(0x04).is_err());
    }

    #[test]
    fn test_spdm_request_code_is_request() {
        // Request codes have bit 7 set
        assert!(SpdmRequestCode::is_request_code(0x84));
        assert!(SpdmRequestCode::is_request_code(0xE1));
        assert!(SpdmRequestCode::is_request_code(0xFF));

        // Response codes have bit 7 clear
        assert!(!SpdmRequestCode::is_request_code(0x04));
        assert!(!SpdmRequestCode::is_request_code(0x61));
        assert!(!SpdmRequestCode::is_request_code(0x7F));
    }

    #[test]
    fn test_spdm_response_code_from_byte() {
        // Success cases
        assert_eq!(SpdmResponseCode::from_byte(0x04).unwrap(), SpdmResponseCode::Version);
        assert_eq!(SpdmResponseCode::from_byte(0x61).unwrap(), SpdmResponseCode::Capabilities);
        assert_eq!(SpdmResponseCode::from_byte(0x63).unwrap(), SpdmResponseCode::Algorithms);
        assert_eq!(SpdmResponseCode::from_byte(0x64).unwrap(), SpdmResponseCode::KeyExchangeRsp);
        assert_eq!(SpdmResponseCode::from_byte(0x65).unwrap(), SpdmResponseCode::FinishRsp);
        assert_eq!(SpdmResponseCode::from_byte(0x56).unwrap(), SpdmResponseCode::EndSessionAck);
        assert_eq!(SpdmResponseCode::from_byte(0x78).unwrap(), SpdmResponseCode::Digests);
        assert_eq!(SpdmResponseCode::from_byte(0x79).unwrap(), SpdmResponseCode::Certificate);
        assert_eq!(SpdmResponseCode::from_byte(0x7F).unwrap(), SpdmResponseCode::Error);
        assert_eq!(SpdmResponseCode::from_byte(0x50).unwrap(), SpdmResponseCode::VendorDefinedResponse);

        // Failure case - request code (bit 7 = 1)
        assert!(SpdmResponseCode::from_byte(0x84).is_err());
    }

    #[test]
    fn test_spdm_response_code_is_response() {
        // Response codes have bit 7 clear
        assert!(SpdmResponseCode::is_response_code(0x04));
        assert!(SpdmResponseCode::is_response_code(0x61));
        assert!(SpdmResponseCode::is_response_code(0x7F));

        // Request codes have bit 7 set
        assert!(!SpdmResponseCode::is_response_code(0x84));
        assert!(!SpdmResponseCode::is_response_code(0xE1));
    }

    #[test]
    fn test_spdm_error_code_from_byte() {
        assert_eq!(SpdmErrorCode::from_byte(0x01).unwrap(), SpdmErrorCode::InvalidRequest);
        assert_eq!(SpdmErrorCode::from_byte(0x03).unwrap(), SpdmErrorCode::Busy);
        assert_eq!(SpdmErrorCode::from_byte(0x42).unwrap(), SpdmErrorCode::ResponseNotReady);
    }

    #[test]
    fn test_spdm_message_header_new_request() {
        let header = SpdmMessageHeader::new_request(
            SpdmVersion::V12,
            SpdmRequestCode::GetVersion,
            0,
            0,
        );

        assert_eq!(header.version, SpdmVersion::V12);
        assert_eq!(header.request_response_code, 0x84);
        assert_eq!(header.param1, 0);
        assert_eq!(header.param2, 0);
        assert!(header.is_request());
        assert!(!header.is_response());
    }

    #[test]
    fn test_spdm_message_header_new_response() {
        let header = SpdmMessageHeader::new_response(
            SpdmVersion::V12,
            SpdmResponseCode::Version,
            0x01, // version_number_entry_count
            0,
        );

        assert_eq!(header.version, SpdmVersion::V12);
        assert_eq!(header.request_response_code, 0x04);
        assert_eq!(header.param1, 0x01);
        assert!(!header.is_request());
        assert!(header.is_response());
    }

    #[test]
    fn test_spdm_message_header_encode_decode() {
        // Test request header
        let request_header = SpdmMessageHeader::new_request(
            SpdmVersion::V12,
            SpdmRequestCode::KeyExchange,
            0x01, // measurement_summary_hash_type
            0x00, // slot_id
        );

        let encoded = request_header.encode();
        assert_eq!(encoded, [0x12, 0xE4, 0x01, 0x00]);

        let decoded = SpdmMessageHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, request_header.version);
        assert_eq!(decoded.request_response_code, request_header.request_response_code);
        assert_eq!(decoded.param1, request_header.param1);
        assert_eq!(decoded.param2, request_header.param2);

        // Test response header
        let response_header = SpdmMessageHeader::new_response(
            SpdmVersion::V12,
            SpdmResponseCode::KeyExchangeRsp,
            0x00,
            0x00,
        );

        let encoded = response_header.encode();
        assert_eq!(encoded, [0x12, 0x64, 0x00, 0x00]);

        let decoded = SpdmMessageHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, response_header.version);
        assert!(decoded.is_response());
    }

    #[test]
    fn test_spdm_message_header_decode_buffer_too_small() {
        let small_buffer = [0x12, 0x84];
        let result = SpdmMessageHeader::decode(&small_buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SpdmStatus::BufferTooSmall);
    }

    #[test]
    fn test_spdm_message_header_decode_invalid_version() {
        let invalid_version_buffer = [0x00, 0x84, 0x00, 0x00];
        let result = SpdmMessageHeader::decode(&invalid_version_buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SpdmStatus::InvalidSpdmVersion);
    }

    #[test]
    fn test_spdm_message_header_get_request_code() {
        let request_header = SpdmMessageHeader::new_request(
            SpdmVersion::V12,
            SpdmRequestCode::GetCapabilities,
            0,
            0,
        );

        let code = request_header.get_request_code().unwrap();
        assert_eq!(code, SpdmRequestCode::GetCapabilities);

        // Should fail for response header
        let response_header = SpdmMessageHeader::new_response(
            SpdmVersion::V12,
            SpdmResponseCode::Capabilities,
            0,
            0,
        );
        assert!(response_header.get_request_code().is_err());
    }

    #[test]
    fn test_spdm_message_header_get_response_code() {
        let response_header = SpdmMessageHeader::new_response(
            SpdmVersion::V12,
            SpdmResponseCode::Algorithms,
            0,
            0,
        );

        let code = response_header.get_response_code().unwrap();
        assert_eq!(code, SpdmResponseCode::Algorithms);

        // Should fail for request header
        let request_header = SpdmMessageHeader::new_request(
            SpdmVersion::V12,
            SpdmRequestCode::NegotiateAlgorithms,
            0,
            0,
        );
        assert!(request_header.get_response_code().is_err());
    }

    #[test]
    fn test_spdm_message_header_default() {
        let header = SpdmMessageHeader::default();
        assert_eq!(header.version, SpdmVersion::V12);
        assert_eq!(header.request_response_code, 0x84); // GET_VERSION
        assert!(header.is_request());
    }
}