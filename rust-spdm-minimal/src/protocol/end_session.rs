use crate::error::{SpdmStatus, SpdmResult};
use crate::message::header::{SpdmMessageHeader, SpdmRequestCode, SpdmResponseCode, SpdmVersion};
use crate::message::codec::{write_slice};
use alloc::vec::Vec;

pub const END_SESSION_REQUEST_SIZE: usize = SpdmMessageHeader::SIZE + 2;
pub const END_SESSION_RESPONSE_SIZE: usize = SpdmMessageHeader::SIZE + 2;

#[derive(Debug, Clone)]
pub struct EndSessionRequest {
    pub header: SpdmMessageHeader,
    pub session_policy: u8,
}

impl EndSessionRequest {
    pub fn new(session_policy: u8) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(SpdmVersion::V12, SpdmRequestCode::EndSession, session_policy, 0),
            session_policy,
        }
    }

    pub fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        if buffer.len() < END_SESSION_REQUEST_SIZE {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let mut offset = 0;
        let header_bytes = self.header.encode();
        write_slice(buffer, offset, &header_bytes)?;
        offset += SpdmMessageHeader::SIZE;

        write_slice(buffer, offset, &[0, 0])?;
        offset += 2;

        Ok(offset)
    }

    pub fn decode(bytes: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_request_code()?;

        Ok(Self {
            header,
            session_policy: header.param1,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EndSessionResponse {
    pub header: SpdmMessageHeader,
}

impl EndSessionResponse {
    pub fn new() -> Self {
        Self {
            header: SpdmMessageHeader::new_response(SpdmVersion::V12, SpdmResponseCode::EndSessionAck, 0, 0),
        }
    }

    pub fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        if buffer.len() < END_SESSION_RESPONSE_SIZE {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let mut offset = 0;
        let header_bytes = self.header.encode();
        write_slice(buffer, offset, &header_bytes)?;
        offset += SpdmMessageHeader::SIZE;

        write_slice(buffer, offset, &[0, 0])?;
        offset += 2;

        Ok(offset)
    }

    pub fn decode(bytes: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_response_code()?;

        Ok(Self { header })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_session_request_encode_decode() {
        let req = EndSessionRequest::new(0x01);
        
        let mut buffer = vec![0u8; END_SESSION_REQUEST_SIZE];
        let written = req.encode(&mut buffer).unwrap();
        assert_eq!(written, END_SESSION_REQUEST_SIZE);
        
        let decoded = EndSessionRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.session_policy, 0x01);
    }

    #[test]
    fn test_end_session_request_default_policy() {
        let req = EndSessionRequest::new(0);
        let mut buffer = vec![0u8; END_SESSION_REQUEST_SIZE];
        req.encode(&mut buffer).unwrap();
        let decoded = EndSessionRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.session_policy, 0);
    }

    #[test]
    fn test_end_session_request_buffer_too_small() {
        let req = EndSessionRequest::new(0);
        let mut small_buf = vec![0u8; 2];
        assert!(req.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_end_session_response_encode_decode() {
        let rsp = EndSessionResponse::new();
        
        let mut buffer = vec![0u8; END_SESSION_RESPONSE_SIZE];
        let written = rsp.encode(&mut buffer).unwrap();
        assert_eq!(written, END_SESSION_RESPONSE_SIZE);
        
        let decoded = EndSessionResponse::decode(&buffer).unwrap();
        assert_eq!(decoded.header.version, SpdmVersion::V12);
    }

    #[test]
    fn test_end_session_response_buffer_too_small() {
        let rsp = EndSessionResponse::new();
        let mut small_buf = vec![0u8; 2];
        assert!(rsp.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_end_session_request_wrong_code() {
        let mut buffer = vec![0u8; END_SESSION_REQUEST_SIZE];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(EndSessionRequest::decode(&buffer).is_err());
    }

    #[test]
    fn test_end_session_response_wrong_code() {
        let mut buffer = vec![0u8; END_SESSION_RESPONSE_SIZE];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(EndSessionResponse::decode(&buffer).is_err());
    }
}