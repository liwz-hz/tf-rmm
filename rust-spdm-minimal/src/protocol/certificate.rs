//! SPDM CERTIFICATE Protocol (GET_CERTIFICATE / CERTIFICATE)

use crate::error::{SpdmStatus, SpdmResult};
use crate::message::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmEncode, SpdmDecode};
use crate::message::codec;
use alloc::vec::Vec;

/// GET_CERTIFICATE Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCertificateRequest {
    pub header: SpdmMessageHeader,
    pub offset: u16,
    pub length: u16,
}

impl GetCertificateRequest {
    pub fn new(version: SpdmVersion, slot_id: u8, offset: u16, length: u16) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(
                version,
                SpdmRequestCode::GetCertificate,
                slot_id,
                0,
            ),
            offset,
            length,
        }
    }

    pub fn default() -> Self {
        Self::new(SpdmVersion::V12, 0, 0, 4096)
    }
}

impl SpdmEncode for GetCertificateRequest {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 8;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        codec::write_u16_le(buffer, 4, self.offset)?;
        codec::write_u16_le(buffer, 6, self.length)?;

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        8
    }
}

impl SpdmDecode for GetCertificateRequest {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 8 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_request() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        Ok(Self {
            header,
            offset: codec::read_u16_le(buffer, 4)?,
            length: codec::read_u16_le(buffer, 6)?,
        })
    }
}

/// CERTIFICATE Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateResponse {
    pub header: SpdmMessageHeader,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub cert_chain: Vec<u8>,
}

impl CertificateResponse {
    pub fn new(version: SpdmVersion, slot_id: u8, portion_length: u16, remainder_length: u16, cert_chain: Vec<u8>) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(
                version,
                SpdmResponseCode::Certificate,
                slot_id,
                0,
            ),
            portion_length,
            remainder_length,
            cert_chain,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.remainder_length == 0
    }

    pub fn slot_id(&self) -> u8 {
        self.header.param1
    }
}

impl SpdmEncode for CertificateResponse {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 8 + self.cert_chain.len();
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        codec::write_u16_le(buffer, 4, self.portion_length)?;
        codec::write_u16_le(buffer, 6, self.remainder_length)?;
        buffer[8..total_size].copy_from_slice(&self.cert_chain);

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        8 + self.cert_chain.len()
    }
}

impl SpdmDecode for CertificateResponse {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 8 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_response() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        let portion_length = codec::read_u16_le(buffer, 4)?;
        let remainder_length = codec::read_u16_le(buffer, 6)?;

        if buffer.len() < 8 + portion_length as usize {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let cert_chain = buffer[8..8 + portion_length as usize].to_vec();

        Ok(Self {
            header,
            portion_length,
            remainder_length,
            cert_chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_certificate_request_encode_decode() {
        let req = GetCertificateRequest::new(SpdmVersion::V12, 0, 0, 1024);
        let mut buffer = [0u8; 8];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, 8);
        assert_eq!(buffer[0..4], [0x12, 0xF9, 0x00, 0x00]);
        assert_eq!(buffer[4..6], [0x00, 0x00]);
        assert_eq!(buffer[6..8], [0x00, 0x04]);

        let decoded = GetCertificateRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.length, 1024);
        assert_eq!(decoded.header.param1, 0);
    }

    #[test]
    fn test_certificate_response_encode_decode() {
        let cert_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let resp = CertificateResponse::new(SpdmVersion::V12, 0, 4, 1000, cert_data.clone());

        let mut buffer = vec![0u8; 12];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, 12);

        let decoded = CertificateResponse::decode(&buffer).unwrap();
        assert_eq!(decoded.portion_length, 4);
        assert_eq!(decoded.remainder_length, 1000);
        assert_eq!(decoded.cert_chain, cert_data);
        assert!(!decoded.is_complete());
    }

    #[test]
    fn test_certificate_response_complete() {
        let cert_data = vec![0xAA, 0xBB];
        let resp = CertificateResponse::new(SpdmVersion::V12, 0, 2, 0, cert_data);
        assert!(resp.is_complete());
    }

    #[test]
    fn test_certificate_slot_id() {
        let cert_data = vec![0xAA];
        let resp = CertificateResponse::new(SpdmVersion::V12, 3, 1, 0, cert_data);
        assert_eq!(resp.slot_id(), 3);
    }

    #[test]
    fn test_certificate_request_buffer_too_small() {
        let req = GetCertificateRequest::default();
        let mut buffer = [0u8; 4];
        assert!(req.encode(&mut buffer).is_err());

        let small_buffer = [0u8; 4];
        assert!(GetCertificateRequest::decode(&small_buffer).is_err());
    }

    #[test]
    fn test_certificate_offset_request() {
        let req = GetCertificateRequest::new(SpdmVersion::V12, 0, 1024, 1024);
        let mut buffer = [0u8; 8];
        req.encode(&mut buffer).unwrap();

        let decoded = GetCertificateRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.offset, 1024);
    }
}