use crate::error::{SpdmStatus, SpdmResult};
use crate::message::header::{SpdmMessageHeader, SpdmRequestCode, SpdmResponseCode, SpdmVersion};
use crate::message::codec::{read_u8, write_u8, write_slice, read_slice};
use crate::crypto::{SHA256_SIZE, SHA384_SIZE};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct FinishRequest {
    pub header: SpdmMessageHeader,
    pub slot_id: u8,
    pub signature: Vec<u8>,
    pub verify_data: Vec<u8>,
}

impl FinishRequest {
    pub fn new(slot_id: u8, signature: Vec<u8>, verify_data: Vec<u8>) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(SpdmVersion::V12, SpdmRequestCode::Finish, 0, 0),
            slot_id,
            signature,
            verify_data,
        }
    }

    pub fn encoded_size(&self) -> usize {
        SpdmMessageHeader::SIZE + 1 + 1 + self.signature.len() + self.verify_data.len()
    }

    pub fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let size = self.encoded_size();
        if buffer.len() < size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let mut offset = 0;
        let header_bytes = self.header.encode();
        write_slice(buffer, offset, &header_bytes)?;
        offset += SpdmMessageHeader::SIZE;

        write_u8(buffer, offset, self.slot_id)?;
        offset += 1;

        write_u8(buffer, offset, 0)?;
        offset += 1;

        if !self.signature.is_empty() {
            write_slice(buffer, offset, &self.signature)?;
            offset += self.signature.len();
        }

        write_slice(buffer, offset, &self.verify_data)?;
        offset += self.verify_data.len();

        Ok(offset)
    }

    pub fn decode(bytes: &[u8], hash_size: usize, has_signature: bool) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_request_code()?;

        let mut offset = SpdmMessageHeader::SIZE;

        let slot_id = read_u8(bytes, offset)?;
        offset += 1;

        offset += 1;

        let signature = if has_signature {
            let sig_size = if hash_size == SHA384_SIZE { 96 } else { 64 };
            let sig = read_slice(bytes, offset, sig_size)?.to_vec();
            offset += sig_size;
            sig
        } else {
            Vec::new()
        };

        let verify_data = read_slice(bytes, offset, hash_size)?.to_vec();

        Ok(Self {
            header,
            slot_id,
            signature,
            verify_data,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FinishResponse {
    pub header: SpdmMessageHeader,
    pub verify_data: Vec<u8>,
}

impl FinishResponse {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(SpdmVersion::V12, SpdmResponseCode::FinishRsp, 0, 0),
            verify_data,
        }
    }

    pub fn encoded_size(&self) -> usize {
        SpdmMessageHeader::SIZE + 2 + self.verify_data.len()
    }

    pub fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let size = self.encoded_size();
        if buffer.len() < size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let mut offset = 0;
        let header_bytes = self.header.encode();
        write_slice(buffer, offset, &header_bytes)?;
        offset += SpdmMessageHeader::SIZE;

        write_slice(buffer, offset, &[0, 0])?;
        offset += 2;

        write_slice(buffer, offset, &self.verify_data)?;
        offset += self.verify_data.len();

        Ok(offset)
    }

    pub fn decode(bytes: &[u8], hash_size: usize) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_response_code()?;

        let offset = SpdmMessageHeader::SIZE + 2;
        let verify_data = read_slice(bytes, offset, hash_size)?.to_vec();

        Ok(Self {
            header,
            verify_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finish_request_encode_decode_no_signature() {
        let verify_data = vec![0xAA; SHA256_SIZE];
        let req = FinishRequest::new(0, Vec::new(), verify_data.clone());
        
        let size = req.encoded_size();
        let mut buffer = vec![0u8; size];
        let written = req.encode(&mut buffer).unwrap();
        assert_eq!(written, size);
        
        let decoded = FinishRequest::decode(&buffer, SHA256_SIZE, false).unwrap();
        assert_eq!(decoded.slot_id, 0);
        assert_eq!(decoded.verify_data.len(), SHA256_SIZE);
        assert!(decoded.signature.is_empty());
    }

    #[test]
    fn test_finish_request_encode_decode_with_signature() {
        let signature = vec![0xBB; 96];
        let verify_data = vec![0xCC; SHA384_SIZE];
        let req = FinishRequest::new(1, signature.clone(), verify_data.clone());
        
        let size = req.encoded_size();
        let mut buffer = vec![0u8; size];
        req.encode(&mut buffer).unwrap();
        
        let decoded = FinishRequest::decode(&buffer, SHA384_SIZE, true).unwrap();
        assert_eq!(decoded.slot_id, 1);
        assert_eq!(decoded.signature.len(), 96);
        assert_eq!(decoded.verify_data.len(), SHA384_SIZE);
    }

    #[test]
    fn test_finish_request_buffer_too_small() {
        let req = FinishRequest::new(0, Vec::new(), vec![0xAA; SHA256_SIZE]);
        let mut small_buf = vec![0u8; 4];
        assert!(req.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_finish_response_encode_decode_sha256() {
        let verify_data = vec![0xDD; SHA256_SIZE];
        let rsp = FinishResponse::new(verify_data.clone());
        
        let size = rsp.encoded_size();
        let mut buffer = vec![0u8; size];
        let written = rsp.encode(&mut buffer).unwrap();
        assert_eq!(written, size);
        
        let decoded = FinishResponse::decode(&buffer, SHA256_SIZE).unwrap();
        assert_eq!(decoded.verify_data.len(), SHA256_SIZE);
    }

    #[test]
    fn test_finish_response_encode_decode_sha384() {
        let verify_data = vec![0xEE; SHA384_SIZE];
        let rsp = FinishResponse::new(verify_data.clone());
        
        let size = rsp.encoded_size();
        let mut buffer = vec![0u8; size];
        rsp.encode(&mut buffer).unwrap();
        
        let decoded = FinishResponse::decode(&buffer, SHA384_SIZE).unwrap();
        assert_eq!(decoded.verify_data.len(), SHA384_SIZE);
    }

    #[test]
    fn test_finish_response_buffer_too_small() {
        let rsp = FinishResponse::new(vec![0xAA; SHA256_SIZE]);
        let mut small_buf = vec![0u8; 4];
        assert!(rsp.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_finish_request_wrong_code() {
        let mut buffer = vec![0u8; SpdmMessageHeader::SIZE + 2 + SHA256_SIZE];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(FinishRequest::decode(&buffer, SHA256_SIZE, false).is_err());
    }

    #[test]
    fn test_finish_response_wrong_code() {
        let mut buffer = vec![0u8; SpdmMessageHeader::SIZE + 2 + SHA256_SIZE];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(FinishResponse::decode(&buffer, SHA256_SIZE).is_err());
    }
}