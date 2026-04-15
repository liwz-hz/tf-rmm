use crate::error::{SpdmStatus, SpdmResult};
use crate::message::header::{SpdmMessageHeader, SpdmRequestCode, SpdmResponseCode, SpdmVersion};
use crate::message::codec::{read_u8, read_u16_le, read_u32_le, write_u8, write_u16_le, write_u32_le, write_slice, read_slice};
use crate::crypto::{SHA256_SIZE, SHA384_SIZE};
use alloc::vec::Vec;

pub const KEY_EXCHANGE_REQUEST_MIN_SIZE: usize = SpdmMessageHeader::SIZE + 8;

#[derive(Debug, Clone)]
pub struct KeyExchangeRequest {
    pub header: SpdmMessageHeader,
    pub measurement_summary_type: u8,
    pub slot_id: u8,
    pub session_id: u32,
    pub exchange_data: Vec<u8>,
    pub opaque_data: Vec<u8>,
}

impl KeyExchangeRequest {
    pub fn new(session_id: u32, slot_id: u8, exchange_data: Vec<u8>) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(SpdmVersion::V12, SpdmRequestCode::KeyExchange, 0, 0),
            measurement_summary_type: 0,
            slot_id,
            session_id,
            exchange_data,
            opaque_data: Vec::new(),
        }
    }

    pub fn encoded_size(&self) -> usize {
        SpdmMessageHeader::SIZE + 1 + 1 + 4 + 2 + self.exchange_data.len() + 2 + self.opaque_data.len()
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

        write_u8(buffer, offset, self.measurement_summary_type)?;
        offset += 1;

        write_u8(buffer, offset, self.slot_id)?;
        offset += 1;

        write_u32_le(buffer, offset, self.session_id)?;
        offset += 4;

        write_u16_le(buffer, offset, self.exchange_data.len() as u16)?;
        offset += 2;

        write_slice(buffer, offset, &self.exchange_data)?;
        offset += self.exchange_data.len();

        write_u16_le(buffer, offset, self.opaque_data.len() as u16)?;
        offset += 2;

        write_slice(buffer, offset, &self.opaque_data)?;
        offset += self.opaque_data.len();

        Ok(offset)
    }

    pub fn decode(bytes: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_request_code()?;

        let mut offset = SpdmMessageHeader::SIZE;

        let measurement_summary_type = read_u8(bytes, offset)?;
        offset += 1;

        let slot_id = read_u8(bytes, offset)?;
        offset += 1;

        let session_id = read_u32_le(bytes, offset)?;
        offset += 4;

        let exchange_len = read_u16_le(bytes, offset)? as usize;
        offset += 2;

        let exchange_data = read_slice(bytes, offset, exchange_len)?.to_vec();
        offset += exchange_len;

        let opaque_len = read_u16_le(bytes, offset)? as usize;
        offset += 2;

        let opaque_data = read_slice(bytes, offset, opaque_len)?.to_vec();

        Ok(Self {
            header,
            measurement_summary_type,
            slot_id,
            session_id,
            exchange_data,
            opaque_data,
        })
    }
}

pub const KEY_EXCHANGE_RESPONSE_MIN_SIZE: usize = SpdmMessageHeader::SIZE + 10;

#[derive(Debug, Clone)]
pub struct KeyExchangeResponse {
    pub header: SpdmMessageHeader,
    pub session_id: u32,
    pub mut_auth_requested: u8,
    pub slot_id: u8,
    pub exchange_data: Vec<u8>,
    pub measurement_summary_hash: Vec<u8>,
    pub opaque_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl KeyExchangeResponse {
    pub fn new(
        session_id: u32,
        slot_id: u8,
        exchange_data: Vec<u8>,
        measurement_summary_hash: Vec<u8>,
    ) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(SpdmVersion::V12, SpdmResponseCode::KeyExchangeRsp, 0, 0),
            session_id,
            mut_auth_requested: 0,
            slot_id,
            exchange_data,
            measurement_summary_hash,
            opaque_data: Vec::new(),
            signature: Vec::new(),
        }
    }

    pub fn encoded_size(&self) -> usize {
        SpdmMessageHeader::SIZE + 2 + 1 + 1 + 4 + 2 + self.exchange_data.len() 
            + self.measurement_summary_hash.len() + 2 + self.opaque_data.len() 
            + self.signature.len()
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

        write_u16_le(buffer, offset, 0)?;
        offset += 2;

        write_u8(buffer, offset, self.mut_auth_requested)?;
        offset += 1;

        write_u8(buffer, offset, self.slot_id)?;
        offset += 1;

        write_u32_le(buffer, offset, self.session_id)?;
        offset += 4;

        write_u16_le(buffer, offset, self.exchange_data.len() as u16)?;
        offset += 2;

        write_slice(buffer, offset, &self.exchange_data)?;
        offset += self.exchange_data.len();

        write_slice(buffer, offset, &self.measurement_summary_hash)?;
        offset += self.measurement_summary_hash.len();

        write_u16_le(buffer, offset, self.opaque_data.len() as u16)?;
        offset += 2;

        write_slice(buffer, offset, &self.opaque_data)?;
        offset += self.opaque_data.len();

        if !self.signature.is_empty() {
            write_slice(buffer, offset, &self.signature)?;
            offset += self.signature.len();
        }

        Ok(offset)
    }

    pub fn decode(bytes: &[u8], hash_size: usize) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(bytes)?;
        header.get_response_code()?;

        let mut offset = SpdmMessageHeader::SIZE + 2;

        let mut_auth_requested = read_u8(bytes, offset)?;
        offset += 1;

        let slot_id = read_u8(bytes, offset)?;
        offset += 1;

        let session_id = read_u32_le(bytes, offset)?;
        offset += 4;

        let exchange_len = read_u16_le(bytes, offset)? as usize;
        offset += 2;

        let exchange_data = read_slice(bytes, offset, exchange_len)?.to_vec();
        offset += exchange_len;

        let measurement_summary_hash = read_slice(bytes, offset, hash_size)?.to_vec();
        offset += hash_size;

        let opaque_len = read_u16_le(bytes, offset)? as usize;
        offset += 2;

        let opaque_data = read_slice(bytes, offset, opaque_len)?.to_vec();
        offset += opaque_len;

        let signature = if offset < bytes.len() {
            bytes[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            header,
            session_id,
            mut_auth_requested,
            slot_id,
            exchange_data,
            measurement_summary_hash,
            opaque_data,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_request_encode_decode() {
        let exchange_data = vec![0xAA; 64];
        let req = KeyExchangeRequest::new(0x12345678, 0, exchange_data.clone());
        
        let size = req.encoded_size();
        let mut buffer = vec![0u8; size];
        let written = req.encode(&mut buffer).unwrap();
        assert_eq!(written, size);
        
        let decoded = KeyExchangeRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.session_id, 0x12345678);
        assert_eq!(decoded.slot_id, 0);
        assert_eq!(decoded.exchange_data.len(), 64);
    }

    #[test]
    fn test_key_exchange_request_with_opaque() {
        let exchange_data = vec![0xAA; 64];
        let opaque_data = vec![0xBB; 32];
        let mut req = KeyExchangeRequest::new(0xABCDEF01, 1, exchange_data);
        req.opaque_data = opaque_data.clone();
        
        let size = req.encoded_size();
        let mut buffer = vec![0u8; size];
        req.encode(&mut buffer).unwrap();
        
        let decoded = KeyExchangeRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.opaque_data, opaque_data);
    }

    #[test]
    fn test_key_exchange_request_buffer_too_small() {
        let req = KeyExchangeRequest::new(1, 0, vec![0xAA; 64]);
        let mut small_buf = vec![0u8; 10];
        assert!(req.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_key_exchange_response_encode_decode_sha256() {
        let exchange_data = vec![0xCC; 64];
        let measurement_hash = vec![0xDD; SHA256_SIZE];
        let rsp = KeyExchangeResponse::new(0x12345678, 0, exchange_data.clone(), measurement_hash.clone());
        
        let size = rsp.encoded_size();
        let mut buffer = vec![0u8; size];
        let written = rsp.encode(&mut buffer).unwrap();
        assert_eq!(written, size);
        
        let decoded = KeyExchangeResponse::decode(&buffer, SHA256_SIZE).unwrap();
        assert_eq!(decoded.session_id, 0x12345678);
        assert_eq!(decoded.exchange_data.len(), 64);
        assert_eq!(decoded.measurement_summary_hash.len(), SHA256_SIZE);
    }

    #[test]
    fn test_key_exchange_response_encode_decode_sha384() {
        let exchange_data = vec![0xEE; 64];
        let measurement_hash = vec![0xFF; SHA384_SIZE];
        let mut rsp = KeyExchangeResponse::new(0xABCDEF01, 1, exchange_data.clone(), measurement_hash.clone());
        rsp.signature = vec![0x11; 96];
        
        let size = rsp.encoded_size();
        let mut buffer = vec![0u8; size];
        rsp.encode(&mut buffer).unwrap();
        
        let decoded = KeyExchangeResponse::decode(&buffer, SHA384_SIZE).unwrap();
        assert_eq!(decoded.measurement_summary_hash.len(), SHA384_SIZE);
        assert_eq!(decoded.signature.len(), 96);
    }

    #[test]
    fn test_key_exchange_response_buffer_too_small() {
        let rsp = KeyExchangeResponse::new(1, 0, vec![0xAA; 64], vec![0xBB; SHA256_SIZE]);
        let mut small_buf = vec![0u8; 10];
        assert!(rsp.encode(&mut small_buf).is_err());
    }

    #[test]
    fn test_key_exchange_request_wrong_code() {
        let mut buffer = vec![0u8; KEY_EXCHANGE_REQUEST_MIN_SIZE + 64];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(KeyExchangeRequest::decode(&buffer).is_err());
    }

    #[test]
    fn test_key_exchange_response_wrong_code() {
        let mut buffer = vec![0u8; KEY_EXCHANGE_RESPONSE_MIN_SIZE + 64 + SHA256_SIZE];
        buffer[0] = 0x12;
        buffer[1] = 0xFF;
        buffer[2] = 0;
        buffer[3] = 0;
        
        assert!(KeyExchangeResponse::decode(&buffer, SHA256_SIZE).is_err());
    }
}