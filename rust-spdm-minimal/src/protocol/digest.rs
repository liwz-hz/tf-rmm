//! SPDM DIGEST Protocol (GET_DIGESTS / DIGESTS)

use crate::error::{SpdmStatus, SpdmResult};
use crate::message::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmEncode, SpdmDecode};
use crate::context::MAX_HASH_SIZE;
use alloc::vec::Vec;

/// GET_DIGESTS Request (4 bytes header only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDigestsRequest {
    pub header: SpdmMessageHeader,
}

impl GetDigestsRequest {
    pub fn new(version: SpdmVersion) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(version, SpdmRequestCode::GetDigests, 0, 0),
        }
    }

    pub fn default() -> Self {
        Self::new(SpdmVersion::V12)
    }
}

impl SpdmEncode for GetDigestsRequest {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        if buffer.len() < 4 {
            return Err(SpdmStatus::BufferTooSmall);
        }
        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        Ok(4)
    }

    fn encoded_size(&self) -> usize {
        4
    }
}

impl SpdmDecode for GetDigestsRequest {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_request() {
            return Err(SpdmStatus::InvalidMsgField);
        }
        Ok(Self { header })
    }
}

/// DIGESTS Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestsResponse {
    pub header: SpdmMessageHeader,
    pub slot_mask: u8,
    pub digests: Vec<[u8; MAX_HASH_SIZE]>,
}

impl DigestsResponse {
    pub fn new(version: SpdmVersion, slot_mask: u8, digests: Vec<[u8; MAX_HASH_SIZE]>) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(
                version,
                SpdmResponseCode::Digests,
                slot_mask,
                0,
            ),
            slot_mask,
            digests,
        }
    }

    pub fn slot_count(&self) -> usize {
        self.slot_mask.count_ones() as usize
    }

    pub fn get_digest(&self, slot_id: u8) -> Option<&[u8; MAX_HASH_SIZE]> {
        if slot_id >= 8 {
            return None;
        }
        if (self.slot_mask & (1 << slot_id)) == 0 {
            return None;
        }
        
        let index = self.slot_mask_bit_index(slot_id);
        self.digests.get(index)
    }

    fn slot_mask_bit_index(&self, slot_id: u8) -> usize {
        (self.slot_mask & ((1 << slot_id) - 1)).count_ones() as usize
    }
}

impl SpdmEncode for DigestsResponse {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 4 + 1 + self.digests.len() * MAX_HASH_SIZE;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        buffer[4] = self.slot_mask;

        for (i, digest) in self.digests.iter().enumerate() {
            buffer[5 + i * MAX_HASH_SIZE..5 + (i + 1) * MAX_HASH_SIZE].copy_from_slice(digest);
        }

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        4 + 1 + self.digests.len() * MAX_HASH_SIZE
    }
}

impl SpdmDecode for DigestsResponse {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 5 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_response() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        let slot_mask = buffer[4];
        let slot_count = slot_mask.count_ones() as usize;
        
        if buffer.len() < 5 + slot_count * MAX_HASH_SIZE {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let digests: Vec<[u8; MAX_HASH_SIZE]> = (0..slot_count)
            .map(|i| {
                let start = 5 + i * MAX_HASH_SIZE;
                let end = start + MAX_HASH_SIZE;
                buffer[start..end].try_into().unwrap_or([0u8; MAX_HASH_SIZE])
            })
            .collect();

        Ok(Self {
            header,
            slot_mask,
            digests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_digests_request_encode_decode() {
        let req = GetDigestsRequest::default();
        let mut buffer = [0u8; 4];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, 4);
        assert_eq!(buffer, [0x12, 0xF8, 0x00, 0x00]);

        let decoded = GetDigestsRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.header.version, SpdmVersion::V12);
    }

    #[test]
    fn test_digests_response_encode_decode() {
        let digest1 = [0xAA; MAX_HASH_SIZE];
        let digest2 = [0xBB; MAX_HASH_SIZE];
        let digests = vec![digest1, digest2];
        let resp = DigestsResponse::new(SpdmVersion::V12, 0x03, digests);

        let expected_size = 4 + 1 + 2 * MAX_HASH_SIZE;
        let mut buffer = vec![0u8; expected_size];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, expected_size);

        let decoded = DigestsResponse::decode(&buffer).unwrap();
        assert_eq!(decoded.slot_mask, 0x03);
        assert_eq!(decoded.slot_count(), 2);
        assert_eq!(decoded.digests[0], [0xAA; MAX_HASH_SIZE]);
    }

    #[test]
    fn test_slot_count() {
        let resp = DigestsResponse::new(SpdmVersion::V12, 0x07, vec![]);
        assert_eq!(resp.slot_count(), 3);

        let resp2 = DigestsResponse::new(SpdmVersion::V12, 0x01, vec![]);
        assert_eq!(resp2.slot_count(), 1);
    }

    #[test]
    fn test_get_digest_by_slot() {
        let digest1 = [0xAA; MAX_HASH_SIZE];
        let digest3 = [0xCC; MAX_HASH_SIZE];
        let digests = vec![digest1, digest3];
        let resp = DigestsResponse::new(SpdmVersion::V12, 0x05, digests);

        assert_eq!(resp.get_digest(0), Some(&[0xAA; MAX_HASH_SIZE]));
        assert_eq!(resp.get_digest(2), Some(&[0xCC; MAX_HASH_SIZE]));
        assert_eq!(resp.get_digest(1), None);
        assert_eq!(resp.get_digest(8), None);
    }

    #[test]
    fn test_digests_buffer_too_small() {
        let digests = vec![[0xAA; MAX_HASH_SIZE]];
        let resp = DigestsResponse::new(SpdmVersion::V12, 0x01, digests);
        
        let mut buffer = [0u8; 4];
        assert!(resp.encode(&mut buffer).is_err());

        let small_buffer = [0u8; 4];
        assert!(DigestsResponse::decode(&small_buffer).is_err());
    }
}