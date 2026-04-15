//! SPDM Hash Module (SHA-256/384)

use crate::error::{SpdmStatus, SpdmResult};
use sha2::{Sha256, Sha384, Digest};

pub const SHA256_SIZE: usize = 32;
pub const SHA384_SIZE: usize = 48;
pub const MAX_HASH_SIZE: usize = SHA384_SIZE;

pub trait SpdmHash {
    fn hash_size(&self) -> usize;
    fn hash(&self, data: &[u8]) -> SpdmResult<Vec<u8>>;
}

pub struct SpdmSha256;
pub struct SpdmSha384;

impl SpdmHash for SpdmSha256 {
    fn hash_size(&self) -> usize {
        SHA256_SIZE
    }

    fn hash(&self, data: &[u8]) -> SpdmResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }
}

impl SpdmHash for SpdmSha384 {
    fn hash_size(&self) -> usize {
        SHA384_SIZE
    }

    fn hash(&self, data: &[u8]) -> SpdmResult<Vec<u8>> {
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }
}

pub fn sha256(data: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmSha256.hash(data)
}

pub fn sha384(data: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmSha384.hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        let data = b"abc";
        let result = sha256(data).unwrap();
        
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"").unwrap();
        assert_eq!(result.len(), SHA256_SIZE);
        
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn test_sha256_long_data() {
        let data = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let result = sha256(data).unwrap();
        assert_eq!(result.len(), SHA256_SIZE);
    }

    #[test]
    fn test_sha384_known_vector() {
        let data = b"abc";
        let result = sha384(data).unwrap();
        
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
            0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
            0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
            0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn test_sha384_empty() {
        let result = sha384(b"").unwrap();
        assert_eq!(result.len(), SHA384_SIZE);
    }

    #[test]
    fn test_hash_size() {
        let sha256_hasher = SpdmSha256;
        assert_eq!(sha256_hasher.hash_size(), SHA256_SIZE);
        
        let sha384_hasher = SpdmSha384;
        assert_eq!(sha384_hasher.hash_size(), SHA384_SIZE);
    }
}