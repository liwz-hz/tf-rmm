//! SPDM HKDF Module (HKDF-Extract/Expand SHA-256/384)

use crate::error::{SpdmStatus, SpdmResult};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use hkdf::hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

pub const HKDF_SHA256_HASH_SIZE: usize = 32;
pub const HKDF_SHA384_HASH_SIZE: usize = 48;

pub trait SpdmHkdf {
    fn hash_size(&self) -> usize;
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> SpdmResult<Vec<u8>>;
    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> SpdmResult<Vec<u8>>;
}

pub struct SpdmHkdfSha256;
pub struct SpdmHkdfSha384;

impl SpdmHkdf for SpdmHkdfSha256 {
    fn hash_size(&self) -> usize {
        HKDF_SHA256_HASH_SIZE
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> SpdmResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(salt)
            .map_err(|_| SpdmStatus::CryptoError)?;
        mac.update(ikm);
        let result = mac.finalize().into_bytes();
        Ok(result.to_vec())
    }

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> SpdmResult<Vec<u8>> {
        let hkdf = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let mut okm = vec![0u8; len];
        hkdf.expand(info, &mut okm)
            .map_err(|_| SpdmStatus::CryptoError)?;
        Ok(okm)
    }
}

impl SpdmHkdf for SpdmHkdfSha384 {
    fn hash_size(&self) -> usize {
        HKDF_SHA384_HASH_SIZE
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> SpdmResult<Vec<u8>> {
        let mut mac = HmacSha384::new_from_slice(salt)
            .map_err(|_| SpdmStatus::CryptoError)?;
        mac.update(ikm);
        let result = mac.finalize().into_bytes();
        Ok(result.to_vec())
    }

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> SpdmResult<Vec<u8>> {
        let hkdf = Hkdf::<Sha384>::from_prk(prk)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let mut okm = vec![0u8; len];
        hkdf.expand(info, &mut okm)
            .map_err(|_| SpdmStatus::CryptoError)?;
        Ok(okm)
    }
}

pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmHkdfSha256.extract(salt, ikm)
}

pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> SpdmResult<Vec<u8>> {
    SpdmHkdfSha256.expand(prk, info, len)
}

pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmHkdfSha384.extract(salt, ikm)
}

pub fn hkdf_expand_sha384(prk: &[u8], info: &[u8], len: usize) -> SpdmResult<Vec<u8>> {
    SpdmHkdfSha384.expand(prk, info, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract_sha256() {
        let salt = b"salt";
        let ikm = b"input key material";
        let prk = hkdf_extract_sha256(salt, ikm).unwrap();
        assert_eq!(prk.len(), HKDF_SHA256_HASH_SIZE);
    }

    #[test]
    fn test_hkdf_expand_sha256() {
        let salt = b"salt";
        let ikm = b"ikm";
        let prk = hkdf_extract_sha256(salt, ikm).unwrap();
        
        let info = b"info";
        let okm = hkdf_expand_sha256(&prk, info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_sha256_zero_info() {
        let prk = [0xAA; 32];
        let okm = hkdf_expand_sha256(&prk, b"", 16).unwrap();
        assert_eq!(okm.len(), 16);
    }

    #[test]
    fn test_hkdf_extract_sha384() {
        let salt = b"salt";
        let ikm = b"input key material";
        let prk = hkdf_extract_sha384(salt, ikm).unwrap();
        assert_eq!(prk.len(), HKDF_SHA384_HASH_SIZE);
    }

    #[test]
    fn test_hkdf_expand_sha384() {
        let salt = b"salt";
        let ikm = b"ikm";
        let prk = hkdf_extract_sha384(salt, ikm).unwrap();
        
        let info = b"info";
        let okm = hkdf_expand_sha384(&prk, info, 48).unwrap();
        assert_eq!(okm.len(), 48);
    }

    #[test]
    fn test_hkdf_expand_sha256_wrong_prk_size() {
        let prk = [0xAA; 16];
        assert!(hkdf_expand_sha256(&prk, b"info", 32).is_err());
    }
}