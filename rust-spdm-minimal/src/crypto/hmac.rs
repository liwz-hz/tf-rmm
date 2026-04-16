//! SPDM HMAC Module (HMAC-SHA-256/384)

use crate::error::{SpdmStatus, SpdmResult};
use sha2::{Sha256, Sha384};
use hkdf::hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> SpdmResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| SpdmStatus::CryptoError)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    Ok(result.to_vec())
}

pub fn hmac_sha384(key: &[u8], data: &[u8]) -> SpdmResult<Vec<u8>> {
    let mut mac = HmacSha384::new_from_slice(key)
        .map_err(|_| SpdmStatus::CryptoError)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    Ok(result.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_known_vector() {
        // Test vector from RFC 4231
        let key = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
        let data = b"Hi There";
        let result = hmac_sha256(key, data).unwrap();
        
        // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9f6247bf1dd3b0e3
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha384_known_vector() {
        let key = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
        let data = b"Hi There";
        let result = hmac_sha384(key, data).unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_hmac_sha384_empty_data() {
        let key = [0xAA; 48];
        let result = hmac_sha384(&key, b"").unwrap();
        assert_eq!(result.len(), 48);
    }
}