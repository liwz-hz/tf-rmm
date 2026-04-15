//! SPDM Sign Module (ECDSA P-256/P-384)

use crate::error::{SpdmStatus, SpdmResult};
use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use p384::ecdsa::{VerifyingKey as VerifyingKey384, Signature as Signature384, signature::Verifier as Verifier384};

pub const ECDSA_P256_SIGNATURE_SIZE: usize = 64;
pub const ECDSA_P384_SIGNATURE_SIZE: usize = 96;

pub trait SpdmSign {
    fn signature_size(&self) -> usize;
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> SpdmResult<bool>;
}

pub struct SpdmEcdsaP256;
pub struct SpdmEcdsaP384;

impl SpdmSign for SpdmEcdsaP256 {
    fn signature_size(&self) -> usize {
        ECDSA_P256_SIGNATURE_SIZE
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> SpdmResult<bool> {
        if signature.len() != ECDSA_P256_SIGNATURE_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let sig = Signature::from_slice(signature)
            .map_err(|_| SpdmStatus::CryptoError)?;
        
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

impl SpdmSign for SpdmEcdsaP384 {
    fn signature_size(&self) -> usize {
        ECDSA_P384_SIGNATURE_SIZE
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> SpdmResult<bool> {
        if signature.len() != ECDSA_P384_SIGNATURE_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let verifying_key = VerifyingKey384::from_sec1_bytes(public_key)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let sig = Signature384::from_slice(signature)
            .map_err(|_| SpdmStatus::CryptoError)?;
        
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

pub fn ecdsa_verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> SpdmResult<bool> {
    SpdmEcdsaP256.verify(public_key, message, signature)
}

pub fn ecdsa_verify_p384(public_key: &[u8], message: &[u8], signature: &[u8]) -> SpdmResult<bool> {
    SpdmEcdsaP384.verify(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p384::ecdsa::{SigningKey as SigningKey384, signature::Signer as Signer384};
    use rand_core::OsRng;

    #[test]
    fn test_ecdsa_verify_p256_success() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        
        let signature: Signature = signing_key.sign(message);
        
        let result = ecdsa_verify_p256(
            verifying_key.to_sec1_bytes().as_ref(),
            message,
            signature.to_bytes().as_ref(),
        ).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_ecdsa_verify_p256_wrong_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        
        let sig: Signature = signing_key.sign(message);
        let mut signature: [u8; 64] = sig.to_bytes().into();
        signature[0] ^= 0xFF;
        
        let result = ecdsa_verify_p256(
            verifying_key.to_sec1_bytes().as_ref(),
            message,
            &signature,
        ).unwrap();
        
        assert!(!result);
    }

    #[test]
    fn test_ecdsa_verify_p256_wrong_message() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        
        let signature: Signature = signing_key.sign(message);
        
        let result = ecdsa_verify_p256(
            verifying_key.to_sec1_bytes().as_ref(),
            b"wrong message",
            signature.to_bytes().as_ref(),
        ).unwrap();
        
        assert!(!result);
    }

    #[test]
    fn test_ecdsa_verify_p384_success() {
        let signing_key = SigningKey384::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        
        let signature: Signature384 = signing_key.sign(message);
        
        let result = ecdsa_verify_p384(
            verifying_key.to_sec1_bytes().as_ref(),
            message,
            signature.to_bytes().as_ref(),
        ).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_ecdsa_verify_p256_invalid_signature_size() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test";
        
        let signature = [0u8; 32];
        assert!(ecdsa_verify_p256(
            verifying_key.to_sec1_bytes().as_ref(),
            message,
            &signature,
        ).is_err());
    }
}