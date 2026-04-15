//! SPDM AEAD Module (AES-128/256-GCM)

use crate::error::{SpdmStatus, SpdmResult};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use alloc::vec::Vec;

pub const AES128_KEY_SIZE: usize = 16;
pub const AES256_KEY_SIZE: usize = 32;
pub const GCM_IV_SIZE: usize = 12;
pub const GCM_TAG_SIZE: usize = 16;

pub trait SpdmAead {
    fn key_size(&self) -> usize;
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> SpdmResult<Vec<u8>>;
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> SpdmResult<Vec<u8>>;
}

pub struct SpdmAes128Gcm;
pub struct SpdmAes256Gcm;

impl SpdmAead for SpdmAes128Gcm {
    fn key_size(&self) -> usize {
        AES128_KEY_SIZE
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> SpdmResult<Vec<u8>> {
        if key.len() != AES128_KEY_SIZE || iv.len() != GCM_IV_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SpdmStatus::CryptoError)?;
        let payload = Payload { msg: plaintext, aad };
        cipher.encrypt(iv.into(), payload).map_err(|_| SpdmStatus::CryptoError)
    }

    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> SpdmResult<Vec<u8>> {
        if key.len() != AES128_KEY_SIZE || iv.len() != GCM_IV_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SpdmStatus::CryptoError)?;
        let payload = Payload { msg: ciphertext, aad };
        cipher.decrypt(iv.into(), payload).map_err(|_| SpdmStatus::CryptoError)
    }
}

impl SpdmAead for SpdmAes256Gcm {
    fn key_size(&self) -> usize {
        AES256_KEY_SIZE
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> SpdmResult<Vec<u8>> {
        if key.len() != AES256_KEY_SIZE || iv.len() != GCM_IV_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SpdmStatus::CryptoError)?;
        let payload = Payload { msg: plaintext, aad };
        cipher.encrypt(iv.into(), payload).map_err(|_| SpdmStatus::CryptoError)
    }

    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> SpdmResult<Vec<u8>> {
        if key.len() != AES256_KEY_SIZE || iv.len() != GCM_IV_SIZE {
            return Err(SpdmStatus::InvalidParameter);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SpdmStatus::CryptoError)?;
        let payload = Payload { msg: ciphertext, aad };
        cipher.decrypt(iv.into(), payload).map_err(|_| SpdmStatus::CryptoError)
    }
}

pub fn aes128_gcm_encrypt(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmAes128Gcm.encrypt(key, iv, aad, plaintext)
}

pub fn aes128_gcm_decrypt(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmAes128Gcm.decrypt(key, iv, aad, ciphertext)
}

pub fn aes256_gcm_encrypt(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmAes256Gcm.encrypt(key, iv, aad, plaintext)
}

pub fn aes256_gcm_decrypt(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> SpdmResult<Vec<u8>> {
    SpdmAes256Gcm.decrypt(key, iv, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_encrypt_decrypt() {
        let key = [0x00; AES128_KEY_SIZE];
        let iv = [0x00; GCM_IV_SIZE];
        let aad = b"aad";
        let plaintext = b"hello world";
        
        let ciphertext = aes128_gcm_encrypt(&key, &iv, aad, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len());
        
        let decrypted = aes128_gcm_decrypt(&key, &iv, aad, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes128_gcm_decrypt_wrong_tag() {
        let key = [0x00; AES128_KEY_SIZE];
        let iv = [0x00; GCM_IV_SIZE];
        let aad = b"aad";
        let plaintext = b"hello";
        
        let ciphertext = aes128_gcm_encrypt(&key, &iv, aad, plaintext).unwrap();
        let mut corrupted = ciphertext.clone();
        corrupted.last_mut().map(|b| *b ^= 0xFF);
        
        assert!(aes128_gcm_decrypt(&key, &iv, aad, &corrupted).is_err());
    }

    #[test]
    fn test_aes128_gcm_decrypt_wrong_key() {
        let key1 = [0x00; AES128_KEY_SIZE];
        let key2 = [0x01; AES128_KEY_SIZE];
        let iv = [0x00; GCM_IV_SIZE];
        let aad = b"aad";
        let plaintext = b"test";
        
        let ciphertext = aes128_gcm_encrypt(&key1, &iv, aad, plaintext).unwrap();
        assert!(aes128_gcm_decrypt(&key2, &iv, aad, &ciphertext).is_err());
    }

    #[test]
    fn test_aes256_gcm_encrypt_decrypt() {
        let key = [0x00; AES256_KEY_SIZE];
        let iv = [0x00; GCM_IV_SIZE];
        let aad = b"aad";
        let plaintext = b"hello world";
        
        let ciphertext = aes256_gcm_encrypt(&key, &iv, aad, plaintext).unwrap();
        let decrypted = aes256_gcm_decrypt(&key, &iv, aad, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes128_gcm_invalid_key_size() {
        let key = [0x00; 10];
        let iv = [0x00; GCM_IV_SIZE];
        assert!(aes128_gcm_encrypt(&key, &iv, b"", b"test").is_err());
    }

    #[test]
    fn test_aes128_gcm_invalid_iv_size() {
        let key = [0x00; AES128_KEY_SIZE];
        let iv = [0x00; 10];
        assert!(aes128_gcm_encrypt(&key, &iv, b"", b"test").is_err());
    }
}