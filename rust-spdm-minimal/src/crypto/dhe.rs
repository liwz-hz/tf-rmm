//! SPDM DHE Module (ECDH P-256/P-384)

use crate::error::{SpdmStatus, SpdmResult};
use p256::ecdh::EphemeralSecret;
use p384::ecdh::EphemeralSecret as EphemeralSecret384;
use alloc::vec::Vec;
use rand_core::OsRng;

pub const P256_PUBLIC_KEY_SIZE: usize = 65;
pub const P256_PRIVATE_KEY_SIZE: usize = 32;
pub const P256_SHARED_SECRET_SIZE: usize = 32;
pub const P384_PUBLIC_KEY_SIZE: usize = 97;
pub const P384_PRIVATE_KEY_SIZE: usize = 48;
pub const P384_SHARED_SECRET_SIZE: usize = 48;

pub trait SpdmDhe {
    fn public_key_size(&self) -> usize;
    fn private_key_size(&self) -> usize;
    fn shared_secret_size(&self) -> usize;
}

pub struct SpdmEcdhP256;
pub struct SpdmEcdhP384;

impl SpdmDhe for SpdmEcdhP256 {
    fn public_key_size(&self) -> usize { P256_PUBLIC_KEY_SIZE }
    fn private_key_size(&self) -> usize { P256_PRIVATE_KEY_SIZE }
    fn shared_secret_size(&self) -> usize { P256_SHARED_SECRET_SIZE }
}

impl SpdmDhe for SpdmEcdhP384 {
    fn public_key_size(&self) -> usize { P384_PUBLIC_KEY_SIZE }
    fn private_key_size(&self) -> usize { P384_PRIVATE_KEY_SIZE }
    fn shared_secret_size(&self) -> usize { P384_SHARED_SECRET_SIZE }
}

pub struct EcdhP256KeyPair {
    secret: EphemeralSecret,
}

pub struct EcdhP384KeyPair {
    secret: EphemeralSecret384,
}

impl EcdhP256KeyPair {
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.secret.public_key().to_sec1_bytes().to_vec()
    }
    
    pub fn shared_secret(&self, peer_public: &[u8]) -> SpdmResult<Vec<u8>> {
        let peer = p256::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(shared.raw_secret_bytes().to_vec())
    }
}

impl EcdhP384KeyPair {
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.secret.public_key().to_sec1_bytes().to_vec()
    }
    
    pub fn shared_secret(&self, peer_public: &[u8]) -> SpdmResult<Vec<u8>> {
        let peer = p384::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| SpdmStatus::CryptoError)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(shared.raw_secret_bytes().to_vec())
    }
}

pub fn ecdh_p256_keypair() -> SpdmResult<EcdhP256KeyPair> {
    let secret = EphemeralSecret::random(&mut OsRng);
    Ok(EcdhP256KeyPair { secret })
}

pub fn ecdh_p384_keypair() -> SpdmResult<EcdhP384KeyPair> {
    let secret = EphemeralSecret384::random(&mut OsRng);
    Ok(EcdhP384KeyPair { secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_p256_keypair() {
        let kp = ecdh_p256_keypair().unwrap();
        let pubkey = kp.public_key_bytes();
        assert_eq!(pubkey.len(), P256_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ecdh_p256_shared_secret() {
        let kp1 = ecdh_p256_keypair().unwrap();
        let kp2 = ecdh_p256_keypair().unwrap();
        
        let secret1 = kp1.shared_secret(&kp2.public_key_bytes()).unwrap();
        let secret2 = kp2.shared_secret(&kp1.public_key_bytes()).unwrap();
        
        assert_eq!(secret1.len(), P256_SHARED_SECRET_SIZE);
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_ecdh_p256_invalid_peer_public() {
        let kp = ecdh_p256_keypair().unwrap();
        let invalid_pub = [0x00; 32];
        assert!(kp.shared_secret(&invalid_pub).is_err());
    }

    #[test]
    fn test_ecdh_p384_keypair() {
        let kp = ecdh_p384_keypair().unwrap();
        let pubkey = kp.public_key_bytes();
        assert_eq!(pubkey.len(), P384_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ecdh_p384_shared_secret() {
        let kp1 = ecdh_p384_keypair().unwrap();
        let kp2 = ecdh_p384_keypair().unwrap();
        
        let secret1 = kp1.shared_secret(&kp2.public_key_bytes()).unwrap();
        let secret2 = kp2.shared_secret(&kp1.public_key_bytes()).unwrap();
        
        assert_eq!(secret1.len(), P384_SHARED_SECRET_SIZE);
        assert_eq!(secret1, secret2);
    }
}