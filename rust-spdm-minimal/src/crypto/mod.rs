pub mod hash;
pub mod aead;
pub mod dhe;
pub mod sign;
pub mod hkdf;
pub mod rand;
pub mod hmac;

pub use hash::{SpdmHash, sha256, sha384, SHA256_SIZE, SHA384_SIZE, MAX_HASH_SIZE};
pub use aead::{SpdmAead, aes128_gcm_encrypt, aes128_gcm_decrypt, aes256_gcm_encrypt, aes256_gcm_decrypt};
pub use dhe::{SpdmDhe, EcdhP256KeyPair, EcdhP384KeyPair, ecdh_p256_keypair, ecdh_p384_keypair, P384_PUBLIC_KEY_RAW_SIZE};
pub use sign::{SpdmSign, ecdsa_verify_p256, ecdsa_verify_p384};
pub use hkdf::{SpdmHkdf, hkdf_extract_sha256, hkdf_expand_sha256, hkdf_extract_sha384, hkdf_expand_sha384};
pub use rand::{SpdmRand, random_bytes};
pub use hmac::{hmac_sha256, hmac_sha384};