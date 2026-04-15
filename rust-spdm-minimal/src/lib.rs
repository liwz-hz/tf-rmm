#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod context;
pub mod error;
pub mod message;
pub mod protocol;
pub mod crypto;
pub mod session;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use context::SpdmContext;
pub use error::{SpdmStatus, SpdmResult, is_error};
pub use message::header::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmErrorCode};
pub use protocol::{
    GetVersionRequest, VersionResponse, SpdmVersionNumberEntry,
    GetCapabilitiesRequest, CapabilitiesResponse,
    NegotiateAlgorithmsRequest, AlgorithmsResponse,
    GetDigestsRequest, DigestsResponse,
    GetCertificateRequest, CertificateResponse,
    KeyExchangeRequest, KeyExchangeResponse,
    FinishRequest, FinishResponse,
    EndSessionRequest, EndSessionResponse,
};
pub use crypto::{
    sha256, sha384, SHA256_SIZE, SHA384_SIZE, MAX_HASH_SIZE,
    aes128_gcm_encrypt, aes128_gcm_decrypt, aes256_gcm_encrypt, aes256_gcm_decrypt,
    EcdhP256KeyPair, EcdhP384KeyPair, ecdh_p256_keypair, ecdh_p384_keypair,
    ecdsa_verify_p256, ecdsa_verify_p384,
    hkdf_extract_sha256, hkdf_expand_sha256, hkdf_extract_sha384, hkdf_expand_sha384,
    random_bytes,
};
pub use session::{
    SessionState, SessionInfo, SessionContext,
    derive_master_secret, derive_encryption_key, derive_mac_key,
    SecuredMessage, encrypt_message, decrypt_message,
};