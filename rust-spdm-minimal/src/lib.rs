#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod context;
pub mod error;
pub mod message;
pub mod protocol;

pub use context::SpdmContext;
pub use error::{SpdmStatus, SpdmResult, is_error};
pub use message::header::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmErrorCode};
pub use protocol::{
    GetVersionRequest, VersionResponse, SpdmVersionNumberEntry,
    GetCapabilitiesRequest, CapabilitiesResponse,
    NegotiateAlgorithmsRequest, AlgorithmsResponse,
    GetDigestsRequest, DigestsResponse,
    GetCertificateRequest, CertificateResponse,
};