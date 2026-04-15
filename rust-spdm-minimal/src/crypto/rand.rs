//! SPDM Random Module

use crate::error::{SpdmStatus, SpdmResult};
use rand_core::{OsRng, RngCore};
use alloc::vec::Vec;

pub trait SpdmRand {
    fn random_bytes(&self, len: usize) -> SpdmResult<Vec<u8>>;
}

pub struct SpdmOsRand;

impl SpdmRand for SpdmOsRand {
    fn random_bytes(&self, len: usize) -> SpdmResult<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        Ok(bytes)
    }
}

pub fn random_bytes(len: usize) -> SpdmResult<Vec<u8>> {
    SpdmOsRand.random_bytes(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_bytes_non_zero() {
        let bytes = random_bytes(32).unwrap();
        let all_zero = bytes.iter().all(|&b| b == 0);
        assert!(!all_zero);
    }

    #[test]
    fn test_random_bytes_different() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_bytes_empty() {
        let bytes = random_bytes(0).unwrap();
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_random_bytes_large() {
        let bytes = random_bytes(1024).unwrap();
        assert_eq!(bytes.len(), 1024);
    }
}