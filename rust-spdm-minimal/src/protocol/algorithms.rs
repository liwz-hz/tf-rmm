//! SPDM ALGORITHMS Protocol (NEGOTIATE_ALGORITHMS / ALGORITHMS)

use crate::error::{SpdmStatus, SpdmResult};
use crate::message::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmEncode, SpdmDecode};
use crate::message::codec;
use alloc::vec::Vec;

/// Base Hash Algorithm Flags
pub const SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256: u32 = 0x00000002;
pub const SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384: u32 = 0x00000004;
pub const SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512: u32 = 0x00000008;

/// Base Asymmetric Algorithm Flags
pub const SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256: u32 = 0x00000010;
pub const SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384: u32 = 0x00000020;
pub const SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048: u32 = 0x00000040;
pub const SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072: u32 = 0x00000080;
pub const SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096: u32 = 0x00000100;

/// DHE Group Flags
pub const SPDM_ALGORITHMS_DHE_ALGO_FFDHE_2048: u16 = 0x0001;
pub const SPDM_ALGORITHMS_DHE_ALGO_FFDHE_3072: u16 = 0x0002;
pub const SPDM_ALGORITHMS_DHE_ALGO_FFDHE_4096: u16 = 0x0004;
pub const SPDM_ALGORITHMS_DHE_ALGO_SECP256R1: u16 = 0x0008;
pub const SPDM_ALGORITHMS_DHE_ALGO_SECP384R1: u16 = 0x0010;

/// AEAD Cipher Suite Flags
pub const SPDM_ALGORITHMS_AEAD_ALGO_AES_128_GCM: u16 = 0x0001;
pub const SPDM_ALGORITHMS_AEAD_ALGO_AES_256_GCM: u16 = 0x0002;
pub const SPDM_ALGORITHMS_AEAD_ALGO_CHACHA20_POLY1305: u16 = 0x0004;

/// Measurement Specification Flags
pub const SPDM_MEASUREMENT_SPEC_DMTF: u8 = 0x01;

/// Measurement Hash Algorithm Flags
pub const SPDM_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM: u32 = 0x00000001;
pub const SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256: u32 = 0x00000002;
pub const SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384: u32 = 0x00000004;

/// NEGOTIATE_ALGORITHMS Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateAlgorithmsRequest {
    pub header: SpdmMessageHeader,
    pub measurement_spec: u8,
    pub other_params: u8,
    pub base_asym_algo: u32,
    pub base_hash_algo: u32,
    pub dhe_group: u16,
    pub aead_cipher_suite: u16,
    pub reserved: u16,
    pub reserved2: u8,
}

impl NegotiateAlgorithmsRequest {
    pub fn new(
        version: SpdmVersion,
        measurement_spec: u8,
        base_asym_algo: u32,
        base_hash_algo: u32,
        dhe_group: u16,
        aead_cipher_suite: u16,
    ) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(version, SpdmRequestCode::NegotiateAlgorithms, 0, 0),
            measurement_spec,
            other_params: 0,
            base_asym_algo,
            base_hash_algo,
            dhe_group,
            aead_cipher_suite,
            reserved: 0,
            reserved2: 0,
        }
    }

    pub fn default() -> Self {
        Self::new(
            SpdmVersion::V12,
            SPDM_MEASUREMENT_SPEC_DMTF,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
                | SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256
                | SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            SPDM_ALGORITHMS_DHE_ALGO_SECP256R1 | SPDM_ALGORITHMS_DHE_ALGO_SECP384R1,
            SPDM_ALGORITHMS_AEAD_ALGO_AES_128_GCM | SPDM_ALGORITHMS_AEAD_ALGO_AES_256_GCM,
        )
    }
}

impl SpdmEncode for NegotiateAlgorithmsRequest {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 32;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        buffer[4] = self.measurement_spec;
        buffer[5] = self.other_params;
        codec::write_u32_le(buffer, 6, self.base_asym_algo)?;
        codec::write_u32_le(buffer, 10, self.base_hash_algo)?;
        codec::write_u16_le(buffer, 14, self.dhe_group)?;
        codec::write_u16_le(buffer, 16, self.aead_cipher_suite)?;
        codec::write_u16_le(buffer, 18, self.reserved)?;
        buffer[20] = self.reserved2;

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        32
    }
}

impl SpdmDecode for NegotiateAlgorithmsRequest {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 32 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_request() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        Ok(Self {
            header,
            measurement_spec: buffer[4],
            other_params: buffer[5],
            base_asym_algo: codec::read_u32_le(buffer, 6)?,
            base_hash_algo: codec::read_u32_le(buffer, 10)?,
            dhe_group: codec::read_u16_le(buffer, 14)?,
            aead_cipher_suite: codec::read_u16_le(buffer, 16)?,
            reserved: codec::read_u16_le(buffer, 18)?,
            reserved2: buffer[20],
        })
    }
}

/// ALGORITHMS Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmsResponse {
    pub header: SpdmMessageHeader,
    pub measurement_spec: u8,
    pub measurement_hash_algo: u32,
    pub base_asym_sel: u32,
    pub base_hash_sel: u32,
    pub dhe_sel: u16,
    pub aead_sel: u16,
    pub reserved: u16,
}

impl AlgorithmsResponse {
    pub fn new(
        version: SpdmVersion,
        measurement_spec: u8,
        measurement_hash_algo: u32,
        base_asym_sel: u32,
        base_hash_sel: u32,
        dhe_sel: u16,
        aead_sel: u16,
    ) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(version, SpdmResponseCode::Algorithms, 0, 0),
            measurement_spec,
            measurement_hash_algo,
            base_asym_sel,
            base_hash_sel,
            dhe_sel,
            aead_sel,
            reserved: 0,
        }
    }

    pub fn hash_algo_is_sha256(&self) -> bool {
        self.base_hash_sel == SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256
    }

    pub fn hash_algo_is_sha384(&self) -> bool {
        self.base_hash_sel == SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384
    }

    pub fn dhe_is_secp256r1(&self) -> bool {
        self.dhe_sel == SPDM_ALGORITHMS_DHE_ALGO_SECP256R1
    }

    pub fn dhe_is_secp384r1(&self) -> bool {
        self.dhe_sel == SPDM_ALGORITHMS_DHE_ALGO_SECP384R1
    }

    pub fn aead_is_aes128_gcm(&self) -> bool {
        self.aead_sel == SPDM_ALGORITHMS_AEAD_ALGO_AES_128_GCM
    }

    pub fn aead_is_aes256_gcm(&self) -> bool {
        self.aead_sel == SPDM_ALGORITHMS_AEAD_ALGO_AES_256_GCM
    }
}

impl SpdmEncode for AlgorithmsResponse {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 36;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        buffer[4] = self.measurement_spec;
        codec::write_u32_le(buffer, 5, self.measurement_hash_algo)?;
        codec::write_u32_le(buffer, 9, self.base_asym_sel)?;
        codec::write_u32_le(buffer, 13, self.base_hash_sel)?;
        codec::write_u16_le(buffer, 17, self.dhe_sel)?;
        codec::write_u16_le(buffer, 19, self.aead_sel)?;
        codec::write_u16_le(buffer, 21, self.reserved)?;

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        36
    }
}

impl SpdmDecode for AlgorithmsResponse {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 36 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_response() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        Ok(Self {
            header,
            measurement_spec: buffer[4],
            measurement_hash_algo: codec::read_u32_le(buffer, 5)?,
            base_asym_sel: codec::read_u32_le(buffer, 9)?,
            base_hash_sel: codec::read_u32_le(buffer, 13)?,
            dhe_sel: codec::read_u16_le(buffer, 17)?,
            aead_sel: codec::read_u16_le(buffer, 19)?,
            reserved: codec::read_u16_le(buffer, 21)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_algorithms_request_encode_decode() {
        let req = NegotiateAlgorithmsRequest::default();
        let mut buffer = [0u8; 32];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, 32);
        assert_eq!(buffer[0..4], [0x12, 0xE3, 0x00, 0x00]);
        assert_eq!(buffer[4], SPDM_MEASUREMENT_SPEC_DMTF);

        let decoded = NegotiateAlgorithmsRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.measurement_spec, SPDM_MEASUREMENT_SPEC_DMTF);
    }

    #[test]
    fn test_algorithms_response_encode_decode() {
        let resp = AlgorithmsResponse::new(
            SpdmVersion::V12,
            SPDM_MEASUREMENT_SPEC_DMTF,
            SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            SPDM_ALGORITHMS_DHE_ALGO_SECP256R1,
            SPDM_ALGORITHMS_AEAD_ALGO_AES_128_GCM,
        );

        let mut buffer = [0u8; 36];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, 36);

        let decoded = AlgorithmsResponse::decode(&buffer).unwrap();
        assert!(decoded.hash_algo_is_sha256());
        assert!(decoded.dhe_is_secp256r1());
        assert!(decoded.aead_is_aes128_gcm());
    }

    #[test]
    fn test_algorithms_check_methods() {
        let resp = AlgorithmsResponse::new(
            SpdmVersion::V12,
            SPDM_MEASUREMENT_SPEC_DMTF,
            SPDM_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            SPDM_ALGORITHMS_DHE_ALGO_SECP384R1,
            SPDM_ALGORITHMS_AEAD_ALGO_AES_256_GCM,
        );

        assert!(resp.hash_algo_is_sha384());
        assert!(!resp.hash_algo_is_sha256());
        assert!(resp.dhe_is_secp384r1());
        assert!(resp.aead_is_aes256_gcm());
    }

    #[test]
    fn test_algorithms_buffer_too_small() {
        let req = NegotiateAlgorithmsRequest::default();
        let mut buffer = [0u8; 20];
        assert!(req.encode(&mut buffer).is_err());

        let small_buffer = [0u8; 20];
        assert!(NegotiateAlgorithmsRequest::decode(&small_buffer).is_err());
    }
}