//! SPDM CAPABILITIES Protocol (GET_CAPABILITIES / CAPABILITIES)

use crate::error::{SpdmStatus, SpdmResult};
use crate::message::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmEncode, SpdmDecode};
use crate::message::codec;
use alloc::vec::Vec;

/// Requester Capability Flags
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP: u32 = 0x00000002;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP: u32 = 0x00000004;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP: u32 = 0x00000008;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP: u32 = 0x00000040;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP: u32 = 0x00000100;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP: u32 = 0x00000200;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP: u32 = 0x00001000;
pub const SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP: u32 = 0x00002000;

/// Responder Capability Flags
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP: u32 = 0x00000002;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP: u32 = 0x00000004;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP: u32 = 0x00000018;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG: u32 = 0x00000008;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG: u32 = 0x00000010;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP: u32 = 0x00000040;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP: u32 = 0x00000080;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP: u32 = 0x00000100;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP: u32 = 0x00000200;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_SESSION_CAP: u32 = 0x00000400;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP: u32 = 0x00000800;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP: u32 = 0x00004000;
pub const SPDM_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP: u32 = 0x00010000;

/// GET_CAPABILITIES Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCapabilitiesRequest {
    pub header: SpdmMessageHeader,
    pub ct_exponent: u8,
    pub reserved: u8,
    pub flags: u32,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl GetCapabilitiesRequest {
    pub fn new(version: SpdmVersion, flags: u32, data_transfer_size: u32, max_spdm_msg_size: u32) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(version, SpdmRequestCode::GetCapabilities, 0, 0),
            ct_exponent: 0,
            reserved: 0,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
        }
    }

    pub fn default() -> Self {
        Self::new(
            SpdmVersion::V12,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            4096,
            4096,
        )
    }
}

impl SpdmEncode for GetCapabilitiesRequest {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 20;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        buffer[4] = self.ct_exponent;
        buffer[5] = self.reserved;
        codec::write_u32_le(buffer, 6, self.flags)?;
        codec::write_u32_le(buffer, 10, self.data_transfer_size)?;
        codec::write_u32_le(buffer, 14, self.max_spdm_msg_size)?;

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        20
    }
}

impl SpdmDecode for GetCapabilitiesRequest {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 20 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_request() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        Ok(Self {
            header,
            ct_exponent: buffer[4],
            reserved: buffer[5],
            flags: codec::read_u32_le(buffer, 6)?,
            data_transfer_size: codec::read_u32_le(buffer, 10)?,
            max_spdm_msg_size: codec::read_u32_le(buffer, 14)?,
        })
    }
}

/// CAPABILITIES Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesResponse {
    pub header: SpdmMessageHeader,
    pub ct_exponent: u8,
    pub reserved: u8,
    pub flags: u32,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl CapabilitiesResponse {
    pub fn new(version: SpdmVersion, flags: u32, data_transfer_size: u32, max_spdm_msg_size: u32) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(version, SpdmResponseCode::Capabilities, 0, 0),
            ct_exponent: 0,
            reserved: 0,
            flags,
            data_transfer_size,
            max_spdm_msg_size,
        }
    }

    pub fn supports_key_exchange(&self) -> bool {
        (self.flags & SPDM_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) != 0
    }

    pub fn supports_cert(&self) -> bool {
        (self.flags & SPDM_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) != 0
    }

    pub fn supports_session(&self) -> bool {
        (self.flags & SPDM_CAPABILITIES_RESPONSE_FLAGS_SESSION_CAP) != 0
    }
}

impl SpdmEncode for CapabilitiesResponse {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let total_size = 20;
        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..4].copy_from_slice(&encoded);
        buffer[4] = self.ct_exponent;
        buffer[5] = self.reserved;
        codec::write_u32_le(buffer, 6, self.flags)?;
        codec::write_u32_le(buffer, 10, self.data_transfer_size)?;
        codec::write_u32_le(buffer, 14, self.max_spdm_msg_size)?;

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        20
    }
}

impl SpdmDecode for CapabilitiesResponse {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        if buffer.len() < 20 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_response() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        Ok(Self {
            header,
            ct_exponent: buffer[4],
            reserved: buffer[5],
            flags: codec::read_u32_le(buffer, 6)?,
            data_transfer_size: codec::read_u32_le(buffer, 10)?,
            max_spdm_msg_size: codec::read_u32_le(buffer, 14)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_capabilities_request_encode_decode() {
        let req = GetCapabilitiesRequest::default();
        let mut buffer = [0u8; 20];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, 20);

        assert_eq!(buffer[0..4], [0x12, 0xE1, 0x00, 0x00]);
        assert_eq!(buffer[4], 0);
        assert_eq!(buffer[5], 0);

        let decoded = GetCapabilitiesRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.header.version, SpdmVersion::V12);
        assert_eq!(decoded.data_transfer_size, 4096);
    }

    #[test]
    fn test_capabilities_response_encode_decode() {
        let flags = SPDM_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | SPDM_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
        let resp = CapabilitiesResponse::new(SpdmVersion::V12, flags, 4096, 4096);

        let mut buffer = [0u8; 20];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, 20);
        assert_eq!(buffer[0..4], [0x12, 0x61, 0x00, 0x00]);

        let decoded = CapabilitiesResponse::decode(&buffer).unwrap();
        assert!(decoded.supports_key_exchange());
        assert!(decoded.supports_cert());
    }

    #[test]
    fn test_capabilities_check_methods() {
        let resp = CapabilitiesResponse::new(
            SpdmVersion::V12,
            SPDM_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_CAPABILITIES_RESPONSE_FLAGS_SESSION_CAP,
            4096,
            4096,
        );
        assert!(resp.supports_key_exchange());
        assert!(resp.supports_session());
        assert!(!resp.supports_cert());
    }

    #[test]
    fn test_capabilities_buffer_too_small() {
        let req = GetCapabilitiesRequest::default();
        let mut buffer = [0u8; 10];
        assert!(req.encode(&mut buffer).is_err());

        let small_buffer = [0u8; 10];
        assert!(GetCapabilitiesRequest::decode(&small_buffer).is_err());
    }
}