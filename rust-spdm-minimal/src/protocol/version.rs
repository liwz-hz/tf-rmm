//! SPDM VERSION Protocol (GET_VERSION / VERSION)

use crate::error::{SpdmStatus, SpdmResult};
use crate::message::{SpdmMessageHeader, SpdmVersion, SpdmRequestCode, SpdmResponseCode, SpdmEncode, SpdmDecode};
use crate::message::codec;
use alloc::vec::Vec;

/// SPDM Version Number Entry (2 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdmVersionNumberEntry {
    pub major: u8,
    pub minor: u8,
}

impl SpdmVersionNumberEntry {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    pub fn from_byte(byte: u8) -> Self {
        Self {
            major: (byte >> 4) & 0x0F,
            minor: byte & 0x0F,
        }
    }

    pub fn to_byte(self) -> u8 {
        (self.major << 4) | self.minor
    }

    pub fn as_version(self) -> SpdmVersion {
        let version_byte = self.to_byte();
        SpdmVersion::from_byte(version_byte).unwrap_or(SpdmVersion::V12)
    }
}

/// GET_VERSION Request (4 bytes header only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetVersionRequest {
    pub header: SpdmMessageHeader,
}

impl GetVersionRequest {
    pub fn new(version: SpdmVersion) -> Self {
        Self {
            header: SpdmMessageHeader::new_request(version, SpdmRequestCode::GetVersion, 0, 0),
        }
    }

    pub fn default() -> Self {
        Self::new(SpdmVersion::V10)
    }
}

impl SpdmEncode for GetVersionRequest {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let encoded = self.header.encode();
        if buffer.len() < 4 {
            return Err(SpdmStatus::BufferTooSmall);
        }
        buffer[..4].copy_from_slice(&encoded);
        Ok(4)
    }

    fn encoded_size(&self) -> usize {
        4
    }
}

impl SpdmDecode for GetVersionRequest {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_request() {
            return Err(SpdmStatus::InvalidMsgField);
        }
        Ok(Self { header })
    }
}

/// VERSION Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionResponse {
    pub header: SpdmMessageHeader,
    pub version_number_entry_count: u8,
    pub versions: Vec<SpdmVersionNumberEntry>,
}

impl VersionResponse {
    pub fn new(version: SpdmVersion, versions: Vec<SpdmVersionNumberEntry>) -> Self {
        Self {
            header: SpdmMessageHeader::new_response(
                version,
                SpdmResponseCode::Version,
                versions.len() as u8,
                0,
            ),
            version_number_entry_count: versions.len() as u8,
            versions,
        }
    }

    pub fn select_highest_version(&self) -> SpdmVersion {
        self.versions
            .iter()
            .map(|v| v.as_version())
            .filter(|v| *v <= SpdmVersion::V12)
            .max()
            .unwrap_or(SpdmVersion::V12)
    }
}

impl SpdmEncode for VersionResponse {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize> {
        let header_size = 4;
        let versions_size = self.versions.len();
        let total_size = header_size + 1 + versions_size;

        if buffer.len() < total_size {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let encoded = self.header.encode();
        buffer[..header_size].copy_from_slice(&encoded);
        buffer[header_size] = self.version_number_entry_count;

        for (i, v) in self.versions.iter().enumerate() {
            buffer[header_size + 1 + i] = v.to_byte();
        }

        Ok(total_size)
    }

    fn encoded_size(&self) -> usize {
        4 + 1 + self.versions.len()
    }
}

impl SpdmDecode for VersionResponse {
    fn decode(buffer: &[u8]) -> SpdmResult<Self> {
        let header = SpdmMessageHeader::decode(buffer)?;
        if !header.is_response() {
            return Err(SpdmStatus::InvalidMsgField);
        }

        if buffer.len() < 5 {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let count = buffer[4];
        if buffer.len() < 5 + count as usize {
            return Err(SpdmStatus::BufferTooSmall);
        }

        let versions = (0..count as usize)
            .map(|i| SpdmVersionNumberEntry::from_byte(buffer[5 + i]))
            .collect();

        Ok(Self {
            header,
            version_number_entry_count: count,
            versions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_number_entry() {
        let entry = SpdmVersionNumberEntry::new(1, 2);
        assert_eq!(entry.to_byte(), 0x12);
        assert_eq!(entry.as_version(), SpdmVersion::V12);

        let entry2 = SpdmVersionNumberEntry::from_byte(0x10);
        assert_eq!(entry2.major, 1);
        assert_eq!(entry2.minor, 0);
        assert_eq!(entry2.as_version(), SpdmVersion::V10);
    }

    #[test]
    fn test_get_version_request_encode_decode() {
        let req = GetVersionRequest::default();
        let mut buffer = [0u8; 4];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, 4);
        assert_eq!(buffer, [0x10, 0x84, 0x00, 0x00]);

        let decoded = GetVersionRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.header.version, SpdmVersion::V10);
    }

    #[test]
    fn test_version_response_encode_decode() {
        let versions = vec![
            SpdmVersionNumberEntry::new(1, 0),
            SpdmVersionNumberEntry::new(1, 1),
            SpdmVersionNumberEntry::new(1, 2),
        ];
        let resp = VersionResponse::new(SpdmVersion::V10, versions);

        let mut buffer = [0u8; 8];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, 8);
        assert_eq!(buffer[0..4], [0x10, 0x04, 0x03, 0x00]);
        assert_eq!(buffer[4], 3);
        assert_eq!(buffer[5..8], [0x10, 0x11, 0x12]);

        let decoded = VersionResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(decoded.version_number_entry_count, 3);
        assert_eq!(decoded.versions.len(), 3);
    }

    #[test]
    fn test_select_highest_version() {
        let versions = vec![
            SpdmVersionNumberEntry::new(1, 0),
            SpdmVersionNumberEntry::new(1, 2),
        ];
        let resp = VersionResponse::new(SpdmVersion::V10, versions);
        assert_eq!(resp.select_highest_version(), SpdmVersion::V12);
    }

    #[test]
    fn test_version_response_buffer_too_small() {
        let versions = vec![SpdmVersionNumberEntry::new(1, 2)];
        let resp = VersionResponse::new(SpdmVersion::V10, versions);
        
        let mut buffer = [0u8; 4];
        assert!(resp.encode(&mut buffer).is_err());
    }
}