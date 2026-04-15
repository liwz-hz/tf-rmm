//! SPDM Message Codec Utilities
//!
//! Provides encoding/decoding helpers for SPDM messages:
//! - Read/write primitives (u8, u16, u32, u64)
//! - Buffer slice operations
//! - Codec trait for message types

use crate::error::{SpdmStatus, SpdmResult};
use alloc::vec::Vec;

/// Read u8 from buffer at offset
pub fn read_u8(buffer: &[u8], offset: usize) -> SpdmResult<u8> {
    if offset >= buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(buffer[offset])
}

/// Read u16 from buffer at offset (little-endian)
pub fn read_u16_le(buffer: &[u8], offset: usize) -> SpdmResult<u16> {
    if offset + 2 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(u16::from_le_bytes([buffer[offset], buffer[offset + 1]]))
}

/// Read u16 from buffer at offset (big-endian)
pub fn read_u16_be(buffer: &[u8], offset: usize) -> SpdmResult<u16> {
    if offset + 2 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(u16::from_be_bytes([buffer[offset], buffer[offset + 1]]))
}

/// Read u32 from buffer at offset (little-endian)
pub fn read_u32_le(buffer: &[u8], offset: usize) -> SpdmResult<u32> {
    if offset + 4 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]))
}

/// Read u32 from buffer at offset (big-endian)
pub fn read_u32_be(buffer: &[u8], offset: usize) -> SpdmResult<u32> {
    if offset + 4 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]))
}

/// Read u64 from buffer at offset (little-endian)
pub fn read_u64_le(buffer: &[u8], offset: usize) -> SpdmResult<u64> {
    if offset + 8 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]))
}

/// Write u8 to buffer at offset
pub fn write_u8(buffer: &mut [u8], offset: usize, value: u8) -> SpdmResult<()> {
    if offset >= buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    buffer[offset] = value;
    Ok(())
}

/// Write u16 to buffer at offset (little-endian)
pub fn write_u16_le(buffer: &mut [u8], offset: usize, value: u16) -> SpdmResult<()> {
    if offset + 2 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    let bytes = value.to_le_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
    Ok(())
}

/// Write u16 to buffer at offset (big-endian)
pub fn write_u16_be(buffer: &mut [u8], offset: usize, value: u16) -> SpdmResult<()> {
    if offset + 2 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    let bytes = value.to_be_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
    Ok(())
}

/// Write u32 to buffer at offset (little-endian)
pub fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) -> SpdmResult<()> {
    if offset + 4 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    let bytes = value.to_le_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
    buffer[offset + 2] = bytes[2];
    buffer[offset + 3] = bytes[3];
    Ok(())
}

/// Write u32 to buffer at offset (big-endian)
pub fn write_u32_be(buffer: &mut [u8], offset: usize, value: u32) -> SpdmResult<()> {
    if offset + 4 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    let bytes = value.to_be_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
    buffer[offset + 2] = bytes[2];
    buffer[offset + 3] = bytes[3];
    Ok(())
}

/// Write u64 to buffer at offset (little-endian)
pub fn write_u64_le(buffer: &mut [u8], offset: usize, value: u64) -> SpdmResult<()> {
    if offset + 8 > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    let bytes = value.to_le_bytes();
    for i in 0..8 {
        buffer[offset + i] = bytes[i];
    }
    Ok(())
}

/// Read slice from buffer at offset
pub fn read_slice(buffer: &[u8], offset: usize, len: usize) -> SpdmResult<&[u8]> {
    if offset + len > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    Ok(&buffer[offset..offset + len])
}

/// Write slice to buffer at offset
pub fn write_slice(buffer: &mut [u8], offset: usize, data: &[u8]) -> SpdmResult<()> {
    if offset + data.len() > buffer.len() {
        return Err(SpdmStatus::BufferTooSmall);
    }
    buffer[offset..offset + data.len()].copy_from_slice(data);
    Ok(())
}

/// Encode trait for SPDM messages
pub trait SpdmEncode {
    fn encode(&self, buffer: &mut [u8]) -> SpdmResult<usize>;
    fn encoded_size(&self) -> usize;
}

/// Decode trait for SPDM messages
pub trait SpdmDecode: Sized {
    fn decode(buffer: &[u8]) -> SpdmResult<Self>;
}

/// Helper to encode message into Vec
pub fn encode_to_vec<M: SpdmEncode>(msg: &M) -> SpdmResult<Vec<u8>> {
    let size = msg.encoded_size();
    let mut buffer = alloc::vec![0u8; size];
    let written = msg.encode(&mut buffer)?;
    buffer.truncate(written);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u8_success() {
        let buffer = [0x12, 0x34, 0x56];
        assert_eq!(read_u8(&buffer, 0).unwrap(), 0x12);
        assert_eq!(read_u8(&buffer, 1).unwrap(), 0x34);
        assert_eq!(read_u8(&buffer, 2).unwrap(), 0x56);
    }

    #[test]
    fn test_read_u8_buffer_too_small() {
        let buffer = [0x12];
        assert!(read_u8(&buffer, 1).is_err());
    }

    #[test]
    fn test_read_u16_le_success() {
        let buffer = [0x34, 0x12];
        assert_eq!(read_u16_le(&buffer, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_be_success() {
        let buffer = [0x12, 0x34];
        assert_eq!(read_u16_be(&buffer, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32_le_success() {
        let buffer = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&buffer, 0).unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u32_be_success() {
        let buffer = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(read_u32_be(&buffer, 0).unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u64_le_success() {
        let buffer = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        assert_eq!(read_u64_le(&buffer, 0).unwrap(), 0x0123456789ABCDEF);
    }

    #[test]
    fn test_write_u8_success() {
        let mut buffer = [0u8; 4];
        write_u8(&mut buffer, 0, 0x12).unwrap();
        write_u8(&mut buffer, 1, 0x34).unwrap();
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
    }

    #[test]
    fn test_write_u16_le_success() {
        let mut buffer = [0u8; 4];
        write_u16_le(&mut buffer, 0, 0x1234).unwrap();
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);
    }

    #[test]
    fn test_write_u16_be_success() {
        let mut buffer = [0u8; 4];
        write_u16_be(&mut buffer, 0, 0x1234).unwrap();
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
    }

    #[test]
    fn test_write_u32_le_success() {
        let mut buffer = [0u8; 8];
        write_u32_le(&mut buffer, 0, 0x12345678).unwrap();
        assert_eq!(buffer, [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
    }

    #[test]
    fn test_write_u32_be_success() {
        let mut buffer = [0u8; 8];
        write_u32_be(&mut buffer, 0, 0x12345678).unwrap();
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
    }

    #[test]
    fn test_write_slice_success() {
        let mut buffer = [0u8; 8];
        let data = [0x01, 0x02, 0x03, 0x04];
        write_slice(&mut buffer, 2, &data).unwrap();
        assert_eq!(buffer, [0, 0, 0x01, 0x02, 0x03, 0x04, 0, 0]);
    }

    #[test]
    fn test_read_slice_success() {
        let buffer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let slice = read_slice(&buffer, 2, 3).unwrap();
        assert_eq!(slice, &[0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_read_slice_buffer_too_small() {
        let buffer = [0x01, 0x02];
        assert!(read_slice(&buffer, 0, 3).is_err());
        assert!(read_slice(&buffer, 1, 2).is_err());
    }

    #[test]
    fn test_write_buffer_too_small() {
        let mut buffer = [0u8; 2];
        assert!(write_u32_le(&mut buffer, 0, 0x12345678).is_err());
        assert!(write_u16_le(&mut buffer, 1, 0x1234).is_err());
        assert!(write_slice(&mut buffer, 0, &[1, 2, 3]).is_err());
    }

    #[test]
    fn test_roundtrip_u32() {
        let mut buffer = [0u8; 4];
        write_u32_le(&mut buffer, 0, 0xDEADBEEF).unwrap();
        let value = read_u32_le(&buffer, 0).unwrap();
        assert_eq!(value, 0xDEADBEEF);
    }
}