pub mod header;
pub mod codec;

pub use codec::{
    read_u8, read_u16_le, read_u16_be, read_u32_le, read_u32_be, read_u64_le,
    write_u8, write_u16_le, write_u16_be, write_u32_le, write_u32_be, write_u64_le,
    read_slice, write_slice,
    SpdmEncode, SpdmDecode, encode_to_vec,
};