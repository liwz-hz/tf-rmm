use crate::error::{SpdmStatus, SpdmResult};
use crate::crypto::{aes128_gcm_encrypt, aes128_gcm_decrypt, aes256_gcm_encrypt, aes256_gcm_decrypt};
use crate::session::context::SessionInfo;
use alloc::vec::Vec;

pub const AEAD_TAG_SIZE: usize = 16;
pub const AEAD_IV_SIZE: usize = 12;
pub const SECURED_MESSAGE_HEADER_SIZE: usize = 6;

#[derive(Debug, Clone)]
pub struct SecuredMessage {
    session_id: u32,
    sequence_number: u64,
}

impl SecuredMessage {
    pub fn new(session_id: u32, sequence_number: u64) -> Self {
        Self { session_id, sequence_number }
    }

    pub fn header_bytes(&self) -> [u8; SECURED_MESSAGE_HEADER_SIZE] {
        let mut header = [0u8; SECURED_MESSAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&self.session_id.to_le_bytes());
        header[4..6].copy_from_slice(&(self.sequence_number as u16).to_le_bytes());
        header
    }

    pub fn parse_header(bytes: &[u8]) -> SpdmResult<Self> {
        if bytes.len() < SECURED_MESSAGE_HEADER_SIZE {
            return Err(SpdmStatus::BufferTooSmall);
        }
        let session_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let sequence_number = u16::from_le_bytes([bytes[4], bytes[5]]) as u64;
        Ok(Self { session_id, sequence_number })
    }
}

pub fn encrypt_message(
    session: &mut SessionInfo,
    plaintext: &[u8],
    aad: &[u8],
) -> SpdmResult<Vec<u8>> {
    if !session.is_established() {
        return Err(SpdmStatus::InvalidStateLocal);
    }

    let enc_key = session.encryption_key().to_vec();
    let seq = session.increment_sequence();
    
    let iv = build_iv(seq);
    
    let secured = SecuredMessage::new(session.session_id(), seq);
    let header = secured.header_bytes();
    
    let full_aad = build_aad(&header, aad);
    
    let ciphertext = if enc_key.len() == 32 {
        aes256_gcm_encrypt(&enc_key, &iv, &full_aad, plaintext)?
    } else if enc_key.len() == 16 {
        aes128_gcm_encrypt(&enc_key, &iv, &full_aad, plaintext)?
    } else {
        return Err(SpdmStatus::InvalidParameter);
    };

    let mut result = Vec::with_capacity(SECURED_MESSAGE_HEADER_SIZE + ciphertext.len());
    result.extend_from_slice(&header);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_message(
    session: &SessionInfo,
    secured_data: &[u8],
    aad: &[u8],
) -> SpdmResult<Vec<u8>> {
    if !session.is_established() {
        return Err(SpdmStatus::InvalidStateLocal);
    }

    if secured_data.len() < SECURED_MESSAGE_HEADER_SIZE + AEAD_TAG_SIZE {
        return Err(SpdmStatus::BufferTooSmall);
    }

    let secured = SecuredMessage::parse_header(secured_data)?;
    if secured.session_id != session.session_id() {
        return Err(SpdmStatus::InvalidParameter);
    }

    let enc_key = session.encryption_key();
    let iv = build_iv(secured.sequence_number);
    
    let ciphertext = &secured_data[SECURED_MESSAGE_HEADER_SIZE..];
    
    let full_aad = build_aad(&secured.header_bytes(), aad);
    
    if enc_key.len() == 32 {
        aes256_gcm_decrypt(enc_key, &iv, &full_aad, ciphertext)
    } else if enc_key.len() == 16 {
        aes128_gcm_decrypt(enc_key, &iv, &full_aad, ciphertext)
    } else {
        Err(SpdmStatus::InvalidParameter)
    }
}

fn build_iv(sequence_number: u64) -> Vec<u8> {
    let mut iv = vec![0u8; AEAD_IV_SIZE];
    iv[4..12].copy_from_slice(&sequence_number.to_le_bytes());
    iv
}

fn build_aad(header: &[u8], extra_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + extra_aad.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(extra_aad);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::context::{SessionInfo, HashAlgo, SessionState};

    fn setup_session() -> SessionInfo {
        let mut session = SessionInfo::new(0x12345678, HashAlgo::Sha256);
        session.set_state(SessionState::Established);
        session.set_encryption_key(vec![0xAA; 16]).unwrap();
        session.set_mac_key(vec![0xBB; 32]).unwrap();
        session
    }

    fn setup_session_sha384() -> SessionInfo {
        let mut session = SessionInfo::new(0xABCDEF01, HashAlgo::Sha384);
        session.set_state(SessionState::Established);
        session.set_encryption_key(vec![0xCC; 32]).unwrap();
        session.set_mac_key(vec![0xDD; 48]).unwrap();
        session
    }

    #[test]
    fn test_secured_message_header() {
        let secured = SecuredMessage::new(0x12345678, 1);
        let header = secured.header_bytes();
        assert_eq!(header.len(), SECURED_MESSAGE_HEADER_SIZE);
        assert_eq!(&header[0..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(&header[4..6], &[0x01, 0x00]);
    }

    #[test]
    fn test_secured_message_parse() {
        let header = [0x78, 0x56, 0x34, 0x12, 0x01, 0x00];
        let secured = SecuredMessage::parse_header(&header).unwrap();
        assert_eq!(secured.session_id, 0x12345678);
        assert_eq!(secured.sequence_number, 1);
    }

    #[test]
    fn test_secured_message_parse_too_small() {
        let small = [0x78, 0x56, 0x34];
        assert!(SecuredMessage::parse_header(&small).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_message_aes128() {
        let mut session = setup_session();
        let plaintext = b"hello world";
        let aad = b"additional data";
        
        let encrypted = encrypt_message(&mut session, plaintext, aad).unwrap();
        assert!(encrypted.len() > plaintext.len());
        assert!(encrypted.len() > SECURED_MESSAGE_HEADER_SIZE);
        
        let mut session2 = setup_session();
        let decrypted = decrypt_message(&session2, &encrypted, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_message_aes256() {
        let mut session = setup_session_sha384();
        let plaintext = b"secure message test";
        let aad = b"aad";
        
        let encrypted = encrypt_message(&mut session, plaintext, aad).unwrap();
        
        let mut session2 = setup_session_sha384();
        let decrypted = decrypt_message(&session2, &encrypted, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_wrong_session_id() {
        let mut session = setup_session();
        let encrypted = encrypt_message(&mut session, b"test", b"aad").unwrap();
        
        let mut wrong_session = SessionInfo::new(0x99999999, HashAlgo::Sha256);
        wrong_session.set_state(SessionState::Established);
        wrong_session.set_encryption_key(vec![0xAA; 16]).unwrap();
        
        assert!(decrypt_message(&wrong_session, &encrypted, b"aad").is_err());
    }

    #[test]
    fn test_encrypt_not_established() {
        let mut session = SessionInfo::new(1, HashAlgo::Sha256);
        assert!(encrypt_message(&mut session, b"test", b"aad").is_err());
    }

    #[test]
    fn test_decrypt_not_established() {
        let mut session = setup_session();
        let encrypted = encrypt_message(&mut session, b"test", b"aad").unwrap();
        
        let mut not_established = SessionInfo::new(0x12345678, HashAlgo::Sha256);
        assert!(decrypt_message(&not_established, &encrypted, b"aad").is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad() {
        let mut session = setup_session();
        let encrypted = encrypt_message(&mut session, b"test", b"correct_aad").unwrap();
        
        let mut session2 = setup_session();
        assert!(decrypt_message(&session2, &encrypted, b"wrong_aad").is_err());
    }

    #[test]
    fn test_sequence_increment() {
        let mut session = setup_session();
        
        let enc1 = encrypt_message(&mut session, b"msg1", b"aad").unwrap();
        let enc2 = encrypt_message(&mut session, b"msg2", b"aad").unwrap();
        
        let header1 = SecuredMessage::parse_header(&enc1).unwrap();
        let header2 = SecuredMessage::parse_header(&enc2).unwrap();
        
        assert_eq!(header2.sequence_number, header1.sequence_number + 1);
    }

    #[test]
    fn test_iv_construction() {
        let iv = build_iv(0x123456789ABCDEF0);
        assert_eq!(iv.len(), AEAD_IV_SIZE);
        assert_eq!(&iv[0..4], &[0, 0, 0, 0]);
        assert_eq!(&iv[4..12], &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
    }
}