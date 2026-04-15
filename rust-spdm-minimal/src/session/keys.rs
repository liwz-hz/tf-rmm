use crate::error::{SpdmStatus, SpdmResult};
use crate::crypto::{hkdf_extract_sha256, hkdf_expand_sha256, hkdf_extract_sha384, hkdf_expand_sha384, SHA256_SIZE, SHA384_SIZE, sha256, sha384};
use alloc::vec::Vec;

const SPDM_VERSION_1_2: &[u8] = b"SPDM_VERSION_1.2";
const SPDM_SEQUENCE_NUMBER_INFO: &[u8] = b"sequence_number_info";
const SPDM_SEQUENCE_NUMBER_CONTEXT: &[u8] = b"sequence_number_context";
const SPDM_ENCRYPTION_INFO: &[u8] = b"encryption_info";
const SPDM_ENCRYPTION_CONTEXT: &[u8] = b"encryption_context";
const SPDM_MAC_INFO: &[u8] = b"mac_info";
const SPDM_MAC_CONTEXT: &[u8] = b"mac_context";

pub fn derive_master_secret(
    shared_secret: &[u8],
    is_sha384: bool,
) -> SpdmResult<Vec<u8>> {
    let salt = b"";
    if is_sha384 {
        hkdf_extract_sha384(salt, shared_secret)
    } else {
        hkdf_extract_sha256(salt, shared_secret)
    }
}

pub fn derive_encryption_key(
    master_secret: &[u8],
    transcript_hash: &[u8],
    is_requester: bool,
    is_sha384: bool,
) -> SpdmResult<Vec<u8>> {
    let label = if is_requester {
        "req_enc_key"
    } else {
        "rsp_enc_key"
    };
    
    let info = build_info(label, transcript_hash, is_sha384);
    let key_len = if is_sha384 { 32 } else { 16 };
    
    if is_sha384 {
        hkdf_expand_sha384(master_secret, &info, key_len)
    } else {
        hkdf_expand_sha256(master_secret, &info, key_len)
    }
}

pub fn derive_mac_key(
    master_secret: &[u8],
    transcript_hash: &[u8],
    is_requester: bool,
    is_sha384: bool,
) -> SpdmResult<Vec<u8>> {
    let label = if is_requester {
        "req_mac_key"
    } else {
        "rsp_mac_key"
    };
    
    let info = build_info(label, transcript_hash, is_sha384);
    let mac_len = if is_sha384 { SHA384_SIZE } else { SHA256_SIZE };
    
    if is_sha384 {
        hkdf_expand_sha384(master_secret, &info, mac_len)
    } else {
        hkdf_expand_sha256(master_secret, &info, mac_len)
    }
}

fn build_info(label: &str, transcript_hash: &[u8], is_sha384: bool) -> Vec<u8> {
    let hash_len = if is_sha384 { SHA384_SIZE } else { SHA256_SIZE };
    let mut info = Vec::with_capacity(label.len() + 2 + hash_len);
    
    info.extend_from_slice(&(hash_len as u16).to_le_bytes());
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.extend_from_slice(transcript_hash);
    
    info
}

pub fn compute_transcript_hash(
    messages: &[&[u8]],
    is_sha384: bool,
) -> SpdmResult<Vec<u8>> {
    let mut combined = Vec::new();
    for msg in messages {
        combined.extend_from_slice(msg);
    }
    
    if is_sha384 {
        sha384(&combined)
    } else {
        sha256(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_secret_sha256() {
        let shared = vec![0xAA; 32];
        let master = derive_master_secret(&shared, false).unwrap();
        assert_eq!(master.len(), SHA256_SIZE);
    }

    #[test]
    fn test_derive_master_secret_sha384() {
        let shared = vec![0xBB; 48];
        let master = derive_master_secret(&shared, true).unwrap();
        assert_eq!(master.len(), SHA384_SIZE);
    }

    #[test]
    fn test_derive_encryption_key_sha256() {
        let master = vec![0xCC; 32];
        let transcript = vec![0xDD; 32];
        
        let enc_key = derive_encryption_key(&master, &transcript, true, false).unwrap();
        assert_eq!(enc_key.len(), 16);
        
        let enc_key_rsp = derive_encryption_key(&master, &transcript, false, false).unwrap();
        assert_eq!(enc_key_rsp.len(), 16);
        assert_ne!(enc_key, enc_key_rsp);
    }

    #[test]
    fn test_derive_encryption_key_sha384() {
        let master = vec![0xCC; 48];
        let transcript = vec![0xDD; 48];
        
        let enc_key = derive_encryption_key(&master, &transcript, true, true).unwrap();
        assert_eq!(enc_key.len(), 32);
    }

    #[test]
    fn test_derive_mac_key_sha256() {
        let master = vec![0xEE; 32];
        let transcript = vec![0xFF; 32];
        
        let mac_key_req = derive_mac_key(&master, &transcript, true, false).unwrap();
        assert_eq!(mac_key_req.len(), SHA256_SIZE);
        
        let mac_key_rsp = derive_mac_key(&master, &transcript, false, false).unwrap();
        assert_eq!(mac_key_rsp.len(), SHA256_SIZE);
        assert_ne!(mac_key_req, mac_key_rsp);
    }

    #[test]
    fn test_derive_mac_key_sha384() {
        let master = vec![0xEE; 48];
        let transcript = vec![0xFF; 48];
        
        let mac_key = derive_mac_key(&master, &transcript, true, true).unwrap();
        assert_eq!(mac_key.len(), SHA384_SIZE);
    }

    #[test]
    fn test_compute_transcript_hash_sha256() {
        let msgs: &[&[u8]] = &[b"msg1", b"msg2"];
        let hash = compute_transcript_hash(msgs, false).unwrap();
        assert_eq!(hash.len(), SHA256_SIZE);
    }

    #[test]
    fn test_compute_transcript_hash_sha384() {
        let msgs: &[&[u8]] = &[b"msg1", b"msg2"];
        let hash = compute_transcript_hash(msgs, true).unwrap();
        assert_eq!(hash.len(), SHA384_SIZE);
    }

    #[test]
    fn test_different_transcript_different_key() {
        let master = vec![0xAA; 32];
        let transcript1 = vec![0x01; 32];
        let transcript2 = vec![0x02; 32];
        
        let key1 = derive_encryption_key(&master, &transcript1, true, false).unwrap();
        let key2 = derive_encryption_key(&master, &transcript2, true, false).unwrap();
        assert_ne!(key1, key2);
    }
}