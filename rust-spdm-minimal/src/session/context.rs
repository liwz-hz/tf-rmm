use crate::error::{SpdmStatus, SpdmResult};
use crate::crypto::{SHA256_SIZE, SHA384_SIZE};
use alloc::vec::Vec;

pub const MAX_SESSION_COUNT: usize = 8;
pub const MAX_KEY_SIZE: usize = SHA384_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    NotStarted,
    HandshakeInProgress,
    Established,
    Ended,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    session_id: u32,
    state: SessionState,
    master_secret: Vec<u8>,
    encryption_key: Vec<u8>,
    mac_key: Vec<u8>,
    sequence_number: u64,
    hash_algo: HashAlgo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha384,
}

impl SessionInfo {
    pub fn new(session_id: u32, hash_algo: HashAlgo) -> Self {
        let key_size = match hash_algo {
            HashAlgo::Sha256 => SHA256_SIZE,
            HashAlgo::Sha384 => SHA384_SIZE,
        };
        Self {
            session_id,
            state: SessionState::NotStarted,
            master_secret: Vec::new(),
            encryption_key: Vec::new(),
            mac_key: Vec::new(),
            sequence_number: 0,
            hash_algo,
        }
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    pub fn set_master_secret(&mut self, secret: Vec<u8>) -> SpdmResult<()> {
        if secret.len() != self.key_size() {
            return Err(SpdmStatus::InvalidParameter);
        }
        self.master_secret = secret;
        Ok(())
    }

    pub fn set_encryption_key(&mut self, key: Vec<u8>) -> SpdmResult<()> {
        self.encryption_key = key;
        Ok(())
    }

    pub fn set_mac_key(&mut self, key: Vec<u8>) -> SpdmResult<()> {
        self.mac_key = key;
        Ok(())
    }

    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }

    pub fn increment_sequence(&mut self) -> u64 {
        self.sequence_number += 1;
        self.sequence_number
    }

    pub fn key_size(&self) -> usize {
        match self.hash_algo {
            HashAlgo::Sha256 => SHA256_SIZE,
            HashAlgo::Sha384 => SHA384_SIZE,
        }
    }

    pub fn hash_algo(&self) -> HashAlgo {
        self.hash_algo
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    pub fn clear(&mut self) {
        self.master_secret.clear();
        self.encryption_key.clear();
        self.mac_key.clear();
        self.sequence_number = 0;
        self.state = SessionState::Ended;
    }
}

impl Drop for SessionInfo {
    fn drop(&mut self) {
        self.master_secret.clear();
        self.encryption_key.clear();
        self.mac_key.clear();
    }
}

pub struct SessionContext {
    sessions: Vec<SessionInfo>,
}

impl SessionContext {
    pub fn new() -> Self {
        Self {
            sessions: Vec::with_capacity(MAX_SESSION_COUNT),
        }
    }

    pub fn create_session(&mut self, session_id: u32, hash_algo: HashAlgo) -> SpdmResult<usize> {
        if self.sessions.len() >= MAX_SESSION_COUNT {
            return Err(SpdmStatus::BufferFull);
        }
        if self.find_session(session_id).is_some() {
            return Err(SpdmStatus::InvalidStateLocal);
        }
        let session = SessionInfo::new(session_id, hash_algo);
        self.sessions.push(session);
        Ok(self.sessions.len() - 1)
    }

    pub fn find_session(&self, session_id: u32) -> Option<usize> {
        self.sessions.iter().position(|s| s.session_id == session_id)
    }

    pub fn get_session(&mut self, index: usize) -> Option<&mut SessionInfo> {
        self.sessions.get_mut(index)
    }

    pub fn get_session_by_id(&mut self, session_id: u32) -> Option<&mut SessionInfo> {
        self.find_session(session_id).and_then(|i| self.sessions.get_mut(i))
    }

    pub fn remove_session(&mut self, session_id: u32) -> SpdmResult<()> {
        let index = self.find_session(session_id)
            .ok_or(SpdmStatus::InvalidParameter)?;
        self.sessions[index].clear();
        self.sessions.remove(index);
        Ok(())
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_info_creation() {
        let session = SessionInfo::new(0x12345678, HashAlgo::Sha256);
        assert_eq!(session.session_id(), 0x12345678);
        assert_eq!(session.state(), SessionState::NotStarted);
        assert_eq!(session.key_size(), SHA256_SIZE);
        assert!(!session.is_established());
    }

    #[test]
    fn test_session_state_transition() {
        let mut session = SessionInfo::new(1, HashAlgo::Sha384);
        session.set_state(SessionState::HandshakeInProgress);
        assert_eq!(session.state(), SessionState::HandshakeInProgress);

        session.set_state(SessionState::Established);
        assert!(session.is_established());
    }

    #[test]
    fn test_session_sequence_number() {
        let mut session = SessionInfo::new(1, HashAlgo::Sha256);
        assert_eq!(session.increment_sequence(), 1);
        assert_eq!(session.increment_sequence(), 2);
        assert_eq!(session.increment_sequence(), 3);
    }

    #[test]
    fn test_session_context_create() {
        let mut ctx = SessionContext::new();
        let idx = ctx.create_session(1, HashAlgo::Sha256).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(ctx.session_count(), 1);

        let idx2 = ctx.create_session(2, HashAlgo::Sha384).unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(ctx.session_count(), 2);
    }

    #[test]
    fn test_session_context_find() {
        let mut ctx = SessionContext::new();
        ctx.create_session(0xABCDEF01, HashAlgo::Sha256).unwrap();
        ctx.create_session(0xABCDEF02, HashAlgo::Sha384).unwrap();

        let idx = ctx.find_session(0xABCDEF01).unwrap();
        assert_eq!(idx, 0);

        let idx2 = ctx.find_session(0xABCDEF02).unwrap();
        assert_eq!(idx2, 1);

        assert!(ctx.find_session(0x99999999).is_none());
    }

    #[test]
    fn test_session_context_duplicate_id() {
        let mut ctx = SessionContext::new();
        ctx.create_session(1, HashAlgo::Sha256).unwrap();
        assert!(ctx.create_session(1, HashAlgo::Sha384).is_err());
    }

    #[test]
    fn test_session_context_max_sessions() {
        let mut ctx = SessionContext::new();
        for i in 0..MAX_SESSION_COUNT {
            ctx.create_session(i as u32, HashAlgo::Sha256).unwrap();
        }
        assert!(ctx.create_session(999, HashAlgo::Sha256).is_err());
    }

    #[test]
    fn test_session_context_remove() {
        let mut ctx = SessionContext::new();
        ctx.create_session(1, HashAlgo::Sha256).unwrap();
        ctx.create_session(2, HashAlgo::Sha256).unwrap();

        ctx.remove_session(1).unwrap();
        assert_eq!(ctx.session_count(), 1);
        assert!(ctx.find_session(1).is_none());
        assert!(ctx.find_session(2).is_some());
    }

    #[test]
    fn test_session_set_keys() {
        let mut session = SessionInfo::new(1, HashAlgo::Sha256);
        let master = vec![0xAA; SHA256_SIZE];
        session.set_master_secret(master.clone()).unwrap();
        
        session.set_encryption_key(vec![0xBB; 16]).unwrap();
        session.set_mac_key(vec![0xCC; SHA256_SIZE]).unwrap();

        assert_eq!(session.encryption_key(), &[0xBB; 16]);
        assert_eq!(session.mac_key(), &[0xCC; SHA256_SIZE]);
    }

    #[test]
    fn test_session_set_master_wrong_size() {
        let mut session = SessionInfo::new(1, HashAlgo::Sha256);
        let wrong_size = vec![0xAA; 16];
        assert!(session.set_master_secret(wrong_size).is_err());
    }
}