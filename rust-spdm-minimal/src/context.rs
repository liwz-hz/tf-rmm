use alloc::boxed::Box;

pub const MAX_SESSIONS: usize = 4;
pub const MAX_HASH_SIZE: usize = 64;
pub const MAX_SPDM_MSG_SIZE: usize = 4096;
pub const TRANSCRIPT_A_SIZE: usize = 2048;
pub const SCRATCH_BUFFER_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ConnectionState {
    #[default]
    NotStarted = 0,
    AfterVersion = 1,
    AfterCapabilities = 2,
    Negotiated = 3,
    AfterDigests = 4,
    AfterCertificate = 5,
    Authenticated = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SessionState {
    #[default]
    NotStarted = 0,
    Handshaking = 1,
    Established = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmVersion {
    V10 = 0x10,
    V11 = 0x11,
    V12 = 0x12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HashAlgo {
    Sha256 = 0x00000001,
    Sha384 = 0x00000002,
    Sha512 = 0x00000004,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AeadSuite {
    Aes128Gcm = 0x00000001,
    Aes256Gcm = 0x00000002,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DheGroup {
    Secp256r1 = 0x00000001,
    Secp384r1 = 0x00000002,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NegotiatedInfo {
    pub version: SpdmVersion,
    pub hash_algo: HashAlgo,
    pub aead_suite: AeadSuite,
    pub dhe_group: DheGroup,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl Default for SpdmVersion {
    fn default() -> Self { SpdmVersion::V12 }
}

impl Default for HashAlgo {
    fn default() -> Self { HashAlgo::Sha256 }
}

impl Default for AeadSuite {
    fn default() -> Self { AeadSuite::Aes128Gcm }
}

impl Default for DheGroup {
    fn default() -> Self { DheGroup::Secp256r1 }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SessionInfo {
    pub session_id: u32,
    pub state: SessionState,
}

#[derive(Debug)]
#[repr(C)]
pub struct SpdmContext {
    pub connection_state: ConnectionState,
    pub negotiated_info: NegotiatedInfo,
    pub sessions: [SessionInfo; MAX_SESSIONS],
    pub transcript_a: Box<[u8; TRANSCRIPT_A_SIZE]>,
    pub transcript_a_len: usize,
    pub scratch_buffer: Box<[u8; SCRATCH_BUFFER_SIZE]>,
}

impl SpdmContext {
    pub fn new() -> Self {
        Self {
            connection_state: ConnectionState::NotStarted,
            negotiated_info: NegotiatedInfo::default(),
            sessions: [SessionInfo::default(); MAX_SESSIONS],
            transcript_a: Box::new([0u8; TRANSCRIPT_A_SIZE]),
            transcript_a_len: 0,
            scratch_buffer: Box::new([0u8; SCRATCH_BUFFER_SIZE]),
        }
    }

    pub fn get_hash_size(&self) -> usize {
        match self.negotiated_info.hash_algo {
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
        }
    }

    pub fn reset(&mut self) {
        self.connection_state = ConnectionState::NotStarted;
        self.transcript_a_len = 0;
        for session in &mut self.sessions {
            session.state = SessionState::NotStarted;
            session.session_id = 0;
        }
    }
}

impl Default for SpdmContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_init_success() {
        let ctx = SpdmContext::new();
        assert_eq!(ctx.connection_state, ConnectionState::NotStarted);
        assert_eq!(ctx.negotiated_info.version, SpdmVersion::V12);
        assert_eq!(ctx.sessions.len(), MAX_SESSIONS);
        assert_eq!(ctx.transcript_a_len, 0);
    }

    #[test]
    fn test_context_reset() {
        let mut ctx = SpdmContext::new();
        ctx.connection_state = ConnectionState::Negotiated;
        ctx.transcript_a_len = 100;
        ctx.sessions[0].session_id = 0x1234;
        ctx.sessions[0].state = SessionState::Established;
        
        ctx.reset();
        
        assert_eq!(ctx.connection_state, ConnectionState::NotStarted);
        assert_eq!(ctx.transcript_a_len, 0);
        assert_eq!(ctx.sessions[0].session_id, 0);
        assert_eq!(ctx.sessions[0].state, SessionState::NotStarted);
    }

    #[test]
    fn test_hash_size() {
        let ctx = SpdmContext::new();
        assert_eq!(ctx.get_hash_size(), 32);
        
        let mut ctx2 = SpdmContext::new();
        ctx2.negotiated_info.hash_algo = HashAlgo::Sha384;
        assert_eq!(ctx2.get_hash_size(), 48);
    }
}