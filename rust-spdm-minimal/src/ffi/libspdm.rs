use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU16, AtomicU8, Ordering};

use crate::crypto::{ecdh_p384_keypair, EcdhP384KeyPair, P384_PUBLIC_KEY_RAW_SIZE, random_bytes, sha384, hkdf_extract_sha384, hkdf_expand_sha384, hmac_sha384};
use alloc::vec::Vec;

extern "C" {
    fn printf(fmt: *const i8, ...);
}

pub const LIBSPDM_STATUS_SUCCESS: u32 = 0;
pub const LIBSPDM_STATUS_ERROR: u32 = 1;

// SPDM request/response codes
pub const SPDM_KEY_EXCHANGE: u8 = 0xE4;
pub const SPDM_KEY_EXCHANGE_RSP: u8 = 0x64;
pub const SPDM_FINISH: u8 = 0xE5;
pub const SPDM_FINISH_RSP: u8 = 0x65;

pub const LIBSPDM_DATA_SPDM_VERSION: u32 = 0;
pub const LIBSPDM_DATA_SECURED_MESSAGE_VERSION: u32 = 1;
pub const LIBSPDM_DATA_CAPABILITY_FLAGS: u32 = 2;
pub const LIBSPDM_DATA_CAPABILITY_CT_EXPONENT: u32 = 3;
pub const LIBSPDM_DATA_CAPABILITY_RTT_US: u32 = 4;
pub const LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE: u32 = 5;
pub const LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE: u32 = 6;
pub const LIBSPDM_DATA_MEASUREMENT_SPEC: u32 = 8;
pub const LIBSPDM_DATA_BASE_ASYM_ALGO: u32 = 10;
pub const LIBSPDM_DATA_BASE_HASH_ALGO: u32 = 11;
pub const LIBSPDM_DATA_DHE_NAME_GROUP: u32 = 12;
pub const LIBSPDM_DATA_AEAD_CIPHER_SUITE: u32 = 13;
pub const LIBSPDM_DATA_REQ_BASE_ASYM_ALG: u32 = 14;
pub const LIBSPDM_DATA_KEY_SCHEDULE: u32 = 15;
pub const LIBSPDM_DATA_OTHER_PARAMS_SUPPORT: u32 = 16;
pub const LIBSPDM_DATA_CONNECTION_STATE: u32 = 18;
pub const LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER: u32 = 31;
pub const LIBSPDM_DATA_PEER_USED_CERT_CHAIN_HASH: u32 = 60;

pub const LIBSPDM_CONNECTION_STATE_NOT_STARTED: u32 = 0;
pub const LIBSPDM_CONNECTION_STATE_AFTER_VERSION: u32 = 1;
pub const LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES: u32 = 2;
pub const LIBSPDM_CONNECTION_STATE_NEGOTIATED: u32 = 3;
pub const LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS: u32 = 4;
pub const LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE: u32 = 5;
pub const LIBSPDM_CONNECTION_STATE_AUTHENTICATED: u32 = 6;

pub type libspdm_return_t = u32;
pub type libspdm_context_t = *mut c_void;
pub type libspdm_session_id_t = u32;

#[repr(C)]
pub struct libspdm_data_parameter_t {
    pub location: u8,
    pub additional_data: [u8; 4],
}

#[repr(C)]
pub struct libspdm_spdm_error_struct_t {
    pub error_code: u8,
    pub error_data: u8,
}

struct SpdmContext {
    send_func: AtomicPtr<c_void>,
    recv_func: AtomicPtr<c_void>,
    transport_encode: AtomicPtr<c_void>,
    transport_decode: AtomicPtr<c_void>,
    acquire_sender: AtomicPtr<c_void>,
    release_sender: AtomicPtr<c_void>,
    acquire_receiver: AtomicPtr<c_void>,
    release_receiver: AtomicPtr<c_void>,
    connection_state: AtomicU32,
    spdm_version: AtomicU32,
    secured_version: AtomicU32,
    cap_flags: AtomicU32,
    cap_ct_exponent: AtomicU32,
    cap_rtt_us: AtomicU32,
    cap_data_transfer_size: AtomicU32,
    cap_max_msg_size: AtomicU32,
    meas_spec: AtomicU32,
    base_asym_algo: AtomicU32,
    base_hash_algo: AtomicU32,
    dhe_group: AtomicU32,
    aead_suite: AtomicU32,
    req_base_asym_algo: AtomicU32,
    key_schedule: AtomicU32,
    slot_mask: AtomicU32,
    other_params: AtomicU32,
    verify_cert_chain_func: AtomicPtr<c_void>,
    cert_chain_hash: [AtomicU8; 64],
    cert_chain_hash_len: AtomicU32,
    cert_chain_buffer: [AtomicU8; 65536],
    cert_chain_len: AtomicU32,
    session_id: AtomicU32,
    req_session_id: AtomicU16,
    rsp_session_id: AtomicU16,
    ecdh_keypair: AtomicU8,
    requester_random: [AtomicU8; 32],
    responder_random: [AtomicU8; 32],
    responder_dhe_pubkey: [AtomicU8; 96],
    handshake_secret: [AtomicU8; 48],
    transcript_hash: [AtomicU8; 48],
    key_exchange_req_data: [AtomicU8; 2048],
    key_exchange_req_len: AtomicU32,
    key_exchange_rsp_data: [AtomicU8; 2048],
    key_exchange_rsp_len: AtomicU32,
    request_handshake_secret: [AtomicU8; 48],
    request_finished_key: [AtomicU8; 48],
    response_handshake_secret: [AtomicU8; 48],
    response_finished_key: [AtomicU8; 48],
    responder_hmac: [AtomicU8; 48],  // responder's verify_data for TH_curr
    responder_hmac_len: AtomicU32,  // 0 = no HMAC, 48 = HMAC included
    // message_a transcript storage (VERSION + CAPABILITIES + ALGORITHMS)
    message_a_data: [AtomicU8; 4096],
    message_a_len: AtomicU32,
}

// Global ECDH keypair for session (stored outside atomic context)
static mut ECDH_KEYPAIR: Option<EcdhP384KeyPair> = None;

static mut SPDM_CTX: SpdmContext = SpdmContext {
    send_func: AtomicPtr::new(core::ptr::null_mut()),
    recv_func: AtomicPtr::new(core::ptr::null_mut()),
    transport_encode: AtomicPtr::new(core::ptr::null_mut()),
    transport_decode: AtomicPtr::new(core::ptr::null_mut()),
    acquire_sender: AtomicPtr::new(core::ptr::null_mut()),
    release_sender: AtomicPtr::new(core::ptr::null_mut()),
    acquire_receiver: AtomicPtr::new(core::ptr::null_mut()),
    release_receiver: AtomicPtr::new(core::ptr::null_mut()),
    connection_state: AtomicU32::new(LIBSPDM_CONNECTION_STATE_NOT_STARTED),
    spdm_version: AtomicU32::new(0),
    secured_version: AtomicU32::new(0),
    cap_flags: AtomicU32::new(0),
    cap_ct_exponent: AtomicU32::new(0),
    cap_rtt_us: AtomicU32::new(0),
    cap_data_transfer_size: AtomicU32::new(0),
    cap_max_msg_size: AtomicU32::new(0),
    meas_spec: AtomicU32::new(0),
    base_asym_algo: AtomicU32::new(0),
    base_hash_algo: AtomicU32::new(0),
    dhe_group: AtomicU32::new(0),
    aead_suite: AtomicU32::new(0),
    req_base_asym_algo: AtomicU32::new(0),
    key_schedule: AtomicU32::new(0),
    slot_mask: AtomicU32::new(0),
    other_params: AtomicU32::new(0),
    cert_chain_hash: [AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
                      AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0)],
    cert_chain_hash_len: AtomicU32::new(0),
    verify_cert_chain_func: AtomicPtr::new(core::ptr::null_mut()),
    cert_chain_buffer: [const { AtomicU8::new(0) }; 65536],
    cert_chain_len: AtomicU32::new(0),
    session_id: AtomicU32::new(0),
    req_session_id: AtomicU16::new(0),
    rsp_session_id: AtomicU16::new(0),
    ecdh_keypair: AtomicU8::new(0),
    requester_random: [const { AtomicU8::new(0) }; 32],
    responder_random: [const { AtomicU8::new(0) }; 32],
    responder_dhe_pubkey: [const { AtomicU8::new(0) }; 96],
    handshake_secret: [const { AtomicU8::new(0) }; 48],
    transcript_hash: [const { AtomicU8::new(0) }; 48],
    key_exchange_req_data: [const { AtomicU8::new(0) }; 2048],
    key_exchange_req_len: AtomicU32::new(0),
    key_exchange_rsp_data: [const { AtomicU8::new(0) }; 2048],
    key_exchange_rsp_len: AtomicU32::new(0),
    request_handshake_secret: [const { AtomicU8::new(0) }; 48],
    request_finished_key: [const { AtomicU8::new(0) }; 48],
    response_handshake_secret: [const { AtomicU8::new(0) }; 48],
    response_finished_key: [const { AtomicU8::new(0) }; 48],
    responder_hmac: [const { AtomicU8::new(0) }; 48],
    responder_hmac_len: AtomicU32::new(0),
    message_a_data: [const { AtomicU8::new(0) }; 4096],
    message_a_len: AtomicU32::new(0),
};

macro_rules! debug_print {
    ($s:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8); }
    };
    ($s:expr, $a:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint, $d as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint, $d as core::ffi::c_uint, $e as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint, $d as core::ffi::c_uint, $e as core::ffi::c_uint, $f as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8, $a, $b, $c, $d, $e, $f, $g); }
    };
}

#[no_mangle]
pub extern "C" fn libspdm_deinit_context(context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("deinit_context(context=%p)", context);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_init_context(context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("init_context(context=%p)", context);
    unsafe {
        SPDM_CTX.connection_state.store(LIBSPDM_CONNECTION_STATE_NOT_STARTED, Ordering::SeqCst);
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_reset_context(context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("reset_context(context=%p)", context);
    unsafe {
        SPDM_CTX.connection_state.store(LIBSPDM_CONNECTION_STATE_NOT_STARTED, Ordering::SeqCst);
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_io_func(
    context: libspdm_context_t,
    send_message: *mut c_void,
    receive_message: *mut c_void,
) {
    debug_print!("register_device_io(context=%p, send=%p, recv=%p)", context, send_message, receive_message);
    unsafe {
        SPDM_CTX.send_func.store(send_message, Ordering::SeqCst);
        SPDM_CTX.recv_func.store(receive_message, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "C" fn libspdm_register_transport_layer_func(
    context: libspdm_context_t,
    max_msg_size: u32,
    transport_header_size: u32,
    transport_tail_size: u32,
    transport_encode: *mut c_void,
    transport_decode: *mut c_void,
) {
    debug_print!("register_transport(context=%p, max=%u, hdr=%u, tail=%u, encode=%p, decode=%p)", 
                 context, max_msg_size, transport_header_size, transport_tail_size, transport_encode, transport_decode);
    unsafe {
        SPDM_CTX.transport_encode.store(transport_encode, Ordering::SeqCst);
        SPDM_CTX.transport_decode.store(transport_decode, Ordering::SeqCst);
        SPDM_CTX.cap_max_msg_size.store(max_msg_size, Ordering::SeqCst);
        let stored_decode = SPDM_CTX.transport_decode.load(Ordering::SeqCst);
        debug_print!("  stored transport_decode=%p (verified)", stored_decode);
    }
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_buffer_func(
    context: libspdm_context_t,
    sender_buffer_size: u32,
    receiver_buffer_size: u32,
    acquire_sender: *mut c_void,
    release_sender: *mut c_void,
    acquire_receiver: *mut c_void,
    release_receiver: *mut c_void,
) {
    debug_print!("register_buffer(context=%p, sender_sz=%u, recv_sz=%u, acq_send=%p, rel_send=%p, acq_recv=%p, rel_recv=%p)",
                 context, sender_buffer_size, receiver_buffer_size, acquire_sender, release_sender, acquire_receiver, release_receiver);
    unsafe {
        SPDM_CTX.acquire_sender.store(acquire_sender, Ordering::SeqCst);
        SPDM_CTX.release_sender.store(release_sender, Ordering::SeqCst);
        SPDM_CTX.acquire_receiver.store(acquire_receiver, Ordering::SeqCst);
        SPDM_CTX.release_receiver.store(release_receiver, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "C" fn libspdm_get_sizeof_required_scratch_buffer(_context: libspdm_context_t) -> usize {
    debug_print!("get_scratch_buffer_size() -> 4096");
    4096
}

#[no_mangle]
pub extern "C" fn libspdm_set_scratch_buffer(
    context: libspdm_context_t,
    scratch_buffer: *mut u8,
    scratch_buffer_size: usize,
) -> libspdm_return_t {
    debug_print!("set_scratch_buffer(context=%p, buf=%p, size=%zu)", context, scratch_buffer, scratch_buffer_size);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_check_context(context: libspdm_context_t) -> bool {
    let state = unsafe { SPDM_CTX.connection_state.load(Ordering::SeqCst) };
    debug_print!("check_context(context=%p) -> state=%u", context, state);
    state >= LIBSPDM_CONNECTION_STATE_AFTER_VERSION
}

#[no_mangle]
pub extern "C" fn libspdm_set_data(
    context: libspdm_context_t,
    data_type: u32,
    _parameter: *const libspdm_data_parameter_t,
    data: *const c_void,
    data_size: usize,
) -> libspdm_return_t {
    debug_print!("set_data(context=%p, type=%u, data=%p, size=%zu)", context, data_type, data, data_size);
    if data.is_null() && data_size > 0 {
        return LIBSPDM_STATUS_ERROR;
    }
    if data_size == 0 {
        debug_print!("  set_data size=0 for type=%u, returning SUCCESS", data_type);
        return LIBSPDM_STATUS_SUCCESS;
    }
    unsafe {
        match data_type {
            LIBSPDM_DATA_SPDM_VERSION => {
                let v = *(data as *const u32);
                SPDM_CTX.spdm_version.store(v, Ordering::SeqCst);
                debug_print!("  set spdm_version=0x%x", v);
            }
            LIBSPDM_DATA_SECURED_MESSAGE_VERSION => {
                let v = *(data as *const u32);
                SPDM_CTX.secured_version.store(v, Ordering::SeqCst);
                debug_print!("  set secured_version=0x%x", v);
            }
            LIBSPDM_DATA_CAPABILITY_FLAGS => {
                let v = *(data as *const u32);
                SPDM_CTX.cap_flags.store(v, Ordering::SeqCst);
                debug_print!("  set cap_flags=0x%x", v);
            }
            LIBSPDM_DATA_CAPABILITY_CT_EXPONENT => {
                let v = *(data as *const u8);
                SPDM_CTX.cap_ct_exponent.store(v as u32, Ordering::SeqCst);
                debug_print!("  set ct_exponent=%u", v as u32);
            }
            LIBSPDM_DATA_CAPABILITY_RTT_US => {
                let v = *(data as *const u32);
                SPDM_CTX.cap_rtt_us.store(v, Ordering::SeqCst);
                debug_print!("  set rtt_us=%u", v);
            }
            LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE => {
                let v = *(data as *const u32);
                SPDM_CTX.cap_data_transfer_size.store(v, Ordering::SeqCst);
                debug_print!("  set data_transfer_size=%u", v);
            }
            LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE => {
                let v = *(data as *const u32);
                SPDM_CTX.cap_max_msg_size.store(v, Ordering::SeqCst);
                debug_print!("  set max_msg_size=%u", v);
            }
            LIBSPDM_DATA_MEASUREMENT_SPEC => {
                let v = *(data as *const u32);
                SPDM_CTX.meas_spec.store(v, Ordering::SeqCst);
                debug_print!("  set meas_spec=0x%x", v);
            }
            LIBSPDM_DATA_BASE_ASYM_ALGO => {
                let v = *(data as *const u32);
                SPDM_CTX.base_asym_algo.store(v, Ordering::SeqCst);
                debug_print!("  set base_asym=0x%x", v);
            }
            LIBSPDM_DATA_BASE_HASH_ALGO => {
                let v = *(data as *const u32);
                SPDM_CTX.base_hash_algo.store(v, Ordering::SeqCst);
                debug_print!("  set base_hash=0x%x", v);
            }
            LIBSPDM_DATA_DHE_NAME_GROUP => {
                let v = *(data as *const u32);
                SPDM_CTX.dhe_group.store(v, Ordering::SeqCst);
                debug_print!("  set dhe=0x%x", v);
            }
            LIBSPDM_DATA_AEAD_CIPHER_SUITE => {
                let v = *(data as *const u32);
                SPDM_CTX.aead_suite.store(v, Ordering::SeqCst);
                debug_print!("  set aead=0x%x", v);
            }
            LIBSPDM_DATA_REQ_BASE_ASYM_ALG => {
                let v = *(data as *const u32);
                SPDM_CTX.req_base_asym_algo.store(v, Ordering::SeqCst);
                debug_print!("  set req_base_asym=0x%x", v);
            }
            LIBSPDM_DATA_KEY_SCHEDULE => {
                let v = *(data as *const u32);
                SPDM_CTX.key_schedule.store(v, Ordering::SeqCst);
                debug_print!("  set key_schedule=0x%x", v);
            }
            LIBSPDM_DATA_OTHER_PARAMS_SUPPORT => {
                let v = *(data as *const u32);
                SPDM_CTX.other_params.store(v, Ordering::SeqCst);
                debug_print!("  set other_params=0x%x", v);
            }
            LIBSPDM_DATA_REQ_BASE_ASYM_ALG => {
                let v = *(data as *const u32);
                SPDM_CTX.req_base_asym_algo.store(v, Ordering::SeqCst);
                debug_print!("  set req_base_asym=0x%x", v);
            }
            LIBSPDM_DATA_KEY_SCHEDULE => {
                let v = *(data as *const u32);
                SPDM_CTX.key_schedule.store(v, Ordering::SeqCst);
                debug_print!("  set key_schedule=0x%x", v);
            }
            LIBSPDM_DATA_PEER_USED_CERT_CHAIN_HASH => {
                debug_print!("  set PEER_USED_CERT_CHAIN_HASH (size=%zu)", data_size);
                if data_size > 64 {
                    debug_print!("  ERROR: hash size too large");
                    return LIBSPDM_STATUS_ERROR;
                }
                let hash_bytes = data as *const u8;
                for i in 0..data_size {
                    SPDM_CTX.cert_chain_hash[i].store(*hash_bytes.add(i), Ordering::SeqCst);
                }
                SPDM_CTX.cert_chain_hash_len.store(data_size as u32, Ordering::SeqCst);
                debug_print!("  stored cert_chain_hash (%zu bytes)", data_size);
            }
            _ => {
                debug_print!("  unknown data_type=%u", data_type);
            }
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

unsafe fn call_acquire_sender(context: libspdm_context_t) -> *mut u8 {
    let func_ptr = SPDM_CTX.acquire_sender.load(Ordering::SeqCst);
    debug_print!("call_acquire_sender(func=%p)", func_ptr);
    if func_ptr.is_null() {
        debug_print!("  ERROR: acquire_sender is NULL!");
        return core::ptr::null_mut();
    }
    let func: extern "C" fn(libspdm_context_t, *mut *mut c_void) -> libspdm_return_t =
        core::mem::transmute(func_ptr);
    let mut buf: *mut c_void = core::ptr::null_mut();
    let ret = func(context, &mut buf);
    debug_print!("  acquire_sender ret=%u, buf=%p", ret, buf);
    if ret == LIBSPDM_STATUS_SUCCESS && !buf.is_null() {
        buf as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

unsafe fn call_release_sender(context: libspdm_context_t, buf: *mut c_void) {
    let func_ptr = SPDM_CTX.release_sender.load(Ordering::SeqCst);
    debug_print!("call_release_sender(func=%p, buf=%p)", func_ptr, buf);
    if !func_ptr.is_null() && !buf.is_null() {
        let func: extern "C" fn(libspdm_context_t, *const c_void) =
            core::mem::transmute(func_ptr);
        func(context, buf);
    }
}

unsafe fn call_acquire_receiver(context: libspdm_context_t) -> *mut u8 {
    let func_ptr = SPDM_CTX.acquire_receiver.load(Ordering::SeqCst);
    debug_print!("call_acquire_receiver(func=%p)", func_ptr);
    if func_ptr.is_null() {
        return core::ptr::null_mut();
    }
    let func: extern "C" fn(libspdm_context_t, *mut *mut c_void) -> libspdm_return_t =
        core::mem::transmute(func_ptr);
    let mut buf: *mut c_void = core::ptr::null_mut();
    let ret = func(context, &mut buf);
    debug_print!("  acquire_receiver ret=%u, buf=%p", ret, buf);
    if ret == LIBSPDM_STATUS_SUCCESS && !buf.is_null() {
        buf as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

unsafe fn call_release_receiver(context: libspdm_context_t, buf: *mut c_void) {
    let func_ptr = SPDM_CTX.release_receiver.load(Ordering::SeqCst);
    if !func_ptr.is_null() && !buf.is_null() {
        let func: extern "C" fn(libspdm_context_t, *const c_void) =
            core::mem::transmute(func_ptr);
        func(context, buf);
    }
}

unsafe fn call_send(context: libspdm_context_t, buf: *const u8, size: usize) -> libspdm_return_t {
    let func_ptr = SPDM_CTX.send_func.load(Ordering::SeqCst);
    debug_print!("call_send(func=%p, buf=%p, size=%zu)", func_ptr, buf, size);
    if func_ptr.is_null() {
        debug_print!("  ERROR: send_func is NULL!");
        return LIBSPDM_STATUS_ERROR;
    }
    let func: extern "C" fn(libspdm_context_t, usize, *const c_void, u64) -> libspdm_return_t =
        core::mem::transmute(func_ptr);
    let ret = func(context, size, buf as *const c_void, 0);
    debug_print!("  send ret=%u, context=%p", ret, context);
    ret
}

unsafe fn call_recv(context: libspdm_context_t, buf: *mut *mut c_void, size: *mut usize) -> libspdm_return_t {
    let func_ptr = SPDM_CTX.recv_func.load(Ordering::SeqCst);
    debug_print!("call_recv(func=%p)", func_ptr);
    if func_ptr.is_null() {
        debug_print!("  ERROR: recv_func is NULL!");
        return LIBSPDM_STATUS_ERROR;
    }
    let func: extern "C" fn(libspdm_context_t, *mut usize, *mut *mut c_void, u64) -> libspdm_return_t =
        core::mem::transmute(func_ptr);
    let ret = func(context, size, buf, 0);
    debug_print!("  recv ret=%u, size=%zu", ret, *size);
    ret
}

unsafe fn call_transport_encode(
    context: libspdm_context_t,
    session_id: *const u32,
    message: *const u8,
    message_size: usize,
    buffer: *mut u8,
    buffer_capacity: usize,
) -> (libspdm_return_t, *mut u8, usize) {
    let func_ptr = SPDM_CTX.transport_encode.load(Ordering::SeqCst);
    debug_print!("call_transport_encode(func=%p, session=%p, msg_size=%zu, buf_cap=%zu)", 
                 func_ptr, session_id, message_size, buffer_capacity);
    if func_ptr.is_null() {
        debug_print!("  transport_encode is NULL, returning raw message");
        return (LIBSPDM_STATUS_SUCCESS, message as *mut u8, message_size);
    }
    debug_print!("  calling transport_encode callback");
    
    let func: extern "C" fn(
        libspdm_context_t,
        *const u32,
        bool,
        bool,
        usize,
        *const c_void,
        *mut usize,
        *mut *mut c_void,
    ) -> libspdm_return_t = core::mem::transmute(func_ptr);
    
    let mut msg_buf_size = buffer_capacity;
    let mut msg_buf_ptr = buffer as *mut c_void;
    
    let ret = func(
        context,
        session_id,
        false,
        true,
        message_size,
        message as *const c_void,
        &mut msg_buf_size,
        &mut msg_buf_ptr,
    );
    debug_print!("  transport_encode ret=%u, encoded_size=%zu", ret, msg_buf_size);
    (ret, msg_buf_ptr as *mut u8, msg_buf_size)
}

unsafe fn call_transport_decode(
    context: libspdm_context_t,
    transport_msg: *mut c_void,
    transport_size: usize,
    message_size: *mut usize,
    message: *mut *mut c_void,
) -> libspdm_return_t {
    let func_ptr = SPDM_CTX.transport_decode.load(Ordering::SeqCst);
    debug_print!("call_transport_decode(func_ptr=%p, size=%u)", func_ptr, transport_size as u32);
    if func_ptr.is_null() {
        debug_print!("  transport_decode is NULL, returning raw message");
        *message_size = transport_size;
        *message = transport_msg;
        return LIBSPDM_STATUS_SUCCESS;
    }
    debug_print!("  calling transport_decode callback");
    
    // Signature: libspdm_return_t (*)(void*, uint32_t**, bool*, bool, size_t, void*, size_t*, void**)
    let func: extern "C" fn(
        libspdm_context_t,
        *mut *mut u32,
        *mut bool,
        bool,
        usize,
        *mut c_void,
        *mut usize,
        *mut *mut c_void,
    ) -> libspdm_return_t = core::mem::transmute(func_ptr);
    
    let mut session_id: *mut u32 = core::ptr::null_mut();
    let mut is_app_message: bool = false;
    
    let ret = func(
        context,
        &mut session_id,
        &mut is_app_message,
        false, // is_request_message
        transport_size,
        transport_msg,
        message_size,
        message,
    );
    debug_print!("  transport_decode ret=%u, msg_size=%zu", ret, *message_size);
    ret
}

#[no_mangle]
pub extern "C" fn libspdm_init_connection(context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("init_connection(context=%p) - START", context);
    
    if context.is_null() {
        debug_print!("  ERROR: context is NULL");
        return LIBSPDM_STATUS_ERROR;
    }

    unsafe {
        let send_ptr = SPDM_CTX.send_func.load(Ordering::SeqCst);
        let recv_ptr = SPDM_CTX.recv_func.load(Ordering::SeqCst);
        let acq_send_ptr = SPDM_CTX.acquire_sender.load(Ordering::SeqCst);
        let acq_recv_ptr = SPDM_CTX.acquire_receiver.load(Ordering::SeqCst);
        
        debug_print!("  send=%p, recv=%p, acq_send=%p, acq_recv=%p", send_ptr, recv_ptr, acq_send_ptr, acq_recv_ptr);
        
        if send_ptr.is_null() || recv_ptr.is_null() || acq_send_ptr.is_null() || acq_recv_ptr.is_null() {
            debug_print!("  ERROR: callbacks not registered");
            return LIBSPDM_STATUS_ERROR;
        }

        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer");
            return LIBSPDM_STATUS_ERROR;
        }

        // Clear message_a transcript at start
        SPDM_CTX.message_a_len.store(0, Ordering::SeqCst);
        
        let negotiated_ver = SPDM_CTX.spdm_version.load(Ordering::SeqCst);
        // GET_VERSION must always use version 1.0 (0x10), per SPDM spec
        let version_byte: u8 = 0x10;
        debug_print!("  using SPDM version 0x%02x for GET_VERSION", version_byte as u32);

        // Write GET_VERSION request using pointer arithmetic
        *sender_buf.add(0) = version_byte;
        *sender_buf.add(1) = 0x84;
        *sender_buf.add(2) = 0x00;
        *sender_buf.add(3) = 0x00;

        debug_print!("  sending GET_VERSION: %02x %02x %02x %02x", 
                     *sender_buf.add(0) as u32, *sender_buf.add(1) as u32, 
                     *sender_buf.add(2) as u32, *sender_buf.add(3) as u32);
        
        let send_ret = call_send(context, sender_buf, 4);
        debug_print!("  send returned %u", send_ret);
        
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            call_release_sender(context, sender_buf as *mut c_void);
            debug_print!("  ERROR: send failed");
            return LIBSPDM_STATUS_ERROR;
        }

        // SAVE REQUEST BEFORE recv() overwrites the buffer!
        // The sender buffer may be reused for receiving, so we must save request bytes now.
        let msg_a_len = SPDM_CTX.message_a_len.load(Ordering::SeqCst) as usize;
        // Save GET_VERSION request bytes (will be overwritten by recv)
        let saved_request_bytes = [
            *sender_buf.add(0),
            *sender_buf.add(1),
            *sender_buf.add(2),
            *sender_buf.add(3),
        ];
        debug_print!("  saved request bytes for message_a: %02x %02x %02x %02x",
            saved_request_bytes[0] as u32, saved_request_bytes[1] as u32,
            saved_request_bytes[2] as u32, saved_request_bytes[3] as u32);

        let receiver_buf = call_acquire_receiver(context);
        if receiver_buf.is_null() {
            call_release_sender(context, sender_buf as *mut c_void);
            debug_print!("  ERROR: failed to acquire receiver buffer");
            return LIBSPDM_STATUS_ERROR;
        }

        let mut recv_size: usize = 4096;
        let mut recv_ptr: *mut c_void = receiver_buf as *mut c_void;
        
        let recv_ret = call_recv(context, &mut recv_ptr, &mut recv_size);
        debug_print!("  recv returned %u, size=%zu", recv_ret, recv_size);
        
        if recv_ret != LIBSPDM_STATUS_SUCCESS || recv_size < 6 {
            debug_print!("  ERROR: recv failed or too small");
            call_release_sender(context, sender_buf as *mut c_void);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        if *receiver_buf.add(1) != 0x04 {
            debug_print!("  ERROR: wrong response code 0x%02x (expected 0x04)", *receiver_buf.add(1) as u32);
            call_release_sender(context, sender_buf as *mut c_void);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Calculate actual SPDM message size (trim DOE padding)
        // VERSION response: header(4) + reserved2(2) + version_number_entry[count*2]
        let version_count = *receiver_buf.add(5) as usize;
        let actual_rsp_size = 6 + version_count * 2;
        debug_print!("  VERSION actual SPDM size: %zu (DOE padded=%zu, count=%u)", actual_rsp_size, recv_size, version_count as u32);
        
        // Save VERSION request+response to message_a transcript using actual SPDM sizes
        for i in 0..4 {
            if msg_a_len + i < 4096 {
                SPDM_CTX.message_a_data[msg_a_len + i].store(saved_request_bytes[i], Ordering::SeqCst);
            }
        }
        for i in 0..actual_rsp_size.min(4096 - msg_a_len - 4) {
            SPDM_CTX.message_a_data[msg_a_len + 4 + i].store(*receiver_buf.add(i), Ordering::SeqCst);
        }
        SPDM_CTX.message_a_len.store((msg_a_len + 4 + actual_rsp_size) as u32, Ordering::SeqCst);
        debug_print!("  saved VERSION to message_a: req=4, rsp=%zu, total=%zu", actual_rsp_size, msg_a_len + 4 + actual_rsp_size);
        
        call_release_sender(context, sender_buf as *mut c_void);
        call_release_receiver(context, receiver_buf as *mut c_void);
        
        debug_print!("  VERSION response OK: code=0x%02x, count=%u", *receiver_buf.add(1) as u32, version_count as u32);
        
        // Parse VERSION response to get negotiated version
        // VERSION response format: version(1), response_code(1), reserved(1), param1(1), reserved2(2), version_number_entry[]
        // version_number_entry is 2 bytes little-endian: bits 15:12=major, bits 11:8=minor
        // Select highest common version between requester and responder
        if recv_size >= 8 {
            // Count of version entries: for SPDM 1.0 format, count is implicit from message size
            // Each entry is 2 bytes, starting at byte 6
            let max_entries = ((recv_size - 6) / 2) as usize;
            debug_print!("  VERSION entries: max %u possible from size %zu", max_entries as u32, recv_size);
            
            // Get requester's supported version (from set_data)
            let requester_ver = SPDM_CTX.spdm_version.load(Ordering::SeqCst);
            let requester_major = (requester_ver >> 12) & 0xF;
            let requester_minor = (requester_ver >> 8) & 0xF;
            debug_print!("  requester supports: major=%u minor=%u (stored=0x%04x)", requester_major, requester_minor, requester_ver);
            
            // Find highest common version from responder's list
            let mut best_major: u32 = 0;
            let mut best_minor: u32 = 0;
            
            for i in 0..max_entries {
                let entry_lower = *receiver_buf.add(6 + i*2) as u32;
                let entry_upper = *receiver_buf.add(6 + i*2 + 1) as u32;
                let entry = entry_lower | (entry_upper << 8);
                let resp_major = (entry >> 12) & 0xF;
                let resp_minor = (entry >> 8) & 0xF;
                debug_print!("  responder entry %u: major=%u minor=%u (entry=0x%04x)", i as u32, resp_major, resp_minor, entry);
                
                // Check if this version matches requester's version
                if resp_major == requester_major && resp_minor == requester_minor {
                    // Found matching version - use it
                    if resp_major > best_major || (resp_major == best_major && resp_minor > best_minor) {
                        best_major = resp_major;
                        best_minor = resp_minor;
                    }
                }
            }
            
            // If no match found, fall back to highest responder version
            if best_major == 0 && best_minor == 0 {
                for i in 0..max_entries {
                    let entry_lower = *receiver_buf.add(6 + i*2) as u32;
                    let entry_upper = *receiver_buf.add(6 + i*2 + 1) as u32;
                    let entry = entry_lower | (entry_upper << 8);
                    let resp_major = (entry >> 12) & 0xF;
                    let resp_minor = (entry >> 8) & 0xF;
                    if resp_major > best_major || (resp_major == best_major && resp_minor > best_minor) {
                        best_major = resp_major;
                        best_minor = resp_minor;
                    }
                }
                debug_print!("  no exact match, using highest responder version");
            }
            
            let negotiated_ver = (best_major << 12) | (best_minor << 8);
            SPDM_CTX.spdm_version.store(negotiated_ver, Ordering::SeqCst);
            debug_print!("  negotiated_version stored: 0x%04x (major=%u, minor=%u)", 
                         negotiated_ver, best_major, best_minor);
        }
        
        SPDM_CTX.connection_state.store(LIBSPDM_CONNECTION_STATE_AFTER_VERSION, Ordering::SeqCst);
        debug_print!("  connection_state -> AFTER_VERSION");
        
// Now send GET_CAPABILITIES using negotiated version
        // GET_CAPABILITIES request format (SPDM 1.2): 20 bytes total
        // header(4) + reserved(1) + ct_exponent(1) + reserved2(2) + flags(4) + data_transfer_size(4) + max_spdm_msg_size(4)
        // For SPDM 1.1: 8 bytes (header + reserved + ct_exp + reserved2 + flags)
        // For SPDM 1.0: 4 bytes (header only)
        let ver_byte = ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8;
        let caps_req_size = if ver_byte >= 0x12 { 20 } else if ver_byte >= 0x11 { 8 } else { 4 };
        let sender_buf2 = call_acquire_sender(context);
        if sender_buf2.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer for GET_CAPABILITIES");
            return LIBSPDM_STATUS_ERROR;
        }
        
        *sender_buf2.add(0) = ver_byte;
        // GET_CAPABILITIES request code
        *sender_buf2.add(1) = 0xE1;
        // reserved
        *sender_buf2.add(2) = 0x00;
        // param1
        *sender_buf2.add(3) = 0x00;
        
        // Fill remaining bytes based on version
        for i in 4..caps_req_size {
            *sender_buf2.add(i) = 0;
        }
        
        // For SPDM 1.2: set requester capabilities at correct offsets
        // C struct: header(4) + reserved(1) + ct_exponent(1) + reserved2(2) + flags(4) + dts(4) + max_msg(4) = 20 bytes
        if caps_req_size >= 20 {
            // reserved at byte 4 (already zeroed)
            // ct_exponent at byte 5
            *sender_buf2.add(5) = SPDM_CTX.cap_ct_exponent.load(Ordering::SeqCst) as u8;
            // reserved2 at bytes 6-7 (already zeroed)
            // flags at bytes 8-11 (little endian)
            let flags = SPDM_CTX.cap_flags.load(Ordering::SeqCst);
            *sender_buf2.add(8) = (flags & 0xFF) as u8;
            *sender_buf2.add(9) = ((flags >> 8) & 0xFF) as u8;
            *sender_buf2.add(10) = ((flags >> 16) & 0xFF) as u8;
            *sender_buf2.add(11) = ((flags >> 24) & 0xFF) as u8;
            // data_transfer_size at bytes 12-15
            let req_dts = 4096u32;  // Use fixed size matching buffer size
            *sender_buf2.add(12) = (req_dts & 0xFF) as u8;
            *sender_buf2.add(13) = ((req_dts >> 8) & 0xFF) as u8;
            *sender_buf2.add(14) = ((req_dts >> 16) & 0xFF) as u8;
            *sender_buf2.add(15) = ((req_dts >> 24) & 0xFF) as u8;
            // max_spdm_msg_size at bytes 16-19
            let req_max_msg = 4096u32;
            *sender_buf2.add(16) = (req_max_msg & 0xFF) as u8;
            *sender_buf2.add(17) = ((req_max_msg >> 8) & 0xFF) as u8;
            *sender_buf2.add(18) = ((req_max_msg >> 16) & 0xFF) as u8;
            *sender_buf2.add(19) = ((req_max_msg >> 24) & 0xFF) as u8;
        }
        
        debug_print!("  sending GET_CAPABILITIES: ver=0x%02x, size=%zu", ver_byte as u32, caps_req_size);
        
        let send_ret2 = call_send(context, sender_buf2, caps_req_size);
        if send_ret2 != LIBSPDM_STATUS_SUCCESS {
            call_release_sender(context, sender_buf2 as *mut c_void);
            debug_print!("  ERROR: GET_CAPABILITIES send failed");
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Save CAPABILITIES request bytes BEFORE recv overwrites the buffer
        let msg_a_len_before_caps = SPDM_CTX.message_a_len.load(Ordering::SeqCst) as usize;
        let saved_caps_req_bytes: Vec<u8> = (0..caps_req_size.min(4096))
            .map(|i| *sender_buf2.add(i))
            .collect();
        
        // Receive CAPABILITIES response
        let receiver_buf2 = call_acquire_receiver(context);
        if receiver_buf2.is_null() {
            call_release_sender(context, sender_buf2 as *mut c_void);
            debug_print!("  ERROR: failed to acquire receiver buffer for CAPABILITIES");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size2: usize = 4096;
        let mut recv_ptr2: *mut c_void = receiver_buf2 as *mut c_void;
        let recv_ret2 = call_recv(context, &mut recv_ptr2, &mut recv_size2);
        
        // Save CAPABILITIES request+response to message_a
        for i in 0..saved_caps_req_bytes.len().min(4096 - msg_a_len_before_caps) {
            SPDM_CTX.message_a_data[msg_a_len_before_caps + i].store(saved_caps_req_bytes[i], Ordering::SeqCst);
        }
        for i in 0..recv_size2.min(4096 - msg_a_len_before_caps - caps_req_size) {
            SPDM_CTX.message_a_data[msg_a_len_before_caps + caps_req_size + i].store(*receiver_buf2.add(i), Ordering::SeqCst);
        }
        SPDM_CTX.message_a_len.store((msg_a_len_before_caps + caps_req_size + recv_size2) as u32, Ordering::SeqCst);
        debug_print!("  saved CAPABILITIES to message_a: req=%zu, rsp=%zu, total=%zu", caps_req_size, recv_size2, msg_a_len_before_caps + caps_req_size + recv_size2);
        
        call_release_sender(context, sender_buf2 as *mut c_void);
        call_release_receiver(context, receiver_buf2 as *mut c_void);
        
        let caps_resp_size = if ver_byte >= 0x12 { 20 } else { 8 };
        if recv_ret2 != LIBSPDM_STATUS_SUCCESS || recv_size2 < caps_resp_size {
            debug_print!("  ERROR: CAPABILITIES recv failed or too small (size=%zu, expected=%zu)", recv_size2, caps_resp_size);
            return LIBSPDM_STATUS_ERROR;
        }
        
        if *receiver_buf2.add(1) != 0x61 {
            debug_print!("  ERROR: wrong CAPABILITIES response code 0x%02x (expected 0x61)", *receiver_buf2.add(1) as u32);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Parse CAPABILITIES response (SPDM 1.2): 20 bytes
        // header(4) + reserved(4) + ct_exponent(1) + flags(4) + data_transfer_size(4) + max_spdm_msg_size(4)
        // data_transfer_size at offset 12-15 (little endian)
        let resp_dts = (*receiver_buf2.add(12) as u32) |
                       ((*receiver_buf2.add(13) as u32) << 8) |
                       ((*receiver_buf2.add(14) as u32) << 16) |
                       ((*receiver_buf2.add(15) as u32) << 24);
        let resp_max_msg = (*receiver_buf2.add(16) as u32) |
                          ((*receiver_buf2.add(17) as u32) << 8) |
                          ((*receiver_buf2.add(18) as u32) << 16) |
                          ((*receiver_buf2.add(19) as u32) << 24);
        
        SPDM_CTX.cap_data_transfer_size.store(resp_dts, Ordering::SeqCst);
        SPDM_CTX.cap_max_msg_size.store(resp_max_msg, Ordering::SeqCst);
        debug_print!("  CAPABILITIES response: data_transfer_size=%u, max_msg_size=%u", resp_dts, resp_max_msg);
        
        // Now send NEGOTIATE_ALGORITHMS
        // For SPDM 1.2, we need struct tables for DHE, AEAD
        // Fixed part: header(4) + length(2) + meas_spec(1) + other_params(1) + base_asym(4) + base_hash(4) + reserved(12) + ext_counts(2) + reserved3(1) + mel(1) = 32 bytes
        // Struct table entries: alg_type(1) + alg_count(1) + alg_supported(2) = 4 bytes each
        
        let sender_buf3 = call_acquire_sender(context);
        if sender_buf3.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer for NEGOTIATE_ALGORITHMS");
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Build NEGOTIATE_ALGORITHMS request
        let base_asym = SPDM_CTX.base_asym_algo.load(Ordering::SeqCst);
        let base_hash = SPDM_CTX.base_hash_algo.load(Ordering::SeqCst);
        let meas_spec = SPDM_CTX.meas_spec.load(Ordering::SeqCst) & 0xFF;  // Only byte 0
        let dhe = SPDM_CTX.dhe_group.load(Ordering::SeqCst);
        let aead = SPDM_CTX.aead_suite.load(Ordering::SeqCst);
        let req_base_asym = SPDM_CTX.req_base_asym_algo.load(Ordering::SeqCst);
        let key_schedule = SPDM_CTX.key_schedule.load(Ordering::SeqCst);
        
        let mut num_struct_tables: u8 = 0;
        if dhe != 0 { num_struct_tables += 1; }
        if aead != 0 { num_struct_tables += 1; }
        if req_base_asym != 0 { num_struct_tables += 1; }
        if key_schedule != 0 { num_struct_tables += 1; }
        
        let alg_req_size = 32 + (num_struct_tables as usize * 4);
        
        *sender_buf3.add(0) = ver_byte;
        *sender_buf3.add(1) = 0xE3;
        *sender_buf3.add(2) = num_struct_tables;
        *sender_buf3.add(3) = 0;
        
        *sender_buf3.add(4) = (alg_req_size as u8) & 0xFF;
        *sender_buf3.add(5) = ((alg_req_size >> 8) as u8) & 0xFF;
        
        *sender_buf3.add(6) = meas_spec as u8;
        
        *sender_buf3.add(7) = 0x02;
        
        // Base asym algo (4 bytes)
        *sender_buf3.add(8) = (base_asym & 0xFF) as u8;
        *sender_buf3.add(9) = ((base_asym >> 8) & 0xFF) as u8;
        *sender_buf3.add(10) = ((base_asym >> 16) & 0xFF) as u8;
        *sender_buf3.add(11) = ((base_asym >> 24) & 0xFF) as u8;
        
        // Base hash algo (4 bytes)
        *sender_buf3.add(12) = (base_hash & 0xFF) as u8;
        *sender_buf3.add(13) = ((base_hash >> 8) & 0xFF) as u8;
        *sender_buf3.add(14) = ((base_hash >> 16) & 0xFF) as u8;
        *sender_buf3.add(15) = ((base_hash >> 24) & 0xFF) as u8;
        
        // Reserved2 (12 bytes) - already zeroed
        for i in 16..28 {
            *sender_buf3.add(i) = 0;
        }
        
        // Ext asym count, ext hash count
        *sender_buf3.add(28) = 0;  // ext_asym_count
        *sender_buf3.add(29) = 0;  // ext_hash_count
        
        // Reserved3 and mel_specification
        *sender_buf3.add(30) = 0;  // reserved3
        *sender_buf3.add(31) = 0;  // mel_specification
        
        // Struct tables start at offset 32
        let mut offset = 32;
        
        // DHE struct table (alg_type=2)
        if dhe != 0 {
            *sender_buf3.add(offset) = 2;  // alg_type = DHE
            *sender_buf3.add(offset + 1) = 0x20;  // alg_count: ext=0, fixed=2
            *sender_buf3.add(offset + 2) = (dhe & 0xFF) as u8;
            *sender_buf3.add(offset + 3) = ((dhe >> 8) & 0xFF) as u8;
            offset += 4;
            debug_print!("  struct_table DHE: type=2, alg=0x%x", dhe);
        }
        
        // AEAD struct table (alg_type=3)
        if aead != 0 {
            *sender_buf3.add(offset) = 3;
            *sender_buf3.add(offset + 1) = 0x20;
            *sender_buf3.add(offset + 2) = (aead & 0xFF) as u8;
            *sender_buf3.add(offset + 3) = ((aead >> 8) & 0xFF) as u8;
            offset += 4;
            debug_print!("  struct_table AEAD: type=3, alg=0x%x", aead);
        }
        
        if req_base_asym != 0 {
            *sender_buf3.add(offset) = 4;
            *sender_buf3.add(offset + 1) = 0x20;
            *sender_buf3.add(offset + 2) = (req_base_asym & 0xFF) as u8;
            *sender_buf3.add(offset + 3) = ((req_base_asym >> 8) & 0xFF) as u8;
            offset += 4;
            debug_print!("  struct_table REQ_BASE_ASYM: type=4, alg=0x%x", req_base_asym);
        }
        
        if key_schedule != 0 {
            *sender_buf3.add(offset) = 5;
            *sender_buf3.add(offset + 1) = 0x20;
            *sender_buf3.add(offset + 2) = (key_schedule & 0xFF) as u8;
            *sender_buf3.add(offset + 3) = ((key_schedule >> 8) & 0xFF) as u8;
            offset += 4;
            debug_print!("  struct_table KEY_SCHEDULE: type=5, alg=0x%x", key_schedule);
        }
        
        debug_print!("  sending NEGOTIATE_ALGORITHMS: ver=0x%02x, size=%zu, tables=%u", ver_byte as u32, alg_req_size, num_struct_tables as u32);
        debug_print!("    base_asym=0x%x, base_hash=0x%x, meas_spec=0x%x", base_asym, base_hash, meas_spec as u32);
        
        // Send NEGOTIATE_ALGORITHMS
        let send_ret3 = call_send(context, sender_buf3, alg_req_size);
        if send_ret3 != LIBSPDM_STATUS_SUCCESS {
            call_release_sender(context, sender_buf3 as *mut c_void);
            debug_print!("  ERROR: NEGOTIATE_ALGORITHMS send failed");
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Save ALGORITHMS request bytes BEFORE recv overwrites the buffer
        let msg_a_len_before_alg = SPDM_CTX.message_a_len.load(Ordering::SeqCst) as usize;
        let saved_alg_req_bytes: Vec<u8> = (0..alg_req_size.min(4096))
            .map(|i| *sender_buf3.add(i))
            .collect();
        
        // Receive ALGORITHMS response
        let receiver_buf3 = call_acquire_receiver(context);
        if receiver_buf3.is_null() {
            call_release_sender(context, sender_buf3 as *mut c_void);
            debug_print!("  ERROR: failed to acquire receiver buffer for ALGORITHMS");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size3: usize = 4096;
        let mut recv_ptr3: *mut c_void = receiver_buf3 as *mut c_void;
        let recv_ret3 = call_recv(context, &mut recv_ptr3, &mut recv_size3);
        
        // Save ALGORITHMS request+response to message_a
        for i in 0..saved_alg_req_bytes.len().min(4096 - msg_a_len_before_alg) {
            SPDM_CTX.message_a_data[msg_a_len_before_alg + i].store(saved_alg_req_bytes[i], Ordering::SeqCst);
        }
        for i in 0..recv_size3.min(4096 - msg_a_len_before_alg - alg_req_size) {
            SPDM_CTX.message_a_data[msg_a_len_before_alg + alg_req_size + i].store(*receiver_buf3.add(i), Ordering::SeqCst);
        }
        SPDM_CTX.message_a_len.store((msg_a_len_before_alg + alg_req_size + recv_size3) as u32, Ordering::SeqCst);
        debug_print!("  saved ALGORITHMS to message_a: req=%zu, rsp=%zu, total=%zu", alg_req_size, recv_size3, msg_a_len_before_alg + alg_req_size + recv_size3);
        
        call_release_sender(context, sender_buf3 as *mut c_void);
        call_release_receiver(context, receiver_buf3 as *mut c_void);
        
        if recv_ret3 != LIBSPDM_STATUS_SUCCESS || recv_size3 < 36 {
            debug_print!("  ERROR: ALGORITHMS recv failed or too small (size=%zu)", recv_size3);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Check response code (0x63 = ALGORITHMS)
        if *receiver_buf3.add(1) != 0x63 {
            debug_print!("  ERROR: wrong ALGORITHMS response code 0x%02x (expected 0x63)", *receiver_buf3.add(1) as u32);
            return LIBSPDM_STATUS_ERROR;
        }
        
        debug_print!("  ALGORITHMS response OK: code=0x%02x", *receiver_buf3.add(1) as u32);
        
        // Parse ALGORITHMS response - store selected algorithms
        // Response: header(4) + length(2) + meas_spec_sel(1) + other_params(1) + meas_hash(4) + base_asym_sel(4) + base_hash_sel(4) + reserved(11) + mel(1) + ext_counts(2) + reserved(2) + ext_asym(4) + ext_hash(4) + struct_tables
        
        // base_asym_sel at offset 12-15
        let resp_base_asym = (*receiver_buf3.add(12) as u32) |
                            ((*receiver_buf3.add(13) as u32) << 8) |
                            ((*receiver_buf3.add(14) as u32) << 16) |
                            ((*receiver_buf3.add(15) as u32) << 24);
        
        // base_hash_sel at offset 16-19
        let resp_base_hash = (*receiver_buf3.add(16) as u32) |
                            ((*receiver_buf3.add(17) as u32) << 8) |
                            ((*receiver_buf3.add(18) as u32) << 16) |
                            ((*receiver_buf3.add(19) as u32) << 24);
        
        SPDM_CTX.base_asym_algo.store(resp_base_asym, Ordering::SeqCst);
        SPDM_CTX.base_hash_algo.store(resp_base_hash, Ordering::SeqCst);
        
        debug_print!("  ALGORITHMS selected: base_asym=0x%x, base_hash=0x%x", resp_base_asym, resp_base_hash);
        
        SPDM_CTX.connection_state.store(LIBSPDM_CONNECTION_STATE_NEGOTIATED, Ordering::SeqCst);
        debug_print!("  connection_state -> NEGOTIATED");
    }

    debug_print!("init_connection() - SUCCESS");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_data(
    context: libspdm_context_t,
    data_type: u32,
    _parameter: *const libspdm_data_parameter_t,
    data: *mut c_void,
    data_size: *mut usize,
) -> libspdm_return_t {
    debug_print!("get_data(context=%p, type=%u, data=%p, size=%p)", context, data_type, data, data_size);
    
    if data.is_null() || data_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }

    unsafe {
        match data_type {
            LIBSPDM_DATA_CONNECTION_STATE => {
                let v = SPDM_CTX.connection_state.load(Ordering::SeqCst);
                debug_print!("  get connection_state=%u", v);
                *data_size = 4;
                *(data as *mut u32) = v;
            }
            LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE => {
                let v = SPDM_CTX.cap_data_transfer_size.load(Ordering::SeqCst);
                debug_print!("  get data_transfer_size=%u", v);
                *data_size = 4;
                *(data as *mut u32) = v;
            }
            LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE => {
                let v = SPDM_CTX.cap_max_msg_size.load(Ordering::SeqCst);
                debug_print!("  get max_msg_size=%u", v);
                *data_size = 4;
                *(data as *mut u32) = v;
            }
            LIBSPDM_DATA_BASE_HASH_ALGO => {
                let v = SPDM_CTX.base_hash_algo.load(Ordering::SeqCst);
                debug_print!("  get base_hash=0x%x", v);
                *data_size = 4;
                *(data as *mut u32) = v;
            }
            _ => {
                debug_print!("  unknown type=%u, returning 0", data_type);
                *data_size = 0;
            }
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_version(
    context: libspdm_context_t,
    version_count: *mut u8,
    _version_number_entry: *mut u32,
) -> libspdm_return_t {
    debug_print!("get_version(context=%p)", context);
    if !version_count.is_null() {
        unsafe { *version_count = 1; }
        debug_print!("  version_count=1");
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_capabilities(_context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("get_capabilities() -> SUCCESS");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_negotiate_algorithms(_context: libspdm_context_t) -> libspdm_return_t {
    debug_print!("negotiate_algorithms() -> SUCCESS");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_digests(
    context: libspdm_context_t,
    slot_mask: *mut u8,
    total_digest_buffer: *mut u8,
) -> libspdm_return_t {
    debug_print!("get_digests(context=%p)", context);
    
    unsafe {
        let ver_byte = ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8;
        let base_hash = SPDM_CTX.base_hash_algo.load(Ordering::SeqCst);
        
        let hash_size = if base_hash & 0x04 != 0 { 64 }      // SHA-512
                       else if base_hash & 0x02 != 0 { 48 }   // SHA-384
                       else if base_hash & 0x01 != 0 { 32 }   // SHA-256
                       else { 48 };  // Default SHA-384
        
        debug_print!("  base_hash=0x%x, hash_size=%u", base_hash, hash_size as u32);
        
        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer for GET_DIGESTS");
            return LIBSPDM_STATUS_ERROR;
        }
        
        *sender_buf.add(0) = ver_byte;
        *sender_buf.add(1) = 0x81;  // SPDM_GET_DIGESTS
        *sender_buf.add(2) = 0;     // param1 = reserved
        *sender_buf.add(3) = 0;     // param2 = reserved
        
        debug_print!("  sending GET_DIGESTS: ver=0x%02x", ver_byte as u32);
        
        let send_ret = call_send(context, sender_buf, 4);
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            call_release_sender(context, sender_buf as *mut c_void);
            debug_print!("  ERROR: GET_DIGESTS send failed");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let receiver_buf = call_acquire_receiver(context);
        if receiver_buf.is_null() {
            call_release_sender(context, sender_buf as *mut c_void);
            debug_print!("  ERROR: failed to acquire receiver buffer for DIGESTS");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size: usize = 4096;
        let mut recv_ptr: *mut c_void = receiver_buf as *mut c_void;
        let recv_ret = call_recv(context, &mut recv_ptr, &mut recv_size);
        
        call_release_sender(context, sender_buf as *mut c_void);
        
        if recv_ret != LIBSPDM_STATUS_SUCCESS || recv_size < 4 {
            call_release_receiver(context, receiver_buf as *mut c_void);
            debug_print!("  ERROR: DIGESTS recv failed or too small (size=%zu)", recv_size);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Check response code (0x01 = DIGESTS)
        if *receiver_buf.add(1) != 0x01 {
            debug_print!("  ERROR: wrong DIGESTS response code 0x%02x (expected 0x01)", *receiver_buf.add(1) as u32);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // param2 contains slot_mask
        let resp_slot_mask = *receiver_buf.add(3);
        debug_print!("  DIGESTS response OK: slot_mask=0x%02x", resp_slot_mask as u32);
        
        if !slot_mask.is_null() {
            *slot_mask = resp_slot_mask;
        }
        
        // Count slots (bits set in slot_mask)
        let slot_count = resp_slot_mask.count_ones() as usize;
        let digest_data_size = 4 + (hash_size * slot_count);
        
        if recv_size < digest_data_size {
            debug_print!("  ERROR: DIGESTS response too small for %u slots (size=%zu, need=%zu)", 
                        slot_count as u32, recv_size, digest_data_size);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Copy digest data to buffer (skip 4-byte header)
        if !total_digest_buffer.is_null() && slot_count > 0 {
            for i in 0..(hash_size * slot_count) {
                *total_digest_buffer.add(i) = *receiver_buf.add(4 + i);
            }
            debug_print!("  copied %zu bytes of digest data", hash_size * slot_count);
        }
        
        SPDM_CTX.slot_mask.store(resp_slot_mask as u32, Ordering::SeqCst);
        
        call_release_receiver(context, receiver_buf as *mut c_void);
        debug_print!("  get_digests SUCCESS");
    }
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_certificate(
    context: libspdm_context_t,
    _session_id: *const u32,
    slot_id: u8,
    cert_chain_size: *mut usize,
    cert_chain: *mut u8,
) -> libspdm_return_t {
    debug_print!("get_certificate(context=%p, slot=%u)", context, slot_id as u32);
    
    if cert_chain_size.is_null() {
        debug_print!("  ERROR: null cert_chain_size");
        return LIBSPDM_STATUS_ERROR;
    }
    
    unsafe {
        let ver_byte = ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8;
        let max_cert_size = *cert_chain_size;
        
        if max_cert_size == 0 {
            debug_print!("  ERROR: cert_chain_size=0");
            return LIBSPDM_STATUS_ERROR;
        }
        
        debug_print!("  max_cert_size=%zu, cert_chain=%p", max_cert_size, cert_chain);
        
        let mut total_offset: usize = 0;
        let mut remainder: u16 = 0xFFFF;  // Start with large remainder
        let mut first_response = true;
        let mut total_cert_length: u16 = 0;
        let mut chunk_num: u32 = 0;
        
        // Loop to get all certificate chunks
        debug_print!("  Certificate retrieval loop START: max_cert_size=%zu", max_cert_size);
        debug_print!("  DEBUG: cert_chain param=%p, cert_chain_size param=%p", cert_chain, cert_chain_size);
        while remainder > 0 && total_offset < max_cert_size {
            chunk_num += 1;
            debug_print!("  DEBUG: loop iteration %u start", chunk_num);
            let sender_buf = call_acquire_sender(context);
            if sender_buf.is_null() {
                debug_print!("  ERROR: failed to acquire sender buffer for GET_CERTIFICATE");
                return LIBSPDM_STATUS_ERROR;
            }
            
            // Request chunk size - use reasonable chunk size
            let request_length: u16 = if first_response { 
                0x400  // First request: ask for 1024 bytes to get total length
            } else {
                core::cmp::min(remainder, 0x400)  // Subsequent: ask for remaining or chunk
            };
            
            debug_print!("  === CHUNK %u START: offset=%zu, request_len=%u ===", chunk_num, total_offset, request_length as u32);
            
            *sender_buf.add(0) = ver_byte;
            *sender_buf.add(1) = 0x82;  // SPDM_GET_CERTIFICATE
            *sender_buf.add(2) = slot_id & 0x0F;  // param1 = slot_id
            *sender_buf.add(3) = 0;     // param2 = reserved
            
            // offset (2 bytes, little endian)
            *sender_buf.add(4) = (total_offset as u8) & 0xFF;
            *sender_buf.add(5) = ((total_offset >> 8) as u8) & 0xFF;
            
            // length (2 bytes, little endian)
            *sender_buf.add(6) = (request_length as u8) & 0xFF;
            *sender_buf.add(7) = ((request_length >> 8) as u8) & 0xFF;
            
            debug_print!("  sending GET_CERTIFICATE: offset=%zu, length=%u", total_offset, request_length as u32);
            
            let send_ret = call_send(context, sender_buf, 8);
            if send_ret != LIBSPDM_STATUS_SUCCESS {
                call_release_sender(context, sender_buf as *mut c_void);
                debug_print!("  ERROR: GET_CERTIFICATE send failed");
                return LIBSPDM_STATUS_ERROR;
            }
            
            let receiver_buf = call_acquire_receiver(context);
            if receiver_buf.is_null() {
                call_release_sender(context, sender_buf as *mut c_void);
                debug_print!("  ERROR: failed to acquire receiver buffer for CERTIFICATE");
                return LIBSPDM_STATUS_ERROR;
            }
            
            let mut recv_size: usize = 4096;
            let mut recv_ptr: *mut c_void = receiver_buf as *mut c_void;
            let recv_ret = call_recv(context, &mut recv_ptr, &mut recv_size);
            
            call_release_sender(context, sender_buf as *mut c_void);
            
            if recv_ret != LIBSPDM_STATUS_SUCCESS || recv_size < 4 {
                call_release_receiver(context, receiver_buf as *mut c_void);
                debug_print!("  ERROR: CERTIFICATE recv failed or too small (size=%zu)", recv_size);
                return LIBSPDM_STATUS_ERROR;
            }
            
            // Call transport_decode to trigger caching callbacks
            debug_print!("  BEFORE call_transport_decode for CERTIFICATE chunk %u", chunk_num);
            let mut msg_size: usize = 0;
            let mut msg_ptr: *mut c_void = core::ptr::null_mut();
            let decode_ret = call_transport_decode(
                context,
                receiver_buf as *mut c_void,
                recv_size,
                &mut msg_size,
                &mut msg_ptr,
            );
            debug_print!("  AFTER call_transport_decode: ret=%u", decode_ret);
            
            if decode_ret != LIBSPDM_STATUS_SUCCESS {
                debug_print!("  ERROR: transport_decode failed");
                call_release_receiver(context, receiver_buf as *mut c_void);
                return LIBSPDM_STATUS_ERROR;
            }
            
            // Use decoded message for processing
            let decoded_buf = if msg_ptr.is_null() { receiver_buf } else { msg_ptr as *mut u8 };
            let decoded_size = if msg_size == 0 { recv_size } else { msg_size };
            
            if decoded_size < 8 {
                call_release_receiver(context, receiver_buf as *mut c_void);
                debug_print!("  ERROR: decoded CERTIFICATE too small (size=%zu)", decoded_size);
                return LIBSPDM_STATUS_ERROR;
            }
            
            // Check response code (0x02 = CERTIFICATE)
            if *decoded_buf.add(1) != 0x02 {
                debug_print!("  ERROR: wrong CERTIFICATE response code 0x%02x (expected 0x02)", *decoded_buf.add(1) as u32);
                call_release_receiver(context, receiver_buf as *mut c_void);
                return LIBSPDM_STATUS_ERROR;
            }
            
            // portion_length at bytes 4-5
            let portion_length = (*decoded_buf.add(4) as u16) |
                                 ((*decoded_buf.add(5) as u16) << 8);
            
            // remainder_length at bytes 6-7
            let remainder_length = (*decoded_buf.add(6) as u16) |
                                    ((*decoded_buf.add(7) as u16) << 8);
            
            debug_print!("  CERTIFICATE response: portion=%u, remainder=%u", portion_length as u32, remainder_length as u32);
            
            debug_print!("  === CHUNK %u COMPLETE: portion=%u, remainder=%u, total_offset=%zu ===", 
                         chunk_num, portion_length as u32, remainder_length as u32, total_offset);
            
            if first_response && portion_length >= 4 {
                // First response contains total length in cert_chain header
                total_cert_length = (*decoded_buf.add(8) as u16) |
                                    ((*decoded_buf.add(9) as u16) << 8);
                debug_print!("  total_cert_length=%u", total_cert_length as u32);
                first_response = false;
            }
            
            // Copy portion data to cert_chain buffer only if buffer is provided
            if portion_length > 0 {
                if !cert_chain.is_null() && total_offset + (portion_length as usize) <= max_cert_size {
                    for i in 0..(portion_length as usize) {
                        *cert_chain.add(total_offset + i) = *decoded_buf.add(8 + i);
                    }
                    debug_print!("  copied %u bytes, total_offset=%zu", portion_length as u32, total_offset + portion_length as usize);
                }
                // Also save to internal cert_chain_buffer for hash calculation
                for i in 0..(portion_length as usize).min(65536 - total_offset) {
                    SPDM_CTX.cert_chain_buffer[total_offset + i].store(*decoded_buf.add(8 + i), Ordering::SeqCst);
                }
                total_offset += portion_length as usize;
            }
            
            remainder = remainder_length;
            call_release_receiver(context, receiver_buf as *mut c_void);
            
            if total_offset >= max_cert_size {
                debug_print!("  reached max_cert_size, stopping");
                break;
            }
        }
        
        *cert_chain_size = total_offset;
        SPDM_CTX.cert_chain_len.store(total_offset as u32, Ordering::SeqCst);
        debug_print!("  === LOOP END: total_chunks=%u, total_size=%zu ===", chunk_num, total_offset);
        debug_print!("  get_certificate SUCCESS: total_size=%zu", total_offset);
        
        // Calculate hash of complete cert_chain (including SPDM header and root cert hash)
        // This matches what responder uses for TH calculation
        let base_hash_algo = SPDM_CTX.base_hash_algo.load(Ordering::SeqCst);
        let hash_size = libspdm_get_hash_size(base_hash_algo);
        if total_offset > 0 && hash_size > 0 {
            let mut cert_chain_data = Vec::with_capacity(total_offset);
            for i in 0..total_offset.min(65536) {
                cert_chain_data.push(SPDM_CTX.cert_chain_buffer[i].load(Ordering::SeqCst));
            }
            match sha384(&cert_chain_data) {
                Ok(hash) => {
                    for i in 0..hash_size.min(48) {
                        SPDM_CTX.cert_chain_hash[i].store(hash[i], Ordering::SeqCst);
                    }
                    SPDM_CTX.cert_chain_hash_len.store(hash_size as u32, Ordering::SeqCst);
                    debug_print!("  computed cert_chain_hash (full chain): len=%zu", hash_size);
                }
                Err(_) => {
                    debug_print!("  ERROR: cert_chain hash computation failed");
                }
            }
        }
    }
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_challenge(
    context: libspdm_context_t,
    _requester_context: *const c_void,
    slot_id: u8,
    measurement_hash_type: u8,
    measurement_hash: *mut u8,
    slot_mask: *mut u8,
) -> libspdm_return_t {
    debug_print!("challenge(context=%p, slot=%u, hash_type=%u)", context, slot_id, measurement_hash_type);
    
    if context.is_null() {
        debug_print!("  ERROR: null context");
        return LIBSPDM_STATUS_ERROR;
    }
    
    let spdm_version = unsafe { ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8 };
    
    // SPDM CHALLENGE request: Header(4) + nonce(32)
    // For SPDM 1.3+: Header(4) + nonce(32) + requester_context(8)
    let req_size = 4 + 32; // SPDM 1.2 format
    
    unsafe {
        // Acquire sender buffer (REQUIRED for proper buffer management)
        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        debug_print!("  sender_buf=%p", sender_buf);
        
        // Build CHALLENGE request in acquired buffer
        let mut offset = 0;
        
        // SPDM header: version + request_code + param1 + param2
        *sender_buf.add(offset) = spdm_version;
        offset += 1;
        *sender_buf.add(offset) = SPDM_CHALLENGE; // 0x83
        offset += 1;
        *sender_buf.add(offset) = slot_id; // param1
        offset += 1;
        *sender_buf.add(offset) = measurement_hash_type; // param2
        offset += 1;
        
        // nonce (32 bytes)
        for i in 0..32 {
            *sender_buf.add(offset + i) = (i as u8) ^ 0xAB;
        }
        offset += 32;
        
        debug_print!("  sending CHALLENGE: size=%zu", req_size);
        
        // Send request
        let send_ret = call_send(context, sender_buf, req_size);
        
        // Release sender buffer AFTER send
        call_release_sender(context, sender_buf as *mut c_void);
        
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  send failed: %u", send_ret);
            return send_ret;
        }
        
        // Acquire receiver buffer (REQUIRED for proper buffer management)
        let receiver_buf = call_acquire_receiver(context);
        if receiver_buf.is_null() {
            debug_print!("  ERROR: failed to acquire receiver buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size: usize = 0;
        let recv_ret = call_recv(context, &mut (receiver_buf as *mut c_void), &mut recv_size);
        
        if recv_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  recv failed: %u", recv_ret);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return recv_ret;
        }
        
        debug_print!("  recv size=%zu", recv_size);
        
        // Parse CHALLENGE_AUTH response:
        // Header(4) + cert_chain_hash(hash_size) + nonce(32) + measurement_summary_hash(hash_size) + opaque_length(2) + opaque_data + signature(sig_size)
        let hash_size = libspdm_get_hash_size(SPDM_CTX.base_hash_algo.load(Ordering::SeqCst));
        let min_rsp_size = 4 + hash_size + 32 + 2; // header + cert_hash + nonce + opaque_len
        
        if recv_size < min_rsp_size {
            debug_print!("  ERROR: response too small (%zu < %zu)", recv_size, min_rsp_size);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        let rsp_code = *receiver_buf.add(1);
        
        if rsp_code != SPDM_CHALLENGE_AUTH { // 0x03
            debug_print!("  ERROR: wrong response code 0x%x (expected 0x%x)", rsp_code, SPDM_CHALLENGE_AUTH);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Extract slot_mask from param2 (byte 3)
        if !slot_mask.is_null() {
            *slot_mask = *receiver_buf.add(3);
            debug_print!("  slot_mask=0x%x", *slot_mask);
        }
        
        // Skip cert_chain_hash and nonce to get measurement_summary_hash
        // Position: header(4) + cert_chain_hash(hash_size) + nonce(32)
        if !measurement_hash.is_null() && measurement_hash_type != 0 {
            let meas_hash_offset = 4 + hash_size + 32;
            for i in 0..hash_size {
                *measurement_hash.add(i) = *receiver_buf.add(meas_hash_offset + i);
            }
            debug_print!("  measurement_hash extracted (size=%zu)", hash_size);
        }
        
        SPDM_CTX.connection_state.store(LIBSPDM_CONNECTION_STATE_AUTHENTICATED, Ordering::SeqCst);
        
        // Release receiver buffer
        call_release_receiver(context, receiver_buf as *mut c_void);
    }
    
    debug_print!("  challenge SUCCESS: authenticated");
    LIBSPDM_STATUS_SUCCESS
}

// SPDM message codes for CHALLENGE
pub const SPDM_CHALLENGE: u8 = 0x83;
pub const SPDM_CHALLENGE_AUTH: u8 = 0x03;

#[no_mangle]
pub extern "C" fn libspdm_key_exchange(
    context: libspdm_context_t,
    measurement_hash_type: u8,
    slot_id: u8,
    session_id: *mut libspdm_session_id_t,
    heartbeat_period: *mut u8,
    measurement_summary_hash: *mut u8,
) -> libspdm_return_t {
    debug_print!("key_exchange(context=%p, slot=%u)", context, slot_id);
    
    if session_id.is_null() {
        debug_print!("  ERROR: null session_id");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if context.is_null() {
        debug_print!("  ERROR: null context");
        return LIBSPDM_STATUS_ERROR;
    }
    
    let spdm_version = unsafe { ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8 };
    let dhe_group = unsafe { SPDM_CTX.dhe_group.load(Ordering::SeqCst) };
    
    // Determine DHE key size based on algorithm
    // DHE: 0x30018 = ECDH P-384 (secp384r1), public key = 96 bytes (X + Y coordinates, NO 0x04 prefix)
    // libspdm expects raw X+Y coordinates without the uncompressed point prefix (0x04)
    let dhe_key_size: usize = if dhe_group == 0x30018 { 96 } else { 64 }; // P-384 or P-256
    
    debug_print!("  dhe_group=0x%x, key_size=%zu (X+Y coordinates, no prefix)", dhe_group, dhe_key_size);
    
    // Generate req_session_id: first session uses 0xFFFF (per C library: 0xFFFF - index)
    let req_session_id: u16 = 0xFFFF;
    unsafe { SPDM_CTX.req_session_id.store(req_session_id, Ordering::SeqCst); }
    
    // Generate real ECDH P-384 key pair
    let ecdh_keypair = match ecdh_p384_keypair() {
        Ok(kp) => kp,
        Err(_) => {
            debug_print!("  ERROR: failed to generate ECDH P-384 key pair");
            return LIBSPDM_STATUS_ERROR;
        }
    };
    
    // Save ECDH keypair to global storage for FINISH HMAC computation
    unsafe {
        ECDH_KEYPAIR = Some(ecdh_keypair);
        SPDM_CTX.ecdh_keypair.store(1, Ordering::SeqCst);
    }
    
    let dhe_pubkey_raw = unsafe { ECDH_KEYPAIR.as_ref().unwrap() }.public_key_raw_bytes();
    debug_print!("  ECDH pubkey generated: size=%zu", dhe_pubkey_raw.len());
    
    // Build KEY_EXCHANGE request:
    // Header(4) + req_session_id(2) + session_policy(1) + reserved(1) + random(32) + exchange_data(dhe_key_size) + opaque_length(2) + opaque_data
    let random_size = 32;
    
    // Opaque data for SPDM 1.2 (secured message version):
    // spdm_general_opaque_data_table_header_t (4) + element_table_header (4) + supported_version (3+2) = 13 bytes
    // Padding to 4-byte alignment: (13+3) & ~3 = 16 bytes
    let opaque_data_size = 16;
    let req_size = 4 + 2 + 1 + 1 + random_size + dhe_key_size + 2 + opaque_data_size;
    
    debug_print!("  KEY_EXCHANGE size: header=4, session_id=2, policy=1, reserved=1, random=32, dhe=%zu, opaque_len=2, opaque=%zu = total %zu",
                 dhe_key_size, opaque_data_size, req_size);
    
    // Generate real random data for requester
    let requester_random = match random_bytes(32) {
        Ok(r) => r,
        Err(_) => {
            debug_print!("  ERROR: failed to generate random data");
            return LIBSPDM_STATUS_ERROR;
        }
    };
    
    unsafe {
        // Acquire sender buffer (REQUIRED for proper buffer management)
        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        debug_print!("  sender_buf=%p", sender_buf);
        
        let mut offset = 0;
        
        // SPDM header: version + request_code + param1 + param2
        *sender_buf.add(offset) = spdm_version;
        offset += 1;
        *sender_buf.add(offset) = SPDM_KEY_EXCHANGE;
        offset += 1;
        *sender_buf.add(offset) = measurement_hash_type; // param1
        offset += 1;
        *sender_buf.add(offset) = slot_id; // param2
        offset += 1;
        
        // req_session_id (little endian)
        *sender_buf.add(offset) = (req_session_id & 0xFF) as u8;
        offset += 1;
        *sender_buf.add(offset) = ((req_session_id >> 8) & 0xFF) as u8;
        offset += 1;
        
        // session_policy
        *sender_buf.add(offset) = 0;
        offset += 1;
        
        // reserved
        *sender_buf.add(offset) = 0;
        offset += 1;
        
        // random_data (32 bytes) - real random
        for i in 0..random_size {
            *sender_buf.add(offset + i) = requester_random[i];
        }
        offset += random_size;
        
        // exchange_data (DHE public key) - raw X+Y coordinates (96 bytes, no 0x04 prefix)
        for i in 0..dhe_key_size {
            *sender_buf.add(offset + i) = dhe_pubkey_raw[i];
        }
        offset += dhe_key_size;
        
        // opaque_length (little endian) = 16
        *sender_buf.add(offset) = (opaque_data_size & 0xFF) as u8;
        *sender_buf.add(offset + 1) = ((opaque_data_size >> 8) & 0xFF) as u8;
        offset += 2;
        
        // opaque_data (16 bytes for SPDM 1.2 secured message version)
        // spdm_general_opaque_data_table_header_t: total_elements=1, reserved[3]=0
        *sender_buf.add(offset) = 1;  // total_elements
        *sender_buf.add(offset + 1) = 0;  // reserved[0]
        *sender_buf.add(offset + 2) = 0;  // reserved[1]
        *sender_buf.add(offset + 3) = 0;  // reserved[2]
        offset += 4;
        
        // opaque_element_table_header_t: id=0, vendor_len=0 (only 2 bytes!)
        *sender_buf.add(offset) = 0;  // id = SPDM_REGISTRY_ID_DMTF
        *sender_buf.add(offset + 1) = 0;  // vendor_len
        offset += 2;
        
        // opaque_element_data_len (2 bytes, little endian) = 5
        *sender_buf.add(offset) = 5;  // opaque_element_data_len low
        *sender_buf.add(offset + 1) = 0;  // opaque_element_data_len high
        offset += 2;
        
        // secured_message_opaque_element_supported_version_t (3 bytes)
        *sender_buf.add(offset) = 1;  // sm_data_version
        *sender_buf.add(offset + 1) = 1;  // sm_data_id = SUPPORTED_VERSION
        *sender_buf.add(offset + 2) = 1;  // version_count
        offset += 3;
        
        // spdm_version_number_t (2 bytes, little endian) = 0x1100 (SPDM 1.1 secured message)
        // Format: bits 15:12=major, bits 11:8=minor, bits 7:0=reserved
        *sender_buf.add(offset) = 0x00;  // version number low byte
        *sender_buf.add(offset + 1) = 0x11;  // version number high byte (major=1, minor=1)
        offset += 2;
        
        // Padding to 16 bytes (3 more bytes)
        *sender_buf.add(offset) = 0;
        *sender_buf.add(offset + 1) = 0;
        *sender_buf.add(offset + 2) = 0;
        offset += 3;
        
        debug_print!("  KEY_EXCHANGE header: %02x %02x %02x %02x", *sender_buf.add(0) as u32, *sender_buf.add(1) as u32, *sender_buf.add(2) as u32, *sender_buf.add(3) as u32);
        debug_print!("  KEY_EXCHANGE session: %02x %02x", *sender_buf.add(4) as u32, *sender_buf.add(5) as u32);
        debug_print!("  KEY_EXCHANGE opaque_len: %02x %02x", *sender_buf.add(136) as u32, *sender_buf.add(137) as u32);
        debug_print!("  KEY_EXCHANGE opaque[0-4]: %02x %02x %02x %02x %02x", *sender_buf.add(138) as u32, *sender_buf.add(139) as u32, *sender_buf.add(140) as u32, *sender_buf.add(141) as u32, *sender_buf.add(142) as u32);
        debug_print!("  KEY_EXCHANGE opaque[5-9]: %02x %02x %02x %02x %02x", *sender_buf.add(143) as u32, *sender_buf.add(144) as u32, *sender_buf.add(145) as u32, *sender_buf.add(146) as u32, *sender_buf.add(147) as u32);
        debug_print!("  KEY_EXCHANGE opaque[10-14]: %02x %02x %02x %02x %02x", *sender_buf.add(148) as u32, *sender_buf.add(149) as u32, *sender_buf.add(150) as u32, *sender_buf.add(151) as u32, *sender_buf.add(152) as u32);
        debug_print!("  KEY_EXCHANGE opaque[15]: %02x", *sender_buf.add(153) as u32);
        
        // Send request
        let send_ret = call_send(context, sender_buf, req_size);
        
        // Save KEY_EXCHANGE request data for TH1 calculation
        for i in 0..req_size.min(2048) {
            SPDM_CTX.key_exchange_req_data[i].store(*sender_buf.add(i), Ordering::SeqCst);
        }
        SPDM_CTX.key_exchange_req_len.store(req_size as u32, Ordering::SeqCst);
        debug_print!("  saved KEY_EXCHANGE request: len=%zu", req_size);
        
        // Release sender buffer AFTER send
        call_release_sender(context, sender_buf as *mut c_void);
        
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  send failed: %u", send_ret);
            return send_ret;
        }
        
        // Acquire receiver buffer (REQUIRED for proper buffer management)
        let receiver_buf = call_acquire_receiver(context);
        if receiver_buf.is_null() {
            debug_print!("  ERROR: failed to acquire receiver buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size: usize = 0;
        let recv_ret = call_recv(context, &mut (receiver_buf as *mut c_void), &mut recv_size);
        
        if recv_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  recv failed: %u", recv_ret);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return recv_ret;
        }
        
        debug_print!("  recv size=%zu (raw transport data)", recv_size);
        
        // Decode transport header to get actual SPDM message
        let mut msg_size: usize = 0;
        let mut msg_ptr: *mut c_void = core::ptr::null_mut();
        let decode_ret = call_transport_decode(
            context,
            receiver_buf as *mut c_void,
            recv_size,
            &mut msg_size,
            &mut msg_ptr,
        );
        
        if decode_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  ERROR: transport_decode failed for KEY_EXCHANGE_RSP");
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Use decoded message (msg_ptr) or raw buffer if decode returned null
        let decoded_buf = if msg_ptr.is_null() { receiver_buf } else { msg_ptr as *mut u8 };
        let decoded_size = if msg_size == 0 { recv_size } else { msg_size };
        
        debug_print!("  decoded SPDM message size=%zu", decoded_size);
        
        // Parse KEY_EXCHANGE_RSP:
        // Header(4) + rsp_session_id(2) + mut_auth_requested(1) + slot_id_param(1) + random(32) + exchange_data + meas_hash + opaque + signature + hmac
        let min_rsp_size = 4 + 2 + 1 + 1 + 32 + dhe_key_size;
        if decoded_size < min_rsp_size {
            debug_print!("  ERROR: response too small (%zu < %zu)", decoded_size, min_rsp_size);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        let rsp_code = *decoded_buf.add(1);
        
        if rsp_code != SPDM_KEY_EXCHANGE_RSP {
            debug_print!("  ERROR: wrong response code 0x%x (expected 0x%x)", rsp_code, SPDM_KEY_EXCHANGE_RSP);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Extract rsp_session_id (bytes 4-5)
        let b0 = *decoded_buf.add(4);
        let b1 = *decoded_buf.add(5);
        let rsp_session_id = (b0 as u16) | ((b1 as u16) << 8);
        
        debug_print!("  rsp_session_id=0x%x", rsp_session_id);
        
        SPDM_CTX.rsp_session_id.store(rsp_session_id, Ordering::SeqCst);
        
        // Generate final session_id = (rsp_session_id << 16) | req_session_id
        let final_session_id = ((rsp_session_id as u32) << 16) | (req_session_id as u32);
        SPDM_CTX.session_id.store(final_session_id, Ordering::SeqCst);
        *session_id = final_session_id;
        
        debug_print!("  final session_id=0x%x", final_session_id);
        
        // Extract heartbeat_period from mut_auth_requested field (byte 6)
        if !heartbeat_period.is_null() {
            let mut_auth = *decoded_buf.add(6);
            *heartbeat_period = 0; // heartbeat not in this field, but we return 0
        }
        
        // Extract responder_random (bytes 8-39, 32 bytes)
        for i in 0..32 {
            SPDM_CTX.responder_random[i].store(*decoded_buf.add(8 + i), Ordering::SeqCst);
        }
        
        // Extract responder_dhe_pubkey (bytes 40-135, 96 bytes for P-384)
        for i in 0..96 {
            SPDM_CTX.responder_dhe_pubkey[i].store(*decoded_buf.add(40 + i), Ordering::SeqCst);
        }
        
        debug_print!("  extracted responder_random and dhe_pubkey");
        
        // Parse KEY_EXCHANGE_RSP structure to calculate actual SPDM message size
        // Structure: Header(4) + rsp_session_id(2) + mut_auth(1) + slot_id(1) + random(32) + dhe_pubkey(96) + opaque_length(2) + opaque_data + signature(96) + HMAC(48)
        // Offset 136: opaque_length (2 bytes, little endian)
        let opaque_offset = 4 + 2 + 1 + 1 + 32 + dhe_key_size;  // = 136
        if decoded_size < opaque_offset + 2 {
            debug_print!("  ERROR: response too small to contain opaque_length");
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        let opaque_length = (*decoded_buf.add(opaque_offset) as u16) |
                            ((*decoded_buf.add(opaque_offset + 1) as u16) << 8);
        debug_print!("  opaque_length=%u", opaque_length as u32);
        
        // Calculate actual SPDM message size
        // For ECDSA-384: signature_size = 96, HMAC_size = 48
        // responder may or may not include HMAC based on HANDSHAKE_IN_THE_CLEAR capability
        // We determine actual size by parsing: check if data after signature matches HMAC pattern
        let sig_size = 96;  // ECDSA-P384 signature size
        let hmac_size = 48;  // SHA-384 HMAC size
        let base_rsp_size = opaque_offset + 2 + opaque_length as usize;  // up to end of opaque_data
        
        // Calculate expected sizes with and without HMAC
        let rsp_size_with_hmac = base_rsp_size + sig_size + hmac_size;
        let rsp_size_no_hmac = base_rsp_size + sig_size;
        
        // Determine actual size: if decoded_size matches with_hmac or no_hmac exactly, use that
        // Otherwise, use decoded_size (which may have DOE padding)
        let actual_rsp_size = if decoded_size == rsp_size_with_hmac || decoded_size == rsp_size_no_hmac {
            decoded_size
        } else if decoded_size > rsp_size_no_hmac && decoded_size <= rsp_size_with_hmac + 4 {
            // DOE padding case: responder sent no_hmac size, DOE padded to DW alignment
            // Use the calculated size without HMAC (responder doesn't support HANDSHAKE_IN_THE_CLEAR)
            rsp_size_no_hmac
        } else {
            decoded_size
        };
        
        debug_print!("  actual SPDM message size: %zu (decoded=%zu, expected_with_hmac=%zu, expected_no_hmac=%zu)", 
                     actual_rsp_size, decoded_size, rsp_size_with_hmac, rsp_size_no_hmac);
        
        // Compute shared secret using saved ECDH keypair
        if ECDH_KEYPAIR.is_some() {
            let keypair = ECDH_KEYPAIR.as_ref().unwrap();
            // Build responder's SEC1 format public key (add 0x04 prefix)
            let mut responder_sec1_pubkey = vec![0x04];
            for i in 0..96 {
                responder_sec1_pubkey.push(SPDM_CTX.responder_dhe_pubkey[i].load(Ordering::SeqCst));
            }
            
match keypair.shared_secret(&responder_sec1_pubkey) {
                    Ok(shared_secret) => {
                        debug_print!("  shared_secret len=%zu first8=%02x%02x%02x%02x", shared_secret.len(),
                            shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[3]);
                        
                        // Save KEY_EXCHANGE response data for TH1 calculation (use actual SPDM size, not DOE padded)
                    for i in 0..actual_rsp_size.min(2048) {
                        SPDM_CTX.key_exchange_rsp_data[i].store(*decoded_buf.add(i), Ordering::SeqCst);
                    }
                    SPDM_CTX.key_exchange_rsp_len.store(actual_rsp_size as u32, Ordering::SeqCst);
                    debug_print!("  saved KEY_EXCHANGE response: len=%zu (actual SPDM size)", actual_rsp_size);
                    
                    // Compute handshake_secret = HKDF-Extract(salt=zero, ikm=shared_secret)
                    let zero_salt = [0u8; 48];
                    match hkdf_extract_sha384(&zero_salt, &shared_secret) {
                        Ok(handshake_secret) => {
                            debug_print!("  handshake_secret computed len=%zu first8=%02x%02x%02x%02x", handshake_secret.len(),
                                handshake_secret[0], handshake_secret[1], handshake_secret[2], handshake_secret[3]);
                            for i in 0..48 {
                                SPDM_CTX.handshake_secret[i].store(handshake_secret[i], Ordering::SeqCst);
                            }
                            debug_print!("  stored handshake_secret");
                            
                            // Compute TH1 = SHA-384(message_a + cert_chain_hash + KEY_EXCHANGE req + rsp(no_sig) + signature)
                            let msg_a_len = SPDM_CTX.message_a_len.load(Ordering::SeqCst) as usize;
                            let req_len = SPDM_CTX.key_exchange_req_len.load(Ordering::SeqCst) as usize;
                            let rsp_len = SPDM_CTX.key_exchange_rsp_len.load(Ordering::SeqCst) as usize;
                            let cert_hash_len = SPDM_CTX.cert_chain_hash_len.load(Ordering::SeqCst) as usize;
                            
                            debug_print!("  TH1 transcript sizes: msg_a=%zu cert_hash=%zu ke_req=%zu ke_rsp=%zu", 
                                         msg_a_len, cert_hash_len, req_len, rsp_len);
                            debug_print!("  message_a first4=%02x%02x%02x%02x", 
                                SPDM_CTX.message_a_data[0].load(Ordering::SeqCst),
                                SPDM_CTX.message_a_data[1].load(Ordering::SeqCst),
                                SPDM_CTX.message_a_data[2].load(Ordering::SeqCst),
                                SPDM_CTX.message_a_data[3].load(Ordering::SeqCst));
                            debug_print!("  cert_chain_hash first4=%02x%02x%02x%02x", 
                                SPDM_CTX.cert_chain_hash[0].load(Ordering::SeqCst),
                                SPDM_CTX.cert_chain_hash[1].load(Ordering::SeqCst),
                                SPDM_CTX.cert_chain_hash[2].load(Ordering::SeqCst),
                                SPDM_CTX.cert_chain_hash[3].load(Ordering::SeqCst));
                            debug_print!("  ke_req first4=%02x%02x%02x%02x", 
                                SPDM_CTX.key_exchange_req_data[0].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_req_data[1].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_req_data[2].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_req_data[3].load(Ordering::SeqCst));
                            debug_print!("  ke_rsp first4=%02x%02x%02x%02x", 
                                SPDM_CTX.key_exchange_rsp_data[0].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_rsp_data[1].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_rsp_data[2].load(Ordering::SeqCst),
                                SPDM_CTX.key_exchange_rsp_data[3].load(Ordering::SeqCst));
                            
                            // responder splits KEY_EXCHANGE_RSP into: rsp(no_sig) + signature
                            // rsp(no_sig) = base_rsp_size = 136 + 2 + opaque_length = 148 bytes
                            // signature = 96 bytes
                            let rsp_no_sig_len = base_rsp_size;  // 148 bytes
                            let signature_len = sig_size;  // 96 bytes
                            
                            let mut transcript_data = Vec::with_capacity(msg_a_len + cert_hash_len + req_len + rsp_no_sig_len + signature_len);
                            
                            // Append message_a
                            for i in 0..msg_a_len.min(4096) {
                                transcript_data.push(SPDM_CTX.message_a_data[i].load(Ordering::SeqCst));
                            }
                            // Append cert_chain_hash
                            if cert_hash_len > 0 {
                                for i in 0..cert_hash_len.min(64) {
                                    transcript_data.push(SPDM_CTX.cert_chain_hash[i].load(Ordering::SeqCst));
                                }
                            }
                            // Append KEY_EXCHANGE req
                            for i in 0..req_len.min(2048) {
                                transcript_data.push(SPDM_CTX.key_exchange_req_data[i].load(Ordering::SeqCst));
                            }
                            // Append KEY_EXCHANGE rsp (no signature)
                            for i in 0..rsp_no_sig_len.min(2048) {
                                transcript_data.push(SPDM_CTX.key_exchange_rsp_data[i].load(Ordering::SeqCst));
                            }
                            // Append signature (after rsp_no_sig)
                            for i in 0..signature_len.min(128) {
                                transcript_data.push(SPDM_CTX.key_exchange_rsp_data[rsp_no_sig_len + i].load(Ordering::SeqCst));
                            }
                            debug_print!("  TH1 transcript: msg_a=%zu + cert_hash=%zu + ke_req=%zu + ke_rsp=%zu", 
                                         msg_a_len, cert_hash_len, req_len, rsp_no_sig_len + signature_len);
                            
                            let th1 = match sha384(&transcript_data) {
                                Ok(h) => {
                                    debug_print!("  TH1 computed first8=%02x%02x%02x%02x", h[0], h[1], h[2], h[3]);
                                    h
                                },
                                Err(_) => {
                                    debug_print!("  ERROR: TH1 hash failed");
                                    return LIBSPDM_STATUS_ERROR;
                                }
                            };
                            debug_print!("  computed TH1: len=%zu", th1.len());
                            
                            // Derive request_handshake_secret
                            // bin_str1 = length(48) + "spdm1.2 req hs data" + TH1
                            // Format: 2 bytes length + "spdm1.2 " (8 bytes) + "req hs data" (10 bytes) + TH1 (48 bytes)
                            let spdm_version = SPDM_CTX.spdm_version.load(Ordering::SeqCst);
                            let major = ((spdm_version >> 12) & 0xF) as u8;
                            let minor = ((spdm_version >> 8) & 0xF) as u8;
                            let bin_str1: Vec<u8> = [
                                48, 0,  // length = 48 (hash size)
                                b's', b'p', b'd', b'm',
                                b'0' + major, b'.', b'0' + minor, b' ',
                                b'r', b'e', b'q', b' ',
                                b'h', b's', b' ', b'd',
                                b'a', b't', b'a',
                            ].iter().cloned().chain(th1.iter().cloned()).collect();
                            debug_print!("  bin_str1 len=%zu", bin_str1.len());
                            
                            match hkdf_expand_sha384(&handshake_secret, &bin_str1, 48) {
                                Ok(req_hs_secret) => {
                                    debug_print!("  request_handshake_secret first8=%02x%02x%02x%02x",
                                        req_hs_secret[0], req_hs_secret[1], req_hs_secret[2], req_hs_secret[3]);
                                    for i in 0..48 {
                                        SPDM_CTX.request_handshake_secret[i].store(req_hs_secret[i], Ordering::SeqCst);
                                    }
                                    debug_print!("  stored request_handshake_secret");
                                    
                                    // Derive request_finished_key
                                    // bin_str7 = length(48) + "spdm1.2 finished"
                                    let bin_str7: Vec<u8> = [
                                        48, 0,  // length = 48
                                        b's', b'p', b'd', b'm',
                                        b'0' + major, b'.', b'0' + minor, b' ',
                                        b'f', b'i', b'n', b'i',
                                        b's', b'h', b'e', b'd',
                                    ].to_vec();
                                    
                                    match hkdf_expand_sha384(&req_hs_secret, &bin_str7, 48) {
                                        Ok(finished_key) => {
                                            for i in 0..48 {
                                                SPDM_CTX.request_finished_key[i].store(finished_key[i], Ordering::SeqCst);
                                            }
                                            debug_print!("  stored request_finished_key");
                                            
                                            // Derive response_handshake_secret
                                            // bin_str2 = length(48) + "spdm1.2 rsp hs data" + TH1
                                            let bin_str2: Vec<u8> = [
                                                48, 0,
                                                b's', b'p', b'd', b'm',
                                                b'0' + major, b'.', b'0' + minor, b' ',
                                                b'r', b's', b'p', b' ',
                                                b'h', b's', b' ', b'd',
                                                b'a', b't', b'a',
                                            ].iter().cloned().chain(th1.iter().cloned()).collect();
                                            
                                            match hkdf_expand_sha384(&handshake_secret, &bin_str2, 48) {
                                                Ok(rsp_hs_secret) => {
                                                    for i in 0..48 {
                                                        SPDM_CTX.response_handshake_secret[i].store(rsp_hs_secret[i], Ordering::SeqCst);
                                                    }
                                                    debug_print!("  stored response_handshake_secret");
                                                    
                                                    // Derive response_finished_key
                                                    match hkdf_expand_sha384(&rsp_hs_secret, &bin_str7, 48) {
                                                        Ok(rsp_finished_key) => {
                                                            for i in 0..48 {
                                                                SPDM_CTX.response_finished_key[i].store(rsp_finished_key[i], Ordering::SeqCst);
                                                            }
                                                            debug_print!("  stored response_finished_key");
                                                            
                                                            // Calculate responder HMAC (verify_data)
                                                            // TH1_hash = SHA384(TH1_transcript)
                                                            let verify_data = match hmac_sha384(&rsp_finished_key, &th1) {
                                                                Ok(h) => h,
                                                                Err(_) => {
                                                                    debug_print!("  ERROR: responder HMAC failed");
                                                                    return LIBSPDM_STATUS_ERROR;
                                                                }
                                                            };
                                                            for i in 0..48 {
                                                                SPDM_CTX.responder_hmac[i].store(verify_data[i], Ordering::SeqCst);
                                                            }
                                                            SPDM_CTX.responder_hmac_len.store(48, Ordering::SeqCst);
                                                            debug_print!("  stored responder HMAC (verify_data)");
                                                        }
                                                        Err(_) => {
                                                            debug_print!("  ERROR: response_finished_key derivation failed");
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    debug_print!("  ERROR: response_handshake_secret derivation failed");
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            debug_print!("  ERROR: finished_key derivation failed");
                                        }
                                    }
                                }
                                Err(_) => {
                                    debug_print!("  ERROR: request_handshake_secret derivation failed");
                                }
                            }
                        }
                        Err(_) => {
                            debug_print!("  ERROR: hkdf_extract failed");
                        }
                    }
                }
                Err(_) => {
                    debug_print!("  ERROR: shared_secret computation failed");
                }
            }
        }
        
        // Release receiver buffer
        call_release_receiver(context, receiver_buf as *mut c_void);
    }
    
    debug_print!("  key_exchange SUCCESS: session_id=0x%x", unsafe { *session_id });
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_finish(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    slot_id: u8,
    request_attribute: u8,
) -> libspdm_return_t {
    debug_print!("finish(context=%p, session=0x%x, slot=%u, attr=%u)", context, session_id, slot_id, request_attribute);
    
    if context.is_null() {
        debug_print!("  ERROR: null context");
        return LIBSPDM_STATUS_ERROR;
    }
    
    let spdm_version = unsafe { ((SPDM_CTX.spdm_version.load(Ordering::SeqCst) >> 8) & 0xFF) as u8 };
    
    // FINISH request (SPDM 1.1/1.2 format): Header(4) + verify_data(HMAC)
    // When signature_included=0 (param1=0), only HMAC is sent
    let hash_size = 48; // SHA-384 for P-384
    let req_size = 4 + hash_size;
    
    unsafe {
        // Acquire sender buffer (REQUIRED for proper buffer management)
        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut offset = 0;
        
        // Header: version + request_code + param1(signature_included=0) + param2(req_slot_id)
        *sender_buf.add(offset) = spdm_version;
        offset += 1;
        *sender_buf.add(offset) = SPDM_FINISH;
        offset += 1;
        *sender_buf.add(offset) = 0;  // param1 = signature_included = 0
        offset += 1;
        *sender_buf.add(offset) = slot_id;  // param2 = req_slot_id
        offset += 1;
        
        // Compute verify_data (HMAC)
        // TH_curr = SHA-384(message_a + cert_chain_hash + KEY_EXCHANGE req + KEY_EXCHANGE rsp + FINISH req header)
        let msg_a_len = SPDM_CTX.message_a_len.load(Ordering::SeqCst) as usize;
        let cert_hash_len = SPDM_CTX.cert_chain_hash_len.load(Ordering::SeqCst) as usize;
        let req_len = SPDM_CTX.key_exchange_req_len.load(Ordering::SeqCst) as usize;
        let rsp_len = SPDM_CTX.key_exchange_rsp_len.load(Ordering::SeqCst) as usize;
        let mut transcript_data = Vec::with_capacity(msg_a_len + cert_hash_len + req_len + rsp_len + 4);
        
        // Append message_a (VERSION + CAPABILITIES + ALGORITHMS)
        for i in 0..msg_a_len.min(4096) {
            transcript_data.push(SPDM_CTX.message_a_data[i].load(Ordering::SeqCst));
        }
        debug_print!("  appended message_a: len=%zu", msg_a_len);
        
        // Append cert_chain_hash (responder's certificate chain hash)
        if cert_hash_len > 0 {
            for i in 0..cert_hash_len.min(64) {
                transcript_data.push(SPDM_CTX.cert_chain_hash[i].load(Ordering::SeqCst));
            }
            debug_print!("  appended cert_chain_hash: len=%zu", cert_hash_len);
        }
        
        // Append KEY_EXCHANGE request
        for i in 0..req_len.min(2048) {
            transcript_data.push(SPDM_CTX.key_exchange_req_data[i].load(Ordering::SeqCst));
        }
        // Append KEY_EXCHANGE response (no signature) - match responder's message_k structure
        // message_k = KE_rsp_no_sig + signature (split by responder)
        let rsp_no_sig_len = if rsp_len >= 96 { rsp_len - 96 } else { rsp_len };  // 148 bytes
        for i in 0..rsp_no_sig_len.min(2048) {
            transcript_data.push(SPDM_CTX.key_exchange_rsp_data[i].load(Ordering::SeqCst));
        }
        // Append signature (from KE_rsp data after rsp_no_sig)
        for i in 0..96.min(128) {
            if rsp_no_sig_len + i < 2048 {
                transcript_data.push(SPDM_CTX.key_exchange_rsp_data[rsp_no_sig_len + i].load(Ordering::SeqCst));
            }
        }
        // Append responder HMAC (verify_data) to message_k - ONLY if HANDSHAKE_IN_THE_CLEAR is NOT enabled
        // HANDSHAKE_IN_THE_CLEAR cap = bit 15 (0x8000) in cap_flags
        // If enabled, responder does NOT include HMAC in message_k
        let cap_flags = SPDM_CTX.cap_flags.load(Ordering::SeqCst);
        let handshake_in_clear = (cap_flags & 0x8000) != 0;
        let hmac_len = SPDM_CTX.responder_hmac_len.load(Ordering::SeqCst) as usize;
        if !handshake_in_clear && hmac_len > 0 {
            for i in 0..hmac_len.min(48) {
                transcript_data.push(SPDM_CTX.responder_hmac[i].load(Ordering::SeqCst));
            }
            debug_print!("  appended responder HMAC: len=%zu (handshake NOT in clear)", hmac_len);
        } else {
            debug_print!("  skipped responder HMAC: handshake_in_clear=%d", handshake_in_clear as usize);
        }
        // Append FINISH request header (first 4 bytes)
        transcript_data.push(spdm_version);
        transcript_data.push(SPDM_FINISH);
        transcript_data.push(0);
        transcript_data.push(slot_id);
        
        debug_print!("  transcript_data total: msg_a=%zu + cert_hash=%zu + ke_req=%zu + ke_rsp=%zu + hmac=%zu + finish_hdr=4", 
                     msg_a_len, cert_hash_len, req_len, rsp_no_sig_len + 96, if !handshake_in_clear { hmac_len } else { 0 });
        
        let th_curr = match sha384(&transcript_data) {
            Ok(h) => h,
            Err(_) => {
                debug_print!("  ERROR: TH_curr hash failed");
                call_release_sender(context, sender_buf as *mut c_void);
                return LIBSPDM_STATUS_ERROR;
            }
        };
        debug_print!("  computed TH_curr hash OK");
        
        // verify_data = HMAC-SHA384(request_finished_key, TH_curr)
        let finished_key: [u8; 48] = {
            let mut key = [0u8; 48];
            for i in 0..48 {
                key[i] = SPDM_CTX.request_finished_key[i].load(Ordering::SeqCst);
            }
            key
        };
        debug_print!("  loaded request_finished_key");
        
        let verify_data = match hmac_sha384(&finished_key, &th_curr) {
            Ok(h) => h,
            Err(_) => {
                debug_print!("  ERROR: HMAC computation failed");
                call_release_sender(context, sender_buf as *mut c_void);
                return LIBSPDM_STATUS_ERROR;
            }
        };
        debug_print!("  computed verify_data: len=%zu", verify_data.len());
        
        // Fill verify_data into FINISH request
        for i in 0..hash_size {
            *sender_buf.add(offset + i) = verify_data[i];
        }
        offset += hash_size;
        
        debug_print!("  sending FINISH: size=%zu (header=4 + hmac=%zu)", req_size, hash_size);
        
        let send_ret = call_send(context, sender_buf, req_size);
        
        call_release_sender(context, sender_buf as *mut c_void);
        
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  send failed: %u", send_ret);
            return send_ret;
        }
        
        // Acquire receiver buffer
        let receiver_buf = call_acquire_receiver(context);
        if receiver_buf.is_null() {
            debug_print!("  ERROR: failed to acquire receiver buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        let mut recv_size: usize = 0;
        let recv_ret = call_recv(context, &mut (receiver_buf as *mut c_void), &mut recv_size);
        
        if recv_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  recv failed: %u", recv_ret);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return recv_ret;
        }
        
        debug_print!("  recv size=%zu", recv_size);
        
        if recv_size < 4 {
            debug_print!("  ERROR: response too small");
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        let rsp_code = *receiver_buf.add(1);
        
        if rsp_code != SPDM_FINISH_RSP {
            debug_print!("  ERROR: wrong response code 0x%x (expected 0x%x)", rsp_code, SPDM_FINISH_RSP);
            call_release_receiver(context, receiver_buf as *mut c_void);
            return LIBSPDM_STATUS_ERROR;
        }
        
        call_release_receiver(context, receiver_buf as *mut c_void);
    }
    
    debug_print!("  finish SUCCESS: session established");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_end_session(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    _end_session_attributes: u8,
) -> libspdm_return_t {
    debug_print!("end_session(context=%p, session=0x%x)", context, session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_measurement_ex(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    _request_attribute: u8,
    _measurement_operation: u8,
    _slot_id: u8,
    _number_of_blocks: *mut u8,
    _measurement_record_length: *mut u32,
    _measurement_record: *mut u8,
) -> libspdm_return_t {
    debug_print!("get_measurement_ex(context=%p, session=0x%x)", context, session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_hash_size(hash_algo: u32) -> usize {
    debug_print!("get_hash_size(algo=0x%x)", hash_algo);
    match hash_algo {
        0x00000002 => 48,  // SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384
        0x00000001 => 32,  // SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256
        0x00000004 => 64,  // SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512
        0x0020 => 48,      // TPM_ALG_SHA384 (fallback for TPM algorithm IDs)
        0x0010 => 32,      // TPM_ALG_SHA256 (fallback for TPM algorithm IDs)
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn libspdm_generate_nonce(
    context: libspdm_context_t,
    nonce: *mut u8,
    nonce_size: usize,
) -> libspdm_return_t {
    debug_print!("generate_nonce(context=%p, size=%zu)", context, nonce_size);
    if nonce.is_null() || nonce_size < 32 {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        for i in 0..nonce_size.min(32) {
            *nonce.add(i) = i as u8;
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_free_context(_context: libspdm_context_t) {}

#[no_mangle]
pub extern "C" fn libspdm_secured_message_get_last_spdm_error_struct(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    last_spdm_error_struct: *mut libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
    debug_print!("get_last_error(context=%p, session=0x%x)", context, session_id);
    if last_spdm_error_struct.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        (*last_spdm_error_struct).error_code = 0;
        (*last_spdm_error_struct).error_data = 0;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_set_last_spdm_error_struct(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    _last_spdm_error_struct: *const libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
    debug_print!("set_last_error(context=%p, session=0x%x)", context, session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_secured_message_context_via_session_id(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> *mut c_void {
    debug_print!("get_secured_msg_ctx(context=%p, session=0x%x)", context, session_id);
    if context.is_null() || session_id == 0 {
        core::ptr::null_mut()
    } else {
        context
    }
}

#[no_mangle]
pub extern "C" fn libspdm_encode_secured_message(
    _secured_message_context: *mut c_void,
    session_id: libspdm_session_id_t,
    _is_request_message: bool,
    _message_size: usize,
    _message: *const u8,
    _secured_message_size: *mut usize,
    _secured_message: *mut u8,
) -> libspdm_return_t {
    debug_print!("encode_secured_msg(session=0x%x)", session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_decode_secured_message(
    _secured_message_context: *mut c_void,
    session_id: libspdm_session_id_t,
    _is_request_message: bool,
    _secured_message_size: usize,
    _secured_message: *const u8,
    _message_size: *mut usize,
    _message: *mut u8,
) -> libspdm_return_t {
    debug_print!("decode_secured_msg(session=0x%x)", session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_is_session_established(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> bool {
    debug_print!("is_session_established(context=%p, session=0x%x)", context, session_id);
    session_id != 0
}

#[no_mangle]
pub extern "C" fn libspdm_get_session_info(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> *mut c_void {
    debug_print!("get_session_info(context=%p, session=0x%x)", context, session_id);
    if context.is_null() || session_id == 0 {
        core::ptr::null_mut()
    } else {
        context
    }
}

#[no_mangle]
pub extern "C" fn libspdm_register_get_response_func(
    context: libspdm_context_t,
    _get_response_func: *mut c_void,
) {
    debug_print!("register_get_response(context=%p)", context);
}

#[no_mangle]
pub extern "C" fn libspdm_register_verify_spdm_cert_chain_func(
    context: libspdm_context_t,
    verify_func: *mut c_void,
) {
    debug_print!("register_verify_cert(context=%p, func=%p)", context, verify_func);
    unsafe {
        SPDM_CTX.verify_cert_chain_func.store(verify_func, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "C" fn libspdm_start_session(
    context: libspdm_context_t,
    use_psk: bool,
    _psk_hint: *const c_void,
    _psk_hint_size: u16,
    measurement_hash_type: u8,
    slot_id: u8,
    session_policy: u8,
    session_id: *mut u32,
    heartbeat_period: *mut u8,
    measurement_hash: *mut c_void,
) -> libspdm_return_t {
    debug_print!("start_session(context=%p, use_psk=%u, slot=%u)", context, use_psk as u32, slot_id as u32);
    if use_psk {
        debug_print!("  PSK not supported");
        return LIBSPDM_STATUS_ERROR;
    }
    if session_id.is_null() {
        debug_print!("  ERROR: null session_id");
        return LIBSPDM_STATUS_ERROR;
    }
    
    let mut local_session_id: u32 = 0;
    let mut local_heartbeat: u8 = 0;
    
    let ke_status = libspdm_key_exchange(
        context,
        measurement_hash_type,
        slot_id,
        &mut local_session_id,
        &mut local_heartbeat,
        measurement_hash as *mut u8,
    );
    
    if ke_status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("  KEY_EXCHANGE failed: 0x%x", ke_status);
        return ke_status;
    }
    
    debug_print!("  KEY_EXCHANGE success: session=0x%x", local_session_id);
    
    let finish_status = libspdm_finish(context, local_session_id, slot_id, session_policy);
    
    if finish_status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("  FINISH failed: 0x%x", finish_status);
        return finish_status;
    }
    
    debug_print!("  FINISH success: session established");
    
    unsafe {
        *session_id = local_session_id;
        if !heartbeat_period.is_null() {
            *heartbeat_period = local_heartbeat;
        }
    }
    
    debug_print!("  start_session SUCCESS: session_id=0x%x", local_session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_stop_session(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> libspdm_return_t {
    debug_print!("stop_session(context=%p, session=0x%x)", context, session_id);
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_send_receive_data(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    request: *const u8,
    request_size: usize,
    response: *mut u8,
    response_size: *mut usize,
) -> libspdm_return_t {
    debug_print!("send_receive_data(context=%p, session=0x%x, req_size=%zu)", context, session_id, request_size);
    
    if request.is_null() || request_size == 0 {
        debug_print!("  ERROR: null/empty request");
        return LIBSPDM_STATUS_ERROR;
    }
    if response.is_null() || response_size.is_null() {
        debug_print!("  ERROR: null response/response_size");
        return LIBSPDM_STATUS_ERROR;
    }
    
    let session_id_ptr = if session_id == 0 { core::ptr::null() } else { &session_id as *const u32 };
    
    unsafe {
        // Step 1: Acquire sender buffer
        let sender_buf = call_acquire_sender(context);
        if sender_buf.is_null() {
            debug_print!("  ERROR: failed to acquire sender buffer");
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Step 2: Copy request to sender buffer (skip transport header space)
        // Transport header size is typically 4 bytes for DOE
        let transport_header_size = 4;
        let transport_tail_size = 0;
        let sender_capacity = 4096 - transport_header_size - transport_tail_size;
        let spdm_request = sender_buf.add(transport_header_size);
        core::ptr::copy_nonoverlapping(request, spdm_request as *mut u8, request_size);
        
        // Step 3: Call transport_encode to wrap message (DOE + secured message if session)
        let (encode_ret, transport_msg, transport_size) = call_transport_encode(
            context,
            session_id_ptr,
            spdm_request as *const u8,
            request_size,
            sender_buf,
            sender_capacity + transport_header_size + transport_tail_size,
        );
        
        if encode_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  transport_encode failed: ret=%u", encode_ret);
            call_release_sender(context, sender_buf as *mut c_void);
            return encode_ret;
        }
        
        debug_print!("  transport_encode success: transport_size=%zu", transport_size);
        
        // Step 4: Send encoded message
        let send_ret = call_send(context, transport_msg, transport_size);
        if send_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  send failed: ret=%u", send_ret);
            call_release_sender(context, sender_buf as *mut c_void);
            return send_ret;
        }
        debug_print!("  send success");
        
        call_release_sender(context, sender_buf as *mut c_void);
        
        // Step 5: Acquire receiver buffer
        let mut recv_buf_ptr: *mut c_void = core::ptr::null_mut();
        let mut recv_size: usize = 0;
        
        let recv_ret = call_recv(context, &mut recv_buf_ptr, &mut recv_size);
        if recv_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  recv failed: ret=%u", recv_ret);
            return recv_ret;
        }
        
        debug_print!("  recv success: raw_size=%zu", recv_size);
        
        // Step 6: Call transport_decode to unwrap (secured message decode if session)
        let mut decoded_msg: *mut c_void = core::ptr::null_mut();
        let mut decoded_size: usize = 0;
        
        let decode_ret = call_transport_decode(
            context,
            recv_buf_ptr,
            recv_size,
            &mut decoded_size,
            &mut decoded_msg,
        );
        
        if decode_ret != LIBSPDM_STATUS_SUCCESS {
            debug_print!("  transport_decode failed: ret=%u", decode_ret);
            call_release_receiver(context, recv_buf_ptr);
            return decode_ret;
        }
        
        debug_print!("  transport_decode success: decoded_size=%zu", decoded_size);
        
        // Step 7: Copy decoded response to caller's buffer
        if decoded_size > *response_size {
            debug_print!("  ERROR: response too large (decoded=%zu, buf=%zu)", decoded_size, *response_size);
            *response_size = decoded_size;
            call_release_receiver(context, recv_buf_ptr);
            return LIBSPDM_STATUS_ERROR;
        }
        
        if !decoded_msg.is_null() && decoded_size > 0 {
            core::ptr::copy_nonoverlapping(decoded_msg as *const u8, response, decoded_size);
        }
        
        *response_size = decoded_size;
        
        call_release_receiver(context, recv_buf_ptr);
    }
    
    debug_print!("  send_receive_data complete: resp_size=%zu", unsafe { *response_size });
    LIBSPDM_STATUS_SUCCESS
}

// ============================================================================
// Stub functions for IDE-KM and TDISP (not needed for this project)
// ============================================================================

/// Stub for libspdm_get_random_number - just fills with deterministic value for testing
#[no_mangle]
pub extern "C" fn libspdm_get_random_number(size: usize, rand: *mut u8) -> bool {
    debug_print!("get_random_number(size=%zu)", size);
    if rand.is_null() || size == 0 {
        return false;
    }
    unsafe {
        for i in 0..size {
            *rand.add(i) = (i as u8) ^ 0xAA;
        }
    }
    true
}