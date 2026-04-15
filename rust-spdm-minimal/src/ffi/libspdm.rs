use core::ffi::c_void;

pub const LIBSPDM_STATUS_SUCCESS: u32 = 0;
pub const LIBSPDM_STATUS_ERROR: u32 = 1;
pub const LIBSPDM_STATUS_BUSY: u32 = 2;
pub const LIBSPDM_STATUS_RESYNC: u32 = 3;
pub const LIBSPDM_STATUS_BUFFER_FULL: u32 = 4;
pub const LIBSPDM_STATUS_BUFFER_TOO_SMALL: u32 = 5;

pub const LIBSPDM_HASH_SIZE_SHA256: usize = 32;
pub const LIBSPDM_HASH_SIZE_SHA384: usize = 48;

pub const LIBSPDM_DATA_SPDM_VERSION: u32 = 0;
pub const LIBSPDM_DATA_SECURED_MESSAGE_VERSION: u32 = 1;
pub const LIBSPDM_DATA_CAPABILITY_FLAGS: u32 = 2;
pub const LIBSPDM_DATA_CAPABILITY_CT_EXPONENT: u32 = 3;
pub const LIBSPDM_DATA_CAPABILITY_RTT_US: u32 = 4;
pub const LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE: u32 = 5;
pub const LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE: u32 = 6;
pub const LIBSPDM_DATA_CONNECTION_STATE: u32 = 18;

pub const LIBSPDM_CONNECTION_STATE_NOT_STARTED: u32 = 0;
pub const LIBSPDM_CONNECTION_STATE_READY: u32 = 4;

pub const LIBSPDM_DEFAULT_DATA_TRANSFER_SIZE: u32 = 4096;

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

#[no_mangle]
pub extern "C" fn libspdm_init_context(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_deinit_context(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_reset_context(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_init_connection(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_check_context(_context: libspdm_context_t) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn libspdm_get_version(
    _context: libspdm_context_t,
    version_count: *mut u8,
    version_number_entry: *mut u32,
) -> libspdm_return_t {
    if version_count.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe { *version_count = 1; }
    if !version_number_entry.is_null() {
        unsafe { *version_number_entry = 0x00120000; }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_capabilities(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_negotiate_algorithms(_context: libspdm_context_t) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_digests(
    _context: libspdm_context_t,
    slot_mask: *mut u8,
    _total_digest_buffer: *mut u8,
) -> libspdm_return_t {
    if slot_mask.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe { *slot_mask = 0x01; }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_certificate(
    _context: libspdm_context_t,
    _slot_id: u8,
    cert_chain_size: *mut usize,
    _cert_chain: *mut u8,
) -> libspdm_return_t {
    if cert_chain_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe { *cert_chain_size = 0; }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_measurement_ex(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _request_attribute: u8,
    _measurement_operation: u8,
    _slot_id: u8,
    _number_of_blocks: *mut u8,
    _measurement_record_length: *mut u32,
    _measurement_record: *mut u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_key_exchange(
    _context: libspdm_context_t,
    _measurement_hash_type: u8,
    _slot_id: u8,
    session_id: *mut libspdm_session_id_t,
    heartbeat_period: *mut u8,
    _measurement_summary_hash: *mut u8,
) -> libspdm_return_t {
    if session_id.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *session_id = 0x12345678;
        if !heartbeat_period.is_null() {
            *heartbeat_period = 0;
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_finish(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _slot_id: u8,
    _request_attribute: u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_end_session(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _end_session_attributes: u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_start_session(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_stop_session(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_send_receive_data(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _request: *const u8,
    _request_size: usize,
    _response: *mut u8,
    _response_size: *mut usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_data(
    _context: libspdm_context_t,
    data_type: u32,
    _parameter: *const libspdm_data_parameter_t,
    data: *mut c_void,
    data_size: *mut usize,
) -> libspdm_return_t {
    if data.is_null() || data_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        match data_type {
            LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE => {
                *data_size = 4;
                *(data as *mut u32) = LIBSPDM_DEFAULT_DATA_TRANSFER_SIZE;
            }
            LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE => {
                *data_size = 4;
                *(data as *mut u32) = 4096;
            }
            LIBSPDM_DATA_CONNECTION_STATE => {
                *data_size = 4;
                *(data as *mut u32) = LIBSPDM_CONNECTION_STATE_READY;
            }
            LIBSPDM_DATA_BASE_HASH_ALGO => {
                *data_size = 4;
                *(data as *mut u32) = 0x0002;
            }
            _ => { *data_size = 0; }
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_set_data(
    _context: libspdm_context_t,
    _data_type: u32,
    _parameter: *const libspdm_data_parameter_t,
    _data: *const c_void,
    _data_size: usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_process_message(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _message: *const u8,
    _message_size: usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_get_response_func(
    _context: libspdm_context_t,
    _get_response_func: *mut c_void,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_is_session_established(
    _context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> bool {
    session_id != 0
}

#[no_mangle]
pub extern "C" fn libspdm_get_session_info(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> *mut c_void {
    if context.is_null() || session_id == 0 {
        return core::ptr::null_mut();
    }
    context
}

#[no_mangle]
pub extern "C" fn libspdm_secured_message_send_receive(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _request: *const u8,
    _request_size: usize,
    _response: *mut u8,
    _response_size: *mut usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_generate_nonce(
    _context: libspdm_context_t,
    nonce: *mut u8,
    nonce_size: usize,
) -> libspdm_return_t {
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
pub extern "C" fn libspdm_get_random_number(
    _context: libspdm_context_t,
    _random_number_size: usize,
    random_number: *mut u8,
) -> libspdm_return_t {
    if random_number.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_hash_size(hash_algo: u32) -> usize {
    match hash_algo {
        0x0002 => LIBSPDM_HASH_SIZE_SHA256,
        0x0004 => LIBSPDM_HASH_SIZE_SHA384,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn libspdm_free_context(_context: libspdm_context_t) {}

#[no_mangle]
pub extern "C" fn libspdm_secured_message_get_last_spdm_error_struct(
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    last_spdm_error_struct: *mut libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
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
    _context: libspdm_context_t,
    _session_id: libspdm_session_id_t,
    _last_spdm_error_struct: *const libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_secured_message_context_via_session_id(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> *mut c_void {
    if context.is_null() || session_id == 0 {
        return core::ptr::null_mut();
    }
    context
}

#[no_mangle]
pub extern "C" fn libspdm_encode_secured_message(
    _secured_message_context: *mut c_void,
    _session_id: libspdm_session_id_t,
    _is_request_message: bool,
    _message_size: usize,
    _message: *const u8,
    _secured_message_size: *mut usize,
    _secured_message: *mut u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_decode_secured_message(
    _secured_message_context: *mut c_void,
    _session_id: libspdm_session_id_t,
    _is_request_message: bool,
    _secured_message_size: usize,
    _secured_message: *const u8,
    _message_size: *mut usize,
    _message: *mut u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_io_func(
    _context: libspdm_context_t,
    _send_message_func: *mut c_void,
    _receive_message_func: *mut c_void,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_transport_layer_func(
    _context: libspdm_context_t,
    _transport_encode_message_func: *mut c_void,
    _transport_decode_message_func: *mut c_void,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_buffer_func(
    _context: libspdm_context_t,
    _acquire_sender_buffer_func: *mut c_void,
    _release_sender_buffer_func: *mut c_void,
    _acquire_receiver_buffer_func: *mut c_void,
    _release_receiver_buffer_func: *mut c_void,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_sizeof_required_scratch_buffer(_context: libspdm_context_t) -> usize {
    4096
}

#[no_mangle]
pub extern "C" fn libspdm_set_scratch_buffer(
    _context: libspdm_context_t,
    _scratch_buffer: *mut u8,
    _scratch_buffer_size: usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_verify_spdm_cert_chain_func(
    _context: libspdm_context_t,
    _verify_spdm_cert_chain_func: *mut c_void,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}