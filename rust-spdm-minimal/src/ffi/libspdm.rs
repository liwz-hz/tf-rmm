use core::ffi::c_void;

pub const LIBSPDM_STATUS_SUCCESS: u32 = 0;
pub const LIBSPDM_STATUS_ERROR: u32 = 1;
pub const LIBSPDM_STATUS_BUSY: u32 = 2;
pub const LIBSPDM_STATUS_RESYNC: u32 = 3;
pub const LIBSPDM_STATUS_BUFFER_FULL: u32 = 4;
pub const LIBSPDM_STATUS_BUFFER_TOO_SMALL: u32 = 5;

pub type libspdm_return_t = u32;
pub type libspdm_context_t = *mut c_void;
pub type libspdm_session_id_t = u32;

#[repr(C)]
pub struct libspdm_data_parameter_t {
    location: u8,
    additional_data: [u8; 4],
}

#[no_mangle]
pub extern "C" fn libspdm_init_context(context: libspdm_context_t) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_version(
    context: libspdm_context_t,
    version_count: *mut u8,
    version_number_entry: *mut u32,
) -> libspdm_return_t {
    if context.is_null() || version_count.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *version_count = 1;
        if !version_number_entry.is_null() {
            *version_number_entry = 0x12 << 24;
        }
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_capabilities(
    context: libspdm_context_t,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_negotiate_algorithms(
    context: libspdm_context_t,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_digests(
    context: libspdm_context_t,
    slot_mask: *mut u8,
    total_digest_buffer: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || slot_mask.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *slot_mask = 0x01;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_certificate(
    context: libspdm_context_t,
    slot_id: u8,
    cert_chain_size: *mut usize,
    cert_chain: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || cert_chain_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_key_exchange(
    context: libspdm_context_t,
    measurement_hash_type: u8,
    slot_id: u8,
    session_id: *mut libspdm_session_id_t,
    heartbeat_period: *mut u8,
    measurement_summary_hash: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || session_id.is_null() {
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
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    slot_id: u8,
    request_attribute: u8,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_end_session(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    end_session_attributes: u8,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_start_session(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_stop_session(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
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
    if context.is_null() || request.is_null() || response.is_null() || response_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_data(
    context: libspdm_context_t,
    data_type: u32,
    parameter: *const libspdm_data_parameter_t,
    data: *mut c_void,
    data_size: *mut usize,
) -> libspdm_return_t {
    if context.is_null() || data.is_null() || data_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_set_data(
    context: libspdm_context_t,
    data_type: u32,
    parameter: *const libspdm_data_parameter_t,
    data: *const c_void,
    data_size: usize,
) -> libspdm_return_t {
    if context.is_null() || data.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_process_message(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    message: *const u8,
    message_size: usize,
) -> libspdm_return_t {
    if context.is_null() || message.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_get_response_func(
    context: libspdm_context_t,
    get_response_func: *mut c_void,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_is_session_established(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
) -> bool {
    if context.is_null() {
        return false;
    }
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
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    request: *const u8,
    request_size: usize,
    response: *mut u8,
    response_size: *mut usize,
) -> libspdm_return_t {
    if context.is_null() || request.is_null() || response.is_null() || response_size.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_generate_nonce(
    context: libspdm_context_t,
    nonce: *mut u8,
    nonce_size: usize,
) -> libspdm_return_t {
    if context.is_null() || nonce.is_null() || nonce_size < 32 {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_free_context(context: libspdm_context_t) {
    if !context.is_null() {
    }
}

#[no_mangle]
pub extern "C" fn libspdm_reset_context(context: libspdm_context_t) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}