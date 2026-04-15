use core::ffi::c_void;

pub const LIBSPDM_STATUS_SUCCESS: u32 = 0;
pub const LIBSPDM_STATUS_ERROR: u32 = 1;
pub const LIBSPDM_STATUS_BUSY: u32 = 2;
pub const LIBSPDM_STATUS_RESYNC: u32 = 3;
pub const LIBSPDM_STATUS_BUFFER_FULL: u32 = 4;
pub const LIBSPDM_STATUS_BUFFER_TOO_SMALL: u32 = 5;

pub const LIBSPDM_HASH_SIZE_SHA256: usize = 32;
pub const LIBSPDM_HASH_SIZE_SHA384: usize = 48;

pub type libspdm_return_t = u32;
pub type libspdm_context_t = *mut c_void;
pub type libspdm_session_id_t = u32;

#[repr(C)]
pub struct libspdm_data_parameter_t {
    location: u8,
    additional_data: [u8; 4],
}

#[repr(C)]
pub struct libspdm_spdm_error_struct_t {
    error_code: u8,
    error_data: u8,
}

#[no_mangle]
pub extern "C" fn libspdm_init_context(context: libspdm_context_t) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_deinit_context(context: libspdm_context_t) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_init_connection(
    context: libspdm_context_t,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_check_context(context: libspdm_context_t) -> bool {
    if context.is_null() {
        return false;
    }
    true
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
pub extern "C" fn libspdm_get_measurement_ex(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    request_attribute: u8,
    measurement_operation: u8,
    slot_id: u8,
    number_of_blocks: *mut u8,
    measurement_record_length: *mut u32,
    measurement_record: *mut u8,
) -> libspdm_return_t {
    if context.is_null() {
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
pub extern "C" fn libspdm_get_random_number(
    context: libspdm_context_t,
    random_number_size: usize,
    random_number: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || random_number.is_null() {
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

#[no_mangle]
pub extern "C" fn libspdm_secured_message_get_last_spdm_error_struct(
    context: libspdm_context_t,
    session_id: libspdm_session_id_t,
    last_spdm_error_struct: *mut libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
    if context.is_null() || last_spdm_error_struct.is_null() {
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
    last_spdm_error_struct: *const libspdm_spdm_error_struct_t,
) -> libspdm_return_t {
    if context.is_null() || last_spdm_error_struct.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
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
    secured_message_context: *mut c_void,
    session_id: libspdm_session_id_t,
    is_request_message: bool,
    message_size: usize,
    message: *const u8,
    secured_message_size: *mut usize,
    secured_message: *mut u8,
) -> libspdm_return_t {
    if secured_message_context.is_null() || message.is_null() || secured_message.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_decode_secured_message(
    secured_message_context: *mut c_void,
    session_id: libspdm_session_id_t,
    is_request_message: bool,
    secured_message_size: usize,
    secured_message: *const u8,
    message_size: *mut usize,
    message: *mut u8,
) -> libspdm_return_t {
    if secured_message_context.is_null() || secured_message.is_null() || message.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_io_func(
    context: libspdm_context_t,
    send_message_func: *mut c_void,
    receive_message_func: *mut c_void,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_transport_layer_func(
    context: libspdm_context_t,
    transport_encode_message_func: *mut c_void,
    transport_decode_message_func: *mut c_void,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_device_buffer_func(
    context: libspdm_context_t,
    acquire_sender_buffer_func: *mut c_void,
    release_sender_buffer_func: *mut c_void,
    acquire_receiver_buffer_func: *mut c_void,
    release_receiver_buffer_func: *mut c_void,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_get_sizeof_required_scratch_buffer(
    context: libspdm_context_t,
) -> usize {
    if context.is_null() {
        return 0;
    }
    4096
}

#[no_mangle]
pub extern "C" fn libspdm_set_scratch_buffer(
    context: libspdm_context_t,
    scratch_buffer: *mut u8,
    scratch_buffer_size: usize,
) -> libspdm_return_t {
    if context.is_null() || scratch_buffer.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn libspdm_register_verify_spdm_cert_chain_func(
    context: libspdm_context_t,
    verify_spdm_cert_chain_func: *mut c_void,
) -> libspdm_return_t {
    if context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}