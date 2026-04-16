#![allow(unsafe_code)]

use core::ffi::c_void;

use crate::ffi::libspdm::{libspdm_return_t, LIBSPDM_STATUS_SUCCESS};

#[no_mangle]
pub extern "C" fn pci_ide_km_query(
    _pci_doe_context: *const c_void,
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _port_index: u8,
    _dev_func_num: *mut u8,
    _bus_num: *mut u8,
    _segment: *mut u8,
    _max_port_index: *mut u8,
    _ide_reg_buffer: *mut u32,
    _ide_reg_buffer_count: *mut u32,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_prog(
    _pci_doe_context: *const c_void,
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _stream_id: u8,
    _key_sub_stream: u8,
    _port_index: u8,
    _key_buffer: *const c_void,
    _kp_ack_status: *mut u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_set_go(
    _pci_doe_context: *const c_void,
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _stream_id: u8,
    _key_sub_stream: u8,
    _port_index: u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_set_stop(
    _pci_doe_context: *const c_void,
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _stream_id: u8,
    _key_sub_stream: u8,
    _port_index: u8,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_send_receive_data(
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _request: *const c_void,
    _request_size: usize,
    _response: *mut c_void,
    _response_size: *mut usize,
) -> libspdm_return_t {
    LIBSPDM_STATUS_SUCCESS
}