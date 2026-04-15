#![allow(unsafe_code)]

use core::ffi::c_void;

use crate::ffi::libspdm::{libspdm_return_t, LIBSPDM_STATUS_SUCCESS, LIBSPDM_STATUS_ERROR};

pub type pci_tdisp_context_t = *mut c_void;

#[repr(C)]
pub struct pci_tdisp_interface_id_t {
    function_id: u8,
    requester_stream_id: u16,
}

#[repr(C)]
pub struct pci_tdisp_requester_capabilities_t {
    flags: u64,
}

#[repr(C)]
pub struct pci_tdisp_responder_capabilities_t {
    flags: u64,
}

#[repr(C)]
pub struct pci_tdisp_lock_interface_param_t {
    lock_interface_flags: u64,
}

#[repr(C)]
pub struct pci_tdisp_interface_report_t {
    interface_report: [u8; 4096],
    interface_report_size: u16,
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_version(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    version: *mut u32,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || version.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *version = 0x00010000;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_capabilities(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    requester_capabilities: *const pci_tdisp_requester_capabilities_t,
    responder_capabilities: *mut pci_tdisp_responder_capabilities_t,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || responder_capabilities.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        (*responder_capabilities).flags = 0;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_interface_state(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    tdisp_state: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || tdisp_state.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *tdisp_state = 0;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_lock_interface(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    lock_interface_param: *const pci_tdisp_lock_interface_param_t,
    nonce: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || nonce.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_interface_report(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    interface_report: *mut pci_tdisp_interface_report_t,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || interface_report.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_start_interface(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
    nonce: *const u8,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() || nonce.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_stop_interface(
    context: pci_tdisp_context_t,
    session_id: u32,
    tdisp_id: *const pci_tdisp_interface_id_t,
) -> libspdm_return_t {
    if context.is_null() || tdisp_id.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}