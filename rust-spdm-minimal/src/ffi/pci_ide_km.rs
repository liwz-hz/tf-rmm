use core::ffi::c_void;

use crate::ffi::libspdm::{libspdm_return_t, LIBSPDM_STATUS_SUCCESS, LIBSPDM_STATUS_ERROR};

pub type pci_ide_km_context_t = *mut c_void;

#[repr(C)]
pub struct pci_ide_km_key_set_t {
    key_id: u8,
    key_select: u8,
    key: [u8; 32],
}

#[no_mangle]
pub extern "C" fn pci_ide_km_query(
    context: pci_ide_km_context_t,
    session_id: u32,
    port_index: u8,
    query_result: *mut u8,
) -> libspdm_return_t {
    if context.is_null() || query_result.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    unsafe {
        *query_result = 0;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_set_key(
    context: pci_ide_km_context_t,
    session_id: u32,
    port_index: u8,
    key_set: *const pci_ide_km_key_set_t,
) -> libspdm_return_t {
    if context.is_null() || key_set.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_get_key(
    context: pci_ide_km_context_t,
    session_id: u32,
    port_index: u8,
    key_id: u8,
    key_set: *mut pci_ide_km_key_set_t,
) -> libspdm_return_t {
    if context.is_null() || key_set.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_prog(
    context: pci_ide_km_context_t,
    session_id: u32,
    port_index: u8,
    key_set: *const pci_ide_km_key_set_t,
) -> libspdm_return_t {
    if context.is_null() || key_set.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    LIBSPDM_STATUS_SUCCESS
}