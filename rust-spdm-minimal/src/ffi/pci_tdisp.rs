#![allow(unsafe_code)]

use core::ffi::c_void;
use crate::ffi::libspdm::{libspdm_return_t, libspdm_send_receive_data, LIBSPDM_STATUS_SUCCESS, LIBSPDM_STATUS_ERROR};

extern "C" {
    fn printf(fmt: *const i8, ...);
}

macro_rules! debug_print {
    ($s:expr) => {
        unsafe { printf(concat!("[RUST_TDISP] ", $s, "\n\0").as_ptr() as *const i8); }
    };
    ($s:expr, $a:expr) => {
        unsafe { printf(concat!("[RUST_TDISP] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr) => {
        unsafe { printf(concat!("[RUST_TDISP] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr) => {
        unsafe { printf(concat!("[RUST_TDISP] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint); }
    };
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        unsafe { printf(concat!("[RUST_TDISP] ", $s, "\n\0").as_ptr() as *const i8, $a as core::ffi::c_uint, $b as core::ffi::c_uint, $c as core::ffi::c_uint, $d as core::ffi::c_uint); }
    };
}

// Constants from pci_tdisp.h
pub const PCI_PROTOCOL_ID_TDISP: u8 = 0x01;
pub const PCI_TDISP_MESSAGE_VERSION_10: u8 = 0x10;

// TDISP request codes
pub const PCI_TDISP_GET_VERSION: u8 = 0x81;
pub const PCI_TDISP_GET_CAPABILITIES: u8 = 0x82;
pub const PCI_TDISP_LOCK_INTERFACE_REQ: u8 = 0x83;
pub const PCI_TDISP_GET_DEVICE_INTERFACE_REPORT: u8 = 0x84;
pub const PCI_TDISP_GET_DEVICE_INTERFACE_STATE: u8 = 0x85;
pub const PCI_TDISP_START_INTERFACE_REQ: u8 = 0x86;
pub const PCI_TDISP_STOP_INTERFACE_REQ: u8 = 0x87;

// TDISP response codes
pub const PCI_TDISP_VERSION: u8 = 0x01;
pub const PCI_TDISP_CAPABILITIES: u8 = 0x02;
pub const PCI_TDISP_LOCK_INTERFACE_RSP: u8 = 0x03;
pub const PCI_TDISP_DEVICE_INTERFACE_REPORT: u8 = 0x04;
pub const PCI_TDISP_DEVICE_INTERFACE_STATE: u8 = 0x05;
pub const PCI_TDISP_START_INTERFACE_RSP: u8 = 0x06;
pub const PCI_TDISP_STOP_INTERFACE_RSP: u8 = 0x07;
pub const PCI_TDISP_ERROR: u8 = 0x7F;

// Interface states
pub const PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED: u8 = 0;
pub const PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED: u8 = 1;
pub const PCI_TDISP_INTERFACE_STATE_RUN: u8 = 2;
pub const PCI_TDISP_INTERFACE_STATE_ERROR: u8 = 3;

// SPDM constants
pub const SPDM_VENDOR_DEFINED_REQUEST: u8 = 0xFE;
pub const SPDM_VENDOR_DEFINED_RESPONSE: u8 = 0x7E;
pub const SPDM_STANDARD_ID_PCISIG: u16 = 0x0003;
pub const SPDM_VENDOR_ID_PCISIG: u16 = 0x0001;

pub const PCI_TDISP_START_INTERFACE_NONCE_SIZE: usize = 32;
const MAX_TDISP_SIZE: usize = 256;

// DOE vendor defined header (8 bytes)
#[repr(C, packed)]
pub struct PciDoeVendorHeader {
    pub standard_id: u16,
    pub len: u8,
    pub vendor_id: u16,
    pub payload_length: u16,
    pub pci_protocol: u8,
}

// SPDM VDM request header (4 + 8 = 12 bytes)
#[repr(C, packed)]
pub struct SpdmVendorDefinedRequest {
    pub spdm_version: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub doe_vendor_header: PciDoeVendorHeader,
}

// SPDM VDM response header (4 + 8 = 12 bytes)
#[repr(C, packed)]
pub struct SpdmVendorDefinedResponse {
    pub spdm_version: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub doe_vendor_header: PciDoeVendorHeader,
}

// TDISP header (16 bytes)
#[repr(C, packed)]
pub struct PciTdispHeader {
    pub version: u8,
    pub message_type: u8,
    pub reserved: [u8; 2],
    pub interface_id: [u8; 12],
}

// TDISP get_version response (17 bytes minimum)
#[repr(C, packed)]
pub struct PciTdispVersionResponse {
    pub header: PciTdispHeader,
    pub version_num_count: u8,
    pub version_num_entry: u8,
}

// TDISP get_capabilities request (20 bytes)
#[repr(C, packed)]
pub struct PciTdispGetCapabilitiesRequest {
    pub header: PciTdispHeader,
    pub req_caps: u32,
}

// TDISP capabilities response (48 bytes)
#[repr(C, packed)]
pub struct PciTdispCapabilitiesResponse {
    pub header: PciTdispHeader,
    pub dsm_caps: u32,
    pub req_msg_supported: [u8; 16],
    pub lock_interface_flags_supported: u16,
    pub reserved: [u8; 3],
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
}

// TDISP lock_interface request (32 bytes)
#[repr(C, packed)]
pub struct PciTdispLockInterfaceRequest {
    pub header: PciTdispHeader,
    pub flags: u16,
    pub default_stream_id: u8,
    pub reserved1: u8,
    pub mmio_reporting_offset: u64,
    pub bind_p2p_address_mask: u64,
}

// TDISP lock_interface response (48 bytes)
#[repr(C, packed)]
pub struct PciTdispLockInterfaceResponse {
    pub header: PciTdispHeader,
    pub start_interface_nonce: [u8; 32],
}

// TDISP state response (17 bytes)
#[repr(C, packed)]
pub struct PciTdispStateResponse {
    pub header: PciTdispHeader,
    pub tdi_state: u8,
}

// TDISP start interface request (16 + 32 = 48 bytes)
#[repr(C, packed)]
pub struct PciTdispStartInterfaceRequest {
    pub header: PciTdispHeader,
    pub start_interface_nonce: [u8; 32],
}

// TDISP start interface response (16 bytes)
#[repr(C, packed)]
pub struct PciTdispStartInterfaceResponse {
    pub header: PciTdispHeader,
}

// TDISP stop interface request (16 bytes)
#[repr(C, packed)]
pub struct PciTdispStopInterfaceRequest {
    pub header: PciTdispHeader,
}

// TDISP stop interface response (16 bytes)
#[repr(C, packed)]
pub struct PciTdispStopInterfaceResponse {
    pub header: PciTdispHeader,
}

// Send TDISP message via SPDM VDM
fn pci_tdisp_send_receive_vdm(
    spdm_context: *mut c_void,
    session_id: *const u32,
    tdisp_message_type: u8,
    tdisp_request: *const u8,
    tdisp_request_size: usize,
    tdisp_response: *mut u8,
    tdisp_response_size: *mut usize,
) -> libspdm_return_t {
    let tdisp_rsp_size_ref = unsafe { &mut *tdisp_response_size };
    let vdm_req_size = 12 + tdisp_request_size;
    let mut vdm_request: [u8; 12 + MAX_TDISP_SIZE] = [0; 12 + MAX_TDISP_SIZE];
    
    let vdm_rsp_size = 12 + *tdisp_rsp_size_ref + 1;
    let mut vdm_response: [u8; 12 + MAX_TDISP_SIZE] = [0; 12 + MAX_TDISP_SIZE];
    
    if tdisp_request_size > MAX_TDISP_SIZE || *tdisp_rsp_size_ref > MAX_TDISP_SIZE {
        debug_print!("TDISP: request/response too large");
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Build SPDM VDM request header
    // Use SPDM version 1.2 (0x12)
    let spdm_req = SpdmVendorDefinedRequest {
        spdm_version: 0x12,
        request_response_code: SPDM_VENDOR_DEFINED_REQUEST,
        param1: 0,
        param2: 0,
        doe_vendor_header: PciDoeVendorHeader {
            standard_id: SPDM_STANDARD_ID_PCISIG,
            len: 2, // sizeof vendor_id
            vendor_id: SPDM_VENDOR_ID_PCISIG,
            payload_length: (1 + tdisp_request_size) as u16, // pci_protocol(1) + payload
            pci_protocol: PCI_PROTOCOL_ID_TDISP,
        },
    };
    
    unsafe {
        // Copy SPDM header
        core::ptr::copy_nonoverlapping(
            &spdm_req as *const SpdmVendorDefinedRequest as *const u8,
            vdm_request.as_mut_ptr(),
            12,
        );
        
        // Copy TDISP payload
        core::ptr::copy_nonoverlapping(
            tdisp_request,
            vdm_request.as_mut_ptr().add(12),
            tdisp_request_size,
        );
    }
    
    extern "C" {
        fn printf(fmt: *const i8, ...);
        fn fflush(stream: *mut core::ffi::c_void) -> i32;
    }
    unsafe { 
        printf(b"[RUST-TDISP] pci_tdisp_send_receive_vdm type=0x%x req_size=%zu\n\0".as_ptr() as *const i8, tdisp_message_type as u32, vdm_req_size);
        fflush(0 as *mut core::ffi::c_void);
    }
    
    let mut actual_rsp_size = vdm_rsp_size;
    let status = libspdm_send_receive_data(
        spdm_context,
        session_id,
        false,
        vdm_request.as_ptr(),
        vdm_req_size,
        vdm_response.as_mut_ptr(),
        &mut actual_rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("TDISP VDM: send_receive_data failed");
        return status;
    }
    
    // Parse VDM response
    if actual_rsp_size < 12 {
        debug_print!("TDISP VDM: response too small (%zu)", actual_rsp_size);
        return LIBSPDM_STATUS_ERROR;
    }
    
    let spdm_rsp = unsafe {
        &*(vdm_response.as_ptr() as *const SpdmVendorDefinedResponse)
    };
    
    // Validate response header
    if spdm_rsp.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE {
        debug_print!("TDISP VDM: wrong response code 0x%x", spdm_rsp.request_response_code);
        return LIBSPDM_STATUS_ERROR;
    }
    
    if spdm_rsp.doe_vendor_header.pci_protocol != PCI_PROTOCOL_ID_TDISP {
        debug_print!("TDISP VDM: wrong protocol 0x%x", spdm_rsp.doe_vendor_header.pci_protocol);
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Extract TDISP payload
    let tdisp_payload_size = spdm_rsp.doe_vendor_header.payload_length as usize;
    if tdisp_payload_size < 1 {
        debug_print!("TDISP VDM: payload too small");
        return LIBSPDM_STATUS_ERROR;
    }
    
    // payload_length includes pci_protocol byte, so actual TDISP size is payload_length - 1
    let actual_tdisp_size = tdisp_payload_size - 1;
    
    unsafe {
        if actual_tdisp_size > *tdisp_response_size {
            debug_print!("TDISP VDM: TDISP response too large");
            *tdisp_response_size = actual_tdisp_size;
            return LIBSPDM_STATUS_ERROR;
        }
        
        // Copy TDISP response to caller's buffer (skip DOE header 12 bytes)
        core::ptr::copy_nonoverlapping(
            vdm_response.as_ptr().add(12),
            tdisp_response,
            actual_tdisp_size,
        );
        
        *tdisp_response_size = actual_tdisp_size;
    }
    
    debug_print!("TDISP VDM: received type=0x%x size=%zu", tdisp_message_type, actual_tdisp_size);
    
    LIBSPDM_STATUS_SUCCESS
}

// Build interface_id from function_id
fn build_interface_id(function_id: u32) -> [u8; 12] {
    let mut id = [0u8; 12];
    id[0] = (function_id & 0xFF) as u8;
    id[1] = ((function_id >> 8) & 0xFF) as u8;
    id[2] = ((function_id >> 16) & 0xFF) as u8;
    id[3] = ((function_id >> 24) & 0xFF) as u8;
    id
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_version(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
) -> libspdm_return_t {
    extern "C" {
        fn printf(fmt: *const i8, ...);
        fn fflush(stream: *mut core::ffi::c_void) -> i32;
    }
    unsafe {
        printf(b"[RUST-TDISP] pci_tdisp_get_version ENTRY\n\0".as_ptr() as *const i8);
        fflush(0 as *mut core::ffi::c_void);
    }
    
    if spdm_context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    let function_id = unsafe { *(interface_id as *const u32) };
    
    let request = PciTdispHeader {
        version: PCI_TDISP_MESSAGE_VERSION_10,
        message_type: PCI_TDISP_GET_VERSION,
        reserved: [0, 0],
        interface_id: build_interface_id(function_id),
    };
    
    let mut response: PciTdispVersionResponse = unsafe { core::mem::zeroed() };
    let mut rsp_size = core::mem::size_of::<PciTdispVersionResponse>();
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_GET_VERSION,
        &request as *const PciTdispHeader as *const u8,
        16,
        &mut response as *mut PciTdispVersionResponse as *mut u8,
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("pci_tdisp_get_version: send_receive failed");
        return status;
    }
    
    if rsp_size != core::mem::size_of::<PciTdispVersionResponse>() {
        debug_print!("pci_tdisp_get_version: invalid response size %zu", rsp_size);
        return LIBSPDM_STATUS_ERROR;
    }
    
    if response.header.message_type != PCI_TDISP_VERSION {
        debug_print!("pci_tdisp_get_version: wrong message_type 0x%x", response.header.message_type);
        return LIBSPDM_STATUS_ERROR;
    }
    
    if response.version_num_count != 1 || response.version_num_entry != PCI_TDISP_MESSAGE_VERSION_10 {
        debug_print!("pci_tdisp_get_version: invalid version");
        return LIBSPDM_STATUS_ERROR;
    }
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_capabilities(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
    req_caps: *const c_void,
    rsp_caps: *mut c_void,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_get_capabilities");
    
    if spdm_context.is_null() || req_caps.is_null() || rsp_caps.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    let function_id = unsafe { *(interface_id as *const u32) };
    let req_caps_val = unsafe { *(req_caps as *const u32) };
    
    let request = PciTdispGetCapabilitiesRequest {
        header: PciTdispHeader {
            version: PCI_TDISP_MESSAGE_VERSION_10,
            message_type: PCI_TDISP_GET_CAPABILITIES,
            reserved: [0, 0],
            interface_id: build_interface_id(function_id),
        },
        req_caps: req_caps_val,
    };
    
    let mut response: PciTdispCapabilitiesResponse = unsafe { core::mem::zeroed() };
    let mut rsp_size = core::mem::size_of::<PciTdispCapabilitiesResponse>();
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_GET_CAPABILITIES,
        &request as *const PciTdispGetCapabilitiesRequest as *const u8,
        20,
        &mut response as *mut PciTdispCapabilitiesResponse as *mut u8,
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("pci_tdisp_get_capabilities: send_receive failed");
        return status;
    }
    
    if rsp_size != core::mem::size_of::<PciTdispCapabilitiesResponse>() {
        debug_print!("pci_tdisp_get_capabilities: invalid response size");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if response.header.message_type != PCI_TDISP_CAPABILITIES {
        debug_print!("pci_tdisp_get_capabilities: wrong message_type");
        return LIBSPDM_STATUS_ERROR;
    }
    
    unsafe {
        let rsp_caps_ptr = rsp_caps as *mut u8;
        let resp_ptr = &response as *const PciTdispCapabilitiesResponse as *const u8;
        core::ptr::copy_nonoverlapping(
            resp_ptr.add(16),
            rsp_caps_ptr,
            32,
        );
    }
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_lock_interface(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
    lock_interface_param: *const c_void,
    start_interface_nonce: *mut u8,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_lock_interface");
    
    if spdm_context.is_null() || lock_interface_param.is_null() || start_interface_nonce.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    let function_id = unsafe { *(interface_id as *const u32) };
    
    let mut request: PciTdispLockInterfaceRequest = unsafe { core::mem::zeroed() };
    request.header.version = PCI_TDISP_MESSAGE_VERSION_10;
    request.header.message_type = PCI_TDISP_LOCK_INTERFACE_REQ;
    request.header.interface_id = build_interface_id(function_id);
    
    unsafe {
        let req_ptr = &mut request as *mut PciTdispLockInterfaceRequest as *mut u8;
        core::ptr::copy_nonoverlapping(
            lock_interface_param as *const u8,
            req_ptr.add(16),
            16,
        );
    }
    
    let mut response: PciTdispLockInterfaceResponse = unsafe { core::mem::zeroed() };
    let mut rsp_size = core::mem::size_of::<PciTdispLockInterfaceResponse>();
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_LOCK_INTERFACE_REQ,
        &request as *const PciTdispLockInterfaceRequest as *const u8,
        32,
        &mut response as *mut PciTdispLockInterfaceResponse as *mut u8,
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("pci_tdisp_lock_interface: send_receive failed");
        return status;
    }
    
    if rsp_size != core::mem::size_of::<PciTdispLockInterfaceResponse>() {
        debug_print!("pci_tdisp_lock_interface: invalid response size");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if response.header.message_type != PCI_TDISP_LOCK_INTERFACE_RSP {
        debug_print!("pci_tdisp_lock_interface: wrong message_type");
        return LIBSPDM_STATUS_ERROR;
    }
    
    unsafe {
        core::ptr::copy_nonoverlapping(
            response.start_interface_nonce.as_ptr(),
            start_interface_nonce,
            PCI_TDISP_START_INTERFACE_NONCE_SIZE,
        );
    }
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_interface_report(
    _pci_doe_context: *const c_void,
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _interface_id: *const c_void,
    _interface_report: *mut u8,
    _interface_report_size: *mut u32,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_get_interface_report (stub)");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_get_interface_state(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
    tdi_state: *mut u8,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_get_interface_state");
    
    if spdm_context.is_null() || tdi_state.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Build TDISP GET_STATE request
    let function_id = unsafe { *(interface_id as *const u32) };
    let tdisp_req = PciTdispHeader {
        version: PCI_TDISP_MESSAGE_VERSION_10,
        message_type: PCI_TDISP_GET_DEVICE_INTERFACE_STATE,
        reserved: [0, 0],
        interface_id: build_interface_id(function_id),
    };
    
    // Send request
    let mut tdisp_rsp: [u8; 17] = [0; 17];
    let mut rsp_size = 17;
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_GET_DEVICE_INTERFACE_STATE,
        &tdisp_req as *const PciTdispHeader as *const u8,
        16,
        tdisp_rsp.as_mut_ptr(),
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("get_interface_state: VDM failed");
        return status;
    }
    
    if rsp_size < 17 {
        debug_print!("get_interface_state: response too small");
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Parse response
    let rsp = unsafe { &*(tdisp_rsp.as_ptr() as *const PciTdispStateResponse) };
    
    if rsp.header.message_type == PCI_TDISP_ERROR {
        debug_print!("get_interface_state: TDISP ERROR");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if rsp.header.message_type != PCI_TDISP_DEVICE_INTERFACE_STATE {
        debug_print!("get_interface_state: wrong response type 0x%x", rsp.header.message_type);
        return LIBSPDM_STATUS_ERROR;
    }
    
    unsafe { *tdi_state = rsp.tdi_state; }
    debug_print!("get_interface_state: state=%u", rsp.tdi_state);
    
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_start_interface(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
    start_interface_nonce: *const u8,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_start_interface");
    
    if spdm_context.is_null() || start_interface_nonce.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Build TDISP START_INTERFACE request
    let function_id = unsafe { *(interface_id as *const u32) };
    let mut nonce_copy = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(start_interface_nonce, nonce_copy.as_mut_ptr(), 32);
    }
    
    let tdisp_req = PciTdispStartInterfaceRequest {
        header: PciTdispHeader {
            version: PCI_TDISP_MESSAGE_VERSION_10,
            message_type: PCI_TDISP_START_INTERFACE_REQ,
            reserved: [0, 0],
            interface_id: build_interface_id(function_id),
        },
        start_interface_nonce: nonce_copy,
    };
    
    // Send request
    let mut tdisp_rsp: [u8; 16] = [0; 16];
    let mut rsp_size = 16;
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_START_INTERFACE_REQ,
        &tdisp_req as *const PciTdispStartInterfaceRequest as *const u8,
        48, // header(16) + nonce(32)
        tdisp_rsp.as_mut_ptr(),
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("start_interface: VDM failed");
        return status;
    }
    
    if rsp_size < 16 {
        debug_print!("start_interface: response too small");
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Parse response
    let rsp = unsafe { &*(tdisp_rsp.as_ptr() as *const PciTdispStartInterfaceResponse) };
    
    if rsp.header.message_type == PCI_TDISP_ERROR {
        debug_print!("start_interface: TDISP ERROR");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if rsp.header.message_type != PCI_TDISP_START_INTERFACE_RSP {
        debug_print!("start_interface: wrong response type 0x%x", rsp.header.message_type);
        return LIBSPDM_STATUS_ERROR;
    }
    
    debug_print!("start_interface: SUCCESS");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_stop_interface(
    _pci_doe_context: *const c_void,
    spdm_context: *mut c_void,
    session_id: *const u32,
    interface_id: *const c_void,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_stop_interface");
    
    if spdm_context.is_null() {
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Build TDISP STOP_INTERFACE request
    let function_id = unsafe { *(interface_id as *const u32) };
    let tdisp_req = PciTdispStopInterfaceRequest {
        header: PciTdispHeader {
            version: PCI_TDISP_MESSAGE_VERSION_10,
            message_type: PCI_TDISP_STOP_INTERFACE_REQ,
            reserved: [0, 0],
            interface_id: build_interface_id(function_id),
        },
    };
    
    // Send request
    let mut tdisp_rsp: [u8; 16] = [0; 16];
    let mut rsp_size = 16;
    
    let status = pci_tdisp_send_receive_vdm(
        spdm_context,
        session_id,
        PCI_TDISP_STOP_INTERFACE_REQ,
        &tdisp_req as *const PciTdispStopInterfaceRequest as *const u8,
        16,
        tdisp_rsp.as_mut_ptr(),
        &mut rsp_size,
    );
    
    if status != LIBSPDM_STATUS_SUCCESS {
        debug_print!("stop_interface: VDM failed");
        return status;
    }
    
    if rsp_size < 16 {
        debug_print!("stop_interface: response too small");
        return LIBSPDM_STATUS_ERROR;
    }
    
    // Parse response
    let rsp = unsafe { &*(tdisp_rsp.as_ptr() as *const PciTdispStopInterfaceResponse) };
    
    if rsp.header.message_type == PCI_TDISP_ERROR {
        debug_print!("stop_interface: TDISP ERROR");
        return LIBSPDM_STATUS_ERROR;
    }
    
    if rsp.header.message_type != PCI_TDISP_STOP_INTERFACE_RSP {
        debug_print!("stop_interface: wrong response type 0x%x", rsp.header.message_type);
        return LIBSPDM_STATUS_ERROR;
    }
    
    debug_print!("stop_interface: SUCCESS");
    LIBSPDM_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn pci_tdisp_send_receive_data(
    _spdm_context: *mut c_void,
    _session_id: *const u32,
    _request: *const c_void,
    _request_size: usize,
    _response: *mut c_void,
    _response_size: *mut usize,
) -> libspdm_return_t {
    debug_print!("pci_tdisp_send_receive_data (deprecated stub)");
    LIBSPDM_STATUS_SUCCESS
}