# TF-RMM Rust SPDM Library Replacement Project

## Project Overview

### Goal
实现 `rust-spdm-minimal` 完全替换 tf-rmm 项目中的 libspdm C 库，使 Rust 版本能像 C 版本一样完整运行，包括所有 SPDM/TDISP 协议流程和 DESTROY 清理操作，最终 Exit code: 0。

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        rmm.elf                                   │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │              rmm-app-dev-assign-elf                        │ │
│  │       (Device Assignment EL0 App)                          │ │
│  │                                                            │ │
│  │   C Layer:                                                 │ │
│  │   dev_tdisp_cmds.c → pci_tdisp_xxx()                       │ │
│  │       → pci_doe_spdm_vendor_send_receive_data()            │ │
│  │                                                            │ │
│  │   Rust Layer (rust-spdm-minimal):                          │ │
│  │   libspdm_send_receive_data()                              │ │
│  │       → transport_encode/decode callbacks                  │ │
│  │       → AES-256-GCM secured message handling               │ │
│  │                                                            │ │
│  │   Platform Layer:                                          │ │
│  │   host_spdm_rsp_ifc.c → TCP socket (port 2323)            │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ TCP/DOE
                              ▼
                    spdm_responder_emu (Responder)
                    ext/spdm-emu/ (External Process)
```

## Build Commands

**使用 Python 脚本构建 - 不要直接运行 cmake:**

```bash
# 使用 C 库 (默认)
python tfrmm.py build

# 使用 Rust 库
python tfrmm.py build --spdm-lib=rust

# 清理构建
python tfrmm.py build --clean --spdm-lib=rust

# 运行测试
python tfrmm.py run --spdm-lib=rust

# 完整流程
python tfrmm.py all --spdm-lib=rust
```

**CMake 切换方式:**
```bash
# Rust库
cmake .. -DRMM_CONFIG=host_defcfg -DLOG_LEVEL=40 -DRMM_USE_RUST_SPDM=ON

# C库
cmake .. -DRMM_CONFIG=host_defcfg -DLOG_LEVEL=40 -DRMM_USE_RUST_SPDM=OFF
```

Build output: `build/Release/rmm.elf`

---

## SPDM/TDISP Protocol Flow

### Complete Protocol Sequence

```
PDEV_CREATE
    │
    ▼
[Stage 1] init_connection()
    │  GET_VERSION → VERSION (spdm_request_len cleared)
    │  GET_CAPABILITIES → CAPABILITIES (spdm_request_len cleared)
    │  NEGOTIATE_ALGORITHMS → ALGORITHMS (spdm_request_len cleared)
    ▼
[Stage 2] get_digests() + get_certificate()
    │  GET_DIGESTS → DIGESTS
    │  GET_CERTIFICATE → CERTIFICATE (chunks, accumulate cert_chain)
    │  cert_chain_len = 1539 bytes
    ▼
[Stage 2] key_exchange()
    │  KEY_EXCHANGE → KEY_EXCHANGE_RSP
    │  session_id = 0xFFFFFFFF (calc: (rsp << 16) | req)
    │  TH1/TH2 transcript computation
    │  finish() → FINISH_RSP
    ▼
[Stage 2] challenge()
    │  CHALLENGE → CHALLENGE_AUTH
    │  Verify cert_chain, extract public key
    ▼
PDEV_HAS_KEY state
    │
    ▼
[Stage 4] VDEV_ASSIGN
    │
    ▼
[Stage 6] TDISP Lock/Start (via secured session)
    │  pci_tdisp_lock_interface() (session_id required)
    │  pci_tdisp_start_interface() (session_id required)
    │  Secured messages: AES-256-GCM encrypted
    ▼
VDEV_RUN state
    │
    ▼
[Cleanup] DESTROY flow
    │  VDEV_UNLOCK → END_SESSION
    │  VDEV_DESTROY
    │  PDEV_STOP
    │  PDEV_DESTROY
    │  REALM_DESTROY
    ▼
Exit code: 0
```

---

## Debugging Methodology

### Comparison Testing

**核心方法: 对比 C 库和 Rust 库的输出**

```bash
# Run C library
python tfrmm.py build --spdm-lib=c
python tfrmm.py run --spdm-lib=c > c_output.log

# Run Rust library
python tfrmm.py build --spdm-lib=rust
python tfrmm.py run --spdm-lib=rust > rust_output.log

# Compare key metrics
diff c_output.log rust_output.log
grep "cert_chain_len" *.log
grep "session_id" *.log
grep "flags=0x" *.log  # Request/Response caching flags
```

### Key Debug Output Patterns

```
[HOST_DEBUG] cache_dev_req_resp: flags=0x3 REQ_CACHE=1 RSP_CACHE=1
[HOST_DEBUG] cache_dev_req_resp: flags=0x6 REQ_CACHE=0 RSP_CACHE=1
[HOST_DEBUG] pdev_cache_object: obj_id=1 buf_len=972 cert_chain_len=0
[RUST] key_exchange SUCCESS: session_id=0xffffffff
[RUST] transport_decode returned: ret=0
```

### Flags Interpretation

| flags | Meaning | When to appear |
|-------|---------|----------------|
| `0x3` (REQ_CACHE + RSP_CACHE) | Both request and response cached | VERSION first response (clears spdm_request_len) |
| `0x6` (RSP_CACHE only) | Only response cached | After spdm_request_len cleared |
| `0x2` (RSP_CACHE bit) | Response only | Normal operation |

---

## Completed Fixes (10 Critical Issues)

### 1. Session ID Formula Fix (commit 6804cd2)

**Problem**: Hardcoded session_id mismatch
**Fix**: `(rsp_session_id << 16) | req_session_id`
**Code**: `libspdm_start_session()` in `rust-spdm-minimal/src/ffi/libspdm.rs`

### 2. req_session_id Value Fix (commit 6804cd2)

**Problem**: Hardcoded 0x1234
**Fix**: Use 0xFFFF (matches C's `LIBSPDM_MAX_SESSION_COUNT`)
**Code**: KEY_EXCHANGE request building

### 3. VERSION DOE Padding Trim (commit 6804cd2)

**Problem**: Using DOE-padded size instead of actual SPDM message size
**Fix**: Calculate actual size from response content
**Code**: `init_connection()` - `actual_rsp_size = 6 + version_count * 2`

### 4. Certificate Caching (commit 9008fd1)

**Problem**: cert_chain not being populated
**Fix**: Call `transport_decode` after each CERTIFICATE chunk to trigger `cma_spdm_cache_certificate`
**Code**: `get_certificate()` line 1612-1622

### 5. TH1 Transcript Storage Fix

**Problem**: Request bytes overwritten by recv()
**Fix**: Save request bytes BEFORE calling recv()
**Code**: KEY_EXCHANGE - `saved_request_bytes` array

### 6. Transport_encode Parameters Fix (commit a725a0f)

**Problem**: Wrong SPDM message pointer and buffer capacity
**Fix**: Pass SPDM message pointer (not transport buffer) and full buffer capacity
**Code**: `call_transport_encode()` signature

### 7. TDISP Stub Functions (commit a366a9c)

**Problem**: TDISP functions unimplemented
**Fix**: Implement `pci_tdisp_get_version`, `pci_tdisp_get_capabilities`, `pci_tdisp_lock_interface`
**Code**: `rust-spdm-minimal/src/ffi/libspdm.rs` lines 3400-3700

### 8. AES-256-GCM Implementation (commit 8bd2e8f)

**Problem**: Secured messages couldn't be encrypted/decrypted
**Fix**: Full AES-256-GCM implementation for secured message encoding/decoding
**Code**: `libspdm_encode_secured_message`, `libspdm_decode_secured_message`

### 9. Transport_decode Buffer Capacity (commit c544e29)

**Problem**: "buffer too small (cap=0, need=6)"
**Fix**: Initialize `decoded_size = 4096` (buffer capacity, not output size)
**Code**: `libspdm_send_receive_data()` line 2066

### 10. init_connection transport_decode Fix (commit c9c812e)

**Problem**: cert_chain corrupted with wrong GET_VERSION request (4 bytes), "Get public key failed"
**Root Cause**: `spdm_request_len` not cleared after init_connection responses
**Fix**: Add `call_transport_decode` after VERSION, CAPABILITIES, ALGORITHMS responses
**Code**: `init_connection()` lines 964, 1140, 1328

---

## Technical Insights

### 1. Buffer Acquisition Model

C 库使用同一个缓冲区作为 sender 和 receiver:
```rust
sender_buf = call_acquire_sender(context);  // Get buffer
call_send(context, sender_buf, size);       // Send from buffer
// recv() may OVERWRITE the same buffer!
recv_buf = call_acquire_receiver(context);  // Same buffer pointer
call_recv(context, recv_buf, &size);        // Receive into same buffer
```

**结论**: 必须在 recv() 之前保存 request bytes。

### 2. Transport Callback Mechanism

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transport Callback Flow                       │
│                                                                 │
│  Request Side:                                                  │
│  transport_encode(spdm_msg, session_id)                        │
│      │                                                          │
│      ├─ session_id=NULL → is_msg_sspdm=false (unsecured)       │
│      │     → save_spdm_req() sets spdm_request_len             │
│      │                                                          │
│      ├─ session_id!=NULL → is_msg_sspdm=true (secured)         │
│      │     → AES-256-GCM encrypt                                │
│      │     → save_spdm_req() sets spdm_request_len             │
│      │                                                          │
│  Response Side:                                                 │
│  transport_decode(transport_msg, session_id)                   │
│      │                                                          │
│      ├─ Parse SPDM header                                       │
│      ├─ Dispatch to cache callback based on response_code:     │
│      │     VERSION → dev_assign_cache_versions_rsp()           │
│      │     CAPABILITIES → dev_assign_cache_capabilities_rsp()  │
│      │     ALGORITHMS → dev_assign_cache_algorithms_rsp()      │
│      │     CERTIFICATE → cma_spdm_cache_certificate()          │
│      │                                                          │
│      ├─ dev_assign_dev_comm_set_cache():                       │
│      │     if spdm_request_len > 0:                             │
│      │         flags |= REQ_CACHE (cache saved request)        │
│      │         spdm_request_len = 0  ← CRITICAL: CLEARS IT    │
│      │     flags |= RSP_CACHE (cache response)                 │
│      │                                                          │
└─────────────────────────────────────────────────────────────────┘
```

**关键发现**: `transport_decode` 的回调函数会清除 `spdm_request_len`。如果不调用 transport_decode，`spdm_request_len` 会保持设置状态，导致后续的 CERTIFICATE response 错误地缓存了之前保存的 GET_VERSION request。

### 3. Secured Message Handling

TDISP 操作需要 secured session:

```
Session establishment:
  KEY_EXCHANGE → session_id = 0xFFFFFFFF
  FINISH → session established

Secured message encoding (AES-256-GCM):
  1. Compute AAD (additional authenticated data)
  2. Generate random IV (12 bytes)
  3. Encrypt: ciphertext + 16-byte tag
  4. Build secured message: header + IV + ciphertext + tag

Session termination:
  END_SESSION → END_SESSION_ACK
  reset_context() clears all session state
```

### 4. Caching Object Types

| obj_id | Object Type | When cached |
|--------|-------------|-------------|
| 0 | VCA (Version/Capabilities/Algorithms) | init_connection responses |
| 1 | Certificate Chain | get_certificate responses |
| 2 | Measurements | challenge responses |
| 3 | Interface Report | TDISP get_interface_report |

---

## Verification Results

### Final Test Matrix (2026-04-22)

| Test | Rust Library | C Library | Status |
|------|-------------|-----------|--------|
| Stage 1 (init_connection) | ✓ | ✓ | PASS |
| Stage 2 (PDEV setup) | ✓ | ✓ | PASS |
| Stage 3 (Attestation) | ✓ | ✓ | PASS |
| Stage 4 (VDEV assign) | ✓ | ✓ | PASS |
| Stage 5 (DA tests) | ✓ | ✓ | PASS |
| Stage 6 (TDISP) | ✓ | ✓ | PASS |
| VDEV_UNLOCK | RMI_SUCCESS | RMI_SUCCESS | PASS |
| VDEV_DESTROY | RMI_SUCCESS | RMI_SUCCESS | PASS |
| PDEV_STOP | RMI_SUCCESS | RMI_SUCCESS | PASS |
| PDEV_DESTROY | RMI_SUCCESS | RMI_SUCCESS | PASS |
| REALM_DESTROY | RMI_SUCCESS | RMI_SUCCESS | PASS |
| Exit Code | **0** | **0** | PASS |
| cert_chain_len | **1539** | **1539** | PASS |
| session_id | 0xFFFFFFFF | 0xFFFFFFFF | PASS |

### Key Metrics Comparison

```
C Library Output:
  cert_chain_len=1539
  session_id=0xffffffff
  flags=0x6 (RSP_CACHE only for CERTIFICATE)
  Exit code: 0

Rust Library Output:
  cert_chain_len=1539
  session_id=0xffffffff
  flags=0x6 (RSP_CACHE only for CERTIFICATE)
  Exit code: 0
```

---

## Key Files Reference

### Rust Library Source
| File | Content |
|------|---------|
| `rust-spdm-minimal/src/ffi/libspdm.rs` | All FFI implementations |
| `rust-spdm-minimal/include/rust_spdm.h` | Header for C integration |
| `rust-spdm-minimal/Cargo.toml` | Build configuration |

### C Integration Points
| File | Role |
|------|------|
| `app/device_assignment/el0_app/src/dev_assign_el0_app.c` | Transport callbacks, caching logic |
| `plat/host/host_build/src/host_da.c` | Device attestation, cert_chain handling |
| `plat/host/host_build/src/host_spdm_rsp_ifc.c` | TCP socket communication |

### Reference C Library
| File | Role |
|------|------|
| `ext/libspdm/library/spdm_requester_lib/libspdm_req_communication.c` | C's init_connection reference |
| `ext/libspdm/library/spdm_requester_lib/libspdm_req_get_certificate.c` | C's get_certificate reference |

---

## Troubleshooting Guide

### If cert_chain_len is wrong

1. Check transport_decode calls: Must call after each init_connection response
2. Check flags output: Should see `0x3` for VERSION, `0x6` for subsequent
3. Verify `spdm_request_len` cleared: Look for REQ_CACHE flag transitions

### If TDISP fails

1. Check session_id: Must be 0xFFFFFFFF (or responder-assigned value)
2. Check secured message encryption: AES-256-GCM with correct IV/AAD
3. Check transport_encode/decode buffer sizes: Must be 4096 capacity

### If program hangs

1. Check spdm_request_len state: If stuck at non-zero, cache callback not triggered
2. Check is_msg_sspdm flag: Must be false for GET_VERSION after END_SESSION
3. Check socket communication: responder_emu may have crashed

---

## Project Status

**Status**: ✅ **COMPLETE**

- Rust library fully replaces C library
- All 10 critical fixes implemented and verified
- Clean build works with exit code 0
- All DESTROY operations visible in output
- Pushed to remote: `github.com:liwz-hz/tf-rmm.git`