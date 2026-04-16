# TF-RMM Fakehost Debug Project

## Purpose
This repository is for **fake_host debugging** of tf-rmm. It is NOT a production build - IDE support was intentionally disabled to simplify SPDM testing (commit f11214a).

## Build Commands
**Always use the Python script - do NOT run cmake directly:**

```bash
python tfrmm.py build          # Build rmm.elf
python tfrmm.py build --clean  # Clean rebuild
python tfrmm.py run            # Run with SPDM responder
python tfrmm.py all            # Full workflow: update, build, run
```

Build output: `build/Release/rmm.elf`

## Submodules
6 submodules required: mbedtls, qcbor, t_cose, cpputest, libspdm, spdm-emu
- Run `python tfrmm.py submodule` or `git submodule update --init --recursive`

## Configuration
- Config: `host_defcfg` (fake_host architecture)
- LOG_LEVEL set for verbose debug output

## Critical Constraints
**IDE is disabled** (commit f11214a):
- `pdev.c`: Requires `NCOH_IDE=FALSE` (changed from TRUE)
- `host_da.c`: SPDM only, no IDE flags
- Do NOT "fix" IDE support - it's intentionally disabled for debugging

## Build Output
- `build/Release/rmm.elf` - RMM executable (linked with libspdm requester)
- `build/Release/spdm_emu/spdm_responder_emu` - SPDM responder (auto-built from submodule)

## SPDM Architecture

### Two-Process Model
The SPDM testing uses a **requester-responder split architecture**:

| Component | Role | Location | Description |
|-----------|------|----------|-------------|
| `spdm_responder_emu` | Responder | `ext/spdm-emu/` | External process, simulates PCIe device |
| `rmm.elf` (dev_assign app) | Requester | `app/device_assignment/` | Links libspdm requester library |

### Startup Flow
```
main() → initialise_app_headers() → launch_spdm_responder_emu()
                                    ↓
                              fork() + execl()
                                    ↓
                         spdm_responder_emu --trans PCI_DOE
                         (listening on TCP port 2323)
```

### Communication Path
```
rmm.elf (requester)          spdm_responder_emu (responder)
       │                              │
       │  host_spdm_rsp_ifc.c         │
       │  (TCP socket)                │
       └──────── DOE encapsulation ───┘
              (port 2323)
```

### Key Files
| File | Role |
|------|------|
| `plat/host/host_build/src/host_setup.c` | `launch_spdm_responder_emu()` - fork/exec startup |
| `plat/host/host_build/src/host_spdm_rsp_ifc.c` | TCP socket + DOE protocol wrapper |
| `app/device_assignment/el0_app/spdm_requester/CMakeLists.txt` | Links libspdm requester libs |
| `app/device_assignment/el0_app/src/dev_assign_private.h` | Includes `spdm_requester_lib.h` |

### libspdm Requester Libraries
Linked into `rmm-app-dev-assign-elf`:
- `spdm_requester_lib` - Core SPDM requester protocol
- `spdm_secured_message_lib` - Secure session handling
- `spdm_common_lib` / `spdm_crypt_lib` - Common/crypto support

## TDISP Architecture

### Library Dependency Chain
TDISP protocol layer is built on top of libspdm:

```
┌─────────────────────────────────────────────────────────────────┐
│                        rmm.elf                                   │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │              rmm-app-dev-assign-elf                        │ │
│  │       (Device Assignment EL0 App)                          │ │
│  │                                                            │ │
│  │   dev_tdisp_cmds.c                                         │ │
│  │   └── pci_tdisp_lock_interface()                           │ │
│  │       └── pci_tdisp_send_receive_data()                    │ │
│  │           └── pci_doe_spdm_vendor_send_receive_data()      │ │
│  │               └── libspdm_send_receive_data()              │ │
│  │                                                            │ │
│  │  LINK_LIBRARIES:                                           │ │
│  │   rmm-pci_tdisp_requester_lib  ← ext/spdm-emu/            │ │
│  │     │                                                      │ │
│  │     ▼ (link PUBLIC)                                        │ │
│  │   rmm-pci_doe_requester_lib   ← ext/spdm-emu/            │ │
│  │     │                                                      │ │
│  │     ▼ (link PUBLIC)                                        │ │
│  │   rmm-spdm_requester          ← ext/libspdm/             │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Library Sources Comparison
| Library | Submodule | Purpose |
|---------|-----------|---------|
| `rmm-spdm_requester` | `ext/libspdm/` | SPDM core protocol |
| `rmm-pci_tdisp_requester_lib` | `ext/spdm-emu/` | TDISP protocol layer (depends on libspdm) |
| `rmm-pci_doe_requester_lib` | `ext/spdm-emu/` | DOE + VDM encapsulation (depends on libspdm) |
| `rmm-pci-ide-km-requester-lib` | `ext/spdm-emu/` | IDE Key Management (disabled but linked) |

### TDISP API Interface
Header: `ext/spdm-emu/include/library/pci_tdisp_requester_lib.h`

| Function | Purpose |
|----------|---------|
| `pci_tdisp_get_version()` | Version negotiation |
| `pci_tdisp_get_capabilities()` | Capability exchange |
| `pci_tdisp_get_interface_state()` | Get TDI state (UNLOCKED/LOCKED/RUN) |
| `pci_tdisp_lock_interface()` | Lock interface, generate nonce |
| `pci_tdisp_get_interface_report()` | Get interface report |
| `pci_tdisp_start_interface()` | Start interface with nonce |
| `pci_tdisp_stop_interface()` | Stop interface |

### TDISP Business Implementation
Code: `app/device_assignment/el0_app/src/dev_tdisp_cmds.c`

| Function | TDISP Flow |
|----------|-----------|
| `dev_tdisp_lock_main()` | GET_VERSION → GET_CAPS → GET_STATE → LOCK_INTERFACE → verify LOCKED |
| `dev_tdisp_report_main()` | GET_INTERFACE_REPORT (optional) |
| `dev_tdisp_start_main()` | DVSEC enable → START_INTERFACE → verify RUN |
| `dev_tdisp_stop_main()` | STOP_INTERFACE → verify UNLOCKED |

### Key Files
| File | Role |
|------|------|
| `app/device_assignment/el0_app/spdm_emu/CMakeLists.txt` | Builds TDISP/DOE requester libs from spdm-emu |
| `app/device_assignment/el0_app/src/dev_tdisp_cmds.c` | TDISP business logic implementation |
| `ext/spdm-emu/library/pci_tdisp_requester_lib/` | TDISP requester library source |
| `ext/spdm-emu/library/pci_doe_requester_lib/` | DOE + VDM transport layer |

### Transmission Mechanism
TDISP messages transmitted via SPDM Vendor Defined Messages (VDM):

```
pci_tdisp_xxx()
    → pci_tdisp_send_receive_data()
        → pci_doe_spdm_vendor_send_receive_data()  (PCI_PROTOCOL_ID_TDISP = 0x01)
            → libspdm_send_receive_data()
                → host_spdm_rsp_communicate()  (TCP socket)
```

### Key Point
- **TDISP library comes from spdm-emu**, NOT from libspdm
- **TDISP library is linked into rmm.elf** as `rmm-pci_tdisp_requester_lib`
- **TDISP library depends on libspdm** through DOE/VDM transport layer
- All TDISP messages require an established SPDM secure session (`session_id`)

## Platform Code
Fake_host platform: `plat/host/`
- `host_build/src/host_da.c`: Device attestation setup
- `host_build/src/host_spdm_rsp_ifc.c`: SPDM responder interface (TCP + DOE)
- `host_build/src/host_setup.c`: Process launch and main entry
- `runtime/rmi/pdev.c`: PDEV creation with SPDM-only flags

## Debugging Status (2026-04-16)

### Session: TH1 Transcript Bug Fix - COMPLETE

**Goal**: 实现 rust-spdm-minimal 完全替换 libspdm C 库

**Status**: ✅ **COMPLETE** - Rust library fully replaces C library

**Critical Bug Fixed**: message_a transcript storage issue
- **Root Cause**: sender_buf and receiver_buf share the same underlying buffer (0x11402e0)
- **Problem**: After `recv()` returns, the buffer contains RESPONSE, not REQUEST
- **Symptom**: `message_a first4=10040000` (VERSION response header) instead of `10840000` (GET_VERSION request header)
- **Impact**: TH1 transcript hash mismatch → FINISH HMAC verification failure
- **Fix**: Save request bytes BEFORE calling `recv()` in VERSION, CAPABILITIES, and ALGORITHMS exchanges

**All Completed Fixes**:
1. ✓ Added `libspdm_challenge` function with proper buffer acquisition
2. ✓ Fixed KEY_EXCHANGE version byte (use `(spdm_version >> 8)` instead of `as u8`)
3. ✓ Fixed KEY_EXCHANGE buffer acquisition (`acquire_sender`/`release_sender` pattern)
4. ✓ Fixed FINISH buffer acquisition
5. ✓ Fixed responder startup conflict (RMM and tfrmm.py both starting responder)
6. ✓ **Fixed message_a transcript storage (buffer reuse bug)**

**Verified Working**:
- `!!! verify_finish_req_hmac - PASS !!!`
- TDISP Lock successful (tdi_id = 256)
- TDISP Start successful (status = 0x0)
- RMM exits with code 0
- Full SPDM session establishment works

**Responder Check Points** (libspdm_rsp_key_exchange.c):
- Line 209-213: connection_version >= 1.1 ✓
- Line 216-219: version match ✓
- Line 239-246: MAC_CAP check ✓ (flags contain 0x80)
- Line 248-252: connection_state >= NEGOTIATED ✓
- Line 253-260: other_params OPAQUE_DATA_FORMAT_1 ✓
- Line 343-347: request_size >= 139 ✓ (we send 140)
- Line 349-356: opaque_length check ✓ (0 bytes)

**Implementation Notes**:
- DHE key generation: Working (ECDH P-384)
- Transcript hash TH1: Working (SHA-384)
- Signature verification: Working (ECDSA P-384)
- HMAC verification: Working (HKDF-SHA384)
- HANDSHAKE_IN_THE_CLEAR: Correctly handled (no HMAC in KEY_EXCHANGE_RSP)

**Key Technical Insight**:
The libspdm buffer acquisition API returns the same buffer pointer for both sender and receiver.
This is an optimization but causes data corruption if request bytes are stored after recv().
Solution: Always save request bytes BEFORE calling recv().