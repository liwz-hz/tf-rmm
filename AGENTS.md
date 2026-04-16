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

### Session: KEY_EXCHANGE Responder Error Analysis

**Goal**: 实现 rust-spdm-minimal 完全替换 libspdm C 库

**Completed Fixes**:
1. ✓ Added `libspdm_challenge` function with proper buffer acquisition
2. ✓ Fixed KEY_EXCHANGE version byte (use `(spdm_version >> 8)` instead of `as u8`)
3. ✓ Fixed KEY_EXCHANGE buffer acquisition (`acquire_sender`/`release_sender` pattern)
4. ✓ Fixed FINISH buffer acquisition
5. ✓ Fixed responder startup conflict (RMM and tfrmm.py both starting responder)

**Current Issue**: KEY_EXCHANGE returns ERROR(0x01) = InvalidRequest

**Verified Correct Fields**:
- Version: 0x12 (SPDM 1.2)
- Request code: 0xE4
- param1: 0x00 (no measurement)
- param2: 0x00 (slot_id=0)
- req_session_id: 0x1234
- session_policy: 0x00
- random_data: 32 bytes
- exchange_data: 97 bytes (P-384)
- opaque_length: 0x0000
- GET_CAPABILITIES flags: 0x82C2 (CERT+ENCRYPT+MAC+KEY_EX+HANDSHAKE_IN_CLEAR)

**Responder Check Points** (libspdm_rsp_key_exchange.c):
- Line 209-213: connection_version >= 1.1 ✓
- Line 216-219: version match ✓
- Line 239-246: MAC_CAP check ✓ (flags contain 0x80)
- Line 248-252: connection_state >= NEGOTIATED ✓
- Line 253-260: other_params OPAQUE_DATA_FORMAT_1 ✓
- Line 343-347: request_size >= 139 ✓ (we send 140)
- Line 349-356: opaque_length check ✓ (0 bytes)

**Next Steps**:
1. Debug responder internal state (negotiated capabilities storage)
2. Implement real DHE key generation (crypto/dhe.rs)
3. Implement transcript hash (TH1)
4. Implement signature/HMAC verification