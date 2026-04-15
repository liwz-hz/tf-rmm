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
- `build/Release/rmm.elf` - RMM executable
- `build/Release/spdm_emu/spdm_responder_emu` - SPDM responder (auto-built from submodule)

## Platform Code
Fake_host platform: `plat/host/`
- `host_build/src/host_da.c`: Device attestation setup
- `host_build/src/host_spdm_rsp_ifc.c`: SPDM responder interface
- `runtime/rmi/pdev.c`: PDEV creation with SPDM-only flags