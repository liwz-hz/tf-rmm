#!/usr/bin/env python3
"""
TF-RMM Build and Run Script

Usage:
    python tfrmm.py --help
    python tfrmm.py build [--clean]
    python tfrmm.py run [--no-spdm]
    python tfrmm.py all
"""

import argparse
import os
import subprocess
import sys
import signal
import time
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent.resolve()
BUILD_DIR = PROJECT_ROOT / "build"
RMM_ELF = BUILD_DIR / "Release" / "rmm.elf"
RMM_CONFIG = "host_defcfg"

SPDM_EMU_PATH = Path("/home/lmm/code/spdm-emu/spdm-emu/build/bin/spdm_responder_emu")
SPDM_TRANSPORT = "PCI_DOE"
SPDM_VERSION = "1.2"
SPDM_PORT = 2323


def run_cmd(cmd, cwd=None, check=True):
    """Run a shell command and return the result."""
    print(f"[CMD] {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(
        cmd,
        cwd=cwd or PROJECT_ROOT,
        shell=isinstance(cmd, str),
        check=False,
    )
    if check and result.returncode != 0:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    return result


def cmd_submodule_update():
    """Update git submodules."""
    print("\n" + "=" * 60)
    print("[STEP] Updating git submodules...")
    print("=" * 60)
    run_cmd(["git", "submodule", "update", "--init", "--recursive"])


def cmd_configure():
    """Configure CMake build."""
    print("\n" + "=" * 60)
    print("[STEP] Configuring CMake...")
    print("=" * 60)
    
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    run_cmd(
        ["cmake", "..", f"-DRMM_CONFIG={RMM_CONFIG}", "-DLOG_LEVEL=50"],
        cwd=BUILD_DIR
    )


def cmd_build(clean=False):
    """Build the project."""
    print("\n" + "=" * 60)
    print("[STEP] Building...")
    print("=" * 60)
    
    if clean:
        print("[INFO] Clean build requested")
        if BUILD_DIR.exists():
            import shutil
            shutil.rmtree(BUILD_DIR)
    
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    
    # Configure if not already done
    if not (BUILD_DIR / "CMakeCache.txt").exists():
        cmd_configure()
    
    run_cmd(["cmake", "--build", "."], cwd=BUILD_DIR)
    
    if RMM_ELF.exists():
        print(f"\n[SUCCESS] Build complete: {RMM_ELF}")
    else:
        print(f"[ERROR] Build failed: {RMM_ELF} not found")
        sys.exit(1)


def cmd_start_spdm():
    """Start SPDM responder emulator in background."""
    print("\n" + "=" * 60)
    print("[STEP] Starting SPDM responder...")
    print("=" * 60)
    
    if not SPDM_EMU_PATH.exists():
        print(f"[ERROR] SPDM emulator not found at {SPDM_EMU_PATH}")
        sys.exit(1)
    
    # Check if already running
    result = run_cmd(["pgrep", "-f", "spdm_responder_emu"], check=False)
    if result.returncode == 0:
        print("[INFO] SPDM responder already running, killing it...")
        run_cmd(["pkill", "-f", "spdm_responder_emu"], check=False)
        time.sleep(1)
    
    # Start SPDM responder in background
    spdm_cmd = [
        str(SPDM_EMU_PATH),
        "--trans", SPDM_TRANSPORT,
        "--ver", SPDM_VERSION,
    ]
    
    print(f"[CMD] {' '.join(spdm_cmd)}")
    spdm_dir = SPDM_EMU_PATH.parent
    
    process = subprocess.Popen(
        spdm_cmd,
        cwd=spdm_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    
    # Give it time to start
    time.sleep(2)
    
    if process.poll() is None:
        print(f"[SUCCESS] SPDM responder started (PID: {process.pid})")
        print(f"         Transport: {SPDM_TRANSPORT}, Version: {SPDM_VERSION}")
        return process
    else:
        print(f"[ERROR] SPDM responder failed to start")
        sys.exit(1)


def cmd_run(start_spdm=True):
    """Run RMM."""
    print("\n" + "=" * 60)
    print("[STEP] Running RMM...")
    print("=" * 60)
    
    if not RMM_ELF.exists():
        print(f"[ERROR] RMM ELF not found: {RMM_ELF}")
        print("[INFO] Run 'python tfrmm.py build' first")
        sys.exit(1)
    
    spdm_process = None
    if start_spdm:
        spdm_process = cmd_start_spdm()
    
    print(f"\n[RUN] {RMM_ELF}")
    print("-" * 60)
    
    try:
        result = subprocess.run(
            [str(RMM_ELF)],
            cwd=PROJECT_ROOT,
        )
        print("-" * 60)
        print(f"[DONE] RMM exited with code {result.returncode}")
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] RMM stopped by user")
    finally:
        if spdm_process:
            print("\n[CLEANUP] Stopping SPDM responder...")
            run_cmd(["pkill", "-f", "spdm_responder_emu"], check=False)


def cmd_all(clean=False):
    """Run all steps: submodule update, build, and run."""
    cmd_submodule_update()
    cmd_build(clean=clean)
    cmd_run()


def main():
    parser = argparse.ArgumentParser(
        description="TF-RMM Build and Run Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python tfrmm.py build          # Build the project
    python tfrmm.py build --clean  # Clean and rebuild
    python tfrmm.py run            # Run RMM with SPDM responder
    python tfrmm.py run --no-spdm  # Run RMM without starting SPDM
    python tfrmm.py all            # Update, build, and run
    python tfrmm.py submodule      # Update submodules only
    python tfrmm.py configure      # Configure CMake only
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # build command
    build_parser = subparsers.add_parser("build", help="Build the project")
    build_parser.add_argument("--clean", action="store_true", help="Clean build directory first")
    
    # run command
    run_parser = subparsers.add_parser("run", help="Run RMM")
    run_parser.add_argument("--no-spdm", action="store_true", help="Don't start SPDM responder")
    
    # all command
    all_parser = subparsers.add_parser("all", help="Update submodules, build, and run")
    all_parser.add_argument("--clean", action="store_true", help="Clean build directory first")
    
    # submodule command
    subparsers.add_parser("submodule", help="Update git submodules")
    
    # configure command
    subparsers.add_parser("configure", help="Configure CMake")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    if args.command == "build":
        cmd_build(clean=args.clean)
    elif args.command == "run":
        cmd_run(start_spdm=not args.no_spdm)
    elif args.command == "all":
        cmd_all(clean=args.clean)
    elif args.command == "submodule":
        cmd_submodule_update()
    elif args.command == "configure":
        cmd_configure()


if __name__ == "__main__":
    main()