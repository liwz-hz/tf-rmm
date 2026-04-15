# CMake 集成方案

## 一、当前 C 依赖结构

### 1.1 现有 CMake 文件

```
app/device_assignment/el0_app/
├── CMakeLists.txt              # 主构建，链接所有 SPDM 库
├── spdm_requester/CMakeLists.txt  # 编译 libspdm (Phase 1 后移除)
└── spdm_emu/CMakeLists.txt     # 编译 DOE/TDISP/IDE-KM + responder_emu
    ├── rmm-pci_doe_requester_lib   (Phase 2 后移除)
    ├── rmm-pci_tdisp_requester_lib (Phase 3 后移除)
    ├── rmm-pci-ide-km-requester-lib (打桩)
    └── spdm_responder_emu          (保留)
```

### 1.2 当前链接关系

```cmake
# el0_app/CMakeLists.txt
target_link_libraries(rmm-app-dev-assign-elf
    PRIVATE
    rmm-app-da-mbedtls           # Crypto backend
    rmm-pci-ide-km-requester-lib # IDE-KM
    rmm-pci_tdisp_requester_lib  # TDISP
    rmm-spdm_requester           # libspdm core
)
```

---

## 二、Phase 1 集成方案

### 2.1 修改 el0_app/CMakeLists.txt

```cmake
# Rust SPDM 库构建
set(RUST_SPDM_DIR "${RMM_SOURCE_DIR}/rust-spdm-minimal")
set(RUST_SPDM_TARGET_DIR "${CMAKE_BINARY_DIR}/rust-spdm-target")
set(RUST_SPDM_LIB "${RUST_SPDM_TARGET_DIR}/release/librust_spdm_minimal.a")

find_program(CARGO cargo REQUIRED)

add_custom_command(
    OUTPUT "${RUST_SPDM_LIB}"
    COMMAND "${CARGO}" build --release --target-dir "${RUST_SPDM_TARGET_DIR}"
    WORKING_DIRECTORY "${RUST_SPDM_DIR}"
    COMMENT "Building Rust SPDM minimal library"
)

add_custom_target(rust-spdm-build ALL DEPENDS "${RUST_SPDM_LIB}")

# 创建导入库
add_library(rust-spdm-minimal STATIC IMPORTED GLOBAL)
set_target_properties(rust-spdm-minimal PROPERTIES
    IMPORTED_LOCATION "${RUST_SPDM_LIB}"
)

target_include_directories(rust-spdm-minimal INTERFACE
    "${RUST_SPDM_DIR}/include"
)

add_dependencies(rust-spdm-minimal rust-spdm-build)

# 链接 Rust 库，移除 libspdm C 库
target_link_libraries(rmm-app-dev-assign-elf
    PRIVATE
    rust-spdm-minimal           # 替换 rmm-spdm_requester
    rmm-app-da-mbedtls          # 可选保留，或移除 (如果 Rust crypto 够用)
    # 保留 C 的 DOE/TDISP (Phase 1)
    rmm-pci_doe_requester_lib
    rmm-pci_tdisp_requester_lib
    rmm-pci-ide-km-requester-lib  # 由 Rust 打桩，但 CMake 仍链接 C 库
)
```

### 2.2 修改 spdm_requester/CMakeLists.txt

**选项 A**: 完全移除该文件

```cmakeake
# 删除整个 spdm_requester 目录
# 不再编译 libspdm C 源码
```

**选项 B**: 仅保留配置头文件

```cmake
# 仅提供配置头文件，不编译源码
add_library(rmm-spdm-config INTERFACE)
target_include_directories(rmm-spdm-config INTERFACE
    "${RMM_SOURCE_DIR}/configs/libspdm"
)
```

### 2.3 保留 spdm_emu/CMakeLists.txt (Phase 1)

Phase 1 时 DOE/TDISP 仍用 C：

```cmake
# spdm_emu/CMakeLists.txt 保留 DOE/TDISP requester 构建
# 仅移除对 rmm-spdm_requester 的依赖

# DOE requester
add_library(rmm-pci_doe_requester_lib STATIC)
target_sources(rmm-pci_doe_requester_lib PRIVATE
    ${SPDM_EMU_SOURCE_DIR}/library/pci_doe_requester_lib/pci_doe_spdm_vendor_send_receive.c
)
# 改为依赖 Rust 而非 C libspdm
target_link_libraries(rmm-pci_doe_requester_lib
    PUBLIC  rust-spdm-minimal   # 改为 Rust
    PRIVATE rmm-lib-common rmm-lib-debug
)

# TDISP requester
add_library(rmm-pci_tdisp_requester_lib STATIC)
target_sources(rmm-pci_tdisp_requester_lib PRIVATE
    ${SPDM_EMU_SOURCE_DIR}/library/pci_tdisp_requester_lib/*.c
)
target_link_libraries(rmm-pci_tdisp_requester_lib
    PUBLIC  rmm-pci_doe_requester_lib
    PRIVATE rmm-lib-common rmm-lib-debug
)

# IDE-KM (保留但实际由 Rust 打桩)
add_library(rmm-pci-ide-km-requester-lib STATIC)
target_sources(rmm-pci-ide-km-requester-lib PRIVATE
    ${SPDM_EMU_SOURCE_DIR}/library/pci_ide_km_requester_lib/*.c
)
# IDE-KM 仍然链接，但 Rust 提供打桩实现覆盖
```

---

## 三、Phase 2 集成方案 (移除 DOE C 库)

### 3.1 修改 spdm_emu/CMakeLists.txt

```cmake
# 移除 C DOE requester 构建
# 不再需要 add_library(rmm-pci_doe_requester_lib)
# DOE 功能由 rust-spdm-minimal 提供

# TDISP requester 改为直接依赖 Rust
add_library(rmm-pci_tdisp_requester_lib STATIC)
target_sources(rmm-pci_tdisp_requester_lib PRIVATE
    ${SPDM_EMU_SOURCE_DIR}/library/pci_tdisp_requester_lib/*.c
)
target_link_libraries(rmm-pci_tdisp_requester_lib
    PUBLIC  rust-spdm-minimal   # 直接依赖 Rust，跳过 DOE C 层
    PRIVATE rmm-lib-common rmm-lib-debug
)

# 注意: C 的 pci_tdisp_send_receive_data.c 仍然需要 pci_doe 函数
# 需要修改 C 代码或 Rust 提供 pci_doe_* FFI
```

**问题**: C 的 TDISP 实现调用 `pci_doe_spdm_vendor_send_receive_data()`，该函数需要在 Rust FFI 中提供。

**解决**: Rust FFI 模块中实现 `pci_doe_spdm_vendor_send_receive_data()` 导出函数。

---

## 四、Phase 3 集成方案 (移除 TDISP C 库)

### 4.1 修改 spdm_emu/CMakeLists.txt

```cmake
# 移除 C TDISP requester 构建
# 不再需要 add_library(rmm-pci_tdisp_requester_lib)

# 移除 IDE-KM C 构建 (已由 Rust 打桩)
# 不再需要 add_library(rmm-pci-ide-km-requester-lib)

# 仅保留 responder_emu 构建
add_executable(spdm_responder_emu)
target_sources(spdm_responder_emu PRIVATE
    ${SPDM_EMU_SOURCE_DIR}/spdm_emu/spdm_responder_emu/*.c
)
target_link_libraries(spdm_responder_emu
    PRIVATE
    # responder 需要的库 (libspdm responder, mbedtls 等)
    # 这些是独立进程，不影响 requester
)
```

### 4.2 最终 el0_app/CMakeLists.txt

```cmake
# Phase 3 最终版本 - 纯 Rust requester

# Rust 库构建
set(RUST_SPDM_DIR "${RMM_SOURCE_DIR}/rust-spdm-minimal")
set(RUST_SPDM_TARGET_DIR "${CMAKE_BINARY_DIR}/rust-spdm-target")
set(RUST_SPDM_LIB "${RUST_SPDM_TARGET_DIR}/release/librust_spdm_minimal.a")

find_program(CARGO cargo REQUIRED)

add_custom_command(
    OUTPUT "${RUST_SPDM_LIB}"
    COMMAND "${CARGO}" build --release --target-dir "${RUST_SPDM_TARGET_DIR}"
    WORKING_DIRECTORY "${RUST_SPDM_DIR}"
)

add_custom_target(rust-spdm-build ALL DEPENDS "${RUST_SPDM_LIB}")

add_library(rust-spdm-minimal STATIC IMPORTED GLOBAL)
set_target_properties(rust-spdm-minimal PROPERTIES
    IMPORTED_LOCATION "${RUST_SPDM_LIB}"
)
target_include_directories(rust-spdm-minimal INTERFACE "${RUST_SPDM_DIR}/include")
add_dependencies(rust-spdm-minimal rust-spdm-build)

# 最终链接 - 仅 Rust，无 C SPDM 库
target_link_libraries(rmm-app-dev-assign-elf
    PRIVATE
    rust-spdm-minimal           # 包含 SPDM Core + DOE + TDISP + IDE-KM 打桩
    # 可选保留 mbedtls 或移除
)
```

---

## 五、C 头文件生成

### 5.1 cbindgen.toml

```toml
[parse]
parse_deps = false

[export]
include = [
    "SpdmContext",
    "SessionInfo",
    "libspdm_return_t",
    "libspdm_data_type_t",
    "libspdm_data_parameter_t",
    "libspdm_error_struct_t",
    "libspdm_init_context",
    "libspdm_deinit_context",
    "libspdm_get_context_size",
    "libspdm_init_connection",
    "libspdm_get_certificate",
    "libspdm_start_session",
    "libspdm_stop_session",
    "libspdm_send_receive_data",
    "libspdm_set_data",
    "libspdm_get_data",
    "libspdm_register_device_io_func",
    "libspdm_register_transport_layer_func",
    "libspdm_register_device_buffer_func",
    "libspdm_encode_secured_message",
    "libspdm_decode_secured_message",
    "libspdm_get_secured_message_context_via_session_id",
    "libspdm_get_hash_size",
    "libspdm_get_random_number",
    "pci_doe_spdm_vendor_send_receive_data",
    "pci_tdisp_get_version",
    "pci_tdisp_get_capabilities",
    "pci_tdisp_get_interface_state",
    "pci_tdisp_lock_interface",
    "pci_tdisp_get_interface_report",
    "pci_tdisp_start_interface",
    "pci_tdisp_stop_interface",
    "pci_ide_km_query",
    "pci_ide_km_key_prog",
    "pci_ide_km_key_set_go",
    "pci_ide_km_key_set_stop",
]

[fn]
sort_by = ["Name"]

[struct]
rename_fields = "None"

[enum]
rename_variants = "None"

[macro_expansion]
bitflags = true
```

### 5.2 build.rs

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let include_dir = out_dir.parent().unwrap().parent().unwrap().parent().unwrap();
    
    cbindgen::Builder::new()
        .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap())
        .with_crate(crate_dir)
        .generate()
        .unwrap()
        .write_to_file(include_dir.join("rust_spdm.h"));
}
```

---

## 六、移除的 CMake 文件/部分汇总

| 阶段 | 移除内容 |
|------|----------|
| Phase 1 | `spdm_requester/CMakeLists.txt` 整个目录 |
| Phase 1 | `spdm_emu/CMakeLists.txt` 中 `rmm-spdm_requester` 依赖 |
| Phase 2 | `spdm_emu/CMakeLists.txt` 中 `rmm-pci_doe_requester_lib` 构建 |
| Phase 3 | `spdm_emu/CMakeLists.txt` 中 `rmm-pci_tdisp_requester_lib` 构建 |
| Phase 3 | `spdm_emu/CMakeLists.txt` 中 `rmm-pci-ide-km-requester-lib` 构建 |

---

## 七、构建验证命令

```bash
# Phase 1 验证
cd /home/lmm/code/tf-rmm
python tfrmm.py build --clean

# 验证 Rust 库链接
ldd build/Release/rmm.elf | grep -i rust

# 运行测试
python tfrmm.py run

# Phase 2/3 验证 (同上)
```