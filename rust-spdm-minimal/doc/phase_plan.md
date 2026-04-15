# 分阶段实施计划

## 总览

| 阶段 | 内容 | 工作量 | 时间 | 消除的 C 依赖 |
|------|------|--------|------|---------------|
| Phase 1 | SPDM Core + IDE-KM 打桩 | ~3500 LOC | 18 天 | ext/libspdm/* (~50k LOC) |
| Phase 2 | DOE 层 | ~200 LOC | 3 天 | ext/spdm-emu/library/pci_doe_requester_lib/ (~136 LOC) |
| Phase 3 | TDISP 层 | ~400 LOC | 5.5 天 | ext/spdm-emu/library/pci_tdisp_requester_lib/ (~300 LOC) |

**总计**：约 26.5 天

---

## Phase 1: SPDM Core + IDE-KM 打桩

### 目标

替换 libspdm 核心，让现有 DOE/TDISP C 层能工作。

### 任务拆解

| 任务编号 | 任务 | 内容 | 预计时间 | 输出 |
|----------|------|------|----------|------|
| P1-01 | 项目初始化 | Cargo.toml, 目录结构, build.rs, cbindgen.toml | 1 天 | 项目骨架 |
| P1-02 | 基础模块 | context.rs, error.rs, 常量定义 | 1 天 | SpdmContext, SpdmStatus |
| P1-03 | 类型定义 | ffi/types.rs (libspdm 类型映射) | 1 天 | FFI 类型 |
| P1-04 | 消息编解码 | message/header.rs, message/codec.rs, message/payload.rs | 2 天 | SPDM 消息结构 |
| P1-05 | 加密框架 | crypto/mod.rs, trait 定义 | 1 天 | 加密抽象层 |
| P1-06 | Hash 实现 | crypto/hash.rs (SHA-256/384) | 1 天 | SpdmHash trait 实现 |
| P1-07 | AEAD 实现 | crypto/aead.rs (AES-128/256-GCM) | 1 天 | SpdmAead trait 实现 |
| P1-08 | DHE 实现 | crypto/dhe.rs (ECDH P-256/P-384) | 1 天 | SpdmDhe trait 实现 |
| P1-09 | HKDF 实现 | crypto/hkdf.rs | 1 天 | 密钥派生函数 |
| P1-10 | VERSION 协议 | protocol/version.rs | 1 天 | GET_VERSION/VERSION |
| P1-11 | CAPABILITIES 协议 | protocol/capabilities.rs | 1 天 | GET_CAPABILITIES/CAPABILITIES |
| P1-12 | ALGORITHMS 协议 | protocol/algorithms.rs | 1 天 | NEGOTIATE_ALGORITHMS/ALGORITHMS |
| P1-13 | DIGESTS 协议 | protocol/digest.rs | 0.5 天 | GET_DIGESTS/DIGESTS |
| P1-14 | CERTIFICATE 协议 | protocol/certificate.rs | 1.5 天 | GET_CERTIFICATE/CERTIFICATE (分段) |
| P1-15 | 密钥派生逻辑 | session/keys.rs | 2 天 | master_secret, data_secret 派生 |
| P1-16 | KEY_EXCHANGE 协议 | protocol/key_exchange.rs | 3 天 | KEY_EXCHANGE/KEY_EXCHANGE_RSP |
| P1-17 | FINISH 协议 | protocol/finish.rs | 1 天 | FINISH/FINISH_RSP |
| P1-18 | END_SESSION 协议 | protocol/end_session.rs | 0.5 天 | END_SESSION/END_SESSION_ACK |
| P1-19 | VENDOR_DEFINED | protocol/vendor.rs | 1 天 | VENDOR_DEFINED_REQUEST/RESPONSE |
| P1-20 | AEAD 加解密 | session/secured.rs | 1 天 | encode/decode_secured_message |
| P1-21 | Session 管理 | session/context.rs | 1 天 | SessionInfo, 状态管理 |
| P1-22 | FFI: 上下文管理 | ffi/libspdm.rs (init/deinit/context 相关) | 0.5 天 | 6 个 FFI 函数 |
| P1-23 | FFI: 数据管理 | ffi/libspdm.rs (set_data/get_data) | 0.5 天 | 2 个 FFI 函数 |
| P1-24 | FFI: 回调注册 | ffi/libspdm.rs (register_* 函数) | 0.5 天 | 4 个 FFI 函数 |
| P1-25 | FFI: 协议核心 | ffi/libspdm.rs (init_connection/get_certificate/start_session/stop_session) | 1 天 | 4 个 FFI 函数 |
| P1-26 | FFI: send_receive | ffi/libspdm.rs (send_receive_data) | 0.5 天 | 1 个 FFI 函数 |
| P1-27 | FFI: secured message | ffi/libspdm.rs (encode/decode_secured, get_secured_context) | 1 天 | 3 个 FFI 函数 |
| P1-28 | FFI: 加密工具 | ffi/libspdm.rs (get_hash_size, get_random) | 0.5 天 | 2 个 FFI 函数 |
| P1-29 | FFI: 错误处理 | ffi/libspdm.rs (error struct 函数) | 0.5 天 | 3 个 FFI 函数 |
| P1-30 | IDE-KM 打桩 | ffi/pci_ide_km.rs | 0.5 天 | 4 个打桩函数 |
| P1-31 | CMake 集成 | 修改 spdm_requester/CMakeLists.txt | 1 天 | Rust 库链接 |
| P1-32 | C 头文件生成 | cbindgen 配置和测试 | 1 天 | rust_spdm.h |
| P1-33 | 集成测试 | 与 spdm_responder_emu 互操作 | 2 天 | 测试通过 |

**Phase 1 总计**：18 天

### 验证点

- [ ] `cargo build --release` 成功
- [ ] C 头文件 `rust_spdm.h` 生成正确
- [ ] CMake 构建成功链接 Rust 库
- [ ] 与 `spdm_responder_emu --trans PCI_DOE` 互操作：
  - [ ] VERSION 协商成功
  - [ ] CAPABILITIES 协商成功
  - [ ] ALGORITHMS 协商成功
  - [ ] CERTIFICATE 获取成功
  - [ ] KEY_EXCHANGE 成功，session_id != 0
  - [ ] FINISH 成功，session 建立
  - [ ] TDISP lock → start → stop 流程成功 (C DOE/TDISP 层调用 Rust)
  - [ ] END_SESSION 成功

---

## Phase 2: DOE 层

### 目标

移除 `pci_doe_requester_lib` C 依赖，实现纯 Rust DOE 层。

### 前置条件

- Phase 1 完成并验证通过
- `libspdm_send_receive_data()` 和 `libspdm_get_data()` FFI 正常工作

### 任务拆解

| 任务编号 | 任务 | 内容 | 预计时间 | 输出 |
|----------|------|------|----------|------|
| P2-01 | DOE 消息结构 | doe/message.rs (Vendor Defined 结构) | 0.5 天 | VDM 结构定义 |
| P2-02 | DOE 封装实现 | doe/vendor.rs (pci_doe_spdm_vendor_send_receive_data) | 1 天 | DOE 核心函数 |
| P2-03 | FFI: DOE 函数 | ffi/pci_doe.rs | 0.5 天 | 4 个 FFI 函数 |
| P2-04 | CMake 修改 | 移除 C DOE 库依赖，链接 Rust DOE | 0.5 天 | 构建修改 |
| P2-05 | 集成测试 | 验证 TDISP 通过 Rust DOE 工作 | 1 天 | 测试通过 |

**Phase 2 总计**：3 天

### 验证点

- [ ] `pci_doe_spdm_vendor_send_receive_data()` Rust 实现正确
- [ ] CMake 不再链接 `rmm-pci_doe_requester_lib`
- [ ] TDISP 流程通过 Rust DOE 层成功

---

## Phase 3: TDISP 层

### 目标

移除 `pci_tdisp_requester_lib` C 依赖，实现纯 Rust TDISP 层。

### 前置条件

- Phase 2 完成并验证通过
- DOE 层 Rust 实现正常工作

### 任务拆解

| 任务编号 | 任务 | 内容 | 预计时间 | 输出 |
|----------|------|------|----------|------|
| P3-01 | TDISP 消息结构 | tdisp/message.rs (所有 TDISP 消息) | 1 天 | 7 对消息结构 |
| P3-02 | TDISP requester 实现 | tdisp/requester.rs (全部 TDISP 函数) | 2 天 | 8 个 TDISP 函数 |
| P3-03 | FFI: TDISP 函数 | ffi/pci_tdisp.rs | 1 天 | 8 个 FFI 函数 |
| P3-04 | CMake 修改 | 移除 C TDISP 库依赖 | 0.5 天 | 构建修改 |
| P3-05 | 完整流程测试 | lock → report → start → stop | 1 天 | 全流程测试 |

**Phase 3 总计**：5.5 天

### 验证点

- [ ] `pci_tdisp_get_version()` 成功
- [ ] `pci_tdisp_get_capabilities()` 成功
- [ ] `pci_tdisp_get_interface_state()` 返回正确状态
- [ ] `pci_tdisp_lock_interface()` 成功，状态变为 LOCKED
- [ ] `pci_tdisp_get_interface_report()` 成功
- [ ] `pci_tdisp_start_interface()` 成功，状态变为 RUN
- [ ] `pci_tdisp_stop_interface()` 成功，状态变为 UNLOCKED
- [ ] CMake 不再链接 `rmm-pci_tdisp_requester_lib`
- [ ] 不再链接任何 spdm-emu requester C 库

---

## 完成标准

Phase 3 完成后，达成：

### 代码层面

- `rmm.elf` 不链接任何 libspdm C 库
- `rmm.elf` 不链接任何 spdm-emu requester C 库
- 所有 requester 功能由 `rust_spdm_minimal.a` 提供

### 构建层面

- CMake 配置简化，仅构建 Rust 库 + responder_emu
- 构建时间减少 (Rust 编译更快)

### 功能层面

- 与原有 C 实现功能完全一致
- TDISP 流程正常工作
- 性能无明显下降

---

## 风险与应对

| 风险 | 影响 | 应对措施 |
|------|------|----------|
| 加密实现与 libspdm 不兼容 | 签名验证失败 | 严格遵循 SPDM 规范，参考 rust-spdm 实现 |
| Transcript hash 计算错误 | KEY_EXCHANGE 失败 | 仔细记录每步消息，测试 transcript 内容 |
| AEAD nonce 构造错误 | 解密失败 | 对比 libspdm 的 nonce 构造方式 |
| FFI 类型映射错误 | 链接/运行失败 | 使用 cbindgen 自动生成头文件 |
| Phase 1 验证不通过 | 阻塞后续阶段 | 预留缓冲时间，充分测试 |

---

## 里程碑

| 里程碑 | 时间 | 标志 |
|--------|------|------|
| M1: Phase 1 完成 | 第 18 天 | libspdm 替换完成，C DOE/TDISP 可调用 |
| M2: Phase 2 完成 | 第 21 天 | DOE 层 Rust 完成，C TDISP 可调用 |
| M3: Phase 3 完成 | 第 26.5 天 | 全栈 Rust 完成，无 C requester 依赖 |