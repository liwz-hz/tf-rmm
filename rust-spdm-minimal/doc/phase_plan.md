# 分阶段实施计划

## 总览

| 阶段 | 内容 | 工作量 | 时间 | 消除的 C 依赖 |
|------|------|--------|------|---------------|
| Phase 1 | SPDM Core + IDE-KM 打桩 | ~3500 LOC | 20 天 | ext/libspdm/* (~50k LOC) |
| Phase 2 | DOE 层 | ~200 LOC | 3 天 | ext/spdm-emu/library/pci_doe_requester_lib/ (~136 LOC) |
| Phase 3 | TDISP 层 | ~400 LOC | 5.5 天 | ext/spdm-emu/library/pci_tdisp_requester_lib/ (~300 LOC) |

**总计**：约 28.5 天

---

## 单元测试要求

所有新开发代码必须有单元测试覆盖：

| 测试类型 | 覆盖范围 | 要求 |
|----------|----------|------|
| **成功场景** | 主要功能路径 | 必须覆盖，验证正常流程 |
| **失败场景** | 主要错误路径 | 覆盖关键失败点（参数错误、边界条件） |
| **边缘场景** | 特殊情况 | 可选，按需补充 |

**测试命名规范**：
```rust
#[test]
fn test_sha256_success() { ... }          // 成功场景

#[test]
fn test_sha256_empty_input() { ... }      // 边缘场景

#[test]
fn test_aes_gcm_decrypt_wrong_tag() { ... } // 失败场景
```

---

## Phase 1: SPDM Core + IDE-KM 打桩

### 目标

替换 libspdm 核心，让现有 DOE/TDISP C 层能工作。

### 子阶段划分

根据依赖关系，调整为：

```
P1-A: 项目框架        (3 天)   不依赖加密
    ↓
P1-C: 明文协议层      (5 天)   不依赖加密，可独立测试
    ↓
    │  【里程碑】第8天：VERSION→CAPS→ALGO→CERT 明文流程跑通
    ↓
P1-B: 加密模块        (5 天)   KEY_EX 前必须完成
    ↓
P1-D: 会话协议层      (3 天)   依赖加密
    ↓
P1-E: FFI + 打桩      (2 天)
    ↓
P1-F: 集成测试        (2 天)
```

---

### P1-A: 项目框架 (3 天)

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| A1 | Cargo.toml + 目录结构 | 无 |
| A2 | lib.rs 入口 | 无 |
| A3 | context.rs (SpdmContext) | `test_context_init_success` |
| A4 | error.rs (SpdmStatus) | `test_status_success`, `test_status_error_codes` |
| A5 | message/header.rs (SPDM Header) | `test_header_encode_success`, `test_header_decode_success` |
| A6 | message/codec.rs (编解码 trait) | `test_codec_basic_types` |
| A7 | build.rs + cbindgen.toml | 无（构建验证） |

**验证**：`cargo build --release` 成功

---

### P1-C: 明文协议层 (5 天)

**依赖分析**：VERSION/CAPS/ALGO/DIGEST/CERT 均不涉及加密，纯编解码 + 消息收发

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| C1 | message/payload.rs (消息结构定义) | `test_payload_sizes` |
| C2 | protocol/version.rs | `test_version_request_encode`, `test_version_response_decode` |
| C3 | protocol/capabilities.rs | `test_caps_request_encode`, `test_caps_response_decode` |
| C4 | protocol/algorithms.rs | `test_algo_request_encode`, `test_algo_response_decode` |
| C5 | protocol/digest.rs | `test_digest_request_encode`, `test_digest_response_decode` |
| C6 | protocol/certificate.rs | `test_cert_request_encode`, `test_cert_partial_response` |
| C7 | protocol/vendor.rs (VDM 结构) | `test_vendor_request_encode` |

**单元测试重点**：
- 成功：encode/decode 正常数据
- 失败：decode 无效格式、超长数据

**集成验证**：`python tfrmm.py run` 
- VERSION 协商成功
- CAPABILITIES 协商成功
- ALGORITHMS 协商成功
- DIGESTS 返回 slot_mask
- CERTIFICATE 完整获取

---

### P1-B: 加密模块 (5 天)

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| B1 | crypto/hash.rs (SHA-256/384) | `test_sha256_known_vector`, `test_sha384_known_vector`, `test_sha256_empty` |
| B2 | crypto/dhe.rs (ECDH P-256/P-384) | `test_ecdh_p256_keypair`, `test_ecdh_p256_shared_secret`, `test_ecdh_p384_keypair` |
| B3 | crypto/sign.rs (ECDSA 验证) | `test_ecdsa_verify_success`, `test_ecdsa_verify_wrong_signature`, `test_ecdsa_verify_wrong_key` |
| B4 | crypto/hkdf.rs | `test_hkdf_expand_sha256`, `test_hkdf_extract_sha256`, `test_hkdf_expand_zero_info` |
| B5 | crypto/aead.rs (AES-128/256-GCM) | `test_aes_gcm_encrypt_decrypt`, `test_aes_gcm_decrypt_wrong_tag`, `test_aes_gcm_decrypt_wrong_key` |
| B6 | crypto/rand.rs (随机数) | `test_random_bytes_non_zero`, `test_random_bytes_length` |

**单元测试重点**：
- 成功：使用已知测试向量（NIST/标准测试数据）
- 失败：错误 key/nonce/tag、边界长度

**已知测试向量示例**：
```rust
// SHA-256: "abc" 的标准输出
assert_eq!(sha256("abc"), [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
]);
```

---

### P1-D: 会话协议层 (3 天)

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| D1 | session/context.rs (SessionInfo) | `test_session_init`, `test_session_state_transition` |
| D2 | session/keys.rs (密钥派生) | `test_key_derivation_master_secret`, `test_key_derivation_encryption_key` |
| D3 | protocol/key_exchange.rs | `test_key_exchange_request_encode`, `test_key_exchange_response_decode` |
| D4 | protocol/finish.rs | `test_finish_request_encode`, `test_finish_response_decode` |
| D5 | session/secured.rs (AEAD 封装) | `test_secured_encode_success`, `test_secured_decode_success`, `test_secured_decode_wrong_session` |
| D6 | protocol/end_session.rs | `test_end_session_encode` |

**单元测试重点**：
- 成功：密钥派生正确、消息编解码正确
- 失败：session_id 无效、密钥长度错误

**集成验证**：
- KEY_EXCHANGE 成功，session_id != 0
- FINISH 成功，session 建立
- END_SESSION 成功

---

### P1-E: FFI 层 + IDE-KM 打桩 (2 天)

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| E1 | ffi/types.rs (FFI 类型) | 无（类型定义） |
| E2 | ffi/libspdm.rs (~25 函数) | 通过 C 调用验证 |
| E3 | ffi/pci_ide_km.rs (4 个打桩) | `test_ide_km_stub_returns_unsupported` |
| E4 | rust_spdm.h 生成验证 | 头文件包含所有函数声明 |

**IDE-KM 打桩实现**：
```rust
#[no_mangle]
pub extern "C" fn pci_ide_km_query(...) -> u32 {
    LIBSPDM_STATUS_UNSUPPORTED_CAP  // 固定返回不支持
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_prog(...) -> u32 {
    LIBSPDM_STATUS_UNSUPPORTED_CAP
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_set_go(...) -> u32 {
    LIBSPDM_STATUS_UNSUPPORTED_CAP
}

#[no_mangle]
pub extern "C" fn pci_ide_km_key_set_stop(...) -> u32 {
    LIBSPDM_STATUS_UNSUPPORTED_CAP
}
```

---

### P1-F: 集成测试 (2 天)

| 任务 | 内容 | 验证方式 |
|------|------|----------|
| F1 | CMake 集成 | `python tfrmm.py build` 成功 |
| F2 | VERSION→CAPS→ALGO 流程 | fakehost + responder_emu |
| F3 | CERTIFICATE 获取 | 完整证书链 |
| F4 | KEY_EX→FINISH 流程 | session 建立 |
| F5 | Secured Message 收发 | 加密消息正确 |
| F6 | TDISP 调用验证 | C DOE/TDISP 调用 Rust 成功 |

---

### Phase 1 验证点汇总

- [ ] 第 3 天：`cargo build --release` 成功
- [ ] 第 5 天：message 单元测试通过
- [ ] 第 8 天：明文协议 VERSION→CAPS→ALGO→CERT 跑通
- [ ] 第 13 天：加密模块单元测试全部通过
- [ ] 第 16 天：KEY_EX→FINISH 会话建立
- [ ] 第 18 天：FFI 函数 CMake 链接成功
- [ ] 第 20 天：完整 fakehost 流程跑通

---

## Phase 2: DOE 层

### 目标

移除 `pci_doe_requester_lib` C 依赖，实现纯 Rust DOE 层。

### 前置条件

- Phase 1 完成并验证通过
- `libspdm_send_receive_data()` FFI 正常工作

### 任务拆解

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| P2-01 | doe/message.rs (Vendor Defined 结构) | `test_vdm_request_encode`, `test_vdm_response_decode` |
| P2-02 | doe/vendor.rs (pci_doe_spdm_vendor_send_receive_data) | `test_vendor_send_success`, `test_vendor_send_wrong_protocol` |
| P2-03 | ffi/pci_doe.rs (4 个 FFI 函数) | C 调用验证 |
| P2-04 | CMake 修改 | 构建验证 |
| P2-05 | 集成测试 | TDISP 通过 Rust DOE 成功 |

**Phase 2 总计**：3 天

### 验证点

- [ ] DOE 单元测试通过
- [ ] CMake 不再链接 `rmm-pci_doe_requester_lib`
- [ ] TDISP lock 通过 Rust DOE 成功

---

## Phase 3: TDISP 层

### 目标

移除 `pci_tdisp_requester_lib` C 依赖，实现纯 Rust TDISP 层。

### 前置条件

- Phase 2 完成并验证通过
- DOE 层 Rust 实现正常工作

### 任务拆解

| 任务 | 内容 | 单元测试 |
|------|------|----------|
| P3-01 | tdisp/message.rs (TDISP 消息结构) | `test_tdisp_lock_request`, `test_tdisp_lock_response`, `test_tdisp_start_request` |
| P3-02 | tdisp/requester.rs (全部 8 个函数) | `test_tdisp_get_version_success`, `test_tdisp_lock_success`, `test_tdisp_lock_wrong_state` |
| P3-03 | ffi/pci_tdisp.rs (8 个 FFI) | C 调用验证 |
| P3-04 | CMake 修改 | 构建验证 |
| P3-05 | 完整流程测试 | lock→report→start→stop |

**Phase 3 总计**：5.5 天

### 验证点

- [ ] TDISP 单元测试通过
- [ ] `pci_tdisp_get_version()` 成功
- [ ] `pci_tdisp_lock_interface()` 成功，状态 LOCKED
- [ ] `pci_tdisp_start_interface()` 成功，状态 RUN
- [ ] `pci_tdisp_stop_interface()` 成功，状态 UNLOCKED
- [ ] CMake 不再链接 `rmm-pci_tdisp_requester_lib`

---

## 完成标准

Phase 3 完成后达成：

### 代码层面

- `rmm.elf` 不链接任何 libspdm C 库
- `rmm.elf` 不链接任何 spdm-emu requester C 库
- 所有 requester 功能由 `rust_spdm_minimal.a` 提供
- 单元测试覆盖率 > 80%（成功场景 + 主要失败路径）

### 构建层面

- CMake 配置简化
- `cargo test` 全部通过

### 功能层面

- 与原有 C 实现功能完全一致
- TDISP 流程正常工作

---

## 里程碑

| 里程碑 | 时间 | 标志 |
|--------|------|------|
| M1-A | 第 3 天 | 项目框架完成，可编译 |
| M1-C | 第 8 天 | **明文协议跑通**：VERSION→CAPS→ALGO→CERT |
| M1-B | 第 13 天 | 加密模块完成，单元测试通过 |
| M1-D | 第 16 天 | **会话建立跑通**：KEY_EX→FINISH |
| M1-E | 第 18 天 | FFI 完成，CMake 链接成功 |
| M1 | 第 20 天 | **Phase 1 完成**：完整 fakehost 流程 |
| M2 | 第 23 天 | **Phase 2 完成**：DOE 层 Rust |
| M3 | 第 28.5 天 | **Phase 3 完成**：全栈 Rust，无 C requester |

---

## 测试文件结构

```
rust-spdm-minimal/
├── src/
│   └── ...
└── tests/
    ├── crypto_test.rs       # 加密模块单元测试
    ├── message_test.rs      # 消息编解码测试
    ├── protocol_test.rs     # 协议层测试（可用 mock transport）
    ├── session_test.rs      # 会话管理测试
    └── ffi_test.rs          # FFI 调用测试（需要 C 环境）
```

---

## 风险与应对

| 风险 | 影响 | 应对措施 |
|------|------|----------|
| 加密测试向量不匹配 | 算法实现错误 | 使用 NIST 标准测试数据 |
| 明文协议 C 调用失败 | FFI 签名不兼容 | cbindgen 自动生成头文件 |
| KEY_EX 签名验证失败 | Transcript 计算错误 | 逐消息打印 transcript 验证 |
| 单元测试覆盖不足 | 隐藏 bug | CI 强制测试通过才能提交 |