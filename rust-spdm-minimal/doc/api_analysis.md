# API 分析文档

## 分析来源

通过对 tf-rmm fakehost 代码的分析，识别出实际调用的 libspdm、DOE、TDISP、IDE-KM API。

分析方法：
1. 搜索 `app/` 和 `plat/` 目录下的 `#include` 语句
2. 搜索 `libspdm_`、`pci_tdisp_`、`pci_doe_`、`pci_ide_km_` 函数调用
3. 分析 CMakeLists.txt 链接依赖

---

## 一、libspdm Core API

### 1.1 上下文管理

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_init_context` | `libspdm_return_t libspdm_init_context(void *spdm_context)` | dev_assign_el0_app.c:1250 | P0 |
| `libspdm_deinit_context` | `void libspdm_deinit_context(void *spdm_context)` | dev_assign_el0_app.c:1150 | P0 |
| `libspdm_get_context_size` | `size_t libspdm_get_context_size(void)` | dev_assign_el0_app.c:1101,1280 | P0 |
| `libspdm_check_context` | `bool libspdm_check_context(void *spdm_context)` | dev_assign_el0_app.c:1288 | P0 |
| `libspdm_set_scratch_buffer` | `void libspdm_set_scratch_buffer(void *spdm_context, void *scratch_buffer, size_t scratch_buffer_size)` | dev_assign_el0_app.c:1285 | P0 |
| `libspdm_get_sizeof_required_scratch_buffer` | `size_t libspdm_get_sizeof_required_scratch_buffer(void *spdm_context)` | dev_assign_el0_app.c:1278 | P0 |

### 1.2 协议核心

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_init_connection` | `libspdm_return_t libspdm_init_connection(void *spdm_context, bool get_version_only)` | dev_assign_cmds.c:93,298 | P0 |
| `libspdm_get_certificate` | `libspdm_return_t libspdm_get_certificate(void *spdm_context, const uint32_t *session_id, uint8_t slot_id, size_t *cert_chain_size, void *cert_chain)` | dev_assign_cmds.c:111 | P0 |
| `libspdm_start_session` | `libspdm_return_t libspdm_start_session(void *spdm_context, bool use_psk, const void *psk_hint, uint16_t psk_hint_size, uint8_t measurement_hash_type, uint8_t slot_id, uint8_t session_policy, uint32_t *session_id, uint8_t *heartbeat_period, void *measurement_hash)` | dev_assign_cmds.c:170 | P0 |
| `libspdm_stop_session` | `libspdm_return_t libspdm_stop_session(void *spdm_context, uint32_t session_id, uint8_t end_session_attributes)` | dev_assign_cmds.c:283 | P0 |
| `libspdm_send_receive_data` | `libspdm_return_t libspdm_send_receive_data(void *spdm_context, const uint32_t *session_id, bool is_app_message, const void *request, size_t request_size, void *response, size_t *response_size)` | pci_doe_spdm_vendor_send_receive.c:75 | P0 |
| `libspdm_challenge` | `libspdm_return_t libspdm_challenge(void *spdm_context, void *reserved, uint8_t slot_id, uint8_t measurement_hash_type, void *measurement_hash, uint8_t *slot_mask)` | dev_assign_cmds.c:157 | P1 (调试) |
| `libspdm_get_measurement_ex` | `libspdm_return_t libspdm_get_measurement_ex(...)` | dev_assign_cmds.c:224 | P1 (可选) |

### 1.3 数据管理

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_set_data` | `libspdm_return_t libspdm_set_data(void *spdm_context, libspdm_data_type_t data_type, const libspdm_data_parameter_t *parameter, void *data, size_t data_size)` | dev_assign_el0_app.c + dev_assign_cmds.c 多处 | P0 |
| `libspdm_get_data` | `libspdm_return_t libspdm_get_data(void *spdm_context, libspdm_data_type_t data_type, const libspdm_data_parameter_t *parameter, void *data, size_t *data_size)` | dev_assign_el0_app.c:520 + dev_assign_cmds.c:32 + pci_doe_spdm_vendor_send_receive.c:58 | P0 |

### 1.4 回调注册

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_register_device_io_func` | `void libspdm_register_device_io_func(void *spdm_context, libspdm_device_send_message_func send_message, libspdm_device_receive_message_func receive_message)` | dev_assign_el0_app.c:1254 | P0 |
| `libspdm_register_transport_layer_func` | `void libspdm_register_transport_layer_func(void *spdm_context, uint32_t max_spdm_msg_size, uint32_t transport_header_size, uint32_t transport_tail_size, libspdm_transport_encode_message_func transport_encode_message, libspdm_transport_decode_message_func transport_decode_message)` | dev_assign_el0_app.c:1261 | P0 |
| `libspdm_register_device_buffer_func` | `void libspdm_register_device_buffer_func(void *spdm_context, uint32_t sender_buffer_size, uint32_t receiver_buffer_size, libspdm_device_acquire_sender_buffer_func acquire_sender_buffer, libspdm_device_release_sender_buffer_func release_sender_buffer, libspdm_device_acquire_receiver_buffer_func acquire_receiver_buffer, libspdm_device_release_receiver_buffer_func release_receiver_buffer)` | dev_assign_el0_app.c:1269 | P0 |
| `libspdm_register_verify_spdm_cert_chain_func` | `void libspdm_register_verify_spdm_cert_chain_func(void *spdm_context, const libspdm_verify_spdm_cert_chain_func verify_spdm_cert_chain)` | dev_assign_el0_app.c:1384 | P1 |

### 1.5 安全消息

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_encode_secured_message` | `libspdm_return_t libspdm_encode_secured_message(void *spdm_secured_message_context, uint32_t session_id, bool is_request_message, size_t app_message_size, void *app_message, size_t *secured_message_size, void *secured_message, const libspdm_secured_message_callbacks_t *spdm_secured_message_callbacks)` | dev_assign_el0_app.c:467 | P0 |
| `libspdm_decode_secured_message` | `libspdm_return_t libspdm_decode_secured_message(void *spdm_secured_message_context, uint32_t session_id, bool is_request_message, size_t secured_message_size, void *secured_message, size_t *app_message_size, void **app_message, const libspdm_secured_message_callbacks_t *spdm_secured_message_callbacks)` | dev_assign_el0_app.c:774 | P0 |
| `libspdm_get_secured_message_context_via_session_id` | `void *libspdm_get_secured_message_context_via_session_id(void *spdm_context, uint32_t session_id)` | dev_assign_el0_app.c:458,764 | P0 |

### 1.6 错误处理

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_get_last_spdm_error_struct` | `void libspdm_get_last_spdm_error_struct(void *spdm_context, libspdm_error_struct_t *last_spdm_error)` | dev_assign_el0_app.c:780 | P1 |
| `libspdm_set_last_spdm_error_struct` | `void libspdm_set_last_spdm_error_struct(void *spdm_context, libspdm_error_struct_t *last_spdm_error)` | dev_assign_el0_app.c:769,782 | P1 |
| `libspdm_secured_message_get_last_spdm_error_struct` | `void libspdm_secured_message_get_last_spdm_error_struct(void *spdm_secured_message_context, libspdm_error_struct_t *last_spdm_error)` | dev_assign_el0_app.c:780 | P1 |

### 1.7 加密工具

| 函数 | 签名 | 调用位置 | 优先级 |
|------|------|----------|--------|
| `libspdm_get_hash_size` | `uint32_t libspdm_get_hash_size(uint32_t base_hash_algo)` | dev_assign_el0_app.c:544 | P0 |
| `libspdm_get_random_number` | `bool libspdm_get_random_number(size_t size, void *rand)` | dev_assign_ide_cmds.c:23 | P0 |

---

## 二、libspdm_data_type_t 使用枚举

实际使用的 data_type：

| 类型枚举 | 用途 | 操作 |
|----------|------|------|
| `LIBSPDM_DATA_SPDM_VERSION` | 获取协商版本 | GET (DOE 层需要) |
| `LIBSPDM_DATA_BASE_HASH_ALGO` | Hash 算法 | SET/GET |
| `LIBSPDM_DATA_CAPABILITY_FLAGS` | 能力标志 | SET |
| `LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE` | 传输大小 | SET/GET |
| `LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE` | 最大消息大小 | SET |
| `LIBSPDM_DATA_PEER_USED_CERT_CHAIN_HASH` | 证书链 hash | SET |
| `LIBSPDM_DATA_MEASUREMENT_SPEC` | 测量规范 | SET |
| `LIBSPDM_DATA_MEASUREMENT_HASH_ALGO` | 测量 hash 算法 | SET |
| `LIBSPDM_DATA_BASE_ASYM_ALGO` | 签名算法 | SET |
| `LIBSPDM_DATA_DHE_NAME_GROUP` | DHE 组 | SET |
| `LIBSPDM_DATA_AEAD_CIPHER_SUITE` | AEAD 套件 | SET |
| `LIBSPDM_DATA_OTHER_PARAMS_SUPPORT` | 其他参数 | SET |

---

## 三、DOE API (来自 spdm-emu)

| 函数 | 签名 | 调用位置 |
|------|------|----------|
| `pci_doe_spdm_vendor_send_receive_data` | `libspdm_return_t pci_doe_spdm_vendor_send_receive_data(void *spdm_context, const uint32_t *session_id, pci_protocol_header_t pci_protocol, const void *request, size_t request_size, void *response, size_t *response_size)` | pci_tdisp_send_receive.c:36 |
| `pci_doe_spdm_vendor_send_receive_data_ex` | 扩展版本，带 vendor_id | - |
| `pci_doe_discovery` | 不使用 (fakehost 不需要) | - |
| `pci_doe_send_receive_data` | 平台提供，不使用 | - |

**内部依赖的 libspdm 函数**：
- `libspdm_get_data(LIBSPDM_DATA_SPDM_VERSION)`
- `libspdm_send_receive_data()`
- `libspdm_zero_mem()`
- `libspdm_copy_mem()`

---

## 四、TDISP API (来自 spdm-emu)

| 函数 | 签名 | 调用位置 |
|------|------|----------|
| `pci_tdisp_get_version` | `libspdm_return_t pci_tdisp_get_version(const void *pci_doe_context, void *spdm_context, const uint32_t *session_id, const pci_tdisp_interface_id_t *interface_id)` | dev_tdisp_cmds.c:35 |
| `pci_tdisp_get_capabilities` | `libspdm_return_t pci_tdisp_get_capabilities(...)` | dev_tdisp_cmds.c:46 |
| `pci_tdisp_get_interface_state` | `libspdm_return_t pci_tdisp_get_interface_state(...)` | dev_tdisp_cmds.c:56,97,183,212,257 |
| `pci_tdisp_lock_interface` | `libspdm_return_t pci_tdisp_lock_interface(...)` | dev_tdisp_cmds.c:84 |
| `pci_tdisp_get_interface_report` | `libspdm_return_t pci_tdisp_get_interface_report(...)` | dev_tdisp_cmds.c:140 |
| `pci_tdisp_start_interface` | `libspdm_return_t pci_tdisp_start_interface(...)` | dev_tdisp_cmds.c:199 |
| `pci_tdisp_stop_interface` | `libspdm_return_t pci_tdisp_stop_interface(...)` | dev_tdisp_cmds.c:248 |
| `pci_tdisp_send_receive_data` | 内部传输函数 | pci_tdisp_*.c 内部调用 |

---

## 五、IDE-KM API (来自 spdm-emu)

| 函数 | 签名 | 调用位置 | 处理方式 |
|------|------|----------|----------|
| `pci_ide_km_query` | `libspdm_return_t pci_ide_km_query(...)` | dev_assign_ide_cmds.c:396 | **打桩** |
| `pci_ide_km_key_prog` | `libspdm_return_t pci_ide_km_key_prog(...)` | dev_assign_ide_cmds.c:246,265 | **打桩** |
| `pci_ide_km_key_set_go` | `libspdm_return_t pci_ide_km_key_set_go(...)` | dev_assign_ide_cmds.c:184 | **打桩** |
| `pci_ide_km_key_set_stop` | `libspdm_return_t pci_ide_km_key_set_stop(...)` | dev_assign_ide_cmds.c:132 | **打桩** |

**打桩原因**：fakehost 中 IDE 功能已禁用 (`NCOH_IDE=FALSE`)，但接口需要存在以避免链接错误。

---

## 六、回调函数类型 (tf-rmm 实现)

以下回调类型由 tf-rmm 实现，注册到 libspdm：

| 回调类型 | 函数名 | 位置 |
|----------|--------|------|
| `libspdm_device_send_message_func` | `spdm_send_message` | dev_assign_el0_app.c |
| `libspdm_device_receive_message_func` | `spdm_receive_message` | dev_assign_el0_app.c |
| `libspdm_transport_encode_message_func` | `spdm_transport_encode_message` | dev_assign_el0_app.c |
| `libspdm_transport_decode_message_func` | `spdm_transport_decode_message` | dev_assign_el0_app.c |
| `libspdm_device_acquire_sender_buffer_func` | `spdm_acquire_sender_buffer` | dev_assign_el0_app.c |
| `libspdm_device_release_sender_buffer_func` | `spdm_release_sender_buffer` | dev_assign_el0_app.c |
| `libspdm_device_acquire_receiver_buffer_func` | `spdm_acquire_receiver_buffer` | dev_assign_el0_app.c |
| `libspdm_device_release_receiver_buffer_func` | `spdm_release_receiver_buffer` | dev_assign_el0_app.c |
| `libspdm_verify_spdm_cert_chain_func` | `cma_spdm_verify_cert_chain` | dev_assign_el0_app.c |

---

## 七、SPDM 消息类型汇总

### 7.1 必须实现的消息

| 消息类型 | Request | Response | Phase |
|----------|---------|----------|-------|
| Version | GET_VERSION | VERSION | Phase 1 |
| Capabilities | GET_CAPABILITIES | CAPABILITIES | Phase 1 |
| Algorithms | NEGOTIATE_ALGORITHMS | ALGORITHMS | Phase 1 |
| Digests | GET_DIGESTS | DIGESTS | Phase 1 |
| Certificate | GET_CERTIFICATE | CERTIFICATE | Phase 1 |
| Key Exchange | KEY_EXCHANGE | KEY_EXCHANGE_RSP | Phase 1 |
| Finish | FINISH | FINISH_RSP | Phase 1 |
| End Session | END_SESSION | END_SESSION_ACK | Phase 1 |
| Vendor Defined | VENDOR_DEFINED_REQUEST | VENDOR_DEFINED_RESPONSE | Phase 1 |
| Secured Message | (AEAD 加密封装) | (AEAD 解密) | Phase 1 |

### 7.2 可选实现的消息

| 消息类型 | Request | Response | 备注 |
|----------|---------|----------|------|
| Challenge | CHALLENGE | CHALLENGE_AUTH | 调试用，LOG_LEVEL >= VERBOSE 时调用 |
| Measurement | GET_MEASUREMENTS | MEASUREMENTS | 可选 |

### 7.3 不需要实现的消息

| 消息类型 | 原因 |
|----------|------|
| PSK_EXCHANGE | fakehost 使用 KEY_EXCHANGE，不用 PSK |
| HEARTBEAT | fakehost 不使用 |
| KEY_UPDATE | fakehost 不使用 |
| Encapsulated | fakehost 不需要 MUT_AUTH |

---

## 八、加密算法需求

| 算法类别 | 必须支持 | 可选支持 |
|----------|----------|----------|
| Hash | SHA-256, SHA-384 | SHA-512 |
| DHE | ECDH P-256, ECDH P-384 | - |
| AEAD | AES-128-GCM, AES-256-GCM | ChaCha20-Poly1305 |
| Signature 验证 | ECDSA-P256, ECDSA-P384 | RSASSA-3072, RSAPSS-3072 |

---

## 九、头文件依赖

tf-rmm 业务代码实际 include 的头文件：

```c
// dev_assign_private.h
#include <industry_standard/spdm.h>
#include <industry_standard/spdm_secured_message.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_secured_message_lib.h>
#include <library/spdm_crypt_lib.h>

// dev_tdisp_cmds.c (通过 dev_assign_private.h)
#include <library/pci_tdisp_requester_lib.h>

// dev_assign_ide_cmds.c
#include <library/pci_ide_km_requester_lib.h>
```

**需要生成的 C 头文件**：
- `rust_spdm.h` - 包含所有 libspdm_*、pci_tdisp_*、pci_doe_*、pci_ide_km_* 函数声明

---

## 十、API 总数汇总

| 类别 | 函数数量 | 处理方式 |
|------|----------|----------|
| libspdm Core | ~25 | 完整实现 |
| DOE | ~4 | Phase 2 实现 |
| TDISP | ~8 | Phase 3 实现 |
| IDE-KM | ~4 | 打桩 |
| **总计** | ~41 | - |