# 技术设计文档

## 一、整体架构

### 1.1 tf-rmm SPDM 通信架构（关键理解）

**核心要点：Rust SPDM 库不负责底层 socket 通信，只负责协议逻辑。**

```
┌─────────────────────────────────────────────────────────────────────┐
│                          tf-rmm 架构分层                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  libspdm (C) / rust-spdm-minimal (Rust)                      │   │
│  │                                                             │   │
│  │  协议层：                                                    │   │
│  │  - libspdm_get_version()                                    │   │
│  │  - libspdm_get_capabilities()                               │   │
│  │  - libspdm_negotiate_algorithms()                           │   │
│  │  - libspdm_key_exchange()                                   │   │
│  │  - libspdm_finish()                                         │   │
│  │                                                             │   │
│  │  内部调用：                                                  │   │
│  │  - libspdm_send_spdm_request() → send_message_func() [回调] │   │
│  │  - libspdm_receive_spdm_response() → receive_message_func() │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          ↓ 注册回调                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  el0_app (用户态应用)                                        │   │
│  │                                                             │   │
│  │  dev_assign_el0_app.c:                                      │   │
│  │  - libspdm_register_device_io_func(                        │   │
│  │        spdm_send_message, spdm_receive_message)             │   │
│  │                                                             │   │
│  │  spdm_send_message():                                       │   │
│  │  - el0_app_service_call(APP_SERVICE_WRITE_TO_NS_BUF)       │   │
│  │  - el0_app_yield() ← 等待 NS host 处理                      │   │
│  │                                                             │   │
│  │  spdm_receive_message():                                    │   │
│  │  - el0_app_service_call(APP_SERVICE_READ_FROM_NS_BUF)      │   │
│  │  - el0_app_yield()                                          │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          ↓ NS host 处理                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  host_da.c (Host 层)                                         │   │
│  │                                                             │   │
│  │  host_dev_communicate():                                    │   │
│  │  - host_rmi_dev_communicate() → 调用 RMI                    │   │
│  │  - 检查 dcomm_exit.flags & REQ_SEND_BIT                     │   │
│  │  - host_pdev_spdm_rsp_communicate() ← 发送请求              │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          ↓ socket 通信                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  host_spdm_rsp_ifc.c (Socket 层)                             │   │
│  │                                                             │   │
│  │  host_spdm_rsp_communicate(spdm_rsp_id, req, rsp):          │   │
│  │  - host_send_doe_spdm_req() → TCP send                      │   │
│  │  - host_recv_doe_spdm_rsp() → TCP recv                      │   │
│  │                                                             │   │
│  │  TCP 协议：                                                  │   │
│  │  - send_data32(SOCKET_SPDM_COMMAND_NORMAL)                  │   │
│  │  - send_data32(SOCKET_TRANSPORT_TYPE_PCI_DOE)               │   │
│  │  - send_data32(payload_size)                                │   │
│  │  - send_bytes(doe_header + spdm_payload)                   │   │
│  │                                                             │   │
│  │  socket: TCP port 2323, connected to responder_emu         │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          ↓ TCP socket                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  spdm_responder_emu (独立进程, C)                            │   │
│  │                                                             │   │
│  │  监听 port 2323                                              │   │
│  │  接收 DOE 封装的 SPDM 请求                                   │   │
│  │  处理并返回响应                                              │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 调用链详细分析

**GET_VERSION 示例流程：**

```
1. dev_assign_cmds.c:
   libspdm_init_connection(spdm_context)
   
2. libspdm_req_get_version.c:
   libspdm_try_get_version()
     → libspdm_send_spdm_request(spdm_context, NULL, request_size, request)
       → spdm_context->send_message(spdm_context, request_size, request, timeout)
         ↑ 这是注册的回调

3. dev_assign_el0_app.c (回调实现):
   spdm_send_message(spdm_context, request_size, request, timeout):
     → el0_app_service_call(APP_SERVICE_WRITE_TO_NS_BUF, ...)
       → el0_app_yield()  ← 暂停，等待 NS host

4. host_da.c (NS host 处理):
   host_dev_communicate():
     → host_rmi_dev_communicate()  ← RMI SMC
     → dcomm_exit.flags |= REQ_SEND_BIT
     → host_pdev_spdm_rsp_communicate(h_pdev, dcomm_enter, dcomm_exit)

5. host_spdm_rsp_ifc.c:
   host_pdev_spdm_rsp_communicate():
     → host_spdm_rsp_communicate(spdm_rsp_id, req_buf, req_len, rsp_buf, rsp_len)
       → host_send_doe_spdm_req():
         - send_data32(sock_fd, SOCKET_SPDM_COMMAND_NORMAL)
         - send_data32(sock_fd, SOCKET_TRANSPORT_TYPE_PCI_DOE)
         - send_data32(sock_fd, payload_size)
         - send_bytes(sock_fd, doe_header)
         - send_bytes(sock_fd, spdm_request)
         
       → host_recv_doe_spdm_rsp():
         - recv_data32(sock_fd, &command)
         - recv_data32(sock_fd, &transport_type)
         - recv_data32(sock_fd, &payload_size)
         - recv_bytes(sock_fd, doe_header)
         - recv_bytes(sock_fd, spdm_response)

6. spdm_responder_emu (独立进程):
   接收 TCP 数据 → 解析 DOE → 处理 SPDM GET_VERSION → 返回 VERSION

7. 返回路径 (反向):
   host_spdm_rsp_communicate() 返回 → 
   host_pdev_spdm_rsp_communicate() 返回 → 
   dcomm_enter.status = RESPONSE → 
   el0_app 从 yield 恢复 → 
   spdm_receive_message() 读取响应 → 
   libspdm_try_get_version() 解析 VERSION
```

### 1.3 Rust SPDM 库的角色

**Rust 只需实现：**
- 协议层逻辑（GET_VERSION/CAPS/ALGO/KEY_EX/FINISH 等）
- 存储注册的回调函数指针
- 在协议函数中调用回调

**Rust 不需实现：**
- Socket 通信（由 host_spdm_rsp_ifc.c 负责）
- DOE 封装（由 host_da.c 调用 host_spdm_rsp_ifc.c）
- el0_app_service_call（由 C 的回调实现）

### 1.4 关键代码位置

| 文件 | 职责 | Rust 需要交互的部分 |
|------|------|---------------------|
| `ext/libspdm/library/spdm_requester_lib/*.c` | SPDM 协议实现 | Rust FFI 替代 |
| `app/device_assignment/el0_app/src/dev_assign_el0_app.c` | 注册回调、回调实现 | Rust 通过 FFI 接收回调指针 |
| `plat/host/host_build/src/host_da.c` | Host 层设备通信 | 不交互 |
| `plat/host/host_build/src/host_spdm_rsp_ifc.c` | TCP socket 通信 | 不交互 |

### 1.5 Rust FFI 实现要点

```rust
// 存储回调指针
static mut GLOBAL_CONTEXT: SpdmContextState = SpdmContextState {
    send_message_func: AtomicPtr::new(null),
    receive_message_func: AtomicPtr::new(null),
    ...
};

// 注册回调
pub extern "C" fn libspdm_register_device_io_func(
    _context: libspdm_context_t,
    send_message_func: *mut c_void,
    receive_message_func: *mut c_void,
) -> libspdm_return_t {
    let state = get_context_state();
    state.send_message_func.store(send_message_func, Ordering::SeqCst);
    state.receive_message_func.store(receive_message_func, Ordering::SeqCst);
    LIBSPDM_STATUS_SUCCESS
}

// 在协议函数中调用回调
pub extern "C" fn libspdm_init_connection(context: libspdm_context_t) -> libspdm_return_t {
    // 构造 GET_VERSION 请求
    let request = [SPDM_VERSION_1_2, SPDM_GET_VERSION, 0, 0];
    
    // 调用注册的回调
    let send_func = state.send_message_func.load(Ordering::SeqCst);
    let func: SendMessageFunc = transmute(send_func);
    func(context, request.len(), &request, 0);
    
    // 等待并接收响应（通过 receive_message_func）
    ...
}
```

---

## 二、核心数据结构

### 2.1 SpdmContext

```rust
#[repr(C)]
pub struct SpdmContext {
    connection_state: ConnectionState,
    negotiated_info: NegotiatedInfo,
    
    cert_slot_id: u8,
    cert_chain_hash: [u8; MAX_HASH_SIZE],
    cert_chain_hash_len: usize,
    
    transcript_a: [u8; TRANSCRIPT_A_SIZE],
    transcript_a_len: usize,
    transcript_m: [u8; TRANSCRIPT_M_SIZE],
    transcript_m_len: usize,
    
    sessions: [SessionInfo; MAX_SESSIONS],
    
    send_message_cb: Option<SendMessageCallback>,
    receive_message_cb: Option<ReceiveMessageCallback>,
    transport_encode_cb: Option<TransportEncodeCallback>,
    transport_decode_cb: Option<TransportDecodeCallback>,
    acquire_sender_cb: Option<AcquireSenderBufferCallback>,
    release_sender_cb: Option<ReleaseSenderBufferCallback>,
    acquire_receiver_cb: Option<AcquireReceiverBufferCallback>,
    release_receiver_cb: Option<ReleaseReceiverBufferCallback>,
    verify_cert_cb: Option<VerifyCertChainCallback>,
    
    scratch_buffer: *mut u8,
    scratch_buffer_size: usize,
    
    last_error: SpdmErrorStruct,
    
    app_context: *mut c_void,
}
```

### 2.2 NegotiatedInfo

```rust
#[repr(C)]
pub struct NegotiatedInfo {
    version: SpdmVersion,        // 协商版本 (默认 1.2)
    hash_algo: HashAlgo,         // SHA-256 或 SHA-384
    dhe_group: DheGroup,         // SECP256R1 或 SECP384R1
    aead_suite: AeadSuite,       // AES-128-GCM 或 AES-256-GCM
    base_asym_algo: BaseAsymAlgo, // ECDSA-P256/P384 等
    measurement_spec: u8,
    measurement_hash_algo: u32,
    other_params: u8,
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
    
    requester_capabilities_flags: u32,
    responder_capabilities_flags: u32,
}
```

### 2.3 SessionInfo

```rust
#[repr(C)]
pub struct SessionInfo {
    session_id: u32,
    state: SessionState,
    
    requester_seq_num: u64,
    responder_seq_num: u64,
    
    encryption_key: [u8; MAX_KEY_SIZE],   // AEAD encryption
    decryption_key: [u8; MAX_KEY_SIZE],   // AEAD decryption
    salt: [u8; MAX_SALT_SIZE],            // AEAD IV
    
    master_secret: [u8; MAX_HASH_SIZE],
    handshake_secret: [u8; MAX_HASH_SIZE],
    data_secret: [u8; MAX_HASH_SIZE],
    
    dhe_shared_secret: Option<[u8; MAX_DHE_SHARED_SIZE]>,
}
```

### 2.4 常量定义

```rust
pub const MAX_SESSIONS: usize = 1;
pub const MAX_CERT_CHAIN_SIZE: usize = 65536;
pub const MAX_HASH_SIZE: usize = 64;          // SHA-512 最大
pub const MAX_KEY_SIZE: usize = 32;           // AES-256 key
pub const MAX_SALT_SIZE: usize = 12;          // AES-GCM IV
pub const MAX_DHE_SHARED_SIZE: usize = 48;    // ECDH P-384
pub const MAX_SPDM_MSG_SIZE: usize = 4096;
pub const TRANSCRIPT_A_SIZE: usize = 2048;    // VCA + CERT
pub const TRANSCRIPT_M_SIZE: usize = 4096;    // KEY_EX + FINISH
pub const SCRATCH_BUFFER_SIZE: usize = 4096;
```

---

## 三、SPDM 协议流程

### 3.1 连接建立 (libspdm_init_connection)

```
Step 1: GET_VERSION
    Request:  {version=1.0, request_code=GET_VERSION}
    Response: {version_number_entry_count, versions[]}
    Action:   选择最高兼容版本 (优先 1.2)
    
Step 2: GET_CAPABILITIES  
    Request:  {version, flags, ct_exponent, data_transfer_size, max_spdm_msg_size}
    Response: {flags, ct_exponent, data_transfer_size, max_spdm_msg_size}
    Action:   检查 responder 是否支持必须能力
    
Step 3: NEGOTIATE_ALGORITHMS
    Request:  {version, measurement_spec, base_asym_algo[], base_hash_algo[], 
               dhe_group[], aead_suite[], key_schedule, other_params}
    Response: {measurement_spec, measurement_hash_algo, base_asym_sel, base_hash_sel,
               dhe_sel, aead_sel, key_schedule_sel, other_params_sel}
    Action:   选择匹配的算法组合
    
State: connection_state = Negotiated
Transcript: append_message_a(request || response for each step)
```

### 3.2 证书获取 (libspdm_get_certificate)

```
Step 1: GET_DIGESTS
    Request:  {version, request_code=GET_DIGESTS}
    Response: {slot_mask, digest[]}
    Action:   获取可用证书槽
    
Step 2: GET_CERTIFICATE (分段循环)
    Request:  {version, slot_id, offset=0, length=4096}
    Response: {portion_length, remainder_length, cert_chain_portion}
    Action:   累加 portion，直到 remainder_length=0
    
State: connection_state = AfterCertificate
Transcript: append_message_a(all CERTIFICATE exchanges)

Callback: 通过注册的 verify_cert_cb 验证证书链
         计算 cert_chain_hash (使用协商的 hash 算法)
         调用 libspdm_set_data(PEER_USED_CERT_CHAIN_HASH)
```

### 3.3 会话建立 (libspdm_start_session)

```
Step 1: KEY_EXCHANGE
    Request:  
        - version, request_code=KEY_EXCHANGE
        - measurement_summary_hash_type
        - slot_id
        - requester_random[32]
        - exchange_data (DHE 公钥)
        - opaque_data
    Response:
        - session_id (req_half | rsp_half)
        - responder_random[32]
        - exchange_data (DHE 公钥)
        - measurement_summary_hash
        - responder_verify_data (签名)
    Action:
        - 计算 DHE shared_secret = ECDH(req_priv, rsp_pub)
        - 验证签名 (使用证书公钥，签名覆盖 transcript)
        - 密钥派生:
            master_secret = HKDF-Extract(salt=0, IKM=shared_secret)
            handshake_secret = HKDF-Expand-Label(master_secret, "handshake secret", hash(transcript))
            finished_key = HKDF-Expand-Label(handshake_secret, "finished", "")
            data_secret = HKDF-Expand-Label(master_secret, "data secret", hash(transcript))
            encryption_key = HKDF-Expand-Label(data_secret, "encryption key", "")
            decryption_key = HKDF-Expand-Label(data_secret, "decryption key", "")
            salt = HKDF-Expand-Label(data_secret, "salt", "")
    
State: session.state = Handshaking
Transcript: append_message_m(KEY_EX request || response)

Step 2: FINISH
    Request:
        - version, request_code=FINISH
        - finish_verify_data (MAC using finished_key)
        - (可选) requester_verify_data (签名)
    Response:
        - finish_verify_data (MAC)
    Action:
        - 验证 responder MAC
        - 计算 requester MAC
        - 完成密钥派生
        
State: session.state = Established
Transcript: append_message_m(FINISH request || response)
```

### 3.4 会话关闭 (libspdm_stop_session)

```
Step 1: END_SESSION
    Request:
        - version, request_code=END_SESSION
        - session_id
        - end_session_attributes
    Response:
        - version, response_code=END_SESSION_ACK
        
Action:
    - 清零 session 密钥
    - session.state = NotStarted
    - session_id = 0
```

---

## 四、密钥派生细节

### 4.1 HKDF-Expand-Label 定义

```rust
fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
    hash_algo: HashAlgo,
) -> Vec<u8> {
    // SPDM 定义:
    // expand_label_data = length || "spdm1.x " + label || context
    // expanded_key = HKDF-Expand(secret, expand_label_data, length)
    
    let spdm_label = format!("spdm1.{} {}", version, label);
    let mut expand_info = Vec::new();
    expand_info.extend_from_slice(&(length as u16).to_be_bytes());
    expand_info.extend_from_slice(spdm_label.as_bytes());
    expand_info.extend_from_slice(context);
    
    hkdf_expand(secret, &expand_info, length, hash_algo)
}
```

### 4.2 密钥派生流程图

```
shared_secret (DHE)
        │
        ▼ HKDF-Extract(salt=0)
    master_secret
        │
        ├────────────────────────────────────────┐
        │                                        │
        ▼ HKDF-Expand-Label("handshake secret")  │
    handshake_secret                            │
        │                                        │
        ├────────────┐                           │
        │            │                           │
        ▼            ▼                           │
    requester    responder                       │
    finished_key finished_key                    │
        │            │                           │
        │            │ (用于 FINISH MAC)        │
        │                                        │
        │◀───────────── transcript_m hash ───────┘
        │
        ▼ HKDF-Expand-Label("data secret", hash(transcript_m))
    data_secret
        │
        ├────────────┬────────────┐
        │            │            │
        ▼            ▼            ▼
    encryption   decryption    salt
    key          key           (AEAD IV)
    (requester→  (responder→
     responder)   requester)
```

---

## 五、AEAD 加密封装

### 5.1 Secured Message 结构

```
Plain SPDM Message:
┌────────────────────┐
│ SPDM Header        │
│ Payload            │
└────────────────────┘

Secured Message (AEAD encrypted):
┌───────────────────────────────────────────────────┐
│ Sequence Number (4 or 8 bytes)                   │
│ Session ID (4 bytes)                             │
│ Encrypted Payload                                │
│ AEAD Tag (16 bytes)                              │
└───────────────────────────────────────────────────┘

AAD (Additional Authenticated Data):
┌───────────────────────────────────────────────────┐
│ Sequence Number                                   │
│ Session ID                                        │
└───────────────────────────────────────────────────┘

Nonce:
┌───────────────────────────────────────────────────┐
│ Salt (从 data_secret 派生)                        │
│ Sequence Number                                   │
└───────────────────────────────────────────────────┘ (12 bytes total)
```

### 5.2 加密流程

```rust
fn encode_secured_message(
    session: &SessionInfo,
    plaintext: &[u8],
) -> Vec<u8> {
    let seq_num = session.requester_seq_num;
    let session_id = session.session_id;
    
    // AAD = seq_num || session_id
    let aad = build_aad(seq_num, session_id);
    
    // nonce = salt || seq_num
    let nonce = build_nonce(&session.salt, seq_num);
    
    // AES-GCM encrypt
    let (ciphertext, tag) = aes_gcm_encrypt(
        &session.encryption_key,
        &nonce,
        plaintext,
        &aad,
    );
    
    // Increment sequence number
    session.requester_seq_num += 1;
    
    // Result = seq_num || session_id || ciphertext || tag
    build_secured_message(seq_num, session_id, ciphertext, tag)
}
```

### 5.3 解密流程

```rust
fn decode_secured_message(
    session: &SessionInfo,
    secured_message: &[u8],
) -> Result<Vec<u8>, SpdmError> {
    // Parse secured message
    let (seq_num, session_id, ciphertext, tag) = parse_secured_message(secured_message)?;
    
    // Verify session_id matches
    if session_id != session.session_id {
        return Err(SpdmError::InvalidSession);
    }
    
    // Verify sequence number (optional replay protection)
    if seq_num != session.responder_seq_num {
        // Could be acceptable if not enforcing strict ordering
    }
    
    // Build AAD and nonce
    let aad = build_aad(seq_num, session_id);
    let nonce = build_nonce(&session.salt, seq_num);
    
    // AES-GCM decrypt
    let plaintext = aes_gcm_decrypt(
        &session.decryption_key,
        &nonce,
        ciphertext,
        tag,
        &aad,
    )?;
    
    // Update sequence number
    session.responder_seq_num = seq_num + 1;
    
    Ok(plaintext)
}
```

---

## 六、Vendor Defined Message 封装

### 6.1 SPDM VDM 结构

```
Vendor Defined Request:
┌────────────────────────────────────────────────────────────────┐
│ SPDM Header (version=1.x, request_code=VENDOR_DEFINED_REQUEST) │
│ Standard ID (2 bytes) = SPDM_STANDARD_ID_PCISIG (0x0001)       │
│ Vendor ID Length (1 byte) = 2                                  │
│ Vendor ID (2 bytes) = SPDM_VENDOR_ID_PCISIG (0x0001)           │
│ Payload Length (2 bytes)                                       │
│ PCI Protocol ID (1 byte)                                       │
│ Protocol-specific Payload                                      │
└────────────────────────────────────────────────────────────────┘

Vendor Defined Response:
┌────────────────────────────────────────────────────────────────┐
│ SPDM Header (version, response_code=VENDOR_DEFINED_RESPONSE)   │
│ Standard ID (2 bytes)                                          │
│ Vendor ID Length (1 byte)                                      │
│ Vendor ID (2 bytes)                                            │
│ Payload Length (2 bytes)                                       │
│ PCI Protocol ID (1 byte)                                       │
│ Protocol-specific Payload                                      │
└────────────────────────────────────────────────────────────────┘
```

### 6.2 DOE 封装层

```rust
pub fn pci_doe_spdm_vendor_send_receive_data(
    spdm_context: &mut SpdmContext,
    session_id: Option<&u32>,
    pci_protocol: PciProtocolHeader,
    request: &[u8],
) -> Result<Vec<u8>, SpdmError> {
    // Get negotiated SPDM version
    let version = spdm_context.get_data(LIBSPDM_DATA_SPDM_VERSION)?;
    
    // Build Vendor Defined Request
    let vdm_request = VendorDefinedRequest {
        spdm_header: SpdmHeader {
            version,
            request_code: SPDM_VENDOR_DEFINED_REQUEST,
        },
        standard_id: SPDM_STANDARD_ID_PCISIG,
        vendor_id: SPDM_VENDOR_ID_PCISIG,
        payload_length: (sizeof(PciProtocolHeader) + request.len()) as u16,
        pci_protocol,
        payload: request,
    };
    
    // Send via libspdm_send_receive_data
    let response = libspdm_send_receive_data(
        spdm_context,
        session_id,
        false,  // not app message
        &vdm_request.encode(),
    )?;
    
    // Parse Vendor Defined Response
    let vdm_response = VendorDefinedResponse::decode(&response)?;
    
    // Verify response fields match request
    assert_eq!(vdm_response.standard_id, SPDM_STANDARD_ID_PCISIG);
    assert_eq!(vdm_response.vendor_id, SPDM_VENDOR_ID_PCISIG);
    assert_eq!(vdm_response.pci_protocol.protocol_id, pci_protocol.protocol_id);
    
    Ok(vdm_response.payload)
}
```

---

## 七、TDISP 消息结构

### 7.1 TDISP Header

```rust
#[repr(C)]
pub struct PciTdispHeader {
    message_type: u8,
    reserved: u8,
    interface_id: PciTdispInterfaceId,
}

#[repr(C)]
pub struct PciTdispInterfaceId {
    function_id: u8,
    reserved: [u8; 3],
}

// TDISP Message Types
pub const PCI_TDISP_GET_VERSION: u8 = 0x01;
pub const PCI_TDISP_VERSION: u8 = 0x81;
pub const PCI_TDISP_GET_CAPABILITIES: u8 = 0x02;
pub const PCI_TDISP_CAPABILITIES: u8 = 0x82;
pub const PCI_TDISP_GET_INTERFACE_STATE: u8 = 0x03;
pub const PCI_TDISP_INTERFACE_STATE: u8 = 0x83;
pub const PCI_TDISP_LOCK_INTERFACE: u8 = 0x04;
pub const PCI_TDISP_LOCK_INTERFACE_RSP: u8 = 0x84;
pub const PCI_TDISP_GET_INTERFACE_REPORT: u8 = 0x05;
pub const PCI_TDISP_INTERFACE_REPORT: u8 = 0x85;
pub const PCI_TDISP_START_INTERFACE: u8 = 0x06;
pub const PCI_TDISP_START_INTERFACE_RSP: u8 = 0x86;
pub const PCI_TDISP_STOP_INTERFACE: u8 = 0x07;
pub const PCI_TDISP_STOP_INTERFACE_ACK: u8 = 0x87;
```

### 7.2 TDISP Protocol ID

```rust
pub const PCI_PROTOCOL_ID_TDISP: u8 = 0x01;
pub const PCI_PROTOCOL_ID_IDE_KM: u8 = 0x00;
```

---

## 八、加密后端实现

### 8.1 方案选择：纯 Rust 加密 Crates

**决策**：rust-spdm-minimal 内部使用纯 Rust 加密 crates，不依赖 mbedtls。

**架构**：
```
┌─────────────────────────────────────────────────────────────┐
│  rmm.elf                                                    │
│                                                             │
│  ├── C 业务代码 (其他功能)                                  │
│  │   └── 继续依赖 mbedtls ←── 保留，不受影响               │
│  │                                                          │
│  └── rust-spdm-minimal (SPDM/TDISP/DOE)                    │
│  │   ├── FFI 接口 (libspdm_*, pci_doe_*, pci_tdisp_*)     │
│  │   │   ↑ 仅暴露这层给 C 调用                             │
│  │   │                                                      │
│  │   └── 内部逻辑                                          │
│  │       └── 加密模块 (纯 Rust)                            │
│  │           ├── sha2      ← crates.io                    │
│  │           ├── aes-gcm   ← crates.io                    │
│  │           ├── p256      ← crates.io                    │
│  │           ├── p384      ← crates.io                    │
│  │           └── hkdf      ← crates.io                    │
│  │                                                          │
│  └─────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

**优势**：
- Rust SPDM 库完全独立，无 C 加密依赖
- rmm 其他业务继续用 mbedtls，互不干扰
- 两套加密实现并存，FFI 边界仅暴露协议接口
- 符合"彻底移除 spdm/tdisp/doe C 库"目标

### 8.2 Rust 加密 Crates

| 功能 | Crate | 版本 | 实现方式 | 社区使用 |
|------|-------|------|----------|----------|
| SHA-256/384 | `sha2` | 0.10 | 纯 Rust + optional ASM | 广泛使用 |
| AES-128/256-GCM | `aes-gcm` | 0.10 | 纯 Rust | 广泛使用 |
| ECDH P-256 | `p256` | 0.13 | 纯 Rust | 广泛使用 |
| ECDH P-384 | `p384` | 0.13 | 纯 Rust | 广泛使用 |
| ECDSA 签名验证 | `p256::ecdsa`, `p384::ecdsa` | 0.13 | 纯 Rust | 广泛使用 |
| RSA 签名验证 | `rsa` | 0.9 | 纯 Rust | 广泛使用 |
| HKDF | `hkdf` | 0.12 | 纯 Rust | 广泛使用 |
| 随机数 | `rand_core` | 0.6 | 纯 Rust | 标准库 |

**说明**：这些 crate 来自 crates.io，是 Rust 社区广泛使用的加密库，算法实现符合标准，与 mbedtls 输出一致。

### 8.3 Crypto 模块实现

```rust
// crypto/hash.rs
use sha2::{Sha256, Sha384, Digest};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

// crypto/aead.rs
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::{Aead, AeadCore, Payload}};
use rand_core::OsRng;

pub fn aes_128_gcm_encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 16]), SpdmError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SpdmError::CryptoError)?;
    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher.encrypt(nonce.into(), payload).map_err(|_| SpdmError::CryptoError)?;
    // AES-GCM tag appended to ciphertext by default, need to separate
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    Ok((ct.to_vec(), tag.try_into().unwrap()))
}

pub fn aes_128_gcm_decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], tag: &[u8; 16], aad: &[u8]) -> Result<Vec<u8>, SpdmError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SpdmError::CryptoError)?;
    let payload = Payload { msg: ciphertext, aad };
    let combined = [ciphertext, tag].concat();
    cipher.decrypt(nonce.into(), combined.as_slice()).map_err(|_| SpdmError::CryptoError)
}

// crypto/dhe.rs
use p256::elliptic_curve::ecdh::Ecdh;
use p256::{PublicKey, SecretKey};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};

pub fn ecdh_p256(private: &[u8], public: &[u8]) -> Result<[u8; 32], SpdmError> {
    let sk = SecretKey::from_slice(private).map_err(|_| SpdmError::CryptoError)?;
    let pk = PublicKey::from_slice(public).map_err(|_| SpdmError::CryptoError)?;
    let shared = Ecdh::new(&sk, &pk).compute_shared_secret();
    Ok(shared.raw_secret_bytes().as_slice().try_into().unwrap())
}

pub fn ecdh_p384(private: &[u8], public: &[u8]) -> Result<[u8; 48], SpdmError> {
    let sk = P384SecretKey::from_slice(private).map_err(|_| SpdmError::CryptoError)?;
    let pk = P384PublicKey::from_slice(public).map_err(|_| SpdmError::CryptoError)?;
    let shared = Ecdh::new(&sk, &pk).compute_shared_secret();
    Ok(shared.raw_secret_bytes().as_slice().try_into().unwrap())
}

// crypto/hkdf.rs
use hkdf::Hkdf;
use sha2::Sha256;

pub fn hkdf_expand_sha256(secret: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), SpdmError> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    hkdf.expand(info, okm).map_err(|_| SpdmError::CryptoError)
}
```

### 8.4 Cargo.toml 依赖配置

```toml
[dependencies]
# 加密后端 - 纯 Rust，无 C 依赖
sha2 = "0.10"
aes-gcm = "0.10"
p256 = { version = "0.13", features = ["ecdh", "ecdsa"] }
p384 = { version = "0.13", features = ["ecdh", "ecdsa"] }
hkdf = "0.12"
rand_core = "0.6"

# RSA 签名验证 (可选，如果 responder 用 RSA)
rsa = { version = "0.9", optional = true }

# 其他
zeroize = { version = "1.6", features = ["derive"] }
byteorder = "1.5"
log = "0.4"

[build-dependencies]
cbindgen = "0.26"
```

### 8.5 依赖边界

| 组件 | 加密实现 | C 依赖 | 说明 |
|------|----------|--------|------|
| rmm 其他 C 业务 | mbedtls | mbedtls | **保留**，不受影响 |
| rust-spdm-minimal | sha2, aes-gcm, p256 等 | **无** | **纯 Rust** |

**FFI 边界**：
- C 调用 Rust：`libspdm_*`, `pci_doe_*`, `pci_tdisp_*`, `pci_ide_km_*`
- Rust 不调用 C：加密逻辑完全内部

### 8.6 Crypto trait 定义

```rust
pub trait SpdmHash {
    fn sha256(data: &[u8]) -> [u8; 32];
    fn sha384(data: &[u8]) -> [u8; 48];
    fn digest_size(algo: HashAlgo) -> usize;
}

pub trait SpdmAead {
    fn aes_gcm_encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 16]), SpdmError>;
    fn aes_gcm_decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], tag: &[u8; 16], aad: &[u8]) -> Result<Vec<u8>, SpdmError>;
}

pub trait SpdmDhe {
    fn ecdh_p256(private: &[u8], public: &[u8]) -> Result<[u8; 32], SpdmError>;
    fn ecdh_p384(private: &[u8], public: &[u8]) -> Result<[u8; 48], SpdmError>;
    fn generate_keypair_p256() -> Result<(Vec<u8>, Vec<u8>), SpdmError>;
    fn generate_keypair_p384() -> Result<(Vec<u8>, Vec<u8>), SpdmError>;
}

pub trait SpdmHkdf {
    fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], SpdmError>;
    fn hkdf_expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), SpdmError>;
    fn hkdf_expand_sha384(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), SpdmError>;
}
```

---

## 九、FFI 类型映射

### 9.1 类型定义

```rust
pub type libspdm_return_t = u32;
pub type libspdm_data_type_t = u32;
pub type libspdm_data_location_t = u8;
pub type size_t = usize;

#[repr(C)]
pub struct libspdm_data_parameter_t {
    location: libspdm_data_location_t,
    additional_data: [u8; 4],
}

#[repr(C)]
pub struct libspdm_error_struct_t {
    error_code: u8,
    error_data: u8,
}
```

### 9.2 状态码映射

```rust
pub const LIBSPDM_STATUS_SUCCESS: u32 = 0;
pub const LIBSPDM_STATUS_INVALID_PARAMETER: u32 = 0x80000001;
pub const LIBSPDM_STATUS_INVALID_STATE_LOCAL: u32 = 0x80000002;
pub const LIBSPDM_STATUS_VERIF_FAIL: u32 = 0x80000005;
pub const LIBSPDM_STATUS_CRYPTO_ERROR: u32 = 0x80000006;
pub const LIBSPDM_STATUS_NEGOTIATION_FAIL: u32 = 0x80000007;
pub const LIBSPDM_STATUS_UNSUPPORTED_CAP: u32 = 0x80000008;

pub fn LIBSPDM_STATUS_IS_ERROR(status: u32) -> bool {
    status >= 0x80000000
}
```

---

## 十、Transcript 计算

### 10.1 Transcript A (VCA + CERT)

用于证书验证时的签名：

```
Transcript A = 
    GET_VERSION request || VERSION response ||
    GET_CAPABILITIES request || CAPABILITIES response ||
    NEGOTIATE_ALGORITHMS request || ALGORITHMS response ||
    GET_DIGESTS request || DIGESTS response ||
    GET_CERTIFICATE request(s) || CERTIFICATE response(s)

Hash_A = hash(Transcript_A)
```

### 10.2 Transcript M (KEY_EX + FINISH)

用于密钥派生和 FINISH MAC：

```
Transcript M =
    KEY_EXCHANGE request || KEY_EXCHANGE_RSP response ||
    FINISH request || FINISH_RSP response

Hash_M = hash(Transcript_M)
```

---

## 十二、调试经验总结

### 12.1 SPDM GET_VERSION 关键发现

**问题：Responder 返回错误响应（4字节，响应码0x7F）**

**原因：GET_VERSION 请求使用了错误的版本字段**

```
错误代码：
  sender_buf[0] = 0x12;  // 版本 1.2 - 错误！

正确代码：
  sender_buf[0] = 0x10;  // 版本 1.0 - 必须使用！
```

**SPDM 规范要求：**
- GET_VERSION 请求必须使用 SPDM version 1.0 (0x10)
- 即使后续协商使用版本 1.2，GET_VERSION 本身必须用 1.0
- Responder 拒绝版本不匹配的 GET_VERSION 请求

**症状对比：**
| 版本字段 | Responder 响应 | 状态 |
|----------|----------------|------|
| 0x12 (错误) | 4字节，错误码 0x7F | 失败 |
| 0x10 (正确) | 8字节，VERSION 响应 | 成功 |

### 12.2 Rust FFI 回调签名匹配

**问题：回调函数类型不匹配导致运行时错误**

**解决方案：**
```rust
// 发送回调签名
type SendFunc = extern "C" fn(
    libspdm_context_t,  // context
    usize,              // request_size  
    *const c_void,      // request
    u64                 // timeout
) -> libspdm_return_t;

// 接收回调签名（注意：参数顺序不同于发送）
type RecvFunc = extern "C" fn(
    libspdm_context_t,  // context
    *mut usize,         // response_size (指针!)
    *mut *mut c_void,   // response (双重指针!)
    u64                 // timeout
) -> libspdm_return_t;
```

**关键点：**
- receive 的 size 和 response 都是可修改的指针
- C 代码中 `size_t *response_size` 对应 Rust `*mut usize`
- C 代码中 `void **response` 对应 Rust `*mut *mut c_void`

### 12.3 Buffer 回调的正确使用

**问题：直接使用栈上的缓冲区导致指针验证失败**

**解决方案：必须通过 acquire_sender_buffer 获取缓冲区**

```rust
// 错误：使用栈缓冲区
let buf = [0u8; 4096];
call_send(context, &buf, 4);  // 指针不在 info->send_recv_buffer 内！

// 正确：通过回调获取
let sender_buf = call_acquire_sender(context);
call_send(context, sender_buf, 4);  // 指针正确
```

**原因：**
- C 回调 `spdm_send_message` 检查 `request` 指针必须在 `info->send_recv_buffer` 范围内
- 缓冲区由 host 层分配，有特定的内存布局要求
- 不使用回调获取的缓冲区会导致 `LIBSPDM_STATUS_SEND_FAIL`

### 12.4 编译配置注意事项

**问题：FFI feature 未启用，无符号导出**

**解决方案：Cargo.toml 添加 feature，cmake 传递参数**

```toml
# Cargo.toml
[features]
ffi = []
```

```cmake
# FindRustSpdm.cmake
COMMAND ${CARGO_EXECUTABLE} build --features ffi --release
```

**验证符号导出：**
```bash
nm librust_spdm_minimal.a | grep " T libspdm"
# 应显示：libspdm_init_connection, libspdm_set_data, 等
```

### 12.6 版本协商关键发现

**VERSION 响应格式分析：**

Responder VERSION 响应示例（SPDM 1.0 格式）：
```
10 04 00 00 00 04 00 10 00 11 00 12 00 13
```

解析：
- Bytes 0-3: header (version=0x10, code=0x04, reserved, param1)
- Bytes 4-5: reserved (在 SPDM 1.0 中)
- Bytes 6+: version_number_entry 列表

每个 version_number_entry (2 bytes, little endian):
- bits 15:12 = major version
- bits 11:8 = minor version
- bits 7:4 = update version
- bits 3:0 = alpha

例如 `00 12` (little endian) = 0x1200 = version 1.2

**版本选择策略：**
- 应选择 requester 和 responder 的最高共同版本
- Requester 支持: 由 set_data(LIBSPDM_DATA_SPDM_VERSION) 设置
- Responder 支持: VERSION 响应中的 version_number_entry 列表
- 选择两者交集的最高版本

**当前问题：**
- 我们的代码取第一个 entry（版本 1.0），而非协商最高版本
- 导致 GET_CAPABILITIES 使用版本 1.0 格式（8 bytes）
- Responder 期望 SPDM 1.2 格式（22 bytes）导致拒绝

### 12.7 GET_CAPABILITIES 格式差异

**SPDM 版本格式差异：**

| SPDM 版本 | GET_CAPABILITIES 请求大小 | 格式 |
|-----------|---------------------------|------|
| 1.0/1.1 | 8 bytes | header(4) + flags(4) |
| 1.2+ | 22 bytes | header(4) + reserved(4) + ct_exp(1) + res(1) + flags(4) + dts(4) + max_msg(4) |

**CAPABILITIES 响应格式：**

| SPDM 版本 | CAPABILITIES 响应大小 | 格式 |
|-----------|------------------------|------|
| 1.0/1.1 | 8-12 bytes | header + flags + optional dts/max_msg |
| 1.2+ | 20 bytes | header(4) + res(4) + ct_exp(1) + res(1) + flags(4) + dts(4) + max_msg(4) |

**关键偏移：**
- DataTransferSize: bytes 12-15 (SPDM 1.2 响应)
- MaxSPDMmsgSize: bytes 16-19 (SPDM 1.2 响应)

## 十三、当前进度与下一步

### 13.1 已完成

1. ✓ Rust 库编译成功（ffi feature 启用）
2. ✓ tf-rmm 编译并链接 Rust 库
3. ✓ GET_VERSION 成功（版本 1.0 正确使用）
4. ✓ Rust 调试打印输出正常
5. ✓ 回调注册和调用正确
6. ✓ 文档更新完成

### 13.2 待修复

1. ⏳ VERSION 解析 - 需实现最高共同版本选择
2. ⏳ GET_CAPABILITIES - 需使用协商版本和正确格式
3. ⏳ NEGOTIATE_ALGORITHMS - 需实现协议交换
4. ⏳ GET_DIGESTS/GET_CERTIFICATE - 证书获取
5. ⏳ KEY_EXCHANGE/FINISH - 会话建立

### 13.3 验证标准

每个接口必须：
- 与 C 版本 SPDM TX/RX 日志对比
- 确认 Responder 正常响应（非 ERROR）
- 确认 PDEV 状态转换正确

**Rust no_std 环境使用 printf：**
```rust
extern "C" {
    fn printf(fmt: *const i8, ...);
}

macro_rules! debug_print {
    ($s:expr) => {
        unsafe { printf(concat!("[RUST] ", $s, "\n\0").as_ptr() as *const i8); }
    };
}
```

**注意：**
- printf 格式字符串必须以 `\0` 结尾
- u8 类型传给 printf 需要 cast 为 u32/c_int
- raw pointer 不能用 `[n]` 索引，必须用 `.add(n)` + deref

### 11.1 SPDM Error Response

```rust
#[repr(C)]
pub struct SpdmErrorResponse {
    version: u8,
    response_code: u8,  // SPDM_RESPONSE_ERROR = 0x7F
    error_code: u8,
    error_data: u8,
    extended_data: Option<Vec<u8>>,
}

// Common Error Codes
pub const SPDM_ERROR_CODE_INVALID_REQUEST: u8 = 0x01;
pub const SPDM_ERROR_CODE_BUSY: u8 = 0x03;
pub const SPDM_ERROR_CODE_UNEXPECTED_REQUEST: u8 = 0x04;
pub const SPDM_ERROR_CODE_DECRYPT_ERROR: u8 = 0x06;
pub const SPDM_ERROR_CODE_REQUEST_RESYNCH: u8 = 0x07;
pub const SPDM_ERROR_CODE_RESPONSE_NOT_READY: u8 = 0x42;
```

### 11.2 Error Handling Flow

```rust
fn handle_error_response(
    spdm_context: &mut SpdmContext,
    error_response: SpdmErrorResponse,
    expected_request_code: u8,
) -> SpdmResult {
    match error_response.error_code {
        SPDM_ERROR_CODE_BUSY => {
            // Retry after delay
            Err(SpdmStatus::BusyPeer)
        }
        SPDM_ERROR_CODE_REQUEST_RESYNCH => {
            // Reset connection
            spdm_context.connection_state = ConnectionState::NotStarted;
            Err(SpdmStatus::ResynchPeer)
        }
        SPDM_ERROR_CODE_RESPONSE_NOT_READY => {
            // Wait for RespondIfReady
            Err(SpdmStatus::BusyPeer)
        }
        _ => {
            spdm_context.last_error.error_code = error_response.error_code;
            spdm_context.last_error.error_data = error_response.error_data;
            Err(SpdmStatus::ErrorPeer)
        }
    }
}
```