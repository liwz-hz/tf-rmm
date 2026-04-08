# SPDM/TDISP 交互流程分析

本文档分析 TF-RMM fakehost 测试程序中 SPDM 和 TDISP 协议的交互接口及关键流程。

## 1. 概述

TF-RMM 使用 libspdm 库实现 SPDM (Security Protocol and Data Model) 协议，
用于 PCIe 设备的安全认证和会话建立。TDISP (TEE Device Interface Security Protocol)
作为 SPDM 的上层协议，通过 SPDM Vendor Defined Messages 传输，实现设备接口的安全绑定。

## 2. SPDM 交互接口

### 2.1 核心文件位置

| 文件 | 路径 | 功能 |
|------|------|------|
| SPDM响应器接口 | `plat/host/host_build/src/host_spdm_rsp_ifc.c` | DOE通信封装 |
| 设备分配逻辑 | `plat/host/host_build/src/host_da.c` | PDEV/VDEV状态管理 |
| SPDM响应器启动 | `plat/host/host_build/src/host_setup.c` | 进程启动管理 |

### 2.2 连接和初始化接口

```c
// 连接到SPDM响应模拟器
int host_spdm_rsp_connect(int *spdm_rsp_id);

// 初始化socket连接
int host_spdm_rsp_init(const char *host_addr, uint32_t port, int *spdm_rsp_id);

// 断开连接
void host_spdm_rsp_deinit(int spdm_rsp_id);

// SPDM通信主函数
int host_spdm_rsp_communicate(int spdm_rsp_id, void *req_buf, size_t req_sz,
                              void *rsp_buf, size_t *rsp_sz, bool is_sspdm);
```

### 2.3 DOE 通信接口

DOE (Data Object Exchange) 是 PCIe 协议定义的数据交换机制，用于封装 SPDM 消息。

**DOE 头结构**:
```c
typedef struct {
    uint16_t vendor_id;       // PCI_DOE_VENDOR_ID_PCISIG = 0x1
    uint8_t data_obj_type;    // SPDM(0x1) 或 SECURED_SPDM(0x2)
    uint8_t reserved;
    uint32_t length;          // payload长度（DWORD为单位）
} pci_doe_header_t;
```

**DOE 数据对象类型**:
| 类型值 | 名称 | 说明 |
|--------|------|------|
| 0x1 | `PCI_DOE_DATA_OBJ_TYPE_SPDM` | 普通SPDM消息 |
| 0x2 | `PCI_DOE_DATA_OBJ_TYPE_SECURED_SPDM` | 加密的SPDM消息（会话内） |

**DOE 发送/接收函数**:
```c
// 发送DOE封装的SPDM请求
int host_send_doe_spdm_req(int spdm_rsp_id, const void *req_buf,
                           size_t req_sz, bool is_sspdm);

// 接收DOE封装的SPDM响应
int host_recv_doe_spdm_rsp(int spdm_rsp_id, void *rsp_buf,
                           size_t *rsp_sz, bool is_sspdm);
```

### 2.4 Socket 传输层

使用 TCP socket 与 spdm_responder_emu 进程通信：
- 默认端口：2323（普通SPDM）、2324（安全SPDM）
- 传输类型：`SOCKET_TRANSPORT_TYPE_PCI_DOE = 0x02`
- 命令类型：`SOCKET_SPDM_COMMAND_NORMAL = 0x0001`

## 3. SPDM 会话建立流程

### 3.1 PDEV 状态转换

PDEV (Physical Device) 的状态管理是实现 SPDM 会话建立的核心：

| 状态 | 值 | 说明 |
|------|-----|------|
| `RMI_PDEV_STATE_NEW` | 0 | 新创建状态 |
| `RMI_PDEV_STATE_NEEDS_KEY` | 1 | 需要建立会话获取密钥 |
| `RMI_PDEV_STATE_HAS_KEY` | 2 | 会话已建立，需要设置公钥 |
| `RMI_PDEV_STATE_READY` | 3 | 设备就绪，可分配给Realm |
| `RMI_PDEV_STATE_STOPPING` | 5 | 正在停止 |
| `RMI_PDEV_STATE_STOPPED` | 6 | 已停止 |
| `RMI_PDEV_STATE_DESTROYING` | 7 | 正在销毁 |

### 3.2 会话建立详细流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    SPDM Session Establishment                    │
└─────────────────────────────────────────────────────────────────┘

1. 启动SPDM响应器进程 (launch_spdm_responder_emu)
   │
   ▼
2. 连接响应器 (host_spdm_rsp_connect)
   │  Socket连接到TCP端口2323
   ▼
3. 创建PDEV (SMC_RMI_PDEV_CREATE)
   │  状态: NEW -> NEEDS_KEY
   ▼
4. SPDM协议交换 (RMI_PDEV_COMMUNICATE)
   │
   ├──► GET_VERSION        (获取SPDM版本)
   ├──► GET_CAPABILITIES   (能力协商)
   ├──► NEGOTIATE_ALGORITHMS (算法协商)
   ├──► GET_CERTIFICATE    (获取证书链，多次请求)
   ├──► KEY_EXCHANGE       (密钥交换，建立安全会话)
   │    └─ 生成session_id
   ├──► FINISH             (完成握手，验证完整性)
   │
   ▼
5. 提取公钥 (host_get_public_key_from_cert_chain)
   │  支持ECDSA P256/P384、RSA-3072
   ▼
6. 设置公钥 (SMC_RMI_PDEV_SET_PUBKEY)
   │  状态: HAS_KEY -> READY
   ▼
7. PDEV就绪，可用于设备分配
```

### 3.3 关键SPDM消息

| 消息类型 | 请求码 | 响应码 | 说明 |
|----------|--------|--------|------|
| GET_VERSION | 0x84 | 0x04 | 版本协商 |
| GET_CAPABILITIES | 0xE1 | 0x61 | 能力交换 |
| NEGOTIATE_ALGORITHMS | 0xE3 | 0x63 | 算法选择 |
| GET_CERTIFICATE | 0x82 | 0x02 | 证书链获取 |
| KEY_EXCHANGE | 0xE4 | 0x64 | 密钥交换 |
| FINISH | 0xE5 | 0x65 | 完成握手 |
| END_SESSION | 0xEC | 0x6C | 结束会话 |

### 3.4 缓存机制

为优化性能，SPDM数据使用缓存：

| 对象类型 | 说明 |
|----------|------|
| `RMI_DEV_COMM_OBJECT_CERTIFICATE` | 设备证书链 |
| `RMI_DEV_COMM_OBJECT_VCA` | Vendor Certificate Authority数据 |

缓存标志：
- `RMI_DEV_COMM_EXIT_FLAGS_REQ_CACHE_BIT` - 缓存请求
- `RMI_DEV_COMM_EXIT_FLAGS_RSP_CACHE_BIT` - 缓存响应

## 4. TDISP 协议分析

### 4.1 TDISP 与 SPDM 的关系

TDISP 完全依赖 libspdm，其消息通过 SPDM Vendor Defined Messages (VDM) 传输：

```
┌─────────────────────────────────────────────────────────────┐
│                   SPDM Secured Session                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            SPDM VDM (Vendor Defined Message)        │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │              TDISP Message Payload             │ │   │
│  │  │  (pci_tdisp_header_t + request/response data)  │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**协议标识**:
```c
#define PCI_PROTOCOL_ID_TDISP 0x01  // TDISP协议ID
```

**传输依赖**:
```c
// TDISP消息通过SPDM vendor函数发送
status = pci_doe_spdm_vendor_send_receive_data(
    spdm_context, session_id, pci_protocol,
    request, request_size, response, response_size);
```

### 4.2 TDISP 核心接口

**请求者接口** (pci_tdisp_requester_lib.h):
```c
libspdm_return_t pci_tdisp_get_version(...);           // 获取版本
libspdm_return_t pci_tdisp_get_capabilities(...);      // 获取能力
libspdm_return_t pci_tdisp_lock_interface(...);        // 锁定接口
libspdm_return_t pci_tdisp_get_interface_report(...);  // 获取报告
libspdm_return_t pci_tdisp_get_interface_state(...);   // 获取状态
libspdm_return_t pci_tdisp_start_interface(...);       // 启动接口
libspdm_return_t pci_tdisp_stop_interface(...);        // 停止接口
```

**TF-RMM实现** (dev_tdisp_cmds.c):
```c
int dev_tdisp_lock_main(struct dev_assign_info *info);   // 锁定流程
int dev_tdisp_report_main(struct dev_assign_info *info); // 获取报告
int dev_tdisp_start_main(struct dev_assign_info *info);  // 启动接口
int dev_tdisp_stop_main(struct dev_assign_info *info);   // 停止接口
```

### 4.3 TDISP 状态机

**状态定义**:
```c
#define PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED 0  // 配置未锁定
#define PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED   1  // 配置锁定
#define PCI_TDISP_INTERFACE_STATE_RUN             2  // 运行状态
#define PCI_TDISP_INTERFACE_STATE_ERROR           3  // 错误状态
```

**状态转换图**:
```
                    ┌─────────────────────┐
                    │  CONFIG_UNLOCKED    │
                    │       (0x0)         │◄─────────────────────┐
                    └──────────┬──────────┘                      │
                               │                                 │
                      LOCK_INTERFACE                      STOP_INTERFACE
                               │                          END_SESSION
                               ▼                                 │
                    ┌─────────────────────┐                      │
                    │   CONFIG_LOCKED     │                      │
                    │       (0x1)         │                      │
                    └──────────┬──────────┘                      │
                               │                                 │
                     START_INTERFACE                            │
                               │                                 │
                               ▼                                 │
                    ┌─────────────────────┐                      │
                    │        RUN          │──────────────────────┘
                    │       (0x2)         │
                    └─────────────────────┘
                               │
                    (错误/异常)
                               ▼
                    ┌─────────────────────┐
                    │       ERROR         │
                    │       (0x3)         │
                    └─────────────────────┘
```

### 4.4 TDISP 消息流程

| 步骤 | 消息 | 状态变化 | 说明 |
|------|------|---------|------|
| 1 | GET_VERSION | - | 版本协商 |
| 2 | GET_CAPABILITIES | - | 能力交换 |
| 3 | GET_INTERFACE_STATE | CONFIG_UNLOCKED(0) | 验证初始状态 |
| 4 | LOCK_INTERFACE | CONFIG_LOCKED(1) | 锁定接口，生成nonce |
| 5 | GET_INTERFACE_STATE | CONFIG_LOCKED(1) | 验证锁定成功 |
| 6 | GET_INTERFACE_REPORT | - | 获取接口报告(可选) |
| 7 | START_INTERFACE | RUN(2) | 使用nonce启动 |
| 8 | [设备正常运行] | RUN(2) | DMA/MMIO操作 |
| 9 | STOP_INTERFACE | CONFIG_UNLOCKED(0) | 停止并释放 |

### 4.5 完整设备分配流程

```
┌─────────────────────────────────────────────────────────────────┐
│                   Device Assignment Flow                         │
└─────────────────────────────────────────────────────────────────┘

1. Realm创建和激活 (STAGE 1)
   │
   ▼
2. PDEV探测和设置 (STAGE 2)
   │  ├── 启动SPDM响应器
   │  ├── 连接响应器
   │  ├── 创建PDEV
   │  ├── SPDM会话建立 (GET_VERSION → FINISH)
   │  ├── 提取并设置公钥
   │  └── PDEV进入READY状态
   │
   ▼
3. Attestation测试 (STAGE 3)
   │
   ▼
4. VDEV创建 (STAGE 4)
   │  SMC_RMI_VDEV_CREATE
   │
   ▼
5. 设备分配和TDISP流程 (STAGE 5)
   │  ├── TDISP_GET_VERSION
   │  ├── TDISP_GET_CAPABILITIES
   │  ├── TDISP_GET_INTERFACE_STATE (验证UNLOCKED)
   │  ├── TDISP_LOCK_INTERFACE
   │  ├── TDISP_GET_INTERFACE_STATE (验证LOCKED)
   │  ├── TDISP_START_INTERFACE
   │  └── 设备在Realm中运行
   │
   ▼
6. 设备释放
   │  ├── TDISP_STOP_INTERFACE
   │  ├── VDEV_DESTROY
   │  ├── PDEV_STOP
   │  ├── SPDM_END_SESSION
   │  └── PDEV_DESTROY
```

## 5. IDE 相关说明

当前 fakehost 配置禁用了 IDE (Link Integrity Encryption) 功能：

**修改点**:
1. `runtime/rmi/pdev.c`: 将 `NCOH_IDE == TRUE` 改为 `NCOH_IDE == FALSE`
2. `plat/host/host_build/src/host_da.c`: 移除 `NCOH_IDE` 标志

**IDE与SPDM/TDISP的关系**:
- IDE是独立的PCIe链路加密机制
- 不影响SPDM会话建立和TDISP流程
- IDE相关状态（COMMUNICATING, IDE_RESETTING）已被跳过

## 6. 关键文件汇总

| 类别 | 文件路径 |
|------|---------|
| **SPDM通信** | `plat/host/host_build/src/host_spdm_rsp_ifc.c` |
| **设备管理** | `plat/host/host_build/src/host_da.c` |
| **启动流程** | `plat/host/host_build/src/host_setup.c` |
| **TDISP命令** | `app/device_assignment/el0_app/src/dev_tdisp_cmds.c` |
| **RMI接口** | `plat/host/harness/src/host_rmi_wrappers.c` |
| **SPDM标准** | `ext/libspdm/include/industry_standard/spdm.h` |
| **TDISP标准** | `ext/libspdm/include/industry_standard/pci_tdisp.h` |

## 7. 参考链接

- [DMTF SPDM Specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.0.pdf)
- [PCIe DOE Specification](https://pcisig.com)
- [TDISP Specification](https://www.trustedcomputinggroup.org)