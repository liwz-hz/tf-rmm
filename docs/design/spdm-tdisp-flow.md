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

## 5. DVSEC 配置流程

### 5.1 DVSEC 概述

DVSEC (Designated Vendor-Specific Extended Capability) 是 PCIe 扩展配置空间中的
特殊能力结构，用于 TDISP 设备分配时配置 Root Port。

**关键结构**:
```c
struct dvsec_rme_da {
    uint32_t ech;            // Extended Capability Header
    uint32_t dvsec_hdr1;     // Vendor ID (ARM: 0x13b5) + Revision
    uint32_t dvsec_hdr2;     // DVSEC ID (RME_DA: 0xFF01)
    uint32_t dvsec_rme_da_ctl_reg1;
    uint32_t dvsec_rme_da_ctl_reg2;
};
```

**DVSEC 标识**:
- Extended Capability ID: `0x23` (DVSEC)
- Vendor ID: `0x13b5` (ARM)
- DVSEC ID: `0xFF01` (RME Device Assignment)

### 5.2 ECAM 地址传递路径

TDISP 需要 ECAM (Enhanced Configuration Access Mechanism) 地址来访问 Root Port
配置空间。参数传递路径如下：

```
┌─────────────────────────────────────────────────────────────────┐
│              ECAM Address Parameter Passing Path                 │
└─────────────────────────────────────────────────────────────────┘

1. Host 端 (host_da.c)
   │  host_utils_pci_get_ecam_base() → 静态缓冲区地址
   │  host_utils_pci_rp_dvsec_setup() → 配置 DVSEC
   │  dev->ecam_addr = ECAM base address
   │  dev->root_id = HOST_ROOT_PORT_ID (0x0)
   │
   ▼
2. PDEV 创建 (pdev.c)
   │  pdev_params->ecam_addr = dev->ecam_addr
   │  pdev_params->root_id = dev->root_id
   │  SMC_RMI_PDEV_CREATE → 传递到 RMM runtime
   │
   ▼
3. Runtime (pdev.c)
   │  dparams.ecam_addr = pdev_params.ecam_addr
   │  dparams.rp_id = pdev_params.root_id
   │  dev_assign_app_init() → 传递到 EL0 app
   │
   ▼
4. EL0 App (dev_assign_el0_app.c)
   │  info->ecam_addr = params->ecam_addr
   │  info->rp_id = params->rp_id
   │
   ▼
5. DVSEC 初始化 (rme_dvsec.c)
   │  dvsec_init(info)
   │  rp_ecam_addr = ecam_addr + (BDF offset)
   │  pcie_find_arm_dvsec() → 找到 DVSEC offset
   │  MMIO 读取验证 DVSEC 存在
```

### 5.3 DVSEC 初始化函数

```c
int dvsec_init(struct dev_assign_info *info)
{
    // 计算 Root Port ECAM 地址
    rp_ecam_addr = info->ecam_addr +
        (PCIE_EXTRACT_BDF_BUS(info->rp_id) * PCIE_MAX_DEV * PCIE_MAX_FUNC * PCIE_CFG_SIZE) +
        (PCIE_EXTRACT_BDF_DEV(info->rp_id) * PCIE_MAX_FUNC * PCIE_CFG_SIZE) +
        (PCIE_EXTRACT_BDF_FUNC(info->rp_id) * PCIE_CFG_SIZE);

    // 查找 ARM RME-DA DVSEC
    rp_dvsec_offset = pcie_find_arm_dvsec(info, rp_ecam_addr);
    if (rp_dvsec_offset == 0U) {
        return -1;  // 未找到 DVSEC
    }

    // 保存地址和偏移
    info->rp_ecam_addr = rp_ecam_addr;
    info->rp_dvsec_offset = rp_dvsec_offset;
    return 0;
}
```

### 5.4 重要修复说明

**问题**: 禁用 IDE 后，`ecam_addr` 和 `rp_id` 未传递给 EL0 app，导致 `dvsec_init()` 失败。

**原因分析**:
```c
// runtime/rmi/pdev.c (原代码)
if (NCOH_IDE == TRUE) {
    dparams.ecam_addr = pdev_params.ecam_addr;  // 只在IDE启用时设置
    dparams.rp_id = pdev_params.root_id;
} else {
    dparams.has_ide = false;  // ecam_addr 未初始化，值为 0
}
```

**修复方案**:
将 `ecam_addr` 和 `rp_id` 的设置移到条件判断之外：

```c
// runtime/rmi/pdev.c (修复后)
if (NCOH_IDE == TRUE) {
    dparams.has_ide = true;
    dparams.ide_sid = pdev_params.ide_sid;
} else {
    dparams.has_ide = false;
}
// 无论 IDE 状态，都必须设置
dparams.ecam_addr = pdev_params.ecam_addr;
dparams.rp_id = pdev_params.root_id;
```

**相关修改文件**:
| 文件 | 修改内容 |
|------|---------|
| `runtime/rmi/pdev.c` | 移动 ecam_addr/rp_id 设置到条件外 |
| `plat/host/host_build/src/host_da.c` | 始终配置 DVSEC 和 ecam_addr |
| `app/el0_app/dev_assign_el0_app.c` | 始终初始化 ecam_addr/rp_id |
| `app/el0_app/dev_tdisp_cmds.c` | LOCK 前调用 dvsec_init |

## 6. IDE 相关说明

当前 fakehost 配置禁用了 IDE (Link Integrity Encryption) 功能：

**禁用 IDE 的原因**:
- fakehost 是模拟环境，不涉及真实 PCIe 链路
- IDE 密钥配置流程复杂，不影响 TDISP 核心功能验证
- 简化测试流程，聚焦 SPDM 和 TDISP 交互

**修改点**:
1. `runtime/rmi/pdev.c`: 验证 `NCOH_IDE == FALSE` 而非 TRUE
2. `plat/host/host_build/src/host_da.c`: 移除 `NCOH_IDE` 标志设置
3. 同时确保 DVSEC 配置不受 IDE 状态影响

**IDE与SPDM/TDISP的关系**:
- IDE是独立的PCIe链路加密机制
- 不影响SPDM会话建立
- TDISP 流程独立于 IDE（但需要 DVSEC）
- IDE相关状态（COMMUNICATING, IDE_RESETTING）已被跳过

## 7. 关键文件汇总

| 类别 | 文件路径 |
|------|---------|
| **SPDM通信** | `plat/host/host_build/src/host_spdm_rsp_ifc.c` |
| **设备管理** | `plat/host/host_build/src/host_da.c` |
| **启动流程** | `plat/host/host_build/src/host_setup.c` |
| **TDISP命令** | `app/device_assignment/el0_app/src/dev_tdisp_cmds.c` |
| **DVSEC配置** | `app/device_assignment/el0_app/src/rme_dvsec.c` |
| **ECAM模拟** | `plat/host/harness/src/host_utils_pci.c` |
| **RMI接口** | `plat/host/harness/src/host_rmi_wrappers.c` |
| **PDEV创建** | `runtime/rmi/pdev.c` |
| **SPDM标准** | `ext/libspdm/include/industry_standard/spdm.h` |
| **TDISP标准** | `ext/libspdm/include/industry_standard/pci_tdisp.h` |

## 8. 参考链接

- [DMTF SPDM Specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.0.pdf)
- [PCIe DOE Specification](https://pcisig.com)
- [TDISP Specification](https://www.trustedcomputinggroup.org)