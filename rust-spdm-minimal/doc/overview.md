# 项目概述

## 项目目标

彻底移除 tf-rmm requester 端对以下 C 库的依赖：

| 原 C 库 | 替换为 |
|---------|--------|
| `ext/libspdm/` | Rust SPDM Core |
| `ext/spdm-emu/library/pci_doe_requester_lib/` | Rust DOE 层 |
| `ext/spdm-emu/library/pci_tdisp_requester_lib/` | Rust TDISP 层 |
| `ext/spdm-emu/library/pci_ide_km_requester_lib/` | 打桩（不实现功能） |

**保留 C 部分**：
- `ext/spdm-emu/spdm_responder_emu/` → responder 服务继续使用 C（独立进程）

## 背景

tf-rmm fakehost 项目用于 SPDM/TDISP 协议调试。当前 requester 端依赖 libspdm 和 spdm-emu 的 C 实现，代码量约 50k+ LOC。

通过 Rust 重写，目标：
- 简化代码，仅实现实际使用的功能
- 消除 C 依赖，便于维护
- 提供更好的类型安全

## 分阶段路线图

```
Phase 1: SPDM Core + IDE-KM 打桩
    ↓
Phase 2: DOE 层
    ↓  
Phase 3: TDISP 层
    ↓
完成：纯 Rust requester，无 C 库依赖
```

| 阶段 | 内容 | 工作量 | 时间 |
|------|------|--------|------|
| Phase 1 | SPDM Core + IDE-KM 打桩 | ~3500 LOC | 18 天 |
| Phase 2 | DOE 层 | ~200 LOC | 3 天 |
| Phase 3 | TDISP 层 | ~400 LOC | 5.5 天 |

**总计**：约 26.5 天

## 加密后端决策

**方案**：rust-spdm-minimal 内部使用纯 Rust 加密 crates，不依赖 mbedtls。

**架构边界**：
- rmm 其他 C 业务 → 继续依赖 mbedtls（保留，不受影响）
- rust-spdm-minimal → 内部用 sha2, aes-gcm, p256, p384 等（纯 Rust）
- FFI 边界 → 仅暴露 libspdm_*, pci_doe_*, pci_tdisp_* 接口

**优势**：
- Rust SPDM 库完全独立，无 C 加密依赖
- rmm 其他业务继续用 mbedtls，互不干扰
- 符合"彻底移除 spdm/tdisp/doe C 库"目标

## 相关文档

- [API 分析](./api_analysis.md) - 实际调用的 API 清单
- [技术设计](./technical_design.md) - 架构和实现细节
- [分阶段计划](./phase_plan.md) - 各阶段任务拆解
- [CMake 集成](./cmake_integration.md) - 构建系统改造