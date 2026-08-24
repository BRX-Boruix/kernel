# 外部依赖清单（DEPENDENCIES）

> 本文件是 BORUIX 内核工作区**全部外部（crates.io）依赖**的唯一登记处。
> 任何新增外部依赖必须在引入的同一变更中在此登记：名称、版本、用途、
> 引入理由、替代方案评估。零披露引入即违规（vfs1 D1 / ADR-023）。
>
> 路径依赖（workspace 内 `path = "../..."`）不属外部依赖，不在本表。

## 运行时依赖

| crate | 版本 | 使用者 | 用途 | 引入理由 |
|---|---|---|---|---|
| `spin` | "0.9"（mm 钉 0.9.8） | klib 之外的各内核 crate（drv/fs/mm/vfs/kernel） | no_std 自旋锁 `Mutex`/`RwLock` 与 `Once` | no_std 下无 std 同步原语；中断上下文需要无阻塞锁。自研替代需正确处理内存序与 MCS 公平性，收益为零——锁原语不是本项目的差异化目标 |
| `buddy_system_allocator` | "0.9" | klib | 内核堆分配器（LockedHeap 挂接 GlobalAlloc） | 堆分配器要求与 LazyBuddy 物理帧分配器语义正交；该 crate 是 no_std 事实标准实现，经审计的伙伴系统。自研需完整对齐/分裂/合并测试面 |
| `limine` | "0.1"（features: requests-section） | kernel | 启动协议（Limine boot protocol 请求结构） | 手写 Limine 请求节是纯 ABI 样板且极易因版本漂移损坏；该 crate 仅声明请求结构，不含运行时行为 |

## 构建期依赖

| 工具 | 版本约束 | 用途 |
|---|---|---|
| Rust toolchain | workspace edition 2024（见 rust-toolchain） | 编译器 |
| `cargo build --target x86_64-unknown-none` | — | 裸机目标 |
| Python ≥3.x + sdk/ 构建脚本 | — | ISO 组装、符号表生成（symbols_generated.rs）、selftest 编排 |

## 版本钉策略

- `spin` 各 crate 写法不一（"0.9" vs "0.9.8"）：Cargo 语义化解析下同树收敛
  到单一版本；mm 的 0.9.8 是历史钉点。统一为 "0.9" 属低风险清理项，
  不在本轮强制。
- 禁止出现同一外部依赖的两个大版本共存于最终内核镜像。

## 审查锚点

- vfs1 D1：本文件缺失曾使 spin 依赖在文档体系零披露——已闭合。
