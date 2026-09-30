# 外部依赖清单（DEPENDENCIES）

> 本文件是 BORUIX 内核工作区**全部外部（crates.io）依赖**的唯一登记处。
> 任何新增外部依赖必须在引入的同一变更中在此登记：名称、版本、用途、
> 引入理由、替代方案评估。零披露引入即违规（vfs1 D1 / ADR-023）。
>
> 路径依赖（workspace 内 `path = "../..."`）不属外部依赖，不在本表。

## 运行时依赖

| crate | 版本 | 使用者 | 用途 | 引入理由 |
|---|---|---|---|---|
| `spin` | "0.9"（各 crate 已统一写法，T-MM） | klib 之外的各内核 crate（drv/fs/mm/vfs/kernel） | no_std 自旋锁 `Mutex`/`RwLock` 与 `Once` | no_std 下无 std 同步原语；中断上下文需要无阻塞锁。自研替代需正确处理内存序与 MCS 公平性，收益为零——锁原语不是本项目的差异化目标 |
| `buddy_system_allocator` | "0.9" | klib | 内核堆分配器（LockedHeap 挂接 GlobalAlloc） | 堆分配器要求与 LazyBuddy 物理帧分配器语义正交；该 crate 是 no_std 事实标准实现，经审计的伙伴系统。自研需完整对齐/分裂/合并测试面 |
| `limine` | "0.1"（features: requests-section） | kernel | 启动协议（Limine boot protocol 请求结构） | 手写 Limine 请求节是纯 ABI 样板且极易因版本漂移损坏；该 crate 仅声明请求结构，不含运行时行为 |
| `lock_api` | 0.4.14（**传递**） | spin | `spin` 的 lock_api 后端（RAII 守卫） | 非直接引入；随 spin 进二进制。上游双许可 MIT OR Apache-2.0，本分发取 MIT 臂 |
| `scopeguard` | 1.2.0（**传递**） | lock_api | `lock_api` 的传递依赖（作用域守卫） | 非直接引入；纯传递。上游双许可 MIT OR Apache-2.0，本分发取 MIT 臂 |

## 构建期依赖

| 工具 | 版本约束 | 用途 |
|---|---|---|
| Rust toolchain | workspace edition 2024（见 rust-toolchain） | 编译器 |
| `cargo build --target x86_64-unknown-none` | — | 裸机目标 |
| Python ≥3.x + tools/ 构建脚本 | — | ISO 组装、符号表生成（symbols_generated.rs）、selftest 编排 |
| `limine-proc` 及宿主端树（`proc-macro2`/`quote`/`syn`/`unicode-ident`） | 见 Cargo.lock | `#[limine::limine_tag]` 过程宏 | 过程宏在**宿主编译期**运行，代码**不进**目标二进制（故无需随二进制披露）。注意 `unicode-ident` 的许可是 `(MIT OR Apache-2.0) AND Unicode-3.0` |

## 版本钉策略

- `spin` 各 crate 写法已统一为 "0.9"（T-MM 清理闭合）：Cargo 语义化解析下
  同树收敛到单一版本（Cargo.lock 固化 0.9.9）。mm 的 0.9.8 历史钉点已清除。
- 禁止出现同一外部依赖的两个大版本共存于最终内核镜像。
- **registry 依赖已 `cargo vendor` 入库**（`vendor/registry/`，源替换见
  `.cargo/config.toml`）：构建不再读 crates.io，也不读本机 `~/.cargo` 缓存——版本钉
  从"锁文件 + 网络"变为"锁文件 + 仓内源码"。**更新依赖后必须重跑 `cargo vendor`**，
  并复核 `python tools/checks/regression/license_audit.py`（有未披露的进二进制 crate
  即 exit 1）。

## 审查锚点

- vfs1 D1：本文件缺失曾使 spin 依赖在文档体系零披露——已闭合。
- 第三方许可证披露：组件表在 `crates/kernel/src/licenses.rs`（收录判据 = 代码真的
  进了内核二进制），人读登记在 `kernel/NOTICE.md`，随二进制披露于 `/system/licenses/`；
  缺口由 `tools/checks/regression/license_audit.py` 机械把关。
