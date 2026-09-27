//! BORUIX 内核通用库。
//!
//! 提供串口输出、日志、boot 堆分配器等内核基础设施。

#![no_std]

// A3（定时器动态表）：klib 需要 alloc 容器（Vec）。no_std crate 无条件引
// alloc：内核目标由 #[global_allocator]（本 crate allocator 模块）供给，
// 宿主测试构建由 std 供给——alloc crate 不反向依赖 klib 模块，无循环（S13）。
extern crate alloc;

// 单测环境（std test harness）需要 std；no_std crate 需显式声明。
#[cfg(test)]
extern crate std;

// 内核堆分配器：增长逻辑（grow_order/grow_heap）在宿主测试构建同样编译
// （KM2：全系统最关键的 126 行堆机制不得存在覆盖盲区，假增长源驱动单测）；
// `#[global_allocator]` 静态物仅在真实内核目标编译：
// - 宿主测试构建（`cargo test`）使用 std 自带的系统分配器，避免未初始化的
//   内核堆接管 test harness 的分配（klib 自身与依赖 klib 的 crate 的单元
//   测试都依赖这一点）；
// - 内核交叉编译目标（x86_64-unknown-none，target_os = "none"）才提供
//   `#[global_allocator]` 与引导堆。
#[cfg(any(test, target_os = "none"))]
pub mod allocator;
pub mod collections;
pub mod console;
pub mod error;
pub mod json;
pub mod log;
pub mod pic_mask;
pub mod random;
pub mod serial;
pub mod sync;
pub mod time;
