//! BORUIX 内核通用库。
//!
//! 提供串口输出、日志、boot 堆分配器等内核基础设施。

#![no_std]

// 单测环境（std test harness）需要 std；no_std crate 需显式声明。
#[cfg(test)]
extern crate std;

// 内核堆分配器（含 `#[global_allocator]`）仅在真实内核目标上编译：
// - 宿主测试构建（`cargo test`，target_os = windows/linux/...）使用 std
//   自带的系统分配器，避免未初始化的内核堆接管 test harness 的分配
//   （klib 自身与依赖 klib 的 crate 的单元测试都依赖这一点）；
// - 内核交叉编译目标（x86_64-unknown-none，target_os = "none"）才编译
//   本模块，提供 `#[global_allocator]`。
#[cfg(all(not(test), target_os = "none"))]
pub mod allocator;
pub mod collections;
pub mod console;
pub mod error;
pub mod format;
pub mod json;
pub mod log;
pub mod random;
pub mod serial;
pub mod sync;
pub mod time;
