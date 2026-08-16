//! BORUIX 内核通用库。
//!
//! 提供串口输出、日志、boot 堆分配器等内核基础设施。

#![no_std]

// 内核堆分配器（含 `#[global_allocator]`）仅在非测试构建下编译：
// 单测环境下它从未被 `init()` 初始化，而 test harness（std 初始化）
// 需要堆分配，会因走未初始化的内核堆而崩溃。故测试构建使用系统分配器。
#[cfg(not(test))]
pub mod allocator;
pub mod console;
pub mod format;
pub mod log;
pub mod serial;
