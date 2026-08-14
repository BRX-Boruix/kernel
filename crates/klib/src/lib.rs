//! BORUIX 内核通用库。
//!
//! 提供串口输出、日志、boot 堆分配器等内核基础设施。

#![no_std]

pub mod allocator;
pub mod serial;
