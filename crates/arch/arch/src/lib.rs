//! BORUIX 架构抽象层。
//!
//! 定义平台无关的 trait，由各具体架构（`arch-x86_64`、未来的
//! `arch-riscv64`、`arch-aarch64`）实现。通用代码只依赖本 crate 的
//! trait，不直接接触硬件寄存器，从而实现"一套业务代码、多架构可移植"。

#![no_std]

// 单测环境（std test harness）需要 std；no_std crate 需显式声明。
#[cfg(test)]
extern crate std;

pub mod acpi;
pub mod addr;
pub mod cpu;
pub mod hhdm;
pub mod paging;
pub mod task;
pub mod timer;

pub use acpi::{Rsdp, SdtHeader};
pub use addr::{PhysAddr, PhysFrame, VirtAddr};
pub use cpu::{Cpu, CpuFeature};
pub use hhdm::{PHYS_OFFSET, phys_to_virt, virt_to_phys};
pub use paging::{ActivePageTable, PageFaultCode, PageFlags, PageSize, PageTable};
pub use task::{TaskContext, switch_to};
pub use timer::{Timer, TimerCallback};

/// 架构平台抽象。
///
/// 每个具体架构实现一个 `Platform`，提供 CPU 停机、串口等基础操作。
/// 通用内核代码通过该 trait 访问硬件，避免直接依赖某架构指令。
pub trait Platform {
    /// 架构名称（如 "x86_64"）。
    fn name() -> &'static str;

    /// 初始化平台硬件（串口、中断控制器等）。
    fn init();

    /// CPU 停机，永远不返回。
    fn halt() -> !;

    /// 串口写入单个字节。
    fn serial_write(byte: u8);

    /// 串口读取单个字节（无数据返回 None）。
    fn serial_read() -> Option<u8>;
}
