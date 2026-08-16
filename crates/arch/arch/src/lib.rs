//! BORUIX 架构抽象层。
//!
//! 定义平台无关的 trait，由各具体架构（`arch-x86_64`、未来的
//! `arch-riscv64`、`arch-aarch64`）实现。通用代码只依赖本 crate 的
//! trait，不直接接触硬件寄存器，从而实现"一套业务代码、多架构可移植"。

#![no_std]

pub mod addr;
pub mod hhdm;
pub mod paging;
pub mod task;

pub use addr::{PhysAddr, PhysFrame, VirtAddr};
pub use hhdm::{phys_to_virt, virt_to_phys, PHYS_OFFSET};
pub use paging::{ActivePageTable, PageFlags, PageSize, PageTable};
pub use task::{switch_to, TaskContext};

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
