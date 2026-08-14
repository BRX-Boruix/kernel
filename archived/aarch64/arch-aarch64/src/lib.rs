//! aarch64 架构实现。
//!
//! 实现 `arch::Platform`，提供 CPU 停机（wfi）、PL011 UART 串口等操作。
//! 在 QEMU virt 平台下运行，PL011 UART 物理基址为 0x09000000。
//! 仅在 aarch64 target 下编译（其他架构编译时为空）。
//!
//! HHDM 偏移由 Limine 提供，需在启动早期通过 `set_hhdm_offset` 注入，
//! 用于把物理地址映射为可访问的虚拟地址。

#![no_std]
#![cfg(target_arch = "aarch64")]

use core::sync::atomic::{AtomicU64, Ordering};
use arch::Platform;

/// QEMU virt 平台的 PL011 UART 物理基址
const PL011_BASE_PHYS: u64 = 0x0900_0000;

/// HHDM 偏移（由 Limine 提供，启动早期注入）
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// 注入 HHDM 偏移（内核入口在获取 Limine HhdmResponse 后调用）
pub fn set_hhdm_offset(offset: u64) {
    HHDM_OFFSET.store(offset, Ordering::SeqCst);
}

/// PL011 寄存器偏移
const DR: u64 = 0x000; // Data Register
const FR: u64 = 0x018; // Flag Register
const TXFF_BIT: u8 = 5; // Transmit FIFO Full
const RXFE_BIT: u8 = 4; // Receive FIFO Empty
const IBRD: u64 = 0x024;
const FBRD: u64 = 0x028;
const LCR_H: u64 = 0x02C;
const CR: u64 = 0x030;

/// 将物理地址转为可访问的虚拟地址（通过 Limine HHDM 偏移）
fn phys_to_virt(phys: u64) -> *mut u8 {
    (HHDM_OFFSET.load(Ordering::SeqCst) + phys) as *mut u8
}

/// 读取 PL011 寄存器
unsafe fn read_reg(offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile(phys_to_virt(PL011_BASE_PHYS + offset) as *const u32) }
}

/// 写入 PL011 寄存器
unsafe fn write_reg(offset: u64, val: u32) {
    unsafe {
        core::ptr::write_volatile(phys_to_virt(PL011_BASE_PHYS + offset) as *mut u32, val);
    }
}

/// 初始化 PL011 UART
fn uart_init() {
    unsafe {
        // 禁用 UART 进行配置
        write_reg(CR, 0);
        // 波特率：QEMU 默认时钟 24MHz，目标 115200
        write_reg(IBRD, 13);
        write_reg(FBRD, 0);
        // 8 位、无校验、1 停止位
        write_reg(LCR_H, 0x60);
        // 使能 UART、TX、RX
        write_reg(CR, 0x301);
    }
}

/// 写入单个字节
fn uart_putc(byte: u8) {
    unsafe {
        // 等待发送 FIFO 非满
        while read_reg(FR) & (1 << TXFF_BIT) != 0 {}
        write_reg(DR, byte as u32);
    }
}

/// aarch64 架构平台
pub struct AArch64Arch;

impl Platform for AArch64Arch {
    fn name() -> &'static str {
        "aarch64"
    }

    fn init() {
        uart_init();
    }

    fn halt() -> ! {
        loop {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfi");
            }
        }
    }

    fn serial_write(byte: u8) {
        uart_putc(byte);
    }

    fn serial_read() -> Option<u8> {
        unsafe {
            // RXFE bit 0 表示 FIFO 空
            if read_reg(FR) & (1 << RXFE_BIT) == 0 {
                Some(read_reg(DR) as u8)
            } else {
                None
            }
        }
    }
}
