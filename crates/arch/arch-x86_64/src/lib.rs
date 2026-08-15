//! x86-64 架构实现。
//!
//! 实现 `arch::Platform`，提供 CPU 停机、串口、GDT/IDT、PIC/LAPIC 等基础操作。

#![no_std]

pub mod gdt;
pub mod interrupts;
pub mod lapic;
pub mod mmio;
pub mod paging;
pub mod pic;
pub mod serial;

use arch::Platform;

/// x86-64 架构平台
pub struct X86_64Arch;

/// 永久停机（关闭中断后 hlt 循环）。
pub fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

impl Platform for X86_64Arch {
    fn name() -> &'static str {
        "x86_64"
    }

    fn init() {
        serial::init();
        gdt::init();
        interrupts::init();
        pic::init();
    }

    fn halt() -> ! {
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack));
            }
        }
    }

    fn serial_write(byte: u8) {
        serial::write_byte(byte);
    }

    fn serial_read() -> Option<u8> {
        serial::read_byte()
    }
}
