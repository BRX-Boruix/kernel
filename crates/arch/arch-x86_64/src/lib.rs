//! x86-64 架构实现。
//!
//! 实现 `arch::Platform`，提供 CPU 停机、串口、GDT/IDT、PIC/LAPIC 等基础操作。

#![no_std]

extern crate alloc;

pub mod acpi;
pub mod cpu;
pub mod gdt;
pub mod hpet;
pub mod interrupts;
pub mod lapic;
pub mod mmio;
pub mod paging;
pub mod pci;
pub mod pic;
pub mod port;
pub mod rtc;
pub mod serial;
pub mod smp;
pub mod task;
pub mod timer;

use arch::Platform;

/// x86-64 架构平台
pub struct X86_64Arch;

/// 永久停机（关闭中断后 hlt 循环）。
pub fn halt_forever() -> ! {
    crate::interrupts::halt_forever()
}

impl Platform for X86_64Arch {
    fn name() -> &'static str {
        "x86_64"
    }

    fn init() {
        // 注入中断状态保存/恢复函数（供 klib 中断安全锁使用；须在任何日志输出前）。
        klib::sync::irq::set_irq_guard(interrupts::irq_save, interrupts::irq_restore);
        serial::init();
        gdt::init();
        interrupts::init();
        pic::init();
        task::init(); // 注入上下文切换实现
    }

    fn halt() -> ! {
        crate::interrupts::halt_forever()
    }

    fn serial_write(byte: u8) {
        serial::write_byte(byte);
    }

    fn serial_read() -> Option<u8> {
        serial::read_byte()
    }
}
