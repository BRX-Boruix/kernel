//! x86-64 架构实现。
//!
//! 实现 `arch::Platform`，提供 CPU 停机、串口等基础操作。

#![no_std]

pub mod serial;

use arch::Platform;

/// x86-64 架构平台
pub struct X86_64Arch;

impl Platform for X86_64Arch {
    fn name() -> &'static str {
        "x86_64"
    }

    fn init() {
        serial::init();
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
