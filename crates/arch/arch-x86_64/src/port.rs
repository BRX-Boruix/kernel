//! x86-64 port I/O（inb/outb）。
//!
//! 供串口、PIC 等设备驱动复用，避免各模块重复实现相同汇编。

/// 读取 port（inb）
#[inline]
pub fn inb(port: u16) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") result,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    result
}

/// 写入 port（outb）
#[inline]
pub fn outb(port: u16, byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}
