//! x86-64 port I/O（inb/outb/inw/outw/inl/outl）。
//!
//! 供串口、PIC、PCI、ATA 等设备驱动复用，避免各模块重复实现相同汇编。

/// 读取 port（inb，8 位）
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

/// 写入 port（outb，8 位）
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

/// 读取 port（inw，16 位）
#[inline]
pub fn inw(port: u16) -> u16 {
    let result: u16;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") result,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    result
}

/// 写入 port（outw，16 位）
#[inline]
pub fn outw(port: u16, word: u16) {
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") word,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// 读取 port（inl，32 位）
#[inline]
pub fn inl(port: u16) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            out("eax") result,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    result
}

/// 写入 port（outl，32 位）
#[inline]
pub fn outl(port: u16, value: u32) {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}
