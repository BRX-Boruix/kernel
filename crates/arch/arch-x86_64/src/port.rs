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

/// 批量读入 count 个 16 位字（rep insw）到 dst（需有 count * 2 字节空间）。
///
/// **为什么必须有**（2026-10 实测的根因修复）：ATA PIO 的扇区传输原实现是 Rust 循环里
/// 逐字 inw —— 每扇区 **256 次端口访问**，而在 QEMU/TCG 下**每次端口访问都是一次 VM exit**。
/// 机内实测：每次小文件写约 **8.9 毫秒**；tcc 链接后节数 4049 ⇒ 36 秒（实测 35 秒）。
/// rep insw 把 256 次压成 **1 次**（一条指令、一次退出）。
///
/// 按**字节指针**取参、不做 16 位对齐假设：x86 的 rep insw 无对齐要求，
/// 用 *mut u16 会在调用点引入"未对齐引用"的 UB 面。
///
/// **安全**：调用方须保证 dst 可写 count * 2 字节、且端口确实处于数据相位。
#[inline]
pub unsafe fn insw(port: u16, dst: *mut u8, count: usize) {
    unsafe {
        core::arch::asm!(
            "rep insw",
            in("dx") port,
            inout("rdi") dst => _,
            inout("rcx") count => _,
            options(nostack, preserves_flags)
        );
    }
}

/// 批量写出 count 个 16 位字（rep outsw）。安全与理由同 insw。
#[inline]
pub unsafe fn outsw(port: u16, src: *const u8, count: usize) {
    unsafe {
        core::arch::asm!(
            "rep outsw",
            in("dx") port,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack, preserves_flags)
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
