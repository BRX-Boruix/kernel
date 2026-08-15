//! 8259 可编程中断控制器（PIC）。
//!
//! 与 APIC 不同，8259 通过 port I/O 编程，无需内存映射，适合当前
//! 尚未建立虚拟内存映射的阶段。将 IRQ0~15 重映射到 IDT 向量 32~47，
//! 避免与 CPU 异常向量 0~31 冲突。

use crate::serial;

// 8259 端口
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW 常量
const ICW1_INIT: u8 = 0x11; // 初始化 + 级联
const ICW4_8086: u8 = 0x01; // 8086 模式

/// 重新映射 IRQ0~15 到 IDT 向量 32~47。
pub fn remap() {
    let mask1 = inb(PIC1_DATA);
    let mask2 = inb(PIC2_DATA);

    // 向两个 PIC 发送初始化命令
    outb(PIC1_COMMAND, ICW1_INIT);
    outb(PIC2_COMMAND, ICW1_INIT);

    // 中断向量偏移：主片 0x20 (32)，从片 0x28 (40)
    outb(PIC1_DATA, 0x20);
    outb(PIC2_DATA, 0x28);

    // 级联配置：主片 IRQ2 接从片；从片级联到主片 IRQ2
    outb(PIC1_DATA, 0x04);
    outb(PIC2_DATA, 0x02);

    // 8086 模式
    outb(PIC1_DATA, ICW4_8086);
    outb(PIC2_DATA, ICW4_8086);

    // 恢复原中断掩码
    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);
}

/// 屏蔽所有 IRQ（除了掩码参数中为 0 的位）。
///
/// `mask` 为 16 位：bit i = 0 表示使能 IRQ i。
pub fn set_mask(mask: u16) {
    outb(PIC1_DATA, (mask & 0xFF) as u8);
    outb(PIC2_DATA, ((mask >> 8) & 0xFF) as u8);
}

/// 读取当前中断掩码。
pub fn get_mask() -> u16 {
    (inb(PIC1_DATA) as u16) | ((inb(PIC2_DATA) as u16) << 8)
}

/// 发送 EOI（中断结束）给主片（和从片）。
pub fn end_of_interrupt(irq: u8) {
    if irq >= 8 {
        outb(PIC2_COMMAND, 0x20);
    }
    outb(PIC1_COMMAND, 0x20);
}

/// 初始化 8259 PIC：重映射到向量 32~47，默认全部屏蔽。
pub fn init() {
    remap();
    set_mask(0xFFFF); // 默认屏蔽所有 IRQ
    serial::write_str("[pic] 8259 remapped to vectors 32-47\r\n");
}

// ---------- port I/O ----------

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
