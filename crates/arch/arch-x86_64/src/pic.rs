//! 8259 可编程中断控制器（PIC）。
//!
//! 与 APIC 不同，8259 通过 port I/O 编程，无需内存映射，适合当前
//! 尚未建立虚拟内存映射的阶段。将 IRQ0~15 重映射到 IDT 向量 32~47，
//! 避免与 CPU 异常向量 0~31 冲突。

use crate::port::{inb, outb};

// 8259 端口（x86 硬件标准，非温室假设）。
// 主片（master）命令/数据端口 0x20/0x21，从片（slave）0xA0/0xA1。
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW 常量
const ICW1_INIT: u8 = 0x11; // 初始化 + 级联
const ICW4_8086: u8 = 0x01; // 8086 模式

/// IA32_APIC_BASE MSR：bit 12 表示 LAPIC 已启用。
const MSR_APIC_BASE: u32 = 0x1B;

/// 检测 LAPIC 是否已由固件/引导器启用。
///
/// 若已启用（现代 UEFI 平台 + APIC 模式），重编程 8259 是多余的，还可能
/// 干扰 IOAPIC 的中断路径，因此跳过重映射、仅屏蔽即可。
fn apic_enabled() -> bool {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_APIC_BASE,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    let value = ((hi as u64) << 32) | lo as u64;
    value & (1 << 12) != 0
}

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

/// 初始化 8259 PIC。
///
/// 无条件重映射 8259 到向量 32~47（避免与 CPU 异常向量 0~31 冲突），并**仅解除
/// 键盘 IRQ1 屏蔽**（bit1=0），其余（含 IRQ0 timer、IRQ2 级联）保持屏蔽。
///
/// 本项目键盘走 **8259 → LAPIC LINT0 (ExtINT)** 路径（QEMU `pc` 机器最可靠的
/// 外部中断源）：`ioapic::init` 把 IMCR 切到 PIC 模式使 8259 输出连 LINT0，
/// `lapic::init` 把 LINT0 配为 ExtINT 接收；此处解屏蔽 IRQ1 才能让其到达 CPU。
/// IRQ0（timer）由 LAPIC 自身定时器接管，故保持屏蔽。
pub fn init() {
    remap();
    // 仅 IRQ1（键盘）使能（bit1=0），其余（含 IRQ0 timer、IRQ2 级联）屏蔽。
    set_mask(0xFFFD);
    klib::info!("[pic] 8259 remapped, IRQ1 (kbd) unmasked");
}
