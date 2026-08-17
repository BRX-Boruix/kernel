//! I/O APIC 驱动（阶段 B）：使能外部 ISA 中断（键盘 IRQ1）。
//!
//! QEMU APIC 模式下，外部中断（ISA 设备如 PS/2 键盘）经 I/O APIC 路由到
//! LAPIC。本驱动在 I/O APIC 默认基址 `0xFEC00000` 上编程（QEMU 标准布局，
//! 无需解析 ACPI MADT——教学内核的务实做法），把键盘 IRQ1（GSI 1）重定向
//! 到向量 33 并解除屏蔽。
//!
//! 仅当需要键盘等外部设备中断时调用；定时器走 LAPIC 自身，不需 IOAPIC。

use crate::mmio;

// I/O APIC 默认物理基址（QEMU 标准）。
const IOAPIC_PHYS: u64 = 0xFEC0_0000;
// I/O APIC MMIO 寄存器（间接索引：offset 0x00 为 index，0x10 为 data）。
const IOAPIC_INDEX: usize = 0x00;
const IOAPIC_DATA: usize = 0x10;

// I/O APIC 寄存器
const IOAPIC_ID: u32 = 0x00;
const IOAPIC_VER: u32 = 0x01;
// 中断重定向表起始：IOREDTBL 从寄存器 0x10 起，每 IRQ 2 个寄存器（低/高 32 位）。
const IOREDTBL_BASE: u32 = 0x10;

/// 键盘 IRQ 号（ISA IRQ1）。
const KBD_IRQ: u32 = 1;
/// 键盘中断向量（指向 IDT 的 isr_33，即 IRQ1）。
const KBD_VECTOR: u32 = 0x21; // 33

/// I/O APIC 是否已映射（成功初始化后 true）。
static MAPPED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// 读 I/O APIC 寄存器。
fn ioapic_read(reg: u32) -> u32 {
    let virt = IOAPIC_PHYS | 0xffff_8000_0000_0000;
    // SAFETY: 映射后的 IOAPIC 寄存器 MMIO。
    unsafe {
        mmio::write_u32(virt + IOAPIC_INDEX as u64, reg);
        mmio::read_u32(virt + IOAPIC_DATA as u64)
    }
}

/// 写 I/O APIC 寄存器。
fn ioapic_write(reg: u32, val: u32) {
    let virt = IOAPIC_PHYS | 0xffff_8000_0000_0000;
    // SAFETY: 映射后的 IOAPIC 寄存器 MMIO。
    unsafe {
        mmio::write_u32(virt + IOAPIC_INDEX as u64, reg);
        mmio::write_u32(virt + IOAPIC_DATA as u64, val);
    }
}

/// 使能键盘 IRQ1 外部中断（重定向到 vector 33）。
///
/// 把 IOREDTBL[1] 的低 32 位设为 `vector | (1<<16)`（物理交付模式）、
/// 高 32 位设为 0（BSP 的 LAPIC ID 0，edge 触发）。调用后 LAPIC 需已使能
/// （`lapic::init` 已设 SVR），且中断已全局使能。
pub fn init() {
    // 映射 I/O APIC MMIO（2MB 页，与 LAPIC 相同方式）。
    if !mmio::map_lapic(IOAPIC_PHYS, IOAPIC_PHYS | 0xffff_8000_0000_0000) {
        klib::info!("[ioapic] map failed");
        return;
    }

    // 校验 I/O APIC 版本寄存器（低 8 位 = max redirection entries - 1）。
    let ver = ioapic_read(IOAPIC_VER);
    let max_entries = (ver & 0xFF) + 1;
    klib::info!("[ioapic] version={:#x} max_entries={}", ver, max_entries);
    if KBD_IRQ >= max_entries {
        klib::info!("[ioapic] IRQ1 out of range");
        return;
    }

    // 屏蔽该 IRQ（先禁用以防瞬间触发）。
    ioapic_write(IOREDTBL_BASE + KBD_IRQ * 2, 1 << 16); // 高 32 位=0，低=中断屏蔽位(bit16)
    ioapic_write(IOREDTBL_BASE + KBD_IRQ * 2 + 1, 0);

    // 配置：vector=33，物理交付，edge 触发，未屏蔽。
    let low = KBD_VECTOR; // bit0-7 vector；bit16=0 不屏蔽
    ioapic_write(IOREDTBL_BASE + KBD_IRQ * 2, low);
    ioapic_write(IOREDTBL_BASE + KBD_IRQ * 2 + 1, 0);

    MAPPED.store(true, core::sync::atomic::Ordering::Release);
    klib::info!("[ioapic] keyboard IRQ1 -> vector {} enabled", KBD_VECTOR);
}

/// I/O APIC 是否已配置键盘中断。
pub fn keyboard_enabled() -> bool {
    MAPPED.load(core::sync::atomic::Ordering::Acquire)
}
