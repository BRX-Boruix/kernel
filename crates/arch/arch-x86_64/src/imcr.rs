//! IMCR（Interrupt Mode Control Register）切换：把中断投递模式切回 PIC。
//!
//! AD2 改名：原模块名 `ioapic` 名不副实——本模块从不编程 I/O APIC（重定向
//! 表保持不动，否则与 8259 双路由冲突），实际职责只有一条 MP 规范规定的
//! IMCR 写序列。按真实职责命名，避免后来者误以为这里存在 IOAPIC 驱动逻辑。
//!
//! 本项目在 QEMU `pc` 机器下，PS/2 键盘 IRQ1 走 **8259 PIC → LAPIC LINT0
//! (ExtINT)** 路径（最可靠的外部中断源）。为此需要三条配合：
//!
//! 1. [`crate::pic`] 在 APIC 模式下重映射 8259 并解除键盘 IRQ1 屏蔽；
//! 2. [`crate::lapic`] 把 LINT0 配置为 ExtINT 接收 8259 输出；
//! 3. 本模块把 **IMCR** 切到 PIC 模式（`0x00`），使 8259 输出重新连到 CPU。
//!
//! QEMU 在 LAPIC 启用后默认 APIC 模式（8259 断开、外部中断改走 I/O APIC），
//! 键盘中断会因此丢失；必须显式切回 PIC 模式。

use crate::port::outb;

/// 中断模式控制寄存器（IMCR）端口：索引 0x22、数据 0x23（MP 规范）。
/// 写 `0x22,0x70` 选 IMCR，再写 `0x23,0x00` 切回 **PIC 模式**（使 8259 输出
/// 重新连到 CPU 的 LAPIC LINT0）。
const IMCR_INDEX: u16 = 0x22;
const IMCR_DATA: u16 = 0x23;
const IMCR_SELECT: u8 = 0x70;
const IMCR_PIC_MODE: u8 = 0x00;

/// 切换中断模式到 PIC（使 8259 输出连到 LAPIC LINT0）。
///
/// 在 LAPIC 已使能、LINT0 已配 ExtINT、8259 已重映射并解除 IRQ1 屏蔽之后调用。
pub fn switch_to_pic_mode() {
    // IMCR 端口写（port::outb 在本 crate 中为安全封装，单线程启动期调用）。
    outb(IMCR_INDEX, IMCR_SELECT);
    outb(IMCR_DATA, IMCR_PIC_MODE);
    klib::info!("[imcr] IMCR -> PIC mode (8259 -> LAPIC LINT0)");
}
