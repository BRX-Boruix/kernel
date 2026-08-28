//! x86-64 中断控制实现（ADR-007 的 `arch::InterruptController`）。
//!
//! 转发到 [`crate::interrupts`] 的现有实现（8259 PIC + LAPIC + IDT 之上的
//! 外部 IRQ 注册表、`sti`/`cli` 中断开关）。trait 使业务代码只依赖
//! `arch::InterruptController`，不接触 x86 的寄存器/中断门细节。

use arch::interrupt::{InterruptController, IrqHandler};

/// x86-64 中断控制器：转发 [`crate::interrupts`] 的外部 IRQ 表与中断开关。
pub struct X86InterruptController;

impl InterruptController for X86InterruptController {
    fn register_irq(irq: u8, handler: IrqHandler) -> bool {
        crate::interrupts::register_irq(irq, handler)
    }

    fn unregister_irq(irq: u8, handler: IrqHandler) -> bool {
        crate::interrupts::unregister_irq(irq, handler)
    }

    fn enable() {
        crate::interrupts::enable();
    }

    fn disable() {
        crate::interrupts::disable();
    }

    fn interrupts_enabled() -> bool {
        crate::interrupts::interrupts_enabled()
    }
}
