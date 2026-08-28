//! 中断控制抽象（ADR-007）。
//!
//! 统一成"注册 handler + 使能/屏蔽"的抽象，不绑定某架构的中断控制器
//! （x86 的 8259 PIC / LAPIC、riscv 的 PLIC、aarch64 的 GIC）。各架构
//! 实现本 trait，业务代码只依赖此接口，从而"一套业务代码、多架构可移植"。
//!
//! 覆盖 ADR-007"中断抽象"中可移植的部分：
//! - 外部中断（IRQ）处理函数注册/注销（共享中断语义）；
//! - 中断使能 / 屏蔽 / 状态查询。
//!
//! 架构相关的回调（页错误、软中断/syscall、调度器 tick 等）各自承载架构
//! 特定的现场帧（如 x86 的 `InterruptFrame`），由对应架构层直接接线；
//! 本 trait 只抽象真正可移植的中断控制面（ADR-007：不把寄存器/帧知识
//! 泄漏进业务逻辑）。

/// 外部中断（IRQ）处理函数。
///
/// 返回 `true` 表示已处理（共享中断分发停止继续）；`false` 表示未处理
/// （交给同 IRQ 的下一个 handler）。
pub type IrqHandler = extern "C" fn(u8) -> bool;

/// 中断控制抽象接口（全静态方法，风格与 [`crate::Platform`] / [`crate::Timer`] 一致）。
pub trait InterruptController {
    /// 注册外部中断（IRQ）处理函数（支持共享：同一 IRQ 可注册多个）。
    ///
    /// 处理函数须为 `'static`（当前为 `extern "C"` 静态函数），且注册期间
    /// 不可注销，以保证中断上下文无锁读取时指针始终有效。
    ///
    /// 返回 `true` 表示注册成功；`false` 表示 IRQ 越界、重复注册或槽位已满。
    fn register_irq(irq: u8, handler: IrqHandler) -> bool;

    /// 注销外部中断处理函数（共享中断下移除一个 handler）。
    ///
    /// 返回 `true` 表示确实存在并已移除。中断上下文中该 handler 可能正在
    /// 执行，调用方须保证注销后不再依赖它。
    fn unregister_irq(irq: u8, handler: IrqHandler) -> bool;

    /// 使能中断。
    fn enable();

    /// 屏蔽中断。
    fn disable();

    /// 当前中断是否使能。
    fn interrupts_enabled() -> bool;
}
