//! 中断描述符表（IDT）与异常/中断处理。
//!
//! - 覆盖 CPU 异常 0~31（除 16 号 FPU 错误外的通用兜底），以及外部中断 32~47。
//! - 通过手写汇编入口将 CPU 压栈的寄存器保存为 `InterruptFrame`，
//!   交给 Rust 端的 `dispatch` 分发。
//! - 支持注册外部中断处理函数（当前提供定时器 PIT 的中断）。

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// 内核代码段选择子（加载 IDT 描述符时使用）。
use crate::gdt::{IST_DF, KCODE};

// ---------- IDT 结构 ----------

/// 一个 IDT 条目（16 字节）。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,   // 处理函数偏移 0..15
    selector: u16,     // 代码段选择子
    ist: u8,           // IST（未用，填 0）
    flags: u8,         // 类型与属性（present, DPL, interrupt gate）
    offset_mid: u16,   // 偏移 16..31
    offset_high: u32,  // 偏移 32..63
    reserved: u32,     // 保留（必须为 0），使条目总大小为 16 字节
}

impl IdtEntry {
    const fn new() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, flags: u8, ist: u8) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = KCODE;
        self.flags = flags;
        self.ist = ist;
    }
}

/// 中断门（从用户态不可访问）
const IDT_FLAG_INTERRUPT: u8 = 0x8E;
/// 陷阱门（从用户态不可访问）
const IDT_FLAG_TRAP: u8 = 0x8F;
/// 陷阱门（DPL=3，用户态可触发；供软中断/系统调用使用）
const IDT_FLAG_TRAP_USER: u8 = 0xEF;

/// IDT（256 个条目）。
#[repr(C, packed)]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::new(); 256],
        }
    }
}

/// IDTR 结构。
#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: Idt = Idt::new();

// ---------- 中断入口（汇编） ----------

// 生成 32 个异常入口 + 16 个外部中断入口，共 48 个。
// 每个入口把中断号压栈，然后跳到公共处理 `common_stub`。
// 有错误码的异常（8,10,11,12,13,14,17）CPU 会自动压栈错误码，
// 这里统一在入口补压一个占位 0，保证帧布局一致。

global_asm!(
    r#"
    .section .text

    // 公共中断处理入口。
    // 栈布局（由低到高）：
    //   rsp -> [压栈的通用寄存器区]
    //          中断号
    //          (错误码，若无则 0)
    //          RIP, CS, RFLAGS, RSP, SS
    .global interrupt_common_stub
    interrupt_common_stub:
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        mov rdi, rsp
        call interrupt_dispatch

        // 恢复寄存器（interrupt_dispatch 返回后）
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax

        // 跳过中断号 + 错误码（各 8 字节）
        add rsp, 16
        iretq

    // 生成异常入口（无错误码）：先压占位错误码 0，再压中断号。
    // 用 .byte 手工编码 `push imm8`（0x6A）以绕开模板对 `$` 的解析。
    .macro isr_noerr num
        .global isr_\num
        .type isr_\num, @function
    isr_\num:
        .byte 0x6a, 0              // push 0  (错误码占位)
        .byte 0x68, \num, 0, 0, 0   // push 中断号 (imm32)
        jmp interrupt_common_stub
    .endm

    // 生成异常入口（有错误码）：CPU 已压错误码，只需压中断号。
    .macro isr_err num
        .global isr_\num
        .type isr_\num, @function
    isr_\num:
        .byte 0x68, \num, 0, 0, 0   // push 中断号 (imm32)
        jmp interrupt_common_stub
    .endm

    isr_noerr 0
    isr_noerr 1
    isr_noerr 2
    isr_noerr 3
    isr_noerr 4
    isr_noerr 5
    isr_noerr 6
    isr_noerr 7
    isr_err   8
    isr_noerr 9
    isr_err   10
    isr_err   11
    isr_err   12
    isr_err   13
    isr_err   14
    isr_noerr 15
    isr_noerr 16
    isr_err   17
    isr_noerr 18
    isr_noerr 19
    isr_noerr 20
    isr_noerr 21
    isr_noerr 22
    isr_noerr 23
    isr_noerr 24
    isr_noerr 25
    isr_noerr 26
    isr_noerr 27
    isr_noerr 28
    isr_noerr 29
    isr_noerr 30
    isr_noerr 31

    // 外部中断 32..47（无错误码）
    isr_noerr 32
    isr_noerr 33
    isr_noerr 34
    isr_noerr 35
    isr_noerr 36
    isr_noerr 37
    isr_noerr 38
    isr_noerr 39
    isr_noerr 40
    isr_noerr 41
    isr_noerr 42
    isr_noerr 43
    isr_noerr 44
    isr_noerr 45
    isr_noerr 46
    isr_noerr 47

    // 软件中断 0x80（无错误码）：用户态软中断/系统调用入口（M2.5.4 / M3）。
    isr_noerr 128

    .global x86_64_load_idt
    x86_64_load_idt:
        lidt [rdi]
        ret
    "#
);

/// 中断号 0~31 的异常名称。
fn exception_name(vector: u8) -> &'static str {
    const NAMES: [&str; 32] = [
        "Divide-by-zero",
        "Debug",
        "Non-maskable Interrupt",
        "Breakpoint",
        "Overflow",
        "Bound Range Exceeded",
        "Invalid Opcode",
        "Device Not Available",
        "Double Fault",
        "Coprocessor Segment Overrun",
        "Invalid TSS",
        "Segment Not Present",
        "Stack-Segment Fault",
        "General Protection Fault",
        "Page Fault",
        "Reserved",
        "x87 Floating-Point Exception",
        "Alignment Check",
        "Machine Check",
        "SIMD Floating-Point Exception",
        "Virtualization Exception",
        "Control Protection Exception",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Hypervisor Injection Exception",
        "VMM Communication Exception",
        "Security Exception",
        "Reserved",
    ];
    NAMES[vector as usize]
}

/// CPU 压栈形成的帧（保存的寄存器 + 中断号 + 错误码 + 处理器状态）。
///
/// `Copy`：全部字段为 u64，调度器（M4.2）需整体拷贝以在进程间迁移中断帧。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InterruptFrame {
    /// 15 个通用寄存器（由公共 stub 压栈）
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// 中断号
    pub vector: u64,
    /// 错误码（若该异常有错误码）
    pub error_code: u64,
    /// 处理器压栈的上下文
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ---------- 外部中断处理函数表（共享中断） ----------

/// 外部中断处理函数（IRQ）。返回 `true` 表示已处理。
pub type IrqHandler = extern "C" fn(u8) -> bool;

/// 每个 IRQ 最多可注册的处理函数数（共享中断）。
///
/// 同一 IRQ 线上的多个设备（如两个网卡共享一根 IRQ）各自注册一个 handler，
/// 分发时依次调用，任一返回 `true` 即视为已处理。4 个槽位对典型 PC 足够。
pub const MAX_HANDLERS_PER_IRQ: usize = 4;

/// 外部中断处理函数表（IRQ0~15，每 IRQ 多个共享槽位）。
///
/// 采用无锁的原子函数指针表，而非 `spin::Mutex`：因为 `interrupt_dispatch`
/// 运行于**中断上下文**，若某 IRQ 打断同 CPU 正在持有该锁的代码，非可重入的
/// 自旋锁会永远自旋 → 死锁。原子表以 `load(Acquire)` 读、`compare_exchange`
/// 写，处理函数均为 `'static` 且只在中断使能前注册，故安全无锁。
///
/// 取值为 0 表示空槽；合法函数地址不可能为 0，因此可兼作"空"标记。
static IRQ_HANDLERS: [[AtomicUsize; MAX_HANDLERS_PER_IRQ]; 16] =
    [const { [const { AtomicUsize::new(0) }; MAX_HANDLERS_PER_IRQ] }; 16];

/// 注册外部中断（IRQ0~15）的处理函数（支持共享：同一 IRQ 可注册多个）。
///
/// - 处理函数须为 `'static`（当前为 `extern "C"` 静态函数），且永不注销，
///   以保证中断上下文无锁读取时指针始终有效；
/// - 重复注册同一 handler 返回 `false`（幂等，不产生重复分发）；
/// - 该 IRQ 槽位已满返回 `false`。
///
/// 返回 `true` 表示注册成功。
pub fn register_irq(irq: u8, handler: IrqHandler) -> bool {
    if irq >= 16 {
        return false;
    }
    let slot = &IRQ_HANDLERS[irq as usize];
    let ptr = handler as usize; // x86_64 下函数指针与 usize 等宽
    for entry in slot {
        let cur = entry.load(Ordering::Acquire);
        if cur == ptr {
            return false; // 已注册，去重
        }
        if cur == 0 {
            // 竞争写入：仅当槽仍为空时占位。
            if entry
                .compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
            // 竞争失败：换下一个槽重试。
        }
    }
    false // 槽满
}

/// 注销外部中断处理函数（共享中断下移除一个 handler）。
///
/// 返回 `true` 表示确实存在并已移除。中断上下文中该 handler 可能正在执行，
/// 调用方须保证注销后不再依赖它（当前无动态卸载场景，仅供完整性提供）。
pub fn unregister_irq(irq: u8, handler: IrqHandler) -> bool {
    if irq >= 16 {
        return false;
    }
    let slot = &IRQ_HANDLERS[irq as usize];
    let ptr = handler as usize;
    for entry in slot {
        if entry.load(Ordering::Acquire) == ptr {
            entry.store(0, Ordering::Release);
            return true;
        }
    }
    false
}

/// 查询某 IRQ 已注册的 handler 数。
pub fn irq_handler_count(irq: u8) -> usize {
    if irq >= 16 {
        return 0;
    }
    IRQ_HANDLERS[irq as usize]
        .iter()
        .filter(|e| e.load(Ordering::Relaxed) != 0)
        .count()
}

// ---------- 嵌套控制与优先级（T7） ----------

/// IRQ 优先级范围：0（最低）~ 15（最高）。
pub const IRQ_PRIO_MIN: u8 = 0;
pub const IRQ_PRIO_MAX: u8 = 15;
/// 不在任何中断上下文时 `current_irq_priority()` 的返回值。
pub const IRQ_PRIO_NONE: u8 = 0xFF;

/// 每 IRQ 的软件优先级（默认 0 最低）。
///
/// 优先级决定嵌套关系：嵌套开启时，**更高优先级**的中断可以打断当前正在
/// 处理的中断；同优先级或更低优先级不可。中断上下文外读取安全（原子）。
static IRQ_PRIORITIES: [AtomicU8; 16] = [const { AtomicU8::new(IRQ_PRIO_MIN) }; 16];

/// 全局嵌套开关。默认关闭（与历史行为一致：中断门已自动关中断，处理期间
/// 不可被打断）；开启后高优先级中断可打断低优先级处理。
static NESTED_IRQ: AtomicBool = AtomicBool::new(false);

/// 当前正在处理的中断优先级（`IRQ_PRIO_NONE` = 不在中断上下文）。
///
/// 进入外部中断分发时原子替换为自身优先级，返回前恢复旧值。仅软件语义，
/// 用于嵌套判断（`prio > prev`）；单核下无需 per-CPU 数组。
static CURRENT_IRQ_PRIO: AtomicU8 = AtomicU8::new(IRQ_PRIO_NONE);

/// 设置某 IRQ 的优先级（0~15）。越界返回 `false`。
pub fn set_irq_priority(irq: u8, prio: u8) -> bool {
    if irq >= 16 || prio > IRQ_PRIO_MAX {
        return false;
    }
    IRQ_PRIORITIES[irq as usize].store(prio, Ordering::Relaxed);
    true
}

/// 查询某 IRQ 的优先级。越界返回 `IRQ_PRIO_MIN`。
pub fn irq_priority(irq: u8) -> u8 {
    if irq >= 16 {
        return IRQ_PRIO_MIN;
    }
    IRQ_PRIORITIES[irq as usize].load(Ordering::Relaxed)
}

/// 开启/关闭中断嵌套（默认关闭）。
///
/// 开启后，外部中断分发时若自身优先级高于当前处理中的中断优先级，会临时
/// 使能中断（`sti`）允许更高优先级打断，返回前恢复。优先级抑制仍然生效：
/// 更低/同级优先级的中断即使硬件到达，也不会在当前处理中嵌套（进入时中断
/// 门保持关中断）。
pub fn set_nested_irq(enabled: bool) {
    NESTED_IRQ.store(enabled, Ordering::Relaxed);
}

/// 当前嵌套开关状态。
pub fn nested_irq_enabled() -> bool {
    NESTED_IRQ.load(Ordering::Relaxed)
}

/// 当前正在处理的中断优先级；不在中断上下文返回 `IRQ_PRIO_NONE`（0xFF）。
pub fn current_irq_priority() -> u8 {
    CURRENT_IRQ_PRIO.load(Ordering::Relaxed)
}

/// 当前中断是否使能（读 RFLAGS.IF）。
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, nostack, preserves_flags),
        );
    }
    flags & (1 << 9) != 0
}

/// 页错误（#PF, 14 号异常）回调。
///
/// 参数为 (CR2 线性地址, 错误码)。返回 `true` 表示已处理（如按需补页后），
/// 继续执行；返回 `false` 表示未处理（内核态缺页/非法访问），保持原停机行为。
///
/// 由虚拟内存/进程子系统注册（M1.3 按需分页）。`arch` 层只提供钩子，
/// 不实现具体策略（ADR-007）。
pub type PageFaultHandler = extern "C" fn(u64, u64) -> bool;
static PAGE_FAULT_HANDLER: spin::Once<PageFaultHandler> = spin::Once::new();

/// 注册页错误处理回调。
pub fn register_page_fault_handler(h: PageFaultHandler) {
    let _ = PAGE_FAULT_HANDLER.call_once(|| h);
}

/// 软中断（vector 0x80）处理函数。
///
/// 由 `int 0x80`（用户态或内核态）触发进入。参数为进入时的中断帧
/// （含用户/内核的 RIP/CS/RFLAGS/RSP/SS）。返回 `true` 表示已处理并继续
/// （`iretq` 返回触发点）；`false` 表示未处理（保留停机行为）。
pub type SoftInterruptHandler = extern "C" fn(&mut InterruptFrame) -> bool;
static SOFT_INT_HANDLER: spin::Once<SoftInterruptHandler> = spin::Once::new();

/// 注册软中断（vector 0x80）处理回调。
pub fn register_soft_interrupt_handler(h: SoftInterruptHandler) {
    let _ = SOFT_INT_HANDLER.call_once(|| h);
}

/// 用户态异常（#PF/#GP/#UD 等，CPL=3）处理器。
///
/// 由进程层注册（M3.3）：当用户态进程触发异常时，不再当作内核崩溃停机，
/// 而是终止/回收该进程。处理器应不返回（停机或恢复调度）；若返回则兜底停机。
pub type UserExceptionHandler = extern "C" fn(&mut InterruptFrame);
static USER_EXCEPTION_HANDLER: spin::Once<UserExceptionHandler> = spin::Once::new();

/// 注册用户态异常处理器（M3.3）。
pub fn register_user_exception_handler(h: UserExceptionHandler) {
    let _ = USER_EXCEPTION_HANDLER.call_once(|| h);
}

/// 调度器 tick 回调（M4.2）：每次 LAPIC 定时器中断（IRQ0）后调用。
///
/// 由调度器注册（kernel 层）。回调持有 `&mut InterruptFrame`，可**整体改写**
/// 中断帧（寄存器 + iretq 帧）为另一进程的保存帧，并切换 CR3/TSS.RSP0；
/// `interrupt_common_stub` 返回后 iretq 即进入目标进程用户态。返回 void，
/// 若调度器未切换（无其他就绪进程），帧保持不变，原进程继续执行。
///
/// 仅在 BSP（CPU0）上调用（M4.2 单核调度模型）。
pub type SchedulerTickHandler = extern "C" fn(&mut InterruptFrame);
static SCHEDULER_TICK: AtomicUsize = AtomicUsize::new(0);

/// 注册调度器 tick 回调（M4.2）。用原子槽单次注册（与软中断 handler 同模式）。
pub fn register_scheduler_tick(h: SchedulerTickHandler) {
    SCHEDULER_TICK.store(h as usize, Ordering::SeqCst);
}

/// 分发入口（由汇编 `interrupt_common_stub` 调用）。
///
/// `frame` 指向保存的寄存器区。
#[unsafe(no_mangle)]
pub extern "C" fn interrupt_dispatch(frame: *mut InterruptFrame) {
    let frame = unsafe { &mut *frame };
    let vector = frame.vector;

    if vector < 32 {
        // CPU 异常：先关中断，避免嵌套
        disable();

        if vector == 14 {
            // 页错误：仅**用户态**缺页交给已注册的 #PF 回调（按需分页 / COW）。
            // 内核态 #PF（含 SMAP/SMEP 违规、访问未映射内核地址）一律视为致命
            // 错误，不交给用户态补页处理器——否则可能被 `cow_pages` 记账误命中
            // 或掩盖真实的防护触发（严格隔离下内核不应访问用户页 / 执行用户代码）。
            // 回调约定：`fn(cr2, error_code) -> bool`（虚拟地址在前，错误码在后）。
            let cr2 = crate::mmio::cr2();
            if frame.cs & 3 == 3 {
                if let Some(h) = PAGE_FAULT_HANDLER.get() {
                    if h(cr2, frame.error_code) {
                        return; // 已处理（如补页成功），返回用户态继续
                    }
                }
            }
        }

        // M3.3：若异常来自用户态（CS.RPL==3），交给进程层终止该进程，
        // 而非当作内核崩溃。处理器应不返回（停机/恢复调度）；返回则兜底停机。
        if frame.cs & 3 == 3 {
            if let Some(h) = USER_EXCEPTION_HANDLER.get() {
                h(frame);
                // 处理器返回了：兜底停机
                crate::halt_forever();
            }
        }

        // 内核态异常（或未注册用户态处理器）：打印并停机
        klib::info!("");
        klib::info!("========== CPU EXCEPTION ==========");
        klib::info!("exception: {}", exception_name(vector as u8));
        klib::info!("  vector: {:#x}", vector);
        klib::info!("  rip:    {:#x}", frame.rip);
        if vector == 14 {
            let cr2 = crate::mmio::cr2();
            // 未注册/未处理/内核态：打印 CR2 并停机
            klib::info!("  cr2:    {:#x}", cr2);
            klib::info!("  error:  P={:#x}", frame.error_code);
        }
        if vector == 8 {
            // Double Fault：打印错误码（0 表示外部中断/软件引起的 DF）
            klib::info!("  error:  {:#x}", frame.error_code);
            klib::info!("  (Double Fault - possible kernel stack overflow)");
        }
        klib::info!("==================================");
        crate::halt_forever();
    } else if vector == 0x80 {
        // 软中断：交给已注册的 handler（M2.5.4 进入用户态冒烟 / M3 syscall 雏形）。
        if let Some(h) = SOFT_INT_HANDLER.get() {
            if h(frame) {
                return; // 已处理，iretq 返回触发点
            }
        }
        klib::info!("========== UNHANDLED SOFT INTERRUPT (0x80) ==========");
        crate::halt_forever();
    } else {
        // 外部中断（32..47 → IRQ0..15）。共享中断：依次调用该 IRQ 的全部
        // handler，任一返回 `true` 即视为已处理并停止；全部未处理则 EOI。
        //
        // 嵌套与优先级（T7）：每 IRQ 一个软件优先级（0 最低 ~ 15 最高）。
        // - 嵌套关闭（默认）：中断门已自动关中断，处理期间不可被打断；
        // - 嵌套开启：若本 IRQ 优先级高于"当前正在处理的中断"优先级，则
        //   临时 `sti` 允许更高优先级中断打断（返回前 `cli` 并恢复状态）。
        //   否则保持关中断——更低/同级优先级的中断无法打断当前处理。
        // `CURRENT_IRQ_PRIO` 进入时原子替换、返回前恢复，供嵌套判断与
        // handler 内查询（`current_irq_priority`）。
        let irq = (vector - 32) as u8;
        let prio = irq_priority(irq);
        let prev = CURRENT_IRQ_PRIO.swap(prio, Ordering::Relaxed);
        let nested = NESTED_IRQ.load(Ordering::Relaxed) && prio > prev;
        if nested {
            enable();
        }
        let slot = &IRQ_HANDLERS[irq as usize];
        let mut handled = false;
        for entry in slot {
            let handler_ptr = entry.load(Ordering::Acquire);
            if handler_ptr == 0 {
                continue;
            }
            // 指针来自 register_irq 写入的合法 'static 函数地址，读回安全。
            let h = unsafe { core::mem::transmute::<usize, IrqHandler>(handler_ptr) };
            if h(irq) {
                handled = true;
                break;
            }
        }
        if nested {
            disable();
        }
        CURRENT_IRQ_PRIO.store(prev, Ordering::Relaxed);
        // 外部中断统一向 8259 发送 EOI，清除其 ISR 服务位——否则 8259 会持续
        // 屏蔽同 IRQ 的后续中断（键盘等只收到第一个字符）。LAPIC EOI 由各
        // handler 自行发送（见 `irq1_handler` 等）。无条件发送对走 LAPIC 自身
        // 定时器（irq0）等路径亦无害。
        crate::pic::end_of_interrupt(irq);
        // M4.2：IRQ0（LAPIC 定时器）之后调用调度器 tick，允许在中断帧上做
        // 进程切换（改写 frame → 返回时 iretq 到目标进程）。仅 BSP 调度。
        if irq == 0 {
            let f = SCHEDULER_TICK.load(Ordering::Acquire);
            if f != 0 {
                let h: SchedulerTickHandler =
                    unsafe { core::mem::transmute::<usize, SchedulerTickHandler>(f) };
                h(frame);
            }
        }
    }
}

// 加载 IDT。
unsafe extern "C" {
    fn x86_64_load_idt(idtr: *const Idtr);
}

/// 启用 FPU/SSE：清除 CR0.TS（Task Switched）。
///
/// bootloader（Limine）可能以 lazy-FPU 方式启动，CR0.TS=1。此时任何 x87/MMX/SSE
/// 指令都会触发 #NM（Device Not Available）异常。内核未实现 FPU 惰性切换，
/// 这里直接清除 TS，让浮点指令始终可用（单核下无需保存/恢复 FPU 状态）。
/// 同时置 MP（monitor coprocessor）与 NE（native error），规范 FPU 行为。
pub fn enable_fpu() {
    unsafe {
        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        // 清 TS(bit3)，置 MP(bit1) 与 NE(bit5)
        let new = (cr0 & !(1 << 3)) | (1 << 1) | (1 << 5);
        core::arch::asm!("mov cr0, {}", in(reg) new, options(nomem, nostack));
    }
}

/// 保存当前 RFLAGS（含 IF）并关中断，返回保存的旧 RFLAGS。
///
/// 注入给 [`klib::sync::irq::set_irq_guard`]，供中断安全锁保存/恢复中断状态。
#[inline]
pub fn irq_save() -> usize {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, nostack, preserves_flags),
        );
    }
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    flags as usize
}

/// 恢复此前保存的 RFLAGS（还原 IF 状态，可能重新打开中断）。
#[inline]
pub fn irq_restore(flags: usize) {
    unsafe {
        core::arch::asm!(
            "push {}",
            "popfq",
            in(reg) flags as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// 初始化 IDT：填充 0~47 号向量，然后加载。
pub fn init() {
    // 启用 FPU/SSE（清 CR0.TS），避免用户态/内核执行浮点指令时触发 #NM → 级联 #DF。
    enable_fpu();

    unsafe {
        let idt_ptr = &raw mut IDT as *mut Idt;

        // 0~31：异常，陷阱门。vector 8（Double Fault）使用独立 IST 栈，
        // 避免异常处理中再次异常导致 Triple Fault 重启。其余不用 IST（0）。
        for vector in 0..32u16 {
            let handler = get_isr_addr(vector);
            let ist = if vector == 8 { IST_DF as u8 } else { 0 };
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_TRAP, ist);
        }
        // 32~47：外部中断，中断门（不用 IST）
        for vector in 32..48u16 {
            let handler = get_isr_addr(vector);
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        }
        // 0x80：用户态软中断（M2.5.4 / M3 syscall 入口），DPL=3 陷阱门，
        // 用户态 `int 0x80` 可触发进入内核。
        let handler = get_isr_addr(0x80);
        (*idt_ptr).entries[0x80].set_handler(handler, IDT_FLAG_TRAP_USER, 0);

        let idtr = Idtr {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: idt_ptr as u64,
        };
        x86_64_load_idt(&idtr as *const Idtr);
    }
}

/// 获取第 `vector` 号中断入口的地址。
/// 汇编生成的符号名形如 `isr_0`、`isr_14`。
fn get_isr_addr(vector: u16) -> u64 {
    // 通过构建符号名无法在稳定 Rust 中反射，改用固定符号表。
    // 这里用 extern 声明并查表。
    unsafe extern "C" {
        fn isr_0();
        fn isr_1();
        fn isr_128();
        fn isr_2();
        fn isr_3();
        fn isr_4();
        fn isr_5();
        fn isr_6();
        fn isr_7();
        fn isr_8();
        fn isr_9();
        fn isr_10();
        fn isr_11();
        fn isr_12();
        fn isr_13();
        fn isr_14();
        fn isr_15();
        fn isr_16();
        fn isr_17();
        fn isr_18();
        fn isr_19();
        fn isr_20();
        fn isr_21();
        fn isr_22();
        fn isr_23();
        fn isr_24();
        fn isr_25();
        fn isr_26();
        fn isr_27();
        fn isr_28();
        fn isr_29();
        fn isr_30();
        fn isr_31();
        fn isr_32();
        fn isr_33();
        fn isr_34();
        fn isr_35();
        fn isr_36();
        fn isr_37();
        fn isr_38();
        fn isr_39();
        fn isr_40();
        fn isr_41();
        fn isr_42();
        fn isr_43();
        fn isr_44();
        fn isr_45();
        fn isr_46();
        fn isr_47();
    }

    const HANDLERS: [unsafe extern "C" fn(); 48] = [
        isr_0, isr_1, isr_2, isr_3, isr_4, isr_5, isr_6, isr_7, isr_8, isr_9,
        isr_10, isr_11, isr_12, isr_13, isr_14, isr_15, isr_16, isr_17, isr_18, isr_19,
        isr_20, isr_21, isr_22, isr_23, isr_24, isr_25, isr_26, isr_27, isr_28, isr_29,
        isr_30, isr_31, isr_32, isr_33, isr_34, isr_35, isr_36, isr_37, isr_38, isr_39,
        isr_40, isr_41, isr_42, isr_43, isr_44, isr_45, isr_46, isr_47,
    ];

    // 软中断向量 0x80 使用独立的 isr_128 入口。
    if vector == 0x80 {
        return isr_128 as *const () as usize as u64;
    }
    HANDLERS[vector as usize] as *const () as usize as u64
}

/// 使能中断。
pub fn enable() {
    unsafe { core::arch::asm!("sti") };
}

/// 禁用中断。
pub fn disable() {
    unsafe { core::arch::asm!("cli") };
}

/// CPU 停机（执行一条 `hlt`）。
#[inline]
pub fn halt() {
    unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
}

/// 永久停机：关中断后空转，永不返回。
///
/// 原实现是 `cli; hlt` 死循环。`hlt` 在关中断时会让 CPU 永久停在 HLT 状态，
/// QEMU 不再推进指令，导致 gdb 单步/continue 永远等待（死锁）。
/// 这里改为 `pause`（spin_loop）空转：占满 CPU 但持续执行，gdb 可随时打断，
/// 且此前由 `interrupt_dispatch` 打印的异常信息仍会先输出到串口。
pub fn halt_forever() -> ! {
    loop {
        disable();
        core::hint::spin_loop(); // pause
    }
}
