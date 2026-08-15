//! 中断描述符表（IDT）与异常/中断处理。
//!
//! - 覆盖 CPU 异常 0~31（除 16 号 FPU 错误外的通用兜底），以及外部中断 32~47。
//! - 通过手写汇编入口将 CPU 压栈的寄存器保存为 `InterruptFrame`，
//!   交给 Rust 端的 `dispatch` 分发。
//! - 支持注册外部中断处理函数（当前提供定时器 PIT 的中断）。

use core::arch::global_asm;

use crate::serial;

/// 内核代码段选择子（加载 IDT 描述符时使用）。
use crate::gdt::KCODE;

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

    fn set_handler(&mut self, handler: u64, flags: u8) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = KCODE;
        self.flags = flags;
        self.ist = 0;
    }
}

/// 中断门（从用户态不可访问）
const IDT_FLAG_INTERRUPT: u8 = 0x8E;
/// 陷阱门（从用户态不可访问）
const IDT_FLAG_TRAP: u8 = 0x8F;

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
        .byte 0x6a, 0          // push 0  (错误码占位)
        .byte 0x6a, \num       // push 中断号
        jmp interrupt_common_stub
    .endm

    // 生成异常入口（有错误码）：CPU 已压错误码，只需压中断号。
    .macro isr_err num
        .global isr_\num
        .type isr_\num, @function
    isr_\num:
        .byte 0x6a, \num       // push 中断号
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
#[repr(C)]
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

// ---------- 外部中断处理函数表 ----------

/// 外部中断处理函数（IRQ）。返回 `true` 表示已处理。
pub type IrqHandler = extern "C" fn(u8) -> bool;

static IRQ_HANDLERS: spin::Mutex<[Option<IrqHandler>; 16]> =
    spin::Mutex::new([None; 16]);

/// 注册外部中断（IRQ0~15）的处理函数。
pub fn register_irq(irq: u8, handler: IrqHandler) {
    if irq < 16 {
        IRQ_HANDLERS.lock()[irq as usize] = Some(handler);
    }
}

/// 分发入口（由汇编 `interrupt_common_stub` 调用）。
///
/// `frame` 指向保存的寄存器区。
#[unsafe(no_mangle)]
pub extern "C" fn interrupt_dispatch(frame: *mut InterruptFrame) {
    let frame = unsafe { &mut *frame };
    let vector = frame.vector;

    if vector < 32 {
        // CPU 异常：打印并停机
        // 先关中断，避免嵌套
        unsafe { core::arch::asm!("cli") };
        serial::write_str("\r\n");
        serial::write_str("========== CPU EXCEPTION ==========\r\n");
        serial::write_str("exception: ");
        serial::write_str(exception_name(vector as u8));
        serial::write_str("\r\n");
        // 打印关键信息
        serial::write_str("  vector: 0x");
        write_hex_u64(vector);
        serial::write_str("\r\n");
        serial::write_str("  rip:    0x");
        write_hex_u64(frame.rip);
        serial::write_str("\r\n");
        if vector == 14 {
            // 页错误：打印 CR2
            let cr2: u64;
            unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2) };
            serial::write_str("  cr2:    0x");
            write_hex_u64(cr2);
            serial::write_str("\r\n");
            serial::write_str("  error:  P=");
            write_hex_u64(frame.error_code);
            serial::write_str("\r\n");
        }
        serial::write_str("==================================\r\n");
        crate::halt_forever();
    } else {
        // 外部中断（32..47 → IRQ0..15）
        let irq = (vector - 32) as u8;
        let handled = IRQ_HANDLERS.lock()[irq as usize]
            .map(|h| h(irq))
            .unwrap_or(false);
        if !handled {
            // 未注册的 IRQ：直接 EOI
            crate::pic::end_of_interrupt(irq);
        }
    }
}

/// 把 u64 以十六进制写到串口。
pub fn write_hex_u64(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX[((value >> shift) & 0xF) as usize];
    }
    for &b in &buf {
        serial::write_byte(b);
    }
}

// 加载 IDT。
unsafe extern "C" {
    fn x86_64_load_idt(idtr: *const Idtr);
}

/// 初始化 IDT：填充 0~47 号向量，然后加载。
pub fn init() {
    unsafe {
        let idt_ptr = &raw mut IDT as *mut Idt;

        // 0~31：异常，陷阱门
        for vector in 0..32u16 {
            let handler = get_isr_addr(vector);
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_TRAP);
        }
        // 32~47：外部中断，中断门
        for vector in 32..48u16 {
            let handler = get_isr_addr(vector);
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_INTERRUPT);
        }

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

    HANDLERS[vector as usize] as usize as u64
}

/// 使能中断。
pub fn enable() {
    unsafe { core::arch::asm!("sti") };
}

/// 禁用中断。
pub fn disable() {
    unsafe { core::arch::asm!("cli") };
}
