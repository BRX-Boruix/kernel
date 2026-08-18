//! PS/2 8042 键盘驱动（阶段 B）。
//!
//! - 初始化 8042 控制器（端口 0x60/0x64），请求并等待键盘自检、开扫描；
//! - 注册 IRQ1 中断 handler（vector 33 → irq 1）：读扫描码 → 译码为 ASCII →
//!   压入输入环形缓冲；
//! - 供内核 `read` syscall（stdin=0）从缓冲取字节；
//! - 支持 Shift 组合（普通/上档两套键位映射）。
//!
//! 外部中断路由：QEMU APIC 模式下由 IOAPIC 把 IRQ1 送到 vector 33；本驱动
//! 假设中断已使能（由 `ioapic::enable_keyboard_irq` 完成），handler 自行 EOI。

use crate::interrupts;
use crate::port::{inb, outb};

// 8042 端口
const DATA_PORT: u16 = 0x60; // 数据端口（读写键盘数据）
const CMD_PORT: u16 = 0x64; // 命令/状态端口

// 8042 命令
const CMD_READ_CTRL: u8 = 0x20; // 读控制器配置字节
const CMD_WRITE_CTRL: u8 = 0x60; // 写控制器配置字节
const CMD_SELF_TEST: u8 = 0xAA; // 自检

// 键盘命令（写到数据端口）
const KB_CMD_ACK: u8 = 0xFA;
const KB_ENABLE_SCAN: u8 = 0xF4; // 开扫描（键盘响应 ACK 后开始）

// 控制器配置字节位
const CFG_IRQ_ENABLE: u8 = 0x01; // bit0：键盘 IRQ1 使能
const CFG_TRANSLATE: u8 = 0x40; // bit6：扫描码集 1 翻译

// 状态寄存器位
const STATUS_OUTPUT_FULL: u8 = 0x01; // 输出缓冲满（可读数据）
const STATUS_INPUT_FULL: u8 = 0x02; // 输入缓冲满（忙）
const STATUS_SELF_TEST_OK: u8 = 0x04; // 自检通过

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// 简单 SPSC 环形缓冲（写入=IRQ1 中断，读取=syscall）。
const BUF_CAP: usize = 128;
static WRITE_INDEX: AtomicUsize = AtomicUsize::new(0);
static READ_INDEX: AtomicUsize = AtomicUsize::new(0);
static BUF_DATA: [AtomicU32; BUF_CAP] = [const { AtomicU32::new(0) }; BUF_CAP];
/// 缓冲是否已初始化（首次键盘输入前 false，read 检查）。
static BUF_INIT: AtomicU32 = AtomicU32::new(0);

/// Shift 是否按住。
static SHIFT: AtomicU32 = AtomicU32::new(0);

// ---------- 内部 8042 操作 ----------

/// 等待输入缓冲空（可写命令/数据），超时返回 false。
fn wait_input_empty() -> bool {
    for _ in 0..100_000 {
        if inb(CMD_PORT) & STATUS_INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 等待输出缓冲满（有数据可读），超时返回 false。
fn wait_output_full() -> bool {
    for _ in 0..100_000 {
        if inb(CMD_PORT) & STATUS_OUTPUT_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 读 8042 配置字节。
fn read_cfg() -> u8 {
    outb(CMD_PORT, CMD_READ_CTRL);
    wait_output_full();
    inb(DATA_PORT)
}

/// 写 8042 配置字节。
fn write_cfg(cfg: u8) {
    wait_input_empty();
    outb(CMD_PORT, CMD_WRITE_CTRL);
    wait_input_empty();
    outb(DATA_PORT, cfg);
}

// ---------- 扫描码译码 ----------

/// 扫描码 → ASCII（无 Shift 时）。索引 = 扫描码（Set 1，~0x01..=0x58）。
const KEYMAP: [u8; 0x80] = {
    let mut m = [0u8; 0x80];
    m[0x01] = 27; // Esc
    m[0x02] = b'1'; m[0x03] = b'2'; m[0x04] = b'3'; m[0x05] = b'4'; m[0x06] = b'5';
    m[0x07] = b'6'; m[0x08] = b'7'; m[0x09] = b'8'; m[0x0A] = b'9'; m[0x0B] = b'0';
    m[0x0C] = b'-'; m[0x0D] = b'='; m[0x0E] = 0x7F; // backspace
    m[0x0F] = b'\t';
    m[0x10] = b'q'; m[0x11] = b'w'; m[0x12] = b'e'; m[0x13] = b'r'; m[0x14] = b't';
    m[0x15] = b'y'; m[0x16] = b'u'; m[0x17] = b'i'; m[0x18] = b'o'; m[0x19] = b'p';
    m[0x1A] = b'['; m[0x1B] = b']'; m[0x1C] = b'\n';
    m[0x1E] = b'a'; m[0x1F] = b's'; m[0x20] = b'd'; m[0x21] = b'f'; m[0x22] = b'g';
    m[0x23] = b'h'; m[0x24] = b'j'; m[0x25] = b'k'; m[0x26] = b'l'; m[0x27] = b';';
    m[0x28] = b'\''; m[0x29] = b'`';
    m[0x2B] = b'\\';
    m[0x2C] = b'z'; m[0x2D] = b'x'; m[0x2E] = b'c'; m[0x2F] = b'v'; m[0x30] = b'b';
    m[0x31] = b'n'; m[0x32] = b'm'; m[0x33] = b','; m[0x34] = b'.'; m[0x35] = b'/';
    m[0x39] = b' ';
    m
};

/// 扫描码 → ASCII（Shift 按住时）。
const KEYMAP_SHIFT: [u8; 0x80] = {
    let mut m = [0u8; 0x80];
    m[0x02] = b'!'; m[0x03] = b'@'; m[0x04] = b'#'; m[0x05] = b'$'; m[0x06] = b'%';
    m[0x07] = b'^'; m[0x08] = b'&'; m[0x09] = b'*'; m[0x0A] = b'('; m[0x0B] = b')';
    m[0x0C] = b'_'; m[0x0D] = b'+';
    m[0x10] = b'Q'; m[0x11] = b'W'; m[0x12] = b'E'; m[0x13] = b'R'; m[0x14] = b'T';
    m[0x15] = b'Y'; m[0x16] = b'U'; m[0x17] = b'I'; m[0x18] = b'O'; m[0x19] = b'P';
    m[0x1A] = b'{'; m[0x1B] = b'}';
    m[0x1E] = b'A'; m[0x1F] = b'S'; m[0x20] = b'D'; m[0x21] = b'F'; m[0x22] = b'G';
    m[0x23] = b'H'; m[0x24] = b'J'; m[0x25] = b'K'; m[0x26] = b'L'; m[0x27] = b':';
    m[0x28] = b'"'; m[0x29] = b'~';
    m[0x2B] = b'|';
    m[0x2C] = b'Z'; m[0x2D] = b'X'; m[0x2E] = b'C'; m[0x2F] = b'V'; m[0x30] = b'B';
    m[0x31] = b'N'; m[0x32] = b'M'; m[0x33] = b'<'; m[0x34] = b'>'; m[0x35] = b'?';
    m
};

/// Shift 键扫描码（左/右）。
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;

// ---------- 输入缓冲 ----------

/// 键盘有输入时通知等待方（如阻塞的 read）的回调。由内核在启动时通过
/// `set_input_callback` 注册（指向 `scheduler::wake_kbd`）。arch 层不反向依赖
/// kernel，故用函数指针解耦。
static mut INPUT_CB: Option<fn()> = None;

/// 注册键盘输入回调（内核启动时调用一次）。
pub fn set_input_callback(cb: fn()) {
    // SAFETY: 早期单线程注册，之后仅只读访问。
    unsafe {
        INPUT_CB = Some(cb);
    }
}

/// 通知等待方：有字符入缓冲（中断上下文调用）。
fn notify_input() {
    // SAFETY: 回调只读，且已注册。
    unsafe {
        if let Some(cb) = INPUT_CB {
            cb();
        }
    }
}

/// 压入一个字符到缓冲（IRQ1 中断上下文调用）。
fn push(ch: u8) {
    let w = WRITE_INDEX.load(Ordering::Relaxed);
    let r = READ_INDEX.load(Ordering::Relaxed);
    if w.wrapping_sub(r) >= BUF_CAP {
        return; // 满，丢弃（避免覆盖未读）
    }
    BUF_DATA[w % BUF_CAP].store(ch as u32, Ordering::Relaxed);
    WRITE_INDEX.store(w + 1, Ordering::Release);
    BUF_INIT.store(1, Ordering::Release);
    notify_input(); // 唤醒阻塞在 read 的进程
}

/// 弹出一个字符（read syscall 调用）。无数据返回 None。
pub fn pop() -> Option<u8> {
    if BUF_INIT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let r = READ_INDEX.load(Ordering::Relaxed);
    let w = WRITE_INDEX.load(Ordering::Acquire);
    if r == w {
        return None;
    }
    let ch = BUF_DATA[r % BUF_CAP].load(Ordering::Relaxed) as u8;
    READ_INDEX.store(r + 1, Ordering::Release);
    Some(ch)
}

/// 缓冲是否非空。
pub fn has_input() -> bool {
    READ_INDEX.load(Ordering::Relaxed) != WRITE_INDEX.load(Ordering::Acquire)
}

// ---------- IRQ1 中断 handler ----------

/// IRQ1 键盘中断：读扫描码、处理 Shift、译码 ASCII、压入缓冲。
pub extern "C" fn irq1_handler(_irq: u8) -> bool {
    // 读数据端口（清中断挂起）。
    let scancode = inb(DATA_PORT);
    let key_up = scancode & 0x80 != 0; // bit7=1 表示释放
    let code = scancode & 0x7F;

    if code == SC_LSHIFT || code == SC_RSHIFT {
        SHIFT.store(if key_up { 0 } else { 1 }, Ordering::Relaxed);
    } else if !key_up && code < 0x80 {
        // 按下且非特殊：译码 ASCII 压入缓冲
        let shift = SHIFT.load(Ordering::Relaxed) != 0;
        let idx = code as usize;
        let ch = if shift { KEYMAP_SHIFT[idx] } else { KEYMAP[idx] };
        if ch != 0 {
            push(ch);
        }
    }

    // 键盘 IRQ 属于外部中断：发送 LAPIC EOI。
    crate::lapic::end_of_interrupt();
    true
}

// ---------- 初始化 ----------

/// 初始化 PS/2 8042 键盘并注册 IRQ1 handler。
///
/// 返回是否成功（键盘自检通过）。须在中断已配置（IDT 加载）、外部中断
/// 路由就绪后调用。
pub fn init() -> bool {
    // 1. 8042 自检。
    wait_input_empty();
    outb(CMD_PORT, CMD_SELF_TEST);
    // 自检结果会写到输出缓冲：0x55 表示通过。
    wait_output_full();
    let test = inb(DATA_PORT);
    if test != 0x55 {
        klib::info!("[kbd] 8042 self-test failed (0x{:02x})", test);
        return false;
    }

    // 2. 使能键盘 IRQ + 扫描码翻译（Set 1 翻译）。
    let mut cfg = read_cfg();
    cfg |= CFG_IRQ_ENABLE | CFG_TRANSLATE;
    write_cfg(cfg);

    // 3. 发送"开扫描"命令，等待 ACK。
    if wait_input_empty() {
        outb(DATA_PORT, KB_ENABLE_SCAN);
        // 等 ACK（0xFA）；可能需先清多余输出。
        let ack = if wait_output_full() { inb(DATA_PORT) } else { 0 };
        if ack != KB_CMD_ACK {
            klib::info!("[kbd] enable-scan ack mismatch (0x{:02x})", ack);
        }
    }

    // 4. 注册 IRQ1 handler。
    let ok = interrupts::register_irq(1, irq1_handler);
    if ok {
        klib::info!("[kbd] PS/2 keyboard initialized (IRQ1)");
    } else {
        klib::info!("[kbd] failed to register IRQ1 handler");
    }
    ok
}
