//! x86-64 COM1 串口实现（基于 port I/O）。
//!
//! 多核下用可重入自旋锁保护写操作，避免多个 CPU 并行写串口导致输出交错。
//! 锁设计：
//! - 基于"持有者 CPU（LAPIC id）+ 重入计数"实现同 CPU 可重入（中断嵌套安全）。
//! - 中断门会自动 `cli`，因此中断上下文与本 CPU 主线程的竞争靠重入计数化解；
//!   不同 CPU 之间靠自旋互斥。

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};

use crate::port::{inb, outb};

/// 保存当前中断状态并关中断（写串口期间禁用本 CPU 中断）。
///
/// 防止"主线程写串口被 IRQ0 打断 → 中断处理也写串口"的竞争导致主线程饿死：
/// 写串口全程关中断，中断上下文（已 cli）重入时保存/恢复不变，安全。
#[inline]
fn irq_save() -> u64 {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
        core::arch::asm!("cli", options(nomem, nostack));
    }
    flags
}

/// 恢复中断状态（`popfq` 恢复 RFLAGS，含 IF）。
#[inline]
fn irq_restore(flags: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) flags, options(nomem, nostack));
    }
}

/// 标准 COM 端口地址表（COM1~COM4）。
const COM_PORTS: [u16; 4] = [0x3F8, 0x2F8, 0x3E8, 0x2E8];

/// 当前使用的串口基址。默认 COM1，`init` 时探测后可能改为其他端口。
static COM_BASE: AtomicU16 = AtomicU16::new(0x3F8);

/// 串口锁：`LOCKED` 表示被某 CPU 占用，`OWNER` 记录占用者 LAPIC id，
/// `DEPTH` 记录同 CPU 重入深度。
static LOCKED: AtomicBool = AtomicBool::new(false);
static OWNER: AtomicU32 = AtomicU32::new(u32::MAX);
static DEPTH: AtomicU8 = AtomicU8::new(0);

/// LAPIC 是否已可用（多核启用后为 true）。早期为 false，此时单核无竞争，
/// 串口锁退化为穿行（owner 用 0，重入计数恒为 1，避免读未映射的 LAPIC）。
static LAPIC_READY: AtomicBool = AtomicBool::new(false);

/// 标记 LAPIC 已可用（由 lapic 初始化后调用）。
pub fn set_lapic_ready() {
    LAPIC_READY.store(true, Ordering::SeqCst);
}

/// 安全地获取当前 CPU id：LAPIC 可用时读 LAPIC id，否则返回 0。
#[inline]
fn safe_cpu_id() -> u32 {
    if LAPIC_READY.load(Ordering::Relaxed) {
        crate::lapic::current_lapic_id()
    } else {
        0
    }
}

struct SerialLock;

impl SerialLock {
    /// 获取串口锁。可重入。
    fn acquire(&self) {
        let cpu = safe_cpu_id();
        loop {
            // 同 CPU 重入
            if OWNER.load(Ordering::SeqCst) == cpu {
                DEPTH.fetch_add(1, Ordering::SeqCst);
                return;
            }
            // 尝试抢占
            if !LOCKED.swap(true, Ordering::SeqCst) {
                OWNER.store(cpu, Ordering::SeqCst);
                DEPTH.store(1, Ordering::SeqCst);
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// 释放串口锁（递减重入计数，归零才真正释放）。
    fn release(&self) {
        if DEPTH.fetch_sub(1, Ordering::SeqCst) == 1 {
            OWNER.store(u32::MAX, Ordering::SeqCst);
            LOCKED.store(false, Ordering::SeqCst);
        }
    }
}

static LOCK: SerialLock = SerialLock;

/// 初始化串口（38400 波特，8N1）。
///
/// 探测 COM1~COM4，选择第一个存在的串口，避免真机上 COM1 不存在（例如
/// 固件把串口映射到其他端口）时输出到空端口行为未定义。
pub fn init() {
    let base = probe_serial();
    COM_BASE.store(base, Ordering::Relaxed);

    let com = COM_BASE.load(Ordering::Relaxed);
    outb(com + 1, 0x00); // 禁用中断
    outb(com + 3, 0x80); // DLAB 开，设置波特率
    outb(com + 0, 0x03); // 除数低字节 (38400)
    outb(com + 1, 0x00); // 除数高字节
    outb(com + 3, 0x03); // 8 位数据，无校验，1 停止位
    outb(com + 2, 0xC7); // 启用 FIFO，清空
    outb(com + 4, 0x0B); // IRQ 使能，RTS/DSR
}

/// 探测可用的串口，返回其基址。找不到则回退 COM1。
///
/// 经典探测法：写 0xAE 到 SCR（scratch 寄存器，偏移 7），若可读回 0xAE
/// 说明端口存在；否则写 0x56 再试（部分实现只支持低 7 位）。
fn probe_serial() -> u16 {
    for &base in &COM_PORTS {
        // 用 SCR 寄存器回读检测端口存在性
        outb(base + 7, 0xAE);
        let mut ok = inb(base + 7) == 0xAE;
        if !ok {
            // 某些 UART 只保留低 7 位
            outb(base + 7, 0x56);
            ok = inb(base + 7) == 0x56;
        }
        if ok {
            return base;
        }
    }
    // 未探测到任何串口，回退 COM1（尽力而为）
    COM_PORTS[0]
}

/// 当前串口基址。
#[inline]
fn com_base() -> u16 {
    COM_BASE.load(Ordering::Relaxed)
}

/// 等待发送保持寄存器空（LSR bit 5），随后写一个字节。
#[inline]
fn putc_wait(byte: u8) {
    let com = com_base();
    while inb(com + 5) & 0x20 == 0 {}
    outb(com, byte);
}

/// 发送单个字节（带锁 + 关中断，防中断上下文重入死锁）。
pub fn write_byte(byte: u8) {
    let saved = irq_save();
    LOCK.acquire();
    putc_wait(byte);
    LOCK.release();
    irq_restore(saved);
}

/// 读取单个字节（无数据返回 None）。
pub fn read_byte() -> Option<u8> {
    let com = com_base();
    // LSR bit 0 表示数据就绪
    if inb(com + 5) & 0x01 != 0 {
        Some(inb(com))
    } else {
        None
    }
}

/// 直接写入一串字节到串口（\n 转 \r\n）。带锁 + 关中断。
pub fn write_str(s: &str) {
    let saved = irq_save();
    LOCK.acquire();
    for &b in s.as_bytes() {
        if b == b'\n' {
            putc_wait(b'\r');
        }
        putc_wait(b);
    }
    LOCK.release();
    irq_restore(saved);
}

/// 串口控制台：`klib::console::Console` 的实现（统一 console 的串口 sink）。
pub struct SerialConsole;

/// 全局串口控制台实例（供 `klib::console::register_console` 注册）。
pub static SERIAL_CONSOLE: SerialConsole = SerialConsole;

impl klib::console::Console for SerialConsole {
    fn name(&self) -> &'static str {
        "serial"
    }
    fn write_str(&self, s: &str) {
        crate::serial::write_str(s);
    }
    fn write_byte(&self, b: u8) {
        crate::serial::write_byte(b);
    }
    fn flush(&self) {}
}
