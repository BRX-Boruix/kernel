//! x86-64 COM1 串口实现（基于 port I/O）。
//!
//! 多核下用可重入自旋锁保护写操作，避免多个 CPU 并行写串口导致输出交错。
//! 锁设计：
//! - 基于"持有者 CPU（LAPIC id）+ 重入计数"实现同 CPU 可重入（中断嵌套安全）。
//! - 中断门会自动 `cli`，因此中断上下文与本 CPU 主线程的竞争靠重入计数化解；
//!   不同 CPU 之间靠自旋互斥。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use crate::port::{inb, outb};

const COM1: u16 = 0x3F8;

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

/// 初始化 COM1 串口（38400 波特，8N1）
pub fn init() {
    outb(COM1 + 1, 0x00); // 禁用中断
    outb(COM1 + 3, 0x80); // DLAB 开，设置波特率
    outb(COM1 + 0, 0x03); // 除数低字节 (38400)
    outb(COM1 + 1, 0x00); // 除数高字节
    outb(COM1 + 3, 0x03); // 8 位数据，无校验，1 停止位
    outb(COM1 + 2, 0xC7); // 启用 FIFO，清空
    outb(COM1 + 4, 0x0B); // IRQ 使能，RTS/DSR
}

/// 等待发送保持寄存器空（LSR bit 5），随后写一个字节。
#[inline]
fn putc_wait(byte: u8) {
    while inb(COM1 + 5) & 0x20 == 0 {}
    outb(COM1, byte);
}

/// 发送单个字节（带锁）。
pub fn write_byte(byte: u8) {
    LOCK.acquire();
    putc_wait(byte);
    LOCK.release();
}

/// 读取单个字节（无数据返回 None）。
pub fn read_byte() -> Option<u8> {
    // LSR bit 0 表示数据就绪
    if inb(COM1 + 5) & 0x01 != 0 {
        Some(inb(COM1))
    } else {
        None
    }
}

/// 直接写入一串字节到串口（\n 转 \r\n）。
pub fn write_str(s: &str) {
    LOCK.acquire();
    for &b in s.as_bytes() {
        if b == b'\n' {
            putc_wait(b'\r');
        }
        putc_wait(b);
    }
    LOCK.release();
}
