//! Local APIC（本地高级可编程中断控制器）定时器。
//!
//! Limine 引导后 CPU 已启用 Local APIC，硬件中断走 APIC 而非 8259 PIC。
//! 因此用 LAPIC 定时器作为时钟源，比 PIT + 8259 更符合现代硬件路径。
//!
//! LAPIC 寄存器通过 MMIO 访问，物理基址通常为 0xFEE00000。
//! 该物理地址不在 Limine 的 HHDM RAM 映射内，需先用 `mmio::map_lapic`
//! 以 2MB 大页映射到高半区虚拟地址，再访问。

use crate::interrupts;
use crate::mmio;
use crate::serial;

use core::sync::atomic::{AtomicU64, Ordering};

/// LAPIC 物理基址。
const LAPIC_PHYS: u64 = 0xFEE0_0000;

/// LAPIC 映射到的虚拟地址（与 HHDM 同 PML4 表项，避免新建 PDPT）。
/// 0xffff8000_0000_0000 + 0xFEE0_0000 = 0xffff8000fee00000。
const LAPIC_VIRT: u64 = 0xffff_8000_0000_0000 | LAPIC_PHYS;

// LAPIC 寄存器偏移
const LAPIC_SVR: usize = 0xF0;      // Spurious Interrupt Vector
const LAPIC_TIMER: usize = 0x320;   // LVT Timer
const LAPIC_TIMER_DIV: usize = 0x3E0; // 分频
const LAPIC_TIMER_INIT: usize = 0x380; // Initial Count
const LAPIC_EOI: usize = 0xB0;      // End of Interrupt

// LVT Timer 位
const TIMER_PERIODIC: u32 = 0x0002_0000; // 周期性模式
// 定时器向量（指向 IDT 中的一个中断向量）
const TIMER_VECTOR: u32 = 0x20;

/// LAPIC ID 寄存器偏移。
const LAPIC_ID: usize = 0x20;

/// 全局 tick 计数。
static TICKS: AtomicU64 = AtomicU64::new(0);

/// 读取当前 CPU 的 LAPIC ID（0~255）。
pub fn current_lapic_id() -> u32 {
    lapic_read(LAPIC_ID) >> 24
}

/// 当前已运行的 tick 数。
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// 读取 LAPIC 寄存器（基于映射后的虚拟地址）。
#[inline]
fn lapic_read(reg: usize) -> u32 {
    let addr = (LAPIC_VIRT + reg as u64) as *const u32;
    // LAPIC 必须 16 字节对齐访问
    unsafe { core::ptr::read_volatile(addr) }
}

/// 写入 LAPIC 寄存器。
#[inline]
fn lapic_write(reg: usize, val: u32) {
    let addr = (LAPIC_VIRT + reg as u64) as *mut u32;
    unsafe { core::ptr::write_volatile(addr, val) };
}

/// 发送 EOI 给 LAPIC。
fn end_of_interrupt() {
    lapic_write(LAPIC_EOI, 0);
}

/// IRQ 处理函数（定时器）：递增 tick 并 EOI。
extern "C" fn lapic_timer_handler(_irq: u8) -> bool {
    let t = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if t <= 5 {
        serial::write_str("[lapic] tick\r\n");
    }
    end_of_interrupt();
    true
}

/// 初始化 Local APIC 定时器。
///
/// `phys_offset` 为 Limine 的 HHDM 偏移，用于映射 LAPIC MMIO。
/// `bus_freq` 为 LAPIC 总线频率（Hz），QEMU 下典型约 1GHz。
pub fn init(phys_offset: u64, bus_freq: u64) {
    // 0. 把 LAPIC 物理地址映射到高半区虚拟地址
    if !mmio::map_lapic(phys_offset, LAPIC_PHYS, LAPIC_VIRT) {
        serial::write_str("[lapic] map failed\r\n");
        return;
    }
    serial::write_str("[lapic] mapped to ");
    write_hex(LAPIC_VIRT);
    serial::write_str("\r\n");

    // 1. 使能 LAPIC（SVR，向量 0xFF）
    let svr = lapic_read(LAPIC_SVR);
    lapic_write(LAPIC_SVR, (svr & !0x100) | 0x100 | 0xFF);

    // 2. 配置定时器分频（divide by 1 → 0x0B）
    lapic_write(LAPIC_TIMER_DIV, 0x0B);

    // 3. 设置 LVT Timer：周期性，向量 0x20
    lapic_write(LAPIC_TIMER, TIMER_PERIODIC | TIMER_VECTOR);

    // 4. 设置初始计数：期望 100Hz
    let target_hz = 100u64;
    let init_count = bus_freq / target_hz;
    lapic_write(LAPIC_TIMER_INIT, init_count as u32);

    // 5. 注册 IRQ 处理（vector 0x20 → irq 0）
    interrupts::register_irq(0, lapic_timer_handler);

    // 标记 LAPIC 已可用（串口锁依赖 LAPIC id 做多核 owner 判断）
    serial::set_lapic_ready();

    serial::write_str("[lapic] LAPIC timer initialized\r\n");
}

/// 以十六进制写 u64 到串口（诊断用）。
fn write_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial::write_str("0x");
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX[((val >> shift) & 0xF) as usize];
    }
    for &b in &buf {
        serial::write_byte(b);
    }
}
