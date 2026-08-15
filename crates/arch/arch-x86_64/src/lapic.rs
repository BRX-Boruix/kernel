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
use crate::port::{inb, outb};
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
const LAPIC_TIMER_CURR: usize = 0x390; // Current Count (只读)
const LAPIC_EOI: usize = 0xB0;      // End of Interrupt

// LVT Timer 位
const TIMER_PERIODIC: u32 = 0x0002_0000; // 周期性模式
// 定时器向量（指向 IDT 中的一个中断向量）
const TIMER_VECTOR: u32 = 0x20;

/// LAPIC ID 寄存器偏移。
const LAPIC_ID: usize = 0x20;

/// 默认 LAPIC 总线频率（Hz）。
///
/// 仅在校准失败（PIT 不可用等）时作为回退值。正常路径会通过
/// `calibrate_bus_freq` 用 PIT 实测，不再依赖此硬编码。
pub const DEFAULT_BUS_FREQ_HZ: u64 = 1_000_000_000;

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
    // LAPIC 必须 16 字节对齐访问
    unsafe { mmio::read_u32(LAPIC_VIRT + reg as u64) }
}

/// 写入 LAPIC 寄存器。
#[inline]
fn lapic_write(reg: usize, val: u32) {
    unsafe { mmio::write_u32(LAPIC_VIRT + reg as u64, val) };
}

/// 对 LAPIC 寄存器做"读-改-写"：清除 `clear_bits`，置位 `set_bits`。
#[inline]
fn lapic_rmw(reg: usize, clear_bits: u32, set_bits: u32) {
    let v = lapic_read(reg);
    lapic_write(reg, (v & !clear_bits) | set_bits);
}

/// 发送 EOI 给 LAPIC。
fn end_of_interrupt() {
    lapic_write(LAPIC_EOI, 0);
}

/// IRQ 处理函数（定时器）：递增 tick 并 EOI。
extern "C" fn lapic_timer_handler(_irq: u8) -> bool {
    let t = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if t <= 5 {
        klib::logln!("[lapic] tick");
    }
    end_of_interrupt();
    true
}

/// 用 PIT 校准 LAPIC 总线频率。
///
/// 原理：PIT 通道 0 的计数频率恒为 1.193182MHz。把 PIT 设为一次性模式
/// （mode 0）并给定一个计数值（对应一段已知时长），同时让 LAPIC 定时器
/// 以分频 1、最大初值跑一个一次性周期。等 PIT 计时结束，读取 LAPIC 已
/// 递减的 tick 数，即可推出总线频率。
///
/// 真实硬件的 LAPIC 总线频率随 CPU 不同（通常 100MHz~400MHz，QEMU 约
/// 1GHz），必须实测而不能硬编码。返回 0 表示校准失败。
fn calibrate_bus_freq() -> u64 {
    const PIT_CH0_DATA: u16 = 0x40; // PIT 通道 0 数据端口
    const PIT_CMD: u16 = 0x43;      // PIT 命令/控制字端口
    const PIT_PORT_B: u16 = 0x61;   // 0x61：bit4 反映通道 0 输出（反相）
    const PIT_FREQ: u64 = 1_193_182; // PIT 计数频率（Hz）
    const PIT_TICKS: u16 = 0xFFFF;   // 最大计数值，约 54.9ms

    // PIT 通道 0：一次性模式 (mode 0)，先低后高字节，二进制计数。
    outb(PIT_CMD, 0x30);
    outb(PIT_CH0_DATA, (PIT_TICKS & 0xFF) as u8);
    outb(PIT_CH0_DATA, (PIT_TICKS >> 8) as u8);

    // LAPIC 定时器：一次性模式（清掉周期性位），分频 1，最大初值。
    lapic_write(LAPIC_TIMER, TIMER_VECTOR);
    lapic_write(LAPIC_TIMER_DIV, 0x0B);
    lapic_write(LAPIC_TIMER_INIT, 0xFFFF_FFFF);

    // 等待 PIT 计时结束：mode 0 下 OUT 从低变高，而 0x61 的 bit4 反相，
    // 故 bit4=1（输出低）时继续等，直到 bit4 变 0（输出高）。
    while (inb(PIT_PORT_B) & 0x10) != 0 {
        core::hint::spin_loop();
    }

    // 读取 LAPIC 剩余计数，算出本周期内递减的 tick 数。
    let remaining = lapic_read(LAPIC_TIMER_CURR);
    let elapsed = 0xFFFF_FFFFu64 - remaining as u64;

    // elapsed 次递减发生在 PIT_TICKS / PIT_FREQ 秒内，
    // 故 总线频率 = elapsed * PIT_FREQ / PIT_TICKS。
    elapsed * PIT_FREQ / PIT_TICKS as u64
}

/// 初始化 Local APIC 定时器（周期模式，100Hz）。
///
/// 总线频率通过 `calibrate_bus_freq` 用 PIT 实测，仅在失败时回退到
/// `DEFAULT_BUS_FREQ_HZ`。
pub fn init() {
    // 0. 把 LAPIC 物理地址映射到高半区虚拟地址
    if !mmio::map_lapic(LAPIC_PHYS, LAPIC_VIRT) {
        klib::logln!("[lapic] map failed");
        return;
    }
    klib::log_hex!("[lapic] mapped to ", LAPIC_VIRT);

    // 1. 使能 LAPIC（SVR，向量 0xFF）
    lapic_rmw(LAPIC_SVR, 0x100, 0x100 | 0xFF);

    // 2. 校准 LAPIC 总线频率（用 PIT 实测，而非硬编码）
    let bus_freq = calibrate_bus_freq();
    let bus_freq = if bus_freq == 0 {
        klib::logln!(
            "[lapic] WARNING: PIT calibration failed, falling back to {} Hz",
            DEFAULT_BUS_FREQ_HZ
        );
        DEFAULT_BUS_FREQ_HZ
    } else {
        klib::logln!("[lapic] calibrated LAPIC bus freq = {} Hz", bus_freq);
        bus_freq
    };

    // 3. 配置定时器分频（divide by 1 → 0x0B）
    lapic_write(LAPIC_TIMER_DIV, 0x0B);

    // 4. 设置 LVT Timer：周期性，向量 0x20
    lapic_write(LAPIC_TIMER, TIMER_PERIODIC | TIMER_VECTOR);

    // 5. 设置初始计数：期望 100Hz
    let target_hz = 100u64;
    let init_count = bus_freq / target_hz;
    lapic_write(LAPIC_TIMER_INIT, init_count as u32);

    // 6. 注册 IRQ 处理（vector 0x20 → irq 0）
    interrupts::register_irq(0, lapic_timer_handler);

    // 标记 LAPIC 已可用（串口锁依赖 LAPIC id 做多核 owner 判断）
    serial::set_lapic_ready();

    klib::logln!("[lapic] LAPIC timer initialized");
}
