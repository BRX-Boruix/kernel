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
use crate::smp;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 默认 LAPIC 物理基址（回退值，绝大多数 x86 平台使用 0xFEE00000）。
///
/// 实际基址通过 MSR `IA32_APIC_BASE` 读取，仅在读取失败时回退此值。
/// AMD 及部分特殊平台可能不同，故不能仅依赖硬编码。
const DEFAULT_LAPIC_PHYS: u64 = 0xFEE0_0000;

/// IA32_APIC_BASE MSR：bit 12 启用 APIC，低 12 位之上为 LAPIC 物理基址。
const MSR_APIC_BASE: u32 = 0x1B;

/// IA32_APIC_BASE bit 11：APIC 全局使能（SDM Vol3 §10.4.3）。
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// IA32_APIC_BASE bit 10：x2APIC 使能（SDM Vol3 §10.4.3）。
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// x2APIC MSR 编号 = 0x800 + 寄存器偏移/16（SDM Vol3 §10.12.1.2）。
const X2APIC_MSR_BASE: u32 = 0x800;
/// x2APIC ICR：单次 64 位写，目标 id 在高 32 位（SDM Vol3 §10.12.9）。
const X2APIC_MSR_ICR: u32 = 0x830;

/// LAPIC 访问模式：true = x2APIC（MSR），false = xAPIC（MMIO）。
///
/// 由 [`init`] 依据 Limine SMP 响应 `flags` bit0 置位——该位由引导器声明
/// （brxlimine-rs lib.rs 552："Bit 0: X2APIC has been enabled"）。全体核共享
/// 同一模式：x2APIC 下 0xFEE00000 的 MMIO 窗口不再代表 LAPIC。
static X2APIC: AtomicBool = AtomicBool::new(false);

/// 设置 LAPIC 访问模式（供 [`init`] 依引导器声明调用）。
pub fn set_x2apic(on: bool) {
    X2APIC.store(on, Ordering::Release);
}

/// 当前是否处于 x2APIC 模式。
pub fn is_x2apic() -> bool {
    X2APIC.load(Ordering::Acquire)
}

/// 读 MSR（本地辅助，与 syscall/gdt 同款内联写法）。
fn msr_read(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// 写 MSR。
fn msr_write(msr: u32, v: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") v as u32,
            in("edx") (v >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// 读取 IA32_APIC_BASE MSR，返回 LAPIC 物理基址。
///
/// 通过 `rdmsr` 读取。返回值低 12 位被清除，得到 4KB 对齐的基址。
fn read_apic_base() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_APIC_BASE,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// 当前 LAPIC 映射到的虚拟地址（物理基址 + 高半区偏移）。
/// 由 `init` 在读取 MSR 后写入，读写函数每次读取当前值。
static LAPIC_VIRT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// LAPIC 寄存器偏移
const LAPIC_SVR: usize = 0xF0; // Spurious Interrupt Vector
/// SVR 的 APIC 软件使能位（bit 8）。
const SVR_APIC_ENABLE: u32 = 1 << 8;
/// 伪中断向量：与 IDT 表项/分发端共用 [`interrupts::SPURIOUS_VECTOR`] 单点定义。
const SPURIOUS_VECTOR_SVR: u32 = interrupts::SPURIOUS_VECTOR as u32;
const LAPIC_TIMER: usize = 0x320; // LVT Timer
const LAPIC_TIMER_DIV: usize = 0x3E0; // 分频
const LAPIC_TIMER_INIT: usize = 0x380; // Initial Count
const LAPIC_TIMER_CURR: usize = 0x390; // Current Count (只读)
const LAPIC_EOI: usize = 0xB0; // End of Interrupt
const LAPIC_LINT0: usize = 0x350; // LVT LINT0 寄存器
const LINT0_EXTINT: u32 = 0x0000_0700; // delivery=ExtINT(111), unmasked

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

/// **per-CPU** tick 计数，按紧凑 CPU 槽位（0..n，见 smp.rs）索引。
///
/// 阶段 1（多核地基）：LAPIC 定时器是每核一份硬件资源——BSP 与每个 AP 都运行
/// 自己的周期定时器（100Hz），各自把自己的槽位计数 +1。若所有核共用单一计数，
/// 各核定时器叠加会让时钟以 N 倍速走（每 10ms 加 N 次）。改为每核一份后：
/// - [ticks]（读本核槽位）用于观察/测试这一核的 tick 推进；
/// - [system_ticks]（恒读槽 0 = BSP）作为全局单调时钟的兜底源——只有 BSP
///   定时器写槽 0，AP 定时器写槽 1..N，故槽 0 计数不被多核叠加，墙钟不加速。
///
/// 容量 256 = LAPIC id 全空间（与 smp.rs 的槽位映射表同源）。
const TICKS_SLOTS: usize = 256;
static TICKS: [AtomicU64; TICKS_SLOTS] = [const { AtomicU64::new(0) }; TICKS_SLOTS];

/// 读取当前 CPU 的 LAPIC ID（0~255）。
pub fn current_lapic_id() -> u32 {
    if is_x2apic() {
        return lapic_read(LAPIC_ID); // x2APIC：32 位完整 id（SDM §10.12.5）
    }
    lapic_read(LAPIC_ID) >> 24
}

/// 当前 CPU 的紧凑槽位。LAPIC 未映射或映射缺失时回退 0（BSP 槽）。
/// 启动早期（LAPIC 映射建立前）只有 BSP 在跑，回退 0 语义正确。
///
/// `pub` 供 SMP 的 TLB shootdown 会合使用（需要知道「本核是谁」以排除自投递）。
///
/// **S6**：LAPIC 已映射但槽位未登记时回退 0（同上，此时刻仍只有 BSP 在跑），
/// 但**必须是显式分支**——若放任 `slot_of_lapic` 的隐式回退，调用方无法区分
/// 「我确定是 BSP」与「我不知道我是谁」，而后者会让 shootdown 误把本核排除
/// 在会合之外（本核的 TLB 不被失效 → 用旧映射访问已回收帧）。
pub fn my_slot() -> usize {
    if !is_mapped() {
        return 0;
    }
    match smp::slot_of_lapic_checked(current_lapic_id()) {
        Some(slot) => slot & 0xFF,
        None => {
            klib::debug!(
                "[lapic] slot not registered yet for LAPIC {:#x}, assuming BSP slot 0",
                current_lapic_id()
            );
            0
        }
    }
}

/// 本核（当前 CPU）已运行的 tick 数。多核下读的是当前核自己的定时器计数。
pub fn ticks() -> u64 {
    TICKS[my_slot()].load(Ordering::Relaxed)
}

/// 系统单调 tick（恒读 BSP/槽 0）。多核下只有 BSP 定时器写槽 0，故该计数
/// 不被各 AP 定时器叠加——用作无 HPET 时全局单调时钟的兜底源（不加速、单调）。
pub fn system_ticks() -> u64 {
    TICKS[0].load(Ordering::Relaxed)
}

/// LAPIC 是否已映射（init 成功写入 LAPIC_VIRT 后为 true）。
///
/// 供 panic 等场景安全读取 CPU id：未映射时调用 `current_lapic_id` 会访问
/// 虚拟地址 0 附近触发二次页错误，需先经此检查。
pub fn is_mapped() -> bool {
    is_x2apic() || LAPIC_VIRT.load(Ordering::Relaxed) != 0
}

/// 读取 LAPIC 寄存器（基于映射后的虚拟地址）。
#[inline]
fn lapic_read(reg: usize) -> u32 {
    if is_x2apic() {
        return msr_read(X2APIC_MSR_BASE + (reg as u32 >> 4)) as u32;
    }
    // LAPIC 必须 16 字节对齐访问
    let virt = LAPIC_VIRT.load(Ordering::Relaxed);
    unsafe { mmio::read_u32(virt + reg as u64) }
}

/// 写入 LAPIC 寄存器。
#[inline]
fn lapic_write(reg: usize, val: u32) {
    if is_x2apic() {
        msr_write(X2APIC_MSR_BASE + (reg as u32 >> 4), val as u64);
        return;
    }
    let virt = LAPIC_VIRT.load(Ordering::Relaxed);
    unsafe { mmio::write_u32(virt + reg as u64, val) };
}

/// 对 LAPIC 寄存器做"读-改-写"：清除 `clear_bits`，置位 `set_bits`。
#[inline]
fn lapic_rmw(reg: usize, clear_bits: u32, set_bits: u32) {
    let v = lapic_read(reg);
    lapic_write(reg, (v & !clear_bits) | set_bits);
}

/// 发送 EOI 给 LAPIC。
pub fn end_of_interrupt() {
    lapic_write(LAPIC_EOI, 0);
}

/// ICR（中断命令寄存器）偏移与字段（Intel SDM §10.6）。
const LAPIC_ICR_LOW: usize = 0x300;
const LAPIC_ICR_HIGH: usize = 0x310;
/// Delivery Status（bit12，只读）：1 = 发送进行中。写入前必须为空闲。
const ICR_SEND_PENDING: u32 = 1 << 12;
/// Level/Assert（bit14）：Fixed 投递要求置位。
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// Destination 目标 APIC id 位于 ICR 高半寄存器 bits 31:24。
const ICR_DEST_SHIFT: u32 = 24;
/// 等待发送队列排空的有界轮询上限（AM2 与 serial TX 同一防自旋纪律）：
/// 正常一次总线投递在数十周期内完成；超限说明目标不存在或总线异常，
/// 放弃本次发送并如实上报失败，绝不永久自旋拖死发起核。
const ICI_SEND_POLL_LIMIT: u32 = 1_000_000;

/// 向指定 LAPIC id 发送 Fixed 模式 IPI（MA1b）。
///
/// 返回 `true` = 已成功发出；`false` = LAPIC 未映射或发送队列未在有界轮询
/// 内排空（调用方按失败处理，如降级为本地排空并告警）。
pub fn send_fixed_ipi(dest_lapic_id: u32, vector: u8) -> bool {
    if is_x2apic() {
        // 单次 64 位写即触发投递（SDM §10.12.9），无需 MMIO 高/低半两次写。
        msr_write(
            X2APIC_MSR_ICR,
            ((dest_lapic_id as u64) << 32) | (vector as u64) | ICR_LEVEL_ASSERT as u64,
        );
        return true;
    }
    if !is_mapped() {
        return false;
    }
    // SDM §10.6.1 写入次序：先写高半（目标），后写低半（触发发送）。
    lapic_write(
        LAPIC_ICR_HIGH,
        (dest_lapic_id & 0xFF) << ICR_DEST_SHIFT,
    );
    for _ in 0..ICI_SEND_POLL_LIMIT {
        if lapic_read(LAPIC_ICR_LOW) & ICR_SEND_PENDING == 0 {
            lapic_write(LAPIC_ICR_LOW, (vector as u32) | ICR_LEVEL_ASSERT);
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 配置 LAPIC LINT0 为 ExtINT 模式接收 8259 中断。
///
/// QEMU `pc` 机器在 LAPIC 启用时，把 8259 输出路由到 LAPIC 的 LINT0；配置为
/// ExtINT 后，ISA 设备（键盘 IRQ1）经 8259 → LINT0 → CPU（向量由 8259 提供，
/// 经 `pic::remap` 重映射为 33）。须在 SVR 使能且 `pic::init` 完成之后调用。
pub fn configure_lint0_extint() {
    lapic_write(LAPIC_LINT0, LINT0_EXTINT);
    klib::info!("[lapic] LINT0 configured as ExtINT (8259 source)");
}

/// IRQ 处理函数（定时器）：把本核 tick 计数 +1、驱动软件定时器队列并 EOI。
///
/// IRQ 表是全体核共享的注册表，每个核自己的 LAPIC 定时器（向量 0x20 = IRQ0）
/// 触发时都会调用本函数。因此：
/// - tick 计数必须写当前核自己的槽位（TICKS per-CPU），否则多核叠加加倍；
/// - 软件定时器队列（klib::time::poll_timeouts）阶段 1 只由 BSP（槽 0）喂，
///   其它核空转不碰队列，避免多核并发驱动同一全局队列造成数据竞争
///   （队列分核/加锁留待阶段 5）。
///
/// pub：供共享中断测试（tests.rs）引用以调整注册顺序。
pub extern "C" fn lapic_timer_handler(_irq: u8) -> bool {
    let slot = my_slot();
    let t = TICKS[slot].fetch_add(1, Ordering::Relaxed) + 1;
    if t <= 3 {
        // 前几次 per-core tick 打印，便于启动期确认每个核的定时器都在推进。
        // 用 debug 级别（默认 Info 不显示）：多核下每核打 1-3 条，恰好在启动
        // 横幅附近输出，把横幅切成碎片（实测）。定时器在推进由 "SMP done,
        // N cpus online" 与 shell 可交互背书，无需每次启动刷屏。需要观察时
        // klib::log::set_level(LogLevel::Debug)。
        klib::debug!("[lapic] tick cpu_slot={} count={}", slot, t);
    }
    // ---- EOI 先于软件定时器回调（顺序原则，非 §6.12.5 主根因）----
    //
    // EOI 的语义是「本次中断受理完毕，可以再投递了」——它与「软件回调要
    // 做什么、做多久」无关。若把 `poll_timeouts()` 放在 EOI 之前，回调的
    // 耗时（如 `wake_enqueue` 取 `RUN` 锁的自旋等待，实测可达毫秒级）会
    // 直接变成本核对 LAPIC「仍在受理」的时间：期间不投递任何后续中断。
    // 回调属于软件逻辑，不该成为硬件中断重新使能的前提，故 EOI 先发。
    //
    // 注意：这只是**顺序卫生**。§6.12.5「前台 `^C` 失效」的真正根因是
    // `sleep_blocking` 兜底忙等的关中断占空比（syscall.rs §6.12.5 追加
    // 修复）与 `waitpid_timeout` pre 检查的测试形态泄漏（scheduler.rs
    // `waitpid_probe`），不在本函数——彼处修复后，无论本函数回调多久，
    // 系统中断都由那一侧保证不被饿死。
    end_of_interrupt();
    // 软件定时器队列仅由 BSP（槽 0）驱动；AP 空转不碰（阶段 1 纪律）。
    if slot == 0 {
        klib::time::poll_timeouts();
    }
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
///
/// 校准顺序：**优先用 HPET 高精度时钟**（精确且不受 QEMU TCG 慢速下
/// PIT 计时失准影响），HPET 不可用时回退 PIT。
fn calibrate_bus_freq() -> u64 {
    // 1. HPET 校准：LAPIC 定时器以分频 1、最大初值跑一次性周期，用 HPET
    //    now_nanos 精确计时 20ms，读 LAPIC 递减 tick 数推算总线频率。
    if crate::hpet::is_ready() {
        lapic_write(LAPIC_TIMER, TIMER_VECTOR);
        lapic_write(LAPIC_TIMER_DIV, 0x0B);
        lapic_write(LAPIC_TIMER_INIT, 0xFFFF_FFFF);

        let t0 = crate::hpet::now_nanos();
        let target = t0 + 20_000_000; // 20ms
        while crate::hpet::now_nanos() < target {
            core::hint::spin_loop();
        }

        let remaining = lapic_read(LAPIC_TIMER_CURR);
        let elapsed = 0xFFFF_FFFFu64 - remaining as u64;
        let freq = elapsed * 1_000_000_000 / 20_000_000;
        if freq != 0 {
            klib::info!("[lapic] bus freq calibrated via HPET = {} Hz", freq);
            return freq;
        }
        klib::warn!("[lapic] HPET calibration gave 0, falling back to PIT");
    }

    // 2. PIT 校准（HPET 不可用或校准失败时回退）。
    const PIT_CH0_DATA: u16 = 0x40; // PIT 通道 0 数据端口
    const PIT_CMD: u16 = 0x43; // PIT 命令/控制字端口
    const PIT_PORT_B: u16 = 0x61; // 0x61：bit4 反映通道 0 输出（反相）
    const PIT_FREQ: u64 = 1_193_182; // PIT 计数频率（Hz）
    const PIT_TICKS: u16 = 0xFFFF; // 最大计数值，约 54.9ms

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

/// 每核 LAPIC 定时器共享的已校准总线频率（Hz）。由 BSP 在 init 校准后写入，
/// AP 经 init_timer_self 直接继承（AP 不重复校准）。0 = 尚未校准。
static CALIBRATED_BUS_FREQ: AtomicU64 = AtomicU64::new(0);

/// 初始化 BSP 的 Local APIC 定时器路径（映射 + 使能 + 校准 + 全局接线）。
///
/// **只在 BSP 上调用一次**（kmain，SMP 之前）。职责分两类：
/// - **全局一次性**：LAPIC MMIO 映射、SVR 使能、校准总线频率并写入
///   CALIBRATED_BUS_FREQ、注册共享 IRQ0 handler、注入全局单调时钟源、
///   set_lapic_ready、配置 LINT0；
/// - **本核定时器启动**：委托 init_timer_self（BSP 也运行自己的定时器）。
///
/// AP 不应调用本函数——它们只需 init_timer_self（在 ap_entry 里调），
/// 不重复映射/校准/注入全局状态。
pub fn init() {
    // 0. 访问模式：引导器在 Limine SMP 响应 flags bit0 声明是否已使能 x2APIC
    //    （brxlimine-rs lib.rs 552）。必须先于任何 LAPIC 访问确定。
    set_x2apic(smp::x2apic_enabled());
    if is_x2apic() {
        // x2APIC：0xFEE00000 的 MMIO 窗口不再代表 LAPIC，不做映射。
        klib::info!("[lapic] x2APIC mode: MSR access (id={})", current_lapic_id());
    } else {
        // 1. 从 MSR IA32_APIC_BASE 读取真实 LAPIC 物理基址，避免硬编码 0xFEE00000。
        //    若 MSR 报告 LAPIC 已启用（bit 12），使用其基址；否则回退默认值。
        let apic_base = read_apic_base();
        let phys = if apic_base & (1 << 12) != 0 {
            apic_base & !0xFFF
        } else {
            DEFAULT_LAPIC_PHYS
        };
        // 映射到高半区虚拟地址：统一设备映射基址（mmio::DEVICE_MMIO_VIRT_BASE，
        // arch1.md AA2：不再各文件硬编码 HHDM 形状的魔数）。
        let virt = phys | mmio::DEVICE_MMIO_VIRT_BASE;
        LAPIC_VIRT.store(virt, Ordering::Relaxed);

        // 把 LAPIC 物理地址映射到高半区虚拟地址（全局内核页表，全体核共享该映射）
        if !mmio::map_lapic(phys, virt) {
            klib::info!("[lapic] map failed");
            return;
        }
        klib::info!("[lapic] mapped to {:#x}", virt);
    }

    // 1. 使能 LAPIC（SVR，伪中断向量 = interrupts::SPURIOUS_VECTOR，
    //    IDT 已在 interrupts::init 填充对应表项——arch1.md AA3）
    lapic_rmw(LAPIC_SVR, SVR_APIC_ENABLE, SVR_APIC_ENABLE | SPURIOUS_VECTOR_SVR);

    // 2. 校准 LAPIC 总线频率（用 PIT 实测，而非硬编码），写入共享静态供 AP 继承
    let bus_freq = calibrate_bus_freq();
    let bus_freq = if bus_freq == 0 {
        klib::info!(
            "[lapic] WARNING: PIT calibration failed, falling back to {} Hz",
            DEFAULT_BUS_FREQ_HZ
        );
        DEFAULT_BUS_FREQ_HZ
    } else {
        klib::info!("[lapic] calibrated LAPIC bus freq = {} Hz", bus_freq);
        bus_freq
    };
    CALIBRATED_BUS_FREQ.store(bus_freq, Ordering::Release);

    // 3. 注册共享 IRQ handler（vector 0x20 → irq 0）。IRQ 表全局共享，
    //    每个核自己的定时器中断都会分发到它，AP 无需重复注册。
    interrupts::register_irq(0, lapic_timer_handler);

    // 4. 注入 klib 全局单调时钟源。HPET 优先：纳秒计数（1GHz），不受多核
    //    叠加影响（HPET 是全局硬件，天然一致）；无 HPET 时回退到 system_ticks
    //    （BSP 槽 0 计数，同样不被 AP 定时器叠加）。
    const TARGET_HZ: u64 = 100;
    if crate::hpet::is_ready() {
        klib::time::set_clock_source(crate::hpet::now_nanos, 1_000_000_000);
        klib::info!("[lapic] clock source: HPET (1 GHz ns clock)");
    } else {
        klib::time::set_clock_source(system_ticks, TARGET_HZ);
        klib::info!("[lapic] clock source: LAPIC tick ({} Hz)", TARGET_HZ);
    }

    // 标记 LAPIC 已可用（串口锁依赖 LAPIC id 做多核 owner 判断）
    serial::set_lapic_ready();

    // 5. 配置 LINT0 为 ExtINT 接收 8259 外部中断（键盘等 ISA 设备）。
    configure_lint0_extint();

    // 6. 启动本核（BSP）自己的周期定时器。
    init_timer_self();

    klib::info!("[lapic] LAPIC timer initialized (BSP)");
}

/// 确保**本核**处于 x2APIC 模式（IA32_APIC_BASE bit10）。
///
/// IA32_APIC_BASE 是每 CPU 寄存器：AP 经 INIT 启动后回到 xAPIC，而内核的
/// LAPIC 访问模式是全局的（由引导器 flags 决定）。因此 AP 入口必须在任何
/// LAPIC 访问（含 `current_lapic_id`）之前调用本函数，否则 x2APIC MSR 读会
/// 在 xAPIC 的核上触发 #GP。幂等：已是 x2APIC 时直接返回。
///
/// **本函数不得打印日志**：它在 AP 的 per-CPU 状态就绪之前运行，而 klib 的
/// 串口锁以 CPU 槽位做同核重入检测——槽位未就绪时 `cpu_slot_id()` 回退为常量
/// 1，会把「BSP 持有该锁」误判为「本核重入」并当场 panic（M12 实测：日志行
/// 加入后 AP 一上线即报 SpinMutex 同核重入）。
pub fn ensure_x2apic_on_this_cpu() {
    if !is_x2apic() {
        return;
    }
    let base = read_apic_base();
    if base & APIC_BASE_X2APIC == 0 {
        msr_write(MSR_APIC_BASE, base | APIC_BASE_ENABLE | APIC_BASE_X2APIC);
    }
}
/// 启动当前 CPU 的 LAPIC 周期定时器（100Hz）。
///
/// 每核一份硬件资源：BSP 在 init 末尾调用；每个 AP 在 smp::ap_entry 上线后调用。
/// 本函数只配置本核定时器，不做任何全局/一次性动作——
/// - 不重新映射 LAPIC（BSP init 已全局映射，AP 继承内核页表映射）；
/// - 不校准（继承 CALIBRATED_BUS_FREQ，BSP 校准一次即可）；
/// - 不注册 IRQ handler（共享表已由 BSP 注册）；
/// - 不注入全局时钟源 / 不 set_lapic_ready / 不配 LINT0（都只该做一次）。
///
/// pub：供 smp::ap_entry 调用以启动每个 AP 自己的定时器。
pub fn init_timer_self() {
    // 已校准总线频率；未校准（异常时序）时回退默认值并如实告警。
    let bus_freq = CALIBRATED_BUS_FREQ.load(Ordering::Acquire);
    let bus_freq = if bus_freq == 0 {
        klib::warn!(
            "[lapic] init_timer_self before calibration; using default {} Hz",
            DEFAULT_BUS_FREQ_HZ
        );
        DEFAULT_BUS_FREQ_HZ
    } else {
        bus_freq
    };

    // 使能本核 LAPIC（Limine 通常已使能；此处幂等确保）。
    lapic_rmw(LAPIC_SVR, SVR_APIC_ENABLE, SVR_APIC_ENABLE | SPURIOUS_VECTOR_SVR);

    // 配置定时器分频（divide by 1 → 0x0B）。
    lapic_write(LAPIC_TIMER_DIV, 0x0B);

    // 设置 LVT Timer：周期性，向量 0x20。
    lapic_write(LAPIC_TIMER, TIMER_PERIODIC | TIMER_VECTOR);

    // 设置初始计数：期望 100Hz。本核定时器到期即 IRQ0 → 共享 handler，
    // handler 把本核槽位 tick +1。
    const TARGET_HZ: u64 = 100;
    let init_count = bus_freq / TARGET_HZ;
    lapic_write(LAPIC_TIMER_INIT, init_count as u32);

    klib::info!("[lapic] per-core timer started (slot {} @ ~{} Hz)", my_slot(), TARGET_HZ);
}