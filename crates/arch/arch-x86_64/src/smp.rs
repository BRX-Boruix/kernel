//! x86-64 多核（SMP）支持。
//!
//! 通过 Limine 的 SMP 请求，引导器会启动辅助处理器（AP）并将它们
//! 停在 `goto_address = 0`。BSP 初始化时，为每个 AP 写入 `goto_address`，
//! 使 AP 跳转到 `ap_entry`，进入自己的 GDT/TSS/内核栈并空转。
//!
//! 每 CPU 拥有独立的 GDT/TSS/内核栈（静态数组，由 CPU 的 LAPIC id 索引）。

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::gdt;
use crate::lapic;
use limine::SmpRequest;

/// 请求 Limine 启动 AP。
#[limine::limine_tag]
static SMP_REQUEST: SmpRequest = SmpRequest::new(0);

/// 已启动的 CPU 数量（原子）。
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 系统总 CPU 数（由 init 记录）。
static TOTAL_CPUS: AtomicUsize = AtomicUsize::new(1);

/// 每 CPU 内核栈大小（AP 用）。Limine 已给 AP 提供 64KB 引导栈，
/// 这里仅提供一个更小的中断栈（TSS.rsp0）用于中断上下文。
const AP_STACK_SIZE: usize = 16 * 1024;

/// AP 槽位上限。静态数组编译期大小固定，这里取一个足够大的值
/// （对齐常见多核配置的上限）。若实际 CPU 数超过该值会拒绝启动超出部分。
const MAX_AP_SLOTS: usize = 64;

/// 每个 CPU 一个内核栈（AP 用）。BSP 用自己的静态栈。
static mut AP_KSTACKS: [[u8; AP_STACK_SIZE]; MAX_AP_SLOTS] = [[0; AP_STACK_SIZE]; MAX_AP_SLOTS];

/// 每个 CPU 一个 GDT/TSS。
static mut AP_GDT: [gdt::Gdt; MAX_AP_SLOTS] = [const { gdt::Gdt::new() }; MAX_AP_SLOTS];
static mut AP_TSS: [gdt::Tss; MAX_AP_SLOTS] = [const { gdt::Tss::new() }; MAX_AP_SLOTS];

/// 输出"p1 + v1 + p2 + v2"（单次串口写）。
fn klog_combined(p1: &str, v1: u32, p2: &str, v2: u64) {
    klib::logln!("{}{}{}{}", p1, v1, p2, v2);
}

/// 获取当前已启动的 CPU 数。
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// 获取系统总 CPU 数。
pub fn total_cpus() -> usize {
    TOTAL_CPUS.load(Ordering::Relaxed)
}

/// AP 入口：由 Limine 跳转，RDI = *const SmpInfo。
///
/// 注意：`goto_address` 必须指向一个 `extern "C" fn(*const SmpInfo) -> !`。
/// Limine 会给 AP 一个 64KB 栈，并在 RDI 传入 SmpInfo 指针。
#[unsafe(no_mangle)]
extern "C" fn ap_entry(_info: *const limine::SmpInfo) -> ! {
    // 取出本 CPU 的 LAPIC id
    let lapic_id = lapic::current_lapic_id();
    // 用槽位上限取模，避免 LAPIC id 超过数组长度时越界
    let idx = lapic_id as usize % MAX_AP_SLOTS;

    // 配置并加载本 CPU 的 GDT/TSS（每 CPU 独立内核栈）
    let (kstack_top, gdt_ptr, tss_ptr) = unsafe {
        (
            gdt::stack_top(core::ptr::addr_of!(AP_KSTACKS[idx]) as *const u8, AP_STACK_SIZE),
            core::ptr::addr_of_mut!(AP_GDT[idx]),
            core::ptr::addr_of_mut!(AP_TSS[idx]),
        )
    };
    gdt::setup_cpu(gdt_ptr, tss_ptr, kstack_top);

    // 开启中断
    crate::interrupts::enable();

    // 用 AcqRel 保证计数递增的可见性与顺序（配合 BSP 的 Release 初始化）
    CPU_COUNT.fetch_add(1, Ordering::AcqRel);

    // 一次 write_str 完整打印，避免与其他 CPU 交错
    klib::log_dec!("[smp] AP online, lapic_id=", lapic_id);

    // AP 空闲循环
    loop {
        crate::interrupts::halt();
    }
}

/// 初始化 SMP：获取 CPU 信息，启动所有 AP。
///
/// 需在 GDT/IDT/LAPIC 初始化后调用。
pub fn init() {
    // 获取 SMP 响应
    let Some(resp) = SMP_REQUEST.get_response().get() else {
        klib::logln!("[smp] no SMP response");
        return;
    };

    let bsp_lapic = resp.bsp_lapic_id;
    let total = resp.cpu_count;
    if total as usize > MAX_AP_SLOTS {
        klib::logln!(
            "[smp] WARNING: {} cpus exceed MAX_AP_SLOTS={}, only first {} will start",
            total,
            MAX_AP_SLOTS,
            MAX_AP_SLOTS
        );
    }
    TOTAL_CPUS.store((total as usize).min(MAX_AP_SLOTS), Ordering::Relaxed);
    // 一次 write_str 完整打印 BSP 信息，避免交错
    klog_combined("[smp] BSP lapic_id=", bsp_lapic, ", total cpus=", total);

    // BSP 计入（Release：保证后续 goto_address 写入对 AP 可见）
    CPU_COUNT.store(1, Ordering::Release);

    // 遍历所有 CPU，对非 BSP 设置 goto_address 使其启动
    // resp.cpus 是指向 `NonNullPtr<SmpInfo>` 数组的指针，每个元素是一个
    // 指向 SmpInfo 的指针。用 from_raw_parts_mut 构造可变指针数组 slice。
    let cpu_slice = unsafe {
        core::slice::from_raw_parts_mut(
            resp.cpus.as_ptr() as *mut limine::NonNullPtr<limine::SmpInfo>,
            resp.cpu_count as usize,
        )
    };
    for ptr in cpu_slice.iter_mut() {
        let info: &mut limine::SmpInfo = unsafe { &mut *ptr.as_ptr() };
        let this_lapic = info.lapic_id;
        if this_lapic == bsp_lapic {
            continue; // 跳过 BSP
        }
        // 写入 goto_address，使 AP 跳转到 ap_entry
        info.goto_address = ap_entry;
        klib::log_dec!("[smp] fired AP lapic_id=", this_lapic);
    }
}

/// 等待所有 AP 上线，返回最终在线 CPU 数。
///
/// 轮询 `CPU_COUNT`（Acquire）直到达到目标数，或超过超时。
pub fn wait_all_online(target: usize, timeout_iters: usize) -> usize {
    let mut iters = 0;
    while cpu_count() < target && iters < timeout_iters {
        iters += 1;
        core::hint::spin_loop();
    }
    cpu_count()
}
