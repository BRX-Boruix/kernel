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
use crate::serial;
use limine::SmpRequest;

/// 请求 Limine 启动 AP。
#[limine::limine_tag]
static SMP_REQUEST: SmpRequest = SmpRequest::new(0);

/// 已启动的 CPU 数量（原子）。
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 每 CPU 内核栈大小（AP 用）。Limine 已给 AP 提供 64KB 引导栈，
/// 这里仅提供一个更小的中断栈（TSS.rsp0）用于中断上下文。
const AP_STACK_SIZE: usize = 16 * 1024;

/// 每个 CPU 一个内核栈（AP 用）。BSP 用自己的静态栈。
/// 只用实际 CPU 数（MAX_AP_SLOTS 个槽，QEMU 测试 4 核足够）。
static mut AP_KSTACKS: [[u8; AP_STACK_SIZE]; 8] = [[0; AP_STACK_SIZE]; 8];

/// 每个 CPU 一个 GDT/TSS。
static mut AP_GDT: [gdt::Gdt; 8] = [const { gdt::Gdt::new() }; 8];
static mut AP_TSS: [gdt::Tss; 8] = [const { gdt::Tss::new() }; 8];

/// 获取当前已启动的 CPU 数。
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// AP 入口：由 Limine 跳转，RDI = *const SmpInfo。
///
/// 注意：`goto_address` 必须指向一个 `extern "C" fn(*const SmpInfo) -> !`。
/// Limine 会给 AP 一个 64KB 栈，并在 RDI 传入 SmpInfo 指针。
#[unsafe(no_mangle)]
extern "C" fn ap_entry(_info: *const limine::SmpInfo) -> ! {
    // 取出本 CPU 的 LAPIC id
    let lapic_id = lapic::current_lapic_id();
    let idx = lapic_id as usize % 8;

    // 配置并加载本 CPU 的 GDT/TSS（每 CPU 独立内核栈）
    unsafe {
        let kstack_top =
            core::ptr::addr_of!(AP_KSTACKS[idx]) as u64 + AP_STACK_SIZE as u64;
        let tss_ptr = core::ptr::addr_of_mut!(AP_TSS[idx]);
        (*tss_ptr).rsp[0] = kstack_top;
        let tss_base = tss_ptr as u64;
        let gdt_ptr = core::ptr::addr_of_mut!(AP_GDT[idx]);
        (*gdt_ptr).set_tss(tss_base);
        gdt::load_and_reload(&*gdt_ptr);
    }

    // 开启中断
    crate::interrupts::enable();

    CPU_COUNT.fetch_add(1, Ordering::Relaxed);

    serial::write_str("[smp] AP online, lapic_id=");
    serial::write_dec_u32(lapic_id);
    serial::write_str("\r\n");

    // AP 空闲循环
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

/// 初始化 SMP：获取 CPU 信息，启动所有 AP。
///
/// 需在 GDT/IDT/LAPIC 初始化后调用。
pub fn init() {
    // 获取 SMP 响应
    let Some(resp) = SMP_REQUEST.get_response().get() else {
        serial::write_str("[smp] no SMP response\r\n");
        return;
    };

    let bsp_lapic = resp.bsp_lapic_id;
    let total = resp.cpu_count;
    serial::write_str("[smp] BSP lapic_id=");
    serial::write_dec_u32(bsp_lapic);
    serial::write_str(", total cpus=");
    serial::write_dec_u64(total);
    serial::write_str("\r\n");

    // BSP 计入
    CPU_COUNT.store(1, Ordering::Relaxed);

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
        serial::write_str("[smp] fired AP lapic_id=");
        serial::write_dec_u32(this_lapic);
        serial::write_str("\r\n");
    }
}
