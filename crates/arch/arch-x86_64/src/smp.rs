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

/// 系统总 CPU 数（由 init 记录）。
static TOTAL_CPUS: AtomicUsize = AtomicUsize::new(1);

/// 每 CPU 内核栈大小（AP 用）。Limine 已给 AP 提供 64KB 引导栈，
/// 这里仅提供一个更小的中断栈（TSS.rsp0）用于中断上下文。
const AP_STACK_SIZE: usize = 16 * 1024;

/// 每个 CPU 一个内核栈（AP 用）。BSP 用自己的静态栈。
/// 只用实际 CPU 数（MAX_AP_SLOTS 个槽，QEMU 测试 4 核足够）。
static mut AP_KSTACKS: [[u8; AP_STACK_SIZE]; 8] = [[0; AP_STACK_SIZE]; 8];

/// 每个 CPU 一个 GDT/TSS。
static mut AP_GDT: [gdt::Gdt; 8] = [const { gdt::Gdt::new() }; 8];
static mut AP_TSS: [gdt::Tss; 8] = [const { gdt::Tss::new() }; 8];

/// 把前缀 + 数字拼成一段字符串（栈缓冲区），并一次性 write_str 输出。
///
/// 避免多条 write_str 分次加锁导致日志交错。
fn klog_num(prefix: &str, val: u32) {
    let mut buf = [0u8; 96];
    let mut n = 0;
    for &b in prefix.as_bytes() {
        if n < buf.len() - 1 {
            buf[n] = b;
            n += 1;
        }
    }
    // 十进制 val
    let mut v = val;
    let mut tmp = [0u8; 11];
    let mut i = 0;
    if v == 0 {
        tmp[i] = b'0';
        i += 1;
    }
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        if n < buf.len() - 1 {
            buf[n] = tmp[i];
            n += 1;
        }
    }
    for &b in b"\r\n" {
        if n < buf.len() {
            buf[n] = b;
            n += 1;
        }
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
    serial::write_str(s);
}

/// 拼接两段"前缀+数字"并一次性输出（u32 + u64）。
fn klog_combined(p1: &str, v1: u32, p2: &str, v2: u64) {
    let mut buf = [0u8; 128];
    let mut n = 0;
    let push = |b: u8, buf: &mut [u8; 128], n: &mut usize| {
        if *n < buf.len() {
            buf[*n] = b;
            *n += 1;
        }
    };
    // u32 十进制写入
    let mut tmp1 = [0u8; 11];
    let mut i1 = 0;
    let mut v1 = v1;
    if v1 == 0 {
        tmp1[i1] = b'0';
        i1 += 1;
    }
    while v1 > 0 {
        tmp1[i1] = b'0' + (v1 % 10) as u8;
        v1 /= 10;
        i1 += 1;
    }
    // u64 十进制写入
    let mut tmp2 = [0u8; 21];
    let mut i2 = 0;
    let mut v2 = v2;
    if v2 == 0 {
        tmp2[i2] = b'0';
        i2 += 1;
    }
    while v2 > 0 {
        tmp2[i2] = b'0' + (v2 % 10) as u8;
        v2 /= 10;
        i2 += 1;
    }
    // 输出 p1 + v1 + p2 + v2 + \r\n
    for &b in p1.as_bytes() {
        push(b, &mut buf, &mut n);
    }
    while i1 > 0 {
        i1 -= 1;
        push(tmp1[i1], &mut buf, &mut n);
    }
    for &b in p2.as_bytes() {
        push(b, &mut buf, &mut n);
    }
    while i2 > 0 {
        i2 -= 1;
        push(tmp2[i2], &mut buf, &mut n);
    }
    for &b in b"\r\n" {
        push(b, &mut buf, &mut n);
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
    serial::write_str(s);
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

    // 用 AcqRel 保证计数递增的可见性与顺序（配合 BSP 的 Release 初始化）
    CPU_COUNT.fetch_add(1, Ordering::AcqRel);

    // 一次 write_str 完整打印，避免与其他 CPU 交错
    klog_num("[smp] AP online, lapic_id=", lapic_id);

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
    TOTAL_CPUS.store(total as usize, Ordering::Relaxed);
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
        klog_num("[smp] fired AP lapic_id=", this_lapic);
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
