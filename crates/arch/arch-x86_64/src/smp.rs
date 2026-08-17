//! x86-64 多核（SMP）支持。
//!
//! 通过 Limine 的 SMP 请求，引导器会启动辅助处理器（AP）并将它们
//! 停在 `goto_address = 0`。BSP 初始化时，为每个 AP 写入 `goto_address`，
//! 使 AP 跳转到 `ap_entry`，进入自己的 GDT/TSS/内核栈并空转。
//!
//! 每 CPU 拥有独立的 GDT/TSS/内核栈（静态数组）。
//! 槽位索引由 BSP 按"启动顺序"分配紧凑唯一值，写入每个 AP 的
//! `SmpInfo::extra_argument`，而不是用 LAPIC id 直接索引——因为真实
//! 硬件上 LAPIC id 可能稀疏（0,8,16,…）甚至超过槽位上限，直接用会冲突。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once};

use arch::phys_to_virt;
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

/// 每个 AP 的 GDT/TSS/内核栈/Double Fault 栈资源。
///
/// 全部使用**物理帧分配器**分配（经 HHDM 映射为可访问虚拟地址），而非内核堆，
/// 从而不占用有限的 4MB 内核堆、也不受核数导致的堆容量限制。
///
/// GDT/TSS 各占一个独立 4KB 帧（实际只用几十字节，但以帧为单位分配简单安全）。
struct ApResources {
    /// 每个 AP 内核栈的物理基址（长度 = AP 数，每块 AP_STACK_SIZE）。
    kstack_paddrs: Vec<u64>,
    /// 每个 AP Double Fault 栈的物理基址（每块 DF_STACK_SIZE）。
    df_stack_paddrs: Vec<u64>,
    /// 每个 AP 的 GDT 帧物理基址（各 4KB）。
    gdt_paddrs: Vec<u64>,
    /// 每个 AP 的 TSS 帧物理基址（各 4KB）。
    tss_paddrs: Vec<u64>,
}

/// 动态分配的 AP 资源（懒初始化，由 BSP 在 `init` 时填入）。
static AP_RESOURCES: Mutex<Option<ApResources>> = Mutex::new(None);

/// 物理帧分配器注入点：`fn(order) -> paddr`，返回 `1 << order` 个连续 4KB 帧的
/// 起始物理地址，失败返回 0。由内核在 `smp::init` 前注入（实际调用 `mm` 分配器）。
/// 用 Rust ABI（非 extern "C"），调用方与实现方均在同一个内核进程内，无需 FFI。
static FRAME_ALLOC: Once<fn(u32) -> u64> = Once::new();

/// 注入物理帧分配器（内核在 mm 初始化后、SMP 启动前调用）。
pub fn set_frame_allocator(f: fn(u32) -> u64) {
    let _ = FRAME_ALLOC.call_once(|| f);
}

/// 分配 `1 << order` 个连续 4KB 帧，返回物理基址（0 表示失败）。
fn alloc_stack_frames(order: u32) -> u64 {
    match FRAME_ALLOC.get() {
        Some(f) => f(order),
        None => 0,
    }
}

/// LAPIC id → 紧凑 CPU 槽位 映射。x86 LAPIC id 为 0..255。
/// BSP 槽位 0，AP 按启动顺序分配 1..n。per-CPU 帧缓存用该紧凑槽位做索引，
/// 避免真机上稀疏 LAPIC id 对固定数取模产生冲突。
static LAPIC_TO_SLOT: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];

/// 查询 LAPIC id 对应的紧凑 CPU 槽位。
pub fn slot_of_lapic(lapic_id: u32) -> usize {
    LAPIC_TO_SLOT[(lapic_id & 0xFF) as usize].load(Ordering::Relaxed)
}

/// 从 Limine SMP 响应读取系统总 CPU 数（可在 `init` 前调用，用于预分配 per-CPU 结构）。
pub fn requested_cpu_count() -> usize {
    SMP_REQUEST
        .get_response()
        .get()
        .map(|r| r.cpu_count as usize)
        .unwrap_or(1)
}

/// 输出"p1 + v1 + p2 + v2"（单次串口写）。
fn klog_combined(p1: &str, v1: u32, p2: &str, v2: u64) {
    klib::info!("{}{}{}{}", p1, v1, p2, v2);
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
/// 槽位索引由 BSP 在 `extra_argument` 中指定（紧凑唯一，从 1 开始）。
#[unsafe(no_mangle)]
extern "C" fn ap_entry(info: *const limine::SmpInfo) -> ! {
    // 从 extra_argument 取得 BSP 分配的唯一槽位索引（>=1）
    let slot = unsafe { (*info).extra_argument as usize };

    // 取出本 CPU 的 LAPIC id（用于日志 + 更新映射）
    let lapic_id = lapic::current_lapic_id();

    // 防御：槽位非法/越界则停机，避免访问动态资源越界
    if slot == 0 {
        klib::info!("[smp] AP slot invalid (0): lapic={}", lapic_id as u64);
        loop {
            crate::interrupts::halt();
        }
    }
    let arr_idx = slot - 1;

    let resources = AP_RESOURCES.lock();
    let Some(res) = resources.as_ref() else {
        klib::info!("[smp] AP resources not initialized");
        loop {
            crate::interrupts::halt();
        }
    };
    if arr_idx >= res.kstack_paddrs.len() {
        klib::info!("[smp] AP slot out of range: {}", slot as u64);
        loop {
            crate::interrupts::halt();
        }
    }

    // 把物理基址经 HHDM 映射为可访问虚拟地址：栈算栈顶（TSS.rsp0 / IST），
    // GDT/TSS 帧作为可写指针交给 setup_cpu 填充。
    let kstack_virt = phys_to_virt(res.kstack_paddrs[arr_idx]);
    let df_virt = phys_to_virt(res.df_stack_paddrs[arr_idx]);
    let (kstack_top, df_stack_top, gdt_ptr, tss_ptr) = (
        gdt::stack_top(kstack_virt as *const u8, AP_STACK_SIZE),
        gdt::stack_top(df_virt as *const u8, gdt::DF_STACK_SIZE),
        phys_to_virt(res.gdt_paddrs[arr_idx]) as *mut gdt::Gdt,
        phys_to_virt(res.tss_paddrs[arr_idx]) as *mut gdt::Tss,
    );
    drop(resources);

    // 记录本 CPU 的 LAPIC id → 槽位映射（供帧缓存索引）
    LAPIC_TO_SLOT[(lapic_id & 0xFF) as usize].store(slot, Ordering::Release);

    gdt::setup_cpu(gdt_ptr, tss_ptr, kstack_top, df_stack_top);

    // AP 上也开启 SMEP/SMAP（CR4 是 per-CPU），与 BSP 保持一致的隔离策略。
    crate::cpu::enable_smep_smap();

    // 开启中断
    crate::interrupts::enable();

    // 用 AcqRel 保证计数递增的可见性与顺序（配合 BSP 的 Release 初始化）
    CPU_COUNT.fetch_add(1, Ordering::AcqRel);

    // 一次 write_str 完整打印，避免与其他 CPU 交错
    klib::info!("[smp] AP online, lapic_id={}", lapic_id);

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
        klib::info!("[smp] no SMP response");
        return;
    };

    let bsp_lapic = resp.bsp_lapic_id;
    let total = resp.cpu_count as usize;

    // 自适应：依据实际 CPU 数动态分配 AP 资源，不再受固定槽位上限制。
    let ap_count = total.saturating_sub(1); // 去掉 BSP

    // 内核栈 / DF 栈各 AP 一块，从物理帧分配器分配（order：AP_STACK_SIZE 与
    // DF_STACK_SIZE 均为 16KB = 4 个 4KB 帧 = order 2）。GDT/TSS 各一个 4KB 帧
    // （order 0）。全部不占内核堆。
    const STACK_ORDER: u32 = 2; // 2^2 * 4KB = 16KB
    const ONE_FRAME_ORDER: u32 = 0; // 1 个 4KB 帧
    let mut kstack_paddrs = Vec::with_capacity(ap_count);
    let mut df_paddrs = Vec::with_capacity(ap_count);
    let mut gdt_paddrs = Vec::with_capacity(ap_count);
    let mut tss_paddrs = Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        let k = alloc_stack_frames(STACK_ORDER);
        let d = alloc_stack_frames(STACK_ORDER);
        let g = alloc_stack_frames(ONE_FRAME_ORDER);
        let t = alloc_stack_frames(ONE_FRAME_ORDER);
        if k == 0 || d == 0 || g == 0 || t == 0 {
            // 物理内存不足：打印后仅初始化已分配的部分（记录到 TOTAL_CPUS）
            klib::info!("[smp] WARNING: out of physical frames for AP resources");
            break;
        }
        kstack_paddrs.push(k);
        df_paddrs.push(d);
        gdt_paddrs.push(g);
        tss_paddrs.push(t);
    }
    let real_ap = kstack_paddrs.len();
    if real_ap < ap_count {
        klib::info!("[smp] only {} AP resources allocated", real_ap as u64);
    }

    // 初始化每个 AP 的 GDT/TSS 物理帧（写入初始值，供 AP 使用）。
    for i in 0..real_ap {
        unsafe {
            core::ptr::write(phys_to_virt(gdt_paddrs[i]) as *mut gdt::Gdt, gdt::Gdt::new());
            core::ptr::write(phys_to_virt(tss_paddrs[i]) as *mut gdt::Tss, gdt::Tss::new());
        }
    }

    let mut res_guard = AP_RESOURCES.lock();
    *res_guard = Some(ApResources {
        kstack_paddrs,
        df_stack_paddrs: df_paddrs,
        gdt_paddrs,
        tss_paddrs,
    });
    drop(res_guard);

    // 总 CPU 数 = BSP + 实际分配成功的 AP 数
    let effective_total = real_ap + 1;
    TOTAL_CPUS.store(effective_total, Ordering::Relaxed);
    // 一次 write_str 完整打印 BSP 信息，避免交错
    klog_combined("[smp] BSP lapic_id=", bsp_lapic, ", total cpus=", total as u64);

    // BSP 槽位 0（默认即 0，显式置位以便清晰）
    LAPIC_TO_SLOT[(bsp_lapic & 0xFF) as usize].store(0, Ordering::Release);

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

    // 为每个 AP 分配紧凑唯一槽位 1..=ap_count。
    // 不用 LAPIC id 直接做索引，因为真机上 LAPIC id 可能稀疏，取模会让
    // 多个 CPU 共享同一槽位，造成 GDT/TSS/内核栈冲突。
    let mut next_slot = 1usize;
    for ptr in cpu_slice.iter_mut() {
        let info: &mut limine::SmpInfo = unsafe { &mut *ptr.as_ptr() };
        let this_lapic = info.lapic_id;
        if this_lapic == bsp_lapic {
            continue; // 跳过 BSP
        }
        let slot = next_slot;
        next_slot += 1;
        if slot > real_ap {
            // 防御：实际 AP 数超过已分配资源（物理内存不足时可能发生），跳过
            klib::info!("[smp] skipping AP lapic_id={}", this_lapic);
            continue;
        }
        // 把槽位传给 AP（extra_argument），并写入 goto_address
        info.extra_argument = slot as u64;
        info.goto_address = ap_entry;
        klib::info!("[smp] fired AP lapic_id={}", this_lapic);
    }
}

/// 等待所有 AP 上线，返回最终在线 CPU 数。
///
/// 轮询 `CPU_COUNT` 直到达到目标数，或超过 `timeout_ms`（毫秒）。
///
/// 用 LAPIC 定时器（100Hz，每 tick = 10ms）作为真实时间源，而不是
/// 机器相关的自旋迭代次数——后者在不同 CPU 速度的机器上语义完全不同，
/// 慢 CPU 上 AP 可能根本起不来就被误判为超时。
pub fn wait_all_online(target: usize, timeout_ms: usize) -> usize {
    // LAPIC 定时器已初始化为 100Hz，每 tick 10ms。
    let start_ticks = crate::lapic::ticks();
    let timeout_ticks = (timeout_ms.div_ceil(10)) as u64; // 换算成 tick 数
    while cpu_count() < target {
        let elapsed = crate::lapic::ticks().saturating_sub(start_ticks);
        if elapsed >= timeout_ticks {
            break;
        }
        core::hint::spin_loop();
    }
    cpu_count()
}
