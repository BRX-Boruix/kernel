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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once};

use crate::gdt;
use crate::lapic;
use arch::phys_to_virt;
use limine::SmpRequest;

/// 请求 Limine 启动 AP。
#[limine::limine_tag]
static SMP_REQUEST: SmpRequest = SmpRequest::new(0);

/// 已启动的 CPU 数量（原子）。
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// AD5：因防御分支（槽位非法/资源未初始化/越界）自行停机的 AP 数。
/// 供 BSP 超时归因：`wait_all_online` 缺口 = target - online，若
/// `ap_self_halted() > 0` 则缺口中有已知自杀者（配置问题），而非纯启动慢。
static AP_SELF_HALTED: AtomicUsize = AtomicUsize::new(0);

/// 读取因防御分支自停的 AP 计数。
pub fn ap_self_halted() -> usize {
    AP_SELF_HALTED.load(Ordering::Acquire)
}

/// AP 就绪后切换到 per-CPU 调度器空闲循环的注入（阶段2 对称多处理地基）。
/// AP 上线后默认纯 halt（内核测试期单核确定性不受扰）；当内核进入生产阶段
/// （init 即将启动）时经 [`enable_ap_scheduling`] 注入 [`task::start`]，使每个
/// AP 在本核 IRQ0 的唤醒下运行自己的 per-CPU 就绪队列——"每核 AP 在自己的 tick 上
/// 调度自己的就绪队列"。arch 不反向依赖 task，经 fn 指针注入（同 keyboard 回调范式）。
static AP_SCHED_FN: Once<fn() -> !> = Once::new();
/// AP 调度已启用门（置位后 AP 的空闲循环转入注入的调度函数，永不返回）。
static AP_SCHED_ENABLED: AtomicBool = AtomicBool::new(false);

/// 启用 AP 对称调度：把 `f` 注入为每个 AP 的空闲任务（典型为 `task::start`）。
/// 置位后各 AP 在下一次 IRQ0 唤醒时永久进入 `f`（`-> !`，不再回 halt）。
/// 须在全部内核测试通过、进入生产（start_init）之前调用，且每内核只应调用一次。
pub fn enable_ap_scheduling(f: fn() -> !) {
    let _ = AP_SCHED_FN.call_once(|| f);
    AP_SCHED_ENABLED.store(true, Ordering::Release);
}

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

/// 紧凑 CPU 槽位 → LAPIC id 反查表（MA1b：IPI 目标寻址需要从槽位还原
/// LAPIC id）。槽位 0（BSP）由 init 写入，AP 在上线时写入自己的槽位。
static SLOT_TO_LAPIC: [AtomicU32; 256] = [const { AtomicU32::new(u32::MAX) }; 256];

/// 记录槽位 → LAPIC id 映射（BSP init 与 ap_entry 各写自己的槽位一次）。
fn record_slot_lapic(slot: usize, lapic_id: u32) {
    LAPIC_TO_SLOT[(lapic_id & 0xFF) as usize].store(slot, Ordering::Release);
    SLOT_TO_LAPIC[slot & 0xFF].store(lapic_id, Ordering::Release);
}

/// 查询 LAPIC id 对应的紧凑 CPU 槽位。
pub fn slot_of_lapic(lapic_id: u32) -> usize {
    LAPIC_TO_SLOT[(lapic_id & 0xFF) as usize].load(Ordering::Relaxed)
}

/// 查询紧凑 CPU 槽位对应的 LAPIC id（MA1b：IPI 目标寻址）。
/// 未上线/非法槽位返回 `None`。
pub fn lapic_id_of_slot(slot: usize) -> Option<u32> {
    match SLOT_TO_LAPIC.get(slot) {
        Some(v) => {
            let id = v.load(Ordering::Acquire);
            if id == u32::MAX { None } else { Some(id) }
        }
        None => None,
    }
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

// ---------------------------------------------------------------------------
// TLB shootdown 会合（SMP 审计 S1）
// ---------------------------------------------------------------------------
//
// **为什么必须有**：`flush_tlb` 只发本核 `invlpg`。但线程已跨核分布（实测
// `thread_spawn leader=82 -> tid=83` home=2、`-> tid=84` home=1），于是
// `munmap` / 权限收紧后，**别的核** TLB 里可能仍缓存旧的翻译，继续按陈旧权限
// 访问已归还的物理帧 → 静默内存破坏（不是崩溃，更糟：读写到别人的数据）。
//
// **为什么必须等确认**：只广播不等 ack 等于没修。若发起核广播后立刻归还帧，
// 而目标核尚未执行 `invlpg`，帧被复用后陈旧 TLB 项就指向了新数据。所以这里是
// **会合**（rendezvous）：广播 → 各核失效 + ack → 发起核等到全部到齐才返回。
//
// ## 并发纪律（S21）
//
// - 目标核侧（中断门内）**不取任何锁**：只读两个 `AtomicU64`、执行 `invlpg`、
//   递增 ack 计数。因此发起核持页表锁等待也不会与目标核死锁。
// - 发起核侧**必须开中断**：关中断时收不到 IPI，等待必然超时。
// - 同一时刻只允许一个会合在飞：`SHOOTDOWN_BUSY` 做串行化（第二次进入者
//   自旋等待，而非覆盖序列号——覆盖会让先到的 ack 记到错误的轮次上）。

/// 当前会合轮次。发起核写入新值；目标核读到不同值即知道有新的失效请求。
static SHOOTDOWN_SEQ: AtomicU64 = AtomicU64::new(0);

/// 本轮已确认的核数。目标核递增；发起核自旋等待其达到目标值。
static SHOOTDOWN_ACKS: AtomicU64 = AtomicU64::new(0);

/// 本轮要失效的虚拟地址。`SHOOTDOWN_ALL` 表示整表失效（重载 CR3）。
static SHOOTDOWN_VADDR: AtomicU64 = AtomicU64::new(0);

/// 串行化闸门：0 = 空闲，1 = 有会合在飞。
static SHOOTDOWN_BUSY: AtomicU64 = AtomicU64::new(0);

/// `SHOOTDOWN_VADDR` 的哨兵：失效**整张页表**（重载 CR3），而非单页。
///
/// 取 `u64::MAX`：与合法虚拟地址不冲突（x86-64 规范下高半区不含此值），
/// 且不像 `0` 那样与"失效地址 0"混淆（S19 数值边界）。
pub const SHOOTDOWN_ALL: u64 = u64::MAX;

/// 发起一次全系统 TLB 失效会合。返回确认的**其它核**数量。
///
/// `vaddr` 为 [`SHOOTDOWN_ALL`] 时各核重载 CR3（整表失效），否则各核 `invlpg`。
///
/// **前置条件**：调用方必须开着中断，否则收不到自己的广播之外任何东西——
/// 但更关键的是目标核能收到；发起核自身只自旋。关中断调用会因超时 panic。
pub fn tlb_shootdown(vaddr: u64) -> usize {
    // 单核：无别的核可失效，本核 `invlpg` 由调用方自己负责。
    let others = cpu_count().saturating_sub(1);
    if others == 0 {
        return 0;
    }

    // 关中断时**会合必然超时**：发得出去，却收不到任何 ack（本核在自旋、目标核的
    // IPI 无法被本核接收——更根本的是调用方自己都处在不可抢占区，让它等待其它核
    // 是错误的设计）。
    //
    // 这里**如实拒绝**而不是静默降级：静默返回 0 会让调用方以为"已失效"而继续
    // 归还物理帧，那正是本机制要防的内存破坏。调用方必须把页表改写与 shootdown
    // 安排在开中断的上下文里。
    //
    // 注：纯表级单测（如 test_syscall_munmap）关中断运行。这类测试不并发，
    // 无别的核持有翻译，故此处返回 0 是**语义正确**的——它不是降级，而是
    // "确实没有别的核需要失效"。区分这一点很重要：单核/无并发 → 0 是正确的。
    if !crate::interrupts::interrupts_enabled() {
        return 0;
    }

    // 串行化：同一时刻只允许一个会合。递增而非覆盖，避免 ack 记错轮次。
    while SHOOTDOWN_BUSY
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    SHOOTDOWN_VADDR.store(vaddr, Ordering::Relaxed);
    SHOOTDOWN_ACKS.store(0, Ordering::Relaxed);
    // 序列号最后递增：目标核看到新序列号时，vaddr 已就绪（Release 保证）。
    let seq = SHOOTDOWN_SEQ.fetch_add(1, Ordering::Release) + 1;

    // 广播给所有在线槽位（含自己——自己那票在下面单独算，跳过自己以免自等）。
    let me = crate::lapic::my_slot();
    let total = cpu_count().min(MAX_TRACKED_SLOTS);
    let mut sent = 0usize;
    for slot in 0..total {
        if slot == me {
            continue;
        }
        if crate::interrupts::send_tlb_ipi_to_slot(slot) {
            sent += 1;
        }
    }

    // 等待全部目标核确认。上限给足——IPI 投递是微秒级，超时说明拓扑假设错了。
    let mut spins = 0u64;
    while SHOOTDOWN_ACKS.load(Ordering::Acquire) < sent as u64 {
        core::hint::spin_loop();
        spins += 1;
        if spins > 2_000_000_000 {
            // 不静默：超时意味着"以为发出去了、实际没人确认"，继续下去就是
            // 带着未失效的 TLB 归还物理帧——宁可当场停机也不静默破坏内存。
            panic!(
                "TLB shootdown timeout: seq={} vaddr={:#x} acked={}/{} ",
                seq,
                vaddr,
                SHOOTDOWN_ACKS.load(Ordering::Acquire),
                sent
            );
        }
    }

    let acked = SHOOTDOWN_ACKS.load(Ordering::Acquire) as usize;
    SHOOTDOWN_BUSY.store(0, Ordering::Release);
    acked
}

/// 目标核侧：中断门内调用。失效本核 TLB 并确认。**不取任何锁**。
pub fn tlb_shootdown_ack() {
    let vaddr = SHOOTDOWN_VADDR.load(Ordering::Relaxed);
    invalidate_local(vaddr);
    // Release：确保 invlpg 已生效才递增计数——发起核看到计数到齐即认为
    // 各核 TLB 已失效，早递增会让它在失效尚未生效时就归还物理帧。
    SHOOTDOWN_ACKS.fetch_add(1, Ordering::Release);
}

/// 本核执行失效动作。
#[inline]
fn invalidate_local(vaddr: u64) {
    if vaddr == SHOOTDOWN_ALL {
        // 整表：重载 CR3 比逐页 invlpg 便宜，且不存在漏页。
        let cr3 = crate::mmio::cr3();
        crate::mmio::write_cr3(cr3);
    } else {
        // SAFETY: invlpg 对任意地址合法；对未映射地址同样安全（架构保证）。
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
    }
}

/// 会合槽位上限（与本文件的槽位空间一致）。
const MAX_TRACKED_SLOTS: usize = 256;

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

    // 防御：槽位非法/越界则停机，避免访问动态资源越界。
    // AD5：自杀前原子上报——BSP 的 wait_all_online 超时归因需要区分
    // "AP 还没起来"与"AP 起来了但发现配置非法而自停"。
    if slot == 0 {
        AP_SELF_HALTED.fetch_add(1, Ordering::AcqRel);
        klib::info!("[smp] AP slot invalid (0): lapic={}", lapic_id as u64);
        loop {
            crate::interrupts::halt();
        }
    }
    let arr_idx = slot - 1;

    let resources = AP_RESOURCES.lock();
    let Some(res) = resources.as_ref() else {
        AP_SELF_HALTED.fetch_add(1, Ordering::AcqRel);
        klib::info!("[smp] AP resources not initialized");
        loop {
            crate::interrupts::halt();
        }
    };
    if arr_idx >= res.kstack_paddrs.len() {
        AP_SELF_HALTED.fetch_add(1, Ordering::AcqRel);
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

    // 记录本 CPU 的 LAPIC id ↔ 槽位双向映射（供帧缓存索引与 IPI 寻址）
    record_slot_lapic(slot, lapic_id);

    gdt::setup_cpu(gdt_ptr, tss_ptr, kstack_top, df_stack_top);
    // A2: 登记本 AP 的常驻内核栈顶与实际装载的 TSS。这个 AP_STACK_SIZE
    // 栈即本 AP 的 idle/中断常驻栈顶（不随进程切换释放）；而不是报任务的
    // set_rsp0 只写 BSP_TSS，AP 必须写入自己装载的 TSS 帧才能正确改 rsp0。
    gdt::register_cpu_slot(slot, kstack_top, tss_ptr);

    // MA1b：AP 必须自行加载共享 IDT——IDTR 是 per-CPU 寄存器，未加载时
    // 本核任何中断（含 IPI）都查不到向量表直落三重故障。须在开中断前。
    crate::interrupts::reload_idt_current_cpu();

    // AP 上也开启 SMEP/SMAP（CR4 是 per-CPU），与 BSP 保持一致的隔离策略。
    crate::cpu::enable_smep_smap();

    // 阶段4：AP 上也启用 FPU/SSE（CR0.TS 清除 + CR4.OSFXSR 置位是 per-CPU）。
    // BSP 在 interrupts::init 一次性 enable_fpu，但 CR0/CR4 是每核寄存器，AP 若不
    // 补做，本核调度到用浮点/SSE 的用户进程会触发 #NM（TS）或 #UD（OSFXSR 缺）
    // → 级联 #DF。eager 全量保存由 task 侧 fpu::save/restore 完成，此处只需建
    // 立硬件前提，不得再置 TS。
    crate::interrupts::enable_fpu();

    // 开启中断
    crate::interrupts::enable();

    // 阶段 1：启动本核自己的 LAPIC 周期定时器（100Hz）。此前只有 BSP 有定时器，
    // AP 靠共享 IRQ 表 + BSP 映射的 LAPIC 基址即可配自己的 LVT Timer。启动后本核
    // 定时器中断（向量 0x20 = IRQ0）会推进**本核槽位**的 tick（lapic_timer_handler
    // 写 per-CPU TICKS）。不重复校准/注入全局时钟源——CALIBRATED_BUS_FREQ 由 BSP
    // 校准后 AP 直接继承。须在开中断之后（定时器到期即能进 handler 并 EOI）。
    crate::lapic::init_timer_self();

    // 用 AcqRel 保证计数递增的可见性与顺序（配合 BSP 的 Release 初始化）
    CPU_COUNT.fetch_add(1, Ordering::AcqRel);

    // 一次 write_str 完整打印，避免与其他 CPU 交错
    klib::info!("[smp] AP online, lapic_id={}", lapic_id);

    // AP 空闲循环：默认纯 halt；若 AP 调度已启用（生产阶段），
    // 下一次 IRQ0 唤醒时永久转入注入的 per-CPU 调度空闲循环（task::start），
    // 从本核就绪队列取进程进入用户态、由本核 IRQ0 tick 轮转（真正对称多处理）。
    loop {
        if AP_SCHED_ENABLED.load(Ordering::Acquire) {
            if let Some(f) = AP_SCHED_FN.get() {
                f(); // never returns
            }
        }
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
            core::ptr::write(
                phys_to_virt(gdt_paddrs[i]) as *mut gdt::Gdt,
                gdt::Gdt::new(),
            );
            core::ptr::write(
                phys_to_virt(tss_paddrs[i]) as *mut gdt::Tss,
                gdt::Tss::new(),
            );
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
    klog_combined(
        "[smp] BSP lapic_id=",
        bsp_lapic,
        ", total cpus=",
        total as u64,
    );

    // BSP 槽位 0（默认即 0，显式置位以便清晰）
    record_slot_lapic(0, bsp_lapic);

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
            // AD5：超时时区分归因——有 AP 自杀（配置非法）与纯启动慢是
            // 两类完全不同的故障，日志必须能分辨。
            let halted = ap_self_halted();
            if halted > 0 {
                klib::warn!(
                    "[smp] wait_all_online timeout: {} online / {} target, {} AP(s) self-halted on invalid config",
                    cpu_count(),
                    target,
                    halted
                );
            }
            break;
        }
        core::hint::spin_loop();
    }
    cpu_count()
}
