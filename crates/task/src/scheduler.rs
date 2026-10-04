//! 调度器（M4.2）：多进程 RR 轮转。
//!
//! 进程在**用户态**被 LAPIC 定时器中断（IRQ0，100Hz）周期性打断，进入内核后
//! 由 [`tick`] 做时间片切换（ADR-017：内核态被打断的 tick 直接忽略，被动抢占
//! 仅存在于用户态边界）：
//! 1. 把当前运行进程的中断帧（`InterruptFrame`，含用户态 iretq 帧 + 全部寄存器）
//!    拷入其 `saved`，状态置 `Ready` 并入队尾；
//! 2. 从就绪队列队头取下一个进程，把其 `saved` 帧拷回当前中断帧；
//! 3. 保存/恢复 FPU 现场（task1 K2，eager fxsave/fxrstor）、切 CR3（目标进程
//!    用户页表）、切 TSS.RSP0（目标进程独立内核栈）、更新 `CURRENT_PROC`；
//! 4. `interrupt_common_stub` 返回后 `iretq` 直接进入目标进程用户态。
//!
//! 关键设计：
//! - **每进程独立内核栈**：16 帧（64K），经 HHDM 映射为内核半区虚拟地址写入
//!   TSS.RSP0，避免多进程共享中断栈互相覆盖（所有进程页表继承内核半区映射，
//!   可见）。帧生命周期由 [`DEAD_KSTACKS`] 延迟回收队列管理（task1 K3，
//!   S18：分配必有释放路径）；
//! - **每进程独立 FPU 现场**（task1 K2）：eager 全量快照，硬件前提由
//!   `arch_x86_64::interrupts::enable_fpu` 一次性建立；
//! - **每核调度**（阶段2 对称多处理）：每个核用自己的 IRQ0 tick 驱动 [`tick`]，在
//!   自己的 per-CPU 就绪队列上 RR 轮转（对称多处理，进程经 [`spawn_home_cpu`] 分发）；
//! - **首次运行**：进程 `spawn` 时构造"初始帧"（`initial_frame`），故首次调度也走
//!   "从 saved 恢复"，调度逻辑统一；内核 idle 主循环 [`start`] 经 `enter_usermode`
//!   进入第一个就绪进程。
//!
//! 失败模式口径（task1 KM7 成文）：**有界可计数资源**（物理帧、pid、fd 槽位）
//! 的耗尽走 `Result<_, Error>` 优雅上抛；**内核堆**由 buddy 分配器的全局
//! OOM 策略治理（alloc error → 受控停机），不做逐调用点 Result 化——两者是
//! 资源性质不同，不是实现不一致。

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use arch::task::TrapFrame;
use arch::PhysFrame;
use arch_x86_64::fpu::{self, FpuArea};
use arch_x86_64::gdt;
use arch_x86_64::interrupts::InterruptFrame;
use arch_x86_64::paging::X86PageTable;
use klib::error::Error;
use klib::sync::irq::{IrqSpinLock, IrqSpinLockGuard};
use mm::user_space::UserAddressSpace;

use crate::process::{
    Caps, Process, ProcessIdentity, TaskState, clear_current_proc, set_current_proc, user_code_selector,
    user_data_selector, USER_RFLAGS,
};
use crate::signal::{DefaultAction, default_disposition};
use crate::signals::SIGKILL;
use crate::signal_set::NSIG;

/// PCB 内保存的进程名上限；与 shell/ELF 路径缓冲无关，超长名在创建时明确拒绝。
const PROCESS_NAME_MAX: usize = 63;

/// 每进程独立内核栈大小（16 帧 = 64K）。
///
/// M4.2 修复：中断处理（IRQ0 → dispatch → tick）+ debug 构建的
/// `copy_nonoverlapping` 前置检查栈需求大，4K 会溢出（RBP 越界、卡死），
/// 故改用 64K。
const KSTACK_SIZE: usize = 65536;
/// 内核栈分配阶：2^4 = 16 帧。
const KSTACK_ORDER: usize = 4;

/// Round-Robin 时间片长度，单位为 LAPIC tick（当前时钟源为 100Hz）。
///
/// 默认 TCG 档为 10 tick（约 100ms 虚拟时间）：QEMU TCG 可能使虚拟时钟相对
/// 指令执行快进，过短的每 tick 切换会让用户任务在到达有效工作前频繁被抢占。
/// 启用 task crate 的 `real-hw` feature 时使用 1 tick（10ms 真实时间），便于
/// 真机部署者显式选择低延迟档。此处是唯一的时间片参数来源。
#[cfg(not(feature = "real-hw"))]
pub const TIMESLICE_TICKS: usize = 10;

/// 真机时间片档：每个 LAPIC tick 触发一次调度。
#[cfg(feature = "real-hw")]
pub const TIMESLICE_TICKS: usize = 1;

/// `TASK_WAIT(target=WAIT_ANY)` 哨兵：等待任意子进程退出（不限 pid）。
/// 与 ADR-014 既有 `target==0→yield/sleep` 语义零冲突，
/// `usize::MAX` 不可能是合法 pid（单调递增，物理不可达）。
pub const WAIT_ANY: usize = usize::MAX;

/// 单进程槽：进程对象 + 被中断时的完整帧 + 独立内核栈顶。
struct ProcEntry {
    /// 进程控制块（含独立用户地址空间、上下文）。
    proc: Box<Process<X86PageTable>>,
    /// 该进程上次被中断时的完整 `InterruptFrame`（含用户态 iretq 帧 + 寄存器）。
    /// 首次 = `spawn` 时构造的初始启动帧。
    saved: InterruptFrame,
    /// 独立内核栈帧句柄（task1 K3）：分配时的 `PhysFrame` 基址（order 记录在
    /// 分配器元数据中，按基址归还即整块回收）。`kstack_top` 仅供快速取用；
    /// **释放唯一入口是 [`DEAD_KSTACKS`] 队列**，禁止就地 drop 归还——
    /// exit 路径在自身内核栈上执行，见队列文档。
    kstack_frames: PhysFrame,
    /// 独立内核栈顶（TSS.RSP0；该进程用户态中断进入内核时切到此栈）。
    kstack_top: u64,
    /// 每进程 x87/SSE 现场（task1 K2）。spawn 时以 FNINIT 模板初始化，
    /// 每次切出 [`fpu::save`]、切入 [`fpu::restore`]（eager 全量）。
    fpu: FpuArea,
    /// 真实可执行程序名的 UTF-8 字节（固定容量，避免 PCB 额外堆分配）。
    name: [u8; PROCESS_NAME_MAX],
    /// `name` 中有效字节数。
    name_len: u8,
    /// 父进程 pid（C7.1）。`0` = 内核直接创建（无父；如 init、内核测试根进程）。
    /// pid 不复用（`next_pid` 单调递增），故父 pid 恒可用作槽位索引。
    ppid: usize,
    /// zombie 退出码（C7.1）：进程终止时由调度器记录，父进程
    /// `waitpid` 收尸时取走。仅在 `TaskState::Exit`（zombie）期间有意义。
    exit_code: u64,
    /// 本进程阻塞等待退出的子 pid（C7.1 `waitpid` 阻塞时登记）。
    ///
    /// 不变式：`waiting_for.is_some()` ⇒ 本进程 `TaskState::Blocked` 且由
    /// waitpid 机制独占管理（唤醒、清登记、写 `saved.rax` 都在子进程终止
    /// 路径单点完成）。通用 [`wake`] 不得触碰此类进程，
    /// 防止提前唤醒导致其带着未填写的 `saved.rax` 返回用户态。
    waiting_for: Option<usize>,
    /// 本进程的 home（常驻）CPU 槽位（阶段2 对称多处理）：spawn 时按 least-loaded
    /// 选定，唤醒/就绪入队目标固定为 `ready[home_cpu]`；进程只在 home 核被调度。
    /// （跨核唤醒 = 外来核把 pid 塞进本 home 队列并视情发 resched IPI。）
    home_cpu: usize,
    /// 每单元用户态 FS 段基址（IA32_FS_BASE，threads.md T2-0/T2-1，ADR-035 D6）。
    /// 线程 = 指向其用户态 TCB（errno 槽 / TLS 区）；普通单线程进程恒 0（从不写）。
    /// 切出点 rdmsr 归档、切入点 wrmsr 恢复（镜像 FPU eager save/restore 点）——
    /// 保证线程切换后 CPU FS base 恒指向当前单元的 TCB（防旧线程 base 泄漏给无 FS 程序）。
    fs_base: u64,
    /// **EEVDF 虚拟运行时间**（SCHED-EEVDF-2）。单调不减、饱和不回绕。
    ///
    /// 语义：本进程累计获得的 CPU 份额（加权）。**越小越该被调度**。
    /// 保护：**per-pid 桶锁**（不做全局原子，避免新的全局争用点）。
    /// 不变式：只在持有该 pid 桶锁时读写；比较与入队一律使用「读出的快照」。
    vruntime: u64,
    /// **nice 值**（-20..=19，SCHED-EEVDF-3）。越小 = 优先级越高 = 权重越大。
    ///
    /// 保护：与 `vruntime` 同域（per-pid 桶锁）。默认 0（同权，行为与 EEVDF-2
    /// 完全一致——**引入 nice 不改变既有进程的调度行为**，这是可回归的前提）。
    /// 越界输入由 `nice_to_weight` 钳制，故此处不假设取值一定合法。
    nice: i32,
}

/// 已退出进程的内核栈帧延迟回收队列（task1 K3，S18 释放路径的单点实现）。
///
/// **为什么不能就地归还**：`exit_current`/自杀式 `kill_pid` 的清理代码运行在
/// 将死进程**自己的内核栈**上；在该临界区内把栈帧还给 buddy，后续指令就在
/// 已释放内存上执行——正确性悬于"窗口内无人恰好分到这些帧"的时序巧合，
/// 正是审查红线深恶痛绝的隐性不变式。
///
/// 协议：所有槽位置 None 的路径经 [`retire_entry`] 把帧移入本队列；
/// 由**确定不在任何将死栈上执行**的入口统一归还——[`tick`] 顶部（运行于
/// 当前存活进程的中断栈）与 [`spawn_with_ppid`] 入口。有界性：仅退出路径
/// 入队、每次至多 +1，tick 周期（TCG ≤100ms / 真机 10ms）内必然清空；
/// 队列非空增长唯一的可能是中断彻底停摆，那已是系统级失效。
///
/// idle 相位说明（审计 R5-O1）：全系统无用户进程时（如 shell 等待键盘），
/// tick 因 ADR-017 CPL 门控整体早退、跳过 drain——队列滞留至下次 spawn
/// 兜底归还（或测试 reset_all）。滞留帧数以退出路径数为上界，正确性无损，
/// 仅回收时机后移。

/// per-CPU delay-reclaim queue (phase2): the retiring core pushes to its own slot;
/// that same core's tick/spawn drains it (avoids cross-core borrow). Every online core
/// (incl. APs) owns its slot under symmetric multiprocessing. This const-array-of-
/// IrqSpinLock is the per-CPU-lock pattern the per-CPU ready/current split will mirror.
static DEAD_KSTACKS: [IrqSpinLock<Vec<DeadRetire>>; MAX_SCHED_CPUS] =
    [const { IrqSpinLock::new(Vec::new()) }; MAX_SCHED_CPUS];

/// 一个等待归还的退役单元：内核栈帧 + 独立用户地址空间。
///
/// **为什么地址空间也要延迟回收**（与内核栈同源，且更致命）：
///
/// `drop(proc)` 会走 [`UserAddressSpace::destroy`]，其中会释放该进程的**顶层
/// 页表帧**。其判定是 `if top == PT::current_paddr()` —— 只保证**销毁核**不在
/// 用该表。但 CR3 是**每核独立**的：销毁核（收尸的父核）的 CR3 不等于 top，
/// **不代表 home 核的 CR3 也不等于 top**。
///
/// `kill_pid` 跨核终止只是远程置 Exit + 发 IPI；home 核在到达调度点之前，
/// CR3 仍悬在该进程的用户页表上。若父核此刻收尸并立即 drop，顶层表帧被还给
/// buddy（随即被复用/清零），home 核再执行内核代码时高半区映射即失真 ——
/// 实测表现为 `CR2 == RIP` 的**取指缺页**（e.code=0x18：P=1 保护违例 + I/D=1
/// 取指），最终 #PF → #DF → **三重故障重启**（QEMU `-d int` 记录 `Triple fault`）。
///
/// 故地址空间与内核栈必须**同一时机**归还：交给 home 核，在 [`idle_loop_body`]
/// （本核已停在 idle 栈、且已 `switch_to_kernel_root`）统一 drop。
struct DeadRetire {
    /// 该进程的内核栈帧（order 记录在分配器元数据中，按基址整块归还）。
    kstack: PhysFrame,
    /// 该进程的 PCB（持有 `Arc<UserAddressSpace>`；drop 即回收页表与叶帧）。
    proc: Option<Box<Process<X86PageTable>>>,
}

/// 槽位退役单点：FPU 区随 entry 丢弃，内核栈帧入**本进程 home 核**的延迟回收队列，
/// 其余字段（Box<Process> → addr_space Drop）沿用 M5 用户资源回收语义。
///
/// 归属论证（跨核收尸修复）：内核栈只有在"使用它的核已不再运行其上"才能释放。
/// 将死/被收尸进程可能仍物理运行在它的 home 核上（跨核 SIGKILL 后 home 核的
/// deschedule tick 尚未跑到即被父核 waitpid 收尸）。因此栈必须交给 **home 核** 的
/// DEAD_KSTACKS[home] 队列，由 home 核在**确定自己已切下该栈**的时机（A3 go_idle
/// 停车到本核 idle 栈后、或切换到新的存活 current）再 drain 释放——绝不能进
/// 收尸核（可能 != home）的队列被其提前释放成 UAF。同核终止时 home==本核，
/// 语义与旧 `my_cpu_slot()` 一致。
fn retire_entry(entry: Box<ProcEntry>, home_cpu: usize) {
    let ProcEntry {
        proc,
        kstack_frames,
        ..
    } = *entry;
    // **栈与地址空间一起延迟归还，交给 home 核。**
    //
    // 原实现只延迟栈、就地 `drop(proc)`，理由是"该 Drop 只操作 HHDM 映射与
    // 空闲池，不触碰本栈"。该论证只覆盖了**栈**，漏了**页表**：`drop(proc)`
    // 会释放顶层页表帧，而 home 核的 CR3 可能仍悬在该表上（跨核 kill 后
    // home 核尚未到达调度点）。表帧一旦被复用，home 核执行内核代码即取指
    // 缺页 → #DF → 三重故障重启。详见 [`DeadRetire`]。
    DEAD_KSTACKS[home_cpu & (MAX_SCHED_CPUS - 1)]
        .lock()
        .push(DeadRetire {
            kstack: kstack_frames,
            proc: Some(proc),
        });
}

/// 归还延迟队列中的全部内核栈帧。
///
/// **只允许在"本核确定已切下所有将死栈"的入口调用**——当前唯一生产入口是
/// [`idle_loop_body`]（本核已停在 idle 栈上）。测试钩子可对哑进程直接调用。
///
/// **tick 顶部与 spawn 入口都曾调用本函数，都因 UAF 被移除**：
/// 跨核收尸后，将死进程的栈帧进入其 **home 核** 的队列，但 home 核此刻可能
/// **仍运行在那个栈上**（`kill_pid` 只是远程置 Exit + 发 IPI，目标要等本核
/// 调度点才真正切下）。此时若"碰巧也在该核"的调用者（tick 中断或 spawn 的
/// 父进程）drain，就会把本核正在使用的栈还给 buddy，随后 `allocate_frames`
/// 又把它分给新进程 —— 两块逻辑上不同的内核栈叠在同一物理帧上，表现为
/// 随机栈损坏，最终 `raw_serial_fmt` 压栈越界 → #PF → #DF → **三重故障重启**
/// （实测：SIGKILL 风暴 round 1→2 之间平台间歇复位，QEMU `-d int` 记录 Triple fault）。
fn drain_dead_kstacks() {
    let mut q = DEAD_KSTACKS[my_cpu_slot()].lock();
    for entry in q.drain(..) {
        // 先 drop PCB（内含 UserAddressSpace::destroy：释放顶层页表与叶帧），
        // 再归还内核栈帧。顺序有意为之：本核此刻已停在 idle 栈上并已由调用方
        // 切回内核根页表，故销毁页表不会波及正在执行的翻译。
        drop(entry.proc);
        // order 记录在分配器帧元数据中，按基址整块归还（16 帧一次到位）。
        mm::deallocate_frame(entry.kstack);
    }
}

/// "干净浮点上电态"模板（FNINIT 后快照），新 PCB 的初始 FPU 现场。
///
/// 锁序：FPU_TEMPLATE 是叶子锁（临界区仅一次快照拷贝，无反向嵌套）。spawn 路径
/// 由 fpu_template_snapshot 短暂取用——此刻既未取新 pid 的 per-pid 锁、也未取
/// RUN[slot]（快照先于 PROCESSES[pid] 写入完成）。
static FPU_TEMPLATE: IrqSpinLock<Option<FpuArea>> = IrqSpinLock::new(None);

fn fpu_template_snapshot() -> FpuArea {
    let mut t = FPU_TEMPLATE.lock();
    if t.is_none() {
        let mut a = FpuArea::zeroed();
        // 硬件前提 TS=0/EM=0/OSFXSR=1 由 enable_fpu（interrupts::init）保证；
        // 若被破坏此处 #NM 即暴露点（宁可报错）。
        fpu::init_template(&mut a);
        *t = Some(a);
    }
    t.expect("template just initialized")
}

/// 每核紧凑 CPU 槽位的调度状态数组容量（上限 = LAPIC id 全空间 256，
/// 与 arch smp.rs 的 LAPIC_TO_SLOT 及 lapic.rs TICKS[256] 同源）。
/// 所有在线核（含 AP）都使用自己的槽位运行 per-CPU 调度（阶段2 对称多处理）。
const MAX_SCHED_CPUS: usize = 256;

/// 全局单调 pid 分配器（M4.2/阶段2：pid 由核无关的原子单点分配，
/// 保证全系统唯一且单调不复用——ppid=槽位索引不变式不随调度分核而破）。
/// 初值 1：0 保留给“无父”语义。usize::MAX 个并发进程物理不可达（task1 KM6）。
/// S4 观测：最近一次 `wake_enqueue` 是否**尝试**了跨核 IPI 投递。
///
/// 与 `interrupts::resched_ipi_send_count` 的区别：后者只统计**成功**投递。
/// BSP 单核自检阶段（`smp::init` 之前）目标槽位未登记，投递必然失败——此时
/// 「是否尝试」才是 S4 的判据（缺陷版本会因 guard 短路而**根本不尝试**）。
static WAKE_ATTEMPTED_CROSS_CORE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

static NEXT_PID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(1);

/// 分配下一个全局 pid（fetch_add 单调递增）。
///
/// task1 KM6 数值边界论证 + 机器强制：usize::MAX 个并发进程物理不可达——
/// 每个存活 PCB 至少消耗 16 帧内核栈 + 一页堆 + 独立页表页，128M 物理内存在
/// pid 空间耗尽前数十亿倍早于枯竭。取到 usize::MAX 属编程错误/不可达，
/// 受控 panic（ADR-010），绝不静默回绕造成 pid 撞车破坏 ppid=槽位索引不变式。
fn alloc_pid() -> usize {
    NEXT_PID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// 当前执行核的紧凑槽位（决定本核调度状态应读写哪一份 per-CPU 状态）。
///
/// 阶段2 地基：LAPIC 未映射（SMP/调度初始化之前）时恒回退 0 = BSP 槽——
/// 此刻全系统只在 BSP 上做调度决策，槽位语义与既有单核一致。镜像 lapic.rs
/// 的 my_slot()（读本核 LAPIC id，槽位反查表，掩码到数组容量）。
fn my_cpu_slot() -> usize {
    if !arch_x86_64::lapic::is_mapped() {
        return 0;
    }
    arch_x86_64::smp::slot_of_lapic(arch_x86_64::lapic::current_lapic_id()) & (MAX_SCHED_CPUS - 1)
}

/// SMP distribution gate (phase2 M4): once production enables per-AP scheduling,
/// newly spawned processes round-robin onto online cores' ready queues so APs truly
/// run user processes from their own queue. Default off keeps kernel-tests single-core.
static DISTRIBUTE_ACROSS_CPUS: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// 是否已有一个 AP 真正启动过用户进程（对称多处理一次打点用；0 = BSP 永不置位）。
static AP_LAUNCHED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable/disable cross-core spawn round-robin (call once production enables AP scheduling).
pub fn set_distribute_across_cpus(on: bool) {
    DISTRIBUTE_ACROSS_CPUS.store(on, core::sync::atomic::Ordering::Release);
}

/// Choose the new process's home CPU slot: default = creating core; when SMP
/// distribution is on and more than one core is online, pick the least-loaded
/// online core (shortest per-core ready queue + running count) so a process
/// lands on the most idle AP queue. Called from spawn before the new pid's per-pid
/// lock is taken; it reads each per-core ready length by transiently taking each
/// RUN[slot] (slots are distinct locks, dropped before returning, no RUN held on
/// return to the caller).
fn spawn_home_cpu() -> usize {
    if DISTRIBUTE_ACROSS_CPUS.load(core::sync::atomic::Ordering::Acquire) {
        let n = arch_x86_64::smp::total_cpus();
        if n > 1 {
            let mut best = 0usize;
            let mut bl = usize::MAX;
            for c in 0..n {
                let r = run(c);
                let l = r.ready.len() + usize::from(r.current.is_some());
                if l < bl { bl = l; best = c; }
            }
            klib::debug!("[sched] spawn least-loaded home={} (load={}, online={})", best, bl, n);
            return best & (MAX_SCHED_CPUS - 1);
        }
    }
    my_cpu_slot()
}

/// 每核运行态：就绪队列（RR）+ 每核当前运行进程。
///
/// 现状（per-pid 拆锁 + per-CPU 锁域多核语义，见 docs/DESIGN-per-pid-scheduler-lock.md）：
/// 进程表已是每 pid 一把独立锁的 PROCESSES 数组（Option<Box<ProcEntry>> 槽，
/// pid 即下标，逐 pid 分别取锁），**不再有**单一全局进程表门闩；就绪队列与当前
/// 进程按紧凑槽拆入本结构，由 RUN 按槽各自上锁。锁序：凡触碰进程表的函数先取
/// 所涉 pid 的 per-pid 锁（多 pid 按 pid 升序）→ RUN[slot]——绝无 RUN 之后再取 pid
/// 锁，绝不在同一临界区重复锁同域/同 pid（IrqSpinLock 不可重入）；纯 RUN 函数
/// （只读/写本核 ready/current，不触碰 PCB）只取 RUN[my_cpu_slot] 即可。多核对称
/// 处理下每核 AP 用自己的槽位在自己的 IRQ0 tick 上调度本核就绪队列（阶段2 M4 后），
/// 跨核只经目标 pid 锁 + 目标核 RUN[home]（锁序 pid → RUN[home]）协调。
struct PerCpuRun {
    /// 每核就绪队列（**EEVDF**：按 vruntime 排序的最小堆）。索引 = 紧凑 CPU 槽位；
    /// [my_cpu_slot] 为当前核槽位。
    ///
    /// SCHED-EEVDF-2：由 `VecDeque<usize>`（纯 RR FIFO）替换为
    /// [`crate::sched_eevdf::VruntimeQueue`]。**语义差异是刻意的**：
    /// 入队不再固定到队尾，而是按 vruntime 决定位置——vruntime 小者先跑。
    /// 对「新进程 vruntime 取当前最小基准」的处理见 `enqueue_ready`。
    ready: crate::sched_eevdf::VruntimeQueue,
    /// 每核当前运行进程。索引 = 紧凑 CPU 槽位（与 process.rs 的 per-CPU
    /// CURRENT_PROC 同槽同步更新，保持“调度器 current 与裸指针别名”单点对应）。
    current: Option<usize>,
}

impl PerCpuRun {
    const fn new() -> Self {
        Self {
            ready: crate::sched_eevdf::VruntimeQueue::new(),
            current: None,
        }
    }
}

/// 进程表分桶数（B1 无界 pid）。pid 值域独立、单调、不再当下标，按哈希散列到某桶。
/// 分桶是**并发粒度**（每桶一把独立 IrqSpinLock），不是 pid 上限——桶内 BTreeMap 动态增长，
/// pid 值域只受 usize 单调分配限制（物理不可达，同 task1 KM6 论证），**无累计创建上限**
/// （消除旧 MAX_PIDS=8192 的"历史累计 spawn 锁死"缺陷）。并发度 = P_TABLE_STRIPES 条独立
/// 桶锁，保住 S1"无单点全局进程表门闩"；多 pid 争同桶概率 = 同哈希冲突，分桶数增大而降低。
const P_TABLE_STRIPES: usize = 128;

/// 进程池（分桶进程表，B1）：pid -> Box<ProcEntry> 的哈希分桶。
///
/// 锁域纪律（per-pid 化，pid 桶锁 → RUN[slot] 相对顺序）：凡触碰进程表取所涉 pid 所在桶的
/// 桶锁；**多个不同 pid 同桶 = 同一把锁**，故多 pid 区域须先判是否同桶——不同桶按**桶号升序**
/// 取，同桶只取一次（绝不在同区域重复锁同一桶；IrqSpinLock 不可重入）；per-CPU 的 RUN 锁在
/// 桶锁**之后**按既有同序取（pid → RUN），纯 RUN 路径只取 RUN。跨核唤醒/终止经目标 pid 桶锁
/// + 目标 home 核 RUN[home] 协调。
static PROCESSES: [IrqSpinLock<BTreeMap<usize, Box<ProcEntry>>>; P_TABLE_STRIPES] =
    [const { IrqSpinLock::new(BTreeMap::new()) }; P_TABLE_STRIPES];

/// pid → 分桶号。乘黄金比例常数后取高位折半（2 的幂掩码），使连续单调 pid 均匀散布各桶。
fn pid_bucket(pid: usize) -> usize {
    let h = pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (h >> (core::mem::size_of::<usize>() * 8 - 7)) & (P_TABLE_STRIPES - 1)
}

/// 取某 pid 所在桶的桶锁（桶恒存在）。调用方再按 pid 判存在（map get/remove/insert）。
fn proc_bucket_lock(pid: usize) -> IrqSpinLockGuard<'static, BTreeMap<usize, Box<ProcEntry>>> {
    PROCESSES[pid_bucket(pid)].lock()
}


/// 每核就绪队列 + 每核当前运行进程（per-CPU 运行态）。索引 = 紧凑 CPU 槽位。
static RUN: [IrqSpinLock<PerCpuRun>; MAX_SCHED_CPUS] =
    [const { IrqSpinLock::new(PerCpuRun::new()) }; MAX_SCHED_CPUS];


/// 域访问器：取指定槽位的 per-CPU 运行态可变域。若调用方同时访问进程表，
/// 须先取所涉 pid 锁再取本域（锁序 pid → RUN[slot]）；纯 RUN（b）路径可单独取本域。
/// slot 掩码到数组容量。
fn run_mut(slot: usize) -> IrqSpinLockGuard<'static, PerCpuRun> {
    RUN[slot & (MAX_SCHED_CPUS - 1)].lock()
}

/// 域访问器：取指定槽位的 per-CPU 运行态只读视图（仅读场景使用；
/// 与 run_mut 同域同锁，锁序一致）。
fn run(slot: usize) -> IrqSpinLockGuard<'static, PerCpuRun> {
    RUN[slot & (MAX_SCHED_CPUS - 1)].lock()
}

/// 生产 init 进程的 PID（由 `start_init` 在 spawn 后登记）。
/// 测试模式经 `test_hooks::reset_all` 复位为 0。`0` = 未登记（不保护）。
static INIT_PID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 登记 init 进程的 PID。必须在 `start_init` 中 spawn init 后立即调用。
pub fn set_init_pid(pid: usize) {
    INIT_PID.store(pid, core::sync::atomic::Ordering::Release);
}

/// 返回已登记的 init 进程 PID；`0` 表示未登记（测试模式或未初始化）。
pub fn init_pid() -> usize {
    INIT_PID.load(core::sync::atomic::Ordering::Acquire)
}

/// 构造"初始中断帧"（模拟进程首次被调度前的中断保存点，供首次从 saved 恢复）。
/// `initial_rdi` 为新单元首跑时 `rdi` 初值（T2-0：线程经 a3 传 starter/TCB 引导指针；
/// 普通 spawn 传 0，保持现状"其余 GPR=0"）。
fn initial_frame(entry_rip: u64, user_stack_top: u64, initial_rdi: u64) -> InterruptFrame {
    InterruptFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: initial_rdi,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: entry_rip,
        // task1 KM5：段选择子/RFLAGS 单点构造（process.rs）。
        cs: user_code_selector() as u64,
        rflags: USER_RFLAGS,
        rsp: user_stack_top,
        ss: user_data_selector() as u64,
    }
}

/// 创建一个进程并入调度器就绪队列。
///
/// 为该进程分配**独立内核栈**（1 物理帧，经 HHDM 映射到内核半区），并初始化
/// "启动帧"（供首次调度从 saved 恢复）。返回 pid。内核直接创建的进程无父
/// （`ppid = 0`）；由用户进程派生的子进程须走 [`spawn_with_ppid`]。
pub fn spawn(
    name: &str,
    entry_rip: u64,
    user_stack_top: u64,
    addr_space: UserAddressSpace<X86PageTable>,
) -> Result<usize, Error> {
    spawn_with_ppid_fds(0, name, entry_rip, user_stack_top, addr_space, 0, None, ProcessIdentity::default_user())
}

/// 校验并拷贝程序名进定长 PCB 缓冲。
///
/// 空名、超长名或非法 UTF-8 一律拒绝——PCB 不允许出现占位名或被截断的假名。
fn store_name(name: &str) -> Result<([u8; PROCESS_NAME_MAX], u8), Error> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > PROCESS_NAME_MAX || core::str::from_utf8(bytes).is_err() {
        return Err(Error::InvalidParam);
    }
    let mut buf = [0u8; PROCESS_NAME_MAX];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok((buf, bytes.len() as u8))
}

/// 带 fd 表继承的 spawn（pipe-features 方案 A）。`None` 等价于 [`spawn`]
/// （新进程独立标准流表）；`Some(inherited)` 时子进程以父进程 fd 表启动，
/// 供管道 `A | B` 把前段 stdout / 后段 stdin 重定向到 pipe 端。pipe 端引用
/// 计数由调用方（kernel syscall 层）在克隆表后递增（task 不依赖 ipc）。
pub fn spawn_with_ppid(
    ppid: usize,
    name: &str,
    entry_rip: u64,
    user_stack_top: u64,
    addr_space: UserAddressSpace<X86PageTable>,
) -> Result<usize, Error> {
    spawn_with_ppid_fds(ppid, name, entry_rip, user_stack_top, addr_space, 0, None, ProcessIdentity::default_user())
}

/// 带 fd 表继承的 spawn 公开形态（pipe-features 方案 A）。`None` 等价于
/// [`spawn_with_ppid`]（新进程独立标准流表）；`Some(inherited)` 时子进程以
/// 父进程 fd 表启动，供管道 `A | B` 把前段 stdout / 后段 stdin 重定向到
/// pipe 端。pipe 端引用计数由调用方（kernel syscall 层）在克隆表后递增
/// （task 不依赖 ipc）。
pub fn spawn_with_ppid_fds(
    ppid: usize,
    name: &str,
    entry_rip: u64,
    user_stack_top: u64,
    addr_space: UserAddressSpace<X86PageTable>,
    trampoline: u64,
    inherited_fds: Option<alloc::vec::Vec<Option<vfs::file_handle::OpenHandle>>>,
    identity: ProcessIdentity,
) -> Result<usize, Error> {
    // **此处不得 drain 内核栈**（task1 K3 的"延迟回收先于新分配"已被推翻）。
    //
    // 原意图是提高 spawn 在内存压力下的成功率，但前提是错的：本函数运行在
    // **调用者（父进程）的内核栈**上，而队列里的栈属于被杀进程的 **home 核**。
    // 父核与 home 核相同时（风暴里 init 的多次 spawn 正是如此），drain 会把
    // **本核可能仍在使用的**栈帧还池，紧接着下方 `allocate_frames(KSTACK_ORDER)`
    // 又把它分给新进程 → 两栈叠帧 → 栈损坏 → 三重故障重启。
    //
    // `kill_pid` 只是远程置 Exit + 发 IPI，目标进程要等其 home 核到达调度点
    // 才真正切下；故"进程已 Exit"**不等于**"其栈已可回收"。回收统一交给
    // [`idle_loop_body`]（本核停在 idle 栈时，确定已切下一切）。
    let (name_buf, name_len) = store_name(name)?;
    // 父必须真实存在且非 zombie，否则拒绝建立虚假父子关系（零伪数据）。
    // 分桶化：父须实际在册（map 中存在）且非 zombie；否则视同无父/不存在。
    if ppid != 0 {
        let ok = proc_bucket_lock(ppid)
            .get(&ppid)
            .map(|p| p.proc.state() != TaskState::Exit)
            .unwrap_or(false);
        if !ok {
            return Err(Error::NotFound);
        }
    }
    let pid = alloc_pid();
    // 分配独立内核栈（16 帧；HHDM 高半区在所有进程页表继承可见）。
    let stack_frame = mm::allocate_frames(KSTACK_ORDER).ok_or(Error::OutOfMemory)?;
    let kstack_top = arch::phys_to_virt(stack_frame.start_paddr()) + KSTACK_SIZE as u64;
    // ADR-034 PRE-3：exec 路径（spawn_elf_image）已把 restorer 装进用户地址空间
    // 保留区并传入 `trampoline` 地址；此处仅登记到进程信号状态。test-only 路径
    // 传 0（无 restorer），保持哑地址空间记账不变。
    // ADR-035 D4：PCB 内部经 Arc 持地址空间；此处把 spawn 传入的空间包成唯一 Arc
    // （地基阶段一进程一份；组共享派生留给 T1，届时传同一 Arc 的 clone）。
    // 3P4-1：主线程 TLS 的 FS base 随地址空间携带，必须在**入队前**写进 PCB。
    // 若改为 spawn 返回后再设，入队与设置之间存在竞态窗口（别的核可能已切入该
    // 进程并以 fs_base=0 运行），首次 fs: 访问即 #PF。
    let tls_fs_base = addr_space.tls_fs_base();
    let mut proc = Box::new(Process::<X86PageTable>::new(
        pid,
        entry_rip,
        user_stack_top,
        kstack_top,
        Arc::new(addr_space),
    ));
    proc.signal_mut().set_trampoline(trampoline);
    // 管道方案 A：注入父进程继承的 fd 表（若提供）。非空才替换（空表保留
    // 默认标准流）。pipe 端引用计数已由 syscall 层在克隆时递增，此处仅挂表。
    if let Some(fds) = inherited_fds {
        proc.set_inherited_fd_table(fds);
    }
    // A1 / ADR-033：注入子进程身份（init 引导特权或父进程继承值）。
    proc.set_identity(identity);
    // 阶段2（M4）：决定本进程 home（常驻）核。缺省 = 创建核；对称多处理使能后
    // 选当前就绪队列最短（最空闲）的在线核，使进程落到某 AP 队列、由该 AP 调度。
    let home_cpu = spawn_home_cpu();
    let entry = Box::new(ProcEntry {
        proc,
        saved: initial_frame(entry_rip, user_stack_top, 0),
        kstack_frames: stack_frame,
        kstack_top,
        fpu: fpu_template_snapshot(),
        name: name_buf,
        name_len,
        ppid,
        exit_code: 0,
        waiting_for: None,
        home_cpu,
        fs_base: tls_fs_base,
        // 新进程 vruntime 先置 0；真正入队时由 `enqueue_ready(is_new=true)`
        // 改写到「当前最小基准」，避免新进程凭空获得优先权。
        vruntime: 0,
        // EEVDF-3：默认 nice 0 = 同权，既有进程行为不变。
        nice: 0,
    });
    // 分桶化：把入口按 pid 写入其所在桶（堆分配 Box，地址稳定）；桶锁随即释放
    // 再入队 home 核（pid 桶 → RUN 锁序：桶锁释放后再取 RUN，不同时持有）。
    proc_bucket_lock(pid).insert(pid, entry);
    // 阶段2（M4）：新进程直接入队其 home 核就绪队列——使每核就绪队列真正各自
    // 承运转到本核的进程（对称多处理），而非一律落在创建核。进程运行中阻塞后再
    // 唤醒仍回 home 核队列（跨核唤醒），实现按核常驻。入队走 RUN[home_cpu] 域
    // （pid 锁已释放，再取 RUN；home 可能非本核）。
    // EEVDF：统一入队口，首次入队 vruntime 取当前最小基准。
    enqueue_ready(&mut run_mut(home_cpu), pid, true);
    Ok(pid)
}
/// 线程派生（T1-1 / ADR-035 D1/D2 / threads.md T1-1）：在组长 `tgid` 所在的线程组内
/// 派生一个**新的同组调度单元**（线程）。
///
/// **组长与组员语义**：组长 = 该地址空间首建进程（tgid == 其 pid）。本函数以组长的
/// 组容器 clone（`Arc::clone`）共享 fd_table/cwd/identity/addr_space，为组员装配
/// **各自独立**的 pid/kstack/saved/FPU/entry/user_stack/state/context/signal，再登记
/// 入分桶进程表并入队 home 核就绪队列。组员 tgid = 组长 pid；组员 ppid = 组长 pid
/// （线程是组长的"成员"关系，非 waitpid 亲子关系；组长/组员共享地址空间即一组）。
///
/// 与 `spawn_with_ppid_fds`/spawn_elf_image 的分工：后两者是**新地址空间 + load ELF**
/// 的组长 spawn（自建独立组）；线程派生**不建新地址空间、不 load ELF**，只 reuse
/// 组长地址空间并 clone 其组容器。真正的 syscall 出口留 T1-7；本步提供 task 层可测
/// 原语 + kernel-tests 直接调用验证。
///
/// `name` 为线程可执行名（PCB 定长缓冲）；`entry_rip`/`user_stack_top` 为该线程
/// 各自的首跑入口与用户栈顶。返回新线程 pid。
pub fn spawn_thread_with(
    tgid: usize,
    name: &str,
    entry_rip: u64,
    user_stack_top: u64,
    starter: u64,
) -> Result<usize, Error> {
    // 同 `spawn_with_ppid_fds`：此处**不得** drain 内核栈。本函数运行在调用
    // 者的内核栈上，而队列中的栈属于被收尸进程的 home 核；两者同核时会把
    // 本核仍在使用的栈还池，紧接着的栈分配即与其叠帧 → 栈损坏 → 三重故障重启。
    // 回收统一交给 `idle_loop_body`（本核停在 idle 栈时，确定已切下一切）。
    let (name_buf, name_len) = store_name(name)?;
    // 组长必须真实在册且非 zombie（零伪数据：找不到组长/组长已退出则拒绝派生）。
    // 锁序：仅短暂持组长所在桶锁快照其组容器 Arc 与信号 restorer 地址，随即释放；
    // 之后不持组长锁再取新 pid 锁（与 spawn_with_ppid_fds 同款 pid 桶 → RUN 锁序）。
    let (group, trampoline) = {
        let g = proc_bucket_lock(tgid);
        let Some(leader) = g.get(&tgid) else {
            return Err(Error::NotFound);
        };
        if leader.proc.state() == TaskState::Exit {
            return Err(Error::NotFound);
        }
        // clone 组长组容器 Arc（共享 fd/cwd/identity/addr_space 的核心动作）。
        (leader.proc.thread_group_arc(), leader.proc.signal().trampoline())
    };
    let pid = alloc_pid();
    // 3P4-1：为组员建立**独立**的 TLS 块（须在 `group` 被 Process::with_group 移走之前）。
    // 模板随组长地址空间携带；每执行单元一块、内容各自独立——这正是"跨线程独立"
    // 的实现点。镜像无 PT_TLS 时 fs_base = 0（该线程不做 fs: 访问，与既有行为一致）。
    let member_fs_base = match group.addr_space().tls_params() {
        Some(p) => group.addr_space().alloc_tls_block(&p)?,
        None => 0,
    };
    // 分配组员独立内核栈（16 帧，同组长；HHDM 高半区共享页表可见）。
    let stack_frame = mm::allocate_frames(KSTACK_ORDER).ok_or(Error::OutOfMemory)?;
    let kstack_top = arch::phys_to_virt(stack_frame.start_paddr()) + KSTACK_SIZE as u64;
    let mut proc = Box::new(Process::<X86PageTable>::with_group(
        pid,
        tgid,
        entry_rip,
        user_stack_top,
        kstack_top,
        group,
    ));
    // PRE-5：signal 每进程独立；组员继承组长已装进共享地址空间保留区的 restorer 地址
    //（SignalState 各持一份，地址同，指向共享地址空间的 restorer 区）。
    proc.signal_mut().set_trampoline(trampoline);
    // 线程不与 spawn 子进程共享 waitpid 亲子语义；ppid 置组长 pid 使"线程属于组长"
    // 关系可追溯（T1-3 组退出时再按组批量终止，本步不在此改动 signal/终止语义）。
    let home_cpu = spawn_home_cpu();
    let entry = Box::new(ProcEntry {
        proc,
        saved: initial_frame(entry_rip, user_stack_top, starter),
        kstack_frames: stack_frame,
        kstack_top,
        fpu: fpu_template_snapshot(),
        name: name_buf,
        name_len,
        ppid: tgid,
        exit_code: 0,
        waiting_for: None,
        home_cpu,
        fs_base: member_fs_base,
        vruntime: 0,
        nice: 0,
    });
    proc_bucket_lock(pid).insert(pid, entry);
    // EEVDF：首次入队走统一入队口（vruntime 取当前最小基准，非 0）。
    enqueue_ready(&mut run_mut(home_cpu), pid, true);
    Ok(pid)
}

// ---------- COW 派生子进程（ADR-038 / kernel-tests M5+） ----------

/// `derive` 内核原语：以 `ppid` 为父，**COW 派生**一个独立线程组的新子进程（ADR-038）。
///
/// 与 [`spawn_with_ppid_fds`] / [`spawn_thread_with`] 的语义分工：
/// - `spawn_with_ppid_fds`：**新地址空间 + load ELF**（等价 `exec`）。子进程从
///   ELF 入口开始，与父无共享；
/// - `spawn_thread_with`：**同组**新调度单元（线程）。共享组长地址空间（`Arc::clone`）；
/// - 本函数：**新组**新子进程，用户地址空间经 [`UserAddressSpace::clone_cow`] 与父
///   **共享物理帧**（写时复制），即 POSIX `fork` 的内核语义。子进程**不**从入口开始，
///   而是从父被 syscall 中断处继续（首跑帧 = 父帧的副本，`rax` 改写为 0）。
///
/// # 返回语义（POSIX fork 铁律）
///
/// 本函数只负责**创建**；「父收 pid、子收 0」的分流由调用方（kernel syscall 层）
/// 在返回给父的帧里写 pid 完成——子进程的首跑帧已在此处固定 `rax = 0`。
///
/// # 失败路径（S20：失败路径优先设计）
///
/// 本函数**要么完全成功，要么不留任何痕迹**。各步失败点与其回滚：
/// 1. 父不存在/已 Exit → `NotFound`（无副作用）；
/// 2. `clone_cow` 失败（无帧/页表拆分 OOM）→ `clone_cow` 内部已回滚父侧只读位与
///    incref，此处直接上抛，父进程状态不变；
/// 3. 内核栈分配失败 → `OutOfMemory`。此时 `clone_cow` **已成功**，子地址空间
///    持有父帧的 incref 引用——**必须显式释放**，否则父帧引用计数永久泄漏
///    （父退出时帧不归还）。由下方 `drop(child_space)` 承担：
///    `UserAddressSpace::drop` 走 destroy 路径按 kind 归还帧，与失败前状态对称；
/// 4. pid 分配（`alloc_pid`）在栈之后，无额外失败点。
///
/// # 多线程父进程
///
/// 若父所在线程组有**多于一个存活成员**，如实返回 `NotSupported`——ADR-038 决策 4：
/// 仅复制调用线程的执行现场，其余线程在子进程内不存在，而它们持有的用户态锁/
/// 不变式状态在子进程里会永久悬空。宁可如实拒绝，绝不静默产出一个语义残缺的子进程。
///
/// # 锁序（S21）
///
/// 全程遵守既有 `桶锁 → RUN 锁` 顺序（与 `spawn_with_ppid_fds` 同）：
/// 先短持父桶锁取组容器信息并释放，再 `clone_cow`（持父地址空间 `core` 锁），
/// 最后取新 pid 桶锁插入、再取 RUN 入队。**不同时持有**桶锁与 RUN 锁。
#[allow(clippy::too_many_arguments)]
pub fn spawn_derived(
    ppid: usize,
    name: &str,
    first_run_frame: InterruptFrame,
) -> Result<usize, Error> {
    let (name_buf, name_len) = store_name(name)?;
    // 阶段 1：校验父在册、非 Exit，并快照其组共享态（fd 表 / cwd / identity /
    // 地址空间）与组内成员数。**父桶锁在本块结束即释放**——后续 clone_cow 需要
    // 取父地址空间的 core 锁，若此处仍持桶锁则形成 桶锁→core 的嵌套（S21 禁止）。
    // **顺序至关重要（S21 / 自身死锁教训）**：`group_members` 会遍历并逐桶加锁
    // ——其中**包含 `ppid` 所在桶**。`proc_bucket_lock` 是不可重入自旋锁，若在
    // 已持 `ppid` 桶锁的临界区内调用它，本核会自旋等待自己已持有的锁 → 永久
    // 死锁（单核下表现为整机静默挂起）。故成员数必须在**取任何桶锁之前**求得。
    // 含组长自身，故单线程父 == 1。
    let member_count = group_members(ppid).len();
    let (fd_table, cwd, identity, trampoline) = {
        let g = proc_bucket_lock(ppid);
        let Some(leader) = g.get(&ppid) else {
            return Err(Error::NotFound);
        };
        if leader.proc.state() == TaskState::Exit {
            return Err(Error::NotFound);
        }
        (
            leader.proc.clone_fd_table(),
            leader.proc.cwd(),
            leader.proc.identity(),
            leader.proc.signal().trampoline(),
        )
    };
    // ADR-038 决策 4：多线程父进程如实拒绝（见函数文档）。
    // 注意顺序：本判定在快照之后，是为了让「父不存在」优先于「父多线程」报错
    // （NotFound 比 NotSupported 更具体地指向调用方的真实错误）。
    if member_count != 1 {
        return Err(Error::NotSupported);
    }
    // 阶段 2：COW 克隆父地址空间。失败时 clone_cow 自身已回滚（见其文档），
    // 父状态不变，直接上抛。
    let child_space = {
        let g = proc_bucket_lock(ppid);
        let Some(leader) = g.get(&ppid) else {
            return Err(Error::NotFound);
        };
        leader.proc.addr_space().clone_cow().map_err(Error::from)?
    };
    // 阶段 3：为子进程分配独立内核栈。**这是 clone_cow 之后唯一的失败点**；
    // 失败必须归还子地址空间（否则父帧 incref 泄漏，见函数文档第 3 点）。
    let stack_frame = match mm::allocate_frames(KSTACK_ORDER) {
        Some(f) => f,
        None => {
            // 显式释放：drop 走 destroy 路径按 kind 归还全部帧并递减父帧 incref。
            drop(child_space);
            return Err(Error::OutOfMemory);
        }
    };
    let kstack_top = arch::phys_to_virt(stack_frame.start_paddr()) + KSTACK_SIZE as u64;
    let pid = alloc_pid();
    // 阶段 4：装配子 PCB。`Process::new` 自建**全新独立组**（默认标准流表 + `/`
    // cwd + 默认身份），随后逐项注入从父快照来的 fd/cwd/identity —— 这正是
    // 「新组 + 深拷贝共享态」与线程「同组 + Arc 共享」的关键区别：子进程改 cwd
    // 或关 fd **不影响父**（POSIX fork 语义），而线程会互相影响。
    let mut proc = Box::new(Process::<X86PageTable>::new(
        pid,
        first_run_frame.rip,
        first_run_frame.rsp,
        kstack_top,
        Arc::new(child_space),
    ));
    // fd 表深拷贝的语义：`clone_fd_table` 只做结构性克隆（`OpenHandle` 的
    // `Clone`），**pipe 端引用计数递增不在 task 层**——由 kernel syscall 层在
    // 本函数返回后对每个 `Pipe { id }` 调 `ipc::pipe_ref_inc`（task 不依赖 ipc，
    // 见 `spawn_with_ppid_fds` 同款注释）。
    proc.set_inherited_fd_table(fd_table);
    proc.set_cwd(cwd);
    proc.set_identity(identity);
    // 信号：子进程继承父已装进**共享地址空间保留区**的 restorer 地址（地址同，
    // 因 COW 子空间与父共享该页）。同样与线程路径一致。
    proc.signal_mut().set_trampoline(trampoline);
    let home_cpu = spawn_home_cpu();
    let entry = Box::new(ProcEntry {
        proc,
        // 子进程首跑帧 = 父被 syscall 中断处的帧副本（**这是 fork 的核心**：子进程
        // 从父的当前位置继续执行，而非从入口）。`rax` 已由调用方置 0 —— 子进程
        // 从 syscall 返回时收 0（POSIX fork 铁律）。
        saved: first_run_frame,
        kstack_frames: stack_frame,
        kstack_top,
        fpu: fpu_template_snapshot(),
        name: name_buf,
        name_len,
        // **亲子关系**：ppid = 调用父 pid，使 waitpid 能收到子进程（与线程的
        // ppid = tgid 的「属于组长」关系不同——子进程是真正的 waitpid 亲子）。
        ppid,
        exit_code: 0,
        waiting_for: None,
        home_cpu,
        fs_base: 0,
        vruntime: 0,
        nice: 0,
    });
    proc_bucket_lock(pid).insert(pid, entry);
    enqueue_ready(&mut run_mut(home_cpu), pid, true);
    Ok(pid)
}

// ---------- T1-2 线程组成员关系查询（ADR-035 D2 / threads.md T1-2） ----------

/// 组内遍历：返回线程组 `tgid`（组长 pid）的全部成员 pid（含组长自身）。
///
/// 成员判定：`ProcEntry.proc.tgid() == tgid`。组长自身 `tgid == 其 pid`，故组长
/// 也落入本集合——组与组长 pid 一一对应，组的全量成员 = 进程表内所有 tgid 等于组长
/// pid 的调度单元。供 T1-3 组退出（整组终止/收继）与 T1-2 组关系统计用。
///
/// 锁纪律（S21）：逐桶持锁**仅收集**成员 pid 后随即释放，返回 pid 集合；调用方在
/// 无桶锁现场按需逐 pid 处理（与孤儿级联 collect-then-act 同款）。
pub fn group_members(tgid: usize) -> Vec<usize> {
    let mut members = Vec::new();
    for bucket in PROCESSES.iter() {
        let gi = bucket.lock();
        for (p, e) in gi.iter() {
            if e.proc.tgid() == tgid {
                members.push(*p);
            }
        }
    }
    members
}

/// 线程组 `tgid` 的存活（非 Exit）成员数（含组长自身）。
///
/// T1-3 组长退出整组终止前用：组长 exit 须等组内其余线程也已终止，组才算全退；
/// 存活成员数为 0（组长为唯一成员或组已空）即整组已可回收。
pub fn group_live_count(tgid: usize) -> usize {
    group_members(tgid)
        .into_iter()
        .filter(|&m| {
            proc_bucket_lock(m).get(&m).map(|e| e.proc.state() != TaskState::Exit).unwrap_or(false)
        })
        .count()
}

/// 组是否全退：线程组 `tgid` 无任何存活成员（含组长自身）。空组按已全退处理。
pub fn group_all_exited(tgid: usize) -> bool {
    group_live_count(tgid) == 0
}

/// 是否组长：pid 的 tgid 等于其自身 pid（组长 = 组的创建者/代表）。
pub fn is_group_leader(pid: usize) -> bool {
    let b = proc_bucket_lock(pid);
    b.get(&pid).map(|e| e.proc.tgid() == pid).unwrap_or(false)
}
/// ---- SCHED-EEVDF-2：vruntime 记账 ----
///
/// ## 记账模型（为什么是「按已运行时间折算」而不是直接累加墙上时间）
///
/// EEVDF 的 vruntime 是 **加权**运行时间：`vruntime += elapsed * (NICE_0_WEIGHT / w)`。
/// 权重 `w` 越大（优先级越高），同样的 `elapsed` 折算出的 vruntime 增量越小，
/// 因而越「不着急」，可以跑更久。SCHED-EEVDF-3 引入 nice 后由 `weight_of` 提供
/// `w`；本阶段（2）尚无 nice，全部进程同权，故 `w == NICE_0_WEIGHT`，折算比为 1，
/// vruntime 即「实际运行的 tick 数」。**这是刻意的分步**：先让记账正确且可验证，
/// 再引入权重（S24：单组件变更可独立验证）。
///
/// ## 记账点（为什么记在切出、而不是记在 tick 顶部）
///
/// 记在切出点时，`elapsed` 恰好等于「本进程本次连续运行了多久」，语义精确，
/// 且与「谁真的用了 CPU」天然对齐。若记在 tick 顶部，则被抢占但未真正切走的
/// 情形（`NothingSelf`/`Empty`）也会被计入，导致 vruntime 虚增。
///
/// ## 并发（S21）
///
/// vruntime 存放于 **per-pid 桶锁** 保护的 `ProcEntry.vruntime`，不做全局原子。
/// 记账必须在该 pid 的桶锁内完成，避免与他核的唤醒/收尸交错。
/// nice 0 的基准权重由 `sched_eevdf` 单点提供（S13）——本模块不再直接引用该常量，
/// 折算全部经 `sched_eevdf` 的接口完成，避免权重语义出现第二个来源。

/// 单次 tick 折算出的 vruntime 增量（**按进程权重**）。
///
/// EEVDF-3：由固定折算比改为按 `weight` 折算。`weight` 越大（nice 越小 / 优先级
/// 越高）→ 增量越小 → vruntime 增长越慢 → 越常被选中。方向由
/// `test_sched_eevdf3_nice_weights` 钉死（该方向写反不会在功能测试中暴露，只在
/// 混合负载下表现为「交互更卡」）。
#[inline]
fn vruntime_charge(weight: u64) -> u64 {
    crate::sched_eevdf::weight_charge(1, weight)
}

/// 把 `pid` 的 vruntime 累加 `delta`（饱和不回绕，S19）。须在 pid 桶锁内调用。
fn charge_vruntime_locked(slot: &mut ProcEntry, delta: u64) {
    slot.vruntime = crate::sched_eevdf::vruntime_add(slot.vruntime, delta);
}

/// 就绪队列的**最小 vruntime 基准**：新就绪的进程以此为起点，避免「新进程
/// vruntime=0 从而长期霸占 CPU」这一经典 EEVDF/CFS 缺陷。
///
/// 队列为空时取 `current` 的 vruntime，仍为空则取 0。
fn min_vruntime_base(run: &PerCpuRun) -> u64 {
    if let Some(v) = run.ready.min_vruntime() {
        return v;
    }
    match run.current {
        Some(c) => proc_bucket_lock(c).get(&c).map(|s| s.vruntime).unwrap_or(0),
        None => 0,
    }
}

/// 统一的就绪入队口：**所有**入队都必须经此，以便集中维护 vruntime 语义。
///
/// `is_new` = 该进程是首次进入就绪态（spawn）还是被唤醒/让出后重新入队。
/// 两者语义不同：
///   - **首次**：vruntime 取当前最小基准（不取 0，防霸占）；
///   - **重新**：保留既有 vruntime（它是「已消耗的 CPU 份额」的历史，不能重置，
///     否则长期占用 CPU 的进程每次让出都清零、重新获得优先权 → 饿死他人）。
fn enqueue_ready(run: &mut PerCpuRun, pid: usize, is_new: bool) {
    let base = min_vruntime_base(run);
    let vt = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            Some(slot) => {
                if is_new {
                    // 新进程从当前最小基准起步（等价于 CFS 的 `place_entity`）。
                    slot.vruntime = base;
                }
                slot.vruntime
            }
            // 槽已不存在（被跨核 reap）：不入队，调用方按既有竞态语义处理。
            None => return,
        }
    };
    run.ready.insert(pid, vt);
}

/// **无锁**就绪入队：调用方已持有该 pid 的桶锁（或已取好 vruntime 快照）时使用。
///
/// ## 为什么必须有无锁变体（S21：锁序纪律）
///
/// `block_current_locked` 在**已持 `cur_pid` 桶锁**的临界区内，需要把先前弹出的
/// `peer` 放回就绪队列（登记失败/cur 已 Exit 两条回滚路径）。若此处调用会自行
/// 取 `peer` 桶锁的 [`enqueue_ready`]，而 `peer` 与 `cur_pid` 恰好散列到**同一桶**，
/// 就会在同一临界区内重复获取同一把 `IrqSpinLock`（不可重入）→ **自死锁**，且此时
/// 中断已关，表现为整机挂死。
///
/// 这不是理论风险：`cur`/`peer` 由同一父进程连续 spawn，pid 相邻、散列到同桶的
/// 概率不低 —— 实测中 `test-block-register-false` 正是这样卡死的。
///
/// 原实现用 `push_back`（纯 RUN 操作、**不取任何 pid 锁**）所以从未暴露该问题；
/// 本变体保持同样的「调用方自持锁」契约。
fn enqueue_ready_with_vruntime(run: &mut PerCpuRun, pid: usize, vt: u64) {
    run.ready.insert(pid, vt);
}

/// 从就绪队列移除（幂等；不在队列中返回 false）。
fn dequeue_ready(run: &mut PerCpuRun, pid: usize) -> bool {
    run.ready.remove(pid)
}

/// 设置进程 nice 值（-20..=19）。返回**实际生效**的 nice（已钳制）。

/// ## 语义与边界（S18/S19）

/// - 越界输入**钳制**到 [-20, 19] 而非报错：nice 来自用户态，越界不应能打挂内核；
///   钳到最近合法档是「最接近用户意图」的确定性行为。
/// - 进程不存在（被 reap）返回 `None`，不 panic。
/// - **不重置 vruntime**：nice 是「未来如何折算」，不是「过去欠了多少」。若在此
///   清零，提高优先级会同时抹掉历史欠账，等于双重奖励，且可被反复利用来霸占 CPU。
pub fn set_nice(pid: usize, nice: i32) -> Option<i32> {
    let clamped = nice.clamp(-20, 19);
    let mut g = proc_bucket_lock(pid);
    let slot = g.get_mut(&pid)?;
    slot.nice = clamped;
    Some(clamped)
}

/// 读取进程 nice 值（不存在返回 `None`）。
pub fn nice_of(pid: usize) -> Option<i32> {
    proc_bucket_lock(pid).get(&pid).map(|s| s.nice)
}

/// 当前就绪进程数（诊断）。
#[allow(dead_code)]
pub fn ready_count() -> usize {
    run(my_cpu_slot()).ready.len()
}

/// 调度器 tick（注册为 `register_scheduler_tick`，每个核自己的 IRQ0 后调用，per-CPU）。
///
/// RR 轮转：保存当前进程帧并入队尾，取队头下一个进程；改写中断帧 + 切 CR3 +
/// 切 TSS.RSP0，使 `interrupt_common_stub` 返回后 iretq 进入目标进程用户态。
/// 仅当前进程自身（单进程）时不做无谓切换。
/// 调度 tick 计数（时间片控制）。
static TICK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub extern "C" fn tick(frame: &mut InterruptFrame) {
    // ADR-017（task1 K1）：被动抢占仅存在于用户态边界。内核态被打断的
    // tick 整体不可见于调度决策——不推进时间片计数、不改任何调度状态。
    // 计数语义随之成文：TIMESLICE_TICKS 度量的是进程的**用户态**进度。
    if frame.cs & 3 != 3 {
        return;
    }
    // 延迟回收已移出 tick 顶部：跨核收尸后进程栈入 home 核 DEAD_KSTACKS，
    // 本核此刻可能仍运行在当前(被收尸)进程栈上，顶部 drain 会释放本核当前栈→UAF。
    // 改在确定已切下所有将死栈的时机回收：idle_loop_body 与 RR 切换成功后。

    // S1-8 触发点 1（ADR-034 §2.4）：tick 返回用户态前派发待投递信号。
    // 放在时间片 RR 切换之前：若当前进程有待投递信号，先投递（可能把帧
    // 改写进用户 handler），而非抢占切换。`deliver_on_return` 的默认终止
    // 路径经 exit_current 内部自行取各 per-pid 锁，故此处不持任何调度锁调用。
    {
        use crate::signal::{DeliveryOutcome, deliver_on_return};
        if let Some(cur) = crate::process::current_proc_mut() {
            if !cur.signal().pending().is_empty() {
                match deliver_on_return(cur, frame) {
                    DeliveryOutcome::Terminated => return, // 已切走，调度接管
                    DeliveryOutcome::Continue => {
                        // 若已进入 handler（in_signal=true），让 handler 先运行，
                        // 本轮不抢占；否则无实际投递，落回下方 RR 逻辑。
                        if cur.signal().in_signal() {
                            return;
                        }
                    }
                }
            }
        }
    }

    let n = TICK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n % TIMESLICE_TICKS != 0 {
        return;
    }

    let cpu_slot = my_cpu_slot();
    // per-pid（a）：RR 切换只需当前进程 cur 与下一进程 next 各自的 per-pid 锁
    // （逐访问点短暂取放）+ 本核 RUN 域；已无全局 PROCS。
    let mut run = run_mut(cpu_slot);

    // 仅当有用户进程运行（current=Some）时才在 tick 里做 RR 切换。
    // 内核 idle/主线程（current=None）不做切换：此时若切走会丢弃主线程
    // 上下文（M4.2 关键修复——否则主线程在启动过程中被 IRQ0 切到用户进程，
    // 剩余 spawn 永远不执行）。进程由 scheduler::start() 的 idle 循环启动。
    let Some(cur_pid) = run.current else {
        return;
    };
    // 防御：current 指向已回收槽位（正常路径 exit_current 会清 current；
    // 此守卫兜底测试钩子清理窗口等非常规序列，避免切进悬空槽）。
    //
    // A3 修复（跨核 reap/deschedule 竞态）：当前进程若被**他核**跨核 SIGKILL
    // 后、本核 fix-A 脱机 tick 尚未跑到就被父核 waitpid 收尸（reap_child_locked
    // 把槽 take 成 None 并把其内核栈 retire 进收尸核 DEAD_KSTACKS），本核此刻
    // 仍物理运行在该进程的（已被 retire、待 drain 释放的）内核栈上。绝不能只
    // 清 current 就 return——否则本核 RSP 落在已回收栈上，round-1 drain 释放它
    // 后本核在已释放/复用栈上执行 → UAF → 全核冻结。必须先 drop(run) 再
    // go_idle_on_own_stack()（本函数即为此设计：在将死/已收尸进程栈上把本核
    // RSP0+RSP 切到本核 idle 栈），永不让渡回已回收栈。
    if !proc_bucket_lock(cur_pid).contains_key(&cur_pid) {
        drop(run);
        go_idle_on_own_stack()
    }

    // 保存当前运行进程（短暂取 cur per-pid 锁；saved/state 写入后释放再入队）。
    // 修复 A：在 cur 的 per-pid 锁内先判 Exit——若当前进程已被**跨核** SIGKILL
    // （terminate_locked 已置 Exit 但本核尚未把它切下 CPU），绝不能把它置
    // Ready/重新入队复活（旧代码把 Exit 覆写成 Ready/Running，使该进程永不成为
    // 可收尸 zombie → init 的 waitpid 永久等待、整系统冻结）。持锁判态与
    // terminate_locked 原子互斥（它置 Exit 也须取同一把 cur 锁），锁内判定 Exit
    // 即 terminate 已完整跑完、不会与本分支并发。改为脱机：释放锁与 RUN 后走
    // [`deschedule_exit_current`]（幂等 terminate + 切走/空闲）。
    {
        let mut g = proc_bucket_lock(cur_pid);
        if g.get(&cur_pid).is_some_and(|s| s.proc.state() == TaskState::Exit) {
            drop(g);
            drop(run);
            deschedule_exit_current(frame, cur_pid);
            return; // *frame 已改/已走空闲，由中断返回路径切换，绝不复活 Exit 进程
        }
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            slot.proc.set_state(TaskState::Ready);
            // EEVDF 记账：本进程刚用完一个时间片，按**其自身 nice 权重**折算累加。
            // 记在此处（持 cur 桶锁、已确认非 Exit）恰与「谁真的用了 CPU」对齐：
            // 走到这里必然是真的运行满了 TIMESLICE_TICKS 个用户态 tick。
            let w = crate::sched_eevdf::nice_to_weight(slot.nice);
            charge_vruntime_locked(slot, vruntime_charge(w));
        }
    }
    // EEVDF：重新入队保留既有 vruntime（不清零，否则长期占用者每次让出都
    // 重新获得优先权 → 饿死他人）。
    enqueue_ready(&mut run, cur_pid, false);

    // 统一"选 next + 原子提交切换"原语：从就绪队列弹候选、持 next 桶锁判存在+Ready 后
    // 原子置 Running+*frame=saved 并物理切入（FPU/CR3/RSP0/CURRENT 单点收口）。跨核收尸
    // 竞态修复：候选在被 reap(槽 None)/置 Exit 时被丢弃重选，绝不 .expect panic；next 桶锁
    // 贯穿切换结束，杜绝窗口 B（提交与 cpu 切换之间再被 reap/置 Exit 的二次 .expect :770）。
    // prev=Some(cur)、exclude=MAX：cur 刚被入队(735)，弹回自身(仅剩 cur)即 NothingSelf。
    match pop_and_commit_switch(&mut run, frame, Some(cur_pid), usize::MAX) {
        NextCommit::Switched => return, // *frame 已改，由中断返回路径 iret 切入 next
        NextCommit::NothingSelf => {
            // 弹回自身(仅当前进程)：不切换，恢复 Running 继续。与旧 cur==next 分支等价。
            let mut g = proc_bucket_lock(cur_pid);
            if let Some(slot) = g.get_mut(&cur_pid) {
                slot.proc.set_state(TaskState::Running);
            }
            return;
        }
        // Empty 理论不可达(cur 已入队 735，非 exclude，必先被弹回为 NothingSelf)；仅当 cur
        // 中途也被跨核 reap(顶部 :709/:724 守卫已先行处理)才可能到达——防御性返回即可
        // (cur 若已消失已由守卫 go_idle/deschedule 接管；此处 cur 仍在队则留待下轮 tick)。
        NextCommit::Empty => return,
    }
}

/// 中断返回边界的信号投递收口（S1-8 触发点 4）。
///
/// # 为什么需要它（实测缺陷：`^C` 对「阻塞型前台子进程」永久失效）
///
/// 既有三处投递触发点全部以「**被中断的那个上下文**属于要投递的进程」为前提：
///
/// 1. `tick()` 顶部 —— 只查 `current_proc_mut()`，且要求 `frame.cs & 3 == 3`；
/// 2. syscall 返回（kernel `deliver_pending_signal`）—— 只查**发起该次 syscall 的**进程；
/// 3. 异常返回 —— 只查**触发该异常的**进程。
///
/// 三者共同漏掉了第四种情形：**进程是「被切入」的**——由调度器经
/// [`commit_same_lock`] 的 `*frame = slot.saved` 直接把用户现场整体恢复并
/// iretq 回用户态。这条路径**不经过任何投递检查**。
///
/// 对「睡眠型」前台程序（spinburn：每 40ms 睡满 40ms）后果是致命的：它绝大部分
/// 时间处于 `Blocked`，仅在唤醒后极短暂地跑用户码（µs~低 ms 量级），而 IRQ0 是
/// 10ms 一次——tick 几乎不可能落在它那段短暂的用户态窗口里。于是 SIGINT 一直躺在
/// `pending` 里：实测 `p8=Blocked pend8=1` → `p8=Ready pend8=1` → `p8=Blocked
/// `pend8=1` 循环十几秒不变，进程永不终止、shell 的 `waitpid` 永不返回、提示符
/// 永不回来。注意 `RUN` 锁的 `locked/owner` 在此期间是**活的**（正常加解锁），
/// 证明这不是死锁而是**投递点缺失**。
///
/// # 调用时机与前置条件
///
/// 由中断分发在 `tick()`（可能已改写 `*frame` 为切入进程的现场）**返回之后**调用。
/// 此刻不得持有任何调度锁（`deliver_on_return` 的默认终止路径经 `exit_current`
/// 自行取 per-pid 桶锁与 `RUN`），故本函数只做「取当前进程 + 查 pending + 投递」。
///
/// # 语义
///
/// - 当前无进程（内核/idle 上下文）、非用户态帧、无 pending：原样返回，零副作用；
/// - 有 pending：按 ADR-034 §2.4 派发。默认终止 → `exit_current` 改写 `*frame`
///   为下一进程现场，返回 `false` 告知调用方**不要再触碰 `*frame`**；
/// - 其余情形返回 `true`（帧有效，可继续 iretq）。
pub fn deliver_pending_on_return(frame: &mut InterruptFrame) -> bool {
    // 仅真实用户态帧可投递（内核态帧无权改写为 handler 入口）。
    if frame.cs & 3 != 3 {
        return true;
    }
    let Some(cur) = crate::process::current_proc_mut() else {
        return true; // 内核/idle 上下文，无用户信号可派发。
    };
    // 廉价预检：无 pending 时不触碰信号状态机。
    if cur.signal().pending().is_empty() {
        return true;
    }
    match crate::signal::deliver_on_return(cur, frame) {
        crate::signal::DeliveryOutcome::Continue => true,
        crate::signal::DeliveryOutcome::Terminated => false,
    }
}

/// 切入 next 进程的共享收口：以已持有的 next per-pid 锁完成 FPU 恢复、CR3/RSP0
/// 切换与 CURRENT/current 更新。调用方（[`commit_same_lock`]）须已持 next 所在桶锁，
/// 并已在该锁内完成"校验存在+Ready、置 Running、*frame=saved"——本函数只做物理切换。
///
/// 跨核收尸竞态修复（DESIGN-cross-core-reap-switch-race §3.3）：本函数在整个切换期间
/// 持续持有 next 桶锁（gnext），与 terminate(置 Exit)/reap(take None) 对 next 的桶锁互斥，
/// 故此处 `.expect` 恒真（锁内槽必在、必非被 reap/置 Exit）。不再有旧实现里
/// "提交 expect 释放桶锁 -> cpu_switch_locked 二次取 next 桶锁"的窗口 B。
fn switch_apply_next(
    next: usize,
    gnext: &mut IrqSpinLockGuard<'static, BTreeMap<usize, Box<ProcEntry>>>,
    run: &mut PerCpuRun,
) {
    let slot = gnext.get_mut(&next).expect("switch target exists");
    fpu::restore(&slot.fpu);
    // T2-0: 恢复切入单元的用户态 FS 基址(镜像 FPU restore;保证切回后 FS base 恒指向
    // 当前单元 TCB——普通单线程进程 fs_base=0，防旧线程 base 泄漏)。
    // FS 选择子必须与基址成对设置：基址走 MSR，而"选择子是否可用"决定 fs: 访问
    // 会不会 #GP。实测用户态 FS 选择子为 0（空选择子）→ 任何 fs: 访问立即 #GP，
    // 与基址是否正确无关（见 gdt::set_fs_user_selector）。
    gdt::set_fs_user_selector(slot.fs_base != 0);
    gdt::write_fs_base(slot.fs_base);
    let cr3 = slot.proc.addr_space().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    run.current = Some(next);
    // S2（SMP 审计）：**先记录、后写 CR3**。
    //
    // 记录的意义：`UserAddressSpace::destroy` 要判断"还有没有别的核 CR3 悬在
    // 这张表上"，据此决定中间页表页能否归还。缺了这一步，销毁方只能看到本核
    // （`current_paddr()`），别的核悬着时表页被提前归还 → 取指缺页 → #DF → 三重故障。
    //
    // 顺序取保守方向：先让世界看到"本核持有该表"，再真正切换。反序会留下
    // "硬件已切走、记录仍说持有"的窗口（保守，安全）；而"硬件未切、记录说没有"
    // 才是危险方向——先记录可杜绝它。
    arch_x86_64::paging::record_current_cr3(my_cpu_slot(), cr3);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
}

/// 单候选提交结果（[`commit_next`]）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CommitNext {
    /// 已把 next 完整切入（*frame 已整体改写为 next.saved；next 桶锁贯穿到切换结束）。
    Done,
    /// next 候选在持锁校验时已不存在（被跨核 reap，槽 None）或已 Exit——不可切；
    /// 本候选被丢弃（不重放）。prev 的 FPU 从未被 save，回滚无副作用。
    Invalid,
}

/// [`commit_next`] 使用的"单候选有效"判定：next 槽存在且 state==Ready（可切入的唯一合法态）。
fn next_is_runnable(g: &BTreeMap<usize, Box<ProcEntry>>, next: usize) -> bool {
    g.get(&next).is_some_and(|s| s.proc.state() == TaskState::Ready)
}

/// 在**已持 next 桶锁 g** 下完成"置 Running + *frame=saved + switch_apply_next"。
/// 调用方保证 next 存在+Ready（已在 [`commit_next`] 校验），故此处 get_mut 恒真。
/// g 贯穿到物理切换结束，杜绝窗口 B（提交与切换之间再被 reap/置 Exit）。
fn commit_same_lock(
    run: &mut PerCpuRun,
    frame: &mut InterruptFrame,
    next: usize,
    g: &mut IrqSpinLockGuard<'static, BTreeMap<usize, Box<ProcEntry>>>,
) {
    let slot = g.get_mut(&next).expect("next just validated");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    switch_apply_next(next, g, run);
}

/// 把单个候选 next"校验存在+Ready -> (切走方 prev 的 FPU 归档，若存在) -> next 置 Running
/// -> *frame=saved -> FPU/CR3/RSP0/CURRENT 切换"在同一把/两把 per-pid 桶锁临界区内原子完成。
///
/// 跨核收尸竞态修复（DESIGN §3.3）：判 next 状态与 terminate(置 Exit)/reap(take None) 对
/// next 的桶锁原子互斥——锁内看到的 next 状态稳定、不会在他核翻转。next 桶锁**贯穿到物理
/// 切换结束**（经 [`commit_same_lock`]/[`switch_apply_next`]），绝不在"置 Running+读 saved"
/// 与 CPU 切换之间释放重取（消除窗口 B 及 :770 的二次 .expect 竞争）。
///
/// 锁序（防 ABBA）：prev==None 只持 next 桶；prev==Some 且与 next 同桶只持一桶；不同桶则按
/// **pid 升序**两桶同持（先 pid 小者）。校验失败（Invalid）时 prev 的 FPU **从未被 save**——
/// 不产生陈旧 FPU 快照；调用方丢弃该候选重选，无残留锁。prev 的 FPU 只在确认"本次确实切走"
/// 后归档（旧 `cpu_switch_locked` 的语义并入本函数）。
fn commit_next(
    run: &mut PerCpuRun,
    frame: &mut InterruptFrame,
    prev: Option<usize>,
    next: usize,
) -> CommitNext {
    match prev {
        // prev=None：切走方已脱机/已置 Blocked（其浮点现场由阻塞/退出路径显式归档），
        // 无 prev 桶锁。只持 next 桶完成校验+提交+切换。
        None => {
            let mut g = proc_bucket_lock(next);
            if !next_is_runnable(&g, next) { return CommitNext::Invalid; }
            commit_same_lock(run, frame, next, &mut g);
            CommitNext::Done
        }
        // prev/next 同桶：单桶锁。先校验 next，再归档 prev FPU，再切入。
        Some(pid) if pid_bucket(pid) == pid_bucket(next) => {
            let mut g = proc_bucket_lock(next);
            if !next_is_runnable(&g, next) { return CommitNext::Invalid; }
            if let Some(ps) = g.get_mut(&pid) {
                fpu::save(&mut ps.fpu);
                ps.fs_base = gdt::read_fs_base();
            }
            commit_same_lock(run, frame, next, &mut g);
            CommitNext::Done
        }
        // prev 桶号更小：按 pid 升序先取 prev 桶、再取 next 桶。
        Some(pid) if pid_bucket(pid) < pid_bucket(next) => {
            let mut gprev = proc_bucket_lock(pid);
            let mut gnext = proc_bucket_lock(next);
            if !next_is_runnable(&gnext, next) { return CommitNext::Invalid; }
            if let Some(ps) = gprev.get_mut(&pid) {
                fpu::save(&mut ps.fpu);
                ps.fs_base = gdt::read_fs_base();
            }
            commit_same_lock(run, frame, next, &mut gnext);
            CommitNext::Done
        }
        // prev 桶号更大：按 pid 升序先取 next 桶、再取 prev 桶（next 桶仍贯穿切换）。
        Some(pid) => {
            let mut gnext = proc_bucket_lock(next);
            let mut gprev = proc_bucket_lock(pid);
            if !next_is_runnable(&gnext, next) { return CommitNext::Invalid; }
            if let Some(ps) = gprev.get_mut(&pid) {
                fpu::save(&mut ps.fpu);
                ps.fs_base = gdt::read_fs_base();
            }
            commit_same_lock(run, frame, next, &mut gnext);
            CommitNext::Done
        }
    }
}

/// 统一"选 next + 原子提交切换"原语（DESIGN §3.2）：从本核就绪队列依次弹出候选，
/// 跳过 exclude，对每个候选经 [`commit_next`] 做存在+Ready 校验并原子切入；无效(被跨核
/// reap/置 Exit)候选被**丢弃不重放**（I1），继续弹下一候选，队列耗尽返回 Empty。
///
/// 调用方持本核 RUN 域（reborrow 传入）。`prev` = 被切出进程 pid（prev=None 表示切走方
/// 已脱机/置 Blocked/Exit，本核已在安全栈）；`exclude` = 需跳过的自身 pid（如 waitpid）。
/// 返回 Switched 表示已真切入某 next（*frame 已整体改写，调用方不得再触碰）；返回 Empty
/// 表示就绪队列无可提交候选（原"空队列/无可切"语义，调用方按其各自收尾处理）；返回
/// NothingSelf 表示弹出的是 prev(cur 自身)（仅 tick/yield 等把 cur 入队的场景可达），调用方
/// 恢复 cur Running 并走"仅剩自身"收尾，避免 CPU 自切空转。
enum NextCommit { Switched, Empty, NothingSelf }

fn pop_and_commit_switch(
    run: &mut PerCpuRun,
    frame: &mut InterruptFrame,
    prev: Option<usize>,
    exclude: usize,
) -> NextCommit {
    loop {
        // EEVDF：取 vruntime 最小者（而非 FIFO 队首）。`pop_min` 空队列返回 None，
        // 保持既有「绝不 panic」纪律（返回 Empty 由调用方按原语义处理）。
        let Some((next, _vt)) = run.ready.pop_min() else { return NextCommit::Empty };
        if next == exclude { continue; }
        if prev == Some(next) {
            // 弹回被切出进程自身（cur，仅当其被重新入队如 tick/yield 才会发生）：不切换。
            // 调用方据此把 cur 恢复 Running 并回 NotSwitched/自恢复；*frame 未被改写。
            return NextCommit::NothingSelf;
        }
        match commit_next(run, frame, prev, next) {
            CommitNext::Done    => return NextCommit::Switched, // 已切入，桶锁已释放
            CommitNext::Invalid => {}
        }
    }
}

/// 调度切换动作结果（KA6：bool+frame 形状的枚举化收口）。
///
/// "是否已把 CPU 现场换成别的进程"必须由类型系统强制调用方处理——bool 返回值
/// 可以被无视，漏翻成普通返回会把 rax=0 之类的值写进**下一进程**的保存现场
/// （K1b 记录的原始事故）。`Switched` 分支下调用方禁止再触碰 frame。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SwitchOutcome {
    /// 已切走：`*frame` 已整体替换为下一进程保存帧；调用方必须以"已切换"
    /// 纪律收尾（syscall 层即 `DispatchResult::Switched`），不得再写 frame。
    Switched,
    /// 未切换：现场仍是当前进程，调用方可正常读写 frame 并回写返回值。
    NotSwitched,
}

/// `yield()`：当前进程**主动**让出 CPU，切换到下一个就绪进程。
///
/// 与 [`tick`] 的被动时间片切换不同，这是进程主动请求让出：保存当前帧并把
/// 进程放回就绪队列尾，取下一个就绪进程切换。若就绪队列里只有当前进程
/// （无可让出），则恢复 Running 继续运行——`yield` 对调用进程等价于空操作。
///
/// `yield` 的返回值 `0` 写回当前进程帧再保存，故进程下次恢复时 `rax=0`，
/// 用户态 `yield()` 正确返回 0。
pub fn yield_now(frame: &mut InterruptFrame) -> SwitchOutcome {
    let cpu_slot = my_cpu_slot();
    // per-pid（a）：只取 cur/next 的 per-pid 锁 + 本核 RUN 域，无全局 PROCS。
    let mut run = run_mut(cpu_slot);
    let Some(cur_pid) = run.current else {
        return SwitchOutcome::NotSwitched; // 内核 idle/主线程不参与让出
    };

    // 写回 yield 返回值 0，随 saved 保存；进程下次恢复时 rax=0。
    frame.rax = 0;
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            slot.proc.set_state(TaskState::Ready);
            // EEVDF 记账：主动 yield 也消耗了一个时间片的 CPU 份额。
            // 若不计账，忙轮询式 yield 的进程可以无限让出而不积累 vruntime，
            // 从而永久占据最小 vruntime、始终被优先选中 —— 必须计。
            // 同样按该进程自身权重折算。
            let w = crate::sched_eevdf::nice_to_weight(slot.nice);
            charge_vruntime_locked(slot, vruntime_charge(w));
        }
    }
    enqueue_ready(&mut run, cur_pid, false);

    // 统一"选 next + 原子提交切换"原语（同 tick）。跨核收尸竞态修复：候选被 reap/置 Exit
    // 时丢弃重选，绝不 .expect panic；next 桶锁贯穿切换结束，杜绝窗口 B。
    // prev=Some(cur)、exclude=MAX：cur 刚入队，弹回自身(仅剩 cur)即 NothingSelf -> 无可让出。
    match pop_and_commit_switch(&mut run, frame, Some(cur_pid), usize::MAX) {
        NextCommit::Switched => SwitchOutcome::Switched, // *frame 已改，调用方须按已切换收尾
        NextCommit::NothingSelf => {
            // 仅当前进程自身：无可让出，恢复 Running 继续（与旧 cur==next 分支等价）。
            let mut g = proc_bucket_lock(cur_pid);
            if let Some(slot) = g.get_mut(&cur_pid) {
                slot.proc.set_state(TaskState::Running);
            }
            SwitchOutcome::NotSwitched
        }
        // Empty 理论不可达(cur 已入队 940，非 exclude)；防御性 NotSwitched（同旧空队分支）。
        NextCommit::Empty => SwitchOutcome::NotSwitched,
    }
}

/// 阻塞当前进程（IPC 等待用）：保存帧并置 `Blocked`，切换到下一个就绪进程。
///
/// 与 [`yield_now`] 不同，当前进程**不**放回就绪队列，而是置 `Blocked`（等待某
/// 事件，如管道数据/空间）。需 [`wake`] 显式唤醒才回到就绪队列。
///
/// 返回 `false` 表示无可调度进程可切（就绪队列空，只有当前进程）：此时**不应**
/// 阻塞（否则系统无进程能唤醒它，死锁），调用方应返回 `WouldBlock` 等错误而非
/// 强行让出。返回 `true` 表示已切走（frame 已改写为下一进程帧）。
///
/// 注意：调用方**必须先释放**持有的 IPC 表锁再调用本函数（阻塞切走时若仍持锁，
/// 下一进程会在同一把 IrqSpinLock 上自旋死锁）。
/// 从就绪队列取出下一个**有效**进程（task1 KM8 统一口径）：跳过已回收槽、
/// 已退出残留与 `exclude` 指定 pid，**仅接受 `Ready` 状态**。
///
/// 历史上存在 `pop_ready`（滤 Exit）与 `pop_ready_filtered`(仅收 Ready 且
/// 排除自身)两个近似函数，过滤规则分裂是潜伏隐患。现统一为本单点：
/// "Blocked 项不入队"的不变式由机器强制兜底——即使未来某路径违规把
/// Blocked 项入队，本函数也不会把它切上 CPU。返回第一个有效 pid，
/// 队列空/仅含死进程时返回 `None`。
fn pop_ready(run: &mut PerCpuRun, exclude: usize) -> Option<usize> {
    // EEVDF：按 vruntime 升序取（`pop_min`），语义等价于原 FIFO 的"取下一个"，
    // 只是"下一个"的定义由队首变为 vruntime 最小者。
    while let Some((pid, _vt)) = run.ready.pop_min() {
        if pid == exclude {
            continue;
        }
        // 分桶化：短暂取候选 pid 所在桶判态（就绪队列内 pid 恒在册）。
        if let Some(slot) = proc_bucket_lock(pid).get(&pid) {
            if slot.proc.state() == TaskState::Ready {
                return Some(pid);
            }
        }
    }
    None
}

/// 从就绪队列中取出**特定的** `target`（不在队头时保持其它就绪进程）。
///
/// 用于事件路径 idle-halt 唤醒：事件等待者 cur_pid 在队列中可能不是队头——
/// 队列头可能是被键盘/其它唤醒源并发入队的另一 Ready 进程。若用 `pop_ready`
/// 弹队头会切错进程，事件等待者永久挂起（O1 竞争面）。本函数弹出队头，非
/// 目标者挪回队尾（保持其 Ready 可调度性），直到取到 `target`；不在队列返回
/// `None`。
fn extract_from_ready(run: &mut PerCpuRun, target: usize) -> Option<usize> {
    // EEVDF 下用 `remove` 直接摘取目标：**不再需要**「逐个弹出、非目标放回」的
    // 撞运气式实现。原实现的前提是 FIFO 队列没有按 key 删除的能力；最小堆在本
    // 类型里已提供 O(n) 定位的 `remove`（`sched_eevdf` 有文档说明为何不用懒惰标记）。
    //
    // 这不只是简化：原实现的 `expect("len>0 in bounded loop")` 是一个 panic 点，
    // 且依赖「`n` 次内必命中」的脆弱假设。`remove` 天然无此风险（S23：失败模式优先）。
    if run.ready.remove(target) {
        Some(target)
    } else {
        None
    }
}

/// [`schedule_from_block`] 的切走结果（K1-1，ADR-031 决策-改造要点 1 的
/// frame-based 落地）。两分支都表示 `frame` 已被改写为下一进程的保存帧，
/// 调用方必须以 `Switched` 纪律收尾（不再触碰 frame）；差异仅在于等待者登记
/// （EVENT_WAITER 等；原 KBD_WAITER 已随 I-EVENTS P5 退役。）是否需要在切回后清理。
enum BlockResume {
    /// 切到**另一个**就绪进程（cur_pid 保持 Blocked + 等待者登记不变）。等待者
    /// 尚未被唤醒，登记必须保留（否则后续事件/键盘到达时无人唤醒它）。
    SwitchedOther,
    /// 切回**自己**（cur_pid 已被唤醒入队）。调用方须在切回后清理自己的等待者
    /// 登记（与既有自唤醒路径的 CAS 清理同构）。
    SwitchedSelf,
}

/// (K1-1, ADR-031) 阻塞等待者的 idle-halt None 分支统一切换原语。
///
/// `block_for_event` 的"无就绪进程可切"分支（`pop_ready` 返回
/// None）不再"halt 只等自己"（旧实现仅检查 `ready.contains(&cur_pid)`），而是：
/// **当就绪队列出现任一进程（自己或其它）时，用 frame-based 切换让出 CPU**——
/// 与既有 `Some(next)` 分支完全同构（`pop_and_commit_switch(None, _)` + iret），
/// 自己保持 Blocked + 等待者登记。只有就绪队列确实为空才 `halt`（此时无任何
/// 可调度进程，halt 合理，绝无忙转）。
///
/// 设计依据（PRE-1 现场交接矩阵 + 本会话对 ADR-031 的实核修正）：
/// BORUIX 进程恢复走**用户态中断帧 + iret** 模型——进程在用户态被切走时只保存
/// `slot.saved`（用户 `InterruptFrame`），`Process.context`（`TaskContext`）在
/// 生产路径恒为空（`process.rs` `TaskContext::empty()`），`arch::task::switch_to`
/// 当前仅内核自测使用。因此 ADR-031 原拟的 `switch_to` 版 `schedule_from_block`
/// （切到**用户态就绪进程**的内核 `TaskContext`）会跳到空上下文崩溃，与现有
/// frame-resume 模型不兼容；正确实现是复用 frame-based 切换原语（`commit_next`/`pop_and_commit_switch`），
/// 保证与 tick/yield/block_current/exit_current 的既有切换机制完全一致、可回滚。
///
/// 上下文约定：调用方须已 `drop` 本核 RUN 锁与所持 per-pid 锁并处于中断**已使能**
/// 态（None 分支进入前的现场）。本函数自行管理 RUN 域与 per-pid 锁的获取/释放
/// （逐访问点短暂取，多 pid 按升序）与
/// `enable`/`disable`/`halt` 的节奏，返回时中断处于**已禁用**态（与既有 None 分支
/// 的返回现场一致，供调用方在 syscall 层 iret 前保持）。
///
/// `prev=None` 纪律：cur_pid 是等待者，其浮点现场已在置 Blocked 前由调用方显式
/// `fpu::save`（PRE-1），切走时 `commit_next(None, _)` 不重复归档。
fn schedule_from_block(frame: &mut InterruptFrame, cur_pid: usize) -> BlockResume {
    // A4：等待期间本核可能被跨核 SIGKILL+收尸 cur_pid（Blocked 中自杀式场景），
    // 故停车等队列前先切 CR3 到内核根，避免本核 CR3 悬在可能被回收的进程表上。
    arch_x86_64::paging::switch_to_kernel_root();
    loop {
        // 等就绪队列出现任一进程（自己或其它）。每次 halt 直到中断到达（绝不忙转）。
        arch_x86_64::interrupts::enable();
        loop {
            // 纯 RUN 探测：短暂取本核 RUN 域（IrqSpinLock ⇒ 检查瞬间 IF 屏蔽）。
            let nonempty = !run(my_cpu_slot()).ready.is_empty();
            if nonempty { break; }
            arch_x86_64::interrupts::halt();
        }
        arch_x86_64::interrupts::disable();
        // per-pid（a）：只取本核 RUN 域；逐候选经统一 commit 提交切换。
        let mut run = run_mut(my_cpu_slot());
        // SwitchedSelf 主路径：cur_pid 已被唤醒入队，先尝试切回自身。持 RUN 下
        // contains/extract 连续（reap 移出就绪也须本核 RUN，被本锁阻断），故 cur 必被取出。
        // EEVDF：`contains` 语义不变（是否在就绪队列中）。
        if run.ready.contains(cur_pid) {
            let c = extract_from_ready(&mut run, cur_pid).expect("woken waiter in ready");
            // 跨核收尸竞态修复：cur(被唤醒等待者)在提取后仍可能被收尸(reap 只取 cur 桶锁
            // 不依赖 RUN)——commit_next 在持 cur 桶锁下重判存在+Ready；无效(cur 槽 None/置
            // Exit)则丢弃(其 KBD/EVENT 登记已被 kill_pid 清理 :2500-2514)，落空后切其它或
            // 重启等待(等同 SwitchedOther 语义)，绝不 .expect panic / 切进已回收槽。
            if commit_next(&mut run, frame, None, c) == CommitNext::Done {
                drop(run);
                return BlockResume::SwitchedSelf; // 中断保持已禁用(返回现场契约)
            }
        }
        // SwitchedOther：切任一剩余有效进程；自己(cur)保持 Blocked+登记不变(若 cur 尚存活)
        // 或已被收尸(登记已清)。无效候选被 commit 丢弃重选；队列又空/无可切则回外层等待。
        match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
            NextCommit::Switched => {
                drop(run);
                return BlockResume::SwitchedOther;
            }
            _ => { drop(run); continue; } // Empty/NothingSelf：无可切，重新 enable+halt 等待
        }
    }
}

/// 阻塞当前进程（IPC 等待用）：保存帧并置 `Blocked`，切换到下一个就绪进程。
///
/// 与 [`yield_now`] 不同，当前进程**不**放回就绪队列，而是置 `Blocked`（等待某
/// 事件，如管道数据/空间）。需 [`wake`] 显式唤醒才回到就绪队列。
///
/// 返回 [`SwitchOutcome::NotSwitched`] 表示无可调度进程可切（就绪队列空，只有
/// 当前进程）：此时**不应**阻塞（否则系统无进程能唤醒它，死锁），调用方应返回
/// `WouldBlock` 等错误而非强行让出。`Switched` 表示已切走（frame 已改写为下一
/// 进程帧，调用方不得再触碰）。
///
/// 注意：调用方**必须先释放**持有的 IPC 表锁再调用本函数（阻塞切走时若仍持锁，
/// 下一进程会在同一把 IrqSpinLock 上自旋死锁）。
pub fn block_current(frame: &mut InterruptFrame) -> SwitchOutcome {
    // per-pid（a）：只取本核 RUN 域；PID 槽访问经 block_current_locked 内逐 pid 锁。
    let mut run = run_mut(my_cpu_slot());
    // 修复 B：若当前进程已 Exit（跨核 SIGKILL 后仍在内核阻塞路径上，尚未被切下
    // CPU），不得把它登记/置 Blocked（会覆写 Exit → 被 sleep-timer wake 复活、
    // 永不成为可收尸 zombie）。持有本核 RUN（owned guard）时先释放再脱机。
    if let Some(cur_pid) = run.current {
        if current_is_exit(cur_pid) {
            drop(run);
            deschedule_exit_current(frame, cur_pid);
            return SwitchOutcome::Switched;
        }
    }
    let out = block_current_locked(&mut run, frame, &mut || true);
    // 二次兜底：block_current_locked 内 cur 才被跨核 SIGKILL 成 Exit（A3 竞态）时返回
    // NotSwitched；此处持有 owned RUN，重查后经 deschedule_exit_current 正确脱机。
    if out == SwitchOutcome::NotSwitched {
        if let Some(cp) = run.current {
            if current_is_exit(cp) {
                drop(run);
                deschedule_exit_current(frame, cp);
                return SwitchOutcome::Switched;
            }
        }
    }
    out
}

/// 原子阻塞变体（ipc1 IA2a / 审计 R6-F2）：与 [`block_current`] 相同的阻塞
/// 语义，但在**调度锁内**先执行 `register`——返回 false（等待者查重拒绝/
/// 目标消失/**唤醒条件在登记点已复检为真**）则不阻塞、零副作用地返回
/// NotSwitched。
///
/// 这把"登记等待者"与"置 Blocked"合并为对唤醒方不可分割的单步。lost-wakeup
/// 的两侧论证：唤醒方的 "消费 + drain + wake" 若发生在本方循环条件检查之后、
/// 登记之前，登记点持同一把锁的**条件复检**会看见翻转并拒绝入睡；若发生在
/// 置 Blocked 之后，wake 正常生效。窗口不存在——与 `block_for_console`/`block_for_event` 的 CAS
/// 纪律同源。
///
/// 锁序：本函数持当前进程的 per-pid 锁期间回调可能取 IPC 表锁（pid → IPC 表，
/// 单向；唤醒方一律在表锁外调用 wake，反向边不存在）。
pub fn block_current_with(
    frame: &mut InterruptFrame,
    register: &mut dyn FnMut() -> bool,
) -> SwitchOutcome {
    // per-pid（a）：只取本核 RUN 域；本函数持当前进程 pid 锁期间回调可能取 IPC
    // 表锁（pid → IPC 表，单向；唤醒方在表锁外调 wake，反向边不存在）。
    let mut run = run_mut(my_cpu_slot());
    // 修复 B：Exit 当前进程不得登记/阻塞（同 block_current），先释放本核 RUN 再脱机。
    if let Some(cur_pid) = run.current {
        if current_is_exit(cur_pid) {
            drop(run);
            deschedule_exit_current(frame, cur_pid);
            return SwitchOutcome::Switched;
        }
    }
    let out = block_current_locked(&mut run, frame, register);
    // 二次兜底：block_current_locked 内 cur 才被跨核 SIGKILL 成 Exit（A3 竞态）时返回
    // NotSwitched；此处持有 owned RUN，重查后经 deschedule_exit_current 正确脱机。
    if out == SwitchOutcome::NotSwitched {
        if let Some(cp) = run.current {
            if current_is_exit(cp) {
                drop(run);
                deschedule_exit_current(frame, cp);
                return SwitchOutcome::Switched;
            }
        }
    }
    out
}

/// 共享阻塞主体：`s` 必须已锁；`register` 在确认存在可切换目标后、置
/// Blocked 前执行。prev=Some(cur) 的浮点现场归档由 commit_next 单点完成
/// （审计 R5-F1 纪律在阻塞路径的原生形态）。
fn block_current_locked(
    run: &mut PerCpuRun,
    frame: &mut InterruptFrame,
    register: &mut dyn FnMut() -> bool,
) -> SwitchOutcome {
    let Some(cur_pid) = run.current else {
        return SwitchOutcome::NotSwitched; // 内核 idle/主线程不参与阻塞
    };
    // 预检：须存在至少一个非 cur 的就绪候选才可能阻塞（无同伴则调用方 WouldBlock，
    // 绝不置 Blocked 后无人接盘 CPU 而自锁）。pop_ready 已滤 Exit/None 并返回首个有效项；
    // 按其桶锁再确认存在+Ready（§6d 预检，缩小"register 后 peer 才失效"的回滚面）。
    // 记录 peer 的 vruntime 快照：下方两条回滚路径必须在**不取 peer 桶锁**的前提下
    // 把 peer 放回队列（此时可能已持 cur 桶锁，同桶会自死锁）。在取任何锁之前读好，
    // 使回滚路径彻底无锁，恢复原 `push_back` 的锁纪律。
    let mut peer = loop {
        let Some(p) = pop_ready(run, usize::MAX) else {
            return SwitchOutcome::NotSwitched;
        };
        if proc_bucket_lock(p).get(&p).is_some_and(|s| s.proc.state() == TaskState::Ready) {
            break p;
        }
        // p 已 Exit/被 reap：pop_ready 弹出但随即失效，丢弃重选（I1，不重放）。
    };
    // 取快照后即可安全用于两条回滚路径（此刻未持任何桶锁）。
    let peer_vruntime = proc_bucket_lock(peer).get(&peer).map(|s| s.vruntime).unwrap_or(0);
    // 登记点必须与唤醒方（wake/wake_with_value 持目标 pid 锁）原子互斥，故持
    // cur 的 per-pid 锁执行 register + 置 Blocked；失败即整体放弃，现场未动。
    {
        let mut gcur = proc_bucket_lock(cur_pid);
        // 修复 B（锁内兜底）：公共入口检查之后、置 Blocked 之前，本进程仍可能被
        // 跨核 SIGKILL（terminate_locked 只取 cur 锁即置 Exit，不依赖本核 RUN）。
        // 持 cur 锁在此原子判 Exit：若已 Exit，绝不登记/置 Blocked（会覆写 Exit → 复活、
        // 永不成为可收尸 zombie）。把预检弹出的同伴 peer 放回就绪队列(不饿死它)，返回
        // NotSwitched 由调用方(wrapper)在收到 NotSwitched 后重查 cur Exit，命中则 drop
        // owned RUN 经 deschedule_exit_current 正确脱机(其 owns run、空队 go_idle_on_own_stack
        // 语义正确)——本函数只持 reborrow，不能在此 go_idle(会留下 caller 的 RUN 未释放)。
        if gcur.get(&cur_pid).is_some_and(|s| s.proc.state() == TaskState::Exit) {
            drop(gcur);
            // EEVDF：放回时保留其既有 vruntime（本次并未消耗 CPU）。
            // **必须用无锁变体**：此刻持有 cur 桶锁，若 peer 与 cur 同桶，
            // `enqueue_ready` 会重复获取同一把不可重入锁而自死锁。
            enqueue_ready_with_vruntime(run, peer, peer_vruntime);
            return SwitchOutcome::NotSwitched;
        }
        if !register() {
            // S26 回归：`peer` 已在上方被 `pop_ready` 弹出（仍为 Ready 态），
            // 若直接返回将永久丢失该就绪进程（无人重新入队 → 饿死）。
            // 必须把它放回就绪队列，保证"登记失败零副作用"成立。
            // EEVDF：保留其 vruntime（本次未消耗 CPU，不得重置）。
            // 注意 `run` 本身已是 `&mut PerCpuRun`，直接传（`&mut run` 会重借用失败）。
            // 同样必须无锁：此刻仍持有 cur 桶锁（ISSUE: 同桶自死锁）。
            enqueue_ready_with_vruntime(run, peer, peer_vruntime);
            return SwitchOutcome::NotSwitched;
        }
        if let Some(slot) = gcur.get_mut(&cur_pid) {
            slot.saved = *frame;
            slot.proc.set_state(TaskState::Blocked);
            // 浮点归档不在此处执行：commit_next(prev=Some) 是唯一的 prev 现场快照点
            //（审计 R6-F3 附带消除双重 fxsave 冗余——两次 save 之间虽无内核代码触碰 XMM
            //（sdk/check-no-sse.py 已证），但冗余写会让"哪一次是权威归档"不可辨认）。
        }
    }
    // 已置 cur Blocked（register 可能已登记等待者，必有待决唤醒）。切到 peer(prev=Some(cur))：
    // commit_next 在持 peer 桶锁下重判存在+Ready——若 peer 被跨核 reap/置 Exit 则丢弃重选其它
    // 就绪进程（不 .expect panic、不切进已回收槽）。
    loop {
        match commit_next(run, frame, Some(cur_pid), peer) {
            CommitNext::Done => return SwitchOutcome::Switched,
            CommitNext::Invalid => {
                match pop_ready(run, usize::MAX) {
                    Some(p) => peer = p,
                    None => break, // 队列耗尽：见下方极端收尾
                }
            }
        }
    }
    // 极端竞态：register 已返回 true、cur 已置 Blocked 后，唯一同伴竟被跨核 reap 且就绪
    // 队列耗尽（SMP 下极窄）。绝不让已 Blocked 的 cur 滞留 CPU 上假装阻塞（否则 saved/状态
    // 与真实运行不一致），也不可进 idle(cur 非 KBD/EVENT waiter，其唤醒由 register 登记的
    // IPC/timer 侧负责，但本核 CPU 须即刻交给其它进程——此处并无其它就绪进程，只能回滚
    // cur 为 Running 交调用方处置(WouldBlock/Refused)）。注意：register 若已登记 opaque 等待者
    // 则此回滚无法撤销其登记——对 sleep(定时器 wake(Running) 被忽略，无害)无碍；对 IPC 等待者
    // 是"已登记但进程仍运行"的已知残留(见报告裁定项)。等价 waitpid revert，撤销 Blocked。
    {
        let mut gcur = proc_bucket_lock(cur_pid);
        if let Some(slot) = gcur.get_mut(&cur_pid) {
            slot.proc.set_state(TaskState::Running);
        }
    }
    SwitchOutcome::NotSwitched
}

// I-EVENTS P5 轨道 A 退役（§6.15.5）：KBD_WAITER/block_for_kbd/wake_kbd 整体移除——
// stdin 阻塞等待源自 P4 起唯一是 CONSOLE_WAITER（console 环），键盘直读字节路径
// 已无调用方；保留同构参照 block_for_event / block_for_console（各自真值源未变）。
/// 把被唤醒进程 pid 塞入 home 核就绪队列，并在跨核唤醒到空闲核时发一次
/// reschedule IPI（阶段2 M5）：让驻留进程在别核、而该核此刻调度空闲 halt 等队列
/// 的场合即时醒来重查，把时延从等目标核下一 IRQ0 tick (~16ms) 压到即时。
///
/// 跨核就绪入队 + 空闲核 IPI：本函数自身短暂取 RUN[home] 域（跨核目标为动态
/// 槽位，无法随参传递单一 guard），不改任何进程表锁状态。调用方须**已释放**所持
/// 的 per-pid 锁（不得与 RUN[home] 同持——IrqSpinLock 不可重入；各唤醒路径在
/// 入队前已 drop pid 锁）。空闲判定 = current[home] 为 None（该核无进程运行、在
/// start() 空队 halt）。目标核若在运行则 IPI 仅 EOI 无副作用（arch 的
/// dispatch_resched 不碰调度锁，不会与本锁死锁）。
///
/// ## 为什么**无条件**投递（SMP 审计 S4）
///
/// 旧实现在 `home != my_cpu_slot()` 之外还加了 `run.current.is_none()` 作为
/// "目标核已停车"的预判，据此**跳过** IPI。该预判是错的：`current` 只在**切换
/// 提交点**更新（在 `commit_next`/`pop_and_commit_switch` 里置 Some，在
/// `block_current`/`schedule_from_block` 入口清 None），它表示"本核当前没有
/// 正在运行的进程"，**不表示"本核已 hlt"**。核在两处切换之间执行内核代码时
/// `current` 同样是 `None`。
///
/// 后果是**单向**的：预判错只会导致**漏发** IPI，此时目标核已 `hlt`，只能等
/// IRQ0 tick（~16ms）兜底重查——唤醒延迟被无谓放大。而省下的只是一次微秒级
/// IPI。任何"要不要唤醒"的预判在多核系统中都是净负收益：判错的代价是不确定
/// 延迟，收益近乎为零。Linux 的 `smp_send_reschedule()` 因此**没有**空闲判断，
/// 一律投递；本实现对齐该语义。
///
/// 投递结果不再 `let _ =` 丢弃：`send_resched_ipi_to_slot` 内部按成功/失败分别
/// 计数（`resched_ipi_send_count` / `resched_ipi_send_fail_count`），失败可观测。
fn wake_enqueue(pid: usize, home: usize) {
    let mut run = run_mut(home);
    // EEVDF：被唤醒的进程保留其既有 vruntime（is_new=false）。
    // 若在此重置，一个频繁阻塞/唤醒的进程能不断"清空"自己的 CPU 份额，
    // 从而长期占据最小 vruntime、饿死 CPU 密集型进程。
    enqueue_ready(&mut run, pid, false);
    drop(run);
    // 无条件投递：见上方理由。本核自己不需要（本核就在执行本函数）。
    if home != my_cpu_slot() {
        // 记录"尝试投递"这一事实，与投递成败分开：BSP 单核自检阶段
        // （smp::init 之前）跨核投递**必然**失败，但"是否尝试"仍可验证，
        // 而它正是 S4 缺陷的判据（旧 guard 会连尝试都跳过）。
        WAKE_ATTEMPTED_CROSS_CORE.store(true, core::sync::atomic::Ordering::Release);
        let _ = arch_x86_64::interrupts::send_resched_ipi_to_slot(home);
    }
}



// ---------------------------------------------------------------------------
// interrupt-to-futex：设备事件驱动的用户态阻塞等待（interrupt→publish_event→
// wake_event→唤醒阻塞进程）。与键盘路径（block_for_kbd/wake_kbd）同构，但条件
// 源是 `driver::event` 硬件拓扑环形日志——设备注册/拔除（DriverHub）发布事件时
// 唤醒在此阻塞等待的进程（volumed），使 ADR-030 §决策3 "不做轮询" 兑现：
// 事件驱动取代有界休眠轮询。
// ---------------------------------------------------------------------------

/// 阻塞等待设备事件的进程 pid（`u32::MAX` 表示无）。`block_for_event` 以 CAS
/// 登记唯一等待者，`publish_event` 经回调 [`wake_event`] 唤醒；第二个并发
/// 事件读者得到 NotSwitched（EAGAIN），不顶掉既有等待者（KM15 单读者仲裁；
/// 同款形态原见 KBD_WAITER，已随 I-EVENTS P5 退役）。
static EVENT_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// 阻塞等待**键盘事件记录**（`/devices/input/events`）的进程 pid
/// （`u32::MAX` 表示无）。I-EVENTS 阶段 2：`block_for_input_event` 以 CAS 登记
/// 唯一等待者，IRQ1 的 `push_event` 经回调 [`wake_input_event`] 唤醒。
///
/// **为何不复用 EVENT_WAITER**（S15 单点语义）：`EVENT_WAITER` 的等待源是
/// `driver::event` 的**设备拓扑事件队列**（`publish_event` 发布、`peek_event`
/// 消费），等待者的用户态契约是 `-EAGAIN` 哨兵重试 `SYS_DRIVER_EVENT_NEXT`。
/// 本等待者的等待源是 arch 层的 **EVQ 键盘记录环**（`push_event` 生产、
/// `pop_event` 消费），用户态契约是「`read` 重试取记录」。两者生产者、消费者、
/// 唤醒回调、用户态重试协议全不同；共用一个槽会让热插拔事件唤醒正在等键盘的
/// 进程（反之亦然），把「误唤醒」变成用户态可见的错误交付。
///
/// 与**已退役的** `KBD_WAITER`（P5 前 stdin 字节流等待者，`push` 唤醒）分工同理：
/// 本槽是**记录**流的等待者（`push_event` 唤醒）。
/// `block_for_input_event` 返回 `WaiterBusy` 的次数（S09 可观察，永久遥测，
/// §6.14.4n 裁决 Ⅰ 转正；单点递增在 `block_for_input_event` 的 Busy 返回处）。
///
/// 判读：该计数暴涨而 `blocked_on_events`（status JSON）同窗不涨，即
/// 「waiter 被残留占用 → 所有 read 立即空读 → 用户态快循环」的直接证据；
/// 正常交互下两者应同量级增长（一真阻塞对应一唤醒，Busy 仅在并发竞争时出现）。
pub static EVENT_WAITER_BUSY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 键盘事件记录等待者的**多槽表**（I-EVENTS P1，§6.15——由单槽
/// `IN_EVENT_WAITER` 升级）。
///
/// **为何表化**：单槽的语义是「全系统至多一名记录读者」——P1 落地后
/// consoled（常驻）与诊断程序可并发空读阻塞，第二名读者会得到 Busy →
/// 空读退化为轮询（§6.14.4n 判读过的紧循环形态）。表化后每名阻塞读者
/// 各占一槽，唤醒方唤醒**全部**槽上的等待者（记录对每读者独立交付，
/// 见 `vfs::stream`）。`u32::MAX` = 空槽；容量是静态上界，无堆分配
/// （IRQ 上下文安全）。
///
/// 并发纪律与单槽完全一致：登记 = CAS 空槽；唤醒 = 取走全部槽（swap MAX）
/// 后逐 pid 复核；lost-wakeup 防线不变（登记先于复检，事件先到则复检为真）。
static IN_EVENT_WAITERS: [core::sync::atomic::AtomicU32; IN_EVENT_WAITER_SLOTS] =
    [const { core::sync::atomic::AtomicU32::new(u32::MAX) }; IN_EVENT_WAITER_SLOTS];

/// 等待者表容量：consoled（1）+ 诊断程序（1）+ 裕量（6）。静态上界——
/// 超出时 `block_for_input_event` 如实返回 `WaiterBusy`（语义从「已有并发
/// 等待者」扩展为「等待者表已满」，调用方契约不变：空读返回）。
const IN_EVENT_WAITER_SLOTS: usize = 8;

/// 阻塞当前进程等待设备事件（`driver::event` 队列非空），或事件到达前一直挂起。
///
/// 返回 [`SwitchOutcome`]：
/// - `Switched`：本进程已置 Blocked 切走。唤醒后经中断路径（tick）回归用户态，
///   `slot.saved.rax` 由唤醒方预置结果——事件唤醒置 `-EAGAIN` 哨兵（用户态封装
///   识别为"曾阻塞、重试"），超时唤醒置 `0`（返回空）。调用方须以
///   `DispatchResult::Switched` 收尾。
/// - `NotSwitched`：**事件已在登记复检时就绪**（调用方应立即返回事件）、或已有
///   并发等待者（EVENT_WAITER 被占）。现场未动、无副作用。**不再因"无同伴可切"
///   返回 NotSwitched**——与 block_for_console 同构（同款原见已退役的
///   block_for_kbd），无就绪进程时走 idle halt 真实
///   挂起（绝不忙转，见 None 分支）。
///
/// **lost-wakeup 论证**：登记（CAS 写 EVENT_WAITER）先于 per-pid 临界区；置 Blocked
/// 在 cur 的 per-pid 锁内完成；[`wake_event`]/[`wake_event_timeout`] 也取目标 pid 锁
/// 才改 Ready。故"事件到达（publish_event → wake_event）"与"本进程登记"二者
/// 被锁完全串行——若事件先到，wake_event 见无等待者直接返回，本进程随后复检
/// 队列**非空** → 不阻塞，返回 NotSwitched 让调用方取事件；若本进程先登记，
/// wake_event 必在登记后（锁内）读到 pid 并唤醒。不存在"登记后事件到达却无人
/// 唤醒"的窗口。`publish_event` 先入队再唤醒，保证唤醒者复检时必见事件。
pub fn block_for_event(frame: &mut InterruptFrame) -> SwitchOutcome {
    let cur_pid = {
        // 纯 RUN 读取（b）：短暂取本核 RUN 域读 current 即可，无需 pid 锁。
        let run = run_mut(my_cpu_slot());
        let cur = run.current.expect("block_for_event outside process");
        assert!(
            cur < u32::MAX as usize,
            "pid {} collides with EVENT_WAITER sentinel",
            cur
        );
        cur
    };
    if EVENT_WAITER
        .compare_exchange(
            u32::MAX,
            cur_pid as u32,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // 已有并发等待者：不阻塞。
        return SwitchOutcome::NotSwitched;
    }
    // 登记后复检事件队列：若已非空，撤销登记、不阻塞（调用方返回该事件）。
    // 这是 lost-wakeup 的关键防线：事件先到则此处直接取到，绝不错过。
    if driver::event::pending_event_count() > 0 {
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        return SwitchOutcome::NotSwitched;
    }
    // 置 Blocked 并保存现场。浮点现场由 commit_next(prev=None) 路径在
    // 唤醒后显式保存（同 block_for_console，K2 纪律），此处不重复归档。
    let cpu_slot = my_cpu_slot();
    // per-pid（a）：只取本核 RUN 域；cur 槽访问逐 pid 锁。
    let mut run = run_mut(cpu_slot);
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            fpu::save(&mut slot.fpu);
            slot.fs_base = gdt::read_fs_base();
            slot.proc.set_state(TaskState::Blocked);
        }
    }
    run.current = None;
    clear_current_proc();

    // 统一"选 next + 原子提交切换"原语（DESIGN §3.2）：cur 已 Blocked+脱机(prev=None、
    // current=None、浮点现场已显式 save)。候选被跨核 reap/置 Exit 时被丢弃重选，绝不
    // .expect panic、不切进已回收槽；next 桶锁贯穿切换结束(杜绝窗口 B)。
    // 队列耗尽(无就绪可切)则 drop RUN 走 schedule_from_block——park 本核等任一就绪进程
    // (cur 被事件/超时唤醒即 resume)，只有就绪队列确实为空才 halt(ADR-031，绝无忙转)。
    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {
            // NOTE：**此处不再 CAS 清除 EVENT_WAITER**。切换只更新调度元数据
            // (current/CR3/RSP0)，不真正改执行流——本分支在切走时立即执行，若此时清
            // EVENT_WAITER 会抹掉本进程已登记的等待者身份，导致后续事件发布时 wake_event
            // 读到 MAX、无法唤醒本进程(ADR-030 热插拔端到端暴露)。EVENT_WAITER 的清除由
            // 唤醒方负责(事件唤醒经 wake_event 的 swap；超时唤醒后由 event_wait_blocking
            // 重新登记前清理残留)。本处保持登记不变，事件才能到达。
            SwitchOutcome::Switched
        }
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            match schedule_from_block(frame, cur_pid) {
                // 切到其它就绪进程：自己仍 Blocked + EVENT_WAITER 登记不变。
                // **不清理登记**(同 Switched 分支纪律)：EVENT_WAITER 的清除由唤醒方
                // 负责。此处若清掉登记，后续事件发布时 wake_event 读到 MAX、无法唤醒
                // 本进程(ADR-030 热插拔端到端暴露的教训)。
                BlockResume::SwitchedOther => SwitchOutcome::Switched,
                // 自己被事件/超时唤醒入队：切回自身。清理登记：事件唤醒已 swap 走
                // EVENT_WAITER(本 pid 不在)，CAS 无效；超时唤醒走 wake_event_timeout
                //(EVENT_WAITER 仍指向本 pid)，此 CAS 清除之，保证后继新等待者不被
                // "占位"拒之门外。
                BlockResume::SwitchedSelf => {
                    let _ = EVENT_WAITER.compare_exchange(
                        cur_pid as u32,
                        u32::MAX,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                    SwitchOutcome::Switched
                }
            }
        }
    }
}

/// [`block_for_input_event`] 的结果。
///
/// **为何需要三态**（而非复用 [`SwitchOutcome`]）：调用方必须能区分
/// 「已挂起」「记录已到、重读即可交付」「等待者被别的进程占用」——
/// 三者对应的动作完全不同（交棒 / 重读 / 如实返回 0）。若把后两者混为
/// `NotSwitched`，调用方只能靠再查一次 `has_event()` 猜测，而「查询」与
/// 「当时那次读返回空」之间存在竞态：猜错就会变成**内核态紧循环**
/// （实测缺陷：`continue` 重读仍空、反复进入本函数而不让出 CPU）。
pub enum InputEventBlock {
    /// 已挂起切走：调用方须以 `DispatchResult::Switched` 收尾，不得再写返回值。
    Switched,
    /// 锁内复检发现记录**确已到达**：调用方应重读一次并如实交付。
    RecordsReady,
    /// 等待者表已满：调用方应如实返回「读走 0 条」
    /// （KM15 单读者仲裁——不抢别人的记录，也不谎报数据）。
    WaiterBusy,
}

/// 阻塞当前进程等待**键盘事件记录**（`/devices/input/events` 空读，I-EVENTS
/// 阶段 2；P1 起等待者**多槽化**，§6.15）。与 [`block_for_event`] 同构
/// （S15 单点：同一套登记/复检/挂起纪律，不另造一套），差异仅在**等待源
/// 判定**、**等待槽组/唤醒回调**与**读者游标探针**。
///
/// `probe` 是**锁内复检探针**（lost-wakeup 防线的数据面）：P1 起记录按读者
/// 独立交付（`vfs::stream`），「有无可读记录」的真值因读者而异——环里可有
/// 被慢读者钉住的记录（全局 `has_event()` 为真），而本读者的游标处已无新
/// 数据；用全局真值复检会让快读者「复检-重读」死循环（§6.13 同族紧循环）。
/// 故探针由调用方按**本读者自己的判定**注入：`true` = 本读者已有可读记录
/// （登记撤销、立即重读）；`false` = 本读者暂无数据、安全入睡。
///
/// 返回 [`InputEventBlock`] 三态（成因与动作一一对应，见该类型说明）：
/// - `Switched`：已置 Blocked 切走。唤醒后经中断路径回归用户态，
///   `slot.saved.rax` 由唤醒方预置 `-EAGAIN` 哨兵，用户态据此**重试**
///   `read` 取记录。
/// - `RecordsReady`：锁内复检探针为真 → 调用方重读交付。
/// - `WaiterBusy`：等待者表已满 → 调用方如实返回「读走 0 条」。
///
/// **lost-wakeup 论证**（与单槽版逐字同构，仅数据面换成探针）：登记（CAS 写
/// 等待者表）先于 per-pid 临界区；置 Blocked 在 cur 的 per-pid 锁内完成；
/// [`wake_input_event`] 也取目标 pid 锁才改 Ready。故「记录到达（IRQ1 →
/// `push_event` → `wake_input_event`）」与「本进程登记」二者被锁完全串行——
/// 记录先到则本进程复检探针为真、不阻塞；本进程先登记则 IRQ 必在登记后
/// （锁内）读到 pid 并唤醒。`push_event` **先入队再唤醒**，保证唤醒者复检
/// 时必见记录。
///
/// **中断上下文安全性**：`wake_input_event` 由 IRQ1 调用，故其临界区只取
/// per-pid 锁（`IrqSpinLock` 在取锁期间屏蔽中断），与本函数同款；登记槽
/// 操作全为单次原子读改写，不含阻塞/分配。
pub fn block_for_input_event(
    frame: &mut InterruptFrame,
    probe: impl Fn() -> bool,
) -> InputEventBlock {
    let cur_pid = {
        // 纯 RUN 读取（b）：短暂取本核 RUN 域读 current 即可，无需 pid 锁。
        let run = run_mut(my_cpu_slot());
        let cur = run.current.expect("block_for_input_event outside process");
        assert!(
            cur < u32::MAX as usize,
            "pid {} collides with event-waiter sentinel",
            cur
        );
        cur
    };
    // 登记进等待者表：CAS 抢任意空槽；表满 = WaiterBusy（不顶掉既有等待者，
    // 遥测判读规则见 EVENT_WAITER_BUSY 文档）。
    let mut registered: Option<usize> = None;
    for (i, slot) in IN_EVENT_WAITERS.iter().enumerate() {
        if slot
            .compare_exchange(
                u32::MAX,
                cur_pid as u32,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
        {
            registered = Some(i);
            break;
        }
    }
    let Some(slot_idx) = registered else {
        EVENT_WAITER_BUSY.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return InputEventBlock::WaiterBusy;
    };
    // 登记后锁内复检（探针按本读者的判定注入）：若已有可读记录，撤销登记、
    // 不阻塞（调用方立即重读交付）。这是 lost-wakeup 的关键防线：记录先到
    // 则此处直接观察到，绝不错过。
    if probe() {
        IN_EVENT_WAITERS[slot_idx].store(u32::MAX, core::sync::atomic::Ordering::Release);
        return InputEventBlock::RecordsReady;
    }
    // 置 Blocked 并保存现场（同 block_for_event：浮点现场由 commit_next 路径
    // 在唤醒后显式保存，此处不重复归档，K2 纪律）。
    let cpu_slot = my_cpu_slot();
    // per-pid（a）：只取本核 RUN 域；cur 槽访问逐 pid 锁。
    let mut run = run_mut(cpu_slot);
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            fpu::save(&mut slot.fpu);
            slot.fs_base = gdt::read_fs_base();
            slot.proc.set_state(TaskState::Blocked);
        }
    }
    run.current = None;
    clear_current_proc();

    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {
            // **不清登记**（同 block_for_event 的 Switched 分支纪律）：
            // 本进程槽位的清除由唤醒方（wake_input_event 的 swap）负责。
            // 此处若清掉，后续按键的 push_event 会读到空表、无法唤醒本进程。
            InputEventBlock::Switched
        }
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            match schedule_from_block(frame, cur_pid) {
                // 切到其它就绪进程：自己仍 Blocked + 登记不变。
                BlockResume::SwitchedOther => InputEventBlock::Switched,
                // 自己被按键唤醒入队：切回自身。清理登记（事件唤醒已 swap 走
                // 本进程槽，CAS 无效；此处保留为对称防御，与 block_for_event
                // 同构）。
                BlockResume::SwitchedSelf => {
                    for slot in IN_EVENT_WAITERS.iter() {
                        let _ = slot.compare_exchange(
                            cur_pid as u32,
                            u32::MAX,
                            core::sync::atomic::Ordering::AcqRel,
                            core::sync::atomic::Ordering::Acquire,
                        );
                    }
                    InputEventBlock::Switched
                }
            }
        }
    }
}

/// 键盘事件记录入队后唤醒等待者（IRQ1 → `push_event` 经回调调用）。
///
/// 取走等待者表内全部 pid，若其仍处 `Blocked`，把保存帧 rax 预置为
/// 「曾阻塞、请重试」哨兵（`EVENT_WAKE_RETRY_SENTINEL` = `-EAGAIN`）并置 Ready
/// 入就绪队列——用户态 `read` 封装识别哨兵后重试取记录（与 `wake_event`
/// 的同款重试协议）。
///
/// **中断上下文**：本函数在 IRQ1 内执行，只取 per-pid 锁（IrqSpinLock 屏蔽
/// 中断）且不做分配/阻塞；`wake_enqueue` 负责跨核 IPI 的延迟唤醒。
pub fn wake_input_event() {
    // 取走**全部**槽（P1 多读者：每名阻塞读者独立交付，全部唤醒；swap 一次性
    // 清空避免与登记路径的任何中间态竞争）。无等待者：绝大多数按键都走这条
    // 快路径（一次原子写 ×8）。
    let mut pids: [u32; IN_EVENT_WAITER_SLOTS] = [u32::MAX; IN_EVENT_WAITER_SLOTS];
    for (i, slot) in IN_EVENT_WAITERS.iter().enumerate() {
        pids[i] = slot.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    }
    // per-pid（a）：只在该 pid 仍 Blocked 且非 waitpid 等待者时才唤醒——
    // 已因其它途径醒来的进程不重复入队（同 wake_event 的判据）。同一 pid
    // 占多槽（同进程并发 fd）天然去重：第一个槽置 Ready 后 state 已非 Blocked。
    for p in pids {
        if p == u32::MAX {
            continue;
        }
        let enqueue = {
            let mut g = proc_bucket_lock(p as usize);
            match g.get_mut(&(p as usize)) {
                Some(slot)
                    if slot.waiting_for.is_none()
                        && slot.proc.state() == TaskState::Blocked =>
                {
                    slot.saved.rax = EVENT_WAKE_RETRY_SENTINEL;
                    slot.proc.set_state(TaskState::Ready);
                    Some(slot.home_cpu)
                }
                _ => None,
            }
        };
        if let Some(home) = enqueue {
            wake_enqueue(p as usize, home);
        }
        // 未达唤醒判据（已醒/已死/waiting_for 占用）：无需动作——槽位已清，
        // 判据不符意味着该进程经其它途径醒来或正在等待其它资源。
    }
}

/// 清等待者表中残留的本进程登记（仅清仍指向 `pid` 的槽）。
///
/// 与 [`clear_event_waiter_if`] 同构：`read` 路径在**重新登记前**调用，清掉
/// 上一次「已就绪但登记未清」的残留，避免空槽被残留占满、本次登记被误判为
/// 「表已满」而退化成空读轮询。绝不误伤指向其它 pid 的并发等待者。
pub fn clear_input_event_waiter_if(pid: usize) {
    for slot in IN_EVENT_WAITERS.iter() {
        let _ = slot.compare_exchange(
            pid as u32,
            u32::MAX,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        );
    }
}

/// console 字节等待者槽（`u32::MAX` = 空闲）（§6.15 P2，第 4 个等待者）。
///
/// **S21 并发显式化**：与 `AUDIO_WAITER` 同构的**单槽**设计（同款原见
/// KBD_WAITER，已随 I-EVENTS P5 退役）。
/// console 的字节生产者是常驻用户态转换者 consoled（甲-a 架构），读者是
/// fd 0（stdin 换源后的前台 shell/login）——同一时刻至多一个前台进程在
/// `read(0)` 阻塞，单槽语义与业务模型吻合（`/devices/input/events` 的
/// `IN_EVENT_WAITERS` 8 槽对应其多读者形态；两者生产者/读者群都不同，
/// S15 单点定义，不共用一张表）。
///
/// **为何不抽通用 `WaitQueue`**：scheduler.rs:2437 的注释自陈「若将来出现
/// 第 4、5 个，那才是明确的抽取信号」——本表就是那个第 4 个。抽取信号
/// **已触发**，但本批次仍按 S28 以第 4 份同构代码落地（同 a-y 的既有序列
/// 纪律：先让事实到位，抽取作为独立小点随后进行，不在同一提交混入结构性
/// 重排），避免本点引入回归面扩大。**抽取候选已在此留痕。**
static CONSOLE_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// console 唤醒预置到保存帧 rax 的"曾阻塞、请重试"哨兵（`-EAGAIN`）。
///
/// **S13**：errno 取自集中定义 [`Error::WouldBlock`]，不内联裸字面量——
/// 与 `EVENT_WAKE_RETRY_SENTINEL` / `AUDIO_WAKE_RETRY_SENTINEL` 同口径。
const CONSOLE_WAKE_RETRY_SENTINEL: u64 = -(Error::WouldBlock.to_errno() as i64) as u64;

/// [`block_for_console`] 的结果（与 [`InputEventBlock`] 三态同构，S28：
/// 变体语义逐条对齐——Switched/切走、DataReady/复检已就绪、WaiterBusy/让位）。
/// **不复用** [`InputEventBlock`] 的理由与不复用 [`SwitchOutcome`] 相同（S15）：
/// 两个流的等待源、唤醒回调、登记表都不同，混用会让类型系统无法区分
/// 「事件记录就绪」与「console 字节就绪」这两个不同的事实。
pub enum ConsoleBlock {
    /// 已置 Blocked 切走：调用方须以 `DispatchResult::Switched` 收尾。
    Switched,
    /// 锁内复检发现字节**确已到达**：调用方应重读一次并如实交付。
    DataReady,
    /// 已有并发等待者：调用方应如实返回「读走 0 字节」（单槽语义，
    /// 不抢别人的唤醒——与 audio 的独占消费者仲裁同型）。
    WaiterBusy,
}


/// 阻塞当前进程等待 console 字节（`read(0)` 空读且节点 `console_stream()`
/// 为真时调用，§6.15 P2）。
///
/// 返回 [`ConsoleBlock`] 三态（成因与动作一一对应，变体名与
/// [`InputEventBlock`] 同构）：
/// - `Switched`：已置 Blocked 切走；consoled 写入字节经 `wake_console` 唤醒，
///   用户态经 `-EAGAIN` 哨兵重试 read。
/// - `DataReady`：**字节已在登记复检时就绪**（调用方立即重读交付）。
/// - `WaiterBusy`：已有并发等待者（调用方按空读处理）。
///
/// **无超时（与 audio 的关键差异，刻意的）**：audio 生产者可能是已死的
/// 驱动（有限超时保证调用者必定返回）；console 的生产者是**常驻 consoled**，
/// 与 `input_event_stream` 的无限期理由同源——终端语义下「稍后必有字节」。
/// 用户态需要非阻塞语义走 `O_NONBLOCK` 探读（`WouldBlock` 如实返回）。
///
/// `has_data` 是调用方提供的就绪探针（读环水位）。作为参数注入而非在本函数
/// 内硬编码读环，同 `block_for_audio` 的理由：task crate **不依赖 vfs**
/// （S12/S14：不制造反向依赖）。
///
/// **lost-wakeup 论证**（与 `block_for_input_event` 逐条同构）：登记（CAS 写
/// `CONSOLE_WAITER`）先于 per-pid 临界区；置 Blocked 在 cur 的 per-pid 锁内
/// 完成；[`wake_console`] 也取目标 pid 锁才改 Ready。故「字节到达 →
/// wake_console」与「本进程登记」被锁完全串行：若字节先到，wake_console 见
/// 无等待者直接返回，本进程随后复检 `has_data()` **为真** → 不阻塞；若本
/// 进程先登记，wake_console 必在登记后（锁内）读到 pid 并唤醒。不存在
/// 「登记后数据到达却无人唤醒」的窗口。
pub fn block_for_console<F>(frame: &mut InterruptFrame, has_data: F) -> ConsoleBlock
where
    F: Fn() -> bool,
{
    let cur_pid = {
        // 纯 RUN 读取（b）：短暂取本核 RUN 域读 current 即可，无需 pid 锁。
        let run = run_mut(my_cpu_slot());
        let cur = run.current.expect("block_for_console outside process");
        assert!(
            cur < u32::MAX as usize,
            "pid {} collides with console-waiter sentinel",
            cur
        );
        cur
    };
    // 登记等待者：单槽 CAS；已有并发等待者 = WaiterBusy（不顶掉既有等待者，
    // 同 audio 的独占消费者语义）。
    if CONSOLE_WAITER
        .compare_exchange(
            u32::MAX,
            cur_pid as u32,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return ConsoleBlock::WaiterBusy;
    }
    // 登记后复检就绪条件：若字节已到，撤销登记、不阻塞（调用方立即重读）。
    // 这是 lost-wakeup 的关键防线——数据先到则此处直接观察到，绝不错过。
    if has_data() {
        CONSOLE_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        return ConsoleBlock::DataReady;
    }
    // 置 Blocked 并保存现场（同 block_for_input_event：浮点现场由 commit_next
    // 路径在唤醒后显式保存，此处不重复归档，K2 纪律）。
    let cpu_slot = my_cpu_slot();
    let mut run = run_mut(cpu_slot);
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            fpu::save(&mut slot.fpu);
            slot.fs_base = gdt::read_fs_base();
            slot.proc.set_state(TaskState::Blocked);
        }
    }
    run.current = None;
    clear_current_proc();

    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {
            // **不清登记**（同 block_for_input_event 的 Switched 分支纪律）：
            // 本进程槽位的清除由唤醒方（wake_console 的 swap）负责。此处若
            // 清掉，后续字节写入会读到 MAX、无法唤醒本进程。
            ConsoleBlock::Switched
        }
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            match schedule_from_block(frame, cur_pid) {
                // 切到其它就绪进程：自己仍 Blocked + 登记不变。
                BlockResume::SwitchedOther => ConsoleBlock::Switched,
                // 自己被字节唤醒入队：切回自身。对称的条件清理（仅当登记仍
                // 指向本 pid）——数据唤醒已 swap 走登记，CAS 无效。
                BlockResume::SwitchedSelf => {
                    let _ = CONSOLE_WAITER.compare_exchange(
                        cur_pid as u32,
                        u32::MAX,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                    ConsoleBlock::Switched
                }
            }
        }
    }
}

/// console 字节写入后唤醒阻塞的读者（vfs `write_at` → wake 钩子调用）。
///
/// 取出 [`CONSOLE_WAITER`] 登记的 pid，若其仍处 `Blocked` 且未在 waitpid，
/// 把保存帧 rax 预置为「曾阻塞、请重试」哨兵并置 Ready 入就绪队列——用户态
/// `read` 封装识别哨兵后重试取字节（与 `wake_input_event` 同款重试协议）。
///
/// **调用上下文**：consoled 经 `write` syscall 写 `/devices/console`，本函数
/// 在 syscall 上下文执行（非中断）；只取 per-pid 锁且不做分配/阻塞，
/// `wake_enqueue` 负责跨核 IPI 的延迟唤醒。无等待者：快路径（一次原子读）。
pub fn wake_console() {
    let p = CONSOLE_WAITER.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    if p == u32::MAX {
        return;
    }
    let enqueue = {
        let mut g = proc_bucket_lock(p as usize);
        match g.get_mut(&(p as usize)) {
            Some(slot) if slot.waiting_for.is_none() && slot.proc.state() == TaskState::Blocked => {
                // 预置"曾阻塞、请重试"哨兵：用户态封装据此重试 read 取字节。
                slot.saved.rax = CONSOLE_WAKE_RETRY_SENTINEL;
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue {
        wake_enqueue(p as usize, home);
    }
    // 未达唤醒判据（已醒/已死/waiting_for 占用）：无需动作——槽位已清，
    // 判据不符意味着该进程经其它途径醒来或正在等待其它资源。
}

/// 清 console 等待者槽中残留的本进程登记（仅当仍指向 `pid`）。
///
/// 与 [`clear_audio_waiter_if`] 同构：`read` 路径在**重新登记前**调用，清掉
/// 上一次「已就绪但登记未清」的残留（哨兵重试路径不清登记，只有真正的字节
/// 唤醒经 swap 清），残留会让本次 CAS 失败（WaiterBusy）且退化成空读轮询。
/// 绝不误伤指向其它 pid 的并发等待者。
pub fn clear_console_waiter_if(pid: usize) {
    let _ = CONSOLE_WAITER.compare_exchange(
        pid as u32,
        u32::MAX,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire,
    );
}
/// 有设备事件入队时唤醒阻塞等待的进程（由 `driver::event::publish_event` 经
/// 回调调用）。取出 [`EVENT_WAITER`] 登记的 pid 置 `Ready` 并入就绪队列。
/// 在发布上下文调用，持锁时间极短（仅入队）。仅当等待者仍处 `Blocked` 才唤醒
/// （已因超时等其它途径醒来的进程由 `block_for_event` 返回后 CAS 清理登记）。
/// 事件唤醒回调（`driver::event::publish_event` 入队后调用）。取走唯一等待者
/// `EVENT_WAITER`，若其在 `Blocked` 且未等待 waitpid，则置 `Ready` 并加入就绪
/// 队列。唤醒前把该进程保存帧 rax 预置为"曾阻塞、请重试"哨兵（`-EAGAIN`）：
/// 进程经中断路径（tick）回归用户态时，用户态封装据此**重试** syscall 取事件。
/// 同时取消等待端注册的未到期超时定时器（避免 stale 定时器在事件唤醒后继续
/// 触发、累积占满定时器表）。
pub fn wake_event() {
    let p = EVENT_WAITER.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    // 关键：**无事件等待者（p==u32::MAX）时绝不触碰 EVENT_TIMER**。
    // 若在 p==MAX 时无条件 swap+cancel EVENT_TIMER，会误取消"刚注册了超时
    // 定时器、尚未登记 EVENT_WAITER"的 volumed（set_timeout → block_for_event
    // 之间的窗口），导致其 1s 超时唤醒失效、永久卡死在事件等待（ADR-030 热
    // 插拔端到端验证暴露：wake_event waiter=MAX timer=69 误取消 volumed 定时器，
    // departed 事件滞留无人消费）。只有真正取到一个事件等待者（p!=MAX）才
    // 取消其注册的超时定时器。
    if p == u32::MAX {
        return;
    }
    let stale = EVENT_TIMER.swap(u64::MAX, core::sync::atomic::Ordering::AcqRel);
    if stale != u64::MAX {
        klib::time::cancel_timeout(stale);
    }
    // per-pid（a）：事件唤醒路径取目标 pid 锁（IrqSpinLock ⇒ 临界区 IF 屏蔽）。
    let enqueue = {
        let mut g = proc_bucket_lock(p as usize);
        let slot = g.get_mut(&(p as usize));
        match slot {
            Some(slot) if slot.waiting_for.is_none() && slot.proc.state() == TaskState::Blocked => {
                slot.saved.rax = EVENT_WAKE_RETRY_SENTINEL;
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue { wake_enqueue(p as usize, home); }
}

/// 事件等待的超时唤醒（`klib::time::set_timeout` 回调，等待端注册）。
/// 与 [`wake_event`] 的差异：把保存帧 rax 预置为 `0`（空），用户态封装识别为
/// "超时无事件"，volumed 据此做周期对账后重新阻塞——不把超时唤醒误当事件重试。
/// 超时触发即说明定时器已到期，无需再 cancel（回调自身就是到期处置）。
///
/// O2 竞争消解：事件唤醒（wake_event）与超时唤醒对 `saved.rax` 竞争时，由下方
/// 的 `if state == Blocked` 检查保证**事件优先**——wake_event 已把等待者置
/// `Ready` 时，本回调不会覆盖其 `-EAGAIN` 哨兵（非 Blocked 不写入）；仅当等待者
/// 仍处 `Blocked`（事件尚未接管，超时是实际唤醒源）才写入 `0`。等待者在
/// `block_for_event` 的 `Some(next)` 阻塞分支切走时 EVENT_WAITER 会被 CAS 提前
/// 清理，故**不能**以 EVENT_WAITER 状态作为是否写入的依据（那会导致超时唤醒
/// 漏写哨兵、用户态把垃圾当事件长度）。`Blocked` 状态才是可靠判据。
pub fn wake_event_timeout(pid: usize) {
    EVENT_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
    // 分桶化：先置 rax 哨兵，随即释放桶锁再走 wake 入队。
    {
        let mut g = proc_bucket_lock(pid);
        if let Some(slot) = g.get_mut(&pid) {
            if slot.proc.state() == TaskState::Blocked {
                slot.saved.rax = 0;
            }
        }
    }
    wake(pid);
}

/// 记录当前事件等待注册的超时定时器 id，供 [`wake_event`] 在事件唤醒时取消
/// （`u64::MAX` = 无待取消定时器）。
pub fn set_event_timeout_timer(id: u64) {
    EVENT_TIMER.store(id, core::sync::atomic::Ordering::Release);
}

/// 清空事件等待超时定时器 id 槽（`u64::MAX` = 无）。在事件等待的**提前返回**
/// 路径（事件已就绪 / NotSwitched 取到事件 / 退化非阻塞）调用，配合
/// `klib::time::cancel_timeout` 防止 stale 定时器泄漏与级联污染新等待（S18/S21）。
pub fn clear_event_timeout_timer() {
    EVENT_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
}

/// 若 EVENT_WAITER 仍残留 `pid`（超时唤醒后本进程登记未清），CAS 清为 MAX。
///
/// 由 `event_wait_blocking` 在每次 block_for_event **重新登记前**调用：超时唤醒
/// 路径不清 EVENT_WAITER（事件唤醒才经 swap 清），残留的登记会让下次 CAS 登记
/// 失败（NotSwitched）且让 wake_event 误读本 pid、误 cancel 新定时器。只在仍
/// 指向 `pid` 时清除，绝不误伤并发等待者。
pub fn clear_event_waiter_if(pid: usize) {
    let _ = EVENT_WAITER.compare_exchange(
        pid as u32,
        u32::MAX,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire,
    );
}

/// driver_irq_wait 的等待端：阻塞当前进程直到其认领设备的 IRQ 触发或超时。
///
/// 复用 [`block_current_with`] 的 per-pid 锁内 register 复检消除 lost-wakeup：
/// - 某 IRQ 已触发（闩锁置位）→ register 复检到即返回 false（不入睡），调用方
///   立即以"已触发"交付，现场未动、零副作用。
/// - 闩锁清零且可切走 → 置 Blocked 入睡；设备 IRQ 触发时 `driver::irq_owner`
///   的 handler 置闩锁并调用注入回调 `wake_with_value(pid, 1)` 唤醒，或超时经
///   [`wake_irq_timeout`]（置 0）唤醒。
///
/// `register` 与唤醒方（`wake_with_value` 持目标 pid 锁）同锁互斥，故闩锁在
/// 置 Blocked 前/后任一时刻的触发都能被准确捕获：先触发则 register 拒睡，后
/// 触发则唤醒生效——无窗口。
pub fn block_for_irq(frame: &mut InterruptFrame, irq: u8) -> SwitchOutcome {
    // register 返回 false = 条件已满足（闩锁置位），不阻塞。
    block_current_with(frame, &mut || !driver::irq_owner::irq_pending_peek(irq))
}

/// driver_irq_wait 的超时唤醒（`klib::time::set_timeout` 回调，等待端注册）。
///
/// 与 [`wake_event_timeout`] 同款语义：把保存帧 rax 预置 `0`（超时无中断）并
/// 唤醒。与设备中断唤醒（`wake_with_value(pid, 1)`）对 `saved.rax` 的竞争由
/// `state == Blocked` 检查保证先到者胜（已置 Ready 则后到不覆盖，IRQ 优先）。
pub fn wake_irq_timeout(pid: usize) {
    {
        let mut g = proc_bucket_lock(pid);
        if let Some(slot) = g.get_mut(&pid) {
            if slot.proc.state() == TaskState::Blocked {
                slot.saved.rax = 0;
            }
        }
    }
    wake(pid);
}

/// 事件等待超时定时器 id 槽（`u64::MAX` = 无）。
static EVENT_TIMER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

// ---------- A2：音频等待者（plan_audio_vfs.md 批次二 A2.4）----------

/// 音频消费者的唯一等待者槽（`u32::MAX` = 空闲）。
///
/// **S21 并发显式化**：与 `EVENT_WAITER` 同构的**单槽**设计（同款原见
/// KBD_WAITER，已随 I-EVENTS P5 退役）。
/// 音频管道的消费者是**独占**的（同一时刻至多一个驱动在 `AUDIO_FETCH`），
/// 故单槽语义与业务模型天然吻合：并发第二个等待者本就该被拒绝（`AUDIO_ATTACH`
/// 已先行拒绝第二个消费者），此处单槽是**防御性冗余**而非能力限制。
///
/// 为何不抽通用 `WaitQueue`：当前全系统只有 3 个等待者，泛化收益不足以抵消
/// 调度器回归面扩大（plan §3.5）。三份同构代码是可接受的重复——若将来出现
/// 第 4、5 个，那才是明确的抽取信号。
static AUDIO_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// 音频等待超时定时器 id 槽（`u64::MAX` = 无）。
static AUDIO_TIMER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// 音频唤醒预置到保存帧 rax 的"曾阻塞、请重试"哨兵（`-EAGAIN`）。
///
/// **S13**：errno 取自集中定义 [`Error::WouldBlock`]，不内联裸字面量——
/// 与 `EVENT_WAKE_RETRY_SENTINEL` 同口径，改码一处即同步。
const AUDIO_WAKE_RETRY_SENTINEL: u64 = -(Error::WouldBlock.to_errno() as i64) as u64;


/// 数据到达时唤醒阻塞的音频消费者（由内核在 PCM 写入后调用）。
///
/// 取出 [`AUDIO_WAITER`] 登记的 pid 置 `Ready` 并入就绪队列，同时取消等待端
/// 注册的未到期超时定时器（防 stale 定时器在数据唤醒后继续触发、占满定时器表）。
///
/// **S21 顺序纪律**（照 `wake_event`）：`p == u32::MAX`（无等待者）时**绝不触碰**
/// `AUDIO_TIMER`。否则会误取消"刚注册了定时器、尚未登记等待者"的窗口期内那个
/// 定时器，导致其超时唤醒失效、永久卡死。只有真正取到一个等待者才取消其定时器。
///
/// 仅在等待者仍处 `Blocked` 且未在 waitpid 时才写哨兵与唤醒——已因超时等其它
/// 途径醒来的进程，其状态已非 Blocked，此处不覆盖（事件优先/超时优先由状态判定
/// 裁决，不用登记槽状态判定——那会在超时路径漏写哨兵）。
pub fn wake_audio() {
    let p = AUDIO_WAITER.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    if p == u32::MAX {
        return;
    }
    let stale = AUDIO_TIMER.swap(u64::MAX, core::sync::atomic::Ordering::AcqRel);
    if stale != u64::MAX {
        klib::time::cancel_timeout(stale);
    }
    let enqueue = {
        let mut g = proc_bucket_lock(p as usize);
        match g.get_mut(&(p as usize)) {
            Some(slot) if slot.waiting_for.is_none() && slot.proc.state() == TaskState::Blocked => {
                // 预置"曾阻塞、请重试"哨兵：用户态封装据此重试 FETCH 取数据。
                slot.saved.rax = AUDIO_WAKE_RETRY_SENTINEL;
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue {
        wake_enqueue(p as usize, home);
    }
}

/// 音频等待的超时唤醒（`klib::time::set_timeout` 回调，等待端注册）。
///
/// 与 [`wake_audio`] 的差异：把保存帧 rax 预置为 `0`（超时），用户态封装识别为
/// "超时无数据"，与"有数据请重试"（`-EAGAIN`）区分开——不把超时误当数据到达。
/// 超时触发即说明定时器已到期，无需再 cancel。
///
/// **S21 竞争消解**（与 `wake_event_timeout` 同构）：`if state == Blocked` 检查保证
/// **数据优先**——wake_audio 已把等待者置 Ready 时，本回调不覆盖其哨兵；仅当等待者
/// 仍处 Blocked（数据尚未接管，超时是实际唤醒源）才写入 0。
pub fn wake_audio_timeout(pid: usize) {
    AUDIO_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
    {
        let mut g = proc_bucket_lock(pid);
        if let Some(slot) = g.get_mut(&pid) {
            if slot.proc.state() == TaskState::Blocked {
                slot.saved.rax = 0;
            }
        }
    }
    wake(pid);
}

/// 记录音频等待注册的超时定时器 id，供 [`wake_audio`] 在数据唤醒时取消。
pub fn set_audio_timeout_timer(id: u64) {
    AUDIO_TIMER.store(id, core::sync::atomic::Ordering::Release);
}

/// 清空音频超时定时器 id 槽。在等待的**提前返回**路径调用，配合
/// `klib::time::cancel_timeout` 防止 stale 定时器泄漏与级联污染新等待（S18/S21）。
pub fn clear_audio_timeout_timer() {
    AUDIO_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
}

/// 若 [`AUDIO_WAITER`] 仍残留 `pid`（超时唤醒后登记未清），CAS 清为 MAX。
///
/// 由等待端在每次 `block_for_audio` **重新登记前**调用：超时唤醒路径不清登记
/// （数据唤醒才经 swap 清），残留会让本次 CAS 失败（NotSwitched）且让 wake_audio
/// 误读本 pid。只在仍指向 `pid` 时清除，绝不误伤并发等待者。
pub fn clear_audio_waiter_if(pid: usize) {
    let _ = AUDIO_WAITER.compare_exchange(
        pid as u32,
        u32::MAX,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire,
    );
}

/// 阻塞当前进程等待音频数据可读（`AUDIO_FETCH` 无数据时调用）。
///
/// 返回 [`SwitchOutcome`]：语义与 [`block_for_event`] 逐条对应。
/// - `Switched`：已置 Blocked 切走；唤醒后经 tick 回归用户态，`saved.rax` 由
///   唤醒方预置（数据到达置 `-EAGAIN` 重试哨兵；超时置 `0`）。调用方须以
///   `DispatchResult::Switched` 收尾。
/// - `NotSwitched`：**数据已在登记复检时就绪**（调用方应立即取数据），或已有
///   并发等待者。现场未动、无副作用。
///
/// `has_data` 是调用方提供的就绪探针（读 ring 水位）。把它作为参数而非在本函数
/// 内硬编码读 ring，是为了让 task crate **不依赖 vfs**（S12/S14：不制造反向依赖，
/// 也不为调度器开特权旁路）。
///
/// **lost-wakeup 论证**（与 `block_for_event` 同构）：登记（CAS 写 AUDIO_WAITER）
/// 先于 per-pid 临界区；置 Blocked 在 cur 的 per-pid 锁内完成；[`wake_audio`]
/// 也取目标 pid 锁才改 Ready。故"数据到达 → wake_audio"与"本进程登记"被锁完全
/// 串行：若数据先到，wake_audio 见无等待者直接返回，本进程随后复检 `has_data()`
/// **为真** → 不阻塞，返回 NotSwitched 让调用方取数；若本进程先登记，wake_audio
/// 必在登记后（锁内）读到 pid 并唤醒。不存在"登记后数据到达却无人唤醒"的窗口。
///
/// `has_data` 的调用时机关键：**在 CAS 登记之后、置 Blocked 之前**。这是闭合
/// lost-wakeup 的复检点——顺序颠倒则数据可在"复检通过"与"置 Blocked"之间到达，
/// 此时 wake_audio 读到已登记的 pid 却因尚未 Blocked 而不唤醒（见 wake_audio 的
/// `state == Blocked` 判据），进程随后入睡且无人再唤醒 = 永久挂起。
pub fn block_for_audio<F>(frame: &mut InterruptFrame, has_data: F) -> SwitchOutcome
where
    F: Fn() -> bool,
{
    let cur_pid = {
        let run = run_mut(my_cpu_slot());
        let cur = run.current.expect("block_for_audio outside process");
        assert!(
            cur < u32::MAX as usize,
            "pid {} collides with AUDIO_WAITER sentinel",
            cur
        );
        cur
    };
    if AUDIO_WAITER
        .compare_exchange(
            u32::MAX,
            cur_pid as u32,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // 已有并发等待者：不阻塞，调用方按"无数据"处理（如实 WouldBlock）。
        return SwitchOutcome::NotSwitched;
    }
    // 登记后复检就绪条件：若数据已到，撤销登记、不阻塞（调用方立即取数）。
    // 这是 lost-wakeup 的关键防线——数据先到则此处直接返回，绝不错过。
    if has_data() {
        AUDIO_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        return SwitchOutcome::NotSwitched;
    }
    let cpu_slot = my_cpu_slot();
    let mut run = run_mut(cpu_slot);
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            fpu::save(&mut slot.fpu);
            slot.fs_base = gdt::read_fs_base();
            slot.proc.set_state(TaskState::Blocked);
        }
    }
    run.current = None;
    clear_current_proc();

    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {
            // 同 block_for_event：**不在此清 AUDIO_WAITER**。切换只更新调度元数据，
            // 此处清除会抹掉已登记的等待者身份，导致数据到达时 wake_audio 读到 MAX、
            // 无法唤醒本进程。清除由唤醒方负责。
            SwitchOutcome::Switched
        }
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            match schedule_from_block(frame, cur_pid) {
                // 切到其它就绪进程：自己仍 Blocked + 登记不变。
                BlockResume::SwitchedOther => SwitchOutcome::Switched,
                // 自己被唤醒入队：切回自身。对称的条件清理（仅当登记仍指向本 pid）——
                // 数据唤醒已 swap 走登记（CAS 无效），超时唤醒则由此清除。
                BlockResume::SwitchedSelf => {
                    let _ = AUDIO_WAITER.compare_exchange(
                        cur_pid as u32,
                        u32::MAX,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                    SwitchOutcome::Switched
                }
            }
        }
    }
}


/// 事件唤醒预置到保存帧 rax 的"曾阻塞、请重试"哨兵（`-EAGAIN`）。
/// 用户态封装看到 `-EAGAIN` 即重试；`0` 表示超时无事件（见 [`wake_event_timeout`]）。
///
/// errno 值取自集中定义 [`Error::WouldBlock`]（S13 错误码单一事实源），不内联
/// 裸字面量：`klib::error::Error::to_errno` 与 libsys 同口径，改码一处即同步。
const EVENT_WAKE_RETRY_SENTINEL: u64 = -(Error::WouldBlock.to_errno() as i64) as u64;

// ---------- B21/KM15 测试钩子（仅 kernel-tests 构建存在）----------

// I-EVENTS P5：KBD_WAITER 已退役，B21 审计钩子随之移除（CONSOLE_WAITER 钩子
// debug_occupy_console_waiter/debug_release_console_waiter 是现役形态）。

/// 预占 CONSOLE_WAITER（I-EVENTS P4：stdin 阻塞源切到 console 环后，B21 的
/// 「第二并发 stdin 读者 EAGAIN」语义随之迁移到本槽——旧 KBD 钩子对 P4 后
/// 的 stdin 路径不再可达）。仅编译进 kernel-tests；运行时路径零足迹。
#[cfg(feature = "kernel-tests")]
pub fn debug_occupy_console_waiter(pid: u32) -> bool {
    CONSOLE_WAITER
        .compare_exchange(
            u32::MAX,
            pid,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

/// 释放 [`debug_occupy_console_waiter`] 的占用（恢复空槽哨兵）。
#[cfg(feature = "kernel-tests")]
pub fn debug_release_console_waiter() {
    CONSOLE_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
}

/// 设置调度器视角的当前进程（审计 B21：`block_for_console` 从本核 RUN 域的
/// `current` 取等待者 pid——仅装 per-cpu current 不够）。Busy 分支在触达
/// 进程槽表之前即返回，pid 无需对应真实槽位。
#[cfg(feature = "kernel-tests")]
pub fn debug_set_scheduler_current(pid: usize) {
    // 纯 RUN（b）：仅改本核 RUN 域 current。
    run_mut(my_cpu_slot()).current = Some(pid);
}

/// 清除调度器当前进程（与上者配对的测试收尾）。
#[cfg(feature = "kernel-tests")]
pub fn debug_clear_scheduler_current() {
    // 纯 RUN（b）：仅清本核 RUN 域 current。
    run_mut(my_cpu_slot()).current = None;
}

/// 预占 EVENT_WAITER（测试钩子，V6）：使 `block_for_event` 的"已有并发等待者"
/// 分支在单核测试中可达（Busy 语义 = 第二并发事件读者得到 NotSwitched）。
#[cfg(feature = "kernel-tests")]
pub fn debug_occupy_event_waiter(pid: u32) -> bool {
    EVENT_WAITER
        .compare_exchange(
            u32::MAX,
            pid,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

/// 释放 [`debug_occupy_event_waiter`] 的占用（恢复空槽哨兵）。
#[cfg(feature = "kernel-tests")]
pub fn debug_release_event_waiter() {
    EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
}

/// 事件等待全局探针（V6 断言用）：返回 (EVENT_WAITER, EVENT_TIMER)。
#[cfg(feature = "kernel-tests")]
pub fn debug_probe_event_globals() -> (u32, u64) {
    (
        EVENT_WAITER.load(core::sync::atomic::Ordering::Acquire),
        EVENT_TIMER.load(core::sync::atomic::Ordering::Acquire),
    )
}

/// 把 `pid` 进程的保存帧 rax 置为指定值（测试钩子，V6 断言唤醒哨兵用）。
/// 进程须存在；配合 [`test_hooks::simulate_blocked`] 构造"已阻塞的事件等待者"。
#[cfg(feature = "kernel-tests")]
pub fn debug_set_saved_rax(pid: usize, rax: u64) -> bool {
    // 分桶化：pid 在册则持其所在桶写保存帧 rax。
    let mut g = proc_bucket_lock(pid);
    let Some(slot) = g.get_mut(&pid) else {
        return false;
    };
    slot.saved.rax = rax;
    true
}

// ---------- C7.1 终止核心：zombie / 退出码交付 / 孤儿级联 ----------

/// 父进程是否具备收尸资格：存在、非 zombie。`0` 表示无父。
///
/// zombie 父进程自己都在等收尸，无资格再收尸；其子女退出时按"无父"处理
/// （立即回收），避免 zombie 链无限累积。
fn parent_reapable(ppid: usize) -> bool {
    ppid != 0
        && proc_bucket_lock(ppid)
            .get(&ppid)
            .map(|p| p.proc.state() != TaskState::Exit)
            .unwrap_or(false)
}

/// 终止结果（供日志与测试钩子断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// 无父（或父已死/父为 zombie）：槽位立即回收。
    Reclaimed,
    /// 父存活但未阻塞等待本 pid：保留为 zombie，等父 waitpid 收尸。
    ZombieKept,
    /// 已交付并即时收尸：父正阻塞 `waitpid(本 pid)`，退出码写入父
    /// `saved.rax`、父置 Ready 入队；本槽位同时释放（交付即收尸，
    /// 父醒来即拿到返回值，不再二次进入内核）。
    DeliveredToParent,
}

/// 终止 `pid`（持锁核心，[`exit_current`]/[`kill_pid`]/测试钩子共用）：
///
/// 1. 置 `TaskState::Exit`、记录退出码、移出就绪队列；
/// 2. 按父进程状态三分支：无父→回收；父阻塞等待本 pid→交付退出码并唤醒
///    （交付即收尸）；否则保留 zombie；
/// 3. 孤儿级联：无论自身去向，其 zombie 子女失去收尸人，一律回收；
/// 4. UIO 驱动沙箱清理单点化（原 `exit_current` 直删路径同样覆盖）。
///
/// per-pid：本函数自持 pid / 父 pid 的 per-pid 锁与 RUN[home]（多 pid 不再同持，
/// 逐槽升序取锁），调用方无需持任何调度锁；对不存在的 pid 返回
/// [`Termination::Reclaimed`]（幂等防御，正常路径不会发生）。
fn terminate_locked(pid: usize, code: u64) -> Termination {
    // ---- T1-3（ADR-035 D3 / threads.md T1-3）组长/组员分流（C0/C1/C2）----
    // 先短暂持 pid 桶锁读出 tgid 判身份，随即释放（组长身份 = tgid==pid；组长可能是
    // 别人的子进程，其 ppid=父进程，但组长身份**不看 ppid**，只看 tgid 与 pid 是否相等，
    // 见 C0）。判定后各步逐 pid 各自取桶锁，不跨桶同持多锁。
    let is_member = {
        let g = proc_bucket_lock(pid);
        match g.get(&pid) {
            Some(e) => e.proc.tgid() != pid,
            None => return Termination::Reclaimed, // 幂等（1694 destroyed 守卫同源）
        }
    };
    // C1：组员 exit/SIGKILL/terminate 短路为**单体保留 zombie**——不算进程退出，
    // 不进父 waitpid/WAIT_ANY 视野（R1），不做孤儿级联/过继（组员不是独立进程的父）。
    if is_member {
        return terminate_member_locked(pid, code);
    }
    // C2：组长退（含 SIGKILL 自杀/他杀）→ 整组随退。在组长**置 Exit 前**先整组展开
    // （collect-then-act，S21），把组内全部非组长组员先按单体 terminate 终止；随后组长
    // 自身走既有完整终止路径。组长退时组内已无存活组员线程，无孤儿线程组（C7）。
    terminate_whole_group_locked(pid, code);
    // 组长自身走完整终止路径（父交付 notify 父 / zombie 保留 / 回收 / 孤儿级联/过继），
    // zombie/exit_code 落点不变（C3）。
    terminate_process_locked(pid, code)
}

/// T1-3 C2：组长终止时的整组展开——终止组内除组长外全部组员线程。
///
/// 锁纪律（S21）：group_members 已 collect-then-act（逐桶短持锁仅收集后释放）；
/// 本函数在**无桶锁现场**逐 pid 调用 terminate_member_locked（逐 pid 取各自桶锁的独立
/// 操作，与既有孤儿级联逐 pid 回收同款），绝不同时跨桶持多把锁；组长与某组员同桶也
/// 不得同持两把锁（collect 已释放）。幂等：组员可能已先行退出（zombie）或已被收尸，
/// terminate_member_locked 幂等安全。
fn terminate_whole_group_locked(leader: usize, code: u64) {
    for m in group_members(leader) {
        if m != leader {
            let _ = terminate_member_locked(m, code);
        }
    }
}

/// T1-3 C1：组员（tgid != pid）的终止**短路**——单体保留 zombie。
///
/// 组员退出不算进程退出：仅置 Exit + 记退出码 + 移出就绪 + 跨核脱机 resched，然后
/// **保留为 zombie**（收尸人 = 组长显式 join / 组长退时随整组清理，R3）。与既有完整
/// 路径的三点差异：
///  1. 不做父交付：组员 ppid=组长，但组员**不是**组长可经 WAIT_ANY 收取的进程子（R1）；
///     显式 waitpid(具体组员 pid)（组长 join，C4）仍经 reap_child_locked 收尸，无需交付。
///  2. 不做孤儿级联/过继：组员不是独立进程的父（线程不另立进程子）。
///  3. 保留 zombie 而非回收：组员 zombie 生命周期（R3）= 组长 join 或组长退时随组清理。
///
/// 幂等（与既有 destroyed/state 守卫同源）：槽已 Exit 或已收尸（None）则无副作用。
/// UAF（R2）：跨核时若组员正 RUN.current 在其它核，仅置 Exit + 发 resched IPI（同既有
/// 移出就绪+脱机路径），由该核 tick 的 Exit 脱机分支（deschedule_exit_current，其会重跑
/// 本函数，幂等）切下后本槽才可被收尸/随组清理；本函数**绝不在组员未脱机时同步 remove**
/// 其 ProcEntry。
fn terminate_member_locked(pid: usize, code: u64) -> Termination {
    // per-pid：先取 pid 锁置 Exit、记退出码、读 home + leader(ppid)（单 pid 区域，随后释放）。
    // UAF(R2)守卫：绝不在此 remove 未脱机的 ProcEntry——先置 Exit 发 resched，脱机后由
    // deschedule_exit_current 重跑本函数(幂等)再收尸/交付。
    let (ppid, home) = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            Some(slot) => {
                slot.exit_code = code;
                slot.proc.set_state(TaskState::Exit);
                (slot.ppid, slot.home_cpu)
            }
            None => return Termination::Reclaimed, // 幂等：组员已被收尸/不存在
        }
    };
    // 移出 home 核就绪队列；跨核且正运行则发 resched IPI（与既有 terminate 移出就绪
    // + 脱机同款）。
    let mut hrun = run_mut(home);
    // EEVDF：`retain` -> `remove`（语义等价：把该 pid 移出就绪队列）。
    dequeue_ready(&mut hrun, pid);
    // 注意与 `wake_enqueue` 的区别：此处条件是**断言性**的——它断言"该核正在运行
    // 这个 pid"（`current` 的真实语义就是"本核正在运行的进程"），不是猜测性预判，
    // 故条件成立且必要：被终止的进程正占着那个核，必须促其尽快切走。
    // 投递失败计入 `resched_ipi_send_fail_count`，非静默。
    let cross_core_running = home != my_cpu_slot() && hrun.current == Some(pid);
    if cross_core_running {
        let _ = arch_x86_64::interrupts::send_resched_ipi_to_slot(home);
    }
    drop(hrun);
    // 单目标 join 交付：组长(ppid)若正阻塞在 waitpid(本组员 pid)上——显式 join 本线程——
    // 则交付退出码并唤醒（等同子进程退出对"显式等待该 pid"父的交付）。**仅限
    // waiting_for == Some(pid)**，绝不服务 WAIT_ANY（R1：组员不产生 waitpid/WAIT_ANY 可见的
    // 进程退出）。交付即收尸（join 回收 zombie）：组员已置 Exit、非跨核正运行时可安全
    // remove + retire；跨核未脱机时保留 zombie 由脱机后重跑本函数交付（幂等）。
    let leader_deliver = if !cross_core_running {
        let mut gp = proc_bucket_lock(ppid);
        let wake = gp.get_mut(&ppid).is_some_and(|ps| {
            ps.proc.state() == TaskState::Blocked && ps.waiting_for == Some(pid)
        });
        if wake {
            // 交付：退出码落组长 saved.rax、组员 pid 落 r10（与进程父交付同款）；组长 Ready。
            let ps = gp.get_mut(&ppid).unwrap();
            ps.waiting_for = None;
            ps.saved.rax = code;
            ps.saved.r10 = pid as u64;
            ps.proc.set_state(TaskState::Ready);
            Some(ps.home_cpu)
        } else {
            None
        }
    } else {
        None // 跨核正运行：保留 zombie，脱机后 deschedule_exit_current 重跑交付（幂等）。
    };
    if let Some(leader_home) = leader_deliver {
        wake_enqueue(ppid, leader_home);
        // join 收尸：移除组员 zombie（本核现场，安全；UAF 由 cross_core_running 守卫）。
        if let Some(e) = proc_bucket_lock(pid).remove(&pid) {
            let oh = e.home_cpu;
            vfs::flock::flock_release_all_for_owner(e.proc.identity().uid);
            // A2（S18）：进程回收时释放其占用的音频消费者槽，否则音频节点会被
            // 一个不存在的进程永久独占，拒绝所有后续驱动（静默且难排查）。
            // 与 flock 释放同点：都是"该进程持有的全局资源"归还处。
            vfs::audio::audio_on_process_exit(pid);
            retire_entry(e, oh);
        }
        Termination::DeliveredToParent
    } else {
        Termination::ZombieKept
    }
}

/// 组长/独立进程的完整终止路径（原 terminate_locked 主体）：置 Exit、移出就绪、
/// 按父状态三分支（无父→回收 / 父阻塞等待本 pid→交付退出码并唤醒 / 否则保留
/// zombie）、孤儿级联 + 孤儿过继。组长自身必须是**组长**（tgid==pid）且组内组员已
/// 由 terminate_whole_group_locked 先行终止，故此处不再感知组——组员不产生
/// waitpid/WAIT_ANY 可见的进程退出；组长 zombie 归父进程 waitpid 收尸、组员 zombie 归
/// 组长显式 join，各自落点互不混淆（C9）。由 terminate_locked 调用。
fn terminate_process_locked(pid: usize, code: u64) -> Termination {
    // per-pid：先取 pid 锁读 ppid/home 并置 Exit（单个 pid 区域，随后释放）。
    let (ppid, home) = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            Some(slot) => {
                slot.exit_code = code;
                slot.proc.set_state(TaskState::Exit);
                (slot.ppid, slot.home_cpu)
            }
            None => return Termination::Reclaimed,
        }
    };
    // 将死进程移出 home 核就绪队列：pid 锁已释放，短暂取 RUN[home]
    // 域（pid → RUN 同向；home 可能非本核，跨核 retain 原子）。
    // 修复 C：若被杀 pid 正是 home 核上**当前正在运行**的进程（跨核 SIGKILL 的
    // RUN.current 情形），其仍未脱机——terminate 只置 Exit，未清 RUN[home].current。
    // 给 home 核发一次 resched IPI，让它在下一个 IRQ0 tick 尽快走进 tick 的 Exit
    // 脱机分支（修复 A），把时延从 ~16ms 降到即时；否则该已死进程会继续在本核
    // 运行直到下一自然 tick。守卫与 wake_enqueue 同源：仅当 home 非本核才发
    // （本核情形 caller 已在 RUN 临界区内，自发 IPI 无意义）；arch 的
    // dispatch_resched 只 EOI、不碰任何调度锁，跨核发送安全。
    {
        let mut hrun = run_mut(home);
        // EEVDF：`retain` -> `remove`（语义等价）。
        dequeue_ready(&mut hrun, pid);
        // 同 L2179：断言性条件（该核正在运行此 pid），非猜测性预判。
        // 投递失败计入 `resched_ipi_send_fail_count`。
        if home != my_cpu_slot() && hrun.current == Some(pid) {
            let _ = arch_x86_64::interrupts::send_resched_ipi_to_slot(home);
        }
    }

    // 父进程判定与交付动作：reapable 自持 ppid 锁判态；若交付则在 ppid 锁内
    // 完成（写入父 waiting_for/保存帧/置 Ready 并读回父 home 供唤醒入队）。
    // 这是第二个 pid 区域，与 pid 槽互斥且单点（交付父与收尸子不并发）。
    let reapable = parent_reapable(ppid);
    let deliver_ppid_home = if reapable {
        let mut gp = proc_bucket_lock(ppid);
        let ps = gp.get_mut(&ppid).expect("parent reapable");
        if ps.proc.state() == TaskState::Blocked
            && (ps.waiting_for == Some(pid) || ps.waiting_for == Some(WAIT_ANY))
        {
            // 交付：退出码即 syscall 成功返回值（pack_ok(code) == code），
            // 直接写进父的保存帧 rax；被收尸子进程 pid 写进保存帧 r10——
            // 父被调度回来 iretq 后用户态即刻拿到 rax=code、r10=pid。
            ps.waiting_for = None;
            ps.saved.rax = code;
            ps.saved.r10 = pid as u64;
            ps.proc.set_state(TaskState::Ready);
            Some(ps.home_cpu)
        } else {
            None
        }
    } else {
        None
    };
    let deliver = deliver_ppid_home.is_some();

    let outcome = if !reapable {
        driver::uio_on_process_exit(pid);
        ipc::sync_release_process(pid);
        // R6 flock（K3）：进程回收时释放其持有的全部锁，杜绝锁表泄漏。
        if let Some(e) = proc_bucket_lock(pid).remove(&pid) {
            vfs::flock::flock_release_all_for_owner(e.proc.identity().uid);
            // A2（S18）：进程回收时释放其占用的音频消费者槽，否则音频节点会被
            // 一个不存在的进程永久独占，拒绝所有后续驱动（静默且难排查）。
            // 与 flock 释放同点：都是"该进程持有的全局资源"归还处。
            vfs::audio::audio_on_process_exit(pid);
            retire_entry(e, home);
        }
        Termination::Reclaimed
    } else if deliver {
        let ppid_home = deliver_ppid_home.unwrap();
        wake_enqueue(ppid, ppid_home);
        driver::uio_on_process_exit(pid);
        ipc::sync_release_process(pid);
        // R6 flock（K3）：进程回收时释放其持有的全部锁，杜绝锁表泄漏。
        if let Some(e) = proc_bucket_lock(pid).remove(&pid) {
            vfs::flock::flock_release_all_for_owner(e.proc.identity().uid);
            // A2（S18）：进程回收时释放其占用的音频消费者槽，否则音频节点会被
            // 一个不存在的进程永久独占，拒绝所有后续驱动（静默且难排查）。
            // 与 flock 释放同点：都是"该进程持有的全局资源"归还处。
            vfs::audio::audio_on_process_exit(pid);
            retire_entry(e, home);
        }
        Termination::DeliveredToParent
    } else {
        Termination::ZombieKept
    };

    // 孤儿级联：本进程的 zombie 子女已无人可收，直接回收（零残留）。
    // 分桶化：逐桶取锁**仅收集**属 pid 的 zombie 孤儿 pid（桶锁随即释放），
    // 再于无桶锁现场逐 pid 回收——uio/ipc/retire 等外部调用不持桶锁，与
    // 旧逐 pid 锁的"检测与回收分离、外部副作用无锁"纪律一致。
    for bucket in PROCESSES.iter() {
        let victims: Vec<usize> = {
            let gi = bucket.lock();
            gi.iter()
                .filter(|(_, e)| e.ppid == pid && e.proc.state() == TaskState::Exit)
                .map(|(p, _)| *p)
                .collect()
        };
        for v in victims {
            driver::uio_on_process_exit(v);
            ipc::sync_release_process(v);
            // R6 flock（K3）：孤儿 zombie 回收时释放其持有的全部锁。
            if let Some(e) = proc_bucket_lock(v).remove(&v) {
                let oh = e.home_cpu;
                vfs::flock::flock_release_all_for_owner(e.proc.identity().uid);
            // A2（S18）：进程回收时释放其占用的音频消费者槽，否则音频节点会被
            // 一个不存在的进程永久独占，拒绝所有后续驱动（静默且难排查）。
            // 与 flock 释放同点：都是"该进程持有的全局资源"归还处。
            vfs::audio::audio_on_process_exit(pid);
                retire_entry(e, oh);
            }
        }
    }

    // 孤儿过继：本进程的存活子女过继给 init（使它们有明确的收尸人）。
    // 仅当 init 已登记且不是本进程自身时才执行（避免自指）。
    // 分桶化：逐桶持锁，桶内直接改写存活子女的 ppid（仅改同桶，不需跨桶）。
    let init = INIT_PID.load(core::sync::atomic::Ordering::Acquire);
    if init != 0 && init != pid {
        for bucket in PROCESSES.iter() {
            let mut gi = bucket.lock();
            for (_, slot) in gi.iter_mut() {
                if slot.ppid == pid && slot.proc.state() != TaskState::Exit {
                    slot.ppid = init;
                }
            }
        }
    }

    outcome
}

/// 收尸（持锁核心）：`child` 必须是 `cur` 的在册直接子进程。
/// zombie → 取走退出码并释放槽位；仍在运行 → `None`（调用方决定阻塞或报错）。
fn reap_child_locked(cur: usize, child: usize) -> Option<(usize, u64)> {
    // 分桶化：child 所在桶自持锁（本函数只读 cur 的父子关系判据，不写 cur）。
    let mut gc = proc_bucket_lock(child);
    let is_mine = matches!(gc.get(&child), Some(e) if e.ppid == cur);
    if !is_mine {
        return None;
    }
    let exited = gc.get(&child).is_some_and(|e| e.proc.state() == TaskState::Exit);
    if !exited {
        return None;
    }
    let code = gc.get(&child).map(|e| e.exit_code).unwrap_or(0);
    driver::uio_on_process_exit(child);
    ipc::sync_release_process(child);
    if let Some(e) = gc.remove(&child) {
        let e_home_from_reap = e.home_cpu;
        retire_entry(e, e_home_from_reap);
    }
    Some((child, code))
}

/// `waitpid` 的完成形态（C7.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// 同步收尸：目标已是 zombie，被收尸子进程的 pid 与退出码随值返回。
    Reaped { pid: usize, code: u64 },
    /// 已超时唤醒（**仅** [`waitpid_timeout`] 路径会产生）：
    /// 子进程**仍在运行**，等待已到期。调用方据此**如实**向用户态
    /// 交付 `WouldBlock`（而非编造一个退出码）。
    TimedOut,
    /// 已真阻塞并切换走：退出码写入调用者保存帧 `rax`、pid 写入 `r10`
    /// （子进程终止路径直接交付），唤醒后 iretq 即得；CPU 不再回到等待方
    /// 内核调用点。
    Blocked,
}

/// `waitpid(target)` 内核实现（C7.1/#7，ADR-014 SYS_TASK_WAIT target>0 分支）。
///
/// - 目标不是调用者的在册直接子进程（不存在/非亲生/已被收尸）→
///   [`Error::NotFound`]（errno 2；klib 错误表无 ECHILD，取语义最近的
///   NotFound，映射决策记录于 ADR-014 实现注记）；
/// - 子进程已是 zombie → 同步收尸，返回 [`Waited::Reaped`]（含 pid 与退出码）；
/// - 子进程仍在运行 → 登记等待后**真阻塞**（`TaskState::Blocked`，不回就绪
///   队列），切换到下一就绪进程，返回 [`Waited::Blocked`]（退出码与 pid 由
///   子进程终止路径写入保存帧 rax/r10）——入口据此跳过
///   rax 回写，保住子进程终止路径交付到保存帧的退出码；
/// - 无其他**就绪**进程但等待目标仍**可唤醒**（如阻塞在键盘/事件上的子进程）
///   → **不**立即认输，而是 park 本核等中断（§6.13 修复；原实现在此直接拒绝，
///   导致调用方紧循环烧满一个核）；
/// - 等待目标**根本不可唤醒**（真死锁）→ 拒绝阻塞，如实返回
///   [`Error::WouldBlock`]（errno 11 EAGAIN），绝不自锁死系统。
///
/// §6.13 修复见 [`park_for_waitpid`] 与 [`blocked_wakeable`]。
///
/// ---
///
/// §6.13 修复的核心动作：**在拥有 RUN guard 的调用方**停车等中断，直到可唤醒。
///
/// # 为什么必须由调用方做
///
/// [`waitpid_inner`] 收到的是 `run: &mut PerCpuRun` —— 一个**借用**。它内部的
/// `drop(run)` 是空操作，调用方的 `run_mut` guard 仍然持有。而
/// [`schedule_from_block`] 自己要 `run()` 取同一把 `IrqSpinLock`，
/// 于是同核重入自锁（实测 panic：`schedule_from_block+0x2d0` ←
/// `waitpid_inner+0xbe3` ← `waitpid`）。故 park 只能在**持有 guard 且能释放**
/// 的调用方执行：此处先 `drop` guard，再 park。
///
/// # 语义
///
/// 前置条件（调用方保证）：`cur` 已是 `Blocked` 且 `waiting_for` 已登记，
/// CPU 上仍运行着 `cur`。本函数让出 CPU 并 `halt`，直到任一中断使就绪队列
/// 非空（`cur` 被子进程终止路径唤醒，或其它进程变为可运行）。
///
/// 返回 `true` 表示已切走（`frame` 已被改写为下一进程帧，调用方**不得**再写
/// `frame`）；被唤醒后调用方须**重新**调用 [`waitpid_inner`] 复判状态
/// （子进程可能已退出→收尸，或仍在跑→再次阻塞）。
///
/// # 为什么不是忙等
///
/// [`schedule_from_block`] 内层是 `enable(); halt();` —— CPU 停机直到中断，
/// **不消耗**运算。这正是 §6.13 缺陷（用户态 `yield_now(); continue;` 紧循环
/// 100% 占用一个核）与正确行为的分界。
fn park_for_waitpid(frame: &mut InterruptFrame, cur: usize) -> bool {
    // 关键：调用方必须先释放 RUN guard（见函数注释）。
    match schedule_from_block(frame, cur) {
        BlockResume::SwitchedSelf | BlockResume::SwitchedOther => true,
    }
}

pub fn waitpid(target_pid: usize, frame: &mut InterruptFrame) -> Result<Waited, Error> {
    // §6.13：无界等待也须能 park。原实现只调用一次 `waitpid_inner`，
    // 若此刻没有其它**就绪**进程（前台唯一子进程阻塞于 I/O 的常见情形），
    // 就回滚并抛 `WouldBlock` —— 调用方（shell）随即重试，形成 100% CPU 的
    // 紧循环。正确行为是**停车等中断**（子进程被 IRQ 唤醒→退出→唤醒本进程）。
    loop {
        // per-pid（a）：只取本核 RUN 域；表访问经 waitpid_inner 内逐 pid 锁。
        let (cur, r) = {
            let mut run = run_mut(my_cpu_slot());
            let cur = run.current.ok_or(Error::NotFound)?;
            (cur, waitpid_inner(&mut run, cur, target_pid, Some(frame)))
        };
        match r {
            Ok(w) => return Ok(w),
            Err(Error::WouldBlock) => {
                // 回滚已发生（cur 恢复 Running、登记已清）。仅当等待目标仍**可唤醒**
                // 时才 park——否则就是真死锁，如实上抛（保留既有安全语义）。
                if !blocked_wakeable_for(target_pid, cur) {
                    return Err(Error::WouldBlock);
                }
                // 重新登记后 park（park 要求 cur 已 Blocked+登记）。
                {
                    let mut gc = proc_bucket_lock(cur);
                    if let Some(slot) = gc.get_mut(&cur) {
                        slot.waiting_for = Some(target_pid);
                        slot.proc.set_state(TaskState::Blocked);
                        slot.saved = *frame;
                    }
                }
                if park_for_waitpid(frame, cur) {
                    // 已切走；被唤醒后回到循环顶部复判（可能已收尸或需再等）。
                    continue;
                }
                return Err(Error::WouldBlock);
            }
            Err(e) => return Err(e),
        }
    }
}

/// `blocked_wakeable` 的「按等待目标」形态：`WAIT_ANY` 时任一子进程可唤醒即可。
///
/// 与 `waitpid_inner` 内的判据同源（S15）：两者都归结到 [`blocked_wakeable`]。
fn blocked_wakeable_for(target_pid: usize, cur: usize) -> bool {
    if target_pid != WAIT_ANY {
        return blocked_wakeable(target_pid);
    }
    for bucket in PROCESSES.iter() {
        let gi = bucket.lock();
        for (p, e) in gi.iter() {
            if e.proc.tgid() == *p
                && e.ppid == cur
                && blocked_wakeable_parts(*p, e.proc.state() != TaskState::Exit, e.waiting_for.is_some())
            {
                return true;
            }
        }
    }
    false
}

/// [`waitpid_timeout`] 的 pre 探测（§6.12.5 ^C 根因修复 · 第二层）。
///
/// **只读**回答两件事，绝不迁移任何调度状态（对比 [`waitpid_inner`] 的
/// frame=None 测试形态会标记 Blocked / 弹出他进程置 Running / 改写
/// `run.current`——那三者对 pre 语境全是破坏性的，见 [`waitpid_timeout`] 注释）：
///
/// 1. 目标（或 WAIT_ANY 的任一直接子进程）已是 zombie → **就地收割**并返回
///    `Ok(Reaped)`（收割本身是收尸语义的一部分，与阻塞路径一致，非破坏性）；
/// 2. 单目标不存在/非亲生 → `Err(NotFound)`（与 inner 同判据）；
/// 3. 其余（有子进程但都在跑）→ `Err(WouldBlock)`（调用方继续注册定时器+真阻塞）。
fn waitpid_probe(cur: usize, target_pid: usize) -> Result<Waited, Error> {
    if target_pid == WAIT_ANY {
        // 扫描所有直接子进程：首个 zombie 即收割（与 inner 的 R1 口径一致：
        // 排除组员——组员 ppid==组长但不是进程子）。
        let mut first_zombie_child: Option<usize> = None;
        for bucket in PROCESSES.iter() {
            let gi = bucket.lock();
            for (p, e) in gi.iter() {
                if e.proc.tgid() == *p && e.ppid == cur && e.proc.state() == TaskState::Exit {
                    first_zombie_child = Some(*p);
                    break;
                }
            }
            if first_zombie_child.is_some() {
                break;
            }
        }
        if let Some(c) = first_zombie_child {
            let (pid, code) = reap_child_locked(cur, c).expect("zombie confirmed");
            return Ok(Waited::Reaped { pid, code });
        }
        // 无 zombie：有子进程 → WouldBlock（等）；无子进程 → NotFound（ECHILD）。
        let has_children = {
            let mut found = false;
            for bucket in PROCESSES.iter() {
                let gi = bucket.lock();
                if gi.iter().any(|(p, e)| e.proc.tgid() == *p && e.ppid == cur) {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_children {
            return Err(Error::NotFound);
        }
        return Err(Error::WouldBlock);
    }
    // ---- 单目标 ----
    if target_pid == 0 {
        return Err(Error::NotFound);
    }
    let is_mine = {
        let gi = proc_bucket_lock(target_pid);
        matches!(gi.get(&target_pid), Some(e) if e.ppid == cur)
    };
    if !is_mine {
        return Err(Error::NotFound);
    }
    if let Some((pid, code)) = reap_child_locked(cur, target_pid) {
        return Ok(Waited::Reaped { pid, code });
    }
    Err(Error::WouldBlock)
}

/// `waitpid(target)` 的**有界**形态（§6.11 所有者裁决 B / 2026-10-04）：
/// 最多等待 `timeout_ns`，到期时子进程**仍在运行**则**如实**返回
/// [`Waited::TimedOut`]，由 syscall 层译为 `WouldBlock` 交还用户态。
///
/// ## 为什么不是「键盘唤醒 waitpid」（裁决时否决的方案 A）
///
/// [`wake`] / [`wake_with_value`] 都带 `waiting_for.is_none()` 守卫，其文档
/// 明确写着：由 waitpid 机制独占管理的进程**不得经此唤醒**——其 `saved.rax`
/// **只能由子进程终止路径填写**，提前唤醒会让用户态把占位值当真实退出码。
/// 方案 A（键盘中断里唤醒 waitpid 等待者）正撞上这条不变量，必须为守卫开例外，
/// 等于**削弱一条现有正确防线**。方案 B 改的是**等待语义**（等多久）而非
/// **唤醒语义**（谁该醒），与那条不变量**正交**——超时是**合法的等待结束**，
/// 不是「假唤醒」，故 `saved.rax` 由本路径**显式**写成 `-EAGAIN` 哨兵，
/// 语义清晰、无歧义。
///
/// ## 与 `sleep_blocking` 的关系
///
/// 复用同一套「一次性定时器 + 到期回调唤醒」机制（`klib::time::set_timeout`），
/// 但回调**不能**用 [`wake`]（会被 `waiting_for` 守卫拒绝），故用专用回调
/// [`wake_waitpid_timeout`]。
///
/// 定时器表满时**如实返回 `WouldBlock`**（不退化忙等）——因为本动词的语义就是
/// 「至多等这么久」，立即返回「没等到」是**正确**的，不是降级。
pub fn waitpid_timeout(
    target_pid: usize,
    frame: &mut InterruptFrame,
    timeout_ns: u64,
) -> Result<Waited, Error> {
    // 本核当前进程（waitpid 的等待者）。取不到（无当前进程）如实 NotFound。
    let cur = {
        let run = run_mut(my_cpu_slot());
        run.current.ok_or(Error::NotFound)?
    };
    // 先做一次**非阻塞**的收尸尝试。子进程已是 zombie 时立即收尸返回，
    // **不**注册定时器——既省一个定时器槽，也避免「刚注册就立刻要取消」的竞态窗口。
    // §6.12.5 根因修复（^C 前台失效 · 第二层）：pre 检查**绝不能**走
    // `waitpid_inner(None)`。该 None 形态是给测试钩子用的「表级迁移」：
    // 无 zombie 可收时会**真实执行**阻塞登记（标记 cur=Blocked+waiting_for、
    // 弹出别的就绪进程置 Running、改写 `run.current`）再返回 Ok(Blocked)——
    // 在 pre 语境里这些**全部是破坏性副作用**：shell 被标记 Blocked 却仍在
    // 跑、被弹出的进程置 Running 却永远不被调度（进程被「吃掉」）、
    // `run.current` 指向一个假 Running 槽。实测（kdbg-pre）：shell 的第一次
    // 有界等待 pre 即返回 Blocked，此后前台子进程被逐次吞掉，`^C` 探键循环
    // 随之瓦解。
    //
    // 修复：pre 用**只读**探测函数——只回答两件事：「有无可收 zombie」与
    // 「有没有子进程」。都不满足阻塞条件时返回 WouldBlock 语义（继续走
    // 注册定时器+真阻塞），绝不做任何状态迁移。
    let pre = waitpid_probe(cur, target_pid);
    match pre {
        // 可收割（pre 内已同步收尸）：交付退出码与 pid，不注册定时器。
        Ok(Waited::Reaped { pid, code }) => {
            frame.rax = code;
            frame.r10 = pid as u64;
            return Ok(Waited::Reaped { pid, code });
        }
        // 真错误（非亲生/不存在）：如实上抛，不注册定时器。
        Err(e) if e != Error::WouldBlock => {
            return Err(e);
        }
        // WouldBlock = 子进程仍在运行（或 probe 无权判定），继续走有界等待。
        _ => {}
    }
    // 注册一次性定时器：到期由专用回调 `wake_waitpid_timeout` 清除等待登记、
    // 写入 -EAGAIN 哨兵并唤醒本进程。
    let Some(_timer_id) = klib::time::set_timeout(timeout_ns, wake_waitpid_timeout, cur)
    else {
        // 定时器表满（或时钟未就绪）：**如实**返回 WouldBlock——本动词语义是
        // 「至多等这么久」，立即报「没等到」是**正确**结果而非降级。
        // 绝不静默退化成无限等（S09：宁可如实报未等到，也不给错误行为）。
        return Err(Error::WouldBlock);
    };
    // 走既有阻塞登记路径（waiting_for + Blocked + 切换）。
    let r = {
        let mut run = run_mut(my_cpu_slot());
        waitpid_inner(&mut run, cur, target_pid, Some(frame))
    };
    match r {
        // 已阻塞并切走：此后由**两条互斥路径**之一唤醒本进程——
        //   ① 子进程退出路径：写真实退出码（既有交付机制，未改）；
        //   ② 本函数的定时器回调：写 -EAGAIN 哨兵。
        // 二者都显式写 `saved.rax`，故用户态**绝不会**拿到占位值。
        Ok(Waited::Blocked) => {
            Ok(Waited::Blocked)
        }
        // ---- §6.13 修复：就绪队列空**不等于**无人会醒来 ----
        //
        // 【缺陷】原实现在此无条件 `cancel_timeout` + 返回 `WouldBlock`。
        // 前台唯一子进程**阻塞于 I/O** 时它不在就绪队列，于是每次都走到这里
        // → 调用方（`shell` 的 `commands.rs:2852`）`yield_now(); continue;`
        // → **100% 占用一个核**（实测 `wp_refused` 19378 次 / 8 秒，docs §6.13）。
        //
        // 【为何原实现错】「此刻无人可切」不代表「无人会醒来」：子进程登记在
        // 等待源上，IRQ（键盘/事件/定时器）到达即唤醒它，退出后终止路径
        // `wake_enqueue(ppid, ...)` 唤醒本进程。故正确动作是**停车等中断**。
        //
        // 【为何在此处做】`run` guard 由本函数的块作用域持有，块结束即释放；
        // 随后 [`schedule_from_block`] 才能安全取 RUN（不可重入，见
        // [`park_for_waitpid`] 注释）。绝不能放进 `waitpid_inner`（借用形态）。
        //
        // 【定时器处理】park 期间**保留**已注册的定时器：它正是本动词「至多等
        // 这么久」的兑现者——到期回调会唤醒本进程并写 -EAGAIN 哨兵，
        // 于是有界语义**逐字不变**（这是与「无界 park」的关键区别）。
        Err(Error::WouldBlock) if blocked_wakeable_for(target_pid, cur) => {
            // 重新登记（inner 的 revert 已清）：park 要求 cur 已 Blocked+登记。
            {
                let mut gc = proc_bucket_lock(cur);
                if let Some(slot) = gc.get_mut(&cur) {
                    slot.waiting_for = Some(target_pid);
                    slot.proc.set_state(TaskState::Blocked);
                    slot.saved = *frame;
                }
            }
            let _ = park_for_waitpid(frame, cur);
            // 已切走：唤醒后的结果由保存帧 rax 交付（真实退出码或 -EAGAIN），
            // 与 `Ok(Waited::Blocked)` 路径**同一条**交付机制（S13 单一路径）。
            Ok(Waited::Blocked)
        }
        // 真死锁（目标根本不可唤醒）：撤销定时器并如实报「没等到」。
        Err(e) => {
            klib::time::cancel_timeout(_timer_id);
            Err(e)
        }
        Ok(other) => Ok(other),
    }
}

/// [`waitpid_timeout`] 的超时回调：把等待者如实体面为「没等到」。
///
/// **与 [`wake`] 的关键差异**：本函数**专为** `waiting_for.is_some()` 的进程设计，
/// 故**不**套用那条守卫，而是**显式**完成守卫所保护的两件事：
///
/// 1. 清 `waiting_for`（该进程不再是 waitpid 的等待者，回归普通可唤醒态）；
/// 2. 写 `saved.rax = -EAGAIN` 哨兵——**这正是守卫存在的理由**：
///    绝不能让用户态拿到占位值 0 并当成真实退出码。此处写入的是**明确的**
///    「超时、没等到」错误码，语义与守卫的意图一致（防伪退出码），不违背其精神。
///
/// 只有在「仍在等待**同一个**目标」时才动作，避免竞态下误伤已经收尸/改等的进程。
pub fn wake_waitpid_timeout(pid: usize) {
    let enqueue = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            // 仍处于 waitpid 等待中才处理：已 Ready/Exit/已改等别的目标则忽略。
            Some(slot)
                if slot.proc.state() == TaskState::Blocked
                    && slot.waiting_for.is_some() =>
            {
                slot.waiting_for = None;
                slot.saved.rax = WAITPID_TIMEOUT_SENTINEL;
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue {
        wake_enqueue(pid, home);
    }

}

/// 有界 waitpid 超时的 `-EAGAIN` 重试哨兵（写入等待者 `saved.rax`）。
///
/// errno 取自集中定义 [`Error::WouldBlock`]（S13 单点），与
/// [`EVENT_WAKE_RETRY_SENTINEL`] 同口径——
/// 用户态 `libsys::call` 解码为 `Err(WouldBlock)`，据此知道「没等到、可重试」，
/// **绝不**把陈旧或占位 rax 当成子进程退出码。
const WAITPID_TIMEOUT_SENTINEL: u64 = -(Error::WouldBlock.to_errno() as i64) as u64;

/// [`waitpid`] 的锁内主体。`frame = None` 为测试钩子形态：只做表级登记与
/// 状态迁移，不做 CPU 切换（物理切换路径由 m41/m42/kbd 既有验收与
/// kernel-test-waitpid 停机验收覆盖）。
/// 判定进程 `pid` 是否「已阻塞但**仍会被唤醒**」——§6.13 修复的核心判据。
///
/// # 为什么需要这个判据
///
/// [`waitpid_inner`] 让出 CPU 前必须确认「让出后有人能让我再跑起来」。
/// 原判据只认 Ready/Running 的进程，于是**前台子进程阻塞于 I/O** 这一最常见的
/// 情形被判为「无人可运行」→ 拒绝阻塞 → `shell` 立刻重试 → 烧满一个核
/// （实测 ~99%，见 docs/TODO/terminal-input.md §6.13）。
///
/// 关键在于：阻塞的进程**不是死掉的**——它登记在某个等待源上，硬件中断到达时
/// 会被唤醒、继续推进、最终退出，而子进程终止路径 `wake_enqueue(ppid, ...)`
/// 会唤醒本进程。故「子进程已阻塞」**不等于**「无人可推进」。
///
/// # 为什么不能简单判 `state != Exit`
///
/// 「存活」不等于「会醒来」。一个 `Blocked` 却**未登记任何等待源**的进程
/// 永远不会被唤醒（真实系统中的永久泄漏）。若把它也算作可唤醒，
/// 父进程就会真的自锁。停机测试 `test-waitpid-core` 的第 8 项
/// （`deadlock-refusal`）正是用 `simulate_blocked` 构造这个情形来钉死
/// 「真死锁必须如实拒绝」的语义——简单放宽会破坏它。
///
/// 故判据是**两段**：进程存在且非 Exit，**且**它登记在某个等待源上。
///
/// # 等待源清单（**新增等待源时必须同步此处**）
///
/// 当前内核的阻塞等待源及其登记槽：
///
/// | 等待源 | 登记槽 | 唤醒方 |
/// | --- | --- | --- |
/// | ~~键盘字节（`stdin`）~~ | ~~`KBD_WAITER`~~ | ~~IRQ1~~ | I-EVENTS P5 退役：stdin 等待源 = `CONSOLE_WAITER`（console 环） |
/// | 通用事件（`event_wait`） | `EVENT_WAITER` / `EVENT_TIMER` | 事件投递 / 定时器 |
/// | 键盘**事件记录**（`/devices/input/events`） | `IN_EVENT_WAITERS` 表 | IRQ1 |
/// | 音频 PCM 数据 | `AUDIO_WAITER` | PCM 写入 / 定时器 |
/// | `waitpid` | `slot.waiting_for` | 子进程终止路径 |
///
/// # 维护纪律（S15 单一真值）
///
/// 本函数是**多个全局单槽 + 一个 per-process 字段的「或」**，是一处
/// **已知的耦合点**：将来新增等待源而忘记在此登记，会让 §6.13 的缺陷
/// **重新出现**（表现为「新等待源上的阻塞子进程导致父进程烧 CPU」）。
///
/// 更彻底的形态是在 PCB 上加一个显式 `blocked_wakeable` 标记，由各阻塞路径置位、
/// 各唤醒路径清除——那才是真正的单点定义。本轮**未**采用（需改动 4+ 条
/// 阻塞/唤醒路径，超出本小点范围），故在此显式登记该技术债。
fn blocked_wakeable(pid: usize) -> bool {
    // 取锁形态：仅用于**未持有**任何桶锁的语境（单目标路径）。
    let (alive, waiting_for) = {
        let g = proc_bucket_lock(pid);
        match g.get(&pid) {
            Some(e) if e.proc.state() != TaskState::Exit => (true, e.waiting_for.is_some()),
            _ => (false, false),
        }
    };
    blocked_wakeable_parts(pid, alive, waiting_for)
}

/// [`blocked_wakeable`] 的**已持锁**形态：供调用方在持有该进程所在桶锁时使用。
///
/// **存在的唯一理由**：`SpinMutex` 同核重入即死锁。`waitpid_inner` 的 `WAIT_ANY`
/// 扫描**已持桶锁**，此时再 `proc_bucket_lock(pid)` 会自锁——实测 panic：
/// `SpinMutex 同核重入死锁`（栈 `blocked_wakeable -> waitpid_inner -> waitpid_timeout`）。
/// 故必须复用已取到的条目，由调用方把两个真值读出来传入。
///
/// 全局单槽检查是原子读、不涉锁，故两种形态共用同一收尾逻辑（S15）。
fn blocked_wakeable_parts(pid: usize, alive: bool, waiting_for: bool) -> bool {
    use core::sync::atomic::Ordering;
    if !alive {
        return false;
    }
    if waiting_for {
        return true;
    }
    let p = pid as u32;
    // I-EVENTS P5：KBD_WAITER 已退役（stdin 等待源唯一是 CONSOLE_WAITER，其清理
    // 由 clear_console_waiter_if 在进程退出路径完成），此处不再核对键盘槽。
    if EVENT_WAITER.load(Ordering::Acquire) == p || AUDIO_WAITER.load(Ordering::Acquire) == p {
        return true;
    }
    // P1 多槽表：任一槽仍登记本 pid 即视为「有未完成的等待登记」。
    IN_EVENT_WAITERS
        .iter()
        .any(|s| s.load(Ordering::Acquire) == p)
}

fn waitpid_inner(
    run: &mut PerCpuRun,
    cur: usize,
    target_pid: usize,
    mut frame: Option<&mut InterruptFrame>,
) -> Result<Waited, Error> {
    // ---- WAIT_ANY（等待任意子进程）分支 ----
    if target_pid == WAIT_ANY {
        // 1. 扫描所有子进程，如有 zombie 则收割（取第一个）。逐桶升序取锁。
        //    桶内 BTreeMap 按 pid 升序迭代；判到首个 zombie 子进程即记下其 pid，
        //    释放桶锁后再交 reap_child_locked 重取该子桶完成收割（避免同桶重锁）。
        let mut first_zombie_child: Option<usize> = None;
        for bucket in PROCESSES.iter() {
            let gi = bucket.lock();
            for (p, e) in gi.iter() {
                // R1：排除组员——组员 ppid==组长（可被组长显式 join / C4），但**不是**
                // 组长可经 WAIT_ANY 收取的进程子。真正的进程子 tgid == 自身 pid（自己的
                // 组长/独立进程）；组员 tgid != 自身 pid，跳过，不得误报给组长。
                if e.proc.tgid() == *p && e.ppid == cur && e.proc.state() == TaskState::Exit {
                    first_zombie_child = Some(*p);
                    break;
                }
            }
            if first_zombie_child.is_some() {
                break;
            }
        }
        if let Some(c) = first_zombie_child {
            let (pid, code) = reap_child_locked(cur, c).expect("zombie confirmed");
            return Ok(Waited::Reaped { pid, code });
        }
        // 2. 无 zombie：检查是否至少有一个子进程存在。
        let has_children = {
            let mut found = false;
            for bucket in PROCESSES.iter() {
                let gi = bucket.lock();
                // R1：has_children 同样排除组员（组员不是 WAIT_ANY 可等的进程子；否则组长
                // 仅有组员时会被误判"有子进程"而走进永久阻塞路径）。
                if gi.iter().any(|(p, e)| e.proc.tgid() == *p && e.ppid == cur) {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_children {
            return Err(Error::NotFound); // 无子进程 = ECHILD 等价
        }
        // 3. 有子进程但无 zombie → 走阻塞路径（哨兵标记 WAIT_ANY）。
    } else {
        // ---- 单目标（既有）分支 ----
        if target_pid == 0 {
            return Err(Error::NotFound);
        }
        // 只能等待自己的直接子进程（无界 pid：存在性以目标是否在册为准）。
        let is_mine = {
            let gi = proc_bucket_lock(target_pid);
            matches!(gi.get(&target_pid), Some(e) if e.ppid == cur)
        };
        if !is_mine {
            return Err(Error::NotFound);
        }
        if let Some((pid, code)) = reap_child_locked(cur, target_pid) {
            return Ok(Waited::Reaped { pid, code }); // zombie 同步收尸
        }
    }

    // 阻塞等待（WAIT_ANY 与单目标共用阻塞逻辑）。
    // 等待目标：WAIT_ANY 或具体 pid。
    let wait_for = if target_pid == WAIT_ANY { WAIT_ANY } else { target_pid };
    // "有无可切对象"必须**全系统**判定，不能只看本核就绪队列。
    //
    // 旧实现只扫 `run.ready`（本核队列）便拒绝阻塞返回 `WouldBlock`。多核下
    // 这几乎必然误判：子进程 home 在别的核、或此刻所有可运行进程都排在别的核
    // 队列上时，本核队列为空 —— 但子进程**照样会跑完**，其终止路径经
    // `deliver_ppid_home` **跨核**把本进程置 Ready 并唤醒（见终止路径注释）。
    // 故"本核队列空"不等于"无人可运行"，更不等于"不该阻塞"。
    //
    // 误判代价极高：shell 前台 `exec` 后 `waitpid_any` 拿到 `WouldBlock`，
    // 旧实现直接放弃并 exit(126)，留下仍在跑的子进程；init 随即重拉 shell，
    // 多个将死 shell 并发读键盘缓冲瓜分输入（`clear` 变 `r`/`clea`）。
    //
    // 正确判据：**系统内是否还有别的可运行进程**（任意核的 ready 或某核正在
    // 运行的非 cur 进程）。有 → 阻塞安全（cur 被唤醒的路径不依赖本核队列）。
    // 只有全系统确实无他人可运行时才拒绝，避免让出后无人可运行。
    let others_ready = {
        let mut found = false;
        for slot in 0..MAX_SCHED_CPUS {
            if slot == my_cpu_slot() {
                // 本核：直接用调用方已持有的 run（同域，不可重入取锁）。
                // EEVDF：`iter()` -> `iter_pids()`（只看 pid，与顺序无关）。
                if run.ready.iter_pids().any(|p| p != cur) {
                    found = true;
                    break;
                }
            } else {
                // 经全路径调用，避开形参 `run` 的同名遮蔽。
                let g = crate::scheduler::run(slot);
                if g.ready.iter_pids().any(|p| p != cur) {
                    found = true;
                    break;
                }
            }
        }
        found
    };
    // 登记/回滚在 cur 的 per-pid 锁内完成（与子进程终止路径对父的交付互斥）。
    let revert = |cur: usize| -> Error {
        let mut gc = proc_bucket_lock(cur);
        if let Some(slot) = gc.get_mut(&cur) {
            slot.waiting_for = None;
            slot.proc.set_state(TaskState::Running);
        }
        Error::WouldBlock
    };
    // ---- §6.13 修复：阻塞安全性第二判据 ----
    //
    // 【缺陷】上方的 `others_ready` 只认「Ready/Running」的进程。前台子进程
    // **阻塞于 I/O**（读键盘 / 读事件节点 / 等音频）时它**不在** ready 队列，
    // 于是「前台唯一子进程阻塞」这一**最常见**的情形被判为「无人可运行」→
    // 拒绝阻塞 → 调用方（`shell` 的 `commands.rs:2852`）拿到 `WouldBlock` 后
    // `yield_now(); continue;` **立刻重试** → 用户态紧循环烧满一个核。
    //
    // 实测（docs/TODO/terminal-input.md §6.13）：前台跑 `blkdemo`（阻塞读 stdin）
    // 或 `evdemo`（阻塞读事件节点）时宿主 CPU ≈ 100%，而 `shell` 空闲仅 ≈ 6%。
    // 二者与「事件流」无关——缺陷在**本判据**，与等待源无关。
    //
    // 【为何可以让出】原判据的顾虑是「让出后无人可运行 ⇒ 自锁」。该顾虑在
    // 本情形下**不成立**，因为唤醒本进程的路径**不依赖 ready 队列**：
    //
    //   1. 子进程退出 → 终止路径 `wake_enqueue(ppid, ppid_home)`
    //      （本文件 :2900）直接入队并投 IPI 唤醒本进程——与「本核队列里有没有
    //      别人」完全无关；
    //   2. 子进程虽 Blocked，但其等待源（IRQ1 键盘 / 事件回调 / 音频 / 定时器）
    //      **仍会到达**：中断一旦到达，子进程被唤醒→最终退出→走 (1) 唤醒本进程；
    //   3. 即使全系统真的无人可运行，本核进入 `idle_loop_body` 用的是
    //      **`hlt`**（`arch-x86_64/src/scheduler` 的 idle 循环），CPU 停机待中断，
    //      **不会空转烧 CPU**；IRQ0 tick 亦会周期性重查。故「让出」的最小代价
    //      只是「等一个中断」，远优于**100% 占用一个核**。
    //
    // 【判据】「存在可被唤醒的等待目标」= 本进程仍有直接子进程**且该子进程
    // 登记了等待源**（判定集中在 [`blocked_wakeable`]，此处不另造口径，S15）。
    //
    // **不能**简化成「子进程存活（非 Exit）」：存活不等于会醒来，
    // 一个无等待源的 Blocked 进程永不被唤醒，那样会让父进程真自锁，
    // 并被 `test-waitpid-core` 第 8 项（`deadlock-refusal`）钉死。
    //
    // 【为何不必担心「子进程永远不退出」】那不是本判据的责任：`shell` 用的是
    // **有界**等待（`waitpid_any_timeout` + 定时器），到期由
    // `wake_waitpid_timeout` 唤醒并如实返回「没等到」，调用方可重试或放弃。
    // 本判据只需回答「让出后有没有人/有没有中断能让我再跑起来」。
    let target_wakeable = if others_ready {
        true
    } else if target_pid == WAIT_ANY {
        // WAIT_ANY：任一直接子进程「注册了等待源」即可（见下方判据说明）。
        let mut ok = false;
        for bucket in PROCESSES.iter() {
            let gi = bucket.lock();
            for (p, e) in gi.iter() {
                // **必须**用 `_parts` 形态：此处已持桶锁，再取同桶锁会自锁
                // （S21 显式并发；实测 panic 见 `blocked_wakeable_parts` 注释）。
                if e.proc.tgid() == *p && e.ppid == cur {
                    if blocked_wakeable_parts(
                        *p,
                        e.proc.state() != TaskState::Exit,
                        e.waiting_for.is_some(),
                    ) {
                        ok = true;
                        break;
                    }
                }
            }
            if ok {
                break;
            }
        }
        ok
    } else {
        // 单目标：该子进程仍存活且注册了等待源。
        let mine = {
            let gi = proc_bucket_lock(target_pid);
            gi.get(&target_pid).is_some_and(|e| e.proc.tgid() == target_pid)
        };
        mine && blocked_wakeable(target_pid)
    };
    if !target_wakeable {
        return Err(revert(cur)); // 尚未标记，直接拒绝
    }
    {
        let mut gc = proc_bucket_lock(cur);
        let slot = gc.get_mut(&cur).expect("current proc exists");
        slot.waiting_for = Some(wait_for);
        slot.proc.set_state(TaskState::Blocked);
        // 占位 rax 随 saved 保存；真实退出码由子进程终止路径覆写。
        // 测试钩子形态（frame=None）不保存帧：saved 保持初始值，交付路径覆写。
        if let Some(f) = frame.as_deref_mut() {
            f.rax = 0;
            slot.saved = *f;
        }
    }
    // cur 已 Blocked+waiting_for 登记。切换到任一非 cur 就绪进程。
    if let Some(f) = frame.as_deref_mut() {
        // 物理切换形态（真实 syscall）：统一"选 next + 原子提交切换"原语（DESIGN §3.2）。
        // exclude=cur：绝不切回自身(waitpid 语义，cur 在等子进程)；候选被跨核 reap/置 Exit
        // 时被丢弃重选，绝不 .expect panic、不切进已回收槽；next 桶锁贯穿切换(杜绝窗口 B)。
        // 队列耗尽(无其它就绪，仅剩已 Blocked 的 cur)——撤销阻塞(清 waiting_for、恢复
        // Running)如实报 WouldBlock(与 waitpid_inner 既有 revert 语义一致)。
        match pop_and_commit_switch(run, f, Some(cur), cur) {
            NextCommit::Switched => Ok(Waited::Blocked),
            // NothingSelf 不可达(cur 已被 exclude 排除)；Empty=无其它可切 -> revert。
            //
            // **§6.13**：此处**不能** park —— `run` 是调用方持有的 `&mut` 借用，
            // 本函数 `drop(run)` 是空操作，`schedule_from_block` 自取 RUN 会
            // 同核重入自锁（实测 panic：`schedule_from_block+0x2d0` ←
            // `waitpid_inner`）。park 必须由**拥有 guard 的调用方**执行，
            // 见 [`park_until_wakeable`]。
            NextCommit::Empty | NextCommit::NothingSelf => Err(revert(cur)),
        }
    } else {
        // 测试形态(frame=None)：只做表级状态迁移，不做物理 CPU 切换。仍须跳过被跨核
        // reap/置 Exit 的候选(槽 None/Exit 不置 Running、不成为 current)，保持表级一致。
        loop {
            let Some(p) = pop_ready_filtered(run, cur) else {
                // 极小窗口防御：就绪项全失效/已耗尽。撤销阻塞如实报错。
                return Err(revert(cur));
            };
            if p == cur {
                return Err(revert(cur));
            }
            let committed = {
                let mut g = proc_bucket_lock(p);
                if g.get(&p).is_some_and(|s| s.proc.state() == TaskState::Ready) {
                    if let Some(slot) = g.get_mut(&p) {
                        slot.proc.set_state(TaskState::Running);
                    }
                    true
                } else {
                    false // p 已被 reap/置 Exit：丢弃重选(I1)
                }
            };
            if committed {
                run.current = Some(p);
                return Ok(Waited::Blocked);
            }
        }
    }
}

/// 从就绪队列取下一个有效进程，额外跳过 `exclude`（waitpid 场景排除自身）。
/// 仅接受 `Ready` 状态（Blocked 项不得被切换执行）——实现已并入 [`pop_ready`]
/// 单点（task1 KM8），此包装保留 waitpid 调用点的语义命名。
fn pop_ready_filtered(run: &mut PerCpuRun, exclude: usize) -> Option<usize> {
    pop_ready(run, exclude)
}

/// 当前 pid 是否处于 `Exit` 态（逐 pid 所在桶锁短暂探测）。
fn current_is_exit(pid: usize) -> bool {
    proc_bucket_lock(pid)
        .get(&pid)
        .is_some_and(|s| s.proc.state() == TaskState::Exit)
}

/// 把一个已在 `Exit` 态、但仍 `RUN.current` 运行在本核的进程脱机（修复 A/B）。
///
/// 产生这种状态的唯一途径是**跨核 SIGKILL**：killer 核的 [`terminate_locked`]
/// 已把本进程置 `Exit`（记录退出码、移出就绪队列、置 ZombieKept/交付/回收），
/// 但本核当时正在运行它（用户态忙转 / 内核阻塞 syscall 中），尚未把它切下 CPU。
///
/// 本函数（幂等）：
/// 1. 重跑一次 [`terminate_locked`]——它是幂等的：槽已是 `Exit`、父活且未等则
///    维持 ZombieKept；若父自上次终止后**转为 Blocked 等待本 pid/ANY** 则交付并
///    回收；若槽已被 waitpid 收尸（None）则 `Reclaimed` 空操作。重跑顺带消化
///    上一轮 kill 与本次脱机之间父进程状态翻转的交付窗口；
/// 2. 清本核 `RUN.current` 与 `CURRENT_PROC`，切到下一就绪进程或进空闲 halt，
///    与 [`exit_current`] 尾部完全同构。
///
/// 锁序约束：调用方必须先释放本核 RUN 域与一切 per-pid 锁再调用（本函数在
/// 无锁现场重跑 terminate_locked，其自取 pid 锁 + RUN[home]）；本函数不得在
/// Exit 进程自身的槽上再写 Ready/Running（复活）。`retire_entry` 经 `DEAD_KSTACKS`
/// 延迟归还将死进程内核栈，本函数可能物理运行在该栈上（tick 的 TSS.RSP0 / 阻塞
/// syscall），切走后经 `gdt::set_rsp0` 脱离，不就地释放——安全前提同 [`exit_current`]。
fn deschedule_exit_current(frame: &mut InterruptFrame, cur_pid: usize) {
    // 读当前退出码（逐 pid 所在桶短暂取；已收尸则退 0，重跑 terminate 无副作用）。
    let exit_code = proc_bucket_lock(cur_pid)
        .get(&cur_pid)
        .map(|s| s.exit_code)
        .unwrap_or(0);
    // 此刻无任何调度锁：terminate_locked 自取 pid 锁 + RUN[home==本核]。
    let _ = terminate_locked(cur_pid, exit_code);
    let cpu_slot = my_cpu_slot();
    let mut run = run_mut(cpu_slot);
    run.current = None;
    clear_current_proc();
    // 统一"选 next + 原子提交切换"原语（DESIGN §3.2/§4 #9）：prev=None(cur 已 Exit、槽随
    // terminate 退役，浮点现场随其消亡无需保存)。候选被跨核 reap/置 Exit 则丢弃重选，绝不
    // .expect panic、不切进已回收槽；next 桶锁贯穿切换(杜绝窗口 B)。
    // 无有效候选时本核物理运行在将死 cur 栈上：空队停车必须切到本核 idle 栈
    // (go_idle_on_own_stack)，绝不在将死栈上 halt(父核可 reap+drain 释放之 → UAF)。
    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {} // 已切入 next，frame 已改
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            // A2 修复：本函数此刻物理运行在将死(被 SIGKILL 后脱机)进程栈上；
            // 空队停车必须切到本核 idle 栈，绝不在将死栈上 halt(reaper 可回收之)。
            go_idle_on_own_stack()
        }
    }
}

// ---------- A2: 核 idle 停车在本核常驻栈，不在将死进程栈上 ----------

/// 将本核物理 RSP 切到本核自己的 idle (常驻引导) 内核栈，并在该栈上等待本核 RUN 就绪队非空。
///
/// 为什么必须：下方路径在将死进程脱机后无就绪可切，若直接在将死栈上 halt 等待，
/// 另一核 (父/reaper) 可收尸并经 DEAD_KSTACKS drain 释放该栈 → 本核的活 RSP 落在已释放内存上 (UAF)。
/// 这里在切栈后把本核 TSS.rsp0 也指回 idle 栈顶，使 idle 期间的中断也落在安全栈上。
/// 调用前必须已释放本核 RUN 与一切 per-pid 锁（同旧路径 drop run 后停车一致）。永不返回。
fn go_idle_on_own_stack() -> ! {
    let cpu_slot = my_cpu_slot();
    // 本核常驻内核栈顶：BSP=BSP_KSTACK，AP=AP_STACK_SIZE 栈（均在 gdt::register_cpu_slot 登记）。
    let idle_top = arch_x86_64::gdt::boot_kstack_top(cpu_slot);
    debug_assert!(idle_top != 0, "go_idle: 本核 idle 栈未登记");
    // 切栈前先关中断，避免切换途中中断落在将弃进程栈上。
    arch_x86_64::interrupts::disable();
    // rsp0 → idle 栈顶：idle 期间 IRQ0 醒睡时切到本核自己的栈，而非被放弃的进程栈。
    arch_x86_64::gdt::set_rsp0_for_slot(cpu_slot, idle_top);
    // 物理 RSP 切到 idle 栈后进入 idle循环（不回到旧进程栈）。
    unsafe { idle_stack_switch(idle_top) }
}

/// 切换 RSP 到 idle 栈顶附近并跳入 idle循环上下文，永不返回旧栈。
#[unsafe(naked)]
unsafe extern "C" fn idle_stack_switch(idle_top: u64) -> ! {
    // naked: rdi = idle_top。设 RSP = idle_top - 预留帧高度（用户中断从 rsp0=idle_top 向下压帧，
    // 预留充足余量使其不与 idle循环框架碰撞），再 16字节对齐后跳入常规函数。
    // jmp 进入 idle_loop_body；把 rsp 置为 8 mod 16 (标准 C ABI 入口对齐)。
    // idle_loop_body 为 `-> !` 永不返回，故无需返回地址。
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "sub rsp, 4104",   // 4096 栈高余量 + 8 → 入口 rsp%16==8
        "jmp {body}",
        body = sym idle_loop_body,
    );
}

/// idle循环主体（运行在 idle 栈上）：关中断条件下 halt 等本核 RUN 就绪队非空，
/// 然后弹出一个就绪进程并经全量 InterruptFrame iretq 恢复到用户态。
unsafe extern "C" fn idle_loop_body() -> ! {
    let cpu_slot = my_cpu_slot();
    // **顺序至关重要：必须先切回内核根页表，再 drain。**
    //
    // A4 修复：本核刚切下某个将死进程并停车，CR3 可能仍指向该进程的用户页表。
    // 内核根表高半区映射与本核一致，切换对运行中的内核透明；后续
    // `switch_apply_next` 切到新进程时会再写回其表。
    //
    // 先切 CR3 才有下面的安全性：`drain_dead_kstacks` 会 `drop(proc)`，而
    // `UserAddressSpace::destroy` 释放顶层页表帧。若此刻本核 CR3 仍悬在该表上，
    // 释放后本核下一条指令的取指就走已回收的表 → 取指缺页 → 三重故障。
    // 切换在前即杜绝此路径（`destroy` 内部也据此判定为"非活动表"直接归还）。
    arch_x86_64::paging::switch_to_kernel_root();
    // 本核已停车在**自己的 idle 栈**上（确定不在任何进程栈上执行）且已切回
    // 内核根页表（确定不悬在任何将死页表上）：此时归还栈帧与地址空间才安全。
    // 跨核收尸入队的、本核曾运行进程的资源，经 A3 go_idle 后本核已切下它们。
    drain_dead_kstacks();
    // 开中断后 halt：与旧 idle halt 一致。spawn 不发 IPI，依赖下一次 IRQ0 醒睡後重检（同 start()）。
    arch_x86_64::interrupts::enable();
    loop {
        // 等就绪队非空（每次 halt 直到中断到达，绝不忙转）。
        loop {
            let nonempty = {
                let r = run(cpu_slot);
                !r.ready.is_empty()
            };
            if nonempty { break; }
            arch_x86_64::interrupts::halt();
        }
        // 有就绪进程了：逐候选在持 next 桶锁下校验存在+Ready，原子置 Running+捕获 saved+
        // 物理切入(prev=None：本核在 idle 栈，只做切入方恢复，不保存 FPU)。
        // 跨核收尸竞态修复：候选被 reap(槽 None)/置 Exit 则丢弃重选，绝不 .expect panic、
        // 不切进已回收槽；next 桶锁贯穿切换(杜绝窗口 B)。
        let mut run = run_mut(cpu_slot);
        while let Some(next) = pop_ready(&mut run, usize::MAX) {
            let mut g = proc_bucket_lock(next);
            if !next_is_runnable(&g, next) {
                continue; // 无效候选：丢弃重选(I1)；g 随迭代结束释放
            }
            let saved = {
                let slot = g.get_mut(&next).expect("next just validated");
                slot.proc.set_state(TaskState::Running);
                slot.saved
            };
            switch_apply_next(next, &mut g, &mut run);
            drop(g);
            drop(run);
            // 本核已在 idle 栈上，无外层 stub 可 iretq；直接从内存帧恢复并 iretq 到用户态
            // (resume_interrupt_frame -> !，永不返回)。
            arch_x86_64::interrupts::resume_interrupt_frame(&saved)
        }
        // while 耗尽(队列中候选全被跨核 reap/置 Exit)：回到外层等队非空。
        drop(run);
    }
}

/// 终止当前进程（`exit` syscall）：zombie 化并按父子关系分发退出码后切换。
///
/// 当前进程经 [`terminate_locked`] 统一处理：有活父且父在等待则交付退出码
/// 并唤醒父；无活父则立即回收。若还有就绪进程，改写 `frame` 为队首进程的
/// 保存帧，返回后由 `syscall_entry` 的 iretq 进入目标进程用户态（与
/// `tick`/`yield` 相同机制）；否则进入 idle halt 等待（可能有 Blocked 进程，
/// 如 shell 或 waitpid 中的父进程）。注意调用后当前进程不再被调度，但函数
/// **正常返回**（不 `!`），由中断返回路径完成切换。
pub fn exit_current(frame: &mut InterruptFrame, code: u64) {
    let cpu_slot = my_cpu_slot();
    // 读 cur_pid 用短暂本核 RUN 域（terminate_locked 自持各 pid 锁 + 跨核 RUN[home]，
    // 故此处不持任何锁调用）。
    let cur_pid = {
        let run = run_mut(cpu_slot);
        run.current.expect("exit called outside process")
    };
    // PID 1 契约：init 不得退出（自杀即 panic）。
    if cur_pid == init_pid() {
        // 常驻取证（§6.16.6，defect #2）：panic 消息附带异常帧三元组
        // (vector, rip, error_code)。init 自杀的来路是「init 用户态异常 →
        // 异常信号 Default 处置 → exit_current」或 init 主动 exit syscall，
        // `frame` 此刻仍是 init 的现场——vector/rip 是定位**哪条指令、哪类
        // 异常**触发的唯一真值。此处是 panic 路径（本来就要停机），多打印
        // 零风险、无探针（§6.12.8：探针会让 1/12 复现消失，取证必须常驻）。
        panic!(
            "attempted to kill init (self-exit pid={}, vector={}, rip={:#x}, error_code={:#x})",
            cur_pid,
            frame.vector,
            frame.rip,
            frame.error_code,
        );
    }
    let _ = terminate_locked(cur_pid, code);
    let mut run = run_mut(cpu_slot);
    run.current = None;
    clear_current_proc();

    // 统一"选 next + 原子提交切换"原语（DESIGN §3.2/§4 #10）：prev=None(cur 已 Exit、槽随
    // terminate 退役)。候选被跨核 reap/置 Exit 则丢弃重选，绝不 .expect panic、不切进已回收
    // 槽；next 桶锁贯穿切换(杜绝窗口 B)。
    // 无有效候选时本核物理运行在将死进程的内核栈上：空队停车必须切到本核 idle 栈
    // (go_idle_on_own_stack，永不让渡回将死栈)，绝不在将死栈上 halt(reaper 可回收+drain 之)。
    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => {} // 已切入 next，frame 已改
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            // A2 修复：本函数此刻物理运行在将死进程的内核栈上。若在此栈上 halt
            // 等待，父/收尸核可回收并 drain 释放它 → 本核在已释放栈上空转 (UAF)。
            // 必须切到本核自己的 idle 栈再停车；go_idle_on_own_stack 永不让渡回此
            // 将死栈（后续唤醒的进程由其完整帧在 idle 栈上 iretq 恢复）。
            go_idle_on_own_stack()
        }
    }
}

/// 枚举全部存活进程，向用户态缓冲写入快照条目。
///
/// 每条 8 字节：`pid: u32`（小端）+ `state: u8`（1=Ready 2=Running 3=Blocked）+ 3 字节填充。
/// 返回写入的条目数（受 `cap` 字节限制）。经 `copy_to_user` 安全写入用户缓冲（SMAP）。
pub fn ps_snapshot(buf: *mut u8, cap: usize) -> usize {
    // 分桶化：逐桶持锁、桶内按 pid 升序遍历所有进程（弱一致快照）。
    let mut off = 0usize;
    let mut n = 0usize;
    'outer: for bucket in PROCESSES.iter() {
        let entry = bucket.lock();
        for (_, e) in entry.iter() {
            if e.proc.state() == TaskState::Exit {
                continue;
            }
            if off + 8 > cap {
                break 'outer;
            }
            let pid = e.proc.pid() as u32;
            // task1 KM3：数值编码取自 TaskState::as_u8 单点（用户态 ABI）。
            let state = e.proc.state().as_u8();
            let ent = [
                pid as u8,
                (pid >> 8) as u8,
                (pid >> 16) as u8,
                (pid >> 24) as u8,
                state,
                0,
                0,
                0,
            ];
            unsafe {
                arch_x86_64::mmio::copy_to_user(buf.add(off) as u64, ent.as_ptr(), 8);
            }
            off += 8;
            n += 1;
        }
    }
    n
}

/// 从 PCB 定长缓冲还原程序名（`&str` 生命周期绑定槽位锁）。
fn entry_name(entry: &ProcEntry) -> &str {
    // store_name 只接受合法 UTF-8，故此处解码不可能失败。
    core::str::from_utf8(&entry.name[..entry.name_len as usize]).unwrap_or("?")
}

/// 收集所有存活进程的快照列表（供 ProcFS 使用）。
pub fn process_snapshots() -> Vec<vfs::ProcessSnapshot> {
    // 分桶化：逐桶持锁、桶内按 pid 升序收集所有存活进程（弱一致快照）。
    let mut list = Vec::new();
    for bucket in PROCESSES.iter() {
        let entry = bucket.lock();
        for (_, e) in entry.iter() {
            if e.proc.state() == TaskState::Exit {
                continue;
            }
            let pid = e.proc.pid();
            // task1 KM3：展示名取自 TaskState::label 单点。
            let state_str = e.proc.state().label();
            list.push(vfs::ProcessSnapshot {
                pid,
                name: alloc::string::String::from(entry_name(e)),
                state: alloc::string::String::from(state_str),
                ppid: e.ppid,
                // C1.2：真实记账值来自该进程地址空间的区域账本，O(区域数)。
                memory_bytes: e.proc.addr_space().declared_bytes(),
            });
        }
    }
    list
}

/// A2-2 / ADR-040 §3.5 G5 配套：**活跃用户快照**（供 SysFS `/system/info/users` 使用）。
///
/// 由真实进程表归并而来：遍历全部存活进程，按 uid 去重，并收集每个 uid 的进程数与
/// 进程名样本。**只反映"此刻有进程在跑的 uid"**——绝不冒充完整账户表（账户表是用户态
/// 的 `/config/users.json`，内核不参与，ADR-040 §2.9）。视图语义边界由此成文。
///
/// 与 `/processes` 的一致性：同一份 `PROCESSES` 表、同一次弱一致快照遍历，故两者不会
/// 互相矛盾（例如 `/processes` 里有的 pid 其 uid 必然出现在本视图）。
///
/// 去重策略：以小容量的定长数组收集（uid 空间在单机实际使用中远小于该上限），避免
/// 引入 `BTreeMap` 分配；超过上限时**如实截断并报告**，不静默丢弃（S09）。
pub fn active_user_snapshots() -> vfs::ActiveUserView {
    /// 视图上限（A9 放大 64 → 4096，owner 指令 2026-09-27）：进程数本身无
    /// 上限（B1），视图截断会漏报活跃用户；4096 与全局 fd 闸同量级，纯理论
    /// 之外的截断如实标记（S09）。
    const MAX_ACTIVE_USERS: usize = 4096;
    let mut out: alloc::vec::Vec<vfs::UserSnapshot> = alloc::vec::Vec::new();
    let mut truncated = false;
    for bucket in PROCESSES.iter() {
        let entry = bucket.lock();
        for (_, e) in entry.iter() {
            if e.proc.state() == TaskState::Exit {
                continue;
            }
            let uid = e.proc.identity().uid;
            // 线性查重（表极小，且避免额外分配）。
            if let Some(slot) = out.iter_mut().find(|u| u.uid == uid) {
                slot.process_count += 1;
            } else if out.len() < MAX_ACTIVE_USERS {
                out.push(vfs::UserSnapshot {
                    uid,
                    process_count: 1,
                });
            } else {
                truncated = true;
            }
        }
    }
    // 稳定输出：按 uid 升序，便于消费方与测试比对（不依赖表遍历顺序）。
    out.sort_by_key(|u| u.uid);
    // 截断**如实上报**（S09）：放进返回值而非仅打日志——日志不可断言，
    // 而消费方必须能区分"活跃用户就这么多"与"视图被上限截断了"。
    vfs::ActiveUserView { users: out, truncated }
}

/// 获取单个进程的快照信息（供 ProcFS 使用）。
pub fn get_process_snapshot(pid: usize) -> Option<vfs::ProcessSnapshot> {
    // 分桶化：pid 在册则持其所在桶读快照（弱一致）。
    let guard = proc_bucket_lock(pid);
    let entry = guard.get(&pid)?;
    if entry.proc.state() == TaskState::Exit {
        return None;
    }
    let state_str = entry.proc.state().label(); // task1 KM3 单点
    Some(vfs::ProcessSnapshot {
        pid,
        name: alloc::string::String::from(entry_name(entry)),
        state: alloc::string::String::from(state_str),
        ppid: entry.ppid,
        memory_bytes: entry.proc.addr_space().declared_bytes(),
    })
}

/// 向进程 `target` 发送信号 `sig`（当前仅 `SIGKILL=9`/`SIGTERM=15` 终止目标；
/// `sig=0` 仅校验进程存在，不实际发送）。
///
/// - `sig=0`：存在性探测——存在返回 `Ok(0)`，不存在返回 `Err(InvalidParam)`，
///   不改变目标状态（与文档约定一致；旧实现误将 sig=0 当作终止执行，已修）。
/// - 目标为当前进程：走标准 [`exit_current`] 退出路径（永不返回），退出码
///   记为信号号。
/// - 目标为其它进程：经 [`terminate_locked`] 统一终止（zombie/唤醒父进程/
///   孤儿级联/UIO 清理单点），退出码记为信号号；被杀进程若有阻塞 waitpid
///   的父进程，父进程同样拿到真实退出码。若其为键盘 waiter，一并清除
///   对应等待槽（原 `KBD_WAITER` 已退役；现役 EVENT_WAITER 等）避免悬挂唤醒。
/// PID 1 契约：该信号若投递给 init 是否会**终止** init（从而应被拒绝）。
/// 依 ADR-034「init 可捕获非致命信号」：仅当默认处置为 Terminate 且 init
/// 未为该信号设 handler（不可捕获）时才判定为终止 → 拒绝。
/// 自持锁的判定助手：本函数自行取 init 的 per-pid 锁读取其信号处置。调用方
/// 不得已持同 pid 锁或本核 RUN 域。
fn init_signal_terminates(init_pid: usize, sig: u32) -> bool {
    if default_disposition(sig) != DefaultAction::Terminate {
        return false;
    }
    // 分桶化：自取 init 所在桶锁读信号处置（调用方不得已持同 pid 锁）。
    let has_handler = proc_bucket_lock(init_pid)
        .get(&init_pid)
        .map(|e| {
            matches!(e.proc.signal().disposition(sig), Some(crate::signal::SigDisposition::Handler(_)))
        })
        .unwrap_or(false);
    !has_handler
}

pub fn kill_pid(target: usize, sig: u32, frame: &mut InterruptFrame) -> Result<u64, Error> {
    // S1-9：接受全部信号号——越界 `InvalidParam`（ADR-034 §2.3）。
    // task1 KM1：信号号常量化——SIGKILL 由 signals 模块单点定义（S13）。
    if sig >= NSIG {
        return Err(Error::InvalidParam);
    }
    // 纯 RUN 读取（b）：取本核当前 pid，无需任何 pid 锁。
    let current = {
        run_mut(my_cpu_slot()).current
    };
    if current == Some(target) {
        if sig == 0 {
            return Ok(0); // 对自己探活
        }
        // PID 1 契约：init 自杀被显式拒绝（exit_current 中会 panic，此处先返回
        // 错误避免 panic 冲击）。但 init **可捕获非致命信号**（ADR-034）：仅当
        // 信号会终止 init（默认 Terminate 且未设 handler）才拒绝。
        if target == init_pid() && init_signal_terminates(target, sig) {
            return Err(Error::PermissionDenied);
        }
        // 自杀：SIGKILL 立即终止（走标准退出路径，zombie 化并切换）；
        // 其余信号转本进程 pending，由返回用户态时的 deliver_on_return 派发
        // （可捕获/可屏蔽信号延迟投递，S1-9/S1-8）。exit_current 内部自行加锁，
        // 故此处不持锁调用；其会把 `*frame` 改写为下一进程现场，调用方（sys_kill）
        // 依此返回 Switched，本函数必须立即返回（S26）。
        if sig == SIGKILL {
            exit_current(frame, sig as u64);
            return Ok(0);
        }
        // 非 SIGKILL 自杀：raise 到 pending，由派发层处理（不再立即终止）。
        {
            // 分桶化：短暂取 target 所在桶 raise。
            let mut g = proc_bucket_lock(target);
            if let Some(slot) = g.get_mut(&target) {
                slot.proc.signal_mut().raise(sig);
            }
        }
        return Ok(0);
    }
    // PID 1 契约：禁止向他杀 init（探活 sig=0 放行）。仅拒绝会**终止** init 的
    // 信号；init 可捕获的非致命信号放行（ADR-034「init 可捕获非致命信号」）。
    if target == init_pid() && sig != 0 && init_signal_terminates(target, sig) {
        return Err(Error::PermissionDenied);
    }
    // 校验目标存在且非 zombie（分桶化：target 在册则持其所在桶判态）。
    let exists = proc_bucket_lock(target)
        .get(&target)
        .map(|e| e.proc.state() != TaskState::Exit)
        .unwrap_or(false);
    if !exists {
        return Err(Error::InvalidParam);
    }
    if sig == 0 {
        return Ok(0); // 仅校验存在，不发送
    }
    // 投递权限强制——两个维度合成**一次**判定（S13 单点，不设第二条路径）：
    //
    // ① **属主维度**（A2-0 / ADR-040 §3.5 G2，POSIX `kill(2)` 语义）：
    //    非同一 uid 的调用者向目标投递信号（含非终止类）需 `CAP_KILL`。
    //    补此维度前的旧规则只比较**特权级**，故普通用户 alice(1000) 可杀
    //    普通用户 bob(1001)——这正是「认证者若可被普通用户 kill，认证即
    //    形同虚设」的可执行面，故 ADR-040 §3.5.2 要求本项**先于 G1 落地**。
    //    属主比较对**全部信号**生效（POSIX：异 uid 无 CAP_KILL 一律 EPERM，
    //    不区分信号号），探活 `sig==0` 已在上方放行、不受本项约束。
    //
    // ② **特权级维度**（承 ADR-034 §2.7 × ADR-040 §2.3 能力位改判）：
    //    无 `CAP_KILL` 的调用者不可向特权进程（`CAP_SYSTEM`）投递**终止类**
    //    信号（`default_disposition==Terminate`）。
    //
    // 二者是**独立必要条件的并集**：任一维度判定拒绝即拒绝。持 `CAP_KILL`
    // 者两维度同时豁免，可向任意进程投递（与原语义一致）。
    {
        // 仅当**确知**存在当前进程且其确不持 CAP_KILL 时才走受限分支（单点判定）。
        // 诚实边界（S39）：两条"Do not check"路径均为**历史语义的保留**，非安全取舍：
        // - `current == None`：内核/驱动上下文（引导期、中断内投递），无可比较 uid；
        // - `current` 有值但槽位已消失（种族：该进程正被回收）：本函数**跳过**判定。
        //   该窗口在 SMP 下理论上存在，但发送方此刻自身正在退出路径上，无法构造
        //   可利用的跨用户投递；若将来需要硬化，应在此处改为 fail-closed 并补
        //   SMP 并发用例——现已如实登记，不谎称已 fail-closed。
        let sender = match current {
            None => None, // 内核上下文：不受本判定约束
            Some(cur) => proc_bucket_lock(cur)
                .get(&cur)
                .map(|e| {
                    let id = e.proc.identity();
                    (id.caps.contains(Caps::KILL), id.uid)
                }),
        };
        // 仅"查得到且不持 CAP_KILL"进入受限判定；其余（内核上下文 / 槽位消失 /
        // 持 CAP_KILL）跳过——见上方诚实边界。
        let restricted_by_uid = match sender {
            None => None,
            Some((true, _)) => None,
            Some((false, uid)) => Some(uid),
        };
        if let Some(sender_uid) = restricted_by_uid {
            let target_id = proc_bucket_lock(target)
                .get(&target)
                .map(|e| {
                    let id = e.proc.identity();
                    (id.uid, id.caps.contains(Caps::SYSTEM))
                });
            // 目标槽位不可读（其间被回收）→ fail-closed：拒绝。此处与既有
            // "target 不存在 → InvalidParam" 不冲突——那条已在更早处判定过，
            // 走到这里说明目标刚刚消失，拒绝是安全侧。
            let Some((target_uid, target_privileged)) = target_id else {
                return Err(Error::PermissionDenied);
            };
            // ① 属主维度：异 uid → 拒绝（POSIX：异 uid 无 CAP_KILL 一律 EPERM）。
            if sender_uid != target_uid {
                return Err(Error::PermissionDenied);
            }
            // ② 特权级维度：同 uid 但目标特权且信号为终止类 → 拒绝
            //    （普通用户不得终止特权进程，即使 uid 巧合相同）。
            if target_privileged && default_disposition(sig) == DefaultAction::Terminate {
                return Err(Error::PermissionDenied);
            }
        }
    }
    // I-EVENTS P5：键盘 waiter（KBD_WAITER）清理段随轨道 A 退役移除——stdin
    // 不再有该形态的等待登记。若是设备事件 waiter（interrupt-to-futex），清空登记并取消其超时定时器：
    // 被杀进程正阻塞在 block_for_event（EVENT_WAITER=pid）时，残留的死 pid 会让
    // 后继事件读者的 CAS 失败、永久 NotSwitched，事件等待功能损坏（S18/S21，V3）。
    // 与上方各等待槽清理路径同一纪律。EVENT_TIMER 同时清空并 cancel，防 stale 定时器
    // 到期唤醒一个已死进程。
    if EVENT_WAITER.load(core::sync::atomic::Ordering::Acquire) == target as u32 {
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        let stale = EVENT_TIMER.swap(u64::MAX, core::sync::atomic::Ordering::AcqRel);
        if stale != u64::MAX {
            klib::time::cancel_timeout(stale);
        }
    }
    // P1（§6.15）：键盘事件记录等待者**多槽表**的同款清理——被杀进程若登记
    // 在任一槽上，残留的死 pid 会白占空槽（8 槽耗尽后所有 read 立即 WaiterBusy
    // 空读，事件等待功能损坏；S18/S21，与 EVENT_WAITER 清理路径对称）。
    // 单槽时代此处漏清 `IN_EVENT_WAITER` 是既有缺口，表化时一并闭合。
    for slot in IN_EVENT_WAITERS.iter() {
        let _ = slot.compare_exchange(
            target as u32,
            u32::MAX,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        );
    }
    // 投递：SIGKILL 立即终止（统一终止核心：置 Exit、按父子关系交付/保留/回收、
    // 孤儿级联、UIO 清理）；其余信号转目标 pending，由目标返回用户态时的
    // deliver_on_return 派发（S1-9：非终止信号不立即杀）。
    if sig == SIGKILL {
        let _ = terminate_locked(target, sig as u64);
    } else {
        let mut g = proc_bucket_lock(target);
        if let Some(slot) = g.get_mut(&target) {
            slot.proc.signal_mut().raise(sig);
            // ADR-052：若目标正**阻塞在 syscall 里**，唤醒它的同时直接把 EINTR 写进它的保存帧。
            // 只置 pending 不够——被唤醒的 syscall 用的是进入阻塞时保存的帧（本系统无内核
            // 上下文切换），而信号会在它回用户态时被消费；于是重试时预检看不到任何待决信号，
            // 又会睡回去（实测：永久挂起）。此处直接交付结果，语义与 POSIX 一致。
            if slot.proc.state() == TaskState::Blocked {
                slot.saved.rax = klib::error::Error::Interrupted.packed();
            }
        }
    }
    // ADR-051：投递必须**唤醒阻塞中的目标**——否则阻塞在 syscall 里的进程永远看不到
    // 信号（实测：父进程阻塞在管道 read 上，子进程 kill 之后父永不返回）。唤醒在桶锁
    // **之外**（wake 自持桶锁）。waitpid 独占管理的进程由 wake 自行跳过（见其文档），
    // 那条路径的 EINTR 接入是 ADR-051「后果」里登记的未覆盖项。
    if sig != SIGKILL {
        wake(target);
    }
    Ok(0)
}

/// 唤醒一个阻塞的进程（IPC 写/读端完成时调用）：置 `Ready` 并入就绪队列。
///
/// 仅当目标进程处于 `Blocked` 时才生效（已就绪/运行中进程忽略，避免重复入队）。
/// 由 waitpid 机制独占管理的进程（`waiting_for` 已登记）不得经此唤醒——其
/// `saved.rax` 只能由子进程终止路径填写，提前唤醒会让用户态拿到占位值。
pub fn wake(pid: usize) {
    // 分桶化（a）：取 pid 所在桶判态置 Ready 并读 home，释放后再跨核入队。
    let enqueue = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            Some(slot) if slot.proc.state() == TaskState::Blocked && slot.waiting_for.is_none() => {
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue { wake_enqueue(pid, home); }
}

/// 唤醒一个阻塞的进程并把其保存帧 `rax` 预置为 `value`（SYNC 域 futex 唤醒）。
///
/// 与 [`wake`] 的差异：唤醒方（`sync_wake`）除了把进程置回 `Ready`，还要让被唤醒
/// 进程的 `SYNC_WAIT` 返回**唤醒时的同步字值**（ADR-032 §4.3）。实现上先写
/// `saved.rax = value`，再走与 [`wake`] 相同的 Blocked + `waiting_for` 守卫入队。
///
/// 竞态与 [`wake_event_timeout`] 同源：超时唤醒与事件唤醒对 `saved.rax` 竞争时，
/// 由 `state == Blocked` 检查保证**先到者胜**——已置 Ready 则后到者不覆盖（不会
/// 把已交付的唤醒值写穿）。
///
/// 仅当目标进程处于 `Blocked` 时才生效（已就绪/运行中进程忽略，避免重复入队）。
/// 由 waitpid 机制独占管理的进程（`waiting_for` 已登记）不得经此唤醒——其
/// `saved.rax` 只能由子进程终止路径填写。
pub fn wake_with_value(pid: usize, value: u64) {
    // 分桶化（a）：取 pid 所在桶置 Ready/写 rax 并读 home，释放后再跨核入队。
    let enqueue = {
        let mut g = proc_bucket_lock(pid);
        match g.get_mut(&pid) {
            Some(slot) if slot.proc.state() == TaskState::Blocked && slot.waiting_for.is_none() => {
                slot.saved.rax = value;
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue { wake_enqueue(pid, home); }
}

/// 启动调度器（内核 idle 主循环）：取第一个就绪进程，经 `enter_usermode` 进入
/// 其用户态。进程在用户态被 tick 打断后由 [`tick`] 轮转。永不返回。
pub fn start() -> ! {
    // 阶段2（M4）对称多处理：AP 进入本调度空闲循环时打点（只一次，BSP 不打点）。
    let entry_slot = my_cpu_slot();
    if entry_slot != 0 {
        // 阶段4: confirm FPU/SSE hw prereq on this AP (CR0.TS=0, CR4.OSFXSR=1).
        let mut cr0v: u64 = 0;
        unsafe { core::arch::asm!("mov {}, cr0", out(reg) cr0v, options(nomem, nostack)); }
        let tsok = cr0v & (1 << 3) == 0;
        let osx = (arch_x86_64::mmio::read_cr4() & (1 << 9)) != 0;
        klib::info!("[sched] AP slot {} idle (fpu ts={} osfxsr={})", entry_slot, tsok, osx);
        // 阶段4 FP proof: actually execute x87/SSE on this AP and read a value back.
        // At AP entry no user process FPU state is loaded yet, so a transient SSE op is
        // safe (the first scheduled process does fpu::restore anyway). If TS were set,
        // fnstcw below would #NM - this proves FP instructions run on the AP.
        let mut fpcheck: u16 = 0;
        unsafe { core::arch::asm!("fnstcw [{}]", in(reg) &mut fpcheck, options(nostack)); }
        // x87 control word low bits: 0x037F default (rounding/precision). Bit set => FPU live.
        klib::info!("[sched] AP slot {} fp probe cw={:#06x} (fpu ts={} osfxsr={})", entry_slot, fpcheck, tsok, osx);
    }
    loop {
        // 逐候选"选 next + 原子提交"（DESIGN §3.2/§4 #11）：持 pid 桶锁判存在+Ready 后，
        // 原子置 Running+读 entry/cr3+物理切入(prev=None：冷启动/唤醒，无当前帧)。
        // 跨核收尸竞态修复：候选被 reap(槽 None)/置 Exit 则丢弃重选，绝不 .expect panic、
        // 不切进已回收槽；pid 桶锁贯穿切换(杜绝窗口 B)。entry/cr3 在**锁内**读——避免
        // 提交后、读 entry 前再被 reap(槽 None 读 entry/cr3 崩溃)。空队 halt 等待。
        let mut run = run_mut(my_cpu_slot());
        while let Some(pid) = pop_ready(&mut run, usize::MAX) {
            let mut g = proc_bucket_lock(pid);
            if !next_is_runnable(&g, pid) {
                continue; // 无效候选：丢弃重选(I1)；g 随迭代释放
            }
            let (entry_rip, user_stack_top, cr3) = {
                let slot = g.get_mut(&pid).expect("next just validated");
                slot.proc.set_state(TaskState::Running);
                (
                    slot.proc.entry_rip(),
                    slot.proc.user_stack_top(),
                    slot.proc.addr_space().page_table_paddr(),
                )
            };
            // K2：首个进程切入前从其 PCB 恢复 FNINIT 模板现场，使"首次运行也走恢复路径"
            // 与后续调度完全一致。切换在持 pid 桶锁内完成(prev=None)。
            switch_apply_next(pid, &mut g, &mut run);
            drop(g);
            let frame = TrapFrame {
                rip: entry_rip,
                cs: user_code_selector() as u64,
                rflags: USER_RFLAGS,
                rsp: user_stack_top,
                ss: user_data_selector() as u64,
                cr3,
            };
            drop(run);
            // 阶段2（M4）对称多处理：AP（非 BSP 槽）首次从自己就绪队列取到进程并即将
            // 进入用户态时打点一次。BSP 槽 0 不打点。
            let diag_cs = my_cpu_slot();
            if diag_cs != 0
                && !AP_LAUNCHED
                    .load(core::sync::atomic::Ordering::Acquire)
            {
                AP_LAUNCHED.store(true, core::sync::atomic::Ordering::Release);
                klib::info!("[sched] AP slot {} launched user proc pid={} (SMP active)", diag_cs, pid);
            }
            arch::task::enter_usermode(&frame); // 永不返回
        }
        drop(run);
        arch_x86_64::interrupts::halt(); // 无进程可启动：停机等待中断
    }
}

// ---------- C7.1 内核自检钩子（仅 kernel-tests 构建存在） ----------

/// 供 `kernel::tests::test_waitpid_core` 直接驱动真实终止/收尸/阻塞决策逻辑。
///
/// 全部操作走与生产路径相同的锁内核心（[`terminate_locked`]/[`reap_child_locked`]/
/// [`waitpid_inner`]），仅不做物理 CPU 切换（CR3/RSP0/CURRENT），避免破坏
/// 内核主线程上下文。物理切换链路由 `kernel-test-waitpid` 停机验收覆盖。
#[cfg(feature = "kernel-tests")]
pub mod test_hooks {
    use super::*;

    /// 以 `ppid` 创建指定名称的测试进程（哑入口/栈，永不被调度执行——就绪队列项在
    /// probe/清理前不会被消费，因为内核主线程不跑 `scheduler::start`）。
    pub fn spawn_named_child_of(ppid: usize, name: &str) -> Result<usize, Error> {
        spawn_with_ppid(ppid, name, 0x1000, 0x5000, dummy_space()?)
    }

    /// S4：最近一次 `wake_enqueue` 是否尝试了跨核投递（与成败无关）。
    pub fn last_wake_attempted_cross_core() -> bool {
        WAKE_ATTEMPTED_CROSS_CORE.load(core::sync::atomic::Ordering::Acquire)
    }

    /// S4：清零尝试标志（夹具前后各调一次，避免跨用例残留）。
    pub fn clear_wake_attempted() {
        WAKE_ATTEMPTED_CROSS_CORE.store(false, core::sync::atomic::Ordering::Release);
    }

    /// S4 夹具：向 `home` 槽位的就绪队列压入一个进程并返回**是否投递了 IPI**。
    ///
    /// 直接练 `wake_enqueue` 的投递契约——这是跨核唤醒唯一会产生 IPI 的路径。
    /// 用一个真实在册的 pid（否则入队的是野 pid，虽不影响 IPI 判定但会污染队列）。
    pub fn debug_wake_enqueue_cross_core(home: usize) -> bool {
        let pid = match spawn_with_ppid(0, "s4.probe", 0x1000, 0x5000, dummy_space().unwrap()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // 直接调用投递路径：与 wake_enqueue 内部同一条（同一函数，无复制逻辑）。
        let before = arch_x86_64::interrupts::resched_ipi_send_count();
        wake_enqueue(pid, home);
        arch_x86_64::interrupts::resched_ipi_send_count() > before
    }

    /// 进程状态探针：(状态, 名称, waiting_for, saved.rax, ppid)。名称为 PCB 缓冲拷贝。
    pub fn probe(pid: usize) -> Option<(TaskState, alloc::string::String, Option<usize>, u64, usize)> {
        // 分桶化：pid 在册则持其所在桶读探针。
        let guard = proc_bucket_lock(pid);
        guard.get(&pid).map(|e| {
            (
                e.proc.state(),
                alloc::string::String::from(entry_name(e)),
                e.waiting_for,
                e.saved.rax,
                e.ppid,
            )
        })
    }

    /// restorer（trampoline）探针（ADR-034 PRE-3 验收用）：返回该进程
    /// `Process.signal().trampoline()` 地址。
    pub fn probe_trampoline(pid: usize) -> Option<u64> {
        // 分桶化：pid 在册则持其所在桶读探针。
        let guard = proc_bucket_lock(pid);
        guard.get(&pid).map(|e| e.proc.signal().trampoline())
    }

    /// 真实内存记账探针（C1.2 验收用）：返回该进程地址空间 declared_bytes()（MM7：虚拟预留量，非 RSS）。
    pub fn probe_memory_bytes(pid: usize) -> Option<u64> {
        // 分桶化：pid 在册则持其所在桶读探针。
        let guard = proc_bucket_lock(pid);
        guard.get(&pid).map(|e| e.proc.addr_space().declared_bytes())
    }

    /// ADR-038 T6 夹具：把 `pid` 注册为进程表内的一个真实入口（哑入口/栈，永不被
    /// 调度执行——内核主线程不跑 `scheduler::start`）。
    ///
    /// 为何必须有：`set_current_proc` 只写 `CURRENT_PROC` 裸指针，**不**把进程登记
    /// 进分桶进程表；而 `spawn_derived` 的父校验走 `proc_bucket_lock(ppid)`，故测试
    /// 若只 `set_current_proc` 会得到 `NotFound`（这正是本夹具的由来，实测踩到）。
    /// 返回是否成功插入。
    pub fn register_test_entry(pid: usize, ppid: usize, name: &str) -> bool {
        let (name_buf, name_len) = match store_name(name) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let space = match dummy_space() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut proc = Box::new(Process::<X86PageTable>::new(pid, 0x1000, 0x5000, 0, Arc::new(space)));
        let _ = &mut proc;
        let entry = Box::new(ProcEntry {
            proc,
            saved: initial_frame(0x1000, 0x5000, 0),
            kstack_frames: match mm::allocate_frames(KSTACK_ORDER) {
                Some(f) => f,
                None => return false,
            },
            kstack_top: 0,
            fpu: fpu_template_snapshot(),
            name: name_buf,
            name_len,
            ppid,
            exit_code: 0,
            waiting_for: None,
            home_cpu: my_cpu_slot(),
            fs_base: 0,
            vruntime: 0,
            nice: 0,
        });
        // 不 `enqueue_ready`：本入口仅作表内存在（供父校验/fd 快照），绝不入就绪
        // 队列——否则 tick 会把它调度执行，摧毁测试现场（KM16 纪律）。
        proc_bucket_lock(pid).insert(pid, entry).is_none()
    }

    /// ADR-038 T6 夹具（带地址空间版）：把 `pid` 登记进进程表，并使用**调用方提供**
    /// 的地址空间（而非哑空间）。
    ///
    /// 为何需要：`spawn_derived` 的地址空间来自**进程表内该 pid 的 PCB**
    /// （`proc_bucket_lock(ppid).get(&ppid).proc.addr_space()`），而非 `CURRENT_PROC`。
    /// 故测试要让派生共享到自己构造的数据页，必须把该地址空间放进**表内入口**；
    /// 只 `set_current_proc` 一个另建的 PCB 不会生效（实测踩到：子进程共享到的是
    /// 哑空间，DATA 页翻译不到）。
    ///
    /// 返回是否成功插入。
    pub fn register_test_entry_with_space(
        pid: usize,
        ppid: usize,
        name: &str,
        space: UserAddressSpace<X86PageTable>,
    ) -> bool {
        let (name_buf, name_len) = match store_name(name) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let proc = Box::new(Process::<X86PageTable>::new(pid, 0x1000, 0x5000, 0, Arc::new(space)));
        let entry = Box::new(ProcEntry {
            proc,
            saved: initial_frame(0x1000, 0x5000, 0),
            kstack_frames: match mm::allocate_frames(KSTACK_ORDER) {
                Some(f) => f,
                None => return false,
            },
            kstack_top: 0,
            fpu: fpu_template_snapshot(),
            name: name_buf,
            name_len,
            ppid,
            exit_code: 0,
            waiting_for: None,
            home_cpu: my_cpu_slot(),
            fs_base: 0,
            vruntime: 0,
            nice: 0,
        });
        proc_bucket_lock(pid).insert(pid, entry).is_none()
    }

    /// ADR-038 T6 探针：返回 COW 派生子的组/亲子/首跑帧事实。
    ///
    /// 返回 `(tgid, ppid, saved.rax, saved.rip, saved.rsp)`。用于端到端验收
    /// 「新组 + fork 亲子 + 子首跑 rax=0 + 从父 RIP/RSP 继续」四条语义——
    /// 这些字段都在 PCB 内部，只有同 crate 的探针能取到，故走本模块
    /// （沿用既有 `probe`/`probe_trampoline` 的同一纪律）。
    pub fn probe_derived_child(pid: usize) -> Option<(usize, usize, u64, u64, u64)> {
        let guard = proc_bucket_lock(pid);
        guard.get(&pid).map(|e| {
            (
                e.proc.tgid(),
                e.ppid,
                e.saved.rax,
                e.saved.rip,
                e.saved.rsp,
            )
        })
    }

    /// ADR-038 T6 探针：在派生子的地址空间上翻译某用户地址（用于断言 COW 共享同一
    /// 物理帧）。取子所在桶锁后直接调其地址空间（内部自锁，不重入桶锁）。
    pub fn probe_derived_child_translate(pid: usize, vaddr: u64) -> Option<u64> {
        let guard = proc_bucket_lock(pid);
        let e = guard.get(&pid)?;
        e.proc
            .addr_space()
            .translate(arch::VirtAddr::new(vaddr))
            .map(|p| p.as_u64())
    }

    /// ADR-038 T6 探针：在派生子的地址空间上驱动一次写故障（真实 COW 复制路径）。
    /// 返回是否被处理。用于验证「子侧写 → 复制私有帧 → 父帧内容/引用计数不受影响」。
    pub fn probe_derived_child_write_fault(pid: usize, vaddr: u64) -> bool {
        let guard = proc_bucket_lock(pid);
        let Some(e) = guard.get(&pid) else {
            return false;
        };
        e.proc.addr_space().handle_page_fault(
            vaddr,
            arch_x86_64::paging::PageFaultCode::new(arch_x86_64::paging::PF_EC_WRITE),
        )
    }

    /// ADR-038 T6 夹具：从进程表移除并**回收** `pid` 的 ProcEntry（含地址空间 →
    /// 走 destroy 归还全部帧）。用于测试收尾，使帧计数回基线（S18）。
    pub fn reclaim_entry(pid: usize) -> bool {
        proc_bucket_lock(pid).remove(&pid).is_some()
    }

    /// 终止 `pid`（真实核心路径），返回终止分支名（测试断言用）。
    pub fn terminate(pid: usize, code: u64) -> &'static str {
        // per-pid：terminate_locked 自持各 pid 锁。
        match terminate_locked(pid, code) {
            Termination::Reclaimed => "reclaimed",
            Termination::ZombieKept => "zombie",
            Termination::DeliveredToParent => "delivered",
        }
    }

    /// 非阻塞收尸尝试（真实核心路径）：NotFound=非亲生/不存在/已收尸；
    /// WouldBlock=子进程仍在运行；Ok((pid,code))=已收尸（槽位已释放）。
    /// §6.11 B（有界 waitpid）测试钩子：**表级**触发超时回调。
    ///
    /// 真实路径由 `klib::time::set_timeout` 在 tick 中断里驱动；宿主测试不跑
    /// 中断，故直接调 [`super::wake_waitpid_timeout`] 验表级语义（这正是该回调
    /// 的全部职责）。与既有 `try_reap`/`block_on_child` 同款「只验表级、不做
    /// 物理切换」的测试纪律。
    pub fn fire_waitpid_timeout(pid: usize) {
        super::wake_waitpid_timeout(pid);
    }

    /// §6.12.6 死锁复现夹具：在**持有本核 RUN 域锁**的前提下，检查超时回调
    /// `wake_waitpid_timeout` 内部要取的锁是否已**不可获取**。
    ///
    /// # 为什么必须这样测（现有 `fire_waitpid_timeout` 测不到它）
    ///
    /// 既有夹具的纪律是「只验表级、不做物理切换」，且注释自陈「宿主测试不跑
    /// 中断，故直接调」。**这恰好绕开了真正的故障前提**：真实路径里回调是在
    /// IRQ0 中断上下文执行的，而调用者（`waitpid_timeout`）可能正持有同一把
    /// `RUN[slot]` 锁。
    ///
    /// `IrqSpinLock` → `SpinMutex` 是**纯自旋、无重入检测**的实现：同核重入
    /// 必然永久自旋（锁由自己持有，等不到释放）。故真实故障序列是：
    ///
    /// 1. shell 在内核态 `waitpid_timeout` 持有 `RUN[0]`；
    /// 2. IRQ0 到达 → `poll_timeouts` → `wake_waitpid_timeout`；
    /// 3. 回调内 `wake_enqueue` → `run_mut(home)` → `RUN[0].lock()` 自旋；
    /// 4. IRQ0 handler **永不返回** → EOI 永不发出 → BSP 定时器永久停止；
    /// 5. 于是第 3 个及之后的超时定时器**永不触发**，shell 永久卡在等待里。
    ///
    /// 实测症状（可信 `-serial file:` 捕获）：`bsp_tick` 停在 1200、
    /// `poll_timeouts` 停在 n=1000，此后 BSP 再无 IRQ0；shell 停在等待循环
    /// 第 ~5 次迭代，`^C` 完全无效。
    ///
    /// # 判据
    ///
    /// 持锁期间用 `try_lock`（非阻塞）探测：真实死锁下它**必然返回 `None`**。
    /// 用 `try_lock` 而非 `lock()` 是刻意的——后者会把「断言失败」变成
    /// 「测试永久挂死」，那是不可诊断的（S21：失败要如实且可定位）。
    ///
    /// 返回 `true` = 复现了同核重入不可获取（即死锁前提成立）。
    /// `hold = true`：先持锁再探测（模拟 `waitpid_timeout` 持锁被 IRQ0 打断）；
    /// `hold = false`：不持锁直接探测（对照，证明锁本身工作正常）。
    ///
    /// 两种形态都返回「再次获取是否被拒」。持锁形态必然 `true`，不持锁形态
    /// 必然 `false`——由调用方（测试）分别断言，避免把两种语义混在一个
    /// 恒真返回值里（初版即因此写错了对照断言）。
    #[cfg(feature = "kernel-tests")]
    pub fn debug_run_lock_try_acquire_rejected(hold: bool) -> bool {
        let slot = my_cpu_slot() & (MAX_SCHED_CPUS - 1);
        let held = if hold { Some(RUN[slot].lock()) } else { None };
        // **非阻塞**探测：纯自旋锁无重入检测，锁被自己持有时必然拿不到。
        let rejected = RUN[slot].try_lock().is_none();
        drop(held);
        rejected
    }

    /// §6.11 B：登记一个有界等待（表级，不做物理切换），返回登记结果。
    ///
    /// `frame=None` 形态下 `waitpid_inner` 不做物理切换，故本钩子只验证
    /// 「表级等待登记是否成立」，超时后的表级效果由
    /// [`fire_waitpid_timeout`] + [`probe`] 验证。
    pub fn block_on_child_table(parent: usize, target: usize) -> Result<Waited, Error> {
        let mut run = run_mut(my_cpu_slot());
        waitpid_inner(&mut run, parent, target, None)
    }
    pub fn try_reap(parent: usize, target: usize) -> Result<(usize, u64), Error> {
        // 分桶化：先校验 target 是 parent 的亲生子（持 target 所在桶判），再收尸。
        let is_mine = proc_bucket_lock(target)
            .get(&target)
            .map(|e| e.ppid == parent)
            .unwrap_or(false);
        if !is_mine {
            return Err(Error::NotFound);
        }
        reap_child_locked(parent, target).ok_or(Error::WouldBlock)
    }

    /// 表级阻塞登记（真实 `waitpid_inner`，frame=None 不做物理切换）：
    /// 返回 Ok(Waited::Blocked) 表示已登记+Blocked+表级切换到下一就绪进程；
    /// Err(WouldBlock) 表示无可切进程已回滚；Err(NotFound) 同生产语义。
    pub fn block_on_child(parent: usize, target: usize) -> Result<Waited, Error> {
        // per-pid（a）：只取本核 RUN 域。
        let mut run = run_mut(my_cpu_slot());
        waitpid_inner(&mut run, parent, target, None)
    }

    /// WAIT_ANY 等价：等待任意子进程。
    /// 编译期仅当 `kernel-tests` 启用，与 `kernel-test-waitpid` 停机验收路径无关。
    pub fn wait_any(parent: usize) -> Result<Waited, Error> {
        // per-pid（a）：只取本核 RUN 域。
        let mut run = run_mut(my_cpu_slot());
        waitpid_inner(&mut run, parent, WAIT_ANY, None)
    }

    /// 清空全部测试进程，返回清除数量（防跨测试泄漏；next_pid 保持单调）。
    ///
    /// task1 K3：哑进程从未进入
    /// 过其内核栈，帧可**就地**归还（延迟队列的"将死栈在执行中"前提对
    /// 哑进程不成立）；顺带清空回收队列保证帧计数断言的确定性。
    /// （I-EVENTS P5：原 KD3 的 KBD_WAITER 同步复位随轨道 A 退役移除。）
    pub fn reset_all() -> usize {
        // S4：清零跨核投递尝试标志，避免用例间残留导致假阳。
        WAKE_ATTEMPTED_CROSS_CORE.store(false, core::sync::atomic::Ordering::Release);
        // 分桶化：逐桶持锁清空全部 pid（无全局 PROCS）。
        let mut n = 0;
        for bucket in PROCESSES.iter() {
            let mut g = bucket.lock();
            let all: Vec<usize> = g.keys().copied().collect();
            for i in all {
                if let Some(e) = g.remove(&i) {
                    driver::uio_on_process_exit(i);
                    // 哑进程栈未被任何执行流触碰：就地归还安全且确定。
                    mm::deallocate_frame(e.kstack_frames);
                    n += 1;
                }
            }
        }
        // 阶段2 地基：清空全部核的 ready/current（复位须全核干净；AP 槽此刻空）。
        // 逐槽短暂取 RUN 域清空（各槽为独立锁）。
        for r in 0..MAX_SCHED_CPUS {
            let mut slot = run_mut(r);
            slot.ready.clear();
            slot.current = None;
        }
        // （I-EVENTS P5：原 KBD_WAITER 复位随轨道 A 退役移除。）
        // 同步复位事件等待全局（S18/S21，V3/V6）：EVENT_WAITER 残留会让后继
        // 用例的 block_for_event 永久 NotSwitched；EVENT_TIMER 残留的 stale id
        // 会污染新等待的定时器取消。P1：记录等待者多槽表同款全清（残留死 pid
        // 会白占槽，让后继用例 WaiterBusy 空读）。
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        for slot in IN_EVENT_WAITERS.iter() {
            slot.store(u32::MAX, core::sync::atomic::Ordering::Release);
        }
        EVENT_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
        drain_dead_kstacks();
        clear_current_proc();
        INIT_PID.store(0, core::sync::atomic::Ordering::Release);
        n
    }

    /// 场景构造：令 pid 进入与 waitpid 无关的 Blocked（模拟等键盘/IPC）并
    /// 移出就绪队列——用于驱动"无就绪同伴 → 拒绝阻塞"的真实回滚分支。
    /// waiting_for 已登记或已退出的进程拒绝操作。
    pub fn simulate_blocked(pid: usize) -> bool {
        // 分桶化：pid 在册则持其所在桶置 Blocked。
        let mut g = proc_bucket_lock(pid);
        let home = {
            let Some(slot) = g.get_mut(&pid) else {
                return false;
            };
            if slot.waiting_for.is_some() || slot.proc.state() == TaskState::Exit {
                return false;
            }
            slot.proc.set_state(TaskState::Blocked);
            slot.home_cpu
        };
        drop(g);
        // EEVDF：`retain` -> `remove`（语义等价）。
        dequeue_ready(&mut run_mut(home), pid);
        true
    }

    // ---- task1 K2/K1 验收钩子 ----

    /// K2 隔离验收·保存半程：把 `marker` 写入 CPU xmm0，再执行与生产切换
    /// 路径相同的 [`fpu::save`] 快照进 pid 的 PCB 保存区。xmm0 显式声明为
    /// 破坏——内核目标启用 SSE，编译器可能跨语句持有 xmm 值。
    pub fn debug_fpu_save(pid: usize, marker: u64) -> bool {
        // 分桶化：pid 在册则持其所在桶保存。
        let mut g = proc_bucket_lock(pid);
        let Some(slot) = g.get_mut(&pid) else {
            return false;
        };
        unsafe {
            core::arch::asm!(
                "movq xmm0, {v}",
                v = in(reg) marker,
                out("xmm0") _,
                options(nomem, nostack)
            );
        }
        fpu::save(&mut slot.fpu);
        true
    }

    /// K2 隔离验收·恢复半程：从 pid 的 PCB 保存区执行生产同款
    /// [`fpu::restore`]，返回恢复后 CPU xmm0 低 64 位。
    pub fn debug_fpu_restore(pid: usize) -> Option<u64> {
        // 分桶化：pid 在册则持其所在桶恢复。
        let mut g = proc_bucket_lock(pid);
        let slot = g.get_mut(&pid)?;
        fpu::restore(&slot.fpu);
        let out: u64;
        unsafe {
            core::arch::asm!(
                "movq {o}, xmm0",
                o = out(reg) out,
                out("xmm0") _,
                options(nomem, nostack)
            );
        }
        Some(out)
    }

    /// K1 验收探针：读取调度器视角的当前 pid（tick 门控断言用）。
    pub fn debug_current_pid() -> Option<usize> {
        // 纯 RUN（b）：只读本核 RUN 域 current。
        run_mut(my_cpu_slot()).current
    }

    /// 审计 R5-F1 验收钩子：整体替换就绪队列内容。
    ///
    /// 场景构造需要"current=A 且队列仅含 B"的状态——spawn 会自动入队，
    /// 无法用现有钩子表达"A 不在队中"。测试夹具专用，生产路径禁用。
    /// EEVDF-3 验收钩子：对两个 pid 各记 10 个 tick 的 vruntime，返回 (a, b) 的增量。
    ///
    /// 走的是**生产记账函数**（`vruntime_charge` + 各自 `nice`），故能验证「nice
    /// 确实接到了调度记账上」，而不只是纯函数方向正确。
    pub fn debug_nice_charge_probe(a: usize, b: usize, ticks: u32) -> Option<(u64, u64)> {
        let (na, nb) = (nice_of(a)?, nice_of(b)?);
        let (wa, wb) = (
            crate::sched_eevdf::nice_to_weight(na),
            crate::sched_eevdf::nice_to_weight(nb),
        );
        let mut va = 0u64;
        let mut vb = 0u64;
        for _ in 0..ticks {
            va = crate::sched_eevdf::vruntime_add(va, vruntime_charge(wa));
            vb = crate::sched_eevdf::vruntime_add(vb, vruntime_charge(wb));
        }
        Some((va, vb))
    }

    /// EEVDF-3 交互延迟探针：模拟「一个 CPU 密集进程 + 一个交互进程」的就绪集合，
    /// 返回**交互进程被选中前，需要先经过多少个就绪候选**。
    ///
    /// ## 为什么用「候选数」而不是墙上时间
    ///
    /// 本内核的调度粒度是 LAPIC tick（TCG 档 10 tick/片 ≈ 100ms 虚拟时间），
    /// 而 TCG 下 rdtsc 计的是翻译指令数、不是真实时间（EEVDF-1 已实测），
    /// 直接报「毫秒」会得到不可信的数字。**候选数**是与硬件无关、可精确复现的
    /// 量：0 = 唤醒后立刻被选中（最优），N = 还要等 N 个进程先跑。
    ///
    /// 本探针**不改动生产记账**，只在独立队列实例上复现同样的插入/选取逻辑，
    /// 故可安全在任意测试上下文调用。
    pub fn debug_interactive_dispatch_rank(
        interactive_nice: i32,
        hog_count: usize,
        hog_nice: i32,
    ) -> (usize, u64, u64) {
        use crate::sched_eevdf::{nice_to_weight, weight_charge, VruntimeQueue};
        let mut q = VruntimeQueue::new();
        let wi = nice_to_weight(interactive_nice);
        let wh = nice_to_weight(hog_nice);
        // 所有进程都跑相同 tick 数（对等负载），差异只来自 nice 权重。
        const TICKS: u64 = 10;
        let vi = weight_charge(TICKS, wi);
        let vh = weight_charge(TICKS, wh);
        // **平局判定必须对交互进程不利**，否则本探针会测出假象。
        //
        // `VruntimeQueue` 在 vruntime 相等时按 **pid 升序**决定（刻意做成确定性）。
        // 若让交互进程持有最小 pid，则同权（RR 等价）臂里它也会因平局胜出，
        // rank 恒为 0 —— 于是「EEVDF 更快」根本无法与「pid 恰好更小」区分。
        // 实测正是如此：两臂 rank 都是 0，断言失败。
        //
        // 故把交互进程放在**最大 pid**：平局时它排最后，唯一能胜出的途径就是
        // 真实的 vruntime 优势。这才是有效的对照。
        let interactive_pid = 1 + hog_count;
        for i in 0..hog_count {
            q.insert(1 + i, vh);
        }
        q.insert(interactive_pid, vi);
        // 统计交互进程被选中前排在前面的候选数。
        let mut rank = 0usize;
        loop {
            match q.pop_min() {
                Some((pid, _)) if pid == interactive_pid => break,
                Some(_) => rank += 1,
                None => break,
            }
            if rank > hog_count + 2 {
                break; // 防御性上限，避免探针本身成为死循环
            }
        }
        (rank, vi, vh)
    }

    pub fn debug_set_ready_queue(pids: &[usize]) {
        let mut q = crate::sched_eevdf::VruntimeQueue::new();
        // EEVDF：测试夹具按给定顺序赋 vruntime，使取出顺序**可预期地等于入参顺序**
        // （否则夹具的"队列仅含 B"前提仍成立，但依赖顺序的用例会不确定）。
        // 递增的 vruntime 让堆的取出顺序与入参一致。
        for (i, p) in pids.iter().enumerate() {
            q.insert(*p, i as u64);
        }
        // 纯 RUN（b）：整体替换本核 RUN 域就绪队列。
        run_mut(my_cpu_slot()).ready = q;
    }

    /// S26 回归验收：`block_current_with` 的登记点返回 false 时，已被
    /// `pop_ready` 弹出的就绪进程必须放回队列（否则该进程永久饿死）。
    ///
    /// 真实 IPC 阻塞路径（`block_current_with` → 登记点复检失败）无法在
    /// 自检中构造（需要真实管道竞态），故直接驱动共享主体
    /// `block_current_locked`：current=A、队列仅含 B、register 恒返回
    /// false。修复前 B 被弹出后直接丢失（返回 NotSwitched 但队列空）；
    /// 修复后 B 重新入队。
    ///
    /// 返回 true 当且仅当：结果 NotSwitched **且** B 仍在就绪队列。
    pub fn debug_block_register_false_keeps_ready(current: usize, peer: usize) -> bool {
        // per-pid（a）：只取本核 RUN 域。
        let mut run = run_mut(my_cpu_slot());
        run.ready.clear();
        // EEVDF：夹具只需 peer 在队中；vruntime 取 0 即可（队列仅此一项）。
        run.ready.insert(peer, 0);
        run.current = Some(current);
        let mut frame = initial_frame(0x400000, 0x7ffefffff000, 0);
        let outcome = block_current_locked(&mut run, &mut frame, &mut || false);
        outcome == SwitchOutcome::NotSwitched && run.ready.contains(peer)
    }

    /// 审计 R5-F2 验收钩子：丢弃 FPU 模板缓存，令下一次 spawn 重新快照。
    /// 模板是全启动期懒单例——不重置则其内容固化在首次 spawn 时刻，
    /// "残值 vs 强零化"语义对后续用例不可观测。测试夹具专用。
    pub fn debug_reset_fpu_template() {
        *FPU_TEMPLATE.lock() = None;
    }

    /// 以指定身份创建测试进程（S1-9/S1-10 kill 权限验收用）。
    /// 复用手工 restorer 安装 + `spawn_with_ppid_fds` 真实路径。
    pub fn spawn_child_with_identity(
        ppid: usize,
        name: &str,
        identity: ProcessIdentity,
    ) -> Result<usize, Error> {
        let us = UserAddressSpace::<X86PageTable>::new()?;
        let trampoline = us.install_signal_restorer().map_err(|_| Error::OutOfMemory)?;
        spawn_with_ppid_fds(ppid, name, 0x1000, 0x5000, us, trampoline, None, identity)
    }

    /// 把 `pid` 置为"当前运行进程"（`s.current` + `CURRENT_PROC` 同步），
    /// 供 kill 权限验收（kill_pid 以当前进程身份判定投递权限）。返回是否成功。
    pub fn set_current(pid: usize) -> bool {
        // 分桶化：pid 在册则持其所在桶取裸指针，再写本核 RUN current。
        let mut g = proc_bucket_lock(pid);
        let mut run = run_mut(my_cpu_slot());
        let ptr = match g.get_mut(&pid) {
            Some(slot) => {
                (&mut *slot.proc as *mut Process<X86PageTable>) as usize
            }
            None => return false,
        };
        run.current = Some(pid);
        set_current_proc(ptr as *mut Process<X86PageTable>);
        true
    }

    /// 清除"当前运行进程"（与 `set_current` 对称）。
    pub fn clear_current() {
        // 纯 RUN（b）：只清本核 RUN current + 对应 CURRENT_PROC 别名。
        run_mut(my_cpu_slot()).current = None;
        clear_current_proc();
    }

    /// 未决信号集探针（S1-9 验收：kill 转 pending 后读回）。
    pub fn pending_of(pid: usize) -> u64 {
        // 分桶化：pid 在册则持其所在桶读探针。
        proc_bucket_lock(pid)
            .get(&pid)
            .map(|e| e.proc.signal().pending().bits())
            .unwrap_or(0)
    }

    /// 线程派生包装（T1-1）：在组长 `leader_pid` 的线程组内派生一个线程（哑入口/栈，
    /// 永不被调度执行——就绪队列项在 verify/reset 前不会被消费，因内核主线程不跑
    /// scheduler::start）。复用真实 `spawn_thread_with` 路径。
    pub fn spawn_thread_of(leader_pid: usize, name: &str) -> Result<usize, Error> {
        spawn_thread_with(leader_pid, name, 0x2000, 0x6000, 0)
    }

    /// 线程结构探针（T1-1）：返回 (state, tgid, kernel_stack_top)。供 kernel::tests
    /// 断言组员与组长各自独立 pid/kstack、同组共享、状态 Ready。
    pub fn thread_probe(pid: usize) -> Option<(TaskState, usize, u64)> {
        // 分桶化：pid 在册则持其所在桶读探针。
        let g = proc_bucket_lock(pid);
        g.get(&pid).map(|e| (e.proc.state(), e.proc.tgid(), e.kstack_top))
    }

    /// 两 pid 是否共享同一 ThreadGroup 容器（Arc::ptr_eq，T1-1 结构断言）。
    /// 同组 ⟺ 共享同一组容器对象（fd/cwd/identity/addr_space 同源）。
    pub fn same_thread_group(a: usize, b: usize) -> bool {
        // 分别短暂持各自桶锁 clone 出组 Arc 再比对（两 pid 可能同桶，不能同时持锁）。
        let ga = proc_bucket_lock(a).get(&a).map(|e| e.proc.thread_group_arc());
        let gb = proc_bucket_lock(b).get(&b).map(|e| e.proc.thread_group_arc());
        match (ga, gb) {
            (Some(x), Some(y)) => Arc::ptr_eq(&x, &y),
            _ => false,
        }
    }

    /// T1-1 单核结构验收（kernel::tests 直接调用）：派生一个组长 + 一个同组线程，
    /// 验证两调度单元：独立 pid、独立内核栈、均 Ready、tgid == 组长 pid、共享同一
    /// ThreadGroup 容器；并构造第二个独立组长作对照：其 tgid/组容器与第一组不同。
    /// 不动调度切换（那是 T1-8 验证）。返回是否全部通过。
    pub fn verify_thread_derive() -> bool {
        reset_all();
        // 哑地址空间装配失败即验收失败（测试夹具内存不足属真失败）。
        let (Ok(spa), Ok(spb)) = (dummy_space(), dummy_space()) else {
            return false;
        };
        // 组长 A：独立组（leader）。
        let Ok(la) = spawn_with_ppid(0, "t1-leader-a", 0x1000, 0x5000, spa) else {
            return false;
        };
        // 组长 B：对照独立组（另一个地址空间/组）。
        let Ok(lb) = spawn_with_ppid(0, "t1-leader-b", 0x1000, 0x5000, spb) else {
            return false;
        };
        // 在 A 组内派生线程 ta。
        let Ok(ta) = spawn_thread_of(la, "t1-thread-a") else {
            return false;
        };
        // 1) 独立 pid：线程 != 组长，也 != 对照组组长。
        if ta == la || ta == lb || la == lb {
            return false;
        }
        // 2) 结构探针：三者均在册且 Ready。
        let (Some((s_la, tg_la, ks_la)), Some((s_ta, tg_ta, ks_ta)), Some((s_lb, tg_lb, _ks_lb))) =
            (thread_probe(la), thread_probe(ta), thread_probe(lb))
        else {
            return false;
        };
        if s_la != TaskState::Ready || s_ta != TaskState::Ready || s_lb != TaskState::Ready {
            return false;
        }
        // 3) tgid：组长 A tgid==自身 pid；线程 ta tgid==组长 A pid；组长 B tgid==自身 pid。
        if tg_la != la || tg_ta != la || tg_lb != lb {
            return false;
        }
        // 4) 独立内核栈：线程 ta 与组长 A 的 kstack_top 不同（各自独立栈帧）。
        if ks_la == ks_ta {
            return false;
        }
        // 5) 共享同一 ThreadGroup 容器：ta 与 la 同组；对照组 lb 与 la 异组。
        if !same_thread_group(la, ta) || same_thread_group(la, lb) {
            return false;
        }
        reset_all();
        true
    }

    /// T1-2 组关系统计验收（kernel::tests 直接调用）：派生组长 A + 两个组员线程
    /// ta/tb + 一个对照独立组长 B，验证组内遍历 `group_members`、存活计数、组长识别
    /// 都正确，且对照组独立不混组。不动调度切换（T1-8）。返回是否全部通过。
    pub fn verify_group_membership() -> bool {
        reset_all();
        let (Ok(spa), Ok(spb)) = (dummy_space(), dummy_space()) else {
            return false;
        };
        let Ok(la) = spawn_with_ppid(0, "t2-leader-a", 0x1000, 0x5000, spa) else {
            return false;
        };
        let Ok(lb) = spawn_with_ppid(0, "t2-leader-b", 0x1000, 0x5000, spb) else {
            return false;
        };
        // A 组内派生两个组员线程。
        let (Ok(ta), Ok(tb)) = (spawn_thread_of(la, "t2-thread-a"), spawn_thread_of(la, "t2-thread-b")) else {
            return false;
        };
        // 1) 组内遍历：A 组恰含 la/ta/tb 三者；B 组恰含 lb（不混组）。
        let mut ma = super::group_members(la);
        ma.sort_unstable();
        let mut expect = alloc::vec![la, ta, tb];
        expect.sort_unstable();
        if ma != expect {
            return false;
        }
        let mb = super::group_members(lb);
        if mb != alloc::vec![lb] {
            return false;
        }
        // 2) 存活成员数：A 组 3、B 组 1。
        if super::group_live_count(la) != 3 || super::group_live_count(lb) != 1 {
            return false;
        }
        // 3) 组长识别：la/lb 是组长，ta/tb 不是。
        if !super::is_group_leader(la) || !super::is_group_leader(lb)
            || super::is_group_leader(ta) || super::is_group_leader(tb) {
            return false;
        }
        // 4) 组未全退（A/B 都有存活成员）。
        if super::group_all_exited(la) || super::group_all_exited(lb) {
            return false;
        }
        reset_all();
        true
    }

    /// T1-3 组退出语义验收（ADR-035 D3/P1 / threads.md T1-3）：单核"置 Exit 不入调度"
    /// 夹具下驱动真实 terminate_locked / waitpid_inner 表级核心，验证 C1/C2/C4/R1/R3：
    ///   (a) 组员单独 exit → 组长仍活、组员 zombie 保留在表；组长显式 waitpid(组员 pid)
    ///       （join）可收尸取码；组长 WAIT_ANY 不被该组员误报（R1）；正控：组长对真实
    ///       进程子的 WAIT_ANY 收尸仍正常。
    ///   (b) 组长 exit（非自杀 SIGKILL，表级 terminate 驱动）→ 整组（含活组员）随退全
    ///       Exit、组长 notify 父（父阻塞 waitpid(组长) 被交付唤醒取码）、组员随组清理。
    ///   (c) 组长 SIGKILL（自杀语义经 terminate_locked 的组分流）→ 整组退、无残留。
    /// 跨核脱机（组员 RUN.current 在其它核时经 resched IPI + tick Exit 脱机）需真调度，
    /// 单核夹具不构造，留给 T1-8/SMP storm 回归验证。返回是否全部通过。
    pub fn verify_group_exit() -> bool {
        // 场景 (a)：组员单独 exit 不算进程退出（C1/R1/C4）。
        {
            reset_all();
            let Ok(l) = spawn_named_child_of(0, "a-leader") else { return false; };
            let Ok(m) = spawn_thread_of(l, "a-thread") else { return false; };
            // 组长/组员身份：l 是组长（tgid==pid），m 不是（tgid==l）。
            if !super::is_group_leader(l) || super::is_group_leader(m) { return false; }
            // 组员单独 exit：短路为单体保留 zombie，组长不受影响。
            if terminate(m, 7) != "zombie" { return false; }
            if super::group_live_count(l) != 1 { return false; } // 组长仍在（组员已退）
            let (s_l, _, _, _, _) = probe(l).expect("leader alive");
            if s_l == TaskState::Exit { return false; } // 组长不得随组员退出
            let (s_m, _, _, _, ppid_m) = probe(m).expect("member zombie in table");
            if s_m != TaskState::Exit || ppid_m != l { return false; } // zombie 保留且属组长
            // R1：组长 WAIT_ANY 不得把组员当进程子收走（此时组长无真实进程子 → NotFound）。
            if !matches!(wait_any(l), Err(super::Error::NotFound)) { return false; }
            if probe(m).is_none() { return false; } // WAIT_ANY 后组员仍须在表（未被误收）
            // C4：组长显式 waitpid(组员 pid)（join）可收尸取码。
            match block_on_child(l, m) {
                Ok(Waited::Reaped { pid, code }) if pid == m && code == 7 => {}
                _ => return false,
            }
            if probe(m).is_some() { return false; } // 收尸后槽位释放
            // 正控：WAIT_ANY 对真实进程子仍正常收尸（排除组员不影响进程子）。
            let Ok(rc) = spawn_named_child_of(l, "a-real-child") else { return false; };
            if terminate(rc, 3) != "zombie" { return false; }
            match wait_any(l) {
                Ok(Waited::Reaped { pid, code }) if pid == rc && code == 3 => {}
                _ => return false,
            }
            reset_all();
        }

        // ---- §6.11 B：有界 waitpid 超时语义（所有者裁决 B / 2026-10-04）----
        //
        // 钉死的是**本决策的核心保证**：超时必须让等待者**如实体面为「没等到」**，
        // 而不是被误当成「子进程已退出」。具体三条：
        //   1. 超时**清除** `waiting_for`（不再由 waitpid 机制独占管理）；
        //   2. 超时把 `saved.rax` 写成 **-EAGAIN 哨兵**（绝不是 0/占位值）；
        //   3. 超时把进程置回 `Ready` 并**保留子进程存活**（子仍应在表中）。
        // 另加一条**负控**：已 Ready 的进程再触发超时回调必须无副作用
        //（防「定时器迟到」把已收尸/已改等的进程误伤）。
        {
            reset_all();
            let Ok(p) = spawn_named_child_of(0, "bounded-parent") else { return false; };
            let Ok(c) = spawn_named_child_of(p, "bounded-child") else { return false; };
            // 父登记等待仍在运行的子：表级形态返回 Blocked。
            if !matches!(block_on_child_table(p, c), Ok(Waited::Blocked)) { return false; }
            // 登记后：父应处于 Blocked 且 waiting_for == Some(子)。
            let (s0, _, wf0, _, _) = probe(p).expect("parent registered");
            if s0 != TaskState::Blocked || wf0 != Some(c) { return false; }
            // 子仍存活（超时**不得**收走子进程）。
            if probe(c).is_none() { return false; }
            // 触发超时回调。
            fire_waitpid_timeout(p);
            let (s1, _, wf1, rax1, _) = probe(p).expect("parent after timeout");
            // 1) 已置回 Ready；2) waiting_for 已清；
            if s1 != TaskState::Ready { return false; }
            if wf1 != None { return false; }
            // 3) rax 必须是 -EAGAIN 哨兵（即 WouldBlock 的 errno 取负），
            //    **不是** 0、**不是**任何真实退出码。
            let want = -(super::Error::WouldBlock.to_errno() as i64) as u64;
            if rax1 != want { return false; }
            // 子进程仍在表中（超时不是收尸）。
            if probe(c).is_none() { return false; }
            // 负控：再次触发超时回调不得有副作用（父已 Ready，不再是等待者）。
            fire_waitpid_timeout(p);
            let (s2, _, wf2, rax2, _) = probe(p).expect("parent still there");
            if s2 != TaskState::Ready || wf2 != None || rax2 != want { return false; }
            // 超时后子进程**仍可正常收尸**——这正是「超时不是收尸」的实证。
            //
            // 注意：超时已清 `waiting_for`，故父**不再是**等待者，
            // `terminate` 此时**不会**走「交付」路径（无人等待），而是走
            // 「保留 zombie」路径——这是**正确**行为，不是缺陷。
            // 故这里断言的是：子成为 zombie 且父仍能**主动**收尸取到真实退出码。
            if terminate(c, 9) != "zombie" { return false; }
            // 父主动收尸：拿到真实退出码 9（与超时哨兵 -EAGAIN 明显不同）。
            match try_reap(p, c) {
                Ok((pid, code)) if pid == c && code == 9 => {}
                _ => return false,
            }
            if probe(c).is_some() { return false; } // 收尸后槽位释放
            // 父的 saved.rax 仍是超时哨兵（收尸经 try_reap 返回，不写 saved.rax），
            // 且 waiting_for 保持为空——证明超时后父已**完全脱离** waitpid 机制。
            let (_, _, wf3, rax3, _) = probe(p).expect("parent after reap");
            if wf3 != None { return false; }
            if rax3 != want { return false; } // 仍是超时哨兵，未被污染
            reset_all();
        }
        // 场景 (b)：组长 exit（非自杀 SIGKILL）→ 整组随退 + notify 父。
        {
            reset_all();
            let Ok(p) = spawn_named_child_of(0, "b-parent") else { return false; };
            let Ok(l) = spawn_named_child_of(p, "b-leader") else { return false; };
            let Ok(m1) = spawn_thread_of(l, "b-t1") else { return false; };
            let Ok(m2) = spawn_thread_of(l, "b-t2") else { return false; };
            if super::group_live_count(l) != 3 { return false; } // 组长+m1+m2
            // 父阻塞 waitpid(组长)：组退出时组长须 notify 父（交付唤醒）。
            if !matches!(block_on_child(p, l), Ok(Waited::Blocked)) { return false; }
            if terminate(l, 42) != "delivered" { return false; }
            // 整组（含活组员）全退：组长交付即收尸，组员随组清理（R3）。
            if probe(l).is_some() || probe(m1).is_some() || probe(m2).is_some() { return false; }
            if super::group_live_count(l) != 0 { return false; } // 整组无存活成员
            // 父被 notify：唤醒、拿到组长退出码、waiting_for 清空。
            let (s_p, _, wf_p, rax_p, _) = probe(p).expect("parent notified");
            if s_p != TaskState::Ready || wf_p != None || rax_p != 42 { return false; }
            reset_all();
        }
        // 场景 (c)：组长 SIGKILL 自杀（terminate_locked 的组分流）→ 整组退。
        {
            reset_all();
            let Ok(l) = spawn_named_child_of(0, "c-leader") else { return false; };
            let Ok(m1) = spawn_thread_of(l, "c-t1") else { return false; };
            let Ok(m2) = spawn_thread_of(l, "c-t2") else { return false; };
            // 自杀 SIGKILL 最终经 exit_current → terminate_locked(L, SIGKILL)。单核夹具不
            // 跑物理切换，直接驱动 terminate_locked 的组长分支（与自杀同组展开语义）。
            if terminate(l, 9) != "reclaimed" { return false; } // 无父组长 → 回收
            if probe(l).is_some() || probe(m1).is_some() || probe(m2).is_some() { return false; }
            if !super::group_all_exited(l) { return false; }
            reset_all();
        }
        // 场景 (d)：组长**阻塞在 waitpid(组员)**（pthread_join 语义）时组员退出 → 单目标
        // 交付唤醒组长并收尸（terminate_member_locked 的 join 交付路径，非 WAIT_ANY）。
        {
            reset_all();
            let Ok(l) = spawn_named_child_of(0, "d-leader") else { return false; };
            let Ok(m) = spawn_thread_of(l, "d-thread") else { return false; };
            // 组长阻塞登记在显式 waitpid(组员 m)——组员仍存活，故返回 Blocked（表级登记）。
            if !matches!(block_on_child(l, m), Ok(Waited::Blocked)) { return false; }
            if !matches!(probe(l), Some((TaskState::Blocked, _, Some(wf), _, _)) if wf == m) {
                return false;
            }
            // 组员此时退出(7)：须唤醒阻塞中的组长并交付退出码，且收尸组员 zombie。
            if terminate(m, 7) != "delivered" { return false; }
            // 组长被唤醒 Ready、waiting_for 清空、saved.rax==7；组员已收尸(槽位释放)。
            if !matches!(probe(l), Some((TaskState::Ready, _, None, 7, _))) { return false; }
            if probe(m).is_some() { return false; }
            reset_all();
        }
        true
    }
    /// 跨核收尸竞态验收钩子（DESIGN §9 / §3.2）：表级驱动 **prev=None** 的统一"选 next
    /// + 原子提交"选择逻辑（即 idle_loop_body / deschedule_exit_current / exit_current /
    /// start 共用的 [`pop_and_commit_switch`] 形态）。`ready` 为预置就绪队列。
    ///
    /// 竞态模型：某进程被上一核 `pop_ready` 选中（弹出、仍 Ready）后，在提交前被**另一
    /// 核**收尸——槽被 `reap_child_locked` 置 None（先经 terminate 置 Exit）。旧实现持该
    /// 槽锁 `.expect("ready proc exists")` 直接 panic(SMP 间歇冻结)或切进已回收槽(UAF)。
    /// 本钩子与生产路径同一把 `next_is_runnable`(槽存在 && state==Ready)闸门：None/Exit 槽
    /// 一律丢弃重选，绝不置 Running、绝不 panic。
    ///
    /// 因表级测试不可做物理 CR3/FPU 切换(会破坏内核主线程上下文)，此处镜像 pop_and_commit_switch
    /// 的**选择+校验+置 Running** 段(即 commit_same_lock 的置 Running 前段，不含 switch_apply_next)。
    /// 返回被提交(置 Running 并成为表级 current)的 pid；就绪项全为 None/Exit/空 → None(Empty)。
    pub fn debug_commit_switch_table(ready: &[usize]) -> Option<usize> {
        let mut run = run_mut(my_cpu_slot());
        run.ready.clear();
        // EEVDF：夹具按入参顺序赋递增 vruntime，保证提交顺序可预期。
        for (i, p) in ready.iter().enumerate() {
            run.ready.insert(*p, i as u64);
        }
        run.current = None;
        while let Some(p) = pop_ready(&mut run, usize::MAX) {
            let mut g = proc_bucket_lock(p);
            if !next_is_runnable(&g, p) {
                continue; // None/Exit 槽：跨核收尸残留，丢弃重选(I1)，不 panic、不置 Running
            }
            let slot = g.get_mut(&p).expect("slot present+Ready just validated");
            slot.proc.set_state(TaskState::Running);
            run.current = Some(p);
            return Some(p);
        }
        None // 全无有效候选(Empty)：表级等价于空队回滚/go_idle 的判定前置
    }

    /// 哑地址空间：仅占位映射（测试进程不执行任何用户代码）。
    fn dummy_space() -> Result<UserAddressSpace<X86PageTable>, Error> {
        use arch::PageSize;
        use arch::VirtAddr;
        let frame = mm::allocate_frame().ok_or(Error::OutOfMemory)?;
        let us = UserAddressSpace::<X86PageTable>::new()?;
        us.map_user(
            VirtAddr::new(0x1000),
            VirtAddr::new(0x2000),
            PageSize::Size4K,
            arch::PageFlags::empty().writable().user(),
            &[frame.start_paddr()],
        )?;
        Ok(us)
    }
}
