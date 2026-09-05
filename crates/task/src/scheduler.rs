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
use alloc::collections::VecDeque;
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
    Process, ProcessIdentity, TaskState, clear_current_proc, set_current_proc, user_code_selector,
    user_data_selector, USER_RFLAGS,
};
use crate::signal::{DefaultAction, default_disposition};
use crate::signals::SIGKILL;
use crate::signal_set::NSIG;
use crate::process::Privilege;

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
    /// 路径单点完成）。通用 [`wake`]/[`wake_kbd`] 不得触碰此类进程，
    /// 防止提前唤醒导致其带着未填写的 `saved.rax` 返回用户态。
    waiting_for: Option<usize>,
    /// 本进程的 home（常驻）CPU 槽位（阶段2 对称多处理）：spawn 时按 least-loaded
    /// 选定，唤醒/就绪入队目标固定为 `ready[home_cpu]`；进程只在 home 核被调度。
    /// （跨核唤醒 = 外来核把 pid 塞进本 home 队列并视情发 resched IPI。）
    home_cpu: usize,
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
static DEAD_KSTACKS: [IrqSpinLock<Vec<PhysFrame>>; MAX_SCHED_CPUS] =
    [const { IrqSpinLock::new(Vec::new()) }; MAX_SCHED_CPUS];

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
    DEAD_KSTACKS[home_cpu & (MAX_SCHED_CPUS - 1)]
        .lock()
        .push(kstack_frames);
    // proc 在此 drop：UserAddressSpace::destroy 回收用户页表/叶帧（M5）。
    // 该 Drop 只操作 HHDM 映射与空闲池，不触碰本栈，就地安全（既有行为）。
    drop(proc);
}

/// 归还延迟队列中的全部内核栈帧（仅限"确定不在将死栈上"的入口调用：
/// tick 顶部、spawn 入口；测试钩子可对哑进程直接调用）。
fn drain_dead_kstacks() {
    let mut q = DEAD_KSTACKS[my_cpu_slot()].lock();
    for frame in q.drain(..) {
        // order 记录在分配器帧元数据中，按基址整块归还（16 帧一次到位）。
        mm::deallocate_frame(frame);
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
            klib::info!("[sched] spawn least-loaded home={} (load={}, online={})", best, bl, n);
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
    /// 每核就绪队列（RR）。索引 = 紧凑 CPU 槽位；[my_cpu_slot] 为当前核槽位。
    ready: VecDeque<usize>,
    /// 每核当前运行进程。索引 = 紧凑 CPU 槽位（与 process.rs 的 per-CPU
    /// CURRENT_PROC 同槽同步更新，保持“调度器 current 与裸指针别名”单点对应）。
    current: Option<usize>,
}

impl PerCpuRun {
    const fn new() -> Self {
        Self {
            ready: VecDeque::new(),
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
fn initial_frame(entry_rip: u64, user_stack_top: u64) -> InterruptFrame {
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
        rdi: 0,
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
    // 延迟回收先于新分配执行（task1 K3）：把已退出进程的内核栈帧还池，
    // 提高 spawn 在内存压力下的成功率。
    drain_dead_kstacks();
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
        saved: initial_frame(entry_rip, user_stack_top),
        kstack_frames: stack_frame,
        kstack_top,
        fpu: fpu_template_snapshot(),
        name: name_buf,
        name_len,
        ppid,
        exit_code: 0,
        waiting_for: None,
        home_cpu,
    });
    // 分桶化：把入口按 pid 写入其所在桶（堆分配 Box，地址稳定）；桶锁随即释放
    // 再入队 home 核（pid 桶 → RUN 锁序：桶锁释放后再取 RUN，不同时持有）。
    proc_bucket_lock(pid).insert(pid, entry);
    // 阶段2（M4）：新进程直接入队其 home 核就绪队列——使每核就绪队列真正各自
    // 承运转到本核的进程（对称多处理），而非一律落在创建核。进程运行中阻塞后再
    // 唤醒仍回 home 核队列（跨核唤醒），实现按核常驻。入队走 RUN[home_cpu] 域
    // （pid 锁已释放，再取 RUN；home 可能非本核）。
    run_mut(home_cpu).ready.push_back(pid);
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
) -> Result<usize, Error> {
    drain_dead_kstacks();
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
        saved: initial_frame(entry_rip, user_stack_top),
        kstack_frames: stack_frame,
        kstack_top,
        fpu: fpu_template_snapshot(),
        name: name_buf,
        name_len,
        ppid: tgid,
        exit_code: 0,
        waiting_for: None,
        home_cpu,
    });
    proc_bucket_lock(pid).insert(pid, entry);
    run_mut(home_cpu).ready.push_back(pid);
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
        }
    }
    run.ready.push_back(cur_pid);

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
    let cr3 = slot.proc.addr_space().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    run.current = Some(next);
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
            if let Some(ps) = g.get_mut(&pid) { fpu::save(&mut ps.fpu); }
            commit_same_lock(run, frame, next, &mut g);
            CommitNext::Done
        }
        // prev 桶号更小：按 pid 升序先取 prev 桶、再取 next 桶。
        Some(pid) if pid_bucket(pid) < pid_bucket(next) => {
            let mut gprev = proc_bucket_lock(pid);
            let mut gnext = proc_bucket_lock(next);
            if !next_is_runnable(&gnext, next) { return CommitNext::Invalid; }
            if let Some(ps) = gprev.get_mut(&pid) { fpu::save(&mut ps.fpu); }
            commit_same_lock(run, frame, next, &mut gnext);
            CommitNext::Done
        }
        // prev 桶号更大：按 pid 升序先取 next 桶、再取 prev 桶（next 桶仍贯穿切换）。
        Some(pid) => {
            let mut gnext = proc_bucket_lock(next);
            let mut gprev = proc_bucket_lock(pid);
            if !next_is_runnable(&gnext, next) { return CommitNext::Invalid; }
            if let Some(ps) = gprev.get_mut(&pid) { fpu::save(&mut ps.fpu); }
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
        let Some(next) = run.ready.pop_front() else { return NextCommit::Empty };
        if next == exclude { continue; }
        if prev == Some(next) {
            // 弹回被切出进程自身（cur，仅当其被重新入队如 tick/yield 才会发生）：不切换。
            // 调用方据此把 cur 恢复 Running 并回 NotSwitched/自恢复；*frame 未被改写。
            return NextCommit::NothingSelf;
        }
        match commit_next(run, frame, prev, next) {
            CommitNext::Done    => return NextCommit::Switched, // 已切入，桶锁已释放
            CommitNext::Invalid => { /* 无效丢弃，不重放；prev 未 save，可安全重选 */ }
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
        }
    }
    run.ready.push_back(cur_pid);

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
    while let Some(pid) = run.ready.pop_front() {
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
    let n = run.ready.len();
    for _ in 0..n {
        let pid = run.ready.pop_front().expect("len>0 in bounded loop");
        if pid == target {
            return Some(pid);
        }
        // 非目标：保持就绪，放回队尾（不破坏其可调度性/公平轮转）。
        run.ready.push_back(pid);
    }
    None
}

/// [`schedule_from_block`] 的切走结果（K1-1，ADR-031 决策-改造要点 1 的
/// frame-based 落地）。两分支都表示 `frame` 已被改写为下一进程的保存帧，
/// 调用方必须以 `Switched` 纪律收尾（不再触碰 frame）；差异仅在于等待者登记
/// （KBD_WAITER / EVENT_WAITER）是否需要在切回后清理。
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
/// `block_for_kbd` / `block_for_event` 的"无就绪进程可切"分支（`pop_ready` 返回
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
        if run.ready.contains(&cur_pid) {
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
            NextCommit::Switched => { drop(run); return BlockResume::SwitchedOther; }
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
/// 置 Blocked 之后，wake 正常生效。窗口不存在——与 `block_for_kbd` 的 CAS
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
    let mut peer = loop {
        let Some(p) = pop_ready(run, usize::MAX) else {
            return SwitchOutcome::NotSwitched;
        };
        if proc_bucket_lock(p).get(&p).is_some_and(|s| s.proc.state() == TaskState::Ready) {
            break p;
        }
        // p 已 Exit/被 reap：pop_ready 弹出但随即失效，丢弃重选（I1，不重放）。
    };
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
            run.ready.push_back(peer);
            return SwitchOutcome::NotSwitched;
        }
        if !register() {
            // S26 回归：`peer` 已在上方被 `pop_ready` 弹出（仍为 Ready 态），
            // 若直接返回将永久丢失该就绪进程（无人重新入队 → 饿死）。
            // 必须把它放回就绪队列，保证"登记失败零副作用"成立。
            run.ready.push_back(peer);
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

/// 阻塞等待键盘输入的进程 pid（`u32::MAX` 表示无）。`block_for_kbd` 以 CAS
/// 登记唯一等待者，键盘中断经回调 [`wake_kbd`] 唤醒；第二个并发 stdin 读者
/// 得到 Busy（EAGAIN），不顶掉既有等待者。
static KBD_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// [`block_for_kbd`] 的结果。
pub enum BlockKbdOutcome {
    /// 已切走：`frame` **整体**变为下一进程的保存帧。调用方必须以
    /// `DispatchResult::Switched` 收尾，不得再写返回值（kernel1.md K1a：
    /// 写 rax 会污染目标进程现场）。
    Switched,
    /// 键盘已有并发等待者：本进程未阻塞、帧未动，调用方应返回 WouldBlock
    /// （kernel1.md KM15：stdin 单读者仲裁）。
    Busy,
}

/// 阻塞当前进程等待键盘输入（`read` syscall 缓冲空时调用）。
///
/// 以 CAS 登记 [`KBD_WAITER`]（唯一等待者）：已有等待者时不阻塞、返回
/// [`BlockKbdOutcome::Busy`]——第二个并发 stdin 读者得到 EAGAIN 而不是把
/// 第一个等待者顶掉（KM15）。CAS 在调度锁内完成，消除"登记后、置 Blocked
/// 前"被 wake_kbd 抢先唤醒的丢失唤醒窗口；该窗口内若真被唤醒，本进程已带
/// Ready 状态在就绪队列里，pop_ready 取回自身时走"仅当前进程"分支恢复
/// 运行，语义收敛为一次空 read 重试。
///
/// 登记成功后把当前进程置 `Blocked`（不回就绪队列），切到下一个就绪进程；
/// 若**无其他就绪进程**（单 shell 场景），进入 idle halt 等待键盘中断唤醒——
/// 键盘 handler 经 [`wake_kbd`] 把本进程放回就绪队列，idle 循环检测到后切回。
/// 被唤醒后用户态 `read` 重试即可取到字符（消除空转 + 刷屏）。
pub fn block_for_kbd(frame: &mut InterruptFrame) -> BlockKbdOutcome {
    let cpu_slot = my_cpu_slot(); // 阶段2 地基：本核槽位（BSP=0）。
    // per-pid（a）：只取本核 RUN 域；cur 的 pid 槽访问逐 pid 锁。
    let mut run = run_mut(cpu_slot);
    // task1 KM4：本 expect 是**编程错误契约**的受控 abort（ADR-010 边界）——
    // 键盘阻塞只可能由 stdin read 的内核路径发起，“无当前进程时到达此处”
    // 意味着调用方违反了入口约定，属不可恢复的内核 bug；按全项目错误策略
    // 这不是运行期可上抛的错误（区别于有界资源耗尽的 Result 家族）。
    let cur_pid = run.current.expect("block_for_kbd outside process");
    // 审计 B19：pid → u32 截断论证。pid 即进程槽表下标（固定容量，远小于
    // 2^32），恒可无损装入 u32；u32::MAX 是 KBD_WAITER 的"空槽"哨兵，与
    // 任何合法 pid 不相交。断言即哨兵撞车防线——若未来放宽 pid 空间先改
    // 此处语义。
    assert!(
        cur_pid < u32::MAX as usize,
        "pid {} collides with KBD_WAITER sentinel",
        cur_pid
    );
    if KBD_WAITER
        .compare_exchange(
            u32::MAX,
            cur_pid as u32,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return BlockKbdOutcome::Busy;
    }
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            // K2：等待者此刻仍持有 CPU 的浮点现场，必须在切走前快照进自己的
            // PCB（Blocked 进程的 FPU 区在唤醒后由恢复路径如实还原）。
            fpu::save(&mut slot.fpu);
            slot.proc.set_state(TaskState::Blocked);
        }
    }
    run.current = None;
    clear_current_proc();

    // 统一"选 next + 原子提交切换"原语（DESIGN §3.2）：cur 已 Blocked+脱机(prev=None、
    // current=None、浮点现场已在上方显式 save)。候选被跨核 reap(槽 None)/置 Exit 时被丢弃
    // 重选，绝不 .expect panic、不切进已回收槽；next 桶锁贯穿切换结束(杜绝窗口 B)。
    // 队列耗尽(无就绪可切)则 drop RUN 走 schedule_from_block——park 本核等任一就绪进程
    // (cur 被键盘唤醒即 resume)，只有就绪队列确实为空才 halt(ADR-031，绝无忙转)。
    match pop_and_commit_switch(&mut run, frame, None, usize::MAX) {
        NextCommit::Switched => BlockKbdOutcome::Switched, // frame 已改，由 syscall_entry iret 切换
        NextCommit::Empty | NextCommit::NothingSelf => {
            drop(run);
            match schedule_from_block(frame, cur_pid) {
                // 切到其它就绪进程：自己仍 Blocked + KBD_WAITER 登记不变。
                // 不清理登记——键盘尚未到达，后续 wake_kbd 仍需借登记唤醒本进程。
                BlockResume::SwitchedOther => BlockKbdOutcome::Switched,
                // 自己被键盘唤醒（wake_kbd 已 swap 取走 KBD_WAITER）：切回自身。
                // 保留对称的条件清理作为防御——只在 KBD_WAITER 仍指向本 pid 时
                // 清除，绝不误伤后续可能的新等待者（与 block_for_event 同构）。
                BlockResume::SwitchedSelf => {
                    let _ = KBD_WAITER.compare_exchange(
                        cur_pid as u32,
                        u32::MAX,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                    BlockKbdOutcome::Switched // frame 已改，由 syscall_entry iret 切换
                }
            }
        }
    }
}

/// 把被唤醒进程 pid 塞入 home 核就绪队列，并在跨核唤醒到空闲核时发一次
/// reschedule IPI（阶段2 M5）：让驻留进程在别核、而该核此刻调度空闲 halt 等队列
/// 的场合即时醒来重查，把时延从等目标核下一 IRQ0 tick (~16ms) 压到即时。
///
/// 跨核就绪入队 + 空闲核 IPI：本函数自身短暂取 RUN[home] 域（跨核目标为动态
/// 槽位，无法随参传递单一 guard），不改任何进程表锁状态。调用方须**已释放**所持
/// 的 per-pid 锁（不得与 RUN[home] 同持——IrqSpinLock 不可重入；各唤醒路径在
/// 入队前已 drop pid 锁）。空闲判定 = current[home] 为 None（该核无进程运行、在
/// start() 空队 halt）。目标核若在运行则 IPI 仅 EOI 无副作用（arch 的
/// dispatch_resched 不碰调度锁，不会与本锁死锁）。发送失败静默——目标核自身
/// IRQ0 兜底会重查，IPI 只是即时优化。
fn wake_enqueue(pid: usize, home: usize) {
    let mut run = run_mut(home);
    run.ready.push_back(pid);
    if home != my_cpu_slot() && run.current.is_none() {
        let _ = arch_x86_64::interrupts::send_resched_ipi_to_slot(home);
    }
}

/// 键盘有输入时唤醒阻塞的进程（由 arch 键盘 handler 经回调调用）。
///
/// 取出 [`KBD_WAITER`] 登记的 pid，将其置 `Ready` 并入就绪队列。调度器下次调度/// （tick ≤10ms 或 idle 循环立即）切回该进程，使其 `read` 重试取到字符。
/// 在中断上下文调用，持锁时间极短（仅入队）。
pub fn wake_kbd() {
    let p = KBD_WAITER.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    if p == u32::MAX {
        return;
    }
    // per-pid（a）：键盘 IRQ 路径取目标 pid 锁（IrqSpinLock ⇒ 临界区 IF 屏蔽）。
    let enqueue = {
        let mut g = proc_bucket_lock(p as usize);
        let slot = g.get_mut(&(p as usize));
        match slot {
            Some(slot) if slot.waiting_for.is_none() => {
                slot.proc.set_state(TaskState::Ready);
                Some(slot.home_cpu)
            }
            _ => None,
        }
    };
    if let Some(home) = enqueue { wake_enqueue(p as usize, home); }
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
/// 事件读者得到 NotSwitched（EAGAIN），不顶掉既有等待者（与 KBD_WAITER 同款
/// KM15 单读者仲裁）。
static EVENT_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// 阻塞当前进程等待设备事件（`driver::event` 队列非空），或事件到达前一直挂起。
///
/// 返回 [`SwitchOutcome`]：
/// - `Switched`：本进程已置 Blocked 切走。唤醒后经中断路径（tick）回归用户态，
///   `slot.saved.rax` 由唤醒方预置结果——事件唤醒置 `-EAGAIN` 哨兵（用户态封装
///   识别为"曾阻塞、重试"），超时唤醒置 `0`（返回空）。调用方须以
///   `DispatchResult::Switched` 收尾。
/// - `NotSwitched`：**事件已在登记复检时就绪**（调用方应立即返回事件）、或已有
///   并发等待者（EVENT_WAITER 被占）。现场未动、无副作用。**不再因"无同伴可切"
///   返回 NotSwitched**——与 block_for_kbd 同构，无就绪进程时走 idle halt 真实
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
    // 唤醒后显式保存（同 block_for_kbd，K2 纪律），此处不重复归档。
    let cpu_slot = my_cpu_slot();
    // per-pid（a）：只取本核 RUN 域；cur 槽访问逐 pid 锁。
    let mut run = run_mut(cpu_slot);
    {
        let mut g = proc_bucket_lock(cur_pid);
        if let Some(slot) = g.get_mut(&cur_pid) {
            slot.saved = *frame;
            fpu::save(&mut slot.fpu);
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

/// 事件等待超时定时器 id 槽（`u64::MAX` = 无）。
static EVENT_TIMER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// 事件唤醒预置到保存帧 rax 的"曾阻塞、请重试"哨兵（`-EAGAIN`）。
/// 用户态封装看到 `-EAGAIN` 即重试；`0` 表示超时无事件（见 [`wake_event_timeout`]）。
///
/// errno 值取自集中定义 [`Error::WouldBlock`]（S13 错误码单一事实源），不内联
/// 裸字面量：`klib::error::Error::to_errno` 与 libsys 同口径，改码一处即同步。
const EVENT_WAKE_RETRY_SENTINEL: u64 = -(Error::WouldBlock.to_errno() as i64) as u64;

// ---------- B21/KM15 测试钩子（仅 kernel-tests 构建存在）----------

/// 预占 KBD_WAITER（审计 B21：使 `block_for_kbd` 的 Busy 分支在单核测试中
/// 可达——Busy 语义 = 第二并发 stdin 读者得到 EAGAIN，此前零测试佐证）。
/// 仅编译进 kernel-tests；运行时路径零足迹。
#[cfg(feature = "kernel-tests")]
pub fn debug_occupy_kbd_waiter(pid: u32) -> bool {
    KBD_WAITER
        .compare_exchange(
            u32::MAX,
            pid,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

/// 释放 [`debug_occupy_kbd_waiter`] 的占用（恢复空槽哨兵）。
#[cfg(feature = "kernel-tests")]
pub fn debug_release_kbd_waiter() {
    KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
}

/// 设置调度器视角的当前进程（审计 B21：`block_for_kbd` 从本核 RUN 域的
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
    hrun.ready.retain(|&p| p != pid);
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
        hrun.ready.retain(|&p| p != pid);
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
/// - 无其他**就绪**进程（阻塞后无人能接盘 CPU 唤醒自己）→ 拒绝阻塞，如实
///   返回 [`Error::WouldBlock`]（errno 11 EAGAIN），绝不自锁死系统。
pub fn waitpid(target_pid: usize, frame: &mut InterruptFrame) -> Result<Waited, Error> {
    // per-pid（a）：只取本核 RUN 域；表访问经 waitpid_inner 内逐 pid 锁。
    let mut run = run_mut(my_cpu_slot());
    let cur = run.current.ok_or(Error::NotFound)?;
    waitpid_inner(&mut run, cur, target_pid, Some(frame))
}

/// [`waitpid`] 的锁内主体。`frame = None` 为测试钩子形态：只做表级登记与
/// 状态迁移，不做 CPU 切换（物理切换路径由 m41/m42/kbd 既有验收与
/// kernel-test-waitpid 停机验收覆盖）。
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
    let others_ready = run.ready.iter().any(|&p| {
        if p == cur { return false; }
        let gi = proc_bucket_lock(p);
        matches!(gi.get(&p), Some(e) if e.proc.state() == TaskState::Ready)
    });
    // 登记/回滚在 cur 的 per-pid 锁内完成（与子进程终止路径对父的交付互斥）。
    let revert = |cur: usize| -> Error {
        let mut gc = proc_bucket_lock(cur);
        if let Some(slot) = gc.get_mut(&cur) {
            slot.waiting_for = None;
            slot.proc.set_state(TaskState::Running);
        }
        Error::WouldBlock
    };
    if !others_ready {
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
    // 本核已停车在**自己的 idle 栈**上，确定不在任何进程栈上执行：
    // 在此 drain 本核 DEAD_KSTACKS 安全——跨核收尸入队的、本核曾运行进程的
    // 栈（经 A3 go_idle 后本核已切下它们）在此归还，杜绝"收尸核提前释放他核在用栈"。
    drain_dead_kstacks();
    // A4 修复：本核刚切下某个将死进程并停车。必须把 CR3 切回**内核根页表**，
    // 否则 CR3 仍指向该将死进程的用户页表；父核随后收尸 drop 其 UserAddressSpace
    // 会释放该顶层表帧，而本核停车的 CR3 仍指向它 → 唤醒/中断时经已释放/复用的
    // 页表翻译 → 全系统内存损坏。内核根表高半区映射与本核一致，切换对运行中
    // 内核透明；后续 switch_apply_next 切到新进程时会再写回其表。
    arch_x86_64::paging::switch_to_kernel_root();
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
        panic!("attempted to kill init (self-exit pid={})", cur_pid);
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
///   `KBD_WAITER` 避免悬挂唤醒。
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
    // S1-10：投递权限强制（ADR-034 §2.7，复用 ProcessIdentity）。
    // User 不可向 System 投递终止类信号（default_disposition==Terminate）→
    // PermissionDenied；System 可向任意投递。探活 sig==0 已在上方放行。
    {
        let sender_priv = match current {
            Some(cur) => proc_bucket_lock(cur)
                .get(&cur)
                .map(|e| e.proc.identity().privilege)
                .unwrap_or(Privilege::System),
            None => Privilege::System, // 无当前进程（内核/驱动）视为 System
        };
        let target_priv = proc_bucket_lock(target)
            .get(&target)
            .map(|e| e.proc.identity().privilege)
            .unwrap_or(Privilege::User);
        if sender_priv == Privilege::User
            && target_priv == Privilege::System
            && default_disposition(sig) == DefaultAction::Terminate
        {
            return Err(Error::PermissionDenied);
        }
    }
    // 若是键盘 waiter，清空避免悬挂唤醒。
    if KBD_WAITER.load(core::sync::atomic::Ordering::Acquire) == target as u32 {
        KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
    }
    // 若是设备事件 waiter（interrupt-to-futex），清空登记并取消其超时定时器：
    // 被杀进程正阻塞在 block_for_event（EVENT_WAITER=pid）时，残留的死 pid 会让
    // 后继事件读者的 CAS 失败、永久 NotSwitched，事件等待功能损坏（S18/S21，V3）。
    // 与 KBD_WAITER 清理路径对称。EVENT_TIMER 同时清空并 cancel，防 stale 定时器
    // 到期唤醒一个已死进程。
    if EVENT_WAITER.load(core::sync::atomic::Ordering::Acquire) == target as u32 {
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        let stale = EVENT_TIMER.swap(u64::MAX, core::sync::atomic::Ordering::AcqRel);
        if stale != u64::MAX {
            klib::time::cancel_timeout(stale);
        }
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
        }
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
    /// task1 KD3：同步复位 `KBD_WAITER`——否则上一个用例登记的键盘等待者
    /// 会泄漏到后续用例（Busy 误报 / 悬挂唤醒）。task1 K3：哑进程从未进入
    /// 过其内核栈，帧可**就地**归还（延迟队列的"将死栈在执行中"前提对
    /// 哑进程不成立）；顺带清空回收队列保证帧计数断言的确定性。
    pub fn reset_all() -> usize {
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
        KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        // 同步复位事件等待全局（S18/S21，V3/V6）：EVENT_WAITER 残留会让后继
        // 用例的 block_for_event 永久 NotSwitched；EVENT_TIMER 残留的 stale id
        // 会污染新等待的定时器取消。
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
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
        run_mut(home).ready.retain(|&p| p != pid);
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
    pub fn debug_set_ready_queue(pids: &[usize]) {
        let mut q = VecDeque::new();
        for p in pids {
            q.push_back(*p);
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
        run.ready.push_back(peer);
        run.current = Some(current);
        let mut frame = initial_frame(0x400000, 0x7ffefffff000);
        let outcome = block_current_locked(&mut run, &mut frame, &mut || false);
        outcome == SwitchOutcome::NotSwitched && run.ready.contains(&peer)
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
        spawn_thread_with(leader_pid, name, 0x2000, 0x6000)
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
        for p in ready {
            run.ready.push_back(*p);
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
