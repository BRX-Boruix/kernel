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
//! - **单核调度**（M4.2）：仅在 BSP 上轮转（tick 回调经 arch 层只在 CPU0 触发），
//!   多核（AP 用户进程）留待后续；
//! - **首次运行**：进程 `spawn` 时构造"初始帧"（`initial_frame`），故首次调度也走
//!   "从 saved 恢复"，调度逻辑统一；内核 idle 主循环 [`start`] 经 `enter_usermode`
//!   进入第一个就绪进程。
//!
//! 失败模式口径（task1 KM7 成文）：**有界可计数资源**（物理帧、pid、fd 槽位）
//! 的耗尽走 `Result<_, Error>` 优雅上抛；**内核堆**由 buddy 分配器的全局
//! OOM 策略治理（alloc error → 受控停机），不做逐调用点 Result 化——两者是
//! 资源性质不同，不是实现不一致。

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use arch::task::TrapFrame;
use arch::PhysFrame;
use arch_x86_64::fpu::{self, FpuArea};
use arch_x86_64::gdt;
use arch_x86_64::interrupts::InterruptFrame;
use arch_x86_64::paging::X86PageTable;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;
use mm::user_space::UserAddressSpace;

use crate::process::{
    Process, TaskState, clear_current_proc, set_current_proc, user_code_selector,
    user_data_selector, USER_RFLAGS,
};
use crate::signals::{SIGKILL, SIGTERM};

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
    /// zombie 退出码（C7.1）：进程终止时由 [`Scheduler`] 记录，父进程
    /// `waitpid` 收尸时取走。仅在 `TaskState::Exit`（zombie）期间有意义。
    exit_code: u64,
    /// 本进程阻塞等待退出的子 pid（C7.1 `waitpid` 阻塞时登记）。
    ///
    /// 不变式：`waiting_for.is_some()` ⇒ 本进程 `TaskState::Blocked` 且由
    /// waitpid 机制独占管理（唤醒、清登记、写 `saved.rax` 都在子进程终止
    /// 路径单点完成）。通用 [`wake`]/[`wake_kbd`] 不得触碰此类进程，
    /// 防止提前唤醒导致其带着未填写的 `saved.rax` 返回用户态。
    waiting_for: Option<usize>,
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
static DEAD_KSTACKS: IrqSpinLock<Vec<PhysFrame>> = IrqSpinLock::new(Vec::new());

/// 槽位退役单点：FPU 区随 entry 丢弃，内核栈帧入延迟回收队列，
/// 其余字段（Box<Process> → addr_space Drop）沿用 M5 用户资源回收语义。
fn retire_entry(entry: ProcEntry) {
    let ProcEntry {
        proc,
        kstack_frames,
        ..
    } = entry;
    DEAD_KSTACKS.lock().push(kstack_frames);
    // proc 在此 drop：UserAddressSpace::destroy 回收用户页表/叶帧（M5）。
    // 该 Drop 只操作 HHDM 映射与空闲池，不触碰本栈，就地安全（既有行为）。
    drop(proc);
}

/// 归还延迟队列中的全部内核栈帧（仅限"确定不在将死栈上"的入口调用：
/// tick 顶部、spawn 入口；测试钩子可对哑进程直接调用）。
fn drain_dead_kstacks() {
    let mut q = DEAD_KSTACKS.lock();
    for frame in q.drain(..) {
        // order 记录在分配器帧元数据中，按基址整块归还（16 帧一次到位）。
        mm::deallocate_frame(frame);
    }
}

/// "干净浮点上电态"模板（FNINIT 后快照），新 PCB 的初始 FPU 现场。
///
/// 锁序：SCHED → FPU_TEMPLATE（叶子锁，临界区仅一次快照拷贝，无反向嵌套）。
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

/// 调度器：进程池（pid 槽）+ 就绪队列（RR）+ 当前进程。
struct Scheduler {
    procs: Vec<Option<ProcEntry>>,
    ready: VecDeque<usize>,
    next_pid: usize,
    current: Option<usize>,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            procs: Vec::new(),
            ready: VecDeque::new(),
            next_pid: 1,
            current: None,
        }
    }

    fn alloc_pid(&mut self) -> usize {
        // task1 KM6：数值边界论证 + 机器强制。usize::MAX 个并发进程物理不可达
        // ——每个存活 PCB 至少消耗 16 帧内核栈 + 一页堆 + 独立页表页，128M
        // 物理内存在 pid 空间耗尽前数十亿倍早于枯竭；checked_add 把"论证过的
        // 不可达"变成受控 panic（编程错误走 abort，ADR-010），而非静默回绕
        // 造成 pid 撞车破坏 ppid=槽位索引不变式。
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .expect("pid space exhausted (u64 overflow)");
        pid
    }
}

static SCHED: IrqSpinLock<Scheduler> = IrqSpinLock::new(Scheduler::new());

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
    spawn_with_ppid(0, name, entry_rip, user_stack_top, addr_space)
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

/// 创建一个进程并登记其父进程与真实程序名（C7.1 父子关系 + C1.1 名称单点）。
///
/// `ppid` 为父进程 pid；`0` 表示内核直创（无收尸人，退出即回收）。`name`
/// 必须是调用方提供的真实可执行程序名（如 `init.elf`、`shell.elf`），
/// ProcFS 直接展示该值，不再按 pid 推断。
pub fn spawn_with_ppid(
    ppid: usize,
    name: &str,
    entry_rip: u64,
    user_stack_top: u64,
    addr_space: UserAddressSpace<X86PageTable>,
) -> Result<usize, Error> {
    // 延迟回收先于新分配执行（task1 K3）：把已退出进程的内核栈帧还池，
    // 提高 spawn 在内存压力下的成功率。
    drain_dead_kstacks();
    let (name_buf, name_len) = store_name(name)?;
    let mut s = SCHED.lock();
    // 父必须真实存在且非 zombie，否则拒绝建立虚假父子关系（零伪数据）。
    if ppid != 0 {
        let ok = matches!(
            s.procs.get(ppid),
            Some(Some(p)) if p.proc.state() != TaskState::Exit
        );
        if !ok {
            return Err(Error::NotFound);
        }
    }
    let pid = s.alloc_pid();
    // 分配独立内核栈（16 帧；HHDM 高半区在所有进程页表继承可见）。
    let stack_frame = mm::allocate_frames(KSTACK_ORDER).ok_or(Error::OutOfMemory)?;
    let kstack_top = arch::phys_to_virt(stack_frame.start_paddr()) + KSTACK_SIZE as u64;
    let proc = Box::new(Process::<X86PageTable>::new(
        pid,
        entry_rip,
        user_stack_top,
        kstack_top,
        addr_space,
    ));
    let entry = ProcEntry {
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
    };
    if pid < s.procs.len() {
        s.procs[pid] = Some(entry);
    } else {
        while s.procs.len() < pid {
            s.procs.push(None);
        }
        s.procs.push(Some(entry));
    }
    s.ready.push_back(pid);
    Ok(pid)
}

/// 当前就绪进程数（诊断）。
#[allow(dead_code)]
pub fn ready_count() -> usize {
    SCHED.lock().ready.len()
}

/// 调度器 tick（注册为 `register_scheduler_tick`，仅 BSP、IRQ0 后调用）。
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
    // 延迟回收点之一（task1 K3）：本函数运行在当前存活进程的中断栈上，
    // 不在任何将死栈上执行，归还安全。放在时间片判断之前——即使本轮
    // 不切换也照常清队，回收延迟与时间片长度解耦。
    drain_dead_kstacks();

    let n = TICK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n % TIMESLICE_TICKS != 0 {
        return;
    }

    let mut s = SCHED.lock();

    // 仅当有用户进程运行（current=Some）时才在 tick 里做 RR 切换。
    // 内核 idle/主线程（current=None）不做切换：此时若切走会丢弃主线程
    // 上下文（M4.2 关键修复——否则主线程在启动过程中被 IRQ0 切到用户进程，
    // 剩余 spawn 永远不执行）。进程由 scheduler::start() 的 idle 循环启动。
    let Some(cur_pid) = s.current else {
        return;
    };
    // 防御：current 指向已回收槽位（正常路径 exit_current 会清 current；
    // 此守卫兜底测试钩子清理窗口等非常规序列，避免切进悬空槽）。
    if s.procs.get(cur_pid).map_or(true, |p| p.is_none()) {
        s.current = None;
        return;
    }

    // 保存当前运行进程。
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Ready);
        s.ready.push_back(cur_pid);
    }

    // 从就绪队列取下一个。
    let Some(next_pid) = s.ready.pop_front() else {
        return; // 无可调度进程
    };

    if cur_pid == next_pid {
        // 仅当前进程自身：不切换，恢复 Running 继续。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return;
    }

    // 切换到 next 进程（FPU 现场 + CR3/RSP0/CURRENT 单点收口）。
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    cpu_switch_locked(&mut s, Some(cur_pid), next_pid);
}

/// 锁内完整 CPU 现场切换单点（task1 K2 收口）：FPU 保存/恢复 +
/// CR3/RSP0/CURRENT 更新。调用方须已持有 `SCHED` 锁、完成 `*frame` 替换与
/// 状态迁移；`prev` 为被切出进程 pid（槽位必须仍存在），`next` 为切入进程。
fn cpu_switch_locked(s: &mut Scheduler, prev: Option<usize>, next: usize) {
    // FPU eager 全量保存/恢复（K2）：prev 槽位此刻仍在表中（退役路径
    // 先经 retire_entry 才可能消失，而那发生在切出之后）。
    if let Some(pid) = prev {
        if let Some(slot) = s.procs[pid].as_mut() {
            fpu::save(&mut slot.fpu);
        }
    }
    let slot = s.procs[next].as_mut().expect("switch target exists");
    fpu::restore(&slot.fpu);
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
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
    let mut s = SCHED.lock();
    let Some(cur_pid) = s.current else {
        return SwitchOutcome::NotSwitched; // 内核 idle/主线程不参与让出
    };

    // 写回 yield 返回值 0，随 saved 保存；进程下次恢复时 rax=0。
    frame.rax = 0;
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Ready);
        s.ready.push_back(cur_pid);
    }

    // 从就绪队列取下一个。
    let Some(next_pid) = s.ready.pop_front() else {
        return SwitchOutcome::NotSwitched; // 无可调度进程（不应发生）
    };

    if cur_pid == next_pid {
        // 仅当前进程自身：无可让出，恢复 Running 继续。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return SwitchOutcome::NotSwitched;
    }

    // 切换到 next 进程（与 tick 相同的切换逻辑）。
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    cpu_switch_locked(&mut s, Some(cur_pid), next_pid);
    SwitchOutcome::Switched
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
fn pop_ready(s: &mut Scheduler, exclude: usize) -> Option<usize> {
    while let Some(pid) = s.ready.pop_front() {
        if pid == exclude {
            continue;
        }
        if let Some(slot) = s.procs[pid].as_ref() {
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
fn extract_from_ready(s: &mut Scheduler, target: usize) -> Option<usize> {
    let n = s.ready.len();
    for _ in 0..n {
        let pid = s.ready.pop_front().expect("len>0 in bounded loop");
        if pid == target {
            return Some(pid);
        }
        // 非目标：保持就绪，放回队尾（不破坏其可调度性/公平轮转）。
        s.ready.push_back(pid);
    }
    None
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
    let mut s = SCHED.lock();
    block_current_locked(&mut s, frame, &mut || true)
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
/// 锁序：本函数持 SCHED 期间回调可能取 IPC 表锁（SCHED → IPC 表，单向）；
/// 唤醒方一律在表锁外调用 wake，反向边不存在。
pub fn block_current_with(
    frame: &mut InterruptFrame,
    register: &mut dyn FnMut() -> bool,
) -> SwitchOutcome {
    let mut s = SCHED.lock();
    block_current_locked(&mut s, frame, register)
}

/// 共享阻塞主体：`s` 必须已锁；`register` 在确认存在可切换目标后、置
/// Blocked 前执行。prev=Some(cur) 交由 cpu_switch_locked 归档浮点现场
/// （审计 R5-F1 纪律在阻塞路径的原生形态）。
fn block_current_locked(
    s: &mut Scheduler,
    frame: &mut InterruptFrame,
    register: &mut dyn FnMut() -> bool,
) -> SwitchOutcome {
    let Some(cur_pid) = s.current else {
        return SwitchOutcome::NotSwitched; // 内核 idle/主线程不参与阻塞
    };
    // 取下一个有效就绪进程（跳过已退出残留引用）。无同伴则不登记、不阻塞：
    // 强行阻塞将无人唤醒（自锁），调用方应返回 WouldBlock。
    let Some(next_pid) = pop_ready(s, usize::MAX) else {
        return SwitchOutcome::NotSwitched;
    };
    if cur_pid == next_pid {
        // 仅当前进程自身：不阻塞（保持 Running 继续）。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return SwitchOutcome::NotSwitched;
    }
    // 调度锁内的登记点：失败即整体放弃，现场未动、表零副作用。
    if !register() {
        // S26 回归：`next_pid` 已在上方被 `pop_ready` 弹出（仍为 Ready 态），
        // 若直接返回将永久丢失该就绪进程（无人重新入队 → 饿死）。
        // 必须把它放回就绪队列，保证"登记失败零副作用"成立。
        s.ready.push_back(next_pid);
        return SwitchOutcome::NotSwitched;
    }
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Blocked);
        // 浮点归档不在此处执行：cpu_switch_locked(prev=Some) 是唯一的 prev
        // 现场快照点（审计 R6-F3 附带消除双重 fxsave 冗余——两次 save 之间
        // 虽无内核代码触碰 XMM（sdk/check-no-sse.py 已证），但冗余写会让
        // "哪一次是权威归档"变得不可辨认）。
    }
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    cpu_switch_locked(s, Some(cur_pid), next_pid);
    SwitchOutcome::Switched
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
    let mut s = SCHED.lock();
    // task1 KM4：本 expect 是**编程错误契约**的受控 abort（ADR-010 边界）——
    // 键盘阻塞只可能由 stdin read 的内核路径发起，"无当前进程时到达此处"
    // 意味着调用方违反了入口约定，属不可恢复的内核 bug；按全项目错误策略
    // 这不是运行期可上抛的错误（区别于有界资源耗尽的 Result 家族）。
    let cur_pid = s.current.expect("block_for_kbd outside process");
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
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        // K2：等待者此刻仍持有 CPU 的浮点现场，必须在切走前快照进自己的
        // PCB（Blocked 进程的 FPU 区在唤醒后由恢复路径如实还原）。
        fpu::save(&mut slot.fpu);
        slot.proc.set_state(TaskState::Blocked);
    }
    s.current = None;
    clear_current_proc();

    // 取下一个有效就绪进程切换（跳过已退出残留引用）。
    match pop_ready(&mut s, usize::MAX) {
        Some(next) => {
            let slot = s.procs[next].as_mut().expect("ready proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            cpu_switch_locked(&mut s, None, next);
            BlockKbdOutcome::Switched // frame 已改，由 syscall_entry iret 切换
        }
        None => {
            drop(s);
            // 无就绪进程：idle halt 等键盘中断唤醒（先释放锁再 halt，使中断可达）。
            //
            // 审计 B17 单核不变式（S21 显式化）：本路径假设**全系统只有本核
            // 执行调度决策**——KBD_WAITER 唯一等待者 + "pop_ready 得到的
            // next 必是刚被唤醒者"都依赖没有第二个 CPU 同时在 pop。当前
            // SMP 拓扑下 AP 不进入本函数（调度仅 BSP tick/block 路径驱动，
            // 见 smp.rs AP 入口无 scheduler 接线）；若未来引入 AP 调度，
            // 本段必须先改造为跨核唤醒协议，否则切错进程 = 永久阻塞。
            arch_x86_64::interrupts::enable();
            loop {
                // 极短持锁检查是否有进程被唤醒；空则释放锁后 halt（中断可达）。
                let ready = !SCHED.lock().ready.is_empty();
                if ready {
                    break;
                }
                arch_x86_64::interrupts::halt();
            }
            arch_x86_64::interrupts::disable();
            let mut s = SCHED.lock();
            let next = pop_ready(&mut s, usize::MAX).expect("woken keyboard waiter");
            let slot = s.procs[next].as_mut().expect("woken proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            // prev=None：阻塞等待者的浮点现场已在置 Blocked 前显式保存，
            // 此处只做切入方恢复（等待者不是被"切出"的运行进程）。
            cpu_switch_locked(&mut s, None, next);
            // 注意：**不在此处重置 KBD_WAITER**。KBD_WAITER 的生命周期由
            // `wake_kbd` 独占管理（每次键盘中断用 swap 取出并重置为空）。
            // 本 idle-halt 路径的唤醒者未必是键盘等待者——其他进程（如
            // volumed 的周期对账、init）被 tick/事件唤醒时，`pop_ready`
            // 弹出的 `next` 不是阻塞等键盘的进程；若在此无条件重置
            // KBD_WAITER，会把仍阻塞等键盘的 shell 的等待者身份错误清空，
            // 导致后续键盘中断 `wake_kbd` 找不到等待者 → shell 永久阻塞、
            // 键盘输入失效（"完全启动后无法输入"）。等待者身份只应被真正
            // 消费它的 `wake_kbd` 复位。
            drop(s);
            BlockKbdOutcome::Switched // frame 已改，由 syscall_entry iret 切换
        }
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
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs[p as usize].as_mut() {
        // waiting_for 由 waitpid 机制独占管理（不变式见 ProcEntry），不得被
        // 键盘路径提前唤醒——否则其带着未填写的 saved.rax 返回用户态。
        if slot.waiting_for.is_some() {
            return;
        }
        slot.proc.set_state(TaskState::Ready);
        s.ready.push_back(p as usize);
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
/// **lost-wakeup 论证**：登记（CAS 写 EVENT_WAITER）与"事件队列复检 + 置 Blocked"
/// 都在 `SCHED` 锁临界区完成；[`wake_event`]/[`wake_event_timeout`] 也持 `SCHED`
/// 锁才改 Ready。故"事件到达（publish_event → wake_event）"与"本进程登记"二者
/// 被锁完全串行——若事件先到，wake_event 见无等待者直接返回，本进程随后复检
/// 队列**非空** → 不阻塞，返回 NotSwitched 让调用方取事件；若本进程先登记，
/// wake_event 必在登记后（锁内）读到 pid 并唤醒。不存在"登记后事件到达却无人
/// 唤醒"的窗口。`publish_event` 先入队再唤醒，保证唤醒者复检时必见事件。
pub fn block_for_event(frame: &mut InterruptFrame) -> SwitchOutcome {
    let cur_pid = {
        let s = SCHED.lock();
        let cur = s.current.expect("block_for_event outside process");
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
    // 置 Blocked 并保存现场。浮点现场由 cpu_switch_locked(prev=None) 路径在
    // 唤醒后显式保存（同 block_for_kbd，K2 纪律），此处不重复归档。
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        fpu::save(&mut slot.fpu);
        slot.proc.set_state(TaskState::Blocked);
    }
    s.current = None;
    clear_current_proc();

    // 取下一个有效就绪进程切换（跳过已退出残留引用）。
    match pop_ready(&mut s, usize::MAX) {
        Some(next) => {
            let slot = s.procs[next].as_mut().expect("ready proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            cpu_switch_locked(&mut s, None, next);
            // 清理登记：CAS 只在仍指向本 pid 时清除（事件唤醒已 swap 走则无事）。
            let _ = EVENT_WAITER.compare_exchange(
                cur_pid as u32,
                u32::MAX,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            );
            SwitchOutcome::Switched
        }
        None => {
            // 无就绪进程：idle halt 等事件/超时唤醒（先释放锁再 halt，中断可达）。
            // 与 block_for_kbd 的 None 分支同构（B17 单核不变式）：EVENT_WAITER
            // 唯一事件等待者，唤醒方（wake_event / wake_event_timeout）只会把本
            // 进程加入就绪队列，halt 循环检测到后切回。**绝不忙转**：每次 halt 让
            // CPU 真正停机直到中断到达（V4）。
            //
            // O1 竞争面（低，继承 B17 单核不变式但已消除）：事件路径有**事件 +
            // 定时器两个唤醒源**，且全系统可能并存被键盘中断唤醒的键盘等待者
            // （都在同一就绪队列）。故不能只在"队列非空"时弹队头——队头可能是
            // 并发唤醒的其它进程，切错即事件等待者永久挂起。这里改为**等待本
            // 事件等待者 cur_pid 就绪**并专门取出它，而非弹任意队头。
            drop(s);
            arch_x86_64::interrupts::enable();
            loop {
                let s = SCHED.lock();
                let woke = s.ready.contains(&cur_pid);
                drop(s);
                if woke {
                    break;
                }
                arch_x86_64::interrupts::halt();
            }
            arch_x86_64::interrupts::disable();
            let mut s = SCHED.lock();
            // 取出特定的本事件等待者（队列头可能已被键盘/其它唤醒并发入队的
            // 其它 Ready 进程占据；extract_from_ready 保持它们就绪）。
            let next = extract_from_ready(&mut s, cur_pid).expect("woken event waiter");
            let slot = s.procs[next].as_mut().expect("woken proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            cpu_switch_locked(&mut s, None, next);
            drop(s);
            // 清理登记：事件唤醒已 swap 走 EVENT_WAITER（本 pid 不在），CAS 无
            // 效；超时唤醒走 wake_event_timeout（EVENT_WAITER 仍指向本 pid），
            // 此 CAS 清除之，保证后继新等待者不被"占位"拒之门外。
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
    let stale = EVENT_TIMER.swap(u64::MAX, core::sync::atomic::Ordering::AcqRel);
    if stale != u64::MAX {
        klib::time::cancel_timeout(stale);
    }
    if p == u32::MAX {
        return;
    }
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs[p as usize].as_mut() {
        // waiting_for 由 waitpid 机制独占管理，不得被事件路径提前唤醒；
        // 非 Blocked（已醒/超时）也不得再置 Ready（避免重入就绪队列）。
        if slot.waiting_for.is_none() && slot.proc.state() == TaskState::Blocked {
            slot.saved.rax = EVENT_WAKE_RETRY_SENTINEL;
            slot.proc.set_state(TaskState::Ready);
            s.ready.push_back(p as usize);
        }
    }
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
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs[pid].as_mut() {
        if slot.proc.state() == TaskState::Blocked {
            slot.saved.rax = 0;
        }
    }
    drop(s);
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

/// 设置调度器视角的当前进程（审计 B21：`block_for_kbd` 从 [`SCHED`] 的
/// `current` 取等待者 pid——仅装 per-cpu current 不够）。Busy 分支在触达
/// 进程槽表之前即返回，pid 无需对应真实槽位。
#[cfg(feature = "kernel-tests")]
pub fn debug_set_scheduler_current(pid: usize) {
    SCHED.lock().current = Some(pid);
}

/// 清除调度器当前进程（与上者配对的测试收尾）。
#[cfg(feature = "kernel-tests")]
pub fn debug_clear_scheduler_current() {
    SCHED.lock().current = None;
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
    let mut s = SCHED.lock();
    let Some(slot) = s.procs.get_mut(pid).and_then(|p| p.as_mut()) else {
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
fn parent_reapable(s: &Scheduler, ppid: usize) -> bool {
    ppid != 0
        && matches!(
            s.procs.get(ppid),
            Some(Some(p)) if p.proc.state() != TaskState::Exit
        )
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
/// 调用方必须持有 `SCHED` 锁。对不存在的 pid 返回 [`Termination::Reclaimed`]
/// （幂等防御，正常路径不会发生）。
fn terminate_locked(s: &mut Scheduler, pid: usize, code: u64) -> Termination {
    let ppid = {
        let Some(slot) = s.procs.get_mut(pid) else {
            return Termination::Reclaimed;
        };
        let Some(slot) = slot.as_mut() else {
            return Termination::Reclaimed;
        };
        slot.exit_code = code;
        slot.proc.set_state(TaskState::Exit);
        s.ready.retain(|&p| p != pid);
        slot.ppid
    };

    // 父进程判定与交付动作在受限借用内完成，入队等表级操作放回外层。
    let deliver = if !parent_reapable(s, ppid) {
        false
    } else {
        let ps = s.procs[ppid].as_mut().expect("parent reapable");
        if ps.proc.state() == TaskState::Blocked
            && (ps.waiting_for == Some(pid) || ps.waiting_for == Some(WAIT_ANY))
        {
            // 交付：退出码即 syscall 成功返回值（pack_ok(code) == code），
            // 直接写进父的保存帧 rax——父被调度回来 iretq 后用户态即刻拿到。
            ps.waiting_for = None;
            ps.saved.rax = code;
            ps.proc.set_state(TaskState::Ready);
            true
        } else {
            false
        }
    };

    let outcome = if !parent_reapable(s, ppid) {
        driver::uio_on_process_exit(pid);
        if let Some(e) = s.procs[pid].take() {
            retire_entry(e);
        }
        Termination::Reclaimed
    } else if deliver {
        s.ready.push_back(ppid);
        driver::uio_on_process_exit(pid);
        if let Some(e) = s.procs[pid].take() {
            retire_entry(e);
        }
        Termination::DeliveredToParent
    } else {
        Termination::ZombieKept
    };

    // 孤儿级联：本进程的 zombie 子女已无人可收，直接回收（零残留）。
    for i in 0..s.procs.len() {
        let orphan_zombie = matches!(&s.procs[i], Some(e)
            if e.ppid == pid && e.proc.state() == TaskState::Exit);
        if orphan_zombie {
            driver::uio_on_process_exit(i);
            if let Some(e) = s.procs[i].take() {
                retire_entry(e);
            }
        }
    }

    // 孤儿过继：本进程的存活子女过继给 init（使它们有明确的收尸人）。
    // 仅当 init 已登记且不是本进程自身时才执行（避免自指）。
    let init = INIT_PID.load(core::sync::atomic::Ordering::Acquire);
    if init != 0 && init != pid {
        for i in 0..s.procs.len() {
            if matches!(&s.procs[i], Some(e)
                if e.ppid == pid && e.proc.state() != TaskState::Exit)
            {
                if let Some(slot) = s.procs[i].as_mut() {
                    slot.ppid = init;
                }
            }
        }
    }

    outcome
}

/// 收尸（持锁核心）：`child` 必须是 `cur` 的在册直接子进程。
/// zombie → 取走退出码并释放槽位；仍在运行 → `None`（调用方决定阻塞或报错）。
fn reap_child_locked(s: &mut Scheduler, cur: usize, child: usize) -> Option<u64> {
    let is_mine = matches!(s.procs.get(child), Some(Some(e)) if e.ppid == cur);
    if !is_mine {
        return None;
    }
    let exited = s.procs[child]
        .as_ref()
        .is_some_and(|e| e.proc.state() == TaskState::Exit);
    if !exited {
        return None;
    }
    let code = s.procs[child].as_ref().map(|e| e.exit_code).unwrap_or(0);
    driver::uio_on_process_exit(child);
    if let Some(e) = s.procs[child].take() {
        retire_entry(e);
    }
    Some(code)
}

/// [`waitpid`] 的完成形态（C7.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// 同步收尸：目标已是 zombie，退出码随值返回。
    Code(u64),
    /// 已真阻塞并切换走：退出码由子进程终止路径直接写入调用者保存帧
    /// `rax`，唤醒后 iretq 即得；CPU 不再回到等待方内核调用点。
    Blocked,
}

/// `waitpid(target)` 内核实现（C7.1/#7，ADR-014 SYS_TASK_WAIT target>0 分支）。
///
/// - 目标不是调用者的在册直接子进程（不存在/非亲生/已被收尸）→
///   [`Error::NotFound`]（errno 2；klib 错误表无 ECHILD，取语义最近的
///   NotFound，映射决策记录于 ADR-014 实现注记）；
/// - 子进程已是 zombie → 同步收尸，返回 [`Waited::Code`]；
/// - 子进程仍在运行 → 登记等待后**真阻塞**（`TaskState::Blocked`，不回就绪
///   队列），切换到下一就绪进程，返回 [`Waited::Blocked`]——入口据此跳过
///   rax 回写，保住子进程终止路径交付到保存帧的退出码；
/// - 无其他**就绪**进程（阻塞后无人能接盘 CPU 唤醒自己）→ 拒绝阻塞，如实
///   返回 [`Error::WouldBlock`]（errno 11 EAGAIN），绝不自锁死系统。
pub fn waitpid(target_pid: usize, frame: &mut InterruptFrame) -> Result<Waited, Error> {
    let mut s = SCHED.lock();
    let cur = s.current.ok_or(Error::NotFound)?;
    waitpid_inner(&mut s, cur, target_pid, Some(frame))
}

/// [`waitpid`] 的锁内主体。`frame = None` 为测试钩子形态：只做表级登记与
/// 状态迁移，不做 CPU 切换（物理切换路径由 m41/m42/kbd 既有验收与
/// kernel-test-waitpid 停机验收覆盖）。
fn waitpid_inner(
    s: &mut Scheduler,
    cur: usize,
    target_pid: usize,
    mut frame: Option<&mut InterruptFrame>,
) -> Result<Waited, Error> {
    // ---- WAIT_ANY（等待任意子进程）分支 ----
    if target_pid == WAIT_ANY {
        // 1. 扫描所有子进程，如有 zombie 则收割（取第一个）。
        for i in 0..s.procs.len() {
            if matches!(&s.procs[i], Some(e)
                if e.ppid == cur && e.proc.state() == TaskState::Exit)
            {
                let code = reap_child_locked(s, cur, i).expect("zombie confirmed");
                return Ok(Waited::Code(code));
            }
        }
        // 2. 无 zombie：检查是否至少有一个子进程存在。
        let has_children = s.procs.iter().any(|p| {
            matches!(p, Some(e) if e.ppid == cur)
        });
        if !has_children {
            return Err(Error::NotFound); // 无子进程 = ECHILD 等价
        }
        // 3. 有子进程但无 zombie → 走阻塞路径（哨兵标记 WAIT_ANY）。
    } else {
        // ---- 单目标（既有）分支 ----
        if target_pid == 0 || target_pid >= s.procs.len() {
            return Err(Error::NotFound);
        }
        // 只能等待自己的直接子进程。
        let is_mine = matches!(s.procs.get(target_pid), Some(Some(e)) if e.ppid == cur);
        if !is_mine {
            return Err(Error::NotFound);
        }
        if let Some(code) = reap_child_locked(s, cur, target_pid) {
            return Ok(Waited::Code(code)); // zombie 同步收尸
        }
    }

    // 阻塞等待（WAIT_ANY 与单目标共用阻塞逻辑）。
    // 等待目标：WAIT_ANY 或具体 pid。
    let wait_for = if target_pid == WAIT_ANY { WAIT_ANY } else { target_pid };
    let others_ready = s.ready.iter().any(|&p| {
        p != cur && matches!(s.procs.get(p), Some(Some(e)) if e.proc.state() == TaskState::Ready)
    });
    let revert = |s: &mut Scheduler| -> Error {
        if let Some(slot) = s.procs[cur].as_mut() {
            slot.waiting_for = None;
            slot.proc.set_state(TaskState::Running);
        }
        Error::WouldBlock
    };
    if !others_ready {
        return Err(revert(s)); // 尚未标记，直接拒绝
    }
    {
        let slot = s.procs[cur].as_mut().expect("current proc exists");
        slot.waiting_for = Some(wait_for);
        slot.proc.set_state(TaskState::Blocked);
        // 占位 rax 随 saved 保存；真实退出码由子进程终止路径覆写。
        // 测试钩子形态（frame=None）不保存帧：saved 保持初始值，交付路径覆写。
        if let Some(f) = frame.as_deref_mut() {
            f.rax = 0;
            slot.saved = *f;
        }
    }
    let Some(next_pid) = pop_ready_filtered(s, cur) else {
        // 极小窗口防御：就绪项全失效（如全部 Exit 残留）。撤销阻塞如实报错。
        return Err(revert(s));
    };
    if next_pid == cur {
        return Err(revert(s));
    }
    if frame.is_some() {
        // 物理切换（FPU + CR3/RSP0/CURRENT 单点）；仅真实 syscall 形态执行。
        // 先置 Running、改写 *frame 为下一进程保存帧，再切 CR3（与 yield_now
        //  line 490-493 / exit_current line 1090-1093 同构）。缺失 *frame 替换
        // 会导致 iretq 以当前进程帧返回用户态（当前已 Blocked），cr3 已是下一
        // 进程页表 → 在错配的 RIP 下执行下一进程代码 → 用户态页错误（S26）。
        let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
        slot.proc.set_state(TaskState::Running);
        if let Some(f) = frame.as_deref_mut() {
            *f = slot.saved;
        }
        cpu_switch_locked(s, Some(cur), next_pid);
    } else {
        // 测试形态：目标进程标记 Running 以维持表级一致性（不切 CR3/RSP0）。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        s.current = Some(next_pid);
    }
    Ok(Waited::Blocked)
}

/// 从就绪队列取下一个有效进程，额外跳过 `exclude`（waitpid 场景排除自身）。
/// 仅接受 `Ready` 状态（Blocked 项不得被切换执行）——实现已并入 [`pop_ready`]
/// 单点（task1 KM8），此包装保留 waitpid 调用点的语义命名。
fn pop_ready_filtered(s: &mut Scheduler, exclude: usize) -> Option<usize> {
    pop_ready(s, exclude)
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
    let mut s = SCHED.lock();
    let cur_pid = s.current.expect("exit called outside process");
    // PID 1 契约：init 不得退出（自杀即 panic）。
    if cur_pid == init_pid() {
        panic!("attempted to kill init (self-exit pid={})", cur_pid);
    }
    let _ = terminate_locked(&mut s, cur_pid, code);
    s.current = None;
    clear_current_proc();

    // 取下一个有效就绪进程（跳过已退出残留引用）。
    let Some(next_pid) = pop_ready(&mut s, usize::MAX) else {
        drop(s);
        // 无 Ready 进程：可能有 Blocked 进程（如 shell 等键盘输入）。进入 idle
        // 等待，被外部中断（键盘 → `wake_kbd` 把其入就绪队列）唤醒后切回，
        // 而非永久停机——否则 shell 收不到输入、系统假死。
        arch_x86_64::interrupts::enable();
        loop {
            // 极短持锁检查是否有被唤醒的进程；空则释放锁后 halt（中断可达）。
            if !SCHED.lock().ready.is_empty() {
                break;
            }
            arch_x86_64::interrupts::halt();
        }
        arch_x86_64::interrupts::disable();
        let mut s = SCHED.lock();
        let next = pop_ready(&mut s, usize::MAX).expect("woken process after idle");
        let slot = s.procs[next].as_mut().expect("woken proc exists");
        slot.proc.set_state(TaskState::Running);
        *frame = slot.saved;
        // prev=None：将死进程的槽位已随 terminate 退役（其 FPU 现场随之消亡，
        // 无需保存），此处只做切入方恢复。本函数此刻仍物理运行在将死栈上，
        // 但 cpu_switch_locked 只把帧归还入队（DEAD_KSTACKS），不就地释放——
        // 栈内存直到下一次 tick/spawn 才真正还池，iretq 前无被复用窗口。
        cpu_switch_locked(&mut s, None, next);
        return; // frame 已改，由 syscall_entry iret 切换
    };
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    cpu_switch_locked(&mut s, None, next_pid);
}

/// 枚举全部存活进程，向用户态缓冲写入快照条目。
///
/// 每条 8 字节：`pid: u32`（小端）+ `state: u8`（1=Ready 2=Running 3=Blocked）+ 3 字节填充。
/// 返回写入的条目数（受 `cap` 字节限制）。经 `copy_to_user` 安全写入用户缓冲（SMAP）。
pub fn ps_snapshot(buf: *mut u8, cap: usize) -> usize {
    let s = SCHED.lock();
    let mut off = 0usize;
    let mut n = 0usize;
    for entry in s.procs.iter() {
        if let Some(e) = entry.as_ref() {
            if e.proc.state() == TaskState::Exit {
                continue;
            }
            if off + 8 > cap {
                break;
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
    let s = SCHED.lock();
    let mut list = Vec::new();
    for entry in s.procs.iter() {
        if let Some(e) = entry.as_ref() {
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
    let s = SCHED.lock();
    let entry = s.procs.get(pid)?.as_ref()?;
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
pub fn kill_pid(target: usize, sig: u32, frame: &mut InterruptFrame) -> Result<u64, Error> {
    // task1 KM1：信号号常量化——字面量 9/15 特判已废除，SIGKILL 由
    // signals 模块单点定义（S13）。
    if sig != 0 && sig != SIGKILL && sig != SIGTERM {
        return Err(Error::NotSupported);
    }
    let current = {
        let s = SCHED.lock();
        s.current
    };
    if current == Some(target) {
        if sig == 0 {
            return Ok(0); // 对自己探活
        }
        // PID 1 契约：init 自杀被显式拒绝（exit_current 中会 panic，
        // 此处先返回错误，避免 panic 对用户态进程的冲击）。
        if target == init_pid() {
            return Err(Error::PermissionDenied);
        }
        // 自杀：走标准退出路径（zombie 化并切换）。exit_current 内部自行加锁，
        // 故此处不持锁调用。exit_current 会把 `*frame` 改写为下一进程现场；
        // 调用方（sys_kill）依此返回 Switched，本函数**必须立即返回**——
        // 落入下方 he-kill 分支会对已死 target 返回 Err(InvalidParam)，
        // 污染调用方对 frame 的后续处理（S26 回归）。
        exit_current(frame, sig as u64);
        return Ok(0); // 不返回不可达：exit_current 是普通返回，切换由 iretq 完成
    }
    // PID 1 契约：禁止向他杀 init（探活 sig=0 放行）。
    if target == init_pid() && sig != 0 {
        return Err(Error::PermissionDenied);
    }
    // 校验目标存在且非 zombie。
    let mut s = SCHED.lock();
    let exists = matches!(s.procs.get(target), Some(Some(e)) if e.proc.state() != TaskState::Exit);
    if !exists {
        return Err(Error::InvalidParam);
    }
    if sig == 0 {
        return Ok(0); // 仅校验存在，不发送
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
    // 统一终止核心：置 Exit、按父子关系交付/保留/回收、孤儿级联、UIO 清理。
    let _ = terminate_locked(&mut s, target, sig as u64);
    Ok(0)
}

/// 唤醒一个阻塞的进程（IPC 写/读端完成时调用）：置 `Ready` 并入就绪队列。
///
/// 仅当目标进程处于 `Blocked` 时才生效（已就绪/运行中进程忽略，避免重复入队）。
/// 由 waitpid 机制独占管理的进程（`waiting_for` 已登记）不得经此唤醒——其
/// `saved.rax` 只能由子进程终止路径填写，提前唤醒会让用户态拿到占位值。
pub fn wake(pid: usize) {
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs.get_mut(pid).and_then(|p| p.as_mut()) {
        if slot.proc.state() == TaskState::Blocked && slot.waiting_for.is_none() {
            slot.proc.set_state(TaskState::Ready);
            s.ready.push_back(pid);
        }
    }
}

/// 启动调度器（内核 idle 主循环）：取第一个就绪进程，经 `enter_usermode` 进入
/// 其用户态。进程在用户态被 tick 打断后由 [`tick`] 轮转。永不返回。
pub fn start() -> ! {
    loop {
        // 取一个有效就绪进程启动（跳过已退出残留引用）。
        let mut s = SCHED.lock();
        let Some(pid) = pop_ready(&mut s, usize::MAX) else {
            drop(s);
            arch_x86_64::interrupts::halt(); // 无进程：停机等待中断
            continue;
        };
        let (entry_rip, user_stack_top, cr3) = {
            let slot = s.procs[pid].as_mut().expect("ready proc exists");
            slot.proc.set_state(TaskState::Running);
            (
                slot.proc.entry_rip(),
                slot.proc.user_stack_top(),
                slot.proc.addr_space().page_table_paddr(),
            )
        };
        // K2：首个进程切入前从其 PCB 恢复 FNINIT 模板现场，
        // 使"首次运行也走恢复路径"与后续调度完全一致。
        cpu_switch_locked(&mut s, None, pid);
        let frame = TrapFrame {
            rip: entry_rip,
            cs: user_code_selector() as u64,
            rflags: USER_RFLAGS,
            rsp: user_stack_top,
            ss: user_data_selector() as u64,
            cr3,
        };
        drop(s);
        arch::task::enter_usermode(&frame); // 永不返回
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
        let s = SCHED.lock();
        s.procs.get(pid).and_then(|p| p.as_ref()).map(|e| {
            (
                e.proc.state(),
                alloc::string::String::from(entry_name(e)),
                e.waiting_for,
                e.saved.rax,
                e.ppid,
            )
        })
    }

    /// 真实内存记账探针（C1.2 验收用）：返回该进程地址空间 declared_bytes()（MM7：虚拟预留量，非 RSS）。
    pub fn probe_memory_bytes(pid: usize) -> Option<u64> {
        let s = SCHED.lock();
        s.procs
            .get(pid)
            .and_then(|p| p.as_ref())
            .map(|e| e.proc.addr_space().declared_bytes())
    }

    /// 终止 `pid`（真实核心路径），返回终止分支名（测试断言用）。
    pub fn terminate(pid: usize, code: u64) -> &'static str {
        let mut s = SCHED.lock();
        match terminate_locked(&mut s, pid, code) {
            Termination::Reclaimed => "reclaimed",
            Termination::ZombieKept => "zombie",
            Termination::DeliveredToParent => "delivered",
        }
    }

    /// 非阻塞收尸尝试（真实核心路径）：NotFound=非亲生/不存在/已收尸；
    /// WouldBlock=子进程仍在运行；Ok(code)=已收尸（槽位已释放）。
    pub fn try_reap(parent: usize, target: usize) -> Result<u64, Error> {
        let mut s = SCHED.lock();
        if !matches!(s.procs.get(target), Some(Some(e)) if e.ppid == parent) {
            return Err(Error::NotFound);
        }
        reap_child_locked(&mut s, parent, target).ok_or(Error::WouldBlock)
    }

    /// 表级阻塞登记（真实 `waitpid_inner`，frame=None 不做物理切换）：
    /// 返回 Ok(Waited::Blocked) 表示已登记+Blocked+表级切换到下一就绪进程；
    /// Err(WouldBlock) 表示无可切进程已回滚；Err(NotFound) 同生产语义。
    pub fn block_on_child(parent: usize, target: usize) -> Result<Waited, Error> {
        let mut s = SCHED.lock();
        waitpid_inner(&mut s, parent, target, None)
    }

    /// WAIT_ANY 等价：等待任意子进程。
    /// 编译期仅当 `kernel-tests` 启用，与 `kernel-test-waitpid` 停机验收路径无关。
    pub fn wait_any(parent: usize) -> Result<Waited, Error> {
        let mut s = SCHED.lock();
        waitpid_inner(&mut s, parent, WAIT_ANY, None)
    }

    /// 清空全部测试进程，返回清除数量（防跨测试泄漏；next_pid 保持单调）。
    ///
    /// task1 KD3：同步复位 `KBD_WAITER`——否则上一个用例登记的键盘等待者
    /// 会泄漏到后续用例（Busy 误报 / 悬挂唤醒）。task1 K3：哑进程从未进入
    /// 过其内核栈，帧可**就地**归还（延迟队列的"将死栈在执行中"前提对
    /// 哑进程不成立）；顺带清空回收队列保证帧计数断言的确定性。
    pub fn reset_all() -> usize {
        let mut s = SCHED.lock();
        let mut n = 0;
        for i in 0..s.procs.len() {
            if let Some(e) = s.procs[i].take() {
                driver::uio_on_process_exit(i);
                // 哑进程栈未被任何执行流触碰：就地归还安全且确定。
                mm::deallocate_frame(e.kstack_frames);
                n += 1;
            }
        }
        s.ready.clear();
        s.current = None;
        KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        // 同步复位事件等待全局（S18/S21，V3/V6）：EVENT_WAITER 残留会让后继
        // 用例的 block_for_event 永久 NotSwitched；EVENT_TIMER 残留的 stale id
        // 会污染新等待的定时器取消。
        EVENT_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
        EVENT_TIMER.store(u64::MAX, core::sync::atomic::Ordering::Release);
        drop(s);
        drain_dead_kstacks();
        clear_current_proc();
        INIT_PID.store(0, core::sync::atomic::Ordering::Release);
        n
    }

    /// 场景构造：令 pid 进入与 waitpid 无关的 Blocked（模拟等键盘/IPC）并
    /// 移出就绪队列——用于驱动"无就绪同伴 → 拒绝阻塞"的真实回滚分支。
    /// waiting_for 已登记或已退出的进程拒绝操作。
    pub fn simulate_blocked(pid: usize) -> bool {
        let mut s = SCHED.lock();
        let Some(slot) = s.procs[pid].as_mut() else {
            return false;
        };
        if slot.waiting_for.is_some() || slot.proc.state() == TaskState::Exit {
            return false;
        }
        slot.proc.set_state(TaskState::Blocked);
        s.ready.retain(|&p| p != pid);
        true
    }

    // ---- task1 K2/K1 验收钩子 ----

    /// K2 隔离验收·保存半程：把 `marker` 写入 CPU xmm0，再执行与生产切换
    /// 路径相同的 [`fpu::save`] 快照进 pid 的 PCB 保存区。xmm0 显式声明为
    /// 破坏——内核目标启用 SSE，编译器可能跨语句持有 xmm 值。
    pub fn debug_fpu_save(pid: usize, marker: u64) -> bool {
        let mut s = SCHED.lock();
        let Some(slot) = s.procs.get_mut(pid).and_then(|p| p.as_mut()) else {
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
        let mut s = SCHED.lock();
        let slot = s.procs.get_mut(pid)?.as_mut()?;
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
        SCHED.lock().current
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
        SCHED.lock().ready = q;
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
        let mut s = SCHED.lock();
        s.ready.clear();
        s.ready.push_back(peer);
        s.current = Some(current);
        let mut frame = initial_frame(0x400000, 0x7ffefffff000);
        let outcome = block_current_locked(&mut s, &mut frame, &mut || false);
        outcome == SwitchOutcome::NotSwitched && s.ready.contains(&peer)
    }

    /// 审计 R5-F2 验收钩子：丢弃 FPU 模板缓存，令下一次 spawn 重新快照。
    /// 模板是全启动期懒单例——不重置则其内容固化在首次 spawn 时刻，
    /// "残值 vs 强零化"语义对后续用例不可观测。测试夹具专用。
    pub fn debug_reset_fpu_template() {
        *FPU_TEMPLATE.lock() = None;
    }

    /// 哑地址空间：仅占位映射（测试进程不执行任何用户代码）。
    fn dummy_space() -> Result<UserAddressSpace<X86PageTable>, Error> {
        use arch::PageSize;
        use arch::VirtAddr;
        let frame = mm::allocate_frame().ok_or(Error::OutOfMemory)?;
        let mut us = UserAddressSpace::<X86PageTable>::new()?;
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
