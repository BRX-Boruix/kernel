//! 调度器（M4.2）：多进程 RR 轮转。
//!
//! 进程在**用户态**被 LAPIC 定时器中断（IRQ0，100Hz）周期性打断，进入内核后
//! 由 [`tick`] 做时间片切换：
//! 1. 把当前运行进程的中断帧（`InterruptFrame`，含用户态 iretq 帧 + 全部寄存器）
//!    拷入其 `saved`，状态置 `Ready` 并入队尾；
//! 2. 从就绪队列队头取下一个进程，把其 `saved` 帧拷回当前中断帧；
//! 3. 切 CR3（目标进程用户页表）、切 TSS.RSP0（目标进程独立内核栈）、更新
//!    `CURRENT_PROC`；
//! 4. `interrupt_common_stub` 返回后 `iretq` 直接进入目标进程用户态。
//!
//! 关键设计：
//! - **每进程独立内核栈**：从物理帧分配器取 1 帧，经 HHDM 映射为内核半区虚拟地址
//!   写入 TSS.RSP0，避免多进程共享中断栈互相覆盖（所有进程页表继承内核半区映射，可见）；
//! - **单核调度**（M4.2）：仅在 BSP 上轮转（tick 回调经 arch 层只在 CPU0 触发），
//!   多核（AP 用户进程）留待后续；
//! - **首次运行**：进程 `spawn` 时构造"初始帧"（`initial_frame`），故首次调度也走
//!   "从 saved 恢复"，调度逻辑统一；内核 idle 主循环 [`start`] 经 `enter_usermode`
//!   进入第一个就绪进程。
#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use arch::task::TrapFrame;
use arch_x86_64::gdt;
use arch_x86_64::interrupts::InterruptFrame;
use arch_x86_64::paging::X86PageTable;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;
use mm::user_space::UserAddressSpace;

use crate::process::{Process, TaskState, clear_current_proc, set_current_proc};

/// 每进程独立内核栈大小（16 帧 = 64K）。
///
/// M4.2 修复：中断处理（IRQ0 → dispatch → tick）+ debug 构建的
/// `copy_nonoverlapping` 前置检查栈需求大，4K 会溢出（RBP 越界、卡死），
/// 故改用 64K。
const KSTACK_SIZE: usize = 65536;
/// 内核栈分配阶：2^4 = 16 帧。
const KSTACK_ORDER: usize = 4;

/// PCB 内保存的进程名上限；与 shell/ELF 路径缓冲无关，超长名在创建时明确拒绝。
const PROCESS_NAME_MAX: usize = 63;

/// 用户态段选择子（RPL=3），对齐 process.rs 的 launch 约定。
const UCODE_RPL3: u16 = arch_x86_64::gdt::UCODE | 3;
const UDATA_RPL3: u16 = arch_x86_64::gdt::UDATA | 3;
/// 用户态 RFLAGS：IF=1（开中断）、IOPL=0、保留位 1。
const USER_RFLAGS: u64 = 0x0000_0000_0000_0202;

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

/// 单进程槽：进程对象 + 被中断时的完整帧 + 独立内核栈顶。
struct ProcEntry {
    /// 进程控制块（含独立用户地址空间、上下文）。
    proc: Box<Process<X86PageTable>>,
    /// 该进程上次被中断时的完整 `InterruptFrame`（含用户态 iretq 帧 + 寄存器）。
    /// 首次 = `spawn` 时构造的初始启动帧。
    saved: InterruptFrame,
    /// 独立内核栈顶（TSS.RSP0；该进程用户态中断进入内核时切到此栈）。
    kstack_top: u64,
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
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }
}

static SCHED: IrqSpinLock<Scheduler> = IrqSpinLock::new(Scheduler::new());

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
        cs: UCODE_RPL3 as u64,
        rflags: USER_RFLAGS,
        rsp: user_stack_top,
        ss: UDATA_RPL3 as u64,
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
        kstack_top,
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

    // 切换到 next 进程。
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next_pid);

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
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next_pid);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
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
/// 从就绪队列取出下一个**有效**进程，跳过已回收/已退出的残留引用。
///
/// `yield`/`exec` 等可能把进程多次入队，进程退出（`procs[pid]=None`）后其
/// 就绪队列引用不会自动清除；直接 `pop_front().expect(...)` 会取到死 pid 并
/// panic。本函数循环弹出并丢弃无效项（`procs[pid]` 为 `None` 或状态 `Exit`），
/// 返回第一个有效 pid，队列空/仅含死进程时返回 `None`。
fn pop_ready(s: &mut Scheduler) -> Option<usize> {
    while let Some(pid) = s.ready.pop_front() {
        if let Some(slot) = s.procs[pid].as_ref() {
            if slot.proc.state() != TaskState::Exit {
                return Some(pid);
            }
        }
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
    let Some(cur_pid) = s.current else {
        return SwitchOutcome::NotSwitched; // 内核 idle/主线程不参与阻塞
    };
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Blocked);
    }
    // 取下一个有效就绪进程（跳过已退出残留引用）。
    let Some(next_pid) = pop_ready(&mut s) else {
        return SwitchOutcome::NotSwitched; // 无可调度进程：调用方不应阻塞
    };
    if cur_pid == next_pid {
        // 仅当前进程自身：不阻塞（保持 Running 继续）。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return SwitchOutcome::NotSwitched;
    }
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next_pid);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
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
        slot.proc.set_state(TaskState::Blocked);
    }
    s.current = None;
    clear_current_proc();

    // 取下一个有效就绪进程切换（跳过已退出残留引用）。
    match pop_ready(&mut s) {
        Some(next) => {
            let slot = s.procs[next].as_mut().expect("ready proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            let cr3 = slot.proc.addr_space_mut().page_table_paddr();
            let ktop = slot.kstack_top;
            let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
            s.current = Some(next);
            drop(s);
            arch_x86_64::mmio::write_cr3(cr3);
            gdt::set_rsp0(ktop);
            set_current_proc(proc_ptr);
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
                // 极短持锁检查是否有进程被唤醒；空则释放锁后 halt（中断可用）。
                let ready = !SCHED.lock().ready.is_empty();
                if ready {
                    break;
                }
                arch_x86_64::interrupts::halt();
            }
            arch_x86_64::interrupts::disable();
            let mut s = SCHED.lock();
            let next = pop_ready(&mut s).expect("woken keyboard waiter");
            let slot = s.procs[next].as_mut().expect("woken proc exists");
            slot.proc.set_state(TaskState::Running);
            *frame = slot.saved;
            let cr3 = slot.proc.addr_space_mut().page_table_paddr();
            let ktop = slot.kstack_top;
            let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
            s.current = Some(next);
            KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
            drop(s);
            arch_x86_64::mmio::write_cr3(cr3);
            gdt::set_rsp0(ktop);
            set_current_proc(proc_ptr);
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
        if ps.proc.state() == TaskState::Blocked && ps.waiting_for == Some(pid) {
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
        drv::uio_on_process_exit(pid);
        s.procs[pid] = None;
        Termination::Reclaimed
    } else if deliver {
        s.ready.push_back(ppid);
        drv::uio_on_process_exit(pid);
        s.procs[pid] = None;
        Termination::DeliveredToParent
    } else {
        Termination::ZombieKept
    };

    // 孤儿级联：本进程的 zombie 子女已无人可收，直接回收（零残留）。
    for i in 0..s.procs.len() {
        let orphan_zombie = matches!(&s.procs[i], Some(e)
            if e.ppid == pid && e.proc.state() == TaskState::Exit);
        if orphan_zombie {
            drv::uio_on_process_exit(i);
            s.procs[i] = None;
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
    drv::uio_on_process_exit(child);
    s.procs[child] = None;
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
    if target_pid == 0 || target_pid >= s.procs.len() {
        return Err(Error::NotFound);
    }
    // 只能等待自己的直接子进程；pid 不复用 ⇒ 槽位索引即 pid。
    let is_mine = matches!(s.procs.get(target_pid), Some(Some(e)) if e.ppid == cur);
    if !is_mine {
        return Err(Error::NotFound);
    }

    if let Some(code) = reap_child_locked(s, cur, target_pid) {
        return Ok(Waited::Code(code)); // zombie 同步收尸
    }

    // 子进程仍在运行：真阻塞。先确认有其他**就绪**进程可接盘 CPU
    // （Blocked/Exit 同伴都接不了盘），否则拒绝阻塞避免自锁。
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
        slot.waiting_for = Some(target_pid);
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
        // 物理切换（与 block_current 相同尾部）；仅真实 syscall 形态执行。
        switch_to_locked(s, next_pid);
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
/// 仅接受 `Ready` 状态（Blocked 项不得被切换执行）。
fn pop_ready_filtered(s: &mut Scheduler, exclude: usize) -> Option<usize> {
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

/// 锁内切换到 `next_pid`（保存帧恢复 + CR3/RSP0/CURRENT 更新）。
/// 调用方负责保证 `next_pid` 有效且当前帧已保存。
fn switch_to_locked(s: &mut Scheduler, next_pid: usize) {
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next_pid);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
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
    let _ = terminate_locked(&mut s, cur_pid, code);
    s.current = None;
    clear_current_proc();

    // 取下一个有效就绪进程（跳过已退出残留引用）。
    let Some(next_pid) = pop_ready(&mut s) else {
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
        let next = pop_ready(&mut s).expect("woken process after idle");
        let slot = s.procs[next].as_mut().expect("woken proc exists");
        slot.proc.set_state(TaskState::Running);
        *frame = slot.saved;
        let cr3 = slot.proc.addr_space_mut().page_table_paddr();
        let ktop = slot.kstack_top;
        let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
        s.current = Some(next);
        drop(s);
        arch_x86_64::mmio::write_cr3(cr3);
        gdt::set_rsp0(ktop);
        set_current_proc(proc_ptr);
        return; // frame 已改，由 syscall_entry iret 切换
    };
    let slot = s.procs[next_pid].as_mut().expect("ready proc exists");
    slot.proc.set_state(TaskState::Running);
    *frame = slot.saved;
    let cr3 = slot.proc.addr_space_mut().page_table_paddr();
    let ktop = slot.kstack_top;
    let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
    s.current = Some(next_pid);
    drop(s);
    arch_x86_64::mmio::write_cr3(cr3);
    gdt::set_rsp0(ktop);
    set_current_proc(proc_ptr);
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
            let state: u8 = match e.proc.state() {
                TaskState::Ready => 1,
                TaskState::Running => 2,
                TaskState::Blocked => 3,
                TaskState::Exit => 0,
            };
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
            let state_str = match e.proc.state() {
                TaskState::Ready => "Ready",
                TaskState::Running => "Running",
                TaskState::Blocked => "Blocked",
                TaskState::Exit => "Exit",
            };
            list.push(vfs::ProcessSnapshot {
                pid,
                name: alloc::string::String::from(entry_name(e)),
                state: alloc::string::String::from(state_str),
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
    let state_str = match entry.proc.state() {
        TaskState::Ready => "Ready",
        TaskState::Running => "Running",
        TaskState::Blocked => "Blocked",
        TaskState::Exit => "Exit",
    };
    Some(vfs::ProcessSnapshot {
        pid,
        name: alloc::string::String::from(entry_name(entry)),
        state: alloc::string::String::from(state_str),
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
    if sig != 0 && sig != 9 && sig != 15 {
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
        // 自杀：走标准退出路径（zombie 化并切换）。exit_current 内部自行加锁，
        // 故此处不持锁调用。
        exit_current(frame, sig as u64);
        // 不返回
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
        let Some(pid) = pop_ready(&mut s) else {
            drop(s);
            arch_x86_64::interrupts::halt(); // 无进程：停机等待中断
            continue;
        };
        let slot = s.procs[pid].as_mut().expect("ready proc exists");
        slot.proc.set_state(TaskState::Running);
        let entry_rip = slot.proc.entry_rip();
        let user_stack_top = slot.proc.user_stack_top();
        let cr3 = slot.proc.addr_space_mut().page_table_paddr();
        let ktop = slot.kstack_top;
        let proc_ptr = &mut *slot.proc as *mut Process<X86PageTable>;
        gdt::set_rsp0(ktop);
        set_current_proc(proc_ptr);
        s.current = Some(pid); // slot 借用已结束，再改 s.current
        let frame = TrapFrame {
            rip: entry_rip,
            cs: UCODE_RPL3 as u64,
            rflags: USER_RFLAGS,
            rsp: user_stack_top,
            ss: UDATA_RPL3 as u64,
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

    /// 进程状态探针：(状态, 名称, waiting_for, saved.rax)。名称为 PCB 缓冲拷贝。
    pub fn probe(pid: usize) -> Option<(TaskState, alloc::string::String, Option<usize>, u64)> {
        let s = SCHED.lock();
        s.procs.get(pid).and_then(|p| p.as_ref()).map(|e| {
            (
                e.proc.state(),
                alloc::string::String::from(entry_name(e)),
                e.waiting_for,
                e.saved.rax,
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

    /// 清空全部测试进程，返回清除数量（防跨测试泄漏；next_pid 保持单调）。
    pub fn reset_all() -> usize {
        let mut s = SCHED.lock();
        let mut n = 0;
        for i in 0..s.procs.len() {
            if s.procs[i].is_some() {
                drv::uio_on_process_exit(i);
                s.procs[i] = None;
                n += 1;
            }
        }
        s.ready.clear();
        s.current = None;
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
