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

use crate::process::{clear_current_proc, set_current_proc, Process, TaskState};

/// 每进程独立内核栈大小（16 帧 = 64K）。
///
/// M4.2 修复：中断处理（IRQ0 → dispatch → tick）+ debug 构建的
/// `copy_nonoverlapping` 前置检查栈需求大，4K 会溢出（RBP 越界、卡死），
/// 故改用 64K。
const KSTACK_SIZE: usize = 65536;
/// 内核栈分配阶：2^4 = 16 帧。
const KSTACK_ORDER: usize = 4;

/// 用户态段选择子（RPL=3），对齐 process.rs 的 launch 约定。
const UCODE_RPL3: u16 = arch_x86_64::gdt::UCODE | 3;
const UDATA_RPL3: u16 = arch_x86_64::gdt::UDATA | 3;
/// 用户态 RFLAGS：IF=1（开中断）、IOPL=0、保留位 1。
const USER_RFLAGS: u64 = 0x0000_0000_0000_0202;

/// 单进程槽：进程对象 + 被中断时的完整帧 + 独立内核栈顶。
struct ProcEntry {
    /// 进程控制块（含独立用户地址空间、上下文）。
    proc: Box<Process<X86PageTable>>,
    /// 该进程上次被中断时的完整 `InterruptFrame`（含用户态 iretq 帧 + 寄存器）。
    /// 首次 = `spawn` 时构造的初始启动帧。
    saved: InterruptFrame,
    /// 独立内核栈顶（TSS.RSP0；该进程用户态中断进入内核时切到此栈）。
    kstack_top: u64,
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
/// "启动帧"（供首次调度从 saved 恢复）。返回 pid。
pub fn spawn(
    entry_rip: u64,
    user_stack_top: u64,
    addr_space: UserAddressSpace<X86PageTable>,
) -> Result<usize, Error> {
    let mut s = SCHED.lock();
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
    // 时间片：每 10 次 tick（~100ms 虚拟）做一次 RR 切换。TCG 慢速下虚拟时钟
    // 快进，若每 tick（10ms 虚拟）都切换，进程时间片过短、执行不到 write；
    // 拉长时间片让进程有足够指令时间。真机上可调回 1（每 tick 切换）。
    let n = TICK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n % 10 != 0 {
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

/// `yield()`：当前进程**主动**让出 CPU，切换到下一个就绪进程。
///
/// 与 [`tick`] 的被动时间片切换不同，这是进程主动请求让出：保存当前帧并把
/// 进程放回就绪队列尾，取下一个就绪进程切换。若就绪队列里只有当前进程
/// （无可让出），则恢复 Running 继续运行——`yield` 对调用进程等价于空操作。
/// 返回 `true` 表示已切换（frame 已被改写为下一进程帧）；`false` 表示未切换。
///
/// `yield` 的返回值 `0` 写回当前进程帧再保存，故进程下次恢复时 `rax=0`，
/// 用户态 `yield()` 正确返回 0。
pub fn yield_now(frame: &mut InterruptFrame) -> bool {
    let mut s = SCHED.lock();
    let Some(cur_pid) = s.current else {
        return false; // 内核 idle/主线程不参与让出
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
        return false; // 无可调度进程（不应发生）
    };

    if cur_pid == next_pid {
        // 仅当前进程自身：无可让出，恢复 Running 继续。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return false;
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
    true
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

pub fn block_current(frame: &mut InterruptFrame) -> bool {
    let mut s = SCHED.lock();
    let Some(cur_pid) = s.current else {
        return false; // 内核 idle/主线程不参与阻塞
    };
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Blocked);
    }
    // 取下一个有效就绪进程（跳过已退出残留引用）。
    let Some(next_pid) = pop_ready(&mut s) else {
        return false; // 无可调度进程：调用方不应阻塞
    };
    if cur_pid == next_pid {
        // 仅当前进程自身：不阻塞（保持 Running 继续）。
        if let Some(slot) = s.procs[next_pid].as_mut() {
            slot.proc.set_state(TaskState::Running);
        }
        return false;
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
    true
}

/// 阻塞等待键盘输入的进程 pid（`u32::MAX` 表示无）。`sys_read` 缓冲空时登记，
/// 键盘中断经回调 [`wake_kbd`] 唤醒。单 waiter（stdin 仅一个读者，即 shell）。
static KBD_WAITER: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// 阻塞当前进程等待键盘输入（`read` syscall 缓冲空时调用）。
///
/// 登记 [`KBD_WAITER`] 后把当前进程置 `Blocked`（不回就绪队列），切到下一个就绪
/// 进程；若**无其他就绪进程**（单 shell 场景），进入 idle halt 等待键盘中断唤醒——
/// 键盘 handler 经 [`wake_kbd`] 把本进程放回就绪队列，idle 循环检测到后切回。
/// 被唤醒后用户态 `read` 重试即可取到字符（消除空转 + 刷屏）。
///
/// 切换成功后改写 `*frame` 并 `return false`：控制流回到 `syscall_entry`，由其
/// `iretq` 进入目标进程用户态（与 `block_current` 相同机制）。函数虽声明返回
/// 值，但切换发生后 CPU 不再回到此处，故返回值不会被真正消费。
pub fn block_for_kbd(frame: &mut InterruptFrame) -> bool {
    let mut s = SCHED.lock();
    let cur_pid = s.current.expect("block_for_kbd outside process");
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.saved = *frame;
        slot.proc.set_state(TaskState::Blocked);
    }
    s.current = None;
    clear_current_proc();
    KBD_WAITER.store(cur_pid as u32, core::sync::atomic::Ordering::Release);

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
            return false; // frame 已改，由 syscall_entry iret 切换
        }
        None => {
            drop(s);
            // 无就绪进程：idle halt 等键盘中断唤醒（先释放锁再 halt，使中断可达）。
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
            return false; // frame 已改，由 syscall_entry iret 切换
        }
    }
}

/// 键盘有输入时唤醒阻塞的进程（由 arch 键盘 handler 经回调调用）。
///
/// 取出 [`KBD_WAITER`] 登记的 pid，将其置 `Ready` 并入就绪队列。调度器下次调度
/// （tick ≤10ms 或 idle 循环立即）切回该进程，使其 `read` 重试取到字符。
/// 在中断上下文调用，持锁时间极短（仅入队）。
pub fn wake_kbd() {
    let p = KBD_WAITER.swap(u32::MAX, core::sync::atomic::Ordering::AcqRel);
    if p == u32::MAX {
        return;
    }
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs[p as usize].as_mut() {
        slot.proc.set_state(TaskState::Ready);
        s.ready.push_back(p as usize);
    }
}

/// 终止当前进程（`exit` syscall）：回收其槽位并切换到下一个就绪进程。
///
/// 当前进程置 `Exit` 并从就绪队列/进程池移除（其 `UserAddressSpace` 随
/// `ProcEntry` drop 自动回收物理资源）。若还有就绪进程，改写 `frame` 为队首
/// 进程的保存帧，返回后由 `syscall_entry` 的 iretq 进入目标进程用户态（与
/// `tick`/`yield` 相同机制）；否则停机（系统空转）。注意调用后当前进程不再
/// 被调度，但函数**正常返回**（不 `!`），由中断返回路径完成切换。
pub fn exit_current(frame: &mut InterruptFrame) {
    let mut s = SCHED.lock();
    let cur_pid = s.current.expect("exit called outside process");
    // 回收当前进程槽位。
    if let Some(slot) = s.procs[cur_pid].as_mut() {
        slot.proc.set_state(TaskState::Exit);
    }
    s.procs[cur_pid] = None;
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

/// 向进程 `target` 发送信号 `sig`（当前仅 `SIGKILL=9`/`SIGTERM=15` 终止目标；
/// `sig=0` 仅校验进程存在，不实际发送）。
///
/// - 目标为当前进程：走标准 `exit_current` 退出路径（永不返回）。
/// - 目标为其它进程（单核、非当前，可安全释放其页表/帧）：从就绪队列移除并回收槽位
///   （`ProcEntry` Drop 自动回收 `UserAddressSpace` 物理资源）；若其为键盘 waiter，
///   一并清除 `KBD_WAITER` 避免悬挂唤醒。
pub fn kill_pid(target: usize, sig: u32, frame: &mut InterruptFrame) -> Result<u64, Error> {
    if sig != 0 && sig != 9 && sig != 15 {
        return Err(Error::NotSupported);
    }
    let current = {
        let s = SCHED.lock();
        s.current
    };
    if current == Some(target) {
        // 自杀：走标准退出路径（释放自身并切换）。exit_current 内部自行加锁，
        // 故此处不持锁调用。
        exit_current(frame);
        // 不返回
    }
    // 校验目标存在且非退出。
    let mut s = SCHED.lock();
    let exists = matches!(s.procs.get(target), Some(Some(e)) if e.proc.state() != TaskState::Exit);
    if !exists {
        return Err(Error::InvalidParam);
    }
    // 若是键盘 waiter，清空避免悬挂唤醒。
    if KBD_WAITER.load(core::sync::atomic::Ordering::Acquire) == target as u32 {
        KBD_WAITER.store(u32::MAX, core::sync::atomic::Ordering::Release);
    }
    s.ready.retain(|&p| p != target);
    s.procs[target] = None; // Drop：回收 UserAddressSpace 等物理资源
    Ok(0)
}

/// 唤醒一个阻塞的进程（IPC 写/读端完成时调用）：置 `Ready` 并入就绪队列。
///
/// 仅当目标进程处于 `Blocked` 时才生效（已就绪/运行中进程忽略，避免重复入队）。
pub fn wake(pid: usize) {
    let mut s = SCHED.lock();
    if let Some(slot) = s.procs.get_mut(pid).and_then(|p| p.as_mut()) {
        if slot.proc.state() == TaskState::Blocked {
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
