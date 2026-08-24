//! 进程控制块（PCB）与进程表（M3.1）。
//!
//! 本模块提供：
//! - `TaskState`：进程状态（就绪/运行/阻塞/退出）——含展示名与数值编码的
//!   **单点映射**（[`TaskState::label`] / [`TaskState::as_u8`]，task1 KM3）；
//! - `Process<PT>`：进程控制块——pid、状态、上下文、独立用户地址空间、内核栈、
//!   用户态入口与用户栈顶、标准流句柄表；
//! - `ProcessTable<PT>`：进程表——pid 分配/回收 + 进程存储。
//!
//! 架构抽象（ADR-007）：`PT: PageTable` 泛型使进程逻辑不绑定具体架构。
//!
//! **与 scheduler 的职责边界（task1 KA1 处置：从自嘲注释升级为成文设计）**：
//! - `Scheduler`（scheduler.rs 的 `ProcEntry` 池）是**唯一生产路径**——
//!   多进程 RR 调度、waitpid/zombie、信号终止全部走它；
//! - `ProcessTable` 是 **PCB 单元级测试夹具 + M3.3/M4.1 单进程停机验收
//!   入口**（SDK `--test-m33/--test-m41` 停机验收流依赖其 `run`/`launch`）。
//!   它刻意不做调度、不持锁、pid 可复用——与 Scheduler 的"pid 单调不复用
//!   （ppid 即槽位索引不变式）"是**两种有意的语义**，不是实现漂移。
//!   合并为单实现的唯一路径是把 SDK 六条里程碑停机验收流迁到调度器，
//!   该迁移立项时本边界随之消解；在此之前，两侧文档互为交叉引用，
//!   禁止在 ProcessTable 上新增生产语义。
//!
//! 用户段选择子/RFLAGS 构造的单点定义见 [`user_code_selector`] 等函数
//! （task1 KM5：原 scheduler/process 两处重复收敛于此）。
//!
//! `CURRENT_PROC` 裸指针别名模型的安全论证见模块尾部
//! "CURRENT_PROC 别名纪律"一节（task1 KA3）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use arch::PageTable;
use arch::task::TaskContext;
use arch_x86_64::paging::X86PageTable;
use mm::user_space::UserAddressSpace;

// Box 仅 `run`（M3.3/M4.1 单进程停机模型）使用。
#[cfg(any(feature = "kernel-test-m33", feature = "kernel-test-m41"))]
use alloc::boxed::Box;

/// 用户态代码段选择子（RPL=3）。
///
/// KM5 单点：scheduler 启动帧与本模块 launch 共用此构造，禁止再写
/// 内联 `UCODE | 3`。位合成依据：x86 段选择子低 2 位为 RPL，置 11B
/// 即请求特权级 3（ADR-007：多平台化时此构造迁入 arch 抽象层）。
pub const fn user_code_selector() -> u16 {
    arch_x86_64::gdt::UCODE | 3
}

/// 用户态数据段选择子（RPL=3）。同 [`user_code_selector`]。
pub const fn user_data_selector() -> u16 {
    arch_x86_64::gdt::UDATA | 3
}

/// 进入用户态的初始 RFLAGS：IF=1（开中断）、IOPL=0（禁 I/O）、保留位 1 恒为 1。
pub const USER_RFLAGS: u64 = 0x0000_0000_0000_0202;

// M4.1：当前运行进程的裸指针（syscall 经它访问进程地址空间/退出）。
// 采用"进程被 `run` 从表取出并 `Box::leak` 为 `'static`，再记录地址"模型：
// - 运行期间不持有 `PROCESS_TABLE` 锁（避免 syscall 中断重入表锁死锁）；
// - 进程生命周期 = 内核生命周期（单进程停机模型下泄漏无害，M4.2 调度器再改为正式持有/回收）。
static CURRENT_PROC: AtomicUsize = AtomicUsize::new(0);

/// 进程缺页处理入口：转发给当前运行进程的 UserAddressSpace::handle_page_fault。
///
/// extern "C" ABI 边界（arch 中断链交付裸错误码）；位解读在边界处一次完成——
/// 包装为 x86_64 的语义视图类型后再进入 mm 策略层（MM6：mm 不手解位编码）。
pub extern "C" fn process_page_fault_handler(vaddr: u64, error_code: u64) -> bool {
    let p = CURRENT_PROC.load(Ordering::Acquire);
    if p == 0 {
        return false;
    }
    let proc = unsafe { &mut *(p as *mut Process<X86PageTable>) };
    let code = arch_x86_64::paging::PageFaultCode::new(error_code);
    proc.addr_space_mut().handle_page_fault(vaddr, code)
}

/// 记录当前运行进程（`run` 进入用户态前设置）。
pub fn set_current_proc(p: *mut Process<X86PageTable>) {
    CURRENT_PROC.store(p as usize, Ordering::Release);
}

/// 清除当前进程记录（进程退出时）。
pub fn clear_current_proc() {
    CURRENT_PROC.store(0, Ordering::Release);
}

/// 当前运行进程的可变引用（syscall 在中断上下文访问）。
///
/// 签名保留 `&'static mut`：进程对象确为 `'static` 存活（Box::leak 模型或
/// 调度器槽内稳定地址），该签名描述的是**生命周期事实**；别名安全性不靠
/// 生命周期表达，而靠下节纪律维持（task1 KA3）。
pub fn current_proc_mut() -> Option<&'static mut Process<X86PageTable>> {
    let p = CURRENT_PROC.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        Some(unsafe { &mut *(p as *mut Process<X86PageTable>) })
    }
}

/// 进程状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// 就绪（可被调度）。
    Ready,
    /// 正在运行。
    Running,
    /// 阻塞（等待某事件）。
    Blocked,
    /// 已退出（等待回收）。
    Exit,
}

impl TaskState {
    /// ps 快照 ABI 的数值编码（单点，task1 KM3）。
    ///
    /// 编码即用户态契约：1=Ready 2=Running 3=Blocked 0=Exit
    /// （`ps_snapshot` 8 字节条目第 5 字节）。禁止调用方自行 match 重排。
    pub const fn as_u8(self) -> u8 {
        match self {
            TaskState::Ready => 1,
            TaskState::Running => 2,
            TaskState::Blocked => 3,
            TaskState::Exit => 0,
        }
    }

    /// ProcFS 展示名（单点，task1 KM3）。
    pub const fn label(self) -> &'static str {
        match self {
            TaskState::Ready => "Ready",
            TaskState::Running => "Running",
            TaskState::Blocked => "Blocked",
            TaskState::Exit => "Exit",
        }
    }
}

/// 进程控制块（PCB）。
pub struct Process<PT: PageTable> {
    /// 进程标识。
    pid: usize,
    /// 当前状态。
    state: TaskState,
    /// 上下文切换所需的 CPU 状态（M4 调度用；首次运行经 `iretq` 进用户态）。
    context: TaskContext,
    /// 独立用户地址空间（含页表、用户区管理）。
    addr_space: UserAddressSpace<PT>,
    /// 内核栈顶（用户态中断/系统调用切回内核时的栈；单核可共用全局栈）。
    kernel_stack_top: u64,
    /// 用户态入口 RIP（首次 `iretq` 的目标）。
    entry_rip: u64,
    /// 用户栈顶 RSP。
    user_stack_top: u64,
    /// 文件描述符表（FD Table，M6.2）。
    fd_table: Vec<Option<vfs::file_handle::FileHandle>>,
}

impl<PT: PageTable> Process<PT> {
    /// 构造一个初始为 `Ready` 的进程（M4.2 调度器直接使用）。
    ///
    /// `kernel_stack_top` 为该进程**独立内核栈**顶（TSS.RSP0 切换用；
    /// 用户态中断/软中断进入内核时切到此栈）。
    pub fn new(
        pid: usize,
        entry_rip: u64,
        user_stack_top: u64,
        kernel_stack_top: u64,
        addr_space: UserAddressSpace<PT>,
    ) -> Self {
        // KM1：三条标准流是**真实的表内句柄**（0=stdin 键盘源、1=stdout、
        // 2=stderr，均由 vfs::stdio 提供）——syscall 层不再有 fd 号特判，
        // "保留 0/1/2"从跨 crate 心照不宣变为结构事实。close 保护仍是
        // syscall 层显式策略：无 dup/redirect 机制前关闭标准流不可恢复。
        let fd_table = alloc::vec![
            Some(vfs::stdio::stdin_handle()),
            Some(vfs::stdio::stdout_handle()),
            Some(vfs::stdio::stderr_handle()),
        ];
        Process {
            pid,
            state: TaskState::Ready,
            context: TaskContext::empty(),
            addr_space,
            kernel_stack_top,
            entry_rip,
            user_stack_top,
            fd_table,
        }
    }

    /// 每进程文件描述符上限（KA7/S33 量化：POSIX NOFILE 传统量级）。
    ///
    /// 无上限的 Vec 增长允许用户循环 open 无限吃内核堆——单进程资源消耗
    /// 必须有显式边界。超限返回 `Error::NoSpace`（ENOSPC，错误表"表满"语义，
    /// 映射决策成文；klib 无 EMFILE，取语义最近项）。
    pub const MAX_FDS: usize = 1024;

    /// 分配新的文件描述符（返回分配的 fd 编号）。
    ///
    /// KM1：0/1/2 槽位由 [`Process::new`] 装入标准流句柄，扫描自然跳过
    /// 占用槽——不再需要 `fd >= 3` 魔法数字条件。
    /// KA7：无空槽且表长已达 [`Self::MAX_FDS`] 时如实上抛
    /// [`Error::NoSpace`]，绝不无界增长；已关闭槽位的复用不受上限挤压。
    pub fn alloc_fd(
        &mut self,
        handle: vfs::file_handle::FileHandle,
    ) -> Result<usize, klib::error::Error> {
        for (fd, slot) in self.fd_table.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(fd);
            }
        }
        if self.fd_table.len() >= Self::MAX_FDS {
            return Err(klib::error::Error::NoSpace);
        }
        let fd = self.fd_table.len();
        self.fd_table.push(Some(handle));
        Ok(fd)
    }

    /// 获取指定 fd 句柄的只读引用。
    pub fn get_fd(&self, fd: usize) -> Option<&vfs::file_handle::FileHandle> {
        self.fd_table.get(fd)?.as_ref()
    }

    /// 关闭并移除指定 fd 句柄。
    pub fn close_fd(&mut self, fd: usize) -> Option<vfs::file_handle::FileHandle> {
        if fd < self.fd_table.len() {
            self.fd_table[fd].take()
        } else {
            None
        }
    }

    /// 进程 id。
    pub fn pid(&self) -> usize {
        self.pid
    }
    /// 当前状态。
    pub fn state(&self) -> TaskState {
        self.state
    }
    /// 设置状态。
    pub fn set_state(&mut self, s: TaskState) {
        self.state = s;
    }
    /// 用户态入口 RIP。
    pub fn entry_rip(&self) -> u64 {
        self.entry_rip
    }
    /// 用户栈顶 RSP。
    pub fn user_stack_top(&self) -> u64 {
        self.user_stack_top
    }
    /// 内核栈顶。
    pub fn kernel_stack_top(&self) -> u64 {
        self.kernel_stack_top
    }
    /// 访问上下文（供 `switch_to` / `init_context` 使用）。
    pub fn context_mut(&mut self) -> &mut TaskContext {
        &mut self.context
    }
    /// 只读访问用户地址空间（快照/统计等只读路径使用）。
    pub fn addr_space(&self) -> &UserAddressSpace<PT> {
        &self.addr_space
    }
    /// 可变访问用户地址空间。
    pub fn addr_space_mut(&mut self) -> &mut UserAddressSpace<PT> {
        &mut self.addr_space
    }

    /// 启动进程：设置状态为 Running，并从内核 `iretq` 进入用户态。
    ///
    /// `enter_usermode` 会先装载本进程页表（`cr3`），再 iretq 进用户态；
    /// 调用方无需预先 `activate()`。永不返回（用户态经中断/异常回到内核；
    /// 进程退出时由内核停机/回收）。
    ///
    /// 注：cs/ss 用 [`user_code_selector`] / [`user_data_selector`] 单点构造
    /// （task1 KM5）。多平台化时应迁入 `arch` 抽象层（ADR-007 半成品，
    /// 迁移点已收敛到 process.rs 顶部三个定义，届时只动一处）。
    ///
    /// **M4.1 单进程停机模型遗留**：M4.2 起由调度器（`scheduler`）接管进程
    /// 运行，本方法仅 M3.3/M4.1 停机验收使用，随对应 feature 编译。
    #[cfg(any(feature = "kernel-test-m33", feature = "kernel-test-m41"))]
    pub fn launch(&mut self) -> !
    where
        PT::Error: From<klib::error::Error>,
    {
        use arch::task::TrapFrame;
        self.state = TaskState::Running;
        // 进程页表物理基址：装载到 CR3，使 iretq 在进程自己的地址空间运行
        let cr3 = self.addr_space.page_table_paddr();
        let frame = TrapFrame {
            rip: self.entry_rip,
            cs: user_code_selector() as u64,
            rflags: USER_RFLAGS,
            rsp: self.user_stack_top,
            ss: user_data_selector() as u64,
            cr3,
        };
        arch::task::enter_usermode(&frame);
    }
}

/// 进程表：pid 分配/回收 + 进程存储。
///
/// pid 分配策略：优先复用 `free` 中的已回收 pid，否则从 `next_pid` 单调递增。
/// 存储用 `Vec<Option<Process>>`，pid 即数组下标（空闲槽为 `None`）。
pub struct ProcessTable<PT: PageTable> {
    /// 进程存储，下标即 pid。
    processes: Vec<Option<Process<PT>>>,
    /// 已回收、可复用的 pid 池。
    free: Vec<usize>,
    /// 下一个递增分配的 pid（从 1 开始，0 保留）。
    next_pid: usize,
}

impl<PT: PageTable> ProcessTable<PT> {
    /// 新建空进程表。
    pub const fn new() -> Self {
        Self {
            processes: Vec::new(),
            free: Vec::new(),
            next_pid: 1,
        }
    }

    /// 分配一个 pid（优先复用回收槽，否则递增）。
    ///
    /// task1 KM6：与 Scheduler::alloc_pid 同款 checked_add 机器强制——
    /// 本表为测试夹具，pid 空间耗尽同样属编程错误而非运行错误。
    fn alloc_pid(&mut self) -> usize {
        if let Some(pid) = self.free.pop() {
            pid
        } else {
            let pid = self.next_pid;
            self.next_pid = self
                .next_pid
                .checked_add(1)
                .expect("pid space exhausted (u64 overflow)");
            pid
        }
    }

    /// 创建（spawn）一个进程：分配 pid 并装配进程。
    ///
    /// `entry_rip` 为用户态入口，`user_stack_top` 为用户栈顶，
    /// `kernel_stack_top` 为内核栈顶（单核简单模型可传全局内核栈），
    /// `addr_space` 为该进程的独立用户地址空间。
    ///
    /// 返回新进程的 pid。
    pub fn spawn(
        &mut self,
        entry_rip: u64,
        user_stack_top: u64,
        kernel_stack_top: u64,
        addr_space: UserAddressSpace<PT>,
    ) -> Result<usize, klib::error::Error> {
        let pid = self.alloc_pid();
        let proc = Process::new(pid, entry_rip, user_stack_top, kernel_stack_top, addr_space);
        // 若 pid 复用空闲槽，直接覆盖；否则追加（可能中间有 None 空洞）。
        if pid < self.processes.len() {
            self.processes[pid] = Some(proc);
        } else {
            // 用 None 填充到 pid，再 push 实际进程
            while self.processes.len() < pid {
                self.processes.push(None);
            }
            self.processes.push(Some(proc));
        }
        Ok(pid)
    }

    /// 只读访问进程。
    pub fn get(&self, pid: usize) -> Option<&Process<PT>> {
        self.processes.get(pid).and_then(|p| p.as_ref())
    }

    /// 可变访问进程。
    pub fn get_mut(&mut self, pid: usize) -> Option<&mut Process<PT>> {
        self.processes.get_mut(pid).and_then(|p| p.as_mut())
    }

    /// 终止进程：回收 pid（槽位置 None，加入 free 池）。
    ///
    /// 丢弃 `Process` 时其 `UserAddressSpace` 字段随之 `Drop` → [`mm::user_space::
    /// UserAddressSpace::destroy`]，自动回收该进程占有的全部物理资源（用户叶帧、
    /// 中间页表页、顶层页表页），实现"进程退出后页表/帧不泄漏"（M5）。
    pub fn terminate(&mut self, pid: usize) -> bool {
        if pid >= self.processes.len() {
            return false;
        }
        if self.processes[pid].is_none() {
            return false;
        }
        self.processes[pid] = None;
        self.free.push(pid);
        true
    }

    /// 当前存活的进程数（不含已回收槽位）。
    pub fn len(&self) -> usize {
        self.processes.iter().filter(|p| p.is_some()).count()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 处于某状态的进程数（诊断用）。
    pub fn count_state(&self, s: TaskState) -> usize {
        self.processes
            .iter()
            .filter(|p| matches!(p.as_ref(), Some(proc) if proc.state() == s))
            .count()
    }
}

impl ProcessTable<X86PageTable> {
    /// 启动（运行）指定 pid 的进程：进入用户态执行。
    ///
    /// 从表取出进程并 `Box::leak` 到全局 [`CURRENT_PROC`]，使 syscall 在中断
    /// 上下文访问进程时**不重入进程表锁**（避免 `run` 持锁进用户态 → syscall
    /// 再锁死锁）。进程生命周期 = 内核生命周期（单进程停机模型泄漏无害；
    /// M4.2 调度器改为正式持有/回收）。永不返回。
    ///
    /// **M4.1 单进程停机模型遗留**：M4.2 起由调度器接管，本方法仅 M3.3/M4.1
    /// 停机验收使用。若 pid 不存在则 panic。
    #[cfg(any(feature = "kernel-test-m33", feature = "kernel-test-m41"))]
    pub fn run(&mut self, pid: usize) -> ! {
        let proc = self.processes[pid]
            .take()
            .expect("process to run does not exist");
        // leak 为 'static：进程存活到内核结束（停机），syscall 经指针访问安全。
        let leaked: &'static mut Process<X86PageTable> = Box::leak(Box::new(proc));
        set_current_proc(leaked as *mut Process<X86PageTable>);
        leaked.launch();
    }
}

// ---------------------------------------------------------------------------
// CURRENT_PROC 别名纪律（task1 KA3：从散落注释收拢为单点成文论证）
//
// `CURRENT_PROC` 是指向当前运行进程的裸地址。绕过 Rust 别名规则的裸构造
// `&mut` 在以下**全部成立**时是健全的：
//
// 1. **单点存在性**：任一时刻至多一个进程是"当前进程"（`s.current` 与
//    本指针由同一段持锁代码原子地共同更新；置 None 与清指针成对出现）。
// 2. **写者收敛**：对该进程的内核态可变访问只发生在两类上下文——
//    a) 当前进程自己的 syscall 处理路径（经 `current_proc_mut()` 即取即用，
//       借用不跨越任何可能改写 CURRENT_PROC 的调度调用）；
//    b) 调度器持 SCHED 锁的切换/终止决策点。
//    两类上下文在单核上不可能并发（中断上下文 vs 被打断路径互斥于 IF/
//    锁序），故不存在两个活跃 `&mut` 同时解引用的窗口。
// 3. **生命周期**：指针目标要么 Box::leak（停机模型），要么活在 SCHED 池
//    槽位中且槽位置 None（terminate/reap/reset）与清 CURRENT_PROC 在同一
//    持锁临界区内完成——悬空窗口不存在于可观察路径。
// 4. **无跨抢占缓存**（ADR-017 后的强化不变式）：禁止把 `current_proc_mut()`
//    返回值存进任何存活超过"当前 syscall 处理"的结构或寄存器级变量。
//    违反此条的代码即违反本纪律，审查按红线处理。
//
// 缺页处理器（`process_page_fault_handler`）同样受 1–3 约束：它在中断
// 上下文即取即用，不缓存引用。
// ---------------------------------------------------------------------------
