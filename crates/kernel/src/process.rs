//! 进程控制块（PCB）与进程表（M3.1）。
//!
//! M3 引入"进程模型"。本模块提供：
//! - `TaskState`：进程状态（就绪/运行/阻塞/退出）。
//! - `Process<PT>`：进程控制块——pid、状态、上下文、独立用户地址空间、内核栈、
//!   用户态入口与用户栈顶。
//! - `ProcessTable<PT>`：进程表——pid 分配/回收 + 进程存储。
//!
//! 架构抽象（ADR-007）：`PT: PageTable` 泛型使进程逻辑不绑定具体架构。
//! 进程持有 `UserAddressSpace<PT>`（M1 的独立地址空间），内核栈由调用方提供
//! （M3 单核简单模型下可共用全局内核栈，M4 调度时再独立分配）。

use alloc::vec::Vec;

use arch::task::TaskContext;
use arch::PageTable;
use mm::user_space::UserAddressSpace;

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
}

impl<PT: PageTable> Process<PT> {
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
    /// 只读访问用户地址空间。
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
    /// 注：cs/ss 用当前平台（x86_64）的 Ring3 段选择子并带 RPL=3。
    /// 多平台化时应改为 `arch` 抽象层提供的用户段常量或注入函数（ADR-007）。
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
            cs: (arch_x86_64::gdt::UCODE | 3) as u64,
            // RFLAGS: IF=1（开中断）、IOPL=0（禁 I/O）、保留位 1 恒为 1
            rflags: 0x0000_0000_0000_0202,
            rsp: self.user_stack_top,
            ss: (arch_x86_64::gdt::UDATA | 3) as u64,
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
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            free: Vec::new(),
            next_pid: 1,
        }
    }

    /// 分配一个 pid（优先复用回收槽，否则递增）。
    fn alloc_pid(&mut self) -> usize {
        if let Some(pid) = self.free.pop() {
            pid
        } else {
            let pid = self.next_pid;
            self.next_pid += 1;
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
        let proc = Process {
            pid,
            state: TaskState::Ready,
            context: TaskContext::empty(),
            addr_space,
            kernel_stack_top,
            entry_rip,
            user_stack_top,
        };
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

    /// 启动（运行）指定 pid 的进程：进入用户态执行。
    ///
    /// 永不返回（进入用户态后由用户代码/中断决定控制流）。
    /// 若 pid 不存在则 panic。
    pub fn run(&mut self, pid: usize) -> !
    where
        PT::Error: From<klib::error::Error>,
    {
        let proc = self
            .get_mut(pid)
            .expect("process to run does not exist");
        proc.launch();
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
    /// 注：M3.1 仅回收 pid 槽位；进程地址空间等资源的物理页回收
    /// 留待 M3.3 / M5（进程退出完整实现）处理。
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
