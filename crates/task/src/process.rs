#![allow(dead_code)]

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
//!
//! 生产化（boot→init）后本模块无条件编译；`ProcessTable`（泛型表）当前主要
//! 供测试使用，调度器自建 `ProcEntry` 池不依赖它——部分成员在生产侧无调用方，
//! 用文件级 `allow(dead_code)` 与 scheduler/elf/signals 保持一致（避免警告）。

// Box 仅 `run`（M3.3/M4.1 单进程停机模型）使用。
#[cfg(any(feature = "kernel-test-m33", feature = "kernel-test-m41"))]
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use arch::PageTable;
use arch::task::TaskContext;
use arch_x86_64::paging::X86PageTable;
use mm::user_space::UserAddressSpace;

// M4.1：当前运行进程的裸指针（syscall 经它访问进程地址空间/退出）。
// 采用"进程被 `run` 从表取出并 `Box::leak` 为 `'static`，再记录地址"模型：
// - 运行期间不持有 `PROCESS_TABLE` 锁（避免 syscall 中断重入表锁死锁）；
// - 进程生命周期 = 内核生命周期（单进程停机模型下泄漏无害，M4.2 调度器再改为正式持有/回收）。
static CURRENT_PROC: AtomicUsize = AtomicUsize::new(0);

/// 进程缺页处理入口：转发给当前运行进程的 UserAddressSpace::handle_page_fault。
pub extern "C" fn process_page_fault_handler(vaddr: u64, error_code: u64) -> bool {
    let p = CURRENT_PROC.load(Ordering::Acquire);
    if p == 0 {
        return false;
    }
    let proc = unsafe { &mut *(p as *mut Process<X86PageTable>) };
    proc.addr_space_mut().handle_page_fault(vaddr, error_code)
}

/// 记录当前运行进程（`run` 进入用户态前设置）。
pub fn set_current_proc(p: *mut Process<X86PageTable>) {
    CURRENT_PROC.store(p as usize, Ordering::Release);
}

/// 清除当前进程记录（进程退出时）。
pub fn clear_current_proc() {
    CURRENT_PROC.store(0, Ordering::Release);
}

/// 当前运行进程的可变引用（syscall 在中断上下文访问，单进程无并发）。
///
/// 进程对象由 `Box::leak` 保证 `'static` 存活，返回 `&'static mut` 安全。
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
        Process {
            pid,
            state: TaskState::Ready,
            context: TaskContext::empty(),
            addr_space,
            kernel_stack_top,
            entry_rip,
            user_stack_top,
            fd_table: Vec::new(),
        }
    }

    /// 分配新的文件描述符（返回分配的 fd 编号）。
    pub fn alloc_fd(&mut self, handle: vfs::file_handle::FileHandle) -> usize {
        for (fd, slot) in self.fd_table.iter_mut().enumerate() {
            // 跳过 0, 1, 2（保留给标准 IO）
            if fd >= 3 && slot.is_none() {
                *slot = Some(handle);
                return fd;
            }
        }
        while self.fd_table.len() < 3 {
            self.fd_table.push(None);
        }
        let fd = self.fd_table.len();
        self.fd_table.push(Some(handle));
        fd
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
    /// 注：cs/ss 用当前平台（x86_64）的 Ring3 段选择子并带 RPL=3。
    /// 多平台化时应改为 `arch` 抽象层提供的用户段常量或注入函数（ADR-007）。
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
    pub const fn new() -> Self {
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
