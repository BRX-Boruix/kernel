//! 进程控制块（PCB）与进程表（M3.1）。
//!
//! 本模块提供：
//! - `TaskState`：进程状态（就绪/运行/阻塞/退出）——含展示名与数值编码的
//!   **单点映射**（[`TaskState::label`] / [`TaskState::as_u8`]，task1 KM3）；
//! - `ThreadGroup<PT>`：**线程组共享容器**（T1-1 / ADR-035 D1/D2）——组内所有
//!   成员（组长 + 组员线程）经共享 `Arc` 持同一 fd_table/cwd/identity/addr_space；
//!   fd_table/cwd/identity 已加组内粗锁（S21 缺口闭合，见该类型文档，T1-8）；
//! - `Process<PT>`：进程控制块——pid/tgid/状态/上下文/每线程内核栈、用户态入口
//!   与用户栈顶、每进程 signal，以及指向其 `ThreadGroup` 的 `Arc`（共享态落在组）；
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

use alloc::sync::Arc;
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

// M4.1/M4.2：当前运行进程的裸指针（syscall/缺页经它访问进程地址空间），
// per-CPU（按紧凑 CPU 槽位索引，与调度器 `current[cpu_slot]` 同槽同步更新）。
// 采用“进程被调度器从表取出并 `Box::leak` 为 `'static`，再记录地址”模型：
// - 运行期间不持有 `PROCESS_TABLE` 锁（避免 syscall 中断重入表锁死锁）；
// - 进程生命周期 = 内核生命周期（阶段2 后由调度器正式持有/回收）。
// 别名安全不靠生命周期表达，而靠下节纪律维持（task1 KA3）：核心 A 的 syscall/
// 缺页只读/写核心 A 自己的槽位；`set_current_proc`/`clear_current_proc` 由调度器
// 在“执行核心”上调用（cpu_switch_locked 用本核槽位），故恒落在调用核自己的槽，
// 与调度器 `Scheduler::current[slot]` 保持单点对应。
/// 每核紧凑 CPU 槽位容量上限（与调度器 `MAX_SCHED_CPUS` 同源：LAPIC id 全空间）。
const MAX_CPUS: usize = 256;

/// 当前执行核的紧凑槽位。LAPIC 未映射（SMP/调度初始化之前）恒回退 0 = BSP 槽——
/// 此时全系统只在 BSP 上运行进程，语义与既有单核完全一致。镜像 scheduler.rs 的
/// `my_cpu_slot()`（读本核 LAPIC id → 槽位反查表 → 掩码到数组容量）。
fn my_cpu_slot() -> usize {
    if !arch_x86_64::lapic::is_mapped() {
        return 0;
    }
    arch_x86_64::smp::slot_of_lapic(arch_x86_64::lapic::current_lapic_id()) & (MAX_CPUS - 1)
}

static CURRENT_PROC: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// 进程缺页处理入口：转发给当前运行进程的 UserAddressSpace::handle_page_fault。
///
/// extern "C" ABI 边界（arch 中断链交付裸错误码）；位解读在边界处一次完成——
/// 包装为 x86_64 的语义视图类型后再进入 mm 策略层（MM6：mm 不手解位编码）。
pub extern "C" fn process_page_fault_handler(vaddr: u64, error_code: u64) -> bool {
    let p = CURRENT_PROC[my_cpu_slot()].load(Ordering::Acquire);
    if p == 0 {
        return false;
    }
    let proc = unsafe { &mut *(p as *mut Process<X86PageTable>) };
    let code = arch_x86_64::paging::PageFaultCode::new(error_code);
    proc.addr_space().handle_page_fault(vaddr, code)
}

/// 记录当前运行进程（调度器 `cpu_switch_locked` 切入前设置；写本核槽位）。
pub fn set_current_proc(p: *mut Process<X86PageTable>) {
    CURRENT_PROC[my_cpu_slot()].store(p as usize, Ordering::Release);
}

/// 清除当前进程记录（进程退出/阻塞切走时；写本核槽位）。
pub fn clear_current_proc() {
    CURRENT_PROC[my_cpu_slot()].store(0, Ordering::Release);
}

/// 当前运行进程的可变引用（syscall 在中断上下文访问；读本核槽位）。
///
/// 签名保留 `&'static mut`：进程对象确为 `'static` 存活（Box::leak 模型或
/// 调度器槽内稳定地址），该签名描述的是**生命周期事实**；别名安全性不靠
/// 生命周期表达，而靠上节纪律维持（task1 KA3）。
pub fn current_proc_mut() -> Option<&'static mut Process<X86PageTable>> {
    let p = CURRENT_PROC[my_cpu_slot()].load(Ordering::Acquire);
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

/// 进程能力位（A1-2 / ADR-040 §2.3）。
///
/// 取代 ADR-033 的 `Privilege { User, System }` 两档布尔：粗粒度 **5 个**，
/// **无预留位**——新增能力必须走 ADR-000 通道（决策级实质变更），防止
/// "随手加一个位" 的 ioctl 式膨胀（ADR-008 精神）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps(u8);

impl Caps {
    pub const EMPTY: Caps = Caps(0);

    /// 系统管理权：吸收 ADR-033 `Privilege::System` 与 `system_only` 门槛、
    /// power/reboot 等系统管理操作、INIT 派生授权。
    pub const SYSTEM: Caps = Caps(1 << 0);
    /// 直接访问/认领设备（driver_register/driver_claim、AUDIO_ATTACH、irq_wait）。
    pub const DEVICE: Caps = Caps(1 << 1);
    /// 映射设备内存/物理地址（DMA 缓冲分配与物理地址披露）。
    pub const MEMORY: Caps = Caps(1 << 2);
    /// 终止任意进程（跨特权级信号投递）。
    pub const KILL: Caps = Caps(1 << 3);
    /// 绕过文件访问策略（DAC_OVERRIDE 对应物；A1-3 强制矩阵启用）。
    pub const OWNER: Caps = Caps(1 << 4);

    pub const fn bits(self) -> u8 { self.0 }

    pub const fn contains(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Caps) -> Caps {
        Caps(self.0 | other.0)
    }
}

/// 进程身份（A1-2 / ADR-040 §2.4；承 ADR-033）。
///
/// 权限强制与 flock owner 识别（R6）的事实来源。`Copy`：身份在 PCB
/// 生命周期内不变（exec 派生时由 `compute_child_identity` 单点决策）。
///
/// **不引入 euid/suid/fsuid**（ADR-040 §2.4）：ADR-033 的单一 `uid` 是干净的；
/// Linux 的四个 uid 是历史伤疤。uid 分配保持 ADR-033 现状
/// （0=默认/保留、1=init），不改 POSIX 的 root=0。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// 用户 id。0 = 保留（未设身份/普通用户默认），1 = init。
    /// 也是 R6 flock owner token 的来源（同一 uid 的进程共享锁语义）。
    pub uid: u32,
    /// 主组 id。0 = 默认组（与 uid=0 同为"未设身份"的保留值）。
    pub gid: u32,
    /// 补充组（有上限，避免无界；ADR-040 §2.4）。当前无生产消费方
    /// （组账户管理属第二阶段 A2-4），字段先行、语义成文于 ADR-040 §2.1
    /// `NamedGid`——**诚实边界**：本字段第一阶段恒空集，不参与求值。
    pub groups: Groups,
    /// 能力位集合（ADR-040 §2.3 的 5 个粗粒度能力）。
    pub caps: Caps,
}

/// 补充组集合（小容量定长，S04/S18 无界防护）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Groups {
    n: u8,
    ids: [u32; Groups::MAX],
}

impl Groups {
    /// 上限 8：与 Linux NGROUPS_SMALL=64000 相比是玩具内核的诚实量级；
    /// 超限拒绝而非静默截断（S09）。
    pub const MAX: usize = 8;

    pub const fn empty() -> Self { Self { n: 0, ids: [0; Groups::MAX] } }

    /// 追加组 id；已满返回 `None`（调用方决定如何如实报错），重复值幂等返回 `Some`。
    pub fn push(&mut self, gid: u32) -> Option<()> {
        if self.ids[..self.n as usize].contains(&gid) {
            return Some(());
        }
        if (self.n as usize) >= Groups::MAX {
            return None;
        }
        self.ids[self.n as usize] = gid;
        self.n += 1;
        Some(())
    }

    pub fn contains(&self, gid: u32) -> bool {
        self.ids[..self.n as usize].contains(&gid)
    }

    pub fn len(&self) -> usize { self.n as usize }

    pub fn is_empty(&self) -> bool { self.n == 0 }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.ids[..self.n as usize].iter().copied()
    }
}

impl ProcessIdentity {
    /// 默认普通用户身份（`Process::new` 初始值）：uid/gid 0，无能力。
    pub const fn default_user() -> Self {
        Self {
            uid: 0,
            gid: 0,
            groups: Groups::empty(),
            caps: Caps::EMPTY,
        }
    }

    /// 普通用户身份（无任何能力位）——A2-0 跨用户 kill 校验与 A2-1 身份变更的
    /// 基准构造点。**不得**用 `system(uid)` 表达普通用户：那会连带授予
    /// CAP_SYSTEM/KILL/OWNER，静默绕过全部强制面（S13 反例）。
    pub const fn user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            groups: Groups::empty(),
            caps: Caps::EMPTY,
        }
    }

    /// init/特权身份（内核引导第一个进程时使用）：全能力。
    pub const fn system(uid: u32) -> Self {
        Self {
            uid,
            gid: 0,
            groups: Groups::empty(),
            caps: Caps::SYSTEM.union(Caps::DEVICE).union(Caps::MEMORY).union(Caps::KILL).union(Caps::OWNER),
        }
    }
}

/// 线程组共享容器（T1-1 / ADR-035 D1/D2 / threads.md T1-1）。
///
/// 线程派生把"进程间可共享态"从 PCB 提入本**组级容器**：组内所有成员（组长 +
/// 组员线程）各自持一份 `Arc<ThreadGroup>` 指向同一容器，经 `Arc` 共享
/// `fd_table` / `cwd` / `identity` / `addr_space`。组长 = 该地址空间首个创建的
/// 进程（现有 `spawn*` 即组长，spawn 时构造一个组并自身持有其 `Arc`）；组员
/// 线程派生时 `Arc::clone` 组长的组容器，不重建。每进程的
/// `pid`/`state`/`context`/`kernel_stack_top`/`entry_rip`/`user_stack_top`/`signal`
/// 仍留在 [`Process`]（线程 = 独立调度单元，各有自己的栈/帧/FPU/状态）。
///
/// # S21 并发锁闭合（T1-8 / threads.md T1-8 范围 A）
///
/// 真并发多线程落地前，本容器内 `fd_table`/`cwd`/`identity` 已从无锁普通字段升级为
/// **内部粗锁**（参照 T1-4 [`mm::user_space::UserAddressSpace`] 的 Arc+内部粗锁模式）：
/// 不同核同时运行组内两个线程（各自持**不同** pid 的 per-pid 锁、共享本容器）时，
/// 对 `fd_table`/`cwd`/`identity` 的并发访问由此内部锁串行化。由此闭合 T1-1 声明的
/// S21 缺口（旧 `Process::group_mut` 的 `Arc::get_mut().expect` 独占可变已删除——
/// 所有可变访问改为锁内读写，多成员组共享后不再受独占限制）。
///
/// **锁粒度与锁序纪律**：
/// - `fd_table`/`cwd`/`identity` 是组内**最内层短锁**，只在"读写槽位/字段"临界区持有，
///   **绝不在持其期间调用 vfs 阻塞操作或取其它会阻塞的锁**——需要做 vfs 工作的值
///   （`OpenHandle` clone / `String` clone / `ProcessIdentity` copy）一律先 clone 出
///   临界区到无锁现场用（[`Process::get_fd`]/[`Process::cwd`] 改为值语义返回即为此）。
/// - 与 per-pid 锁的锁序为 per-pid → 组内锁，不反向：持 per-pid 锁的代码（spawn
///   装配 / terminate）取组内锁为合法内层；持组内锁**绝不**反向取 per-pid 锁。
/// - 中断安全：这些访问只发生在 syscall / 调度装配上下文，临界区不关中断亦不会被
///   同核中断重入（组内锁**不在**任何中断处理器路径内取用），故取纯自旋
///   `klib::sync::spin::SpinMutex` 即可（语义同 T1-4 user_space，属 klib 在架原语，
///   不引外部 crate 依赖）。
///
/// `addr_space` 已是 `Arc`（内部粗锁，T1-4），不在此重复包装。
pub(crate) struct ThreadGroup<PT: PageTable> {
    /// 组共享文件描述符表（S21 闭合：内部短锁保护，见类型文档）。
    fd_table: klib::sync::spin::SpinMutex<alloc::vec::Vec<Option<vfs::file_handle::OpenHandle>>>,
    /// 组共享当前工作目录（S21 闭合：内部短锁保护，见类型文档）。
    cwd: klib::sync::spin::SpinMutex<alloc::string::String>,
    /// 组共享进程身份（S21 闭合：内部短锁保护——`ProcessIdentity` 虽 `Copy`，但组长
    /// exec 换身份与组员并发读若为普通字段即成数据竞争，故亦加锁，见类型文档裁定）。
    identity: klib::sync::spin::SpinMutex<ProcessIdentity>,
    /// 组共享用户地址空间（`Arc` 共享 + 内部粗锁，T1-4；不重复包装）。
    addr_space: Arc<UserAddressSpace<PT>>,
}

impl<PT: PageTable> ThreadGroup<PT> {
    /// 构造一个独立组（组长独占）：默认标准流 fd 表 + `/` cwd + 默认身份 +
    /// 传入的地址空间 `Arc`。组长进程在其 PCB 构造时经此自建并持有本组。
    fn new(addr_space: Arc<UserAddressSpace<PT>>) -> Self {
        Self {
            fd_table: klib::sync::spin::SpinMutex::new(default_stdio_table()),
            cwd: klib::sync::spin::SpinMutex::new(alloc::string::String::from("/")),
            identity: klib::sync::spin::SpinMutex::new(ProcessIdentity::default_user()),
            addr_space,
        }
    }
}

/// 进程表与 PCB 初始化的默认标准流表（0=stdin 键盘源、1=stdout、2=stderr）。
/// 独立组（组长 spawn）与测试直构 [`Process`] 共用此单点，避免跨处复制。
fn default_stdio_table() -> Vec<Option<vfs::file_handle::OpenHandle>> {
    alloc::vec![
        Some(vfs::file_handle::OpenHandle::File(vfs::stdio::stdin_handle())),
        Some(vfs::file_handle::OpenHandle::File(vfs::stdio::stdout_handle())),
        Some(vfs::file_handle::OpenHandle::File(vfs::stdio::stderr_handle())),
    ]
}

/// 进程控制块（PCB）。
pub struct Process<PT: PageTable> {
    /// 进程标识（线程与组长一样有独立 pid；pid 即调度身份，进程表无额外每线程字段）。
    pid: usize,
    /// 当前状态。
    state: TaskState,
    /// 上下文切换所需的 CPU 状态（M4 调度用；首次运行经 `iretq` 进用户态）。
    context: TaskContext,
    /// 内核栈顶（用户态中断/系统调用切回内核时的栈；单核可共用全局栈）。
    kernel_stack_top: u64,
    /// 用户态入口 RIP（首次 `iretq` 的目标）。
    entry_rip: u64,
    /// 用户栈顶 RSP。
    user_stack_top: u64,
    /// 线程组归属（T1-1 / threads.md）：组长 pid。组长进程自身 tgid == 本 pid；
    /// 组员线程 tgid == 组长 pid（即共享的同一 [`ThreadGroup`] 的创建者）。独立
    /// pid 是调度身份，tgid 是把调度单元归到某个组/地址空间的身份；两进程同组
    /// ⟺ tgid 相等（组与组长 pid 一一对应）。T1-2 组表示查询据此。
    tgid: usize,
    /// 组共享容器句柄（T1-1 / ADR-035 D1/D2）：组内所有进程（组长 + 组员线程）
    /// 各持一份 clone 指向同一 [`ThreadGroup`]，经它访问共享的 fd_table/cwd/
    /// identity/addr_space。组长 spawn 时自建组并持有；组员线程派生时 clone。
    group: Arc<ThreadGroup<PT>>,
    /// 每进程信号状态（ADR-034 §2.2）：处置/屏蔽/未决/重入守卫/restorer。
    ///
    /// PRE-5（T1-1 阶段）：**信号保持每进程独立**，不随组共享——逐线程信号全套
    /// 留 libpthread；致命信号整组终止是 T1-3 的事。本阶段不动 signal 语义。
    signal: crate::signal::SignalState,
}

impl<PT: PageTable> Process<PT> {
    /// 构造一个**组长**（独立组）进程（M4.2 调度器直接使用）。
    ///
    /// 组长语义（T1-1 / ADR-035 D1/D2）：本构造把传入的地址空间 `Arc` 包成一份
    /// **全新独立组**（[`ThreadGroup`]：默认标准流 fd 表 + `/` cwd + 默认身份 +
    /// 该地址空间）并自持其 `Arc`；tgid = 本 pid。这是每个新地址空间首建进程
    /// 的标准入口（ProcessTable::spawn / Scheduler::spawn* / spawn_elf_image 路径），
    /// 与既有"一进程一地址空间"语义完全等价——只是共享态现在落在组容器而非 PCB。
    ///
    /// `kernel_stack_top` 为该进程**独立内核栈**顶（TSS.RSP0 切换用；
    /// 用户态中断/软中断进入内核时切到此栈）。
    ///
    /// 线程派生**不走本入口**（那是新地址空间 + load ELF）；组员线程复用组长组容器
    /// 应走 [`Self::with_group`]（见 scheduler::spawn_thread_with）。
    pub fn new(
        pid: usize,
        entry_rip: u64,
        user_stack_top: u64,
        kernel_stack_top: u64,
        addr_space: Arc<UserAddressSpace<PT>>,
    ) -> Self {
        // 组长自建独立组（KM1 标准流表单点在 ThreadGroup::new 内构造）。
        Self::with_group(pid, pid, entry_rip, user_stack_top, kernel_stack_top,
            Arc::new(ThreadGroup::new(addr_space)),
        )
    }

    /// 以**既有线程组容器**构造一个 PCB（T1-1：线程派生的核心装配）。
    ///
    /// `pid` 为本调度单元（组长/组员线程）的独立 pid；`tgid` 为组长 pid（组长
    /// 传自身 pid，组员线程传组长 pid）。`group` 为组长已持有的 `Arc<ThreadGroup>`，
    /// 此处直接 clone/move 进来，**不重建**组内共享态（fd_table/cwd/identity/addr_space）
    /// ——共享经 Arc 成立。每线程的 `signal` 仍独立新建（PRE-5）。调用方负责配
    /// 好本 PCB 的独立 `kernel_stack_top`/`entry_rip`/`user_stack_top`（线程各自）。
    ///
    /// crate 可见：线程派生只在 task crate 内部（scheduler::spawn_thread_with），且参数
    /// 含 `Arc<ThreadGroup>`（该容器类型本阶段保持 crate 私有），故本构造也不外露。
    pub(crate) fn with_group(
        pid: usize,
        tgid: usize,
        entry_rip: u64,
        user_stack_top: u64,
        kernel_stack_top: u64,
        group: Arc<ThreadGroup<PT>>,
    ) -> Self {
        Process {
            pid,
            state: TaskState::Ready,
            context: TaskContext::empty(),
            kernel_stack_top,
            entry_rip,
            user_stack_top,
            tgid,
            group,
            signal: crate::signal::SignalState::new(),
        }
    }

    /// 组共享态的只读句柄 clone（crate 可见：线程派生/test_hooks 同 crate 用；
    /// 外部经公开 accessor 访问，不把 `ThreadGroup` 具体类型暴露到 crate 边界）。
    pub(crate) fn thread_group_arc(&self) -> Arc<ThreadGroup<PT>> {
        Arc::clone(&self.group)
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
    ///
    /// S21 闭合（T1-8）：方法改 `&self`，在组内 `fd_table` 锁内找空槽/扩表
    /// （短持锁，仅槽位读写，不做 vfs 工作），不再依赖 `group_mut` 独占可变。
    pub fn alloc_fd(
        &self,
        handle: vfs::file_handle::OpenHandle,
    ) -> Result<usize, klib::error::Error> {
        let mut table = self.group.fd_table.lock();
        for (fd, slot) in table.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(fd);
            }
        }
        if table.len() >= Self::MAX_FDS {
            return Err(klib::error::Error::NoSpace);
        }
        let fd = table.len();
        table.push(Some(handle));
        Ok(fd)
    }

    /// 获取指定 fd 句柄的**副本**（值语义返回）。
    ///
    /// S21 闭合（T1-8）：返回槽位 `OpenHandle` 的 clone（`File` 结构性浅拷贝，与
    /// 槽位共享同一 inode+offset 的 `Arc`；`Pipe` 仅复制 id）。锁内短持、clone 出
    /// 临界区即释放 fd 锁，调用方在**无锁现场**对 owned 句柄做 vfs 工作，语义与原
    /// 跨锁借用等价（见实核结论：clone 后对 File 共享 Arc、offset 共享，无 UAF）。
    pub fn get_fd(&self, fd: usize) -> Option<vfs::file_handle::OpenHandle> {
        self.group.fd_table.lock().get(fd)?.clone()
    }

    /// 关闭并移除指定 fd 句柄（返回被移除的 owned 句柄）。
    ///
    /// S21 闭合（T1-8）：方法改 `&self`。先短持 `fd_table` 锁 `take` 出槽位值并释放
    /// 锁，再在无锁现场对已 take 出的 handle 做 `flock_unlock`（取 vfs 锁的动作移出
    /// fd 锁，满足"fd 锁内不做 vfs 阻塞操作"的锁序纪律）。close 只 take 槽位，不影响
    /// 其它线程已 clone 出的句柄（并发语义改善，无 UAF）。
    pub fn close_fd(&self, fd: usize) -> Option<vfs::file_handle::OpenHandle> {
        let handle = {
            let mut table = self.group.fd_table.lock();
            if fd < table.len() {
                table[fd].take()
            } else {
                None
            }
        };
        // flock owner 用组共享身份的 uid（`Copy` 值，先读出自锁现场再用于解锁）。
        let uid = self.group.identity.lock().uid;
        if let Some(vfs::file_handle::OpenHandle::File(fh)) = &handle {
            vfs::flock::flock_unlock(&fh.inode, vfs::flock::LockOwner { uid });
        }
        handle
    }

    /// 把句柄安装到指定 fd 槽位（`dup2` 目标）。原槽位若已有句柄则**被覆盖
    /// 丢弃**——调用方必须先把旧句柄取出并正确处理（pipe 端 `pipe_ref_dec`），
    /// 否则泄漏/错账。槽位超出当前表长则扩展填充到 `fd`（含空槽），受
    /// [`Self::MAX_FDS`] 上限约束。
    ///
    /// 用于 `dup2(old, new)` 的"复制到指定编号"，与 [`Self::alloc_fd`]（找
    /// 最低空闲槽）互补。
    ///
    /// S21 闭合（T1-8）：方法改 `&self`，组内 `fd_table` 锁内短持读写槽位。
    pub fn set_fd(
        &self,
        fd: usize,
        handle: vfs::file_handle::OpenHandle,
    ) -> Result<(), klib::error::Error> {
        if fd >= Self::MAX_FDS {
            return Err(klib::error::Error::NoSpace);
        }
        let mut table = self.group.fd_table.lock();
        if fd >= table.len() {
            table.resize(fd + 1, None);
        }
        table[fd] = Some(handle);
        Ok(())
    }

    /// 克隆整张 fd 表（spawn 时子进程继承父进程句柄）。
    ///
    /// 仅做结构性克隆（`OpenHandle` 的 `Clone`）。**pipe 端引用计数递增不在
    /// 本方法内**——由 kernel syscall 层在克隆后对每个 `Pipe { id }` 调
    /// `ipc::pipe_ref_inc(id)`，保证子进程继承的 pipe 端也持有一个 ref。
    ///
    /// S21 闭合（T1-8）：组内 `fd_table` 锁内整体 clone 出临界区（短持锁，无 vfs）。
    pub fn clone_fd_table(&self) -> alloc::vec::Vec<Option<vfs::file_handle::OpenHandle>> {
        self.group.fd_table.lock().clone()
    }

    /// 以父进程继承的 fd 表替换本进程的默认标准流表（spawn 时注入）。
    ///
    /// 仅当继承表**非空**时替换：默认标准流表（0/1/2）由 [`Self::new`] 已装好，
    /// 空表保留默认（等价于无继承、新进程有独立标准流）。pipe 端引用计数由
    /// 调用方（syscall 层）在替换后对每个 `Pipe { id }` 调 `ipc::pipe_ref_inc`。
    ///
    /// S21 闭合（T1-8）：方法改 `&self`，组内 `fd_table` 锁内整体替换（短持锁）。
    pub fn set_inherited_fd_table(
        &self,
        inherited: alloc::vec::Vec<Option<vfs::file_handle::OpenHandle>>,
    ) {
        if !inherited.is_empty() {
            *self.group.fd_table.lock() = inherited;
        }
    }

    /// 进程 id（本调度单元的独立 pid）。
    pub fn pid(&self) -> usize {
        self.pid
    }
    /// 线程组归属（T1-1）：组长 pid。组长自身 tgid == pid；组员线程 tgid == 组长 pid。
    /// 两进程同组 ⟺ tgid 相等（组与组长 pid 一一对应）。T1-2 组表示查询据此。
    pub fn tgid(&self) -> usize {
        self.tgid
    }
    /// 是否与另一进程共享同一 `ThreadGroup`（T1-1 结构断言：`Arc::ptr_eq` 判
    /// 同一组容器对象，而非仅 tgid 相等——同一组必然共享同一对象）。
    pub fn same_thread_group(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.group, &other.group)
    }
    /// 进程身份（A1 / ADR-033）。
    ///
    /// S21 闭合（T1-8）身份锁裁定：`ProcessIdentity` 是 `Copy` 小结构（uid/privilege），
    /// 但组长 exec 换身份与组员并发读若为普通字段即成数据竞争，故亦改
    /// `spin::Mutex<ProcessIdentity>`，本访问器锁内 `Copy` 返回（短持锁，值语义）。
    pub fn identity(&self) -> ProcessIdentity {
        *self.group.identity.lock()
    }
    /// 设置进程身份（A1 / ADR-033）。S21 闭合（T1-8）：方法改 `&self`，身份锁内写入。
    pub fn set_identity(&self, identity: ProcessIdentity) {
        *self.group.identity.lock() = identity;
    }
    /// 每进程信号状态（ADR-034 §2.2）可变访问（派发/投递/sigaction 用）。
    pub fn signal_mut(&mut self) -> &mut crate::signal::SignalState {
        &mut self.signal
    }
    /// 每进程信号状态只读访问。
    pub fn signal(&self) -> &crate::signal::SignalState {
        &self.signal
    }
    /// 当前工作目录（规范绝对路径），返回 owned `String`。
    ///
    /// S21 闭合（T1-8）：原返回跨锁借用 `&str`；加锁后无法跨锁返回借用，改为组内
    /// `cwd` 锁内 clone 出 owned `String`（短持锁、值语义），调用点据此适配。
    pub fn cwd(&self) -> alloc::string::String {
        self.group.cwd.lock().clone()
    }
    /// 设置当前工作目录（调用方保证为规范绝对路径）。
    ///
    /// S21 闭合（T1-8）：方法改 `&self`，组内 `cwd` 锁内整体替换（短持锁）。
    pub fn set_cwd(&self, cwd: alloc::string::String) {
        *self.group.cwd.lock() = cwd;
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
    /// 访问用户地址空间（T1-1 / ADR-035 D4）。
    ///
    /// 地址空间在**组容器**里以 `Arc` + 内部粗锁共享（T1-4）；不再有
    /// `&mut UserAddressSpace` 的公开形态——所有互操作方法已改 `&self` 内部自锁。
    /// 本访问器经组容器解引用返回 `&UserAddressSpace`，调用方直接调用（内部锁
    /// 保证互斥）。原 `addr_space_mut` 已删除：语义收敛到本方法。组内所有成员
    /// 经各自 `Process` 的同一访问器看到同一个共享地址空间对象。
    pub fn addr_space(&self) -> &UserAddressSpace<PT> {
        &self.group.addr_space
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
        // addr_space 为 Arc 共享（内部锁已保护读一致）；取 CR3 装载值。
        let cr3 = self.addr_space().page_table_paddr();
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
        // ADR-035 D4：进程内部持 Arc；此处把进程专属空间包成唯一 Arc（地基阶段
        // 一进程一份，共享派生留给 T1）。
        let proc = Process::new(
            pid,
            entry_rip,
            user_stack_top,
            kernel_stack_top,
            Arc::new(addr_space),
        );
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
// 1. **单点存在性**：任一时刻至多一个进程是"当前进程"（本核 RUN[my].current
//    槽与本指针由同一段持锁代码原子地共同更新；置 None 与清指针成对出现）。
// 2. **写者收敛**：对该进程的内核态可变访问只发生在两类上下文——
//    a) 当前进程自己的 syscall 处理路径（经 `current_proc_mut()` 即取即用，
//       借用不跨越任何可能改写 CURRENT_PROC 的调度调用）；
//    b) 调度器持 per-pid 锁（含其下 per-CPU RUN[my] 当前槽；无全局进程池锁）的切换/终止决策点。
//    两类上下文在单核上不可能并发（中断上下文 vs 被打断路径互斥于 IF/
//    锁序），故不存在两个活跃 `&mut` 同时解引用的窗口。
// 3. **生命周期**：指针目标要么 Box::leak（停机模型），要么活在 PROCESSES
//    per-pid 槽位中且槽位置 None（terminate/reap/reset）与清 CURRENT_PROC 在同一
//    持锁临界区内完成——悬空窗口不存在于可观察路径。
// 4. **无跨抢占缓存**（ADR-017 后的强化不变式）：禁止把 `current_proc_mut()`
//    返回值存进任何存活超过"当前 syscall 处理"的结构或寄存器级变量。
//    违反此条的代码即违反本纪律，审查按红线处理。
//
// 缺页处理器（`process_page_fault_handler`）同样受 1–3 约束：它在中断
// 上下文即取即用，不缓存引用。
// ---------------------------------------------------------------------------
