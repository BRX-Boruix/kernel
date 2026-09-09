//! 系统调用（syscall）机制——M4.1。
//!
//! 内核侧 syscall ABI（与 `libsys` 约定一致，ADR-003）：
//! - **入口**：用户态 `int 0x80`（DPL=3 陷阱门），经软中断 handler 进入内核；
//! - **参数**：`rax = 系统调用号`，`rdi/rsi/rdx/r10/r8/r9 = a1..a6`
//!   （由 `InterruptFrame` 保存，syscall handler 直接读取）；
//! - **返回**：`rax` 为**全 64 位结果**（可容纳地址/指针/长度）；错误时
//!   `bit63` 置位（等价于 `-errno` 的补码，ADR-003"错误码直接返回"）。
//!   薄封装（`libsys`）解包为 Rust 风格 `Result<T, Error>`；
//! - **syscall 号编码**：`(domain << 8) | op`——资源域（高字节）+ 统一操作
//!   （低字节），号码自描述、扩展不冲突（见 `nr`）。
//!
//! 设计哲学（RESTful 资源观 + Rust 风格错误）：所有资源共享同一套 CRUD
//! 操作码（CREATE/READ/WRITE/CLOSE/CONTROL/QUERY），新资源只需新开域块。

use arch::syscall::SyscallFrame;
use arch::PageFlags;
use arch_x86_64::interrupts::InterruptFrame;
use klib::error::Error;
use mm::user_space::{USER_BASE, USER_TOP, UserAccess};

use task::{
    current_proc_mut, Privilege, ProcessIdentity,
};

// ---------- 用户缓冲区资源边界（kernel1.md K7 / arch1.md AR1） ----------

/// 单次内核↔用户拷贝块的字节上限。
///
/// 选择依据（S17 默认值论证）：用户态一次 `read`/`write` 的合理工作集远小于
/// 该值（stdio 缓冲通常 4KiB~64KiB）；超过上限的传输由分块循环完成，语义是
/// 允许的短读/短写而非失败。该上限把"用户参数直通堆分配"的最坏单次分配钉在
/// 常量上，杜绝传一个巨大 len 即触发内核 OOM panic 或耗尽物理内存的攻击面
/// （kernel1.md K7）。取值对齐常见页级缓存的整数倍，避免块内碎片拷贝。
const SYSCALL_COPY_CHUNK_BYTES: u64 = 1024 * 1024;

/// 路径类 syscall 参数（mkdir/unlink/readdir 等）的用户路径字节上限
/// （vfs1 M15 / ADR-023 §2 命名化）。
///
/// - 为什么存在边界：用户字符串必须有界，否则"路径直通堆分配"是无界
///   DoS 面（与 SYSCALL_COPY_CHUNK_BYTES 同一纪律）；
/// - 为什么是 4096：单页足够容纳本内核全部合法路径；超限**显式
///   InvalidParam 拒绝而非静默截断**——ADR-011 §1.3 反对的是无界魔法数
///   与静默截断，不是"存在显式边界"本身；
/// - 与 PATH_PARAM_MAX 旧名的关系：更名以表达"用户输入上限"语义，
///   内核内部路径不受此约束。
const MAX_USER_PATH_BYTES: usize = 4096;

/// 从可移植 `SyscallFrame` 取回底层架构中断帧（Switched 路径专用）。
///
/// `arch_frame` 由架构层（`arch-x86_64::syscall`）填充为真实
/// `&mut InterruptFrame` 的地址。阻塞/让出 syscall（read 阻塞、waitpid、
/// exit、kill 自杀）需要它来**整体替换**现场为下一进程的保存帧（调度器
/// 语义，见 `task` crate）；此访问是架构耦合的边界，仅切换路径使用，
/// 非切换路径不读 `arch_frame`。
///
/// S21：`arch_frame` 指向的 `InterruptFrame` 由架构层保证有效（当前软中断
/// 现场），且本分发入口是唯一持有者；`task::*` 切换原语在读改写现场时
/// 持有调度器锁。非切换路径不得调用本函数。
fn arch_frame<'a>(frame: &'a mut SyscallFrame) -> &'a mut InterruptFrame {
    unsafe { &mut *(frame.arch_frame as *mut InterruptFrame) }
}

// ---------- syscall 号（域 + 操作二维编码） ----------

// ---------- 4 类资源域与 4 个动词 ----------

pub mod domain {
    pub const STREAM: u32 = 0x10;
    pub const MEMORY: u32 = 0x20;
    pub const TASK: u32 = 0x30;
    pub const VFS: u32 = 0x40;
    pub const DEVICE: u32 = 0x50;
    /// VOLUME 域（ADR-030 §决策6）：卷管理能力（挂/列/更/格/卸）。
    pub const VOLUME: u32 = 0x60;
    /// SYNC 域（ADR-032 ACCEPTED）：跨进程同步字对象（通用 futex 等待/唤醒）。
    pub const SYNC: u32 = 0x70;
    /// SIGNAL 域（ADR-034 PROPOSED）：可编程信号派发（sigaction/sigprocmask/rt_sigreturn）。
    pub const SIGNAL: u32 = 0x80;
    /// POWER 域（ADR-036）：系统电源管理（S5 软关机 / 重启）。
    pub const POWER: u32 = 0x90;
}

pub mod op {
    pub const CREATE: u32 = 0x01;
    pub const READ: u32 = 0x02;
    pub const WRITE: u32 = 0x03;
    pub const DELETE: u32 = 0x04;
    /// VOLUME 域扩展动词：格式化卷。独立于 4 通用动词，不复用 DELETE 的 0x04。
    pub const FORMAT: u32 = 0x05;
    /// VOLUME 域扩展动词：卸载卷。
    pub const UNMOUNT: u32 = 0x06;
    /// DEVICE 域扩展动词（P2-2）：消费下一条硬件拓扑事件（DeviceArrived/Departed）。
    /// 供用户态 `volumed` 订阅内核块设备事件（ADR-030 §决策3 事件通道）。
    pub const EVENT: u32 = 0x07;
}

const fn nr(d: u32, o: u32) -> u32 {
    d | o
}

// ---------- 1. STREAM Domain (0x10) ----------
pub const SYS_STREAM_CREATE: u32 = nr(domain::STREAM, op::CREATE); // 0x11
pub const SYS_STREAM_READ: u32 = nr(domain::STREAM, op::READ); // 0x12
pub const SYS_STREAM_WRITE: u32 = nr(domain::STREAM, op::WRITE); // 0x13
pub const SYS_STREAM_CLOSE: u32 = nr(domain::STREAM, op::DELETE); // 0x14
/// SYS_STREAM_DUP（0x15，dup2）：把 `old_fd` 句柄复制到 `new_fd`（pipe-features
/// 方案 A，fd 重定向）。副本与原句柄共享文件描述/管道端；管道端引用计数由
/// 本路径同步 `ipc::pipe_ref_inc`。
pub const SYS_STREAM_DUP: u32 = nr(domain::STREAM, 0x05); // 0x15
/// STREAM 域扩展动词：flock 文件锁（ADR-014 / ADR-033 A2-1 R6）。
/// a1=fd, a2=cmd（0=LOCK_SH, 1=LOCK_EX, 2=UNLOCK）。
pub const SYS_STREAM_LOCK: u32 = nr(domain::STREAM, 0x06); // 0x16
/// STREAM 域扩展动词：fstat（按 fd 读元数据，ADR-014 第二原语）。
/// a1=fd, a2=out_buf_ptr（收 `vfs::inode::StatInfo` 完整定长结构）。
pub const SYS_STREAM_FSTAT: u32 = nr(domain::STREAM, 0x07); // 0x17

/// STREAM read/write 的顺序 I/O 哨兵值。
///
/// 仅此值表示使用并推进 FD 的当前位置；`0` 与其他所有偏移都表示定位
/// `pread`/`pwrite`，其中 `0` 即文件起始位置。
const STREAM_OFFSET_CURRENT: u64 = u64::MAX;

// ---------- 2. MEMORY Domain (0x20) ----------
pub const SYS_MEMORY_MAP: u32 = nr(domain::MEMORY, op::CREATE); // 0x21

/// SYS_MEMORY_MAP `flags` 位：新建共享内存对象并映射（ADR-014 §4.2，旧
/// SYS_SHM_CREATE 合并路径；`shared_id` 参数置 0 走本路径）。
pub const MEM_MAP_SHARED: u64 = 1 << 0;
pub const SYS_MEMORY_QUERY: u32 = nr(domain::MEMORY, op::READ); // 0x22
pub const SYS_MEMORY_GROW: u32 = nr(domain::MEMORY, op::WRITE); // 0x23
pub const SYS_MEMORY_UNMAP: u32 = nr(domain::MEMORY, op::DELETE); // 0x24

// ---------- 3. TASK Domain (0x30) ----------
pub const SYS_TASK_SPAWN: u32 = nr(domain::TASK, op::CREATE); // 0x31
pub const SYS_TASK_WAIT: u32 = nr(domain::TASK, op::READ); // 0x32
pub const SYS_TASK_SIGNAL: u32 = nr(domain::TASK, op::WRITE); // 0x33
pub const SYS_TASK_EXIT: u32 = nr(domain::TASK, op::DELETE); // 0x34
/// `thread_spawn(entry, user_stack_top) -> tid`：在调用方线程组（组长 = 调用方
/// 自身进程）内派生一个**同组新调度单元**（T1-7 / ADR-035 D1 / PRE-6）。共享组长
/// 地址空间/fd/cwd/identity，装配各自 entry + user_stack。TASK 域扩展动词 0x05；
/// 双侧镜像（S13）：与 libsys `nr.rs::SYS_TASK_THREAD_SPAWN` 同值、注释互指。
pub const SYS_TASK_THREAD_SPAWN: u32 = nr(domain::TASK, 0x05); // 0x35
/// `thread_join(tid) -> code`：等价组长对**具体组员 pid** 的 waitpid 收尸取退出码
/// （T1-3 单目标 join 交付）。TASK 域扩展动词 0x06；双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_TASK_THREAD_JOIN` 同值、注释互指。
pub const SYS_TASK_THREAD_JOIN: u32 = nr(domain::TASK, 0x06); // 0x36
/// `set_fs_base(base) -> 0`：把调用线程的 `IA32_FS_BASE`（x86-64 MSR 0xC0000100）设为 `base`
/// （threads.md T2-1 / ADR-035 D6）。RDMSR/WRMSR 是 CPL0 特权指令，用户态直写会 #GP，故写侧
/// 走本内核 syscall（内核在 CPL0 经 wrmsr）。读侧用户态用 `fs:[0]` 段相对寻址（免 MSR）。
/// 内核已在切换点保存/恢复每线程 FS base（T2-0，4f0b724）：本 syscall 仅写当前运行线程的
/// 活动 FS base；下次切出时内核 rdmsr 自动归档进 `ProcEntry.fs_base`，故无需在此写 slot。
/// 典型用途：线程引导装配其 `Tcb`（errno/TLS 段基址）。参数 `a1`=新 FS base（用户虚拟地址，
/// 通常是本线程 mmap 的 `Tcb`）。返回 0。TASK 域扩展动词 0x07；双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_TASK_SET_FS_BASE` 同值、注释互指。
pub const SYS_TASK_SET_FS_BASE: u32 = nr(domain::TASK, 0x07); // 0x37

/// `gettid() -> tid`：返回调用线程自己的 pid（= 线程 id，threads.md T2-6）。在 BORUIX 中每线程
/// = 一个 ProcEntry/pid；组长 pid == tgid、组员 pid == 其线程 id。POSIX 线程要经 gettid 查本线程 id；
/// 组长/组员都可用。TASK 域扩展动词 0x08；双侧镜像（S13）：与 libsys `nr.rs::SYS_TASK_GETTID` 同值。
pub const SYS_TASK_GETTID: u32 = nr(domain::TASK, 0x08); // 0x38

/// `getpid() -> pid`：返回调用线程所在进程（线程组）的组长 pid（= POSIX 进程 id / tgid）。
/// BORUIX 每进程一个组长（leader）；所有线程共享同一 tgid。替代 libc 读 `/processes/list` 扫
/// Running 进程的脆弱启发（SMP/多线程下会挑错成员）。TASK 域扩展动词 0x09；双侧镜像（S13）：
/// 与 libsys `nr.rs::SYS_TASK_GETPID` 同值。
pub const SYS_TASK_GETPID: u32 = nr(domain::TASK, 0x09); // 0x39
pub const SYS_ENTRY_CREATE: u32 = nr(domain::VFS, op::CREATE); // 0x41
pub const SYS_ENTRY_READ: u32 = nr(domain::VFS, op::READ); // 0x42
pub const SYS_ENTRY_UPDATE: u32 = nr(domain::VFS, op::WRITE); // 0x43
pub const SYS_ENTRY_DELETE: u32 = nr(domain::VFS, op::DELETE); // 0x44

/// `chdir(path)`：切换当前进程工作目录（VFS 域扩展，0x45）。
///
/// VFS 层仍只接受绝对路径（ADR-011 M1 契约不变）；本 syscall 与其余路径
/// syscall 在 syscall 层把相对路径与进程 cwd 拼接成绝对路径。
pub const SYS_ENTRY_CHDIR: u32 = nr(domain::VFS, 0x05); // 0x45
/// `getcwd()`：读当前进程工作目录（VFS 域扩展，0x46）。
pub const SYS_ENTRY_GETCWD: u32 = nr(domain::VFS, 0x06); // 0x46

// ---------- SYS_ENTRY_READ kind 编码（stat 技术报告）----------
/// readdir 模式（默认）：a4=0，输出 JSON 目录项列表。
#[allow(dead_code)] // 默认值 0，与 libsys 同名常量保持对齐（读取目录模式隐式）
pub const ENTRY_READ_READDIR: u64 = 0;
/// stat 模式：a4=1，解析路径后把节点元数据以 `StatInfo` 定长结构写入用户缓冲（a2）。
pub const ENTRY_READ_STAT: u64 = 1;

// ---------- SYS_ENTRY_UPDATE 动作编码（a4 区分 rename/chmod）----------
/// rename（默认）：a4=0，a1=old_path, a2=new_path。
pub const ENTRY_UPDATE_RENAME: u64 = 0;
/// chmod：a4=1，a1=path, a2=mode_bits（`Permissions::to_bits` 编码）。
pub const ENTRY_UPDATE_CHMOD: u64 = 1;

// ---------- SYS_ENTRY_CREATE kind 编码（ADR-014 §4.4，与 INodeType 对齐）----------
/// 创建普通文件（kind=REG/FILE）。
pub const ENTRY_KIND_FILE: u64 = 1;
/// 创建目录（kind=DIR/DIRECTORY）。
pub const ENTRY_KIND_DIRECTORY: u64 = 0;
/// 创建符号链接（kind=LINK/SYMLINK）。
pub const ENTRY_KIND_SYMLINK: u64 = 2;
/// 创建命名管道（kind=FIFO）。
pub const ENTRY_KIND_FIFO: u64 = 3;
/// 创建字符设备节点（kind=CHRDEV）。
pub const ENTRY_KIND_CHARDEV: u64 = 4;
/// 创建块设备节点（kind=BLKDEV）。
pub const ENTRY_KIND_BLOCKDEV: u64 = 5;
/// 创建套接字节点（kind=SOCK）。
pub const ENTRY_KIND_SOCKET: u64 = 6;

// ---------- 5. DEVICE Domain (0x50, UIO Sandboxing) ----------
pub const SYS_DRIVER_REGISTER: u32 = nr(domain::DEVICE, op::CREATE); // 0x51
pub const SYS_DRIVER_QUERY: u32 = nr(domain::DEVICE, op::READ); // 0x52
pub const SYS_DRIVER_CLAIM: u32 = nr(domain::DEVICE, op::WRITE); // 0x53
pub const SYS_DRIVER_UNREGISTER: u32 = nr(domain::DEVICE, op::DELETE); // 0x54
/// 消费下一条硬件拓扑事件（P2-2，DEVICE 域 op::EVENT=0x07 → 0x57）。
pub const SYS_DRIVER_EVENT_NEXT: u32 = nr(domain::DEVICE, op::EVENT); // 0x57
/// 对指定块设备做缓存穿透探测读（DEVICE 域 0x08 → 0x58）：volumed 低频对账
/// 用它兜底发现"拔除但无事件"的空闲卷。返回 `ProbeStatus`（alive=0/gone=1/
/// notfound=2/notio=3）。
pub const SYS_DEVICE_PROBE: u32 = nr(domain::DEVICE, 0x08); // 0x58
/// `driver_irq_wait(uio_id, timeout_ns) -> 1/0`（DEVICE 域 0x09 → 0x59）：阻塞
/// 等待当前进程认领设备的中断触发（有中断待服务）或超时。返回 1 = 该设备
/// 的 IRQ 已触发（驱动应读设备状态寄存器服务）；0 = 超时。用户态驱动借此
/// 中断驱动而非轮询（阶段一：PCI IRQ → 认领它的用户驱动）。
pub const SYS_DRIVER_IRQ_WAIT: u32 = nr(domain::DEVICE, 0x09); // 0x59
/// `driver_dma_alloc(bytes) -> vaddr`（DEVICE 域 0x0A → 0x5A，阶段二）：分配一块
/// 物理连续、以不可缓存(PCD)映射到调用进程的 DMA 一致性缓冲并返回其用户起始
/// 虚拟地址；驱动写满后用 [`SYS_DRIVER_DMA_PHYS`] 取物理地址编程设备、服务完用
/// [`SYS_DRIVER_DMA_FREE`] 释放。仅 System 进程。缓冲随进程退出自动回收。
pub const SYS_DRIVER_DMA_ALLOC: u32 = nr(domain::DEVICE, 0x0A); // 0x5A
/// `driver_dma_phys(vaddr) -> phys`（DEVICE 域 0x0C → 0x5C，阶段二）：返回某块
/// DMA 缓冲（vaddr 为其起始）的基物理地址，供驱动编程设备 DMA 描述符。
pub const SYS_DRIVER_DMA_PHYS: u32 = nr(domain::DEVICE, 0x0C); // 0x5C
/// `driver_dma_free(vaddr) -> ()`（DEVICE 域 0x0B → 0x5B，阶段二）：释放一块 DMA
/// 一致性缓冲（unmap + 归还物理帧）。非 DMA 缓冲区如实 NotFound。
pub const SYS_DRIVER_DMA_FREE: u32 = nr(domain::DEVICE, 0x0B); // 0x5B

// ---------- 6. VOLUME Domain (0x60, ADR-030) ----------
pub const SYS_VOLUME_MOUNT: u32 = nr(domain::VOLUME, op::CREATE); // 0x61
pub const SYS_VOLUME_LIST: u32 = nr(domain::VOLUME, op::READ); // 0x62
pub const SYS_VOLUME_UPDATE: u32 = nr(domain::VOLUME, op::WRITE); // 0x63
pub const SYS_VOLUME_FORMAT: u32 = nr(domain::VOLUME, op::FORMAT); // 0x65
pub const SYS_VOLUME_UNMOUNT: u32 = nr(domain::VOLUME, op::UNMOUNT); // 0x66

// ---------- 7. SYNC Domain (0x70, ADR-032 ACCEPTED) ----------
/// `sync_create(init_value) -> sync_id`：创建内核同步字对象，初值 `init_value`。
pub const SYS_SYNC_CREATE: u32 = nr(domain::SYNC, op::CREATE); // 0x71
/// `sync_wait(sync_id, expected, timeout_ns)`：值 `== expected` 则阻塞；否则立即
/// 返回当前值。唤醒/超时返回唤醒时当前值（ADR-032 §4.2）。
pub const SYS_SYNC_WAIT: u32 = nr(domain::SYNC, op::READ); // 0x72
/// `sync_wake(sync_id, value, n)`：设值为 `value`，唤醒至多 `n` 个等待者，返回实际唤醒数。
pub const SYS_SYNC_WAKE: u32 = nr(domain::SYNC, op::WRITE); // 0x73
/// `sync_delete(sync_id)`：销毁对象；仍有等待者返回 `Busy`。
pub const SYS_SYNC_DELETE: u32 = nr(domain::SYNC, op::DELETE); // 0x74

// ---------- 8. SIGNAL Domain (0x80, ADR-034 PROPOSED) ----------
/// `signal_mask(how, set) -> old_set`：查/改屏蔽集（sigprocmask）。
pub const SYS_SIGNAL_MASK: u32 = nr(domain::SIGNAL, op::READ); // 0x82
/// `signal_action(sig, handler, flags) -> old_disposition`：查/设处置（sigaction）。
pub const SYS_SIGNAL_ACTION: u32 = nr(domain::SIGNAL, op::WRITE); // 0x83
/// `signal_return()`：handler 返回后恢复原帧（rt_sigreturn）。
pub const SYS_SIGNAL_RETURN: u32 = nr(domain::SIGNAL, op::DELETE); // 0x84

// ---------- 9. POWER Domain (0x90, ADR-036) ----------
/// `power_off()`：请求 ACPI S5 软关机（断电）。双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_POWER_OFF` 同值、注释互指。
pub const SYS_POWER_OFF: u32 = nr(domain::POWER, 0x01); // 0x91
/// `reboot()`：请求系统重启（ACPI reset / 8042）。双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_POWER_REBOOT` 同值、注释互指。
pub const SYS_POWER_REBOOT: u32 = nr(domain::POWER, 0x02); // 0x92

// ---------- ABI 打包（成功 / 错误） ----------

/// 打包成功值：原样返回全 64 位（可容纳地址/指针/长度）。
#[inline]
fn pack_ok(v: u64) -> u64 {
    v
}

/// 打包错误：返回 `-errno` 的补码（`bit63` 置位 = 错误，ADR-003 错误码直接返回）。
#[inline]
fn pack_err(e: Error) -> u64 {
    (e.to_errno() as i64).wrapping_neg() as u64
}

// ---------- 具体 syscall 实现 ----------

/// 单次 syscall 用户缓冲长度上限（审计 B2：逐页预校验的 CPU 有界性）。
///
/// `validate_user_range` 对区间**逐页**走页表，len 无上限 = 用户一个 read
/// 就能让内核空转 ~2^34 次页表查询。上限取 64MiB——与单地址空间配额
/// （MAX_USER_AREA_TOTAL_BYTES）同量级，覆盖全部合法批量 IO；超出即参数
/// 错误（InvalidParam），调用方分次提交。Linux 同型先例：MAX_RW_COUNT。
const MAX_SYSCALL_BUF_BYTES: u64 = 64 * 1024 * 1024;

/// 预校验当前进程的用户缓冲区 `[buf, buf + len)` 对 `access` 意图可访问
/// （arch1.md AR1a EFAULT 路线的统一入口）。
///
/// 三层检查：
/// 1. **长度上限**——超过 [`MAX_SYSCALL_BUF_BYTES`] 直接 InvalidParam：
///    页表预校验逐页执行，必须保证其迭代次数有界（B2）；
/// 2. **窗口检查**——区间必须整体落在用户半区 `[USER_BASE, USER_TOP)`，
///    越界属参数值错误，返回 [`Error::OutOfRange`]；
/// 3. **页表预校验**——经 [`mm::user_space::UserAddressSpace::is_range_mapped`]
///    逐页确认已映射、带 user 位、写意图另需可写位；不满足返回
///    [`Error::BadAddress`]（EFAULT）。
///
/// 任何 STAC 拷贝（`copy_from_user`/`copy_to_user`）之前必须先通过本校验：
/// arch 层对内核态 #PF 一律停机，这里放过一个野指针就是放过了整机死机。
fn validate_user_range(buf: u64, len: u64, access: UserAccess) -> Result<(), Error> {
    if len > MAX_SYSCALL_BUF_BYTES {
        return Err(Error::InvalidParam);
    }
    let Some(end) = buf.checked_add(len) else {
        return Err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return Err(Error::OutOfRange);
    }
    let Some(proc) = current_proc_mut() else {
        return Err(Error::NotFound);
    };
    if proc.addr_space().is_range_mapped(buf, len, access) {
        Ok(())
    } else {
        Err(Error::BadAddress)
    }
}

/// 从用户空间拷贝以 null 结尾的路径字符串。
///
/// 逐字节读取并在**首次跨入每个新页**时对该页做读意图预校验：路径长度上限
/// 内的任何未映射页都会在校验层被拦下并返回 [`Error::BadAddress`]，而不是
/// 在内核态触发 #PF。
///
/// 上限语义（ADR-011 §1.3 / ADR-023 §2 M15）：`max_len` 是**显式有界**——
/// 从 `path_ptr` 起始的连续字节必须在 `max_len` 内出现 NUL 终止符，否则即
/// 视为路径超长（或缺失终止符），**显式返回 [`Error::InvalidParam`] 而非
/// 静默截断**。静默截断会把一条超长的路径伪装成完整交付，调用方无从得知
/// 真值被丢弃。
fn copy_path_from_user(path_ptr: u64, max_len: usize) -> Result<alloc::string::String, Error> {
    if path_ptr < USER_BASE || path_ptr >= USER_TOP {
        return Err(Error::OutOfRange);
    }
    const PAGE_SIZE: u64 = 0x1000;
    let mut validated_page_end = path_ptr & !(PAGE_SIZE - 1);
    let mut bytes = alloc::vec::Vec::new();
    let mut cur = path_ptr;
    let mut terminated = false;
    while bytes.len() < max_len {
        if cur >= USER_TOP {
            return Err(Error::OutOfRange);
        }
        if cur >= validated_page_end {
            // 跨入新页：整页做一次读意图校验（含本页与后续页边界对齐）。
            validate_user_range(cur, 1, UserAccess::Read)?;
            validated_page_end = (cur & !(PAGE_SIZE - 1)) + PAGE_SIZE;
        }
        let mut byte = [0u8; 1];
        unsafe {
            arch_x86_64::mmio::copy_from_user(byte.as_mut_ptr(), cur, 1);
        }
        if byte[0] == 0 {
            terminated = true;
            break;
        }
        bytes.push(byte[0]);
        cur += 1;
    }
    // 耗尽 max_len 仍未遇 NUL：路径超长或缺失终止符，显式拒绝，绝不静默截断。
    if !terminated {
        return Err(Error::InvalidParam);
    }
    alloc::string::String::from_utf8(bytes).map_err(|_| Error::InvalidParam)
}

/// 把用户提供的路径规范化为**绝对路径**（ADR-011 M1：VFS 只接受绝对路径，
/// cwd 拼接在 syscall 层完成，VFS 契约不变）。
///
/// - 绝对输入（`/` 开头）：直接规范化（消除 `.`/`..`/连续斜杠）；
/// - 相对输入：与当前进程 cwd 拼接成 `{cwd}/{rel}` 再规范化（`../` 正确上溯）。
///
/// 用 `vfs::path::Path::canonicalize`（ADR-023 §2 成文契约：词法消解，不查
/// 文件系统、不穿透符号链接/挂载点）。返回恒以 `/` 开头，VFS resolve 可接受。
fn absolute_path(path: &str) -> Result<alloc::string::String, Error> {
    if path.is_empty() {
        return Err(Error::InvalidParam);
    }
    let abs = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else {
        let Some(proc) = current_proc_mut() else {
            return Err(Error::NotFound);
        };
        let cwd = proc.cwd();
        if cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", cwd, path)
        }
    };
    Ok(vfs::path::Path::canonicalize(&abs))
}

/// `chdir(path_ptr)`：切换当前进程工作目录（VFS 域 0x45）。
///
/// 目标必须是存在的目录（用 VFS `ENTRY_READ` 解析确认），否则不改动 cwd
/// 并返回错误。相对路径相对当前 cwd 解析。
fn sys_chdir(frame: &mut SyscallFrame) -> u64 {
    let path = match copy_path_from_user(frame.a1, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let abs = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // 确认目标是目录；非目录或不存在如实报错（宁缺毋假）。
    let root = crate::vfs_init::root();
    let node = match root.resolve(&abs, true) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    if node.node_type().map(|t| t != vfs::inode::INodeType::Directory).unwrap_or(true) {
        return pack_err(Error::NotDirectory);
    }
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    proc.set_cwd(abs);
    pack_ok(0)
}

/// `getcwd(buf_ptr, cap)`：读当前进程工作目录到用户缓冲（VFS 域 0x46）。
///
/// 写入含终止 NUL；`cap` 不足时如实 `Error::NoSpace`，绝不静默截断。
fn sys_getcwd(frame: &mut SyscallFrame) -> u64 {
    let buf_ptr = frame.a1;
    let cap = frame.a2 as usize;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let cwd = proc.cwd();
    // 需要 cap 容纳 cwd 字节 + 终止 NUL。
    if cwd.len() + 1 > cap {
        return pack_err(Error::NoSpace);
    }
    let mut out_buf = alloc::vec::Vec::with_capacity(cwd.len() + 1);
    out_buf.extend_from_slice(cwd.as_bytes());
    out_buf.push(0);
    // 逐块写回用户缓冲（与其余 syscall 同款 validate + copy 纪律）。
    if let Err(e) = validate_user_range(buf_ptr, out_buf.len() as u64, UserAccess::Write) {
        return pack_err(e);
    }
    unsafe {
        arch_x86_64::mmio::copy_to_user(buf_ptr, out_buf.as_ptr(), out_buf.len());
    }
    pack_ok(cwd.len() as u64)
}

/// A1 / ADR-033：权限强制。
///
/// 在 `sys_open`（`resolve` 后、`FileHandle::new` 前）与 `sys_exec`（解析
/// inode 后、装载前）调用。当前只强制 `system_only` 节点的特权门槛：
/// `Permissions::system_only == true` 的节点仅 `Privilege::System` 进程
/// 可打开/执行，其余身份返回 `Error::PermissionDenied`（EACCES）。
///
/// 诚实边界（PRE-3）：readable/writable/executable 的 owner 维度在多用户
/// 立项前不做（ABI §4 单用户抹平）；本函数当前只比较 `system_only` 布尔 +
/// 进程 `Privilege` 两档，无 owner/group/other 矩阵。
fn enforce_open_permission(
    identity: ProcessIdentity,
    inode: &alloc::sync::Arc<dyn vfs::inode::INode>,
) -> Result<(), Error> {
    let meta = inode.metadata()?;
    if meta.permissions.system_only && identity.privilege != Privilege::System {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// `open(path_ptr, flags_bits, perm_bits)`：打开或创建文件，返回 fd。
///
/// ADR-014 §4.1 FLAG_PIPE：当 `flags` 含 `pipe` 位且 `path_ptr` 指向空串
/// （仅根路径 `/` 或空串）时，本 syscall 改为分配一对匿名管道端，返回值
/// 为 `(read_fd << 32) | write_fd` 打包（两 fd 均 < 2^32，bit63 恒 0 即成功）。
/// 两 fd 均引用同一 ipc 管道（环形缓冲），读写经 `ipc::pipe_*` 路由。
fn sys_open(frame: &mut SyscallFrame) -> u64 {
    let path_ptr = frame.a1;
    let flags_bits = frame.a2 as u32;
    let perm_bits = frame.a3 as u32;

    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };

    let flags = vfs::file_handle::OpenFlags::from_bits(flags_bits);
    let perm = vfs::inode::Permissions::from_bits(perm_bits);

    // ADR-014 FLAG_PIPE：匿名管道，不落文件系统。路径须为空（"" 或 "/"）。
    if flags.pipe {
        return sys_open_pipe(path, frame);
    }

    // 相对路径与进程 cwd 拼接成绝对路径（VFS 只接受绝对路径，ADR-011 M1）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };

    let root = crate::vfs_init::root();

    // A1 / ADR-033 (V7 fix): 创建授权——User 进程不得创建 system_only=true 节点。
    // 若创建时请求了 system_only 位，必须是 System 特权；否则 PermissionDenied，
    // 杜绝"User 自建 system_only 节点后经强制打开被拒"的边界漏洞。
    if flags.create && perm.system_only {
        let creator = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if creator.privilege != Privilege::System {
            return pack_err(Error::PermissionDenied);
        }
    }

    let inode = match root.resolve(&path, true) {
        Ok(n) => {
            if flags.truncate {
                // kernel1.md K8：截断失败必须上抛，绝不能 `let _ =` 吞错——
                // 吞错会让调用者相信文件已清空而实际内容原样保留（伪成功）。
                // O_TRUNC 无写位：POSIX 语义要求截断以写权限为前提；本内核
                // 选择显式拒绝（EINVAL）并成文于 ABI 注释，而非静默不生效。
                if !flags.write {
                    return pack_err(Error::InvalidParam);
                }
                if let Err(e) = n.truncate(0) {
                    return pack_err(e);
                }
            }
            n
        }
        Err(Error::NotFound) if flags.create => match root.create_file(&path, perm) {
            Ok(n) => n,
            Err(e) => return pack_err(e),
        },
        Err(e) => return pack_err(e),
    };

    // A1 / ADR-033：权限强制（system_only 节点仅 System 特权可开）。
    // 无当前进程时回退 User（拒绝最严）。inode 已解析、句柄未构造，
    // 为最低成本的拒绝点。
    let identity = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    if let Err(e) = enforce_open_permission(identity, &inode) {
        return pack_err(e);
    }

    // vfs1 M4/M3：O_DIRECTORY 强制与 append 起点真值在 FileHandle::new
    // 内完成；失败（目标非目录等）如实上抛，不再静默产出坏句柄。
    let handle = match vfs::file_handle::FileHandle::new(inode, flags) {
        Ok(h) => h,
        Err(e) => return pack_err(e),
    };
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    // KA7：fd 表满（每进程上限）如实 ENOSPC，绝不无界吃内核堆。
    match proc.alloc_fd(vfs::file_handle::OpenHandle::File(handle)) {
        Ok(fd) => pack_ok(fd as u64),
        Err(e) => pack_err(e),
    }
}

/// FLAG_PIPE：创建一对匿名管道端并各分配一个 fd。
///
/// 路径必须是空串 `""` 或根路径 `"/"`（宁缺毋假：带真实路径的 FLAG_PIPE
/// 返回 `InvalidParam`，绝不静默忽略路径）。返回 `(read_fd << 32) | write_fd`。
fn sys_open_pipe(path: alloc::string::String, _frame: &mut SyscallFrame) -> u64 {
    if path != "/" && !path.is_empty() {
        return pack_err(Error::InvalidParam);
    }
    // 建管道（refs=0），随后为两个 fd 端各增记一次引用。
    let id = match ipc::pipe_create() {
        Ok(i) => i,
        Err(e) => return pack_err(e),
    };
    let inc = |id: u64| ipc::pipe_ref_inc(id);
    let dec = |id: u64| {
        let _ = ipc::pipe_ref_dec(id);
    };
    if inc(id).is_err() {
        // 理论不可达（刚创建必在表内），防御性清理。
        let _ = ipc::pipe_close(id);
        return pack_err(Error::NotFound);
    }
    let Some(proc) = current_proc_mut() else {
        dec(id);
        return pack_err(Error::NotFound);
    };
    // 分配两个 fd 端。第二个失败需回滚：释放第一个 fd 槽 + 递减引用。
    let read_fd = match proc.alloc_fd(vfs::file_handle::OpenHandle::Pipe { id }) {
        Ok(fd) => fd,
        Err(e) => {
            dec(id);
            return pack_err(e);
        }
    };
    if inc(id).is_err() {
        proc.close_fd(read_fd);
        dec(id);
        return pack_err(Error::NotFound);
    }
    let write_fd = match proc.alloc_fd(vfs::file_handle::OpenHandle::Pipe { id }) {
        Ok(fd) => fd,
        Err(e) => {
            proc.close_fd(read_fd);
            dec(id);
            return pack_err(e);
        }
    };
    // 打包：read_fd 低 32 位，write_fd 高 32 位。fd < 2^32，bit63 恒 0 → 成功。
    let packed = (read_fd as u64) | ((write_fd as u64) << 32);
    pack_ok(packed)
}

/// `close(fd)`：关闭用户分配的文件描述符。
///
/// fd 0/1/2 是进程的保留标准流，不是可关闭的用户句柄；拒绝该操作并返回
/// `Error::NotSupported`（ENOTSUP），绝不以成功码掩盖未发生的状态变化。
fn sys_close(frame: &mut SyscallFrame) -> u64 {
    let fd = frame.a1 as usize;
    if fd < 3 {
        return pack_err(Error::NotSupported);
    }
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.close_fd(fd) {
        Some(vfs::file_handle::OpenHandle::Pipe { id }) => {
            // 释放管道端引用；归零即销毁（ipc::pipe_ref_dec 语义）。
            match ipc::pipe_ref_dec(id) {
                Ok(()) => pack_ok(0),
                Err(_) => pack_err(Error::NotFound),
            }
        }
        Some(vfs::file_handle::OpenHandle::File(_)) => pack_ok(0),
        None => pack_err(Error::NotFound),
    }
}

/// flock 文件锁（SYS_STREAM_LOCK, 0x16，ADR-014 / ADR-033 A2-1 R6）。
///
/// a1=fd, a2=cmd（0=LOCK_SH, 1=LOCK_EX, 2=UNLOCK）。advisory：冲突返回 Busy，
/// 不阻塞；不阻断无锁读写。锁按调用者 uid（ProcessIdentity.uid）登记，是
/// flock 的**唯一生产加锁入口**（K1：syscall 层真链路，非仅测试温室）。
fn sys_flock(frame: &mut SyscallFrame) -> u64 {
    let fd = frame.a1 as usize;
    let cmd = frame.a2;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let uid = proc.identity().uid;
    let Some(vfs::file_handle::OpenHandle::File(fh)) = proc.get_fd(fd) else {
        return pack_err(Error::NotFound); // fd 缺失或 pipe 端（flock 仅文件）
    };
    let owner = vfs::flock::LockOwner { uid };
    match cmd {
        0 => vfs::flock::flock_lock(&fh.inode, owner, false).map_or_else(pack_err, |_| pack_ok(0)),
        1 => vfs::flock::flock_lock(&fh.inode, owner, true).map_or_else(pack_err, |_| pack_ok(0)),
        2 => {
            vfs::flock::flock_unlock(&fh.inode, owner);
            pack_ok(0)
        }
        _ => pack_err(Error::InvalidParam),
    }
}

/// `fstat(fd, out_buf_ptr)`（SYS_STREAM_FSTAT）：按 fd 读元数据。
///
/// 从 fd 的文件句柄取 inode，调用 `INode::metadata` 后以
/// `vfs::inode::StatInfo` 定长结构写入用户缓冲（a2），返回结构
/// 字节数。只支持文件句柄（OpenHandle::File）；pipe 端如实
/// NotFound（与 flock 同政策）。
fn sys_fstat(frame: &mut SyscallFrame) -> u64 {
    let fd = frame.a1 as usize;
    let buf_ptr = frame.a2;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(vfs::file_handle::OpenHandle::File(fh)) = proc.get_fd(fd) else {
        return pack_err(Error::NotFound); // fd 缺失或 pipe 端（fstat 仅文件）
    };
    let meta = match fh.inode.metadata() {
        Ok(m) => m,
        Err(e) => return pack_err(e),
    };
    let info = vfs::inode::StatInfo::from_metadata(&meta);
    let bytes = core::mem::size_of::<vfs::inode::StatInfo>();
    if let Err(e) = validate_user_range(buf_ptr, bytes as u64, UserAccess::Write) {
        return pack_err(e);
    }
    unsafe {
        arch_x86_64::mmio::copy_to_user(
            buf_ptr,
            &info as *const vfs::inode::StatInfo as *const u8,
            bytes,
        );
    }
    pack_ok(bytes as u64)
}

/// `dup2(old_fd, new_fd)`（SYS_STREAM_DUP，pipe-features 方案 A）。
///
/// 把 `old_fd` 的句柄复制到 `new_fd`：先关 `new_fd` 旧句柄（pipe 端
/// `pipe_ref_dec`），再把 `old_fd` 副本装入 `new_fd`（pipe 端 `pipe_ref_inc`）。
/// `old_fd == new_fd` 时仅校验存在性返回 `new_fd`。副本与原句柄共享同一文件
/// 描述（`Arc` + 共享 offset）/管道端。旧 fd 越界或不存在如实 `NotFound`。
fn sys_dup2(frame: &mut SyscallFrame) -> u64 {
    let old_fd = frame.a1 as usize;
    let new_fd = frame.a2 as usize;
    // 目标 fd 槽位上限（与 Process::MAX_FDS 对齐，NA6 防无界扩展）。
    if new_fd >= task::process::Process::<arch_x86_64::paging::X86PageTable>::MAX_FDS {
        return pack_err(Error::NoSpace);
    }
    // 校验 old 存在并取得副本句柄（值拷贝，随后可释放 proc 借用做 ipc）。
    let old_handle = {
        let Some(proc) = current_proc_mut() else {
            return pack_err(Error::NotFound);
        };
        match proc.get_fd(old_fd) {
            Some(h) => h,
            None => return pack_err(Error::NotFound),
        }
    };
    if old_fd == new_fd {
        return pack_ok(new_fd as u64);
    }
    // 副本是 pipe 端：递增引用计数（每个持有该 id 的 fd 记 1 ref）。
    // 用引用绑定取 id（Pipe 的 u64 是 Copy），不 move old_handle——它稍后
    // 要整体 move 进 set_fd。
    if let vfs::file_handle::OpenHandle::Pipe { id } = &old_handle {
        if ipc::pipe_ref_inc(*id).is_err() {
            return pack_err(Error::NoSpace);
        }
    }
    // 关 new 的旧句柄（若为 pipe 端递减引用）。
    if let Some(old) = { current_proc_mut().and_then(|p| p.close_fd(new_fd)) } {
        if let vfs::file_handle::OpenHandle::Pipe { id } = old {
            let _ = ipc::pipe_ref_dec(id);
        }
    }
    // 装入副本（new_fd 已在入口校验 < MAX_FDS，set_fd 必成功）。
    let Some(proc) = current_proc_mut() else {
        // proc 消失的极小窗口：回滚刚递增的 pipe 引用。
        if let vfs::file_handle::OpenHandle::Pipe { id } = &old_handle {
            let _ = ipc::pipe_ref_dec(*id);
        }
        return pack_err(Error::NotFound);
    };
    match proc.set_fd(new_fd, old_handle) {
        Ok(()) => pack_ok(new_fd as u64),
        Err(_) => pack_err(Error::NoSpace),
    }
}

/// `entry_create(path_ptr, kind, perm)`：创建目录或特殊节点（ADR-014 §4.4 0x41）。
///
/// 参数：`a1=path_ptr`、`a2=kind`（[`ENTRY_KIND_*`]）、`a3=perm`。`kind` 决定
/// 待建节点类型——不再无条件当目录创建。当前 VFS 实际支持创建目录（`mkdir`）
/// 与普通文件（`create_file`）；其余 kind（symlink/fifo/chardev/blkdev/socket）
/// 尚无可落地路径，**如实返回 `NotSupported`**（S09 宁缺毋假），绝不把特殊
/// 节点静默当成目录创建造成伪成功。未知 kind 返回 `InvalidParam`。
fn sys_entry_create(frame: &mut SyscallFrame) -> u64 {
    let path_ptr = frame.a1;
    let kind = frame.a2;
    let perm_bits = frame.a3 as u32;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let perm = vfs::inode::Permissions::from_bits(perm_bits);
    // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    let root = crate::vfs_init::root();
    match kind {
        crate::syscall::ENTRY_KIND_DIRECTORY => match root.mkdir(&path, perm) {
            Ok(_) => pack_ok(0),
            Err(e) => pack_err(e),
        },
        crate::syscall::ENTRY_KIND_FILE => match root.create_file(&path, perm) {
            Ok(_) => pack_ok(0),
            Err(e) => pack_err(e),
        },
        crate::syscall::ENTRY_KIND_SYMLINK
        | crate::syscall::ENTRY_KIND_FIFO
        | crate::syscall::ENTRY_KIND_CHARDEV
        | crate::syscall::ENTRY_KIND_BLOCKDEV
        | crate::syscall::ENTRY_KIND_SOCKET => pack_err(Error::NotSupported),
        _ => pack_err(Error::InvalidParam),
    }
}

/// `unlink(path_ptr)`：删除文件或空目录。
fn sys_unlink(frame: &mut SyscallFrame) -> u64 {
    let path_ptr = frame.a1;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    let root = crate::vfs_init::root();
    match root.unlink(&path) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `entry_update(a1, a2, a3, a4)`：按 `a4` 区分两种动作（ADR-014 0x43）。
/// - `a4=ENTRY_UPDATE_RENAME(0)`：同目录重命名（a1=old_path, a2=new_path, a3=flags=0）。
///   源与目标须在同一父目录（跨目录移动如实 `NotSupported`）。
/// - `a4=ENTRY_UPDATE_CHMOD(1)`：设置节点权限（a1=path, a2=mode_bits）。
/// 非法 `a4` 如实 `InvalidParam`，不静默忽略。
fn sys_entry_update(frame: &mut SyscallFrame) -> u64 {
    let action = frame.a4;
    match action {
        // rename：a4=0，a1=old_path, a2=new_path, a3=flags(=0)。
        ENTRY_UPDATE_RENAME => {
            let old_path_ptr = frame.a1;
            let new_path_ptr = frame.a2;
            let flags = frame.a3;
            if flags != 0 {
                return pack_err(Error::InvalidParam);
            }
            let old_path = match copy_path_from_user(old_path_ptr, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            let new_path = match copy_path_from_user(new_path_ptr, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
            let old_path = match absolute_path(&old_path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
            let new_path = match absolute_path(&new_path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
            let root = crate::vfs_init::root();
            match root.rename(&old_path, &new_path) {
                Ok(()) => pack_ok(0),
                Err(e) => pack_err(e),
            }
        }
        // chmod：a4=1，a1=path, a2=mode_bits（`Permissions::to_bits` 编码）。
        ENTRY_UPDATE_CHMOD => {
            let path_ptr = frame.a1;
            let mode_bits = frame.a2 as u32;
            let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            let path = match absolute_path(&path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
            let perm = vfs::inode::Permissions::from_bits(mode_bits);
            let root = crate::vfs_init::root();
            let node = match root.resolve(&path, false) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            };
            match node.set_permissions(perm) {
                Ok(()) => pack_ok(0),
                Err(e) => pack_err(e),
            }
        }
        _ => pack_err(Error::InvalidParam),
    }
}

/// `readdir(path_ptr, buf_ptr, max_bytes)`：获取目录项列表（以 JSON 结构或固定格式写入用户缓冲）。
fn sys_readdir(frame: &mut SyscallFrame) -> u64 {
    let path_ptr = frame.a1;
    let buf_ptr = frame.a2;
    let max_bytes = frame.a3 as usize;

    // S31：max_bytes 是用户可控上限，内核侧给读目录结果设独立上限——否则
    // 用户可传巨大值迫使内核为 out String 分配任意大堆块。上限远大于现实
    // 目录输出（单个目录项数十字节），仅防无界分配。
    const MAX_READDIR_OUT_BYTES: usize = 1 * 1024 * 1024;
    if max_bytes > MAX_READDIR_OUT_BYTES {
        return pack_err(Error::InvalidParam);
    }

    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };

    // 第二原语：stat 模式（a4 == ENTRY_READ_STAT）。解析路径后把
    // 节点元数据以 StatInfo 定长结构整块拷入用户缓冲（a2），返回结构字节数。
    // follow_symlink=true（POSIX stat 跟软链符），与 readdir 同路径解析。
    if frame.a4 == ENTRY_READ_STAT {
        let root = crate::vfs_init::root();
        let node = match root.resolve(&path, true) {
            Ok(n) => n,
            Err(e) => return pack_err(e),
        };
        let meta = match node.metadata() {
            Ok(m) => m,
            Err(e) => return pack_err(e),
        };
        let info = vfs::inode::StatInfo::from_metadata(&meta);
        let bytes = core::mem::size_of::<vfs::inode::StatInfo>();
        if max_bytes < bytes {
            return pack_err(Error::InvalidParam); // 缓冲过小，如实拒绝
        }
        if let Err(e) = validate_user_range(buf_ptr, bytes as u64, UserAccess::Write) {
            return pack_err(e);
        }
        unsafe {
            arch_x86_64::mmio::copy_to_user(
                buf_ptr,
                &info as *const vfs::inode::StatInfo as *const u8,
                bytes,
            );
        }
        return pack_ok(bytes as u64);
    }

    let root = crate::vfs_init::root();
    let dir_node = match root.resolve(&path, true) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };

    let entries = match dir_node.list_dir() {
        Ok(list) => list,
        Err(e) => return pack_err(e),
    };

    // 标准紧凑 JSON 数组输出（ADR-014 §4.1 / ADR-013 对象视图一致约定）：
    //   [{"name":"...","type":"file","size":123}, ...]
    // 经 klib::json 的 JsonWriter 逐字段转义（S09 宁缺毋假：名字含引号/反斜杠
    // 等控制符均正确转义，绝不裸拼破坏成帧）。KM5：只交付**完整数组**——放
    // 不下整条时尾部条目整体省略，绝不把半截 `{"name":"...` 交给调用方；返回
    // 字节数 < 完整列表长度即表示还有剩余条目（分页语义，成文）。
    /// readdir 单条记录的类型标签（JSON `type` 字段值，ADR-013 约定）。
    const fn type_tag(t: vfs::inode::INodeType) -> &'static str {
        match t {
            vfs::inode::INodeType::Directory => "dir",
            vfs::inode::INodeType::RegularFile => "file",
            vfs::inode::INodeType::Symlink => "link",
            vfs::inode::INodeType::CharacterDevice => "chardev",
            vfs::inode::INodeType::BlockDevice => "blkdev",
            vfs::inode::INodeType::Fifo => "fifo",
            vfs::inode::INodeType::Socket => "sock",
        }
    }

    // 先在内存 VecTarget 构建完整 JSON 数组（总长受 max_bytes 约束，防无界
    // 分配），再整块校验并拷入用户缓冲。VecTarget::write_str 无分配错误路径，
    // JsonWriter 的 Result 恒 Ok，.expect 保守可行。
    let mut target = klib::json::VecTarget::new();
    let mut writer = klib::json::JsonWriter::new(&mut target);
    let mut array = writer.start_array().expect("Vec-backed JSON cannot fail");
    // 已写数组字节数（不含进行中的元素）；array 持有 target 可变借用，故用
    // 计数变量而非 target.as_bytes() 量长。
    let mut written = 0usize;
    let mut first = true;
    for e in &entries {
        // 单条记录 JSON 化到临时 target 再量长：放不下则整条省略（含其前导
        // 逗号），保证主数组永不含未闭合/半截对象。
        let mut item = klib::json::VecTarget::new();
        let mut iw = klib::json::JsonWriter::new(&mut item);
        let mut obj = iw.start_object().expect("Vec-backed JSON cannot fail");
        obj.field_str("name", e.name.as_str())
            .expect("Vec-backed JSON cannot fail")
            .field_str("type", type_tag(e.node_type))
            .expect("Vec-backed JSON cannot fail")
            .field_u64("size", e.size)
            .expect("Vec-backed JSON cannot fail");
        let _ = obj.end();
        let item_bytes = item.as_bytes();
        // item 仅由 JsonWriter 生成，恒为合法 UTF-8（field_str 按 char 转义）。
        let item_str = match core::str::from_utf8(item_bytes) {
            Ok(s) => s,
            Err(_) => continue, // 保守：非法 UTF-8 则跳过该条（理论不可达）
        };
        // 估算加入本条后的总长：非首条多一个前导逗号。
        let add = item_bytes.len() + if first { 0 } else { 1 };
        if written + add + 1 > max_bytes {
            break; // 放不下本条，整体省略剩余条目
        }
        if array.push_raw(item_str).is_err() {
            break;
        }
        written += add;
        first = false;
    }
    let _ = array.end();
    let bytes = target.as_bytes();
    let n = bytes.len();
    // B10：缓冲连 `[]` 都放不下（max_bytes<2）时返回 0 会与 EOF/空目录不可
    // 区分。按 POSIX getdents 惯例以 EINVAL 如实拒绝；entries 为空才返回 0。
    if n == 0 && !entries.is_empty() {
        return pack_err(Error::InvalidParam);
    }
    if n > 0 {
        if let Err(e) = validate_user_range(buf_ptr, n as u64, UserAccess::Write) {
            return pack_err(e);
        }
        unsafe {
            arch_x86_64::mmio::copy_to_user(buf_ptr, bytes.as_ptr(), n);
        }
    }
    pack_ok(n as u64)
}

/// `write(fd, buf, len, offset)`：写入 stdout/stderr 或用户 FD 句柄。
///
/// ABI 约定：仅 [`STREAM_OFFSET_CURRENT`] 表示顺序写；`offset=0` 以及任意其他
/// 偏移均为定位写（`pwrite`），不会推进句柄当前位置。
fn sys_write(frame: &mut SyscallFrame) -> u64 {
    let fd = frame.a1;
    let buf = frame.a2;
    let len = frame.a3;
    let offset = frame.a4;

    if len == 0 {
        return pack_ok(0);
    }

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };

    // ADR-014 FLAG_PIPE：管道端直接经 ipc::pipe_write 路由（环形缓冲 +
    // 内部阻塞/唤醒）。管道不可定位，非顺序写哨兵如实 ESPIPE。
    let pipe_id = match proc.get_fd(fd as usize) {
        Some(vfs::file_handle::OpenHandle::Pipe { id }) => Some(id),
        Some(vfs::file_handle::OpenHandle::File(_)) => None,
        None => return pack_err(Error::InvalidParam),
    };
    if let Some(id) = pipe_id {
        if offset != STREAM_OFFSET_CURRENT {
            return pack_err(Error::IllegalSeek);
        }
        // pipe_write 内部可能阻塞切走并等待唤醒后继续；进程回归后本帧即
        // 当前进程现场（见 sys_read 阻塞契约），完成后可安全回写 result。
        let space = proc.addr_space();
        return match ipc::pipe_write(arch_frame(frame), id, space, buf, len) {
            Ok(n) => pack_ok(n),
            Err(e) => pack_err(e),
        };
    }
    let handle = match proc.get_fd(fd as usize) {
        Some(vfs::file_handle::OpenHandle::File(h)) => h,
        Some(vfs::file_handle::OpenHandle::Pipe { .. }) => unreachable!("handled above"),
        None => return pack_err(Error::InvalidParam),
    };

    // KM1：无 fd 号特判——1/2 与普通句柄走同一条路，stdout/stderr 节点在
    // write_at 内直发字节（K5 完全体：串口 sink 字节透明，文本 sink 自行
    // lossy），syscall 层零转换。
    // KM17：字符流不可定位。可定位性来自节点真值（is_seekable），不再依赖
    // fd 号魔法数字；除顺序写哨兵外的任何偏移以 ESPIPE 如实拒绝。
    if !handle.inode.is_seekable() && offset != STREAM_OFFSET_CURRENT {
        return pack_err(Error::IllegalSeek);
    }

    let want = core::cmp::min(len, SYSCALL_COPY_CHUNK_BYTES) as usize;
    let mut kbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if kbuf.try_reserve_exact(want).is_err() {
        return pack_err(Error::OutOfMemory);
    }
    kbuf.resize(want, 0);
    let chunk_cap = want as u64;

    let mut total = 0u64;
    while total < len {
        let n = core::cmp::min(len - total, chunk_cap);
        // S19：buf/offset 与 total 均为用户可控 u64，回绕即错误地址——
        // checked 失败如实 InvalidParam，绝不静默写错偏移（release 无溢出
        // 检查，裸加法回绕=错址写报成功）。
        let Some(ubuf) = buf.checked_add(total) else {
            if total == 0 {
                return pack_err(Error::InvalidParam);
            }
            return pack_ok(total); // 已写部分有效，短写交付
        };
        // S19：fpos 仅**定位写**需要（offset != STREAM_OFFSET_CURRENT）。
        // 顺序写哨兵 STREAM_OFFSET_CURRENT == u64::MAX，对其做
        // `u64::MAX + total`（total≥1 时必然回绕）是错把哨兵当真实偏移，
        // 误触发"短交付"把 >1MiB 的顺序写静默截断。顺序路径不推进 fpos，
        // 直接走 handle.write() 的句柄内部 offset。
        if offset != STREAM_OFFSET_CURRENT {
            if offset.checked_add(total).is_none() {
                if total == 0 {
                    return pack_err(Error::InvalidParam);
                }
                return pack_ok(total); // 已写部分有效，短写交付
            }
        }
        if let Err(e) = validate_user_range(ubuf, n, UserAccess::Read) {
            if total == 0 {
                return pack_err(e);
            }
            // 已成功写出部分后校验失败：以短写语义交付已写字节数。
            return pack_ok(total);
        }
        unsafe {
            arch_x86_64::mmio::copy_from_user(kbuf.as_mut_ptr(), ubuf, n as usize);
        }
        let wrote = if offset == STREAM_OFFSET_CURRENT {
            handle.write(&kbuf[..n as usize])
        } else {
            // 已在上方保证 `offset + total` 不回绕，此处安全推进定位偏移。
            let fpos = offset + total;
            handle.pwrite(fpos, &kbuf[..n as usize])
        };
        match wrote {
            Ok(w) => {
                total += w as u64;
                if (w as u64) < n {
                    break; // 设备短写：如实上报已写数量
                }
            }
            Err(e) => {
                if total == 0 {
                    return pack_err(e);
                }
                break; // 已写部分有效，按短写交付
            }
        }
    }
    pack_ok(total)
}

/// `read(fd, buf, len, offset)`：从 stdin 键盘或用户 FD 句柄读取。
///
/// ABI 约定：仅 [`STREAM_OFFSET_CURRENT`] 表示顺序读；`offset=0` 以及任意其他
/// 偏移均为定位读（`pread`），不会推进句柄当前位置。
///
/// 返回 [`DispatchResult`]：stdin 阻塞路径会把 `*frame` 整体切换为下一进程
/// 现场（K1a），此时入口不得再写 rax——返回值语义由 [`DispatchResult`]
/// 显式表达，杜绝 bool 被调用方无视。
fn sys_read(frame: &mut SyscallFrame) -> DispatchResult {
    let fd = frame.a1;
    let buf = frame.a2;
    let len = frame.a3;
    let offset = frame.a4;
    if len == 0 {
        return done(pack_ok(0));
    }

    let Some(proc) = current_proc_mut() else {
        return done(pack_err(Error::NotFound));
    };

    // ADR-014 FLAG_PIPE：管道端直接经 ipc::pipe_read 路由。管道不可定位，
    // 非顺序读哨兵如实 ESPIPE。pipe_read 内部阻塞/唤醒（进程回归后本帧即
    // 当前进程现场），完成后可安全回写 result。
    let pipe_id = match proc.get_fd(fd as usize) {
        Some(vfs::file_handle::OpenHandle::Pipe { id }) => Some(id),
        Some(vfs::file_handle::OpenHandle::File(_)) => None,
        None => return done(pack_err(Error::InvalidParam)),
    };
    if let Some(id) = pipe_id {
        if offset != STREAM_OFFSET_CURRENT {
            return done(pack_err(Error::IllegalSeek));
        }
        let space = proc.addr_space();
        return match ipc::pipe_read(arch_frame(frame), id, space, buf, len) {
            Ok(n) => done(pack_ok(n)),
            Err(e) => done(pack_err(e)),
        };
    }
    let handle = match proc.get_fd(fd as usize) {
        Some(vfs::file_handle::OpenHandle::File(h)) => h,
        Some(vfs::file_handle::OpenHandle::Pipe { .. }) => unreachable!("handled above"),
        None => return done(pack_err(Error::InvalidParam)),
    };
    // KM1：无 fd 号特判——0 与普通句柄走同一条路。stdin 节点空读返回
    // WouldBlock，下方按节点真值（interactive_input）翻译为阻塞切换。
    // KM17：字符流不可定位，可定位性来自节点真值。
    if !handle.inode.is_seekable() && offset != STREAM_OFFSET_CURRENT {
        return done(pack_err(Error::IllegalSeek));
    }

    let want = core::cmp::min(len, SYSCALL_COPY_CHUNK_BYTES) as usize;
    let mut kbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if kbuf.try_reserve_exact(want).is_err() {
        return done(pack_err(Error::OutOfMemory));
    }
    kbuf.resize(want, 0);
    let chunk_cap = want as u64;

    let mut total = 0u64;
    while total < len {
        let n = core::cmp::min(len - total, chunk_cap);
        // S19：同 write 路径——用户可控 u64 加法一律 checked。
        let Some(ubuf) = buf.checked_add(total) else {
            if total == 0 {
                return done(pack_err(Error::InvalidParam));
            }
            break; // 已读部分有效，短读交付
        };
        // S19：同 write 路径——fpos 仅**定位读**需要。顺序读哨兵
        // STREAM_OFFSET_CURRENT == u64::MAX，对其 `+total` 必然回绕，
        // 误当真实偏移会把 >1MiB 的顺序读静默截断成 1MiB。
        if offset != STREAM_OFFSET_CURRENT {
            if offset.checked_add(total).is_none() {
                if total == 0 {
                    return done(pack_err(Error::InvalidParam));
                }
                break;
            }
        }
        let chunk = &mut kbuf[..n as usize];
        let got = if offset == STREAM_OFFSET_CURRENT {
            handle.read(chunk)
        } else {
            // 已在上方保证 `offset + total` 不回绕，此处安全推进定位偏移。
            let fpos = offset + total;
            handle.pread(fpos, chunk)
        };
        match got {
            Ok(0) => break, // EOF（total==0 时即原始 EOF 语义）
            Ok(r) => {
                if let Err(e) = validate_user_range(ubuf, r as u64, UserAccess::Write) {
                    if total == 0 {
                        return done(pack_err(e));
                    }
                    break; // 先读到的部分有效，按短读交付
                }
                unsafe {
                    arch_x86_64::mmio::copy_to_user(ubuf, kbuf.as_ptr(), r);
                }
                total += r as u64;
                if (r as u64) < n {
                    break; // 设备短读：如实交付已读数量
                }
            }
            Err(e) => {
                // KM1/K1a：交互输入句柄（stdin）空读的 WouldBlock → 登记唯一
                // 等待者并阻塞切走。Busy = 已有并发 stdin 读者，如实返回
                // EAGAIN 而不是把对方顶掉（KM15）；Switched = 帧已整体切换，
                // 禁止再写 rax（K1a）。唤醒后用户 read 重试取字符。
                if total == 0 && e == Error::WouldBlock && handle.inode.interactive_input() {
                    return match task::block_for_kbd(arch_frame(frame)) {
                        task::scheduler::BlockKbdOutcome::Switched => DispatchResult::Switched,
                        task::scheduler::BlockKbdOutcome::Busy => done(pack_err(Error::WouldBlock)),
                    };
                }
                if total == 0 {
                    return done(pack_err(e));
                }
                break; // 已读部分有效，按短读交付
            }
        }
    }
    done(pack_ok(total))
}

/// `exec(prog, cmd)`：加载程序（VFS 路径字符串指针，或内建索引）为新进程并运行。
///
/// ABI（libsys nr.rs `task_spawn`）：`prog` 为用户态路径字符串指针；仅
/// [`BUILTIN_INDEX_INIT`] / [`BUILTIN_INDEX_SHELL`] 两个小整数被解释为内建
/// 程序索引，映射到 `/programs/init.elf` / `/programs/shell.elf`。ELF 数据
/// 来自 VFS `/programs`：构建期内置 liveCD payload 垫底，外部盘 EXT2 挂载
/// 成功后整体覆盖（盘优先，ADR-017）。
///
/// KM3：删除原"小索引 VFS resolve 失败后回退 program_elf(idx)"死亡分支——
/// 两者解析同一路径必然同样失败，且 `program_elf` 对 idx≥2 恒为 None；
/// 回退链只会把同一个 NotFound 伪装成两条路径都试过的假象。
/// KD8：同步删除无名魔数边界 `arg1 < 16`——内建索引实际只有 {0,1} 两项，
/// 2..15 恒失败；现在除两个命名内建索引外一切值都按其 ABI 本义（路径指针）
/// 处理，野指针由 copy_path_from_user 预校验如实拒绝。
fn sys_exec(frame: &mut SyscallFrame) -> u64 {
    let arg1 = frame.a1;
    let arg_ptr = frame.a2;
    let arg_len = frame.a3;

    let root = crate::vfs_init::root();

    // 1. 获取 ELF 字节数据
    let elf_data: alloc::vec::Vec<u8> = match arg1 {
        BUILTIN_INDEX_INIT | BUILTIN_INDEX_SHELL => {
            // 内建索引走统一单源读取（ADR-028）：`/programs` 只由内置
            // liveCD payload 填充，外部盘不再遮蔽（盘优先双源已废除）。
            // 与 KM3 无冲突——这里删去的是 read_binary_dual_source 的
            // 磁盘优先回退分支，单源即 /programs。
            let name = if arg1 == BUILTIN_INDEX_INIT {
                "init.elf"
            } else {
                "shell.elf"
            };
            match crate::read_binary_from_programs(name) {
                Some(v) => v,
                None => return pack_err(Error::NotFound),
            }
        }
        // 路径字符串模式：arg1 即用户态路径指针
        _ => {
            let path = match copy_path_from_user(arg1, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
            let path = match absolute_path(&path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
            match root.resolve(&path, true) {
                Ok(inode) => {
                    // A1 / ADR-033：执行前强制——system_only 可执行文件仅
                    // System 特权进程可装载。
                    let identity = current_proc_mut()
                        .map(|p| p.identity())
                        .unwrap_or_else(ProcessIdentity::default_user);
                    if let Err(e) = enforce_open_permission(identity, &inode) {
                        return pack_err(e);
                    }
                    let meta = match inode.metadata() {
                        Ok(m) => m,
                        Err(e) => return pack_err(e),
                    };
                    // S31：不得按 meta.size 无界分配内核堆整读——恶意/超大
                    // 可执行文件会触发内核 OOM abort（自伤面）。用既有批量
                    // IO 上限 MAX_SYSCALL_BUF_BYTES 约束；超限即拒绝装载。
                    if meta.size > MAX_SYSCALL_BUF_BYTES {
                        return pack_err(Error::ExecFormat);
                    }
                    let mut buf = alloc::vec![0u8; meta.size as usize];
                    if let Err(e) = inode.read_at(0, &mut buf) {
                        return pack_err(e);
                    }
                    buf
                }
                Err(e) => return pack_err(e),
            }
        }
    };

    spawn_elf_image(&elf_data, arg_ptr, arg_len, arg1)
}

/// 内建程序索引：init（与 libsys nr::PROG_* 约定同源；内核不依赖
/// 用户态 crate，双侧常量注释互指）。
/// `pub`：A1 测试与继承决策逻辑引用单点，不重复硬编码（S13）。
pub const BUILTIN_INDEX_INIT: u64 = 0;
/// 内建程序索引：shell。
pub const BUILTIN_INDEX_SHELL: u64 = 1;

/// A1 / ADR-033：计算派生子进程身份（单点决策，供 spawn_elf_image 与测试复用）。
///
/// - `idx_or_tag == BUILTIN_INDEX_INIT`：仅 `System` 特权调用者可派生
///   `System/uid=1` 子进程；`User` 调用者返回 `Err(PermissionDenied)`——
///   防"任意 User 经 exec(0,..) 未认证提权"（V2）。
/// - 其余分支：原样继承调用者身份（caller 已由调用方解析为 current 或默认）。
pub fn compute_child_identity(idx_or_tag: u64, caller: ProcessIdentity) -> Result<ProcessIdentity, Error> {
    if idx_or_tag == BUILTIN_INDEX_INIT {
        if caller.privilege != Privilege::System {
            return Err(Error::PermissionDenied);
        }
        Ok(ProcessIdentity::system(1))
    } else {
        Ok(caller)
    }
}

fn spawn_elf_image(elf_bytes: &[u8], arg_ptr: u64, arg_len: u64, idx_or_tag: u64) -> u64 {
    /// prog_name 末段长度上限（超长拒绝，防注册表/日志被撑爆）。
    const PROG_NAME_MAX_LEN: usize = 63;
    /// 命令行缓冲容量。KM5：超出即 E2BIG 显式失败——静默截断会把被裁剪的
    /// 命令行伪装成完整交付。
    const CMD_BUF_BYTES: usize = 512;
    if arg_len as usize > CMD_BUF_BYTES {
        return pack_err(Error::ArgListTooLong);
    }
    // 拷命令行到内核缓冲（带 SMAP 安全的 copy_from_user）。空命令行 → 正常启动。
    let mut cmd = [0u8; CMD_BUF_BYTES];
    let cmd_len = if arg_len == 0 {
        0
    } else {
        // E2BIG 守卫已保证 arg_len ≤ CMD_BUF_BYTES，此处不再截断。
        let l = arg_len as usize;
        // 命令行缓冲同样经预校验（AR1）：野指针在此返回 EFAULT 而非内核态
        // #PF 停机。
        if let Err(e) = validate_user_range(arg_ptr, l as u64, UserAccess::Read) {
            return pack_err(e);
        }
        unsafe {
            arch_x86_64::mmio::copy_from_user(cmd.as_mut_ptr(), arg_ptr, l);
        }
        l
    };
    let cmd = &cmd[..cmd_len];
    // C1.1：程序名取自真实加载来源（VFS 路径末段或内建索引名），非 pid 推断。
    let prog_name: alloc::string::String = match idx_or_tag {
        BUILTIN_INDEX_INIT => alloc::string::String::from("init.elf"),
        BUILTIN_INDEX_SHELL => alloc::string::String::from("shell.elf"),
        // 路径字符串模式：idx_or_tag 即用户态路径指针。
        _ => {
            let path = match copy_path_from_user(idx_or_tag, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            let trimmed = path.trim_end_matches('\0');
            let last = trimmed
                .rsplit('/')
                .find(|seg| !seg.is_empty())
                .unwrap_or(trimmed);
            if last.is_empty() || last.len() > PROG_NAME_MAX_LEN {
                return pack_err(Error::InvalidParam);
            }
            alloc::string::String::from(last)
        }
    };
    let Ok(mut us) = mm::user_space::UserAddressSpace::<arch_x86_64::paging::X86PageTable>::new()
    else {
        return pack_err(Error::OutOfMemory);
    };
    let loaded = match loader::load(elf_bytes, &mut us, cmd) {
        Ok(l) => l,
        Err(e) => return pack_err(e),
    };
    // exec 派生的是**当前调用进程的子进程**（C7.1）：登记真实 ppid，
    // 使 waitpid/退出码交付对 shell 前台等待等场景成立。
    let parent_pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    // 管道方案 A：子进程继承父进程 fd 表（含 pipe 端）。克隆表并为每个
    // Pipe { id } 递增引用计数，使子进程继承的 pipe 端也持有一个 ref。
    let inherited = match current_proc_mut() {
        Some(parent) => match clone_inherited_fd_table(parent) {
            Ok(t) => Some(t),
            // 引用计数上限不可达的极端防御：如实上抛而非静默丢表。
            Err(e) => return pack_err(e),
        },
        None => None,
    };
    // A1 / ADR-033 (V2 fix): 子进程身份经单点决策 compute_child_identity。
    // init 内建索引仅 System 调用者可派生 System/uid=1；User 调用者被拒（PermissionDenied）。
    let caller = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    let child_identity = match compute_child_identity(idx_or_tag, caller) {
        Ok(id) => id,
        Err(e) => return pack_err(e),
    };
    // ADR-034 PRE-3：exec 时把信号 restorer 装进本进程用户地址空间保留区，
    // 记录 trampoline 地址（handler 返回后经 restorer 调 rt_sigreturn）。
    // 安装失败如实上抛——不静默缺 restorer 造成 handler 投递时无法恢复现场。
    let trampoline = match us.install_signal_restorer() {
        Ok(addr) => addr,
        Err(_) => return pack_err(Error::OutOfMemory),
    };
    match task::spawn_with_ppid_fds(
        parent_pid,
        &prog_name,
        loaded.entry,
        loaded.user_stack_top,
        us,
        trampoline,
        inherited,
        child_identity,
    ) {
        Ok(pid) => {
            klib::info!(
                "[syscall] exec prog={} -> pid={} (ppid={}) entry={:#x}",
                prog_name,
                pid,
                parent_pid,
                loaded.entry
            );
            pack_ok(pid as u64)
        }
        Err(e) => pack_err(e),
    }
}

/// 克隆当前进程 fd 表供子进程继承，并对每个 `Pipe { id }` 端递增引用计数。
///
/// 返回克隆表；pipe 端引用计数同步递增，保证子进程继承后该管道在父进程
/// 关闭/退出后仍存活（UAF 防线）。任意 pipe_ref_inc 失败（引用计数回绕上限）
/// 即如实上抛——绝不静默丢表造成子进程缺句柄。
fn clone_inherited_fd_table(
    parent: &mut task::process::Process<arch_x86_64::paging::X86PageTable>,
) -> Result<alloc::vec::Vec<Option<vfs::file_handle::OpenHandle>>, Error> {
    let table = parent.clone_fd_table();
    // 克隆后为每个 pipe 端递增引用（记下已增项，失败即回滚）。
    let mut incd: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    for slot in table.iter() {
        if let Some(vfs::file_handle::OpenHandle::Pipe { id }) = slot {
            if ipc::pipe_ref_inc(*id).is_err() {
                for done in incd {
                    let _ = ipc::pipe_ref_dec(done);
                }
                return Err(Error::NoSpace);
            }
            incd.push(*id);
        }
    }
    Ok(table)
}

/// `mmap(size)`：在当前进程用户空间预留一段按需分页区，返回起始地址。
fn sys_mmap(frame: &mut SyscallFrame) -> u64 {
    let size = frame.a1;
    let flags = frame.a2;
    let shared_id = frame.a3;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    // ADR-014 §4.2 共享语义：`shared_id != 0` 映射指定共享内存对象（旧
    // SYS_SHM_MAP 合并）；`flags & MEM_MAP_SHARED` 新建共享对象并映射（旧
    // SYS_SHM_CREATE 合并）。二者返回起始虚拟地址。均经 `ipc::shm_*` 路径，
    // 不再把 shared_id 静默忽略成匿名映射。
    if shared_id != 0 {
        let addr_space = proc.addr_space();
        return match ipc::shm_map::<arch_x86_64::paging::X86PageTable>(shared_id, addr_space) {
            Ok(vaddr) => pack_ok(vaddr),
            Err(e) => {
                klib::info!("[mmap] shm_map id={} failed: {:?}", shared_id, e);
                pack_err(Error::NotFound)
            }
        };
    }
    if flags & MEM_MAP_SHARED != 0 {
        // 新建共享对象并映射（旧 SHM_CREATE 合并路径）。对象 id 由 QUERY 按
        // 地址反查（同 MEM_MAP_SHARED 语义）；此处只负责建+映射。
        let new_id = match ipc::shm_create(size) {
            Ok(id) => id,
            Err(e) => return pack_err(e),
        };
        let addr_space = proc.addr_space();
        return match ipc::shm_map::<arch_x86_64::paging::X86PageTable>(new_id, addr_space) {
            Ok(vaddr) => pack_ok(vaddr),
            Err(e) => {
                // 映射失败则销毁刚建的对象，避免悬挂（诚实回滚）。
                let _ = ipc::shm_destroy(new_id);
                klib::info!("[mmap] shm_create+map failed: {:?}", e);
                pack_err(Error::NoSpace)
            }
        };
    }
    let pf = PageFlags::empty().writable().user();
    match proc.addr_space().mmap_user(size, pf) {
        Ok(addr) => pack_ok(addr),
        Err(e) => pack_err(e),
    }
}

/// `munmap(addr, size)`：释放当前进程的一段 mmap 地址区间（匿名或共享）。
///
/// ABI 使用 `rdi=addr`、`rsi=size`。地址必须 4KiB 粒度。若 `addr` 命中本进程
/// 已映射的共享内存对象（ADR-014 共享语义），则走 `ipc::shm_unmap` 解除该
/// 对象映射（引用归零即回收帧）；否则走匿名 `munmap_anonymous`。
fn sys_munmap(frame: &mut SyscallFrame) -> u64 {
    let addr = frame.a1;
    let size = frame.a2;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    // 共享优先：查本进程 shm_maps 是否有以 `addr` 起始的对象映射。
    let shared_id = proc
        .addr_space()
        .shm_maps()
        .iter()
        .find(|m| m.vaddr == addr)
        .map(|m| m.id);
    if let Some(id) = shared_id {
        return match ipc::shm_unmap::<arch_x86_64::paging::X86PageTable>(id, proc.addr_space()) {
            Ok(_) => {
                klib::info!("[munmap] shm_unmap id={} at {:#x}", id, addr);
                pack_ok(0)
            }
            Err(_) => pack_err(Error::NotFound),
        };
    }
    match proc.addr_space().munmap_anonymous(addr, size) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `memory_query(addr, out_ptr)`（KM2：SYS_MEMORY_QUERY / 0x22）。
///
/// libsys 契约早已声明该调用号而内核分发表缺席——用户调用落入 unknown-nr，
/// 属"契约有了、实现缺席"。本实现查询 `addr` 所在 4KB 页的页表真值并写入
/// `out_ptr`（8 字节 u64 位图，须为可写用户缓冲）：
/// - 位图值 `0` = 未映射（含 demand 区已声明但未触碰——查询只读页表，
///   绝不触发补页）；
/// - `MEMQ_PRESENT | [MEMQ_USER] | [MEMQ_WRITABLE]` = 已映射页的实际属性。
///
/// 位值与 libsys `nr::MEMQ_*` 双侧定义、注释互指（同 STREAM_OFFSET_CURRENT
/// 模式：内核不依赖用户态 crate）。
fn sys_memory_query(frame: &mut SyscallFrame) -> u64 {
    /// 查询结果位图：页表项 present。
    const MEMQ_PRESENT: u64 = 1 << 0;
    /// 查询结果位图：用户态可访问。
    const MEMQ_USER: u64 = 1 << 1;
    /// 查询结果位图：可写。
    const MEMQ_WRITABLE: u64 = 1 << 2;
    /// out_ptr 指向的位图字节数（u64）。
    const OUT_LEN: u64 = 8;

    let addr = frame.a1;
    let out_ptr = frame.a2;

    if let Err(e) = validate_user_range(out_ptr, OUT_LEN, UserAccess::Write) {
        return pack_err(e);
    }
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let bits = match proc.addr_space().query_page(addr) {
        Some(q) => {
            let mut b = MEMQ_PRESENT;
            if q.user {
                b |= MEMQ_USER;
            }
            if q.writable {
                b |= MEMQ_WRITABLE;
            }
            b
        }
        None => 0,
    };
    unsafe {
        arch_x86_64::mmio::copy_to_user(out_ptr, bits.to_le_bytes().as_ptr(), OUT_LEN as usize);
    }
    pack_ok(0)
}

/// `brk(new)`：调整当前进程堆断点（0 = 仅查询）。
fn sys_brk(frame: &mut SyscallFrame) -> u64 {
    let new = frame.a1;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.addr_space().brk(new) {
        Ok(b) => pack_ok(b),
        Err(e) => pack_err(e),
    }
}

/// `task_wait(target_pid, timeout_ns)` (ADR-014: SYS_TASK_WAIT / 0x32)
/// - target_pid == 0 && timeout_ns == 0: yield_now 主动让出 CPU
/// - target_pid == 0 && timeout_ns > 0: sleep 精准时钟挂起睡眠
/// - target_pid > 0: waitpid——等待**自己的直接子进程**退出（C7.1/#7）：
///   子已 zombie → 同步收尸返回其真实退出码；子仍在运行 → 真阻塞（Blocked），
///   返回 [`DispatchResult::Switched`]——子进程 exit 时内核把退出码写入本
///   进程保存帧 rax 并唤醒，iretq 后用户态直接拿到；入口禁止回写占位值。
///   目标非亲生/不存在/已收尸 → `NotFound`（errno 2，klib 错误表无 ECHILD
///   的最近语义）；无其他就绪进程可切时拒绝阻塞 → `WouldBlock`。
fn sys_task_wait(frame: &mut SyscallFrame) -> DispatchResult {
    let target_pid = frame.a1 as usize;
    let timeout_ns = frame.a2;

    if target_pid == 0 && timeout_ns == 0 {
        // K1b/KA6：yield_now 返回 Switched 时 `*frame` 已被整体替换为下一进程
        // 保存帧（yield 返回值 0 由调度器写入被保存帧，scheduler.rs），此处若再以
        // Done(0) 收尾会把 rax=0 写穿目标进程现场。枚举强制穷尽匹配，漏翻
        // 编译期即不可能；NotSwitched 才是普通的 Done(0)。
        match task::yield_now(arch_frame(frame)) {
            task::SwitchOutcome::Switched => return DispatchResult::Switched,
            task::SwitchOutcome::NotSwitched => return done(pack_ok(0)),
        }
    }

    if target_pid == 0 && timeout_ns > 0 {
        // ADR-014 §4.3：`SYS_TASK_WAIT(0, timeout)` 的语义是"精准时钟挂起
        // 睡眠"（挂起，而非忙等）。原实现直接 `klib::time::sleep_nanos` 在
        // 内核态自旋忙等——klib time.rs 注释自陈"当前无调度器，只能忙等"；
        // 而 ADR-017 的 CPL 门控又使 tick 无法抢占内核态（`cs&3!=3` 直接
        // return），于是后台 `sleep &` 会占死 CPU，前台进程被彻底饿死。
        // 改用"注册定时器到期唤醒 + 调度器显式阻塞原语挂起本进程"——主动
        // 切换原语（block/yield/exit）与"被动抢占仅限用户态"正交（ADR-017
        // §决策），进程挂起不占 CPU，前台进程得以正常调度。
        return sleep_blocking(frame, timeout_ns);
    }

    match task::waitpid(target_pid, arch_frame(frame)) {
        Ok(task::Waited::Reaped { pid, code }) => {
            // 同步收尸：rax 交付退出码（既有语义），r10 经 aux_pid 交付被收尸
            // 子进程 pid——架构层在写回 rax 的同时把 aux_pid 写进返回帧 r10，
            // 与阻塞路径 `saved.r10=pid` 交付对齐，waitpid 两条路径一致返回
            // (rax=code, r10=pid)。
            frame.aux_pid = pid as u64;
            done(pack_ok(code))
        }
        Ok(task::Waited::Blocked) => DispatchResult::Switched,
        Err(e) => done(pack_err(e)),
    }
}

/// thread_spawn 处理器（T1-7 / SYS_TASK_THREAD_SPAWN / 0x35）：在调用方线程组内
/// 派生一个同组新调度单元（线程）。以调用方自身进程的 tgid（组长 pid）为组长调
/// `task::spawn_thread_with`，复用其 Arc 地址空间/组容器。参数为裸 u64（PRE-6）：
/// - `a1` = 线程入口 RIP；
/// - `a2` = 线程用户栈顶（用户态已 mmap 的独立栈区）；
/// - `a3` = （可选，T2-0/ADR-035 D6）初始 rdi（starter 指针）：供 libc/libpthread 线程引导
///   经 `initial_frame` 把 starter 块地址置入新线程首跑 `rdi`，据此定位其 TCB/参数。
///   默认 0（兼容 T1 无引导调用：现有 threaddemo 等不传 a3 → 首跑 rdi=0）。
/// name 固定传字面量 `"thread"`（经 `store_name` 拷入 PCB 定长缓冲，无 copyin/无越界）。
/// 返回组员 pid（rax）；不阻塞（永不 Switched）。组长不存在/已退 → NotFound，分配失败 → OutOfMemory。
/// 借用在进入 `task::*` 前释放（task1 KA3：先取 tgid 值再调 spawn_thread_with）。
fn sys_thread_spawn(frame: &mut SyscallFrame) -> u64 {
    let entry = frame.a1;
    let user_stack_top = frame.a2;
    // T2-0：a3 = 初始 rdi（starter/TCB 引导指针），经 initial_frame 置入新线程首跑 rdi。
    let starter = frame.a3;
    // 先取 tgid（借用立即结束），随后释放借用再调 spawn_thread_with（KA3：借用不跨越调度调用）。
    let Some(tgid) = current_proc_mut().map(|p| p.tgid()) else {
        return pack_err(Error::NotFound);
    };
    match task::spawn_thread_with(tgid, "thread", entry, user_stack_top, starter) {
        Ok(tid) => {
            klib::info!(
                "[syscall] thread_spawn leader={} -> tid={} entry={:#x} stack={:#x}",
                tgid,
                tid,
                entry,
                user_stack_top
            );
            pack_ok(tid as u64)
        }
        Err(e) => pack_err(e),
    }
}

/// `set_fs_base` 处理器（T2-1 / SYS_TASK_SET_FS_BASE / 0x37）：把当前运行线程的 `IA32_FS_BASE`
/// 设为 `a1`。仅写活动 FS base（wrmsr，CPL0）；每线程跨切换保存/恢复已由 T2-0 在切换点
/// rdmsr/wrmsr 负责，故下一次切出即自动归档进 `ProcEntry.fs_base`。用户传入的 `base` 是其自有
/// `Tcb` 的地址（用户虚拟地址），属线程自有的每线程控制块，内核不校验有效性（写坏只影响调用
/// 线程自身，与用户任选栈顶/堆地址同级，非安全边界）。返回 0。永不 Switched。
fn sys_set_fs_base(frame: &mut SyscallFrame) -> u64 {
    let base = frame.a1;
    // 内核 CPL0 写当前 CPU 的 FS base（wrmsr）；当前即运行本 syscall 的线程。
    arch_x86_64::gdt::write_fs_base(base);
    pack_ok(0)
}

/// `gettid` 处理器（T2-6 / SYS_TASK_GETTID / 0x38）：返回调用线程自己的 pid（线程 id）。
/// 每线程 = 一 ProcEntry/pid；组长 pid==tgid、组员 pid==线程 id。取当前线程的 pid 即可，
/// 无副作用、永不 Switched。
fn sys_gettid(_frame: &mut SyscallFrame) -> u64 {
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    pack_ok(pid as u64)
}

/// `getpid` 处理器（T2-6 / SYS_TASK_GETPID / 0x39）：返回调用线程所在进程（线程组）的组长
/// pid（POSIX 进程 id / tgid）。每线程共享同一 tgid。
fn sys_getpid(_frame: &mut SyscallFrame) -> u64 {
    let tgid = current_proc_mut().map(|p| p.tgid()).unwrap_or(0);
    pack_ok(tgid as u64)
}

/// thread_join 处理器（T1-7 / SYS_TASK_THREAD_JOIN / 0x36）：等价组长对**具体组员
/// pid** 的 waitpid 收尸取退出码（T1-3 单目标 join 交付）。薄委托 `task::waitpid`，
/// 与 `sys_task_wait` 单目标分支同构：
/// - 组员已 zombie → 同步收尸，rax 交付退出码、r10 经 aux_pid 交付组员 pid；
/// - 组员仍在运行 → 真阻塞切换（DispatchResult::Switched，禁写 rax——退出码由组员
///   终止路径写入本进程保存帧 rax/r10，唤醒后 iretq 即得）；
/// - 目标非亲生/不存在/已收尸（组员 ppid = 组长，故仅组长可 join 其组员；非组长调
///   目标自然 NotFound）→ NotFound。
fn sys_thread_join(frame: &mut SyscallFrame) -> DispatchResult {
    let tid = frame.a1 as usize;
    match task::waitpid(tid, arch_frame(frame)) {
        Ok(task::Waited::Reaped { pid, code }) => {
            // 同步收尸：与 sys_task_wait 同款——rax=code、r10 经 aux_pid 交付组员 pid。
            frame.aux_pid = pid as u64;
            done(pack_ok(code))
        }
        Ok(task::Waited::Blocked) => DispatchResult::Switched,
        Err(e) => done(pack_err(e)),
    }
}

/// 精准时钟挂起睡眠（ADR-014 §4.3 `SYS_TASK_WAIT(0, timeout)`）：注册定时器
/// 到期唤醒 + 调度器显式阻塞原语挂起本进程，取代内核态忙等。
///
/// 优雅路径：`set_timeout` 注册成功且就绪队列有其它进程（可阻塞切换）→
/// 阻塞挂起，定时器到期由 `task::wake` 唤醒（tick 中断驱动 `poll_timeouts`
/// 触发）。退化路径（定时器表满 / 就绪队列空无法阻塞 / 时钟未就绪）退化为
/// 忙等 `sleep_nanos`，保证 sleep 语义不丢——就绪队列空时本进程是唯一执行
/// 体，忙等占 CPU 无害。
///
/// lost-wakeup 论证（与 `block_current_with` 的 register 复检语义一致）：
/// 定时器到期触发 `task::wake` 时，`poll_timeouts` 的条件是 `deadline <= now`，
/// 故 wake 执行时刻必然 `now >= deadline`；此时进程尚未 Blocked（wake 会因
/// 非 Blocked 而被忽略）。register 复检 `now < deadline` 因此必然为 false，
/// 判定"不阻塞"，杜绝"定时器已触发却仍阻塞而永睡"的窗口。正常情形
/// `now < deadline`（wake 未触发）→ register 为 true → 阻塞，之后定时器
/// 触发 wake 正确唤醒。
fn sleep_blocking(frame: &mut SyscallFrame, timeout_ns: u64) -> DispatchResult {
    if !klib::time::clock_ready() {
        // 时钟未注入（启动早期兜底，klib time.rs S09）：忙等语义不变。
        klib::time::sleep_nanos(timeout_ns);
        return done(pack_ok(0));
    }
    let deadline = klib::time::now_nanos()
        .expect("clock_ready checked")
        .saturating_add(timeout_ns);
    // 当前 pid：供定时器到期回调唤醒本进程。借用在进入 `block_current_with`
    // 之前立即结束并释放引用，不跨越调度切换——符合 CURRENT_PROC 别名纪律
    // （task1 KA3：借用不得跨越任何可能改写 CURRENT_PROC 的调度调用）。
    let Some(cur_pid) = current_proc_mut().map(|p| p.pid()) else {
        return done(pack_err(Error::NotFound));
    };
    // 注册一次性定时器，到期以 `task::wake(cur_pid)` 唤醒本进程。
    // 回调在 tick 中断的 `poll_timeouts`（锁外）执行，取调度 per-pid 锁安全。
    if klib::time::set_timeout(timeout_ns, task::wake, cur_pid).is_none() {
        // 定时器表满（klib time.rs：有界静态槽位，MAX_TIMERS）：退化忙等，
        // 不丢 sleep 语义。
        klib::time::sleep_nanos(timeout_ns);
        return done(pack_ok(0));
    }
    // 原子阻塞：register 在调度锁内复检 deadline，消除 lost-wakeup。
    let register = &mut || klib::time::now_nanos().map_or(false, |n| n < deadline);
    match task::block_current_with(arch_frame(frame), register) {
        task::SwitchOutcome::Switched => DispatchResult::Switched,
        task::SwitchOutcome::NotSwitched => {
            // 就绪队列空 / 仅自身（阻塞会自锁），或 deadline 已过（定时器已
            // 触发）：退化为忙等剩余时间（deadline 已过时立即返回，占 CPU 无害）。
            klib::time::sleep_nanos(timeout_ns);
            done(pack_ok(0))
        }
    }
}

/// `exit(code)`：终止当前进程并调度到下一个就绪进程（多进程场景）。
///
/// 经 `scheduler::exit_current(frame, code)` 统一终止核心处理：有活父且父
/// 阻塞 waitpid 时交付退出码并唤醒父，否则 zombie 保留/按无父回收。若还有
/// 就绪进程，改写 `frame` 为下一个就绪进程的保存帧；返回后 `syscall_entry`
/// 的 iretq 进入目标进程。若所有进程都退出则 idle halt 等待。返回值为填充
/// 占位（当前进程已死，实际由 iretq 接管）。
fn sys_exit(frame: &mut SyscallFrame) -> u64 {
    let code = frame.a1;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    klib::info!("[syscall] process {} exit(code={})", pid, code);
    task::exit_current(arch_frame(frame), code);
    0
}

/// POWER 域（ADR-036）公共停机动原：本 CPU 关中断 + 广播停机其它核。
///
/// 仿 panic 的 KA1 纪律（先关本核中断再停其它核），随后交给架构层做真正的
/// 断电/复位。调用后本 CPU 处于关中断且其它核已停的状态——只能走**终结**
/// 路径（断电/复位/永久停机），不可再返回调度。
fn power_prepare_terminal() {
    arch_x86_64::interrupts::disable();
    crate::halt_other_cpus_via_ipi();
}

/// `power_off()`（POWER 0x91）：请求 ACPI S5 软关机（整机断电）。
///
/// 属**特权**操作：仅 `Privilege::System` 进程可发起，否则 `PermissionDenied`。
/// S5 电源关停信息未就绪（无 PM1a / DSDT 无 `_S5`）时返回 `NotSupported`——
/// 我们**绝不**在无凭据下猜测 SLP_TYP 写端口（宁缺毋假）。
///
/// 就绪后为终结路径：停其它核 → 写 PM1 触发断电（`power_off` 永不返回，
/// 断电后 CPU 停止）。故本条从不带现场回到调用进程。
fn sys_power_off(_frame: &mut SyscallFrame) -> DispatchResult {
    let priv_ok = current_proc_mut()
        .map(|p| p.identity().privilege == Privilege::System)
        .unwrap_or(false);
    if !priv_ok {
        return done(pack_err(Error::PermissionDenied));
    }
    if !arch_x86_64::acpi::s5_ready() {
        klib::warn!("[syscall] power_off refused: S5 not ready");
        return done(pack_err(Error::NotSupported));
    }
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    klib::info!("[syscall] power_off by pid {}: halting CPUs then S5", pid);
    power_prepare_terminal();
    // power_off 写 PM1 后永久空转等待断电；不会正常返回。
    let _ = arch_x86_64::acpi::power_off();
    // 不可达：S5 写入后固件应断电。若固件异常未断电（理论上不会），在此停死。
    unreachable!("power_off returned without powering off");
}

/// `reboot()`（POWER 0x92）：请求系统复位重启。
///
/// 属**特权**操作：仅 `Privilege::System` 进程可发起，否则 `PermissionDenied`。
/// 走 ACPI reset 寄存器（若固件提供，QEMU 通常无）或 8042 快速复位（0x64←0xFE，
/// QEMU/SeaBIOS 均支持）。终结路径：停其它核 → 触发复位（`reboot` 永不返回）。
fn sys_reboot(_frame: &mut SyscallFrame) -> DispatchResult {
    let priv_ok = current_proc_mut()
        .map(|p| p.identity().privilege == Privilege::System)
        .unwrap_or(false);
    if !priv_ok {
        return done(pack_err(Error::PermissionDenied));
    }
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    klib::info!("[syscall] reboot by pid {}: halting CPUs then reset", pid);
    power_prepare_terminal();
    arch_x86_64::acpi::reboot();
    // 不可达：复位后 CPU 重启。
    unreachable!("reboot returned without resetting");
}

/// `kill(pid, sig) -> 0`：向进程发送信号（终止 / 校验存在）。
///
/// **自杀必须返回 [`DispatchResult::Switched`] 而非 `Done`**（S26 回归）：
/// `exit_current` 会把 `*frame` 整体改写为下一进程的保存帧并切走；若此处
/// 返回 `Done(0)`，`syscall_entry` 会置 `result=0`，架构层把 0 写回 `rax`
/// 覆盖**下一进程**的现场（把自杀进程的返回值写进别人家）。与 `sys_exit`
/// 同纪律：切换发生后返回值语义交由调度接管。
fn sys_kill(frame: &mut SyscallFrame) -> DispatchResult {
    let target = frame.a1 as usize;
    let sig = frame.a2 as u32;
    // 自杀判定：仅 SIGKILL 立即终止（exit_current 走标准退出路径并切换帧，
    // 返回 Switched）。非 SIGKILL 自杀（raise 语义）由 kill_pid 转本进程
    // pending，返回用户态时经 deliver_on_return 派发（S1-9）。init 自杀由
    // kill_pid 的 PID1 防护拒绝（此处不自行 exit，避免绕过防护）。
    let is_suicide_sigkill = {
        let cur = task::current_proc_mut().map(|p| p.pid());
        cur == Some(target) && sig == task::signals::SIGKILL && target != task::init_pid()
    };
    if is_suicide_sigkill {
        task::exit_current(arch_frame(frame), sig as u64);
        return DispatchResult::Switched;
    }
    match task::kill_pid(target, sig, arch_frame(frame)) {
        Ok(_) => done(pack_ok(0)),
        Err(e) => done(pack_err(e)),
    }
}


/// 旧处置 → ABI 返回值编码（0=Default、1=Ignore、其它为 handler 指针）。
fn encode_disposition(d: task::signal::SigDisposition) -> u64 {
    match d {
        task::signal::SigDisposition::Default => 0,
        task::signal::SigDisposition::Ignore => 1,
        task::signal::SigDisposition::Handler(p) => p,
    }
}

/// `signal_action(sig, handler, flags) -> 旧处置`（sigaction，ADR-034 §3.2）。
///
/// `handler`：0=SIG_DFL、1=SIG_IGN、其余为用户函数指针。返回旧处置（同样编码）。
/// SIGKILL/SIGSTOP 设非默认 → `InvalidParam`；越界信号号 → `OutOfRange`。
/// 本调用不触发投递（仅查/设处置，ADR-034 §2.3）。
fn sys_signal_action(frame: &mut SyscallFrame) -> u64 {
    use task::signal::SigDisposition;
    let sig = frame.a1 as u32;
    let handler = frame.a2;
    // flags 当前仅 0 接受（S2-1 sigaltstack 预留位）。
    if frame.a3 != 0 {
        return pack_err(Error::InvalidParam);
    }
    let disp = match handler {
        0 => SigDisposition::Default,
        1 => SigDisposition::Ignore,
        p => SigDisposition::Handler(p),
    };
    let cur = match task::current_proc_mut() {
        Some(p) => p,
        None => return pack_err(Error::NotSupported),
    };
    match cur.signal_mut().set_disposition(sig, disp) {
        Ok(Some(old)) => pack_ok(encode_disposition(old)),
        Ok(None) => pack_err(Error::InvalidParam), // 越界（不应达，validate 已拒）
        Err(e) => pack_err(e),
    }
}

/// `signal_return()`（rt_sigreturn，ADR-034 §2.5）：handler 返回后恢复原帧。
///
/// 从用户栈读回 SignalFrame（经 task::signal::sigreturn），恢复被打断的现场；
/// 成功后调用方照常 iretq 回原 RIP。帧损坏/越界 → `InvalidParam`。
fn sys_signal_return(frame: &mut SyscallFrame) -> u64 {
    let arch: &mut arch_x86_64::interrupts::InterruptFrame = arch_frame(frame);
    let cur = task::current_proc_mut();
    match task::signal::sigreturn(cur, arch) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// 返回用户态前派发待投递信号（ADR-034 §2.4 触发点：syscall 返回）。
///
/// 返回 `true` 表示当前进程继续（帧有效，可回写 syscall 结果）；`false` 表示
/// 进程已被默认动作终止并经 `exit_current` 切换（调度接管，不得回写 result）。
fn deliver_pending_signal(frame: &mut SyscallFrame) -> bool {
    // 仅对真实用户态返回帧做派发：kernel-tests 用合成 SyscallFrame（arch_frame 为
    // 0 或指向局部帧），无真实用户态返回帧可改写，跳过。用 `read_unaligned`
    // 读取 `cs`（代码段）判断是否用户态（cs & 3 == 3），避免对未对齐帧的
    // 对齐解引用 panic。
    if frame.arch_frame == 0 {
        return true;
    }
    // InterruptFrame.cs 偏移：15 个 GP 寄存器(120) + vector(8) + error_code(8)
    // + rip(8) = 144，cs 恰在 144；152 是 rflags。
    const CS_OFFSET: usize = 144;
    let cs: u64 = unsafe { core::ptr::read_unaligned((frame.arch_frame as *const u8).add(CS_OFFSET) as *const u64) };
    if cs & 3 != 3 {
        return true; // 非用户态返回帧（内核态/合成测试帧），无用户信号可派发。
    }
    // 廉价检查：当前进程有未决信号才触碰 arch_frame。
    let has_pending = task::current_proc_mut()
        .map(|p| !p.signal().pending().is_empty())
        .unwrap_or(false);
    if !has_pending {
        return true;
    }
    let arch: &mut arch_x86_64::interrupts::InterruptFrame = arch_frame(frame);
    let Some(cur) = task::current_proc_mut() else {
        return true; // 无当前进程（内核/idle 上下文），无用户信号可派发。
    };
    match task::signal::deliver_on_return(cur, arch) {
        task::signal::DeliveryOutcome::Continue => true,
        task::signal::DeliveryOutcome::Terminated => false,
    }
}

/// 用户态异常 → 信号投递处理器（S1-11，ADR-034 §2.8）。
///
/// 由 `interrupts::register_user_exception_handler` 在引导期注册，取代原先
/// "用户异常一律终止"的兜底：
/// - 映射 `sig = signal_for_exception(vector)`；
/// - 查处置：`Handler` → 携 siginfo（CR2/vector/error_code）投递并 iretq 进 handler；
///   `Ignore`/`Default` → 等价终止（防异常风暴，S30），`exit_current` 把帧改写为
///   下一进程现场后 iretq。
///
/// 返回 `true` 表示已处置（handler 入口 或 已切换到下一进程），架构层 iretq；
/// 返回 `false` 表示无法处置（无当前进程等致命情形），架构层停机。
pub extern "C" fn user_exception_signal_handler(
    cr2: u64,
    frame: &mut arch_x86_64::interrupts::InterruptFrame,
) -> bool {
    use task::signal::SigDisposition;
    let sig = task::signals::signal_for_exception(frame.vector);
    let Some(cur) = task::current_proc_mut() else {
        // 无当前进程（内核/idle 上下文）：停机。
        return false;
    };
    // SIGKILL/SIGSTOP 等硬信号不会到达 Handler 处置（validate 保证恒 Default）。
    match cur.signal().disposition(sig) {
        Some(SigDisposition::Handler(f)) => {
            let restorer = cur.signal().trampoline();
            if restorer == 0 {
                // 无 restorer（PRE-3 未装）：无法安全进 handler，终止兜底。
                task::exit_current(frame, sig as u64);
                return true; // exit_current 已改写帧为下一进程，iretq 切走
            }
            // SigInfo 字段契约：fault_addr 仅 #PF（vector 14）填 CR2 出错线性地址，
            // 其余异常 CR2 无意义填 0（见 SigInfo::fault_addr 文档；S4 整改）。
            let fault_addr = if frame.vector == 14 { cr2 } else { 0 };
            let siginfo = task::signal::SigInfo {
                sig,
                vector: frame.vector as u32,
                error_code: frame.error_code,
                fault_addr,
                pid: cur.pid() as u64,
            };
            if task::signal::deliver_handler(cur, frame, sig, f, siginfo, restorer) {
                return true; // 已改写帧为 handler 入口，iretq 进用户 handler
            }
            // 用户栈写帧失败（越界/不可写）：无法安全投递，终止兜底。
            task::exit_current(frame, sig as u64);
            return true;
        }
        // Ignore → 对同步异常等价 Default 终止（防异常风暴，S30）；
        // Default → 终止（现状）；越界防御同样终止。
        _ => {
            task::exit_current(frame, sig as u64);
            return true; // exit_current 已改写帧为下一进程，iretq 切走
        }
    }
}

/// `signal_mask(how, set) -> 旧屏蔽集`（sigprocmask，ADR-034 §3.2）。
///
/// `how`：0=SET、1=BLOCK、2=UNBLOCK。返回旧屏蔽集（u64 位图）。
/// SIGKILL 不可屏蔽（强制清位）；SIGSTOP 位保留。越界 how → `InvalidParam`。
fn sys_signal_mask(frame: &mut SyscallFrame) -> u64 {
    let how = frame.a1 as u32;
    let set = task::signal_set::SignalSet(frame.a2);
    let cur = match task::current_proc_mut() {
        Some(p) => p,
        None => return pack_err(Error::NotSupported),
    };
    match cur.signal_mut().mask(how, set) {
        Ok(old) => pack_ok(old.bits()),
        Err(e) => pack_err(e),
    }
}
/// UIO/DEVICE 特权门禁（ADR-037 决策 5）：当前进程是否 `Privilege::System`。
///
/// `driver_register`/`driver_claim` 直接授予设备认领与 MMIO 映射（内核级权限），
/// 非 System 一律 `PermissionDenied`。单点判定，供本族特权 syscall 复用（S13：
/// 权限语义成文、不重复硬编码）。`driver_query`(读) / `driver_unregister`(释放自身
/// 持有) 不授予 MMIO，故不在门禁内。
fn current_is_system() -> bool {
    current_proc_mut()
        .map(|p| p.identity().privilege == Privilege::System)
        .unwrap_or(false)
}

/// `driver_register(name_ptr, len) -> uio_id` (M11.1)
fn sys_driver_register(frame: &mut SyscallFrame) -> u64 {
    if !current_is_system() {
        return pack_err(Error::PermissionDenied);
    }
    let name_ptr = frame.a1 as *const u8;
    let len = frame.a2 as usize;
    if len == 0 || len > 32 {
        return pack_err(Error::InvalidParam);
    }
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    let mut name_buf = [0u8; 32];
    // 设备名缓冲同样经预校验（AR1）：野指针返回 EFAULT 而非内核态 #PF 停机。
    if let Err(e) = validate_user_range(name_ptr as u64, len as u64, UserAccess::Read) {
        return pack_err(e);
    }
    unsafe {
        arch_x86_64::mmio::copy_from_user(name_buf.as_mut_ptr(), name_ptr as u64, len);
    }
    let dev_name = match core::str::from_utf8(&name_buf[..len]) {
        Ok(s) => s,
        Err(_) => return pack_err(Error::InvalidParam),
    };
    // KA4：注册即唯一认领声明——签名不再携带 MMIO 坐标（设备物理资源是
    // 内核登记事实，不是用户可自报字段）。
    match driver::uio_register_driver(pid, dev_name) {
        Ok(id) => pack_ok(id as u64),
        Err(e) => pack_err(e),
    }
}

/// `driver_claim(uio_id, mmio_base, size) -> user_vaddr` (M11.1)
///
/// K2 + KA4 完整闭环：
/// ① 授权半程——`uio_id` 精确定位 + 调用者归属校验（NotFound / PermissionDenied）；
/// ② 映射半程——从内核登记表解析该设备的 MMIO 物理窗口（用户自报的
///    `mmio_base/size` 参数**从不具效力**），经 `map_mmio_user` 以不可缓存
///    页真实映射进当前进程地址空间，返回用户虚拟地址。
/// 设备未发布窗口（如无 MMIO BAR 的设备）→ NotSupported；窗口映射失败按
/// mm 错误如实上抛。绝不以匿名内存伪装映射成功。
fn sys_driver_claim(frame: &mut SyscallFrame) -> u64 {
    if !current_is_system() {
        return pack_err(Error::PermissionDenied);
    }
    let uio_id = frame.a1 as usize;
    let _mmio_base = frame.a2;
    let _size = frame.a3;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    // 授权半程：id 存在性 + 归属校验。
    if let Err(e) = driver::uio_claim_device(uio_id, pid) {
        klib::info!(
            "[uio] driver_claim({}) denied for pid={}: {:?}",
            uio_id,
            pid,
            e
        );
        return pack_err(e);
    }
    // 从登记表取该设备（= 认领的设备名）的真实 MMIO 窗口。
    let Some((phys, len)) = driver::uio_device_window_of(uio_id) else {
        klib::info!(
            "[uio] driver_claim({}) authorized but device publishes no MMIO window",
            uio_id
        );
        return pack_err(Error::NotSupported);
    };
    // 映射半程：设备帧 → 用户空间（PCD 不可缓存）。
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.addr_space().map_mmio_user(phys, len) {
        Ok(vaddr) => {
            klib::info!(
                "[uio] claim mapped: pid={} uio_id={} phys={:#x} len={:#x} -> user {:#x}",
                pid,
                uio_id,
                phys,
                len,
                vaddr
            );
            pack_ok(vaddr)
        }
        Err(e) => {
            klib::info!("[uio] claim mapping failed: {:?}", e);
            pack_err(e)
        }
    }
}

/// `driver_query(dev_name_ptr, out_json_ptr, cap) -> len` (ADR-014 0x52)
///
/// 查询设备绑定状态（READ）：输出紧凑 JSON 到用户缓冲。
/// - 设备不存在 → `{"error":"not_found","device":"<name>"}`；
/// - 已真实接管（驱动绑定 + controls_hardware）→
///   `{"device":"<name>","binding":"driver:<name>","uio_claimed":<bool>}`；
/// - 竞标胜出未接管（candidate-only）→
///   `{"device":"<name>","binding":"candidate:<name>(unimplemented)","uio_claimed":<bool>}`。
/// `uio_claimed` 如实反映该设备是否已被用户态驱动（UIO）活跃认领。放不下
/// 完整 JSON 时按 `InvalidParam` 拒绝（宁缺毋假，不截断交付半截 JSON）。
fn sys_driver_query(frame: &mut SyscallFrame) -> u64 {
    let name_ptr = frame.a1;
    let out_ptr = frame.a2;
    let cap = frame.a3 as usize;

    const MAX_QUERY_OUT_BYTES: usize = 512;
    if cap > MAX_QUERY_OUT_BYTES {
        return pack_err(Error::InvalidParam);
    }

    // 拷贝设备名（NUL 结尾，上限 UIO 名长 32）。
    let name = match copy_path_from_user(name_ptr, driver::uio::UIO_DEV_NAME_MAX) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    if name.is_empty() {
        return pack_err(Error::InvalidParam);
    }

    let mut target = klib::json::VecTarget::new();
    let mut writer = klib::json::JsonWriter::new(&mut target);
    // 枚举 DriverHub 找设备并判定绑定态。
    let mut found = false;
    let count = driver::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = driver::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.name != name.as_str() {
            continue;
        }
        found = true;
        let claimed = driver::uio_is_device_claimed(&name);
        let binding = if driver::DriverHub::device_driver_is_candidate(i) {
            alloc::format!("candidate:{}(unimplemented)", info.name)
        } else if let Some(d) = driver::DriverHub::device_driver_at(i) {
            alloc::format!("driver:{}", d)
        } else {
            alloc::string::String::from("unbound")
        };
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("device", &name)?;
                o.field_str("binding", &binding)?;
                o.field_bool("uio_claimed", claimed)?;
                o.end()
            })
            .expect("Vec-backed query JSON cannot fail");
        break;
    }
    if !found {
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("error", "not_found")?;
                o.field_str("device", &name)?;
                o.end()
            })
            .expect("Vec-backed query JSON cannot fail");
    }
    let bytes = target.as_bytes();
    let n = bytes.len();
    if n == 0 || n > cap {
        return pack_err(Error::InvalidParam);
    }
    if let Err(e) = validate_user_range(out_ptr, n as u64, UserAccess::Write) {
        return pack_err(e);
    }
    unsafe {
        arch_x86_64::mmio::copy_to_user(out_ptr, bytes.as_ptr(), n);
    }
    pack_ok(n as u64)
}

/// `device_probe(name_ptr) -> ProbeStatus`（DEVICE 域 0x58，ADR-030 热插拔兜底）。
///
/// 对指定块设备做一次**缓存穿透探测读**（绕过 VFS 页缓存，直接触达底层驱动
/// 真实访问设备）。若设备已消失（拔盘/后端移除），驱动在 `read_at` 内部经
/// `is_device_gone` + `notify_device_gone` 发布 `DeviceDeparted`（热插拔闭环）。
/// `volumed` 低频对账用它兜底发现"拔除但无事件"的空闲卷。
///
/// 返回 `ProbeStatus` 数值：`Alive=0` / `Gone=1` / `NotFound=2` / `NotIo=3`。
/// 不做缓存、不创建文件，一次性真实读；调用方（volumed）低频调用（秒级/分钟级
/// 对账），不构成高频轮询。
fn sys_device_probe(frame: &mut SyscallFrame) -> u64 {
    const MAX_NAME: usize = 256;
    let Ok(name) = copy_path_from_user(frame.a1, MAX_NAME) else {
        return pack_err(Error::InvalidParam);
    };
    match driver::DriverHub::probe_io_device(&name) {
        driver::ProbeStatus::Alive => pack_ok(0),
        driver::ProbeStatus::Gone => pack_ok(1),
        driver::ProbeStatus::NotFound => pack_ok(2),
        driver::ProbeStatus::NotIo => pack_ok(3),
    }
}

/// `driver_event_next(buf_ptr, cap, timeout_ns) -> len`（P2-2/interrupt-to-futex，
/// DEVICE 域 0x57）。
/// 消费**下一条**硬件拓扑事件（`driver::event::DeviceEvent`：DeviceArrived /
/// DeviceDeparted），序列化为 JSON 写入用户缓冲，返回写出长度；无待消费事件且
/// `timeout_ns == 0` 时返回 `0`（非阻塞空）。`timeout_ns > 0` 时为**阻塞等待**：
/// 队列空则挂起本进程，直到事件到达（`driver::event::publish_event` 经回调唤醒）
/// 或超时到期，随后重试取事件——这是 ADR-030 §决策3 的 interrupt-to-futex：
/// 设备注册/拔除中断直达用户态等待者，取代 volumed 的有界休眠轮询。
///
/// **S09 诚实**：无事件返回 0（空），绝不编造事件；事件种类/设备名都来自
/// `DeviceInfo` 真实描述符。错误码口径：`cap` 超过内部上限（512）→
/// [`Error::InvalidParam`]；**事件 JSON 长度超过 `cap` → [`Error::NoSpace`]，
/// 事件不被消费**（[`driver::event::peek_event`] 先量测再 pop，避免缓冲不足时
/// 事件永久丢失，S18）。与 `sys_driver_query` 的 `n>cap→InvalidParam` 口径
/// 不同：本处事件是"一次性的"，丢不得，故用 `NoSpace` 且不消费。
///
/// **单消费者前提**：peek（量测）+ pop（消费）是两次独立锁临界区，非原子对。
/// 跨调用者并发存在 TOCTOU 错配面（见 driver::event 头注释）。当前唯一消费者
/// 是 `volumed`（单进程单线程顺序排空），错配不可达；阻塞等待经 `EVENT_WAITER`
/// 登记唯一等待者（同 KBD_WAITER 单读者仲裁，并发第二个等待者返回 WouldBlock）。
fn sys_driver_event_next(frame: &mut SyscallFrame) -> DispatchResult {
    const MAX_EVENT_BYTES: usize = 512;
    // 阻塞等待的超时上界（S31 对抗输入边界）：1 小时。设备事件等待是短时
    // 驱动的（volumed 用 1s 周期对账）；超长 timeout 只会占住一个定时器槽
    // 直到其远未来 deadline（且被 V2 提前返回/V3 被杀时取消），但对调用方
    // 无真实收益，故显式拒绝，避免把 u64::MAX 之类对抗值当合法超时吞下。
    const MAX_WAIT_TIMEOUT_NS: u64 = 3_600_000_000_000; // 1h
    let out_ptr = frame.a1;
    let cap = frame.a2 as usize;
    let timeout_ns = frame.a3;
    if cap > MAX_EVENT_BYTES {
        return done(pack_err(Error::InvalidParam));
    }
    if timeout_ns > MAX_WAIT_TIMEOUT_NS {
        return done(pack_err(Error::InvalidParam));
    }
    // 先窥视不消费：量测 JSON 长度，cap 不足时事件留在队列（调用方加大缓冲
    // 重试仍能取回）——绝不"先消费再因装不下而丢弃"（S18 事件不丢失）。
    if let Some(ev) = driver::event::peek_event() {
        return done(driver_event_serialize(&ev, out_ptr, cap));
    }
    // 无待消费事件。
    if timeout_ns == 0 {
        // 非阻塞：返回 0（空），调用方稍后重试。
        return done(pack_ok(0));
    }
    // 阻塞等待：挂起本进程直到事件到达或超时。
    event_wait_blocking(frame, timeout_ns)
}

/// 把队头事件序列化为 JSON 并拷回用户缓冲（peek 已取拷贝，不消费）。
/// 返回 syscall 返回值（成功=长度，失败=错误）。
fn driver_event_serialize(ev: &driver::event::DeviceEvent, out_ptr: u64, cap: usize) -> u64 {
    let mut target = klib::json::VecTarget::new();
    let mut writer = klib::json::JsonWriter::new(&mut target);
    // DeviceInfo → JSON：kind/name/volatile 是 volumed 做挂载决策所需的全部。
    let (event_type, info) = match ev {
        driver::event::DeviceEvent::DeviceArrived(info) => ("arrived", info),
        driver::event::DeviceEvent::DeviceDeparted(info) => ("departed", info),
    };
    let kind = match info.kind {
        driver::DeviceKind::Char => "char",
        driver::DeviceKind::Block => "block",
        driver::DeviceKind::Net => "net",
        driver::DeviceKind::Display => "display",
        driver::DeviceKind::Misc => "misc",
    };
    writer
        .start_object()
        .and_then(|mut o| {
            o.field_str("event", event_type)?;
            o.field_str("kind", kind)?;
            o.field_str("name", info.name)?;
            o.field_bool("volatile", info.volatile)?;
            o.end()
        })
        .expect("Vec-backed event JSON cannot fail");
    let bytes = target.as_bytes();
    let n = bytes.len();
    if n == 0 || n > cap {
        // cap 不足：事件未被消费（仅 peek），返回 NoSpace，调用方可加大缓冲重试。
        return pack_err(Error::NoSpace);
    }
    // 用户指针校验在 pop 之前（R2）：调用方传非法指针时事件不被消费，重试仍可
    // 取回——契约内（volumed 传合法缓冲）不触发，但坏指针调用方不吞事件。
    if let Err(e) = validate_user_range(out_ptr, n as u64, UserAccess::Write) {
        return pack_err(e);
    }
    // 缓冲与指针都合法：现在才消费（peek 保证 pop 必成功）。
    let _ = driver::event::pop_event();
    unsafe {
        arch_x86_64::mmio::copy_to_user(out_ptr, bytes.as_ptr(), n);
    }
    pack_ok(n as u64)
}

/// 阻塞等待事件到达或超时（interrupt-to-futex 的等待端）。
///
/// 与 `sleep_blocking` 同构（ADR-030 §决策3"不做轮询"）：事件队列空时
/// `block_for_event` 挂起本进程并切走，本函数返回 `DispatchResult::Switched`；
/// 进程经中断路径（tick）回归用户态时，保存帧 rax 由唤醒方预置结果——事件
/// 唤醒置 `-EAGAIN` 哨兵（用户态封装**重试**取事件），超时唤醒置 `0`（返回
/// 空，volumed 做周期对账）。事件到达经 `publish_event` → [`task::wake_event`]
/// 唤醒；超时经定时器 [`task::wake_event_timeout`] 唤醒。
///
/// lost-wakeup 由 `block_for_event` 的锁内事件队列复检（register 闭包）闭合：
/// 事件先到则复检非空→不阻塞，本函数直接取到；本进程先登记则事件到达唤醒。
/// `publish_event` 先入队再唤醒，保证唤醒者复检时必见事件。
///
/// 返回：事件序列化结果（`done(len)`）、超时无事件（`done(0)`）或 `Switched`
/// （已挂起，用户态以哨兵重试）。
fn event_wait_blocking(frame: &mut SyscallFrame, timeout_ns: u64) -> DispatchResult {
    let out_ptr = frame.a1;
    let cap = frame.a2 as usize;
    // 时钟未就绪：退化非阻塞（如实返回 0，volumed 上层回退周期对账）。
    if !klib::time::clock_ready() {
        return done(pack_ok(0));
    }
    let Some(cur_pid) = current_proc_mut().map(|p| p.pid()) else {
        return done(pack_err(Error::NotFound));
    };
    // 注册超时定时器（一次性）：到期经 `task::wake_event_timeout` 把保存帧 rax
    // 预置 `0`（超时无事件）并唤醒本进程。记录 id 供 [`task::wake_event`] 在
    // 事件唤醒时取消；本函数所有"立即返回成功/空"的路径也在此显式取消并清
    // EVENT_TIMER，杜绝 stale 定时器泄漏与级联污染新等待（S18/S21，见 V2）。
    // 定时器表满时静默退化——事件到达仍能唤醒，超时仅是对活性的兜底。
    let registered_timer = match klib::time::set_timeout(timeout_ns, task::wake_event_timeout, cur_pid)
    {
        Some(tid) => {
            task::set_event_timeout_timer(tid);
            Some(tid)
        }
        None => None,
    };
    // 返回前取消超时定时器并清 EVENT_TIMER（仅"已确定交付/返回"的路径调用；
    // Switched 阻塞路径不清，交给事件唤醒取消或到期自然触发）。
    let cancel_timer = |registered: Option<u64>| {
        if let Some(tid) = registered {
            klib::time::cancel_timeout(tid);
        }
        task::clear_event_timeout_timer();
    };
    // 事件已就绪 → 交付（提前返回：取消定时器）。
    if let Some(ev) = driver::event::peek_event() {
        let r = done(driver_event_serialize(&ev, out_ptr, cap));
        cancel_timer(registered_timer);
        return r;
    }
    // 重新登记前清理本进程残留的事件等待者身份：超时唤醒路径不清 EVENT_WAITER
    // （事件唤醒才经 wake_event swap 清），残留会让本次 block_for_event 的 CAS
    // 登记失败（NotSwitched）且让 wake_event 误读本 pid。只在仍指向本 pid 时清，
    // 不误伤并发等待者。
    task::clear_event_waiter_if(cur_pid);
    match task::block_for_event(arch_frame(frame)) {
        // 已挂起切走：用户态经哨兵重试。定时器保持待触发，由事件唤醒取消或
        // 到期自然触发——不留 stale（两条路径都收敛到 EVENT_TIMER=MAX）。
        task::SwitchOutcome::Switched => DispatchResult::Switched,
        // 未挂起（事件已就绪 / 无同伴可切 / 已有并发等待者）：重取事件并取消
        // 定时器（此路径返回结果，定时器不再需要）。
        task::SwitchOutcome::NotSwitched => {
            let r = if let Some(ev) = driver::event::peek_event() {
                done(driver_event_serialize(&ev, out_ptr, cap))
            } else {
                done(pack_ok(0))
            };
            cancel_timer(registered_timer);
            r
        }
    }
}

fn sys_driver_unregister(frame: &mut SyscallFrame) -> u64 {
    let uio_id = frame.a1 as usize;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    match driver::uio_unregister_driver(uio_id, pid) {
        Ok(()) => {
            klib::info!("[uio] driver_unregister({}) released slot", uio_id);
            pack_ok(0)
        }
        Err(e) => {
            klib::info!(
                "[uio] driver_unregister({}) denied for pid={}: {:?}",
                uio_id,
                pid,
                e
            );
            pack_err(e)
        }
    }
}

/// `driver_irq_wait(uio_id, timeout_ns) -> 1/0`（DEVICE 域 0x59，阶段一）。
///
/// 阻塞当前进程直到其认领的设备中断触发或超时，使用户态驱动**中断驱动**而非
/// 轮询。归属校验同 claim（id 存在 + 调用者是该认领者）。
///
/// 返回：1 = 该设备 IRQ 已触发（驱动应读设备状态寄存器服务）；0 = 超时无中断。
/// 设备无 PCI 中断线（irq_line==0）→ NotSupported（本函数对无中断设备无意义）。
///
/// 语义（含闩锁防丢边沿）：设备 IRQ 触发时 driver::irq_owner 的 handler 置
/// "待服务"闩锁并定向唤醒本 pid（`wake_with_value(pid,1)`）。若闩锁已在阻塞前
/// 置位（驱动忙于服务时又有中断），本函数立即返回 1 不入睡——绝不丢"有活
/// 要干"的信号。驱动通过读设备状态寄存器完成真实服务。
///
/// 时钟未就绪/超时注册失败：如实退化（见下）。
fn sys_driver_irq_wait(frame: &mut SyscallFrame) -> DispatchResult {
    const MAX_WAIT_TIMEOUT_NS: u64 = 3_600_000_000_000; // 1h，同事件等待口径
    if !current_is_system() {
        return done(pack_err(Error::PermissionDenied));
    }
    let uio_id = frame.a1 as usize;
    let timeout_ns = frame.a2;
    if timeout_ns > MAX_WAIT_TIMEOUT_NS {
        return done(pack_err(Error::InvalidParam));
    }
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        return done(pack_err(Error::NotFound));
    };
    // 归属校验 + 取该认领设备的中断线。
    let irq = match driver::uio_claimed_device_irq(uio_id, pid) {
        Ok(irq) => irq,
        Err(e) => return done(pack_err(e)),
    };
    if irq == 0 {
        // 设备无 PCI 中断线：中断驱动等待对它无意义，如实拒绝。
        return done(pack_err(Error::NotSupported));
    }
    // 闩锁已置（有中断待服务，含驱动忙于服务期间到达的边沿）：立即交付。
    if driver::irq_owner::irq_pending_consume(irq) {
        return done(pack_ok(1));
    }
    if timeout_ns == 0 {
        // 非阻塞且无待服务中断：返回 0（空），调用方稍后重试。
        return done(pack_ok(0));
    }
    // 阻塞等待：挂起直到设备中断或超时。
    irq_wait_blocking(frame, pid, irq, timeout_ns)
}

/// driver_irq_wait 的阻塞段（等待端）。
///
/// 与 event_wait_blocking 同构：注册一次性超时定时器（到期经 [`task::wake_irq_timeout`]
/// 置 rax=0 唤醒），再经 [`task::block_for_irq`] 挂起。设备中断触发时 irq_owner
/// handler 置闩锁并定向唤醒本 pid（置 rax=1）；`block_for_irq` 的 per-pid 锁内
/// 复检（闩锁置位即拒睡）闭合 lost-wakeup。
fn irq_wait_blocking(frame: &mut SyscallFrame, pid: usize, irq: u8, timeout_ns: u64) -> DispatchResult {
    if !klib::time::clock_ready() {
        // 时钟未就绪：如实退化非阻塞（返回 0）。
        return done(pack_ok(0));
    }
    // 注册超时定时器：到期唤醒置 rax=0（超时）。表满则静默退化——中断到达仍能
    // 唤醒，超时仅是对活性的兜底（同 event_wait_blocking 纪律）。
    let registered_timer = klib::time::set_timeout(timeout_ns, task::wake_irq_timeout, pid);
    // 把定时器登记进该 IRQ 的槽（绑定到满足等待的那个 IRQ）：本 IRQ 触发时
    // device_irq_handler 据槽取消并清，杜绝定时器残留到下一次等待伪造超时
    // （复查 FINDING-1）。
    if let Some(tid) = registered_timer {
        driver::irq_owner::irq_timer_arm(irq, tid);
    }
    // 取消本等待的超时定时器并清 IRQ 槽（仅"已确定交付/返回"的路径调用；
    // Switched 阻塞路径不清，交由 IRQ handler 在唤醒时 irq_timer_cancel，或
    // 到期自然触发——两条路径都收敛到槽=MAX，不留 stale）。
    let cancel_timer = |registered: Option<u64>| {
        if let Some(tid) = registered {
            klib::time::cancel_timeout(tid);
        }
        driver::irq_owner::irq_timer_clear(irq);
    };
    match task::block_for_irq(arch_frame(frame), irq) {
        task::SwitchOutcome::Switched => DispatchResult::Switched,
        task::SwitchOutcome::NotSwitched => {
            // 未入睡（闩锁已置 / 无同伴可切）：交付结果。若闩锁置位 → 1；否则
            // （无可切同伴的退化）返回 0。取消超时定时器并清 IRQ 槽。
            let fired = driver::irq_owner::irq_pending_consume(irq);
            cancel_timer(registered_timer);
            done(if fired { pack_ok(1) } else { pack_ok(0) })
        }
    }
}

/// `driver_dma_alloc(bytes) -> vaddr`（DEVICE 0x5A，阶段二）：分配用户态驱动 DMA
/// 一致性缓冲并返回其用户起始虚拟地址。
///
/// 仅 System 进程。缓冲 = 物理连续 RAM（不可缓存 PCD 映射，CPU 写对设备 DMA
/// 可见），登记在调用进程地址空间，随进程退出/崩溃自动回收（0 panic）。字节数
/// 0 或超 64MiB → InvalidParam；物理帧分配失败 → OutOfMemory（如实）；虚拟区/
/// 额度不足 → NoSpace。返回 vaddr；驱动经 SYS_DRIVER_DMA_PHYS 取物理地址。
fn sys_driver_dma_alloc(frame: &mut SyscallFrame) -> u64 {
    if !current_is_system() {
        return pack_err(Error::PermissionDenied);
    }
    let bytes = frame.a1;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.addr_space().alloc_dma_user(bytes) {
        Ok((vaddr, phys)) => {
            klib::info!("[dma] alloc pid={} bytes={} -> vaddr={:#x} phys={:#x}",
                proc.pid(), bytes, vaddr, phys);
            pack_ok(vaddr)
        }
        Err(e) => pack_err(e),
    }
}

/// `driver_dma_phys(vaddr) -> phys`（DEVICE 0x5C，阶段二）：返回 DMA 缓冲基物理地址。
/// vaddr 须为该进程某块 DMA 缓冲的起始；否则如实 NotFound（不泄露任意物理地址）。
fn sys_driver_dma_phys(frame: &mut SyscallFrame) -> u64 {
    if !current_is_system() {
        return pack_err(Error::PermissionDenied);
    }
    let vaddr = frame.a1;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.addr_space().dma_base_phys(vaddr) {
        Some(phys) => pack_ok(phys),
        None => pack_err(Error::NotFound),
    }
}

/// `driver_dma_free(vaddr) -> ()`（DEVICE 0x5B，阶段二）：释放一块 DMA 一致性缓冲。
/// vaddr 须为该进程某块 DMA 缓冲的起始；非 DMA 区起点 → NotFound。
fn sys_driver_dma_free(frame: &mut SyscallFrame) -> u64 {
    if !current_is_system() {
        return pack_err(Error::PermissionDenied);
    }
    let vaddr = frame.a1;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    match proc.addr_space().munmap_dma(vaddr) {
        Ok(()) => {
            klib::info!("[dma] free pid={} vaddr={:#x}", proc.pid(), vaddr);
            pack_ok(0)
        }
        Err(e) => pack_err(e),
    }
}

// ---------- VOLUME Domain (0x60, ADR-030) ----------

/// `volume_mount(dev_name_ptr, out_path_ptr, out_cap) -> len`（M4.2，0x61）。
///
/// 按块设备名把其首分区的 EXT2 挂载到 `/volumes/{label}`（复用 M1.2 链路），
/// 卷标命名/冲突消解由 [`MountTable::mount_volume`] 承担。成功后把**真实挂载
/// 路径**（含同名自增消解后缀，如 `/volumes/X-2`）写入 `out_path_ptr`，返回其
/// 字节长度。失败如实上抛（NotFound/Corrupt/NotSupported/ReadOnly），绝不伪挂
/// 成功。路径长度超内部上限（255）→ `OutOfRange`；超 `out_cap` → `NoSpace`。
fn sys_volume_mount(frame: &mut SyscallFrame) -> u64 {
    // 路径上限 255：保证回传路径（含最长卷标后缀）落在 libsys 的 256 字节
    // 缓冲内且留出终结判断余量，与 libsys `n >= 256` 拒绝口径一致（V4）。
    const MAX_MOUNT_PATH_BYTES: usize = 255;
    let dev_name_ptr = frame.a1;
    let out_path_ptr = frame.a2;
    let out_cap = frame.a3 as usize;
    let dev_name = match copy_path_from_user(dev_name_ptr, MAX_USER_PATH_BYTES) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    if dev_name.is_empty() {
        return pack_err(Error::InvalidParam);
    }
    match crate::vfs_init::mount_device_volume(&dev_name) {
        Ok(final_path) => {
            klib::info!("[volume] mounted '{}' at {}", dev_name, final_path);
            // 回传**真实挂载路径**（含同名自增消解后缀，如 -2）：调用方据此
            // 精确掌握本次挂载目标，无需从 volume_list 反查（S06 真实链路）。
            let bytes = final_path.as_bytes();
            if bytes.len() >= MAX_MOUNT_PATH_BYTES {
                return pack_err(Error::OutOfRange);
            }
            if bytes.len() > out_cap {
                return pack_err(Error::NoSpace);
            }
            if let Err(e) = validate_user_range(out_path_ptr, bytes.len() as u64, UserAccess::Write) {
                return pack_err(e);
            }
            unsafe {
                arch_x86_64::mmio::copy_to_user(out_path_ptr, bytes.as_ptr(), bytes.len());
            }
            pack_ok(bytes.len() as u64)
        }
        Err(e) => {
            // 自 vfs_init 改造后，mount_device_volume 对已挂载设备返回已有路径
            // （Ok），AlreadyExists 仅剩登记表异常态（有设备名无路径）的防御，
            // 正常路径不再触发。其余错误（NotFound/Corrupt/NotSupported/ReadOnly）
            // 如实留痕。
            if e != klib::error::Error::AlreadyExists {
                klib::info!("[volume] mount '{}' failed: {:?}", dev_name, e);
            }
            pack_err(e)
        }
    }
}

/// `volume_list(buf_ptr, cap) -> len`（M4.2，0x62）。
///
/// 返回 `/volumes` 下已挂载卷的 JSON 数组（每项 `{"path":...}`）。挂载点
/// 枚举直接读 VFS 的 `/volumes` 目录项（真实挂载点，S09：绝不从无数据源
/// 处编造卷）。写出长度返回给用户；`cap` 超过内部上限（512）→ `InvalidParam`，
/// 实际写出字节数 0 或超 cap → `NoSpace`。
fn sys_volume_list(frame: &mut SyscallFrame) -> u64 {
    const MAX_VOLUME_LIST_BYTES: usize = 512;
    let out_ptr = frame.a1;
    let cap = frame.a2 as usize;
    if cap > MAX_VOLUME_LIST_BYTES {
        return pack_err(Error::InvalidParam);
    }
    let root = crate::vfs_init::root();
    // 读 /volumes 目录项（真实挂载点）。
    let volumes_node = match root.resolve("/volumes", true) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let entries = match volumes_node.list_dir() {
        Ok(e) => e,
        Err(e) => return pack_err(e),
    };
    let mut target = klib::json::VecTarget::new();
    let mut writer = klib::json::JsonWriter::new(&mut target);
    writer
        .start_array()
        .and_then(|mut arr| {
            for entry in entries {
                let path = alloc::format!("/volumes/{}", entry.name);
                arr.push_object(|o| {
                    o.field_str("path", &path)?;
                    Ok(())
                })?;
            }
            arr.end()
        })
        .expect("Vec-backed volume JSON cannot fail");
    let bytes = target.as_bytes();
    let n = bytes.len();
    if n == 0 || n > cap {
        return pack_err(Error::NoSpace);
    }
    if let Err(e) = validate_user_range(out_ptr, n as u64, UserAccess::Write) {
        return pack_err(e);
    }
    unsafe {
        arch_x86_64::mmio::copy_to_user(out_ptr, bytes.as_ptr(), n);
    }
    pack_ok(n as u64)
}

/// `volume_update(path_ptr, new_path_ptr, flags) -> 0`（M4.2，0x63）。
///
/// 卷属性管理：重命名挂载点。内核当前 `MountTable` 无"挂载点改名"原子接口
/// （rename 只作用于普通节点，挂载点改名会改变 mounts 表键），故本实现
/// 如实返回 [`Error::NotSupported`]——宁缺毋假，不伪做"卸载旧 + 挂新"的
/// 破坏性近似。`flags` 当前仅 0 接受。
fn sys_volume_update(frame: &mut SyscallFrame) -> u64 {
    let _path_ptr = frame.a1;
    let _new_path_ptr = frame.a2;
    let flags = frame.a3;
    if flags != 0 {
        return pack_err(Error::InvalidParam);
    }
    // 挂载点改名需 MountTable 的原子 mount-rename 接口（P2），未实现前如实拒绝。
    pack_err(Error::NotSupported)
}

/// `volume_format(dev_name_ptr, label_ptr) -> 0`（M4.2，0x65）。
///
/// 格式化卷 = 在块设备上新建 EXT2 文件系统（mkfs：superblock/位图/GDT/根
/// 目录初值）。M3 交付的是"在**既有** EXT2 上分配/释放/写"的最小可写支集，
/// 并不含 mkfs 建文件系统例程——那是独立里程碑（P2）。故如实返回
/// [`Error::NotSupported`]，绝不伪造"已格式化"的伪成功（S09）。
fn sys_volume_format(frame: &mut SyscallFrame) -> u64 {
    let _dev_name_ptr = frame.a1;
    let _label_ptr = frame.a2;
    // mkfs 例程未实现（M3 只含既有 fs 的写支集，不含建 fs）。
    pack_err(Error::NotSupported)
}

/// `volume_unmount(path_ptr) -> 0`（M4.2，0x66）。
///
/// 卸载指定挂载点（`MountTable::unmount`）。路径须为 `/volumes/...` 绝对路径，
/// 由用户提供并规范化；不存在的挂载点如实 `NotFound`。
fn sys_volume_unmount(frame: &mut SyscallFrame) -> u64 {
    let path_ptr = frame.a1;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    let root = crate::vfs_init::root();
    match root.unmount(&path) {
        Ok(()) => {
            // 反向注销设备登记（V5）：该设备可被再次挂载（热插拔往返/手动重挂）。
            crate::vfs_init::unmark_device_by_path(&path);
            klib::info!("[volume] unmounted {}", path);
            pack_ok(0)
        }
        Err(e) => pack_err(e),
    }
}

// ---------- SYNC Domain (0x70, ADR-032 ACCEPTED) ----------

/// 同步字对象/生命周期/值域校验/进程退出清理的**数据与状态**实现在 `ipc::sync_*`
/// （ADR-032 §9：SYNC 表与 shm/pipe 同置 ipc crate）。本文件只保留薄 syscall 分发壳：
/// 取值、边界校验（bit63）、阻塞/唤醒的平台翻译（arch frame + task 调度）由 ipc 侧
/// 经 `IpcTaskNotifier`（ipc_init.rs 适配）完成，这里不再持任何同步字表。

/// `sync_create(init_value) -> sync_id`（SYS_SYNC_CREATE / 0x71）。
/// 创建进程即 owner（进程退出时经 `ipc::sync_release_process` 释放其 ref，S18）。
fn sys_sync_create(frame: &mut SyscallFrame) -> u64 {
    let init_value = frame.a1;
    let owner = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    match ipc::sync_create(init_value, owner) {
        Ok(id) => pack_ok(id),
        Err(e) => pack_err(e),
    }
}

/// `sync_wait(sync_id, expected, timeout_ns)`（SYS_SYNC_WAIT / 0x72，可阻塞）。
/// 可阻塞路径经 `ipc::sync_wait` 完成（调度锁内登记 + 复检 + 阻塞/切走）。
fn sys_sync_wait(frame: &mut SyscallFrame) -> DispatchResult {
    let id = frame.a1;
    let expected = frame.a2;
    let timeout_ns = frame.a3;
    // 传原始 arch_frame 指针（usize）而非解引用：ipc 侧仅在真正阻塞/切换路径才读它
    // （S21 契约：非切换路径不读 arch_frame）。
    match ipc::sync_wait(frame.arch_frame, id, expected, timeout_ns) {
        ipc::SyncWaitResult::Done(v) => done(pack_ok(v)),
        ipc::SyncWaitResult::Switched => DispatchResult::Switched,
        ipc::SyncWaitResult::WouldBlock => done(pack_err(Error::WouldBlock)),
        ipc::SyncWaitResult::NotFound => done(pack_err(Error::NotFound)),
        ipc::SyncWaitResult::InvalidParam => done(pack_err(Error::InvalidParam)),
    }
}

/// `sync_wake(sync_id, value, n) -> n`（SYS_SYNC_WAKE / 0x73）。
/// ipc 侧改值 + drain 等待者，本壳在表锁外逐个带值唤醒（锁序纪律同 pipe）。
fn sys_sync_wake(frame: &mut SyscallFrame) -> u64 {
    let id = frame.a1;
    let value = frame.a2;
    let n = frame.a3 as usize;
    let (cnt, removed) = match ipc::sync_wake(id, value, n) {
        Ok(x) => x,
        Err(e) => return pack_err(e),
    };
    for w in &removed {
        if w.timer != 0 {
            let _ = klib::time::cancel_timeout(w.timer);
        }
        task::wake_with_value(w.pid, value);
    }
    pack_ok(cnt as u64)
}

/// `sync_delete(sync_id)`（SYS_SYNC_DELETE / 0x74）。
/// refs 归零才真正移除（ADR-032 §4.4），仍有等待者返回 `Busy`。
fn sys_sync_delete(frame: &mut SyscallFrame) -> u64 {
    match ipc::sync_delete(frame.a1) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}


// ---------- 分发 ----------

/// 分发结果：`Done(v)` = 正常返回值（写入 `frame.result`，架构层写回 rax 带
/// 回调用进程）；`Switched` = 调度器已把真实中断帧**整体替换**为下一进程的
/// 保存帧并切换（waitpid 阻塞 / exit 切换）。此时目标进程 rax 由调度语义
/// 交付（如 waitpid 交付的退出码），入口**必须禁止**再写返回值——否则会用
/// 占位值覆盖交付结果/目标进程现场（置 `frame.switched`，架构层不写回）。
enum DispatchResult {
    Done(u64),
    Switched,
}

/// 普通处理器结果包装。
fn done(v: u64) -> DispatchResult {
    DispatchResult::Done(v)
}

/// 按系统调用号分发到具体实现。
fn dispatch(nr: u64, frame: &mut SyscallFrame) -> DispatchResult {
    match nr as u32 {
        // STREAM Domain (0x10)
        SYS_STREAM_CREATE => done(sys_open(frame)),
        // read 可能阻塞切换（stdin），自带 DispatchResult 语义（K1a）。
        SYS_STREAM_READ => sys_read(frame),
        SYS_STREAM_WRITE => done(sys_write(frame)),
        SYS_STREAM_CLOSE => done(sys_close(frame)),
        SYS_STREAM_DUP => done(sys_dup2(frame)),
        SYS_STREAM_LOCK => done(sys_flock(frame)),
        SYS_STREAM_FSTAT => done(sys_fstat(frame)),

        // MEMORY Domain (0x20)
        SYS_MEMORY_MAP => done(sys_mmap(frame)),
        SYS_MEMORY_QUERY => done(sys_memory_query(frame)),
        SYS_MEMORY_GROW => done(sys_brk(frame)),
        SYS_MEMORY_UNMAP => done(sys_munmap(frame)),

        // TASK Domain (0x30)
        SYS_TASK_SPAWN => done(sys_exec(frame)),
        SYS_TASK_WAIT => sys_task_wait(frame),
        // kill 可能自杀切换（exit_current → Switched），自带 DispatchResult 语义。
        SYS_TASK_SIGNAL => sys_kill(frame),
        // exit 已切换到下一进程（或进入 idle），永不以正常值返回。
        SYS_TASK_EXIT => {
            sys_exit(frame);
            DispatchResult::Switched
        }
        // thread_spawn：非阻塞，返回组员 pid。
        SYS_TASK_THREAD_SPAWN => done(sys_thread_spawn(frame)),
        // thread_join 可能阻塞切换（组长阻塞 waitpid 组员），自带 DispatchResult 语义。
        SYS_TASK_THREAD_JOIN => sys_thread_join(frame),
        // set_fs_base：非阻塞，wrmsr 当前线程 FS base（T2-1 / 0x37）。
        SYS_TASK_SET_FS_BASE => done(sys_set_fs_base(frame)),
        // gettid/getpid：非阻塞，返回本线程 pid / 组长 tgid（T2-6 / 0x38/0x39）。
        SYS_TASK_GETTID => done(sys_gettid(frame)),
        SYS_TASK_GETPID => done(sys_getpid(frame)),

        // VFS Domain (0x40)
        SYS_ENTRY_CREATE => done(sys_entry_create(frame)),
        SYS_ENTRY_READ => done(sys_readdir(frame)),
        SYS_ENTRY_UPDATE => done(sys_entry_update(frame)),
        SYS_ENTRY_DELETE => done(sys_unlink(frame)),
        SYS_ENTRY_CHDIR => done(sys_chdir(frame)),
        SYS_ENTRY_GETCWD => done(sys_getcwd(frame)),

        // DEVICE Domain (0x50)
        SYS_DRIVER_REGISTER => done(sys_driver_register(frame)),
        SYS_DRIVER_QUERY => done(sys_driver_query(frame)),
        SYS_DRIVER_CLAIM => done(sys_driver_claim(frame)),
        SYS_DRIVER_UNREGISTER => done(sys_driver_unregister(frame)),
        // 事件等待可能阻塞切换（interrupt-to-futex），自带 DispatchResult 语义。
        SYS_DRIVER_EVENT_NEXT => sys_driver_event_next(frame),
        // 块设备缓存穿透探测读（volumed 低频对账）。
        SYS_DEVICE_PROBE => done(sys_device_probe(frame)),
        // driver_irq_wait 可能阻塞切换（设备中断定向唤醒），自带 DispatchResult 语义。
        SYS_DRIVER_IRQ_WAIT => sys_driver_irq_wait(frame),
        SYS_DRIVER_DMA_ALLOC => done(sys_driver_dma_alloc(frame)),
        SYS_DRIVER_DMA_PHYS => done(sys_driver_dma_phys(frame)),
        SYS_DRIVER_DMA_FREE => done(sys_driver_dma_free(frame)),

        // VOLUME Domain (0x60, ADR-030)
        SYS_VOLUME_MOUNT => done(sys_volume_mount(frame)),
        SYS_VOLUME_LIST => done(sys_volume_list(frame)),
        SYS_VOLUME_UPDATE => done(sys_volume_update(frame)),
        SYS_VOLUME_FORMAT => done(sys_volume_format(frame)),
        SYS_VOLUME_UNMOUNT => done(sys_volume_unmount(frame)),

        // SYNC Domain (0x70, ADR-032 ACCEPTED)
        SYS_SYNC_CREATE => done(sys_sync_create(frame)),
        // WAIT 可能阻塞切换（futex 阻塞），自带 DispatchResult 语义。
        SYS_SYNC_WAIT => sys_sync_wait(frame),
        SYS_SYNC_WAKE => done(sys_sync_wake(frame)),
        SYS_SYNC_DELETE => done(sys_sync_delete(frame)),

        // SIGNAL Domain (0x80, ADR-034 PROPOSED)
        SYS_SIGNAL_ACTION => done(sys_signal_action(frame)),
        SYS_SIGNAL_MASK => done(sys_signal_mask(frame)),
        SYS_SIGNAL_RETURN => done(sys_signal_return(frame)),

        // POWER Domain (0x90, ADR-036): 终结路径（断电/复位后 CPU 不再返回用户态）
        SYS_POWER_OFF => sys_power_off(frame),
        SYS_POWER_REBOOT => sys_reboot(frame),

        _ => {
            klib::info!("[syscall] unknown nr={:#x}", nr);
            done(pack_err(Error::NotSupported))
        }
    }
}

// ---------- 软中断入口 ----------

/// `int 0x80` 软中断处理回调（注册为 `arch::SyscallEntry::register`）。
///
/// 从 `SyscallFrame` 读 `nr`（系统调用号）与参数寄存器，分发执行：
/// - [`DispatchResult::Done`]：把结果写入 `frame.result`，架构层写回 rax，
///   iretq 带回调用进程；
/// - [`DispatchResult::Switched`]：调度器已把真实中断帧**整体替换**为下一
///   进程的保存帧，其 rax 由调度语义负责（如 waitpid 交付的子进程退出码），
///   故置 `frame.switched`，架构层**不得**把 result 写回。
///
/// 返回 `true` 让 `iretq` 把（可能的）新现场带回目标用户态。
pub extern "C" fn syscall_entry(frame: &mut SyscallFrame) -> bool {
    let nr = frame.nr;
    // 进入/返回 trace 仅在自检构建开启（避免每条 syscall 生产刷屏）。
    #[cfg(feature = "kernel-tests")]
    klib::info!(
        "[syscall] nr={:#x} a1={:#x} a2={:#x} a3={:#x}",
        nr,
        frame.a1,
        frame.a2,
        frame.a3
    );
    match dispatch(nr, frame) {
        DispatchResult::Done(ret) => {
            #[cfg(feature = "kernel-tests")]
            klib::info!("[syscall] nr={:#x} -> {:#x}", nr, ret);
            // 非切换路径：返回用户态前派发待投递信号（ADR-034 §2.4 触发点 2）。
            // S1-8 接线：先回写 syscall 结果，再派发。`deliver_pending_signal` 内部
            // 用 `read_unaligned` 读 cs 判定是否真实用户态返回帧（合成测试帧的
            // arch_frame 为 0 或指向未对齐局部帧时安全跳过），避免 misaligned deref。
            frame.result = ret;
            if !deliver_pending_signal(frame) {
                // 进程被默认动作终止并已切走：架构层不得再把 result 回写（调度已
                // 替换帧）。置 switched 由调度语义接管。
                frame.switched = true;
                return true;
            }
        }
        DispatchResult::Switched => {
            #[cfg(feature = "kernel-tests")]
            klib::info!("[syscall] nr={:#x} -> <switched>", nr);
            // 现场已整体切换为下一进程，架构层不得回写 result。
            frame.switched = true;
        }
    }
    true
}
