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
    Caps, current_proc_mut, ProcessIdentity,
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
    /// AUDIO 域（plan_audio_vfs.md 批次二）：音频管道消费者动词。
    ///
    /// 与 VFS 域的分工：读写 PCM **走 VFS 路径**（`open(/devices/audio/dsp)`
    /// + `read`/`write`），不在此域重复造读写。本域只提供 VFS 无法表达的**流控**
    /// 动词——附加/注销消费者、提交消费、主动取帧。这样"数据通路"与"控制通路"
    /// 各归其位，也避免同一份 PCM 有两条语义不同的入口（S15）。
    pub const AUDIO: u32 = 0xA0;
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

/// `SYS_STREAM_READ` 的 `a5` 标志位：**非阻塞读**（§6.12.5，所有者裁决甲）。
///
/// # 为什么需要它
///
/// 「**看一眼**键盘，有没有都立刻回来」与「**等着要**一个字符」是**两种不同
/// 的语义**，但此前共用一个系统调用、且无法区分。后果是一个真实缺陷：
/// 前台等待循环里的 `probe_interrupt` 只能用阻塞 `read`，而交互 stdin 空读
/// 会**登记 `KBD_WAITER` 并切走**——子进程被 `^C` 杀死后，shell 回到循环开头
/// 又立刻阻塞在探键上，**永远走不到 `waitpid`**（实测挂死）。
///
/// 本标志把这两种语义分开：**置位时不登记 `KBD_WAITER`**，故本进程绝不会
/// 为它切走。不登记是「永不阻塞」的**充分**条件。
///
/// # 取值与兼容
///
/// `a5` 此前**恒为 0**（`libsys::read`/`pread` 都传 0），故 `0` 保持既有
/// **阻塞**语义逐位不变——即「安全侧默认」（S17）。
pub const STREAM_READ_NONBLOCK: u64 = 1;

/// `SYS_STREAM_READ` 的 `a5` 标志位：**预览（不消费）**（§6.12.5）。
///
/// 置位时本次读**不推进节点读取位置**。
///
/// # 为何必须有它（而不是只有 NONBLOCK）
///
/// 探键只想知道「下一个是不是 `^C`」。若只能取走才能看，
/// 那么属于子进程的普通按键就会被静默丢弃。
/// 实测：`/programs/spinburn.elf` 变成 `/prams/spinburn.elf`（`o`/`g` 丢失）。
pub const STREAM_READ_PEEK: u64 = 2;

/// `SYS_STREAM_READ` 的 `a5` 是否要求**预览**（S13 单点判定）。
#[inline]
pub const fn read_is_peek(flags: u64) -> bool {
    flags & STREAM_READ_PEEK != 0
}

/// `SYS_STREAM_READ` 的 `a5` 是否要求**非阻塞**（S13 单点判定）。
///
/// 只有 `a5` 的**最低位**（[`STREAM_READ_NONBLOCK`]）被认定为非阻塞。
/// 其余位当前**未定义**：为了不把未来可能新增的标志误判成非阻塞，
/// 本函数**显式**按位与判定，而非 `a5 != 0`——后者会把将来的任何新标志
/// 都悄悄变成「非阻塞」，属静默语义漂移（S09 精神）。
#[inline]
pub const fn read_is_nonblock(flags: u64) -> bool {
    flags & STREAM_READ_NONBLOCK != 0
}
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
/// STREAM 域扩展动词：焦点实例切换（ADR-048 T3，owner 裁决 α 2026-09-27：
/// 受控例外形状 = audio attach 同款「独立域动词 + 能力门禁」；ADR-044
/// 「不新增 syscall」红线按本意澄清——防的是无序动词蔓延破坏单径事件链，
/// 域内受控子动作 ≠ 新 syscall；ADR-014 §4.1 动词表随本动词同步修订）。
/// a1=实例 id（预创建 0..CONSOLES_N-1；运行期创建的实例亦合法，上限 CONSOLES_MAX=64）。**门禁在 syscall 层**（`current_has_cap`）：
/// VFS 节点层 `write_at` 无调用者身份，焦点切换若落在节点层 = 任意进程
/// 终端劫持面（S17/S20）；语义 = tcsetpgrp/TIOCSPGRP 的本域同构（权限
/// 判定在有 caller 身份的内核边界，机制内核、策略用户态）。
pub const SYS_STREAM_FOCUS_SET: u32 = nr(domain::STREAM, 0x08); // 0x18

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

/// `derive(flags, entry_rsp, entry_rip) -> pid`：**COW 派生子进程**（ADR-038）。
///
/// 语义：以调用进程为父，派生一个**新线程组**的子进程，其用户地址空间与父
/// **共享全部已映射数据帧**（写时复制），fd 表/cwd/identity 按 ADR-038 §2 决策 2
/// 逐项取得。子进程在父被本 syscall 中断处继续执行。
///
/// **返回语义（POSIX fork 铁律）**：父收新子进程 pid（>0）、子收 0、失败父收 -errno。
///
/// **入参（首期保留，非 0 即拒绝——绝不静默忽略）**：`flags` / `entry_rsp` /
/// `entry_rip` 首期必须全为 `0`（表示「继承父当前 RIP/RSP」）。保留是为将来
/// 「带入口的派生」预留 ABI 位置；现取值一律返回 `InvalidParam`。
///
/// **不新增 fork syscall**（ADR-003 明文禁止 POSIX `fork()` 进入内核）：本动词是
/// TASK 域的 object-verb 原语，符合 ADR-014 编码规则；POSIX 兼容层的 `fork()`
/// 由 libc 包装本调用提供。TASK 域扩展动词 0x0A；双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_TASK_DERIVE` 同值、注释互指。
pub const SYS_TASK_DERIVE: u32 = nr(domain::TASK, 0x0A); // 0x3A

/// `identity_query(out_ptr) -> 0`：把调用进程的**真实** uid/gid/caps 写入用户缓冲
/// （[`IdentityInfo`]，12 字节）。
///
/// A2-1 / ADR-040 §3.5 G1（承 ADR-033 遗留 T-A1b）。**只读**，无权限门禁——进程
/// 查自己的身份不构成越权；不提供"查任意 pid"形态（那需要额外的授权语义，本项
/// 不做，避免开出未被裁定的越权面）。TASK 域扩展动词 0x0B；双侧镜像（S13）：
/// 与 libsys `nr.rs::SYS_TASK_IDENTITY_QUERY` 同值、注释互指。
pub const SYS_TASK_IDENTITY_QUERY: u32 = nr(domain::TASK, 0x0B); // 0x3B

/// `identity_set(uid, gid, reserved, caps) -> 0`：变更调用进程组的身份。
///
/// **路线 B：完整 setuid 语义**（ADR-040 §3.5.4 #14 的对称完整形态；项目所有者
/// 2026-09 裁定）。授权按 `CAP_SYSTEM` 二分：
/// - 无 `CAP_SYSTEM`：只允许**降权或保持不变**（uid/gid 不得改变，caps 只能
///   去掉已有位）；任何提权或改 uid → `PermissionDenied`。
/// - 持 `CAP_SYSTEM`：可设为**任意** uid/gid（login 校验通过后据此把 shell
///   变成目标用户——这是 A2-7 登录闭环的唯一通道）。
///
/// 身份变更是**进程组级**（`ThreadGroup` 共享 `identity`，承现有
/// `Process::set_identity` 组锁），故本调用影响调用线程所在组的全部成员。
/// 参数只用定长数字（ADR-018 三层校验零改动 / ADR-040 §2.10）；
/// TASK 域扩展动词 0x0C；双侧镜像（S13）：与 libsys
/// `nr.rs::SYS_TASK_IDENTITY_SET` 同值、注释互指。
pub const SYS_TASK_IDENTITY_SET: u32 = nr(domain::TASK, 0x0C); // 0x3C

/// `SYS_TASK_IDENTITY_SET` 的保留参数（`a3`）唯一合法取值。
/// 用命名常量而非字面量 0，使"保留位"是一处成文语义而非魔法值（S13）。
pub const IDENTITY_SET_RESERVED_NONE: u64 = 0;

/// `SYS_TASK_GROUPS_SET`（A2-4 / TASK 域扩展动词 0x0D = 0x3D）：设置调用进程组的
/// **补充组集合**。
///
/// **为何需要独立动词而非并入 identity_set**：`identity_set` 的参数已用满
/// （a1/a2/a3/a4），而补充组是**变长**语义（最多 `Groups::MAX` 项），无法塞进定长
/// 数字面。ADR-040 §2.10 要求「参数只用定长数字」，故遵循 ADR-018 的两段式约定：
/// 先以 `count` 探测/申请，再以用户缓冲传数组（同 `entry_read_aces` 手法）。
///
/// **授权（S13 单点）**：与 `identity_set` 同门禁——持 `CAP_SYSTEM` 者可设为任意
/// 组集合（login 后按 `/config/groups.json` 装配成员的补充组）；无 `CAP_SYSTEM` 者
/// 只能**收缩或保持不变**（不得新增自己不属于的组，否则即组越权）。
///
/// 参数：`a1`=调用方组数组指针（`u32` 定长元素）、`a2`=元素个数、
/// `a3`=保留（必须 0）、`a4`=方向（`GROUPS_SET_REPLACE` / `GROUPS_SET_CLEAR`）。
pub const SYS_TASK_GROUPS_SET: u32 = nr(domain::TASK, 0x0D); // 0x3D

/// `SYS_TASK_GROUPS_SET` 的保留参数（`a3`）唯一合法取值。
pub const GROUPS_SET_RESERVED_NONE: u64 = 0;

/// `SYS_TASK_GROUPS_SET` 的 `a4`：以 `a1`/`a2` 给定的集合**整体替换**当前补充组。
pub const GROUPS_SET_REPLACE: u64 = 0;

/// `SYS_TASK_GROUPS_SET` 的 `a4`：清空补充组（此时 `a1`/`a2` 必须为 0）。
pub const GROUPS_SET_CLEAR: u64 = 1;

/// `SYS_TASK_GROUPS_SET` 的 ABI 结果结构（A2-4）：回传**实际生效**的补充组，
/// 使调用方无需再次查询即可确知结果（超限时也能看清发生了如实拒绝）。
///
/// `#[repr(C)]` 固定布局，与 libsys 侧镜像同布局（PRE-12 纪律）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupsInfo {
    /// 实际生效的补充组个数（`0..=Groups::MAX`）。
    pub count: u32,
    /// 保留（显式置 0，便于将来向尾部增长而不破 ABI）。
    pub reserved: u32,
    /// 组 id 数组（前 `count` 项有效；其余为 0）。定长 = `Groups::MAX`。
    pub gids: [u32; task::Groups::MAX],
}

/// 身份查询/变更的 ABI 结果结构（A2-1；与 libsys `io::IdentityInfo` 同布局镜像）。
///
/// `#[repr(C)]` 固定布局，跨边界真实数据合约；任一侧改字段必须同变更同步
/// （PRE-12 纪律）。字段全为定长数字（ADR-018/ADR-040 §2.10）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    /// 真实 uid（**不得**伪造、不得兜底）。
    pub uid: u32,
    /// 真实 gid。
    pub gid: u32,
    /// 能力位（`Caps::bits()` 零扩展）。
    pub caps: u32,
}

/// A2-1：两侧（kernel ↔ libsys）镜像一致性断言（编译期钉死，PRE-12 纪律）。
const _: () = {
    assert!(core::mem::size_of::<IdentityInfo>() == 12, "IdentityInfo layout drifted: sync libsys mirror");
    assert!(core::mem::offset_of!(IdentityInfo, uid) == 0);
    assert!(core::mem::offset_of!(IdentityInfo, gid) == 4);
    assert!(core::mem::offset_of!(IdentityInfo, caps) == 8);
};

/// `SYS_TASK_DERIVE` 的保留位域（ADR-038 §2 决策 1）。
///
/// 首期只接受 [`DERIVE_FLAGS_NONE`]；任何其它位如实 `InvalidParam`。
/// 用命名常量而非字面量 0，使「保留位」是一处成文的语义而非魔法值（S13）。
pub const DERIVE_FLAGS_NONE: u64 = 0;

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

// ---------- SYS_ENTRY_UPDATE 动作编码（a4 区分 rename/chmod/chown）----------
/// rename（默认）：a4=0，a1=old_path, a2=new_path。
pub const ENTRY_UPDATE_RENAME: u64 = 0;
/// chmod：a4=1，a1=path, a2=mode_bits（classic 9 位 + 门禁 bit9 编码）。
pub const ENTRY_UPDATE_CHMOD: u64 = 1;
/// chown（A1-7 / ADR-014「更新节点元数据」）：a4=2，a1=path, a2=uid, a3=gid。
pub const ENTRY_UPDATE_CHOWN: u64 = 2;
/// A2-6 / ADR-040 §3.5.1 G4：`ENTRY_UPDATE` 动作 3 —— **设置显式 ACE 列表**。
///
/// 参数：`a1=path_ptr`、`a2=aces_ptr`（指向用户态 `[AceWire; n]` 定长数组）、
/// `a3=count`（条数，`0` 表示清空显式列表）、`a4=ENTRY_UPDATE_SET_ACES`。
/// 整表替换语义（与 chmod 的"写门径"同类）：`count=0` 即清空。
/// **不**改 classic 三段、**不**改属主、**不**改门禁位——与 `with_classic_mode`
/// 同一纪律（只改本动作负责的那一维）。
pub const ENTRY_UPDATE_SET_ACES: u64 = 3;

/// A2-6：`ENTRY_READ` 子动作 —— **读取节点显式 ACE 列表**。
///
/// 参数：`a1=path_ptr`、`a2=out_ptr`（收 `[AceWire; cap]`）、`a3=cap`
/// （调用方容量，0 合法——用于**探测条数**）、`a4=ENTRY_READ_ACES`。
/// 返回：成功时为**写入的条数**（`<= cap`）；若节点 ACE 数 > `cap` 则
/// 返回 `Error::NoSpace`（**不**截断——截断会让用户态误以为拿到了全部策略）。
pub const ENTRY_READ_ACES: u64 = 2;

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

// ---------- 6b. AUDIO Domain (0xA0，plan_audio_vfs.md 批次二) ----------
/// 附加为音频管道消费者（独占）。`a1 = timeout_ns`（预留）。
/// 已有消费者 → `Busy`（EBUSY，结构性占用，重试不会成功）。
pub const SYS_AUDIO_ATTACH: u32 = nr(domain::AUDIO, 0x01); // 0xA1
/// 注销消费者（仅属主）。非属主 → `PermissionDenied`。
pub const SYS_AUDIO_DETACH: u32 = nr(domain::AUDIO, 0x02); // 0xA2
/// 取 PCM 数据。`a1 = buf_ptr`、`a2 = len`。无数据且已附加 → 阻塞等待
/// （有限超时）；无消费者 → `NotSupported`（诚实性红线）。
pub const SYS_AUDIO_FETCH: u32 = nr(domain::AUDIO, 0x03); // 0xA3
/// 提交已消费的 n 字节（推进读指针）。`a1 = n`。越界 → `InvalidParam`。
pub const SYS_AUDIO_COMMIT: u32 = nr(domain::AUDIO, 0x04); // 0xA4
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
/// 就能让内核空转 ~2^34 次页表查询。上限取 64MiB——历史参考平台上与旧
/// 单空间配额同量级，覆盖全部合法批量 IO；这是 **IO 有界性**关切，与内存
/// 承诺记账（B1 全局账）无涉。超出即参数错误（InvalidParam），调用方分次
/// 提交。Linux 同型先例：MAX_RW_COUNT。
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

/// A2-3 / ADR-040 §3.4：**目录遍历权限单点**——逐级父目录要求 Execute（搜索）位。
///
/// POSIX 语义：路径解析的**每一级父目录**都需要 x 位；缺 x 则无法穿越该目录抵达
/// 其下任何条目，**与目标条目自身权限无关**（一个 0644 的文件在无 x 的父目录下
/// 同样不可达）。这是"搜索权限"与"读权限"的正交性。
///
/// 为何有独立 helper 而非在 `resolve` 内做（S13 单点说明）：`resolve` 是 vfs 层
/// 纯路径函数，**没有身份参数**（依赖方向 task→vfs，vfs 不得反向依赖身份）。
/// 故遍历检查属**强制矩阵**，与 `check_access` 同理落在 kernel 侧。
///
/// 判定面：对 `abs_path` 的每一级**中间目录**（不含最后一段——最后一段是调用方
/// 自己的操作对象，其权限由各调用点按语义判定）求 Execute。实施要点：
/// - 根 `/` 亦参与检查（POSIX：`/` 通常 0755，但若被改窄则应当拦截）；
/// - 任一中间目录缺失/不可解析 → 如实 `NotFound`（不伪造成 EACCES）；
/// - 权限不足 → `PermissionDenied`（EACCES）；
/// - `CAP_OWNER` 豁免与门禁位语义与 `check_access` 一致（复用同一单点，不另起判定）。
///
/// 调用时机：各 path-taking syscall 在 `absolute_path` 之后、`resolve` 之前调用。
fn check_traverse_access(
    identity: &ProcessIdentity,
    abs_path: &str,
) -> Result<(), Error> {
    let root = crate::vfs_init::root();
    // 逐级构造中间目录前缀并求 Execute。末段（含尾随空段）不检查。
    let comps: alloc::vec::Vec<&str> = vfs::path::Path::new(abs_path).components().collect();
    if comps.is_empty() {
        return Ok(());
    }
    let mut prefix = alloc::string::String::new();
    // prefix 代表「进入 comps[i] 之前所在目录」。
    // 只检查 **中间目录**：根 `/` 与 comps[0..len-1] 构成的每级父目录。
    // **不检查最后一段**——它是调用方的操作对象本身，其权限（读/写/执行）由各
    // 调用点按自己的语义判定（如 stat 求 Read、mkdir 求父目录 Write）。把末段也
    // 按 Execute 检查会造成语义重复与错误拒绝（例：对文件 stat 会因文件无 x 被拒）。
    for i in 0..comps.len() {
        let node = match root.resolve(if prefix.is_empty() { "/" } else { &prefix }, true) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        // **可穿越性**必须问节点自己，而不是问 `node_type()` 是否等于 Directory。
        //
        // 二者是两个正交问题：`node_type()` 答"它**是**什么"，穿越判定答"能否
        // **穿过**它"。绝大多数节点上答案一致，于是极易被合并；而下面这些节点
        // 是反例——它们都是**容器型字符设备**（`node_type()` 如实报
        // `CharacterDevice`，同时又 `add_child` 了子文件并覆写 `lookup`/`list_dir`）：
        //
        //   - `/devices/audio/dsp`        —— `format`/`channels`/`rate`/`status`
        //   - `/devices/input/events`     —— I-EVENTS 阶段 1（ADR-047）
        //   - `/devices/random`           —— `status`
        //
        // 旧的类型判定让它们的整棵子树在真实 `open` 路径上不可达。音频那一路的
        // 后果最重：`init` 永远读不到 `attached`，判定"无音频消费者"并**永久跳过
        // audiod**，PCM ring 从此无人写数据，驱动只能播静音并持续空转。
        //（详见 `vfs::INode::allows_traversal` 与 `test_container_device_allows_traversal`。）
        //
        // 【与 fix/hda-bcis 合并前的两版修法取舍】本分支曾用"lookup 一个魔数名
        // 再看返回错码"的等价探测（魔数 `__probe_nonexistent__`），并保留
        // `InvalidParam`。那是**权宜**——注释自身也写道"这里无法预知子名"。
        // 它有两个结构性问题：其一，判定依赖一个必须**永不成为真实子项**的魔数名
        // （这个约束无处强制，将来若有人恰好创建该名字即静默失效）；其二，
        // "能否穿越"这个事实因此有了**两份来源**（`node_type()` 与 lookup 行为），
        // 而合并前它已经因两份来源不一致而失效过一次。
        //
        // 现改为 `allows_traversal()`（`vfs::INode` 上的单点定义，默认按"能否真的
        // 枚举子项"推导）：事实只剩一份，且与 `lookup`/`list_dir` 的既有能力声明
        // 同源，不存在可能与它冲突的副本。
        //
        // 【错误码更正】此处原写"本仓 Error 无 NotDir"故退回 `InvalidParam`。
        // 该说法**不成立**：`klib::Error::NotDirectory` 存在且映射 errno 20（ENOTDIR）。
        // 错报 `InvalidParam`（EINVAL）把一个"路径穿不过去"谎报成"参数非法"，
        // 属 S09 意义上的伪信息——排查时会把注意力引向调用方参数而非路径结构。
        // 现按 POSIX 语义返回 `NotDirectory`。
        if !node.allows_traversal() {
            return Err(Error::NotDirectory);
        }
        check_access(identity, node.as_ref(), vfs::inode::PermBits::EXECUTE)?;
        // 前进：只有还有下一段时才前进（最后一段为操作对象，不参与穿越）。
        if i + 1 < comps.len() {
            prefix.push_str("/");
            prefix.push_str(comps[i]);
        }
    }
    Ok(())
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &abs) {
            return pack_err(e);
        }
    }
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

/// A1-2 / ADR-040 §2.3：系统门禁强制（承 ADR-033 的 system_only 语义）。
///
/// 在 `sys_open`（`resolve` 后、`FileHandle::new` 前）与 `sys_exec`（解析
/// inode 后、装载前）调用。门禁位 wire bit9（A1-1 起原 `system_only` bit3
/// 迁址于此，`AccessPolicy` 的 `gate_system`）标记的**系统门禁节点**仅持
/// `CAP_SYSTEM` 的进程可打开/执行，其余身份返回
/// `Error::PermissionDenied`（EACCES）。
///
/// A1-1：本函数同时是 open/exec 的策略求值入口（门禁 → `CAP_OWNER` 豁免
/// → `AccessPolicy::evaluate`，判定序见函数文档）。
/// open/exec 强制点（A1-1 / ADR-040 §2.1+§2.6）。
///
/// 判定序（成文）：
/// 1. **系统门禁**（wire bit9，原 `system_only` 语义迁址）：置位且无
///    `CAP_SYSTEM` → [`Error::PermissionDenied`]（CAP_OWNER 不豁免门禁——
///    门禁是系统完整性边界，不是文件属主权）。
/// 2. **`CAP_OWNER` 绕过**（ADR-040 §2.6，DAC_OVERRIDE 对应物）：持有者
///    在策略求值前直接放行。
/// 3. **策略求值**：节点 [`vfs::inode::AccessPolicy`] 对 `required` 位集
///    求值（唯一算法，见 `AccessPolicy::evaluate`）。
fn enforce_open_permission(
    identity: ProcessIdentity,
    inode: &alloc::sync::Arc<dyn vfs::inode::INode>,
    required: vfs::inode::PermBits,
) -> Result<(), Error> {
    check_access(&identity, inode.as_ref(), required)
}

/// A1-3 / ADR-040 §2.6：**统一强制矩阵单点**。
///
/// 所有访问路径（open/create、read/write、readdir/stat、unlink/mkdir/
/// rename 的父目录写面、chmod 的属主面、exec）在唯一位置调用本函数，
/// 禁止各 syscall 散装判定（PRE-6：零强制正是散装的后果）。
///
/// 判定序（与 [`enforce_open_permission`] 一致，成文）：
/// 1. **系统门禁**（wire bit9）：置位且无 `CAP_SYSTEM` → EACCES（
///    `CAP_OWNER` 不豁免门禁——系统完整性边界，非属主权）。
/// 2. **`CAP_OWNER` 绕过**（§2.6，Linux `CAP_DAC_OVERRIDE` 对应物）：
///    持有者在策略求值前直接放行。
/// 3. **策略求值**：节点 [`vfs::inode::AccessPolicy`] 对 `required` 求值。
///
/// A1-3 语义注记：门禁对 chmod **不适用**（`set_permissions` 是门禁唯一
/// 写入门径；门禁位本身无属主概念，属主校验独立于节点内容策略）。
/// unlink/mkdir/rename 的**目标属主面**属 A1-5（属主真值落地）后才有
/// 完整数据，本阶段先接线父目录 Write 面。
fn check_access(
    identity: &ProcessIdentity,
    inode: &dyn vfs::inode::INode,
    required: vfs::inode::PermBits,
) -> Result<(), Error> {
    let meta = inode.metadata()?;
    if meta.permissions.gate_system() && !identity.caps.contains(Caps::SYSTEM) {
        return Err(Error::PermissionDenied);
    }
    if identity.caps.contains(Caps::OWNER) {
        return Ok(());
    }
    policy_allows(identity, &meta.permissions, required)
}

/// A1-3 / §2.6「chmod：属主或 CAP_OWNER」单点（此前完全缺失——PRE-6
/// 独立高危项）。判定序：门禁**不适用**（chmod 是门禁写入门径，见
/// `check_access` 注记）→ 属主 uid 命中或 `CAP_OWNER` → 放行；其余 EACCES。
fn check_chmod_access(identity: &ProcessIdentity, policy: &vfs::inode::AccessPolicy) -> Result<(), Error> {
    if identity.uid == policy.owner_uid() || identity.caps.contains(Caps::OWNER) {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// A1-3 / §2.6「unlink/mkdir/rename：父目录 Write + 目标属主」的父目录面
/// 单点。目标属主面（持有 `CAP_OWNER` 者可删他人文件等）待 A1-5 属主
/// 真值落地后补全（本阶段注释如实记账，不伪称完整）。
/// A2-8：把【继承派生出的策略】应用到刚建成的子节点。
///
/// 单点助手（S13）：`sys_entry_create` 的目录/文件两条分支共用，不各写一份。
/// 语义注记：这是"先建后落策略"的两步——若第二步失败则子节点保持创建时的
/// classic 策略（**不会**得到半套继承 ACE）。之所以可接受：`set_permissions`
/// 由内核内部调用（非用户态通道），失败仅意味着底层 fs 拒绝写元数据（如只读
/// 挂载），此时调用方收到的错误如实上抛，不存在"静默降级成更宽策略"的面
/// ——子节点仍是**创建者自己的 classic 策略**，不比请求更宽。
fn apply_inherited_policy(
    node: &alloc::sync::Arc<dyn vfs::inode::INode>,
    policy: &vfs::inode::AccessPolicy,
) -> Result<(), Error> {
    node.set_permissions(policy)
}

/// A2-6 / ADR-040 §3.5.1 G4：**设置节点显式 ACE 列表**（整表替换）。
///
/// 授权面（与 chmod 同源，单点 `check_chmod_access`）：属主或 `CAP_OWNER`。
/// 理由：ACE 列表就是访问策略本体——能改它等于能改节点权限，故与 chmod 同权限。
/// 门禁**不**适用（同 chmod：这是策略写入门径，不是策略求值对象）。
///
/// 校验分层（ADR-018 三层 + 编码层）：
/// 1. `count <= ACE_WIRE_MAX` → 越界 `InvalidParam`（防超长表制造资源压力）；
/// 2. `validate_user_range(aces_ptr, count*24, Read)` → 数组整体在窗口内且页表就绪；
/// 3. 逐条 `AceWire::to_ace()` 严格解码（畸形即 `InvalidParam`，绝不静默忽略 S09）；
/// 4. **全部解码成功后才写回**——避免「前几条写进去、后面解码失败」的半套策略。
///
/// 只改显式 ACE：classic 三段 / 属主 / 门禁位一律原样（与 chmod 的纪律对称）。
fn sys_entry_set_aces(path_ptr: u64, aces_ptr: u64, count: u64) -> u64 {
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    if count > vfs::inode::ACE_WIRE_MAX as u64 {
        return pack_err(Error::InvalidParam);
    }
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
    let root = crate::vfs_init::root();
    let node = match root.resolve(&path, false) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let identity = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    let meta = match node.metadata() {
        Ok(m) => m,
        Err(e) => return pack_err(e),
    };
    if let Err(e) = check_chmod_access(&identity, &meta.permissions) {
        return pack_err(e);
    }
    // 先整体解码到内核侧 Vec（零副作用）——任一条畸形即整体拒绝，不写回半套。
    let mut aces: alloc::vec::Vec<vfs::inode::Ace> = alloc::vec::Vec::new();
    if count > 0 {
        let bytes = count as usize * vfs::inode::ACE_WIRE_SIZE;
        if let Err(e) = validate_user_range(aces_ptr, bytes as u64, UserAccess::Read) {
            return pack_err(e);
        }
        for i in 0..count as usize {
            let mut wire = vfs::inode::AceWire {
                principal_kind: 0,
                principal_id: 0,
                allow: 0,
                perms: 0,
                inherit: 0,
                reserved: 0,
            };
            // 定长结构整体读入（copy_from_user 走 STAC 窗口；SMAP 下不可直接解引用）。
            let dst = (&mut wire as *mut vfs::inode::AceWire) as *mut u8;
            unsafe {
                arch_x86_64::mmio::copy_from_user(
                    dst,
                    aces_ptr + (i * vfs::inode::ACE_WIRE_SIZE) as u64,
                    vfs::inode::ACE_WIRE_SIZE,
                );
            }
            match wire.to_ace() {
                Ok(a) => aces.push(a),
                Err(e) => return pack_err(e),
            }
        }
    }
    // 写回：只替换显式 ACE 列表，其余维度原样（S13 单点）。
    let policy = meta.permissions.with_explicit_aces(aces);
    match node.set_permissions(&policy) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// A2-6 / ADR-040 §3.5.1 G4：**读取节点显式 ACE 列表**。
///
/// 授权面（与 stat 同源）：**READ** 权限。ACE 列表是策略的可见部分，读它
/// 与读元数据同级——能看到策略不等于能改策略（改的授权见 `sys_entry_set_aces`）。
///
/// `a4=cap` 为调用方容量；返回**实际条数**。三条路径：
/// 1. 节点 ACE 数 > `cap` → `NoSpace`（**不截断**：截断会让用户态误以为
///    拿到全部策略，是安全面的伪成功 S09）；
/// 2. 成功 → 返回条数，写回 `count*24` 字节；
/// 3. `cap=0` → 合法的**探测**调用：不写任何字节，只返回条数。
fn sys_entry_read_aces(path_ptr: u64, out_ptr: u64, cap: u64) -> u64 {
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    if cap > vfs::inode::ACE_WIRE_MAX as u64 {
        return pack_err(Error::InvalidParam);
    }
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
    let root = crate::vfs_init::root();
    let node = match root.resolve(&path, false) {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let identity = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    if let Err(e) = check_access(&identity, node.as_ref(), vfs::inode::PermBits::READ) {
        return pack_err(e);
    }
    let meta = match node.metadata() {
        Ok(m) => m,
        Err(e) => return pack_err(e),
    };
    let aces: alloc::vec::Vec<vfs::inode::Ace> = meta.permissions.explicit_aces().collect();
    // `cap=0` 是**合法的探测调用**：只回报条数、不写任何字节。必须早于容量检查
    // ——否则 0 会先被"容量不足"截住，探测路径永远不可达（实现期实测发现）。
    if cap == 0 {
        return pack_ok(aces.len() as u64);
    }
    // 容量不足：如实 NoSpace，绝不截断（截断＝用户态误以为拿到全部策略）。
    if aces.len() as u64 > cap {
        return pack_err(Error::NoSpace);
    }
    if aces.is_empty() {
        return pack_ok(0);
    }
    let bytes = aces.len() * vfs::inode::ACE_WIRE_SIZE;
    if let Err(e) = validate_user_range(out_ptr, bytes as u64, UserAccess::Write) {
        return pack_err(e);
    }
    for (i, ace) in aces.iter().enumerate() {
        let wire = vfs::inode::AceWire::from_ace(*ace);
        let src = (&wire as *const vfs::inode::AceWire) as *const u8;
        unsafe {
            arch_x86_64::mmio::copy_to_user(
                out_ptr + (i * vfs::inode::ACE_WIRE_SIZE) as u64,
                src,
                vfs::inode::ACE_WIRE_SIZE,
            );
        }
    }
    pack_ok(aces.len() as u64)
}

fn check_parent_write_access(
    identity: &ProcessIdentity,
    parent: &alloc::sync::Arc<dyn vfs::inode::INode>,
) -> Result<(), Error> {
    check_access(identity, parent.as_ref(), vfs::inode::PermBits::WRITE)
}

/// A1-1：`ProcessIdentity` → vfs `Subject` 视图借用转换（`Groups::iter`
/// 零拷贝收集；依赖方向 task→vfs，vfs 不得反向依赖，见 Subject 文档）。
/// 调用点均为 syscall 入口（非热路径），收集分配如实付出。
fn policy_allows(
    identity: &ProcessIdentity,
    policy: &vfs::inode::AccessPolicy,
    required: vfs::inode::PermBits,
) -> Result<(), Error> {
    let groups: alloc::vec::Vec<u32> = identity.groups.iter().collect();
    let subject = vfs::inode::Subject {
        uid: identity.uid,
        gid: identity.gid,
        groups: &groups,
    };
    policy.evaluate(&subject, required)
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
    // A1-1：wire 位集 → AccessPolicy（兼容映射见 from_wire；创建用）。
    let perm = vfs::inode::AccessPolicy::from_wire(perm_bits);

    // ADR-014 FLAG_PIPE：匿名管道，不落文件系统。路径须为空（"" 或 "/"）。
    if flags.pipe {
        return sys_open_pipe(path, frame);
    }

    // 相对路径与进程 cwd 拼接成绝对路径（VFS 只接受绝对路径，ADR-011 M1）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }

    let root = crate::vfs_init::root();

    // A1-1：创建属主 = 创建者（POSIX 语义；wire 只传 mode，杜绝"冒充他人
    // 属主创建"）。旧"User 不得创建 system_only 节点"创建门禁随 system_only
    // 位移除而删除——门禁位现走 bit9，创建路径不再接收门禁语义（A1-3 起由
    // 父目录 Write + chown 通道重建系统节点的受控创建）。无当前进程时以
    // 默认身份 (0,0) 创建（内核启动期路径）。
    let creator = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);

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
        Err(Error::NotFound) if flags.create => {
            match root.create_file(&path, perm.classic_mode(), (creator.uid, creator.gid))
            {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            }
        }
        Err(e) => return pack_err(e),
    };

    // A1-1 / ADR-040：open 强制 = 门禁 + CAP_OWNER 豁免 + 策略求值。
    // required 由 open 位（S15 语义归调用者声明，读=Read/写=Write）。
    // 无当前进程时回退默认身份（无能力，拒绝最严）。inode 已解析、句柄未构造，
    // 为最低成本的拒绝点。
    let mut required = vfs::inode::PermBits::empty();
    if flags.read {
        required = required.union(vfs::inode::PermBits::READ);
    }
    if flags.write {
        required = required.union(vfs::inode::PermBits::WRITE);
    }
    let identity = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    if let Err(e) = enforce_open_permission(identity, &inode, required) {
        return pack_err(e);
    }

    // vfs1 M4/M3：O_DIRECTORY 强制与 append 起点真值在 FileHandle::new
    // 内完成；失败（目标非目录等）如实上抛，不再静默产出坏句柄。
    let mut handle = match vfs::file_handle::FileHandle::new(inode, flags) {
        Ok(h) => h,
        Err(e) => return pack_err(e),
    };
    // I-EVENTS P1（§6.15）：**每读者事件流**节点在打开时铸造读者令牌
    // （游标 = 读墙，见 vfs::stream::open_reader）——读位置按读者分账，
    // dup2/fork 继承同一游标，关闭收敛。铸造失败（后端缺失等）不上抛：
    // 句柄退回 backlog 读形态（stream_token 恒 None → read_at 单径），
    // 语义仍是真实的，只是不分账（S17 保守侧）。
    if handle.inode.event_stream_reader().is_some() {
        let _ = handle.attach_event_reader();
    }
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

/// 焦点实例切换（SYS_STREAM_FOCUS_SET，ADR-048 T3，owner 裁决 α）：
/// a1 = 目标实例 id。**门禁先行**（audio attach 同款纪律：先权限后解析，
/// 防止非特权调用者从返回码差异探测实例存在性——信息泄露）：非
/// CAP_SYSTEM → EACCES + 日志留痕；实例不存在 → InvalidParam（越界
/// 如实拒绝，绝不静默夹取，S17）；成功 → 返回 0 并留痕（审计可查谁
/// 何时切了焦点——终端语义下这是可观测的用户可见动作）。
///
/// 内核对 console 保持零知识 + 一致性判定：本函数不碰字节、不碰环，
/// 只把「焦点真值」改写到 VFS 层单点（`vfs::console::set_focus_instance`，
/// T2 落的 registry 真值），stdin 真值链（input_read/input_peek）随之
/// 自然改道——单一事实源，无第二通道（S13/S15）。
fn sys_stream_focus_set(frame: &mut SyscallFrame) -> u64 {
    if !current_has_cap(Caps::SYSTEM) {
        let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
        klib::info!("[console] pid={} FOCUS_SET denied (no CAP_SYSTEM)", pid);
        return pack_err(Error::PermissionDenied);
    }
    let instance = frame.a1 as usize;
    match vfs::console::set_focus_instance(instance) {
        Ok(()) => {
            let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
            klib::info!("[console] pid={} focus -> instance {}", pid, instance);
            pack_ok(0)
        }
        Err(e) => {
            let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
            klib::info!("[console] pid={} FOCUS_SET instance={} rejected: {:?}", pid, instance, e);
            pack_err(e)
        }
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
    // A1-3 / §2.6：元数据读随 readdir 归 Read 语义——fstat 也强制。
    let identity = proc.identity();
    if let Err(e) = check_access(&identity, fh.inode.as_ref(), vfs::inode::PermBits::READ) {
        return pack_err(e);
    }
    let meta = match fh.inode.metadata() {
        Ok(m) => m,
        Err(e) => return pack_err(e),
    };
    // J-TOKEN-A / ADR-044 §1.2：终端真值由**节点**自述（`is_terminal()`）。
    // 本函数是唯一能看到 inode 的地方，故在此补写；`from_metadata` 只看得见
    // `FileMetadata`（无节点身份），故它本身不得虚报。
    let info = vfs::inode::StatInfo::with_console_owner(
        vfs::inode::StatInfo::with_terminal(
            vfs::inode::StatInfo::from_metadata(&meta),
            fh.inode.is_terminal(),
        ),
        fh.inode.console_owner(),
    );
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
    // A1 无限化：目标 fd 编号不再有单进程上限——表扩展受全局 fd 闸门约束，
    // 拒绝语义（NoSpace）经 set_fd 返回（原入口 MAX_FDS 预检删除）。
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
    // 要整体 move 进 set_fd。id 先存副本：set_fd 失败时 old_handle 已 move，
    // 回滚需要这个 id（A1 闸门拒绝路径，S20）。
    let old_pipe_id: Option<u64> = if let vfs::file_handle::OpenHandle::Pipe { id } = &old_handle {
        if ipc::pipe_ref_inc(*id).is_err() {
            return pack_err(Error::NoSpace);
        }
        Some(*id)
    } else {
        None
    };
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
        Err(_) => {
            // A1：set_fd 可因全局闸门拒绝（原入口预检已删）——pipe 引用
            // 必须回滚，否则闸门拒绝路径泄漏 ref（S20）。
            if let Some(id) = old_pipe_id {
                let _ = ipc::pipe_ref_dec(id);
            }
            pack_err(Error::NoSpace)
        }
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
    // A1-1：wire 位集 → classic mode（from_wire 兼容映射统一入口）。
    // 创建属主 = 当前进程身份（POSIX 语义；内核启动期回退默认 (0,0)）。
    let mode = vfs::inode::AccessPolicy::from_wire(perm_bits).classic_mode();
    let creator = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    let owner = (creator.uid, creator.gid);
    // 相对路径与进程 cwd 拼接（VFS 只接受绝对路径）。
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
    let root = crate::vfs_init::root();
    // A1-3 / ADR-040 §2.6：mkdir/create = **父目录 Write**。
    // A2-8 / §3.5 G3：同一处解析父节点，供权限检查与 **ACE 继承派生**共用
    // （单点解析，不重复 lookup）。
    let parent = match split_parent(&path) {
        Some((parent_path, _)) => {
            let parent = match root.resolve(&parent_path, true) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            };
            if let Err(e) = check_parent_write_access(&creator, &parent) {
                return pack_err(e);
            }
            parent
        }
        None => return pack_err(Error::InvalidParam),
    };
    // A2-8 / ADR-040 §3.5 G3：**ACE 继承**——新建子节点的策略由父目录显式列表中
    // `inherit == true` 的 ACE 派生（`derive_for_child` 单点，不引入第二条求值
    // 路径 S13）。父目录无 inherit ACE 时派生结果与纯 classic 等价，故本步对既有
    // 行为零影响（无显式 ACE 的父目录派生出的子策略 = 请求 mode 的 classic 三段）。
    let parent_policy = match parent.metadata() {
        Ok(m) => m.permissions,
        Err(e) => return pack_err(e),
    };
    let mut child_policy = parent_policy.derive_for_child(mode);
    // 属主 = 创建者（POSIX；`derive_for_child` 有意不继承父属主，在此烙印）。
    child_policy = child_policy.with_owner(owner.0, owner.1);
    let inherited_count = child_policy.explicit_aces().count();
    match kind {
        crate::syscall::ENTRY_KIND_DIRECTORY => match root.mkdir(&path, mode, owner) {
            Ok(node) => {
                if let Err(e) = apply_inherited_policy(&node, &child_policy) {
                    return pack_err(e);
                }
                if inherited_count > 0 {
                    klib::info!("[vfs] inherited {} ACE(s) into new dir {}", inherited_count, path);
                }
                pack_ok(0)
            }
            Err(e) => pack_err(e),
        },
        crate::syscall::ENTRY_KIND_FILE => match root.create_file(&path, mode, owner) {
            Ok(node) => {
                if let Err(e) = apply_inherited_policy(&node, &child_policy) {
                    return pack_err(e);
                }
                if inherited_count > 0 {
                    klib::info!("[vfs] inherited {} ACE(s) into new file {}", inherited_count, path);
                }
                pack_ok(0)
            }
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
    let root = crate::vfs_init::root();
    // A1-3 / ADR-040 §2.6：unlink = **父目录 Write**（经父目录路径求值）。
    let parent_node = match split_parent(&path) {
        Some((parent_path, _)) => {
            let parent = match root.resolve(&parent_path, true) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            };
            let identity = current_proc_mut()
                .map(|p| p.identity())
                .unwrap_or_else(ProcessIdentity::default_user);
            if let Err(e) = check_parent_write_access(&identity, &parent) {
                return pack_err(e);
            }
            parent
        }
        None => return pack_err(Error::InvalidParam),
    };
    // A1-5 / §2.6：unlink 还需**目标属主**面（或 `CAP_OWNER`）。B3 修正
    // （2026-09-28 晚）：增**父目录属主豁免**——目录属主管理自己目录内的
    // 条目（/system/console-requests 属主 = init 0:0，消费 openvt（uid
    // 1000）创建的请求文件是设计语义；此前 init 无 CAP_OWNER 而被拒 →
    // 请求文件永不消失 → 巡检重复 drop 刷屏）。判定序：父目录写面 →
    // 目标属主面（父属主豁免在后者内）。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        let target = match root.resolve(&path, false) {
            Ok(n) => n,
            Err(e) => return pack_err(e),
        };
        let meta = match target.metadata() {
            Ok(m) => m,
            Err(e) => return pack_err(e),
        };
        let parent_meta = match parent_node.metadata() {
            Ok(m) => m,
            Err(e) => return pack_err(e),
        };
        let owner_ok = identity.uid == meta.permissions.owner_uid()
            || identity.uid == parent_meta.permissions.owner_uid()
            || identity.caps.contains(Caps::OWNER);
        if !owner_ok {
            return pack_err(Error::PermissionDenied);
        }
    }
    match root.unlink(&path) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// A1-3：路径拆分（父目录路径, 末端名）。根路径 `"/"` 返回 None——
/// 根无父目录可校验（根操作走 CAP 语义，见 vfs_init 引导身份）。
fn split_parent(path: &str) -> Option<(alloc::string::String, alloc::string::String)> {
    let p = path.trim_end_matches('/');
    let idx = p.rfind('/')?;
    let name = alloc::string::String::from(&p[idx + 1..]);
    if name.is_empty() {
        return None;
    }
    let parent = if idx == 0 {
        alloc::string::String::from("/")
    } else {
        alloc::string::String::from(&p[..idx])
    };
    Some((parent, name))
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &old_path) {
            return pack_err(e);
        }
    }
            let new_path = match absolute_path(&new_path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &new_path) {
            return pack_err(e);
        }
    }
            let root = crate::vfs_init::root();
            // A1-3 / ADR-040 §2.6：rename = **父目录 Write**。源与目标同父
            // 是本 syscall 的既有约束（跨目录如实 NotSupported），故对父
            // 目录求值一次即覆盖读写两面。
            match split_parent(&old_path) {
                Some((parent_path, _)) => {
                    let parent = match root.resolve(&parent_path, true) {
                        Ok(n) => n,
                        Err(e) => return pack_err(e),
                    };
                    let identity = current_proc_mut()
                        .map(|p| p.identity())
                        .unwrap_or_else(ProcessIdentity::default_user);
                    if let Err(e) = check_parent_write_access(&identity, &parent) {
                        return pack_err(e);
                    }
                }
                None => return pack_err(Error::InvalidParam),
            }
            // A1-5 / §2.6：rename 还需**目标属主**面（或 `CAP_OWNER`）——
            // 源（被改名者）与目标（被覆盖者，若存在）的属主即持有者。
            // 源/目标不存在时其属主面空缺：缺失源的报错语义（跨目录
            // NotSupported / 同目录 NotFound）交由 root.rename 原生契约，
            // 属主面不得截胡（test-syscall-entry-update 5a 锚定的契约）。
            let identity = current_proc_mut()
                .map(|p| p.identity())
                .unwrap_or_else(ProcessIdentity::default_user);
            if let Ok(src) = root.resolve(&old_path, false) {
                if let Ok(meta) = src.metadata() {
                    if identity.uid != meta.permissions.owner_uid()
                        && !identity.caps.contains(Caps::OWNER)
                    {
                        return pack_err(Error::PermissionDenied);
                    }
                }
            }
            if let Ok(dst) = root.resolve(&new_path, false) {
                if let Ok(meta) = dst.metadata() {
                    if identity.uid != meta.permissions.owner_uid()
                        && !identity.caps.contains(Caps::OWNER)
                    {
                        return pack_err(Error::PermissionDenied);
                    }
                }
            }
            match root.rename(&old_path, &new_path) {
                Ok(()) => pack_ok(0),
                Err(e) => pack_err(e),
            }
        }
        // chmod：a4=1，a1=path, a2=mode_bits（A1-1：classic 9 位 + 门禁 bit9）。
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
            let root = crate::vfs_init::root();
            let node = match root.resolve(&path, false) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            };
            // A1-3 / ADR-040 §2.6：chmod = **属主或 CAP_OWNER**（此前完全
            // 缺失——PRE-6 独立高危项）。门禁不适用（chmod 是门禁写入门径）。
            let identity = current_proc_mut()
                .map(|p| p.identity())
                .unwrap_or_else(ProcessIdentity::default_user);
            let meta = match node.metadata() {
                Ok(m) => m,
                Err(e) => return pack_err(e),
            };
            if let Err(e) = check_chmod_access(&identity, &meta.permissions) {
                return pack_err(e);
            }
            // A1-5（chmod 保主）+ A2-6（chmod 保 ACE）：chmod 是**写门径**，只改
            // classic 9 位 mode——属主、**显式 ACE 列表**、门禁位一律原样保留。
            // 此前经 `from_wire(mode_bits)` 重建策略：`from_wire` 恒产出空 ACE
            // 列表（wire 只有单个 u32，无 ACE 通道），于是**一次 chmod 就把全部
            // 显式 ACE 清零**（ADR-040 §3.5.3 隐患）。改由 `with_classic_mode`
            // 单点派生（S13）：只换 mode，其余字段原样。
            let policy = meta.permissions.with_classic_mode(mode_bits);
            match node.set_permissions(&policy) {
                Ok(()) => pack_ok(0),
                Err(e) => pack_err(e),
            }
        }
        // chown：a4=2，a1=path, a2=uid, a3=gid（A1-7 / ADR-014「更新节点元数据」。
        // 强制面 = chmod（属主或 CAP_OWNER）+ 易他主需 CAP_SYSTEM）。
        ENTRY_UPDATE_CHOWN => {
            let path_ptr = frame.a1;
            let new_uid = frame.a2 as u32;
            let new_gid = frame.a3 as u32;
            let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            let path = match absolute_path(&path) {
                Ok(a) => a,
                Err(e) => return pack_err(e),
            };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
            let root = crate::vfs_init::root();
            let node = match root.resolve(&path, false) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            };
            let identity = current_proc_mut()
                .map(|p| p.identity())
                .unwrap_or_else(ProcessIdentity::default_user);
            let meta = match node.metadata() {
                Ok(m) => m,
                Err(e) => return pack_err(e),
            };
            // 强制面：属主或 CAP_OWNER 可发 chown；**易他主**（新属主 ≠ 调用者
            // 且调用者非 CAP_SYSTEM）拒绝——POSIX chown 限制面（防权限赠予）。
            if let Err(e) = check_chmod_access(&identity, &meta.permissions) {
                return pack_err(e);
            }
            let changes_owner = new_uid != meta.permissions.owner_uid();
            if changes_owner && !identity.caps.contains(Caps::SYSTEM) {
                return pack_err(Error::PermissionDenied);
            }
            // A1-5 / A2-6：with_owner 烙印新属主。**必须从现有策略派生**，不得经
            // `from_wire` 重建——`from_wire` 恒产出空 ACE 列表（wire 只有单个 u32，
            // 无 ACE 通道），重建即**静默清空全部显式 ACE**（ADR-040 §3.5.3 隐患；
            // 显式 deny 被清空后主体落到 classic 尾部段，可能由拒绝变放行）。
            // 原注释称"显式 ACE 如实整体替换"，**该说法不实**——是"替换为空"。
            // with_owner 单点只换属主，classic 三段/门禁位/ACE 列表原样保留。
            let policy = meta.permissions.with_owner(new_uid, new_gid);
            match node.set_permissions(&policy) {
                Ok(()) => pack_ok(0),
                Err(e) => pack_err(e),
            }
        }
        // A2-6 / ADR-040 §3.5.1 G4：设置显式 ACE 列表（整表替换）。
        // a4=3，a1=path, a2=aces_ptr（`[AceWire; count]`）, a3=count。
        ENTRY_UPDATE_SET_ACES => {
            let aces_path_ptr = frame.a1;
            let aces_ptr = frame.a2;
            let count = frame.a3;
            sys_entry_set_aces(aces_path_ptr, aces_ptr, count)
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }

    // A2-6 / ADR-040 §3.5.1 G4：第三原语 —— 读取显式 ACE 列表（a4 == ENTRY_READ_ACES）。
    // 早于 stat/readdir 分派：本模式**不**解析为目录项列表，而是把节点显式 ACE
    // 以 `AceWire` 定长数组写入用户缓冲（a2=out_ptr，a3=cap）。
    if frame.a4 == ENTRY_READ_ACES {
        return sys_entry_read_aces(path_ptr, frame.a2, frame.a3);
    }

    // 第二原语：stat 模式（a4 == ENTRY_READ_STAT）。解析路径后把
    // 节点元数据以 StatInfo 定长结构整块拷入用户缓冲（a2），返回结构字节数。
    // follow_symlink=true（POSIX stat 跟软链符），与 readdir 同路径解析。
    if frame.a4 == ENTRY_READ_STAT {
        // A2-3 / §3.4：遍历检查已由本函数入口（readdir 之上）统一完成，此处不重复。
        // 单点纪律：同一次调用只检查一次，避免"两个地方各查一半"导致的不一致。
        let root = crate::vfs_init::root();
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        let node = match root.resolve(&path, true) {
            Ok(n) => n,
            Err(e) => return pack_err(e),
        };
        // A1-3 / §2.6：stat 面随 readdir 归目录读语义——对节点求 Read。
        if let Err(e) = check_access(&identity, node.as_ref(), vfs::inode::PermBits::READ) {
            return pack_err(e);
        }
        let meta = match node.metadata() {
            Ok(m) => m,
            Err(e) => return pack_err(e),
        };
        // 同 `sys_fstat`：终端真值取自节点自述（J-TOKEN-A）。
        // `stat(path)` 与 `fstat(fd)` 对同一节点必须给出相同答案，
        // 否则两条查询通道会互相矛盾。
        let info = vfs::inode::StatInfo::with_console_owner(
            vfs::inode::StatInfo::with_terminal(
                vfs::inode::StatInfo::from_metadata(&meta),
                node.is_terminal(),
            ),
            node.console_owner(),
        );
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
    // A1-3 / ADR-040 §2.6：readdir 面强制——目录 Read。
    let identity = current_proc_mut()
        .map(|p| p.identity())
        .unwrap_or_else(ProcessIdentity::default_user);
    if let Err(e) = check_access(&identity, dir_node.as_ref(), vfs::inode::PermBits::READ) {
        return pack_err(e);
    }

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
    if pipe_id.is_none() {
        // A1-3 / ADR-040 §2.6：**每次** write 调用都强制（非仅 open）——
        // 拿到 fd 后权限收紧必须即刻生效（§3.2 #5）。
        let identity = proc.identity();
        let handle = match proc.get_fd(fd as usize) {
            Some(vfs::file_handle::OpenHandle::File(h)) => h,
            _ => unreachable!("pipe branch handled above"),
        };
        if let Err(e) = check_access(&identity, handle.inode.as_ref(), vfs::inode::PermBits::WRITE) {
            return pack_err(e);
        }
    }
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
    // §6.12.5（所有者裁决甲）：`a5` 为非阻塞标志。
    // 此前恒为 0，故不带该位时行为逐位不变（S17 安全侧默认）。
    // 判定单点在 `read_is_nonblock`（S13），不在此处硬编码位运算。
    let nonblock = read_is_nonblock(frame.a5);
    let peek = read_is_peek(frame.a5);
    // 遥测（§6.14.4n→Ⅰ 转正）：read 进入计数，按 a5 非阻塞位分流。
    // **单点在 sys_read**（S13）——此前放在 `syscall_entry` 按 nr 判，计数器只应
    // 由本函数增减。计数频率为键盘/流读量级，Relaxed 原子加可忽略（判定见
    // `STREAM_READS` 文档）。 `nr == SYS_STREAM_READ` 的等价性：`sys_read` 仅由
    // `dispatch` 的 `SYS_STREAM_READ` 分支调用（单一调用点，S28）。
    if nonblock {
        STREAM_READS_NONBLOCK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    } else {
        STREAM_READS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
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
    if pipe_id.is_none() {
        // A1-3 / ADR-040 §2.6：**每次** read 调用都强制（非仅 open）——
        // 拿到 fd 后权限收紧必须即刻生效（§3.2 #5）。
        let identity = proc.identity();
        let handle = match proc.get_fd(fd as usize) {
            Some(vfs::file_handle::OpenHandle::File(h)) => h,
            _ => unreachable!("pipe branch handled above"),
        };
        if let Err(e) = check_access(&identity, handle.inode.as_ref(), vfs::inode::PermBits::READ) {
            return done(pack_err(e));
        }
    }
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

    // §6.12.5（裁决甲）：**预览**路径——节点声明了预览能力时，
    // 只读不推进：把看到的那一字节交付给调用方，而它仍留在队列里给下一个读者。
    //
    // 为何这样对：前台子进程运行期间，shell 的探键**不得**消费
    // 属于子进程的按键（那些是 `cat` 之类的正当输入）。
    // 旧实现只能取走再判断，故静默丢弃
    // （实测：`/programs/spinburn.elf` → `/prams/spinburn.elf`）。
    if peek {
        if let Some(ch) = handle.inode.peek_input() {
            let one = [ch];
            unsafe {
                arch_x86_64::mmio::copy_to_user(buf, one.as_ptr(), 1);
            }
            return done(pack_ok(1));
        }
        // 无数据：如实告诉调用方「现在没有」，**不登记等待者**。
        return done(pack_err(Error::WouldBlock));
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
        // S19：同 read 路径——用户可控 u64 加法一律 checked。
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
            // I-EVENTS 阶段 2（ADR-047）：键盘事件记录流的**空读不是 EOF**，
            // 而是「此刻没有键事件」——等待源是 IRQ1，稍后必有。故在
            // total==0 时登记等待者并挂起（`push_event` → `wake_input_event`
            // 唤醒后用户态经哨兵重试取记录），而不是把 Ok(0) 当 EOF 交付。
            //
            // 已在本次 read 交付过部分记录（total>0）则按短读如实返回：
            // 让调用方先消费已到的记录，避免"为了凑满一次调用而扣住数据"。
            // 节点真值判定（S15）：仅 `input_event_stream()` 自述为真的节点走
            // 此路，普通文件/其它设备的 Ok(0) 仍逐位保持原 EOF 语义。
            Ok(0) => {
                // §6.15 P2：console 字节流（甲-a 字节端）——空读是「consoled
                // 尚未喂入」而非 EOF。真值判定（S15）与事件支路同构：只有
                // `console_stream()` 自述为真的节点走此路，其余 Ok(0) 逐位
                // 保持原 EOF 语义。探针 = 环水位 `used() > 0`（S15 单点：与
                // `ConsoleRing::read` 的消费判据同源）。
                if total == 0 && handle.inode.console_stream() {
                    // 交互输入停车前的行缓冲冲刷（事件支路同一纪律）：读者
                    // 可能刚写过**无换行**的部分行——不冲刷则输出滞留行缓冲，
                    // 用户在进程停车的整个期间什么都看不到（r8 实测缺陷）。
                    klib::console::flush_all_line_buffers();
                    match console_blocking(frame, &handle.inode) {
                        // 已挂起切走 / 已如实交付（并发等待者被占时的 0 字节）：
                        // 本帧结果已定，入口不得再写返回值。
                        Some(r) => return r,
                        // 锁内复检发现字节已到：回到循环顶部重读交付。
                        None => continue,
                    }
                }
                if total == 0 && handle.inode.input_event_stream() {
                    // P1（§6.15）：锁内复检探针按**本读者的判定**注入——
                    // 有令牌（每读者）用 `tok.has_data()`（游标 vs 写指针）；
                    // 无令牌（backlog 形态）用 `backlog_probe_cursor`（与
                    // stream_pop_next 判据同源）；都不可用则退全局真值。
                    // 全局 `has_event()` 在多读者下会把被慢读者钉住的记录
                    // 算作本读者的数据，造成复检-重读死循环（§6.13 同族）。
                    let probe = || -> bool {
                        if let Some(tok) = handle.stream_token.as_ref() {
                            tok.has_data()
                        } else if let Some(prov) = handle.inode.event_stream_reader() {
                            vfs::stream::backlog_probe_cursor(&prov).is_some()
                        } else {
                            arch_x86_64::keyboard::has_event()
                        }
                    };
                    // 交互输入阻塞前的行缓冲冲刷（与 stdin 支路同一纪律，
                    // S13 单径）：事件流读者停车前可能刚写过**无换行**的部分行
                    // （如 demo 的 `[CHAR a]`）——不冲刷则输出滞留行缓冲，用户
                    // 在进程停车的整个期间什么都看不到（r8 实测缺陷）。
                    klib::console::flush_all_line_buffers();
                    match input_event_blocking(frame, probe) {
                        // 已挂起切走（`Switched`）或已如实交付（等待者被占
                        // 时的 0 字节）：本帧结果已定，入口不得再写返回值。
                        Some(r) => return r,
                        // 复检发现记录已到：回到循环顶部重读并交付。
                        // 循环有进展的保证见 `input_event_blocking` 的注释
                        // （仅事件环非空时返回本支）。
                        None => continue,
                    }
                }
                break; // EOF（total==0 时即原始 EOF 语义）
            }
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
                //
                // 交互读前的行缓冲冲刷：shell 的提示符/回显是逐字符 write（无
                // `\n`），全部攒在 stdout 行缓冲里；阻塞等键之前冲刷，用户才
                // 能看到即时回显（否则盲打无回显，Enter 后整行突然吐出——
                // 实测缺陷）。冲刷的是整行片段，行原子性不变。
                klib::console::flush_all_line_buffers();
                // §6.12.5（裁决甲）：**非阻塞探键**路径。
                //
                // `peek_input()` 是节点真值（S15）：能不能预览由节点自述。
                // 预览到的字节写进调用方缓冲并如实交付（长度 1），
                // 但**不推进读指针**——故此处还需真正取走那一字节（否则
                // 调用方会看到同一字节无限次）。
                //
                // 故本分支只做一件事：**如实告诉调用方「现在无数据」**，
                // 而不登记等待者。调用方（shell 探键）自己决定是否取走。
                if nonblock && total == 0 && e == Error::WouldBlock {
                    return done(pack_err(Error::WouldBlock));
                }
                if total == 0 && e == Error::WouldBlock && handle.inode.interactive_input() {
                    // I-EVENTS P4 单径切换（§6.15）→ P5 轨道 A 退役：stdin 的
                    // 唯一等待源是 console 环（consoled 落环唤醒），登记
                    // CONSOLE_WAITER。旧 KBD_WAITER 键盘等待路径已整体退役
                    // （本分支的 else 臂曾直呼 task::block_for_kbd，P5-a 移除；
                    // 节点真值 `console_stream()` 唯一实现是 StdinNode=true，
                    // 故此处即 stdin 全部阻塞形态，无第二形态）。DataReady
                    // （None）：复检发现字节已到——回循环顶部重读交付（与
                    // Ok(0) console 支路的 `None => continue` 同一契约；落穿
                    // 会被 total==0 误判成 WouldBlock 返回，把「有数据」谎报成
                    // 「无数据」，S09 红线）。
                    if let Some(r) = console_blocking(frame, &handle.inode) {
                        return r;
                    }
                    continue;
                }
                // A2：音频 dsp 节点的空读（Waiting 源是 PCM 数据到达，非键盘）。
                // 与上一分支**互斥**：`interactive_input` 仅 stdin 为真，本分支
                // 再要求非 interactive，故两条路径不可能同时成立——stdin 的既有
                // 行为逐位不变（回归零风险）。
                //
                // 节点自述取代硬编码特判（A2.5）：`blocks_when_empty` 由 DspNode
                // 实现，且**仅在确有消费者时**为真——无消费者时空读是"没人会产生",
                // 不是"稍后会有"，不睡。
                if total == 0
                    && e == Error::WouldBlock
                    && !handle.inode.interactive_input()
                    && handle.inode.blocks_when_empty()
                {
                    return audio_fetch_blocking(frame, &handle.inode);
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

/// 键盘事件记录流空读的阻塞路径（I-EVENTS 阶段 2，ADR-047）。
///
/// 与 [`event_wait_blocking`] 同构（S15 单点：同一套登记→复检→挂起纪律，
/// 不另造一套）：登记 `IN_EVENT_WAITER` → 在锁内复检事件环 → 仍空则挂起
/// 本进程并切走；IRQ1 的 `push_event` 经 `task::wake_input_event` 唤醒。
///
/// **不做超时**（与 `event_wait_blocking` / `audio_fetch_blocking` 的差异，
/// 是刻意的）：键盘事件等待是**无限期**语义——`read` 一个键盘设备本就应当
/// 阻塞到有按键为止（POSIX 终端/输入设备语义）。音频取超时是因为其生产者
/// 可能是已死的驱动（无限等待会让调用者永久挂死）；键盘的生产者是 IRQ1，
/// 硬件中断永不「退出」，故无限等待不会变成挂死。用户态若需非阻塞语义，
/// 走 `read_nonblocking`（探键）或 `yield` 自旋——那是调用方的选择，
/// 不是节点的默认。
///
/// 返回 `Some(result)` 表示**本帧已被接管或已交付**（调用方须直接返回该
/// 结果）；`None` 表示「记录已到、请调用方重读交付」（调用方 `continue`）。
/// 三态语义与成因一一对应：
/// - `Some(Switched)`：已挂起切走，用户态经 `-EAGAIN` 哨兵重试；
/// - `Some(Done(0))`：`IN_EVENT_WAITER` 已被别的进程占用，如实交付
///   「读走 0 条」——不抢别人的记录、也不谎报数据（KM15 单读者仲裁）；
/// - `None`：锁内复检发现记录**确已到达**（登记与到达的竞争由本复检闭合，
///   见 `block_for_input_event` 的 lost-wakeup 论证），重读即可交付。
///
/// **诊断日志**：仅在「真的切走」时留一条运行期痕迹（同 audio 路径纪律）——
/// 事件阻塞是本批次无法在启动期测试覆盖的路径，e2e 需要能区分
/// 「挂在等键」与「卡在别处」。
///
/// 事件流空读导致的内核阻塞次数（S09 可观察，永久遥测，§6.14.4n 裁决 Ⅰ 转正；
/// 由 `input_event_blocking` 的 `Switched` 分支递增）。
///
/// **为何是原子计数而非日志**：本计数在**切换路径上**递增，而日志会取控制台/
/// 串口锁——切换会整体替换中断帧，锁可能随被切走的帧一起悬挂（实测缺陷：
/// 加日志后 evdemo 固定在第 6 轮冻结）。计数器无锁、无分配，切换前安全。
/// 真机验收以「evdemo 的 `waits=` 与连续阻塞-唤醒循环」为判据，不依赖日志。
pub static BLOCKED_ON_EVENTS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// console 空读阻塞进入次数（§6.15 P2，S09 可观察——与 `BLOCKED_ON_EVENTS`
/// 同款纪律：切换路径上不能取控制台锁留日志，只累加原子计数，由
/// `/devices/console/status` 读取。用于区分「真阻塞」（几乎不增）与
/// 「用户态空转」（每轮 read 都增长））。
pub static BLOCKED_ON_CONSOLE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// `SYS_STREAM_READ`（阻塞形态，a5 无 NONBLOCK 位）的累计进入次数（S09 可观察）。
///
/// **永久遥测**（§6.14.4n 立功后所有者裁决 Ⅰ 转正；原名 `READ_SYSCALLS`，
/// 因语义是**全部流读**而非全部 read，更名以求名实相符，S15）。本进程未
/// 重启时**单调不减**（内核级累计，**不区分来源进程**）；跨时间比较必须用
/// **窗口增量**，绝对值无意义。
///
/// 用来**区分「真阻塞」与「用户态空转」**：
/// - 真阻塞：进程挂起在 read 里，计数**几乎不增**；
/// - 空转：每轮都重新 read，计数**持续增长**。
///
/// 之所以必须用**内核侧**计数：被测进程**自身的串口输出不可靠**（§6.14.4l），
/// 且 QEMU monitor 的 RIP 采样**偏向内核**、采不到用户态（§6.14.4m）。
/// 计数经现成的 `/devices/input/events/status` 暴露（S15 复用既有遥测通道）。
///
/// 单点约束：**仅 `sys_read` 的非阻塞分支之外**递增（S13）。覆盖范围含普通
/// 文件/管道等一切 `SYS_STREAM_READ` 阻塞读——按读源归因须结合窗口内行为
/// （如 `read_nonblocking` 同窗为 0 才能排除 shell 探键污染）。
pub static STREAM_READS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// `SYS_STREAM_READ` 非阻塞形态（a5 置 [`STREAM_READ_NONBLOCK`]）的累计进入
/// 次数（S09 可观察）。与 [`STREAM_READS`] 相加即流读总量。
///
/// **永久遥测**（同上，裁决 Ⅰ 转正；原名 `READ_SYSCALLS_NB`）。
/// 【缺陷记录（§6.14.4n 收尾实测）】d2a4e85 初版**只有定义没有自增点**——
/// 计数器恒为 0，当时「rnb=0 ⇒ 无 shell 探键污染」的结论是**空真**（S09 红线：
/// 测量工具本身没接电）。转正时在 `sys_read` 补上单点自增（S13）。
pub static STREAM_READS_NONBLOCK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

fn input_event_blocking(
    frame: &mut SyscallFrame,
    probe: impl Fn() -> bool,
) -> Option<DispatchResult> {
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        // 无当前进程（内核启动期）：如实返回「读走 0 条」。
        return Some(done(pack_ok(0)));
    };
    // 重新登记前清理本进程残留的等待者身份：唤醒哨兵重试的路径不清
    // 等待者表（只有真正的按键唤醒经 swap 清），残留会白占槽，槽被占满后
    // 本次登记被误判为「表已满」，退化成空读。只在仍指向本 pid 的槽清，
    // 不误伤其它读者的并发等待（与 clear_event_waiter_if 同纪律）。
    task::clear_input_event_waiter_if(pid);
    match task::block_for_input_event(arch_frame(frame), probe) {
        // 已挂起切走：本帧整体交棒，用户态经 `-EAGAIN` 哨兵重试 read。
        task::InputEventBlock::Switched => {
            // 运行期痕迹（同 audio 阻塞路径纪律）：事件阻塞无法在启动期
            // 测试覆盖，e2e 需能区分「挂在等键」与「卡在别处」。
            // S09 可观察：以**不持控制台锁**的方式留痕。此处位于切换路径上，
            // 不能用 `klib::info!`——它在切换前取控制台/串口锁，而现场即将被
            // 整体替换，锁可能随被切走的帧一起「悬挂」（实测：加了这条日志后
            // evdemo 在第 6 轮冻结）。故只累加一个原子计数，由 status 遥测读取。
            BLOCKED_ON_EVENTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let _ = pid;
            Some(DispatchResult::Switched)
        }
        // 锁内复检发现记录已到：令调用方重读交付（本轮由复检观察到，
        // 不会空转——`.0` 为 true 即「重读」信号，见函数与调用点契约）。
        task::InputEventBlock::RecordsReady => None,
        // 已有并发等待者：如实返回「读走 0 条」，不抢别人的记录。
        task::InputEventBlock::WaiterBusy => Some(done(pack_ok(0))),
    }
}

/// `SYS_STREAM_READ` 的 console 字节流空读阻塞路径（§6.15 P2）。
///
/// 与 [`input_event_blocking`] 同构（S15 单点：同一套登记→复检→挂起
/// 纪律，不另造一套），差异仅在**等待源真值**与**唤醒原语**：等待的是
/// consoled 经 `write_at` 落环的字节（唤醒钩子 `vfs::console::set_wake_hook`
/// → `task::wake_console`，vfs_init 启动期安装）；登记槽是单槽
/// `CONSOLE_WAITER`（终端读者 = 切换后的 fd 0，同一时刻至多一个前台
/// 进程阻塞在读上，单槽与业务模型吻合——audio 的独占消费者仲裁同型）。
///
/// **无超时**（与 audio 的刻意差异）：audio 的生产者可能是已死的驱动，
/// 有限超时保证调用者必返；console 的生产者是常驻 consoled，终端语义
/// 「稍后必有字节」——与 `input_event_stream` 的无限期理由同源。
///
/// 返回与 [`input_event_blocking`] 相同的三态契约：`Some(_)` 本帧已定，
/// `None` 复检发现字节已到、调用方重读交付。
fn console_blocking(
    frame: &mut SyscallFrame,
    inode: &alloc::sync::Arc<dyn vfs::inode::INode>,
) -> Option<DispatchResult> {
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        // 无当前进程（内核启动期）：如实返回「读走 0 字节」。
        return Some(done(pack_ok(0)));
    };
    // 重新登记前清理本进程残留的等待者身份（同事件支路纪律：哨兵重试
    // 路径不清登记，残留会占死单槽，让本次 CAS 失败退化成空读轮询）。
    task::clear_console_waiter_if(pid);
    // 就绪探针（S15 单点）：经节点声明的环句柄读 `used()`——**非消费**。
    // console 的 read_at 是真消费（不同于 audio 的 peek），消费式探针会把
    // 环里最后的字节交付给探针而非读者（S09 丢字节）。探针说有 = 交付
    // 路径此刻真的读得到（同一水位真值），绝不另设第二真相源；audio 的
    // `audio_ring_empty` 同款形态（环句柄 + 水位判定）。
    // 节点未声明环（默认 None）→ 探针恒假：不阻塞、走空读返回（S17 安全侧）。
    let ring = inode.as_console_ring();
    let probe = move || -> bool {
        ring.as_ref().is_some_and(|r| r.used() > 0)
    };
    match task::block_for_console(arch_frame(frame), probe) {
        // 已挂起切走：本帧整体交棒，用户态经 `-EAGAIN` 哨兵重试 read。
        task::ConsoleBlock::Switched => {
            // 运行期痕迹：切换路径上不能用 klib::info!（取控制台/串口锁，
            // 随被切走帧悬挂——实测缺陷），只累加原子计数（S09 可观察）。
            BLOCKED_ON_CONSOLE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Some(DispatchResult::Switched)
        }
        // 锁内复检发现字节已到：令调用方重读交付（本轮由复检观察到，
        // 不会空转——探针为真即「重读」信号，见函数契约）。
        task::ConsoleBlock::DataReady => None,
        // 已有并发等待者：如实返回「读走 0 字节」，不抢别人的唤醒。
        task::ConsoleBlock::WaiterBusy => Some(done(pack_ok(0))),
    }
}

/// `AUDIO_FETCH` 的无数据阻塞路径（A2，plan §3.4）。
///
/// 与 [`event_wait_blocking`] 同构：登记 AUDIO_WAITER → 复检就绪 → 入睡。
/// 数据到达时内核在 PCM 写入后调 `task::wake_audio()` 唤醒本进程。
///
/// 超时采用**有限**值（非无限）：音频管道前端若无消费者推进（驱动崩溃、
/// 进程被挂起），无限等待会让调用者永久挂死。有限超时保证调用者必定返回，
/// 由用户态决定重试策略——与 `driver_irq_wait` 同口径。
///
/// `has_data` 探针直接读 ring 水位（S15：就绪条件单点定义为"ring 非空"）。
/// 音频 `fetch` 空读阻塞的**有限**超时（纳秒）。
///
/// **取值理由（S17）**：必须**显著大于**一个驱动的 BDL 周期，否则正常
/// 欠载会被误判为超时；又必须足够短，使"驱动已死/生产者已退出"能被及时
/// 发现而不是永久挂起。intel-hda 的一个周期 = `STREAM_CHUNK_BYTES`(16 KiB)
/// ÷ 192000 B/s ≈ 85 ms，故取 500 ms（约 6 个周期）——正常播放绝不会连续
/// 6 个周期拿不到数据，而一旦拿不到，500 ms 内必定如实返回。
///
/// **为何不用无限等待**：见本文件 `audio_fetch_blocking` 的说明——初版就是
/// 事实上的无限等待，导致驱动在"已 attach 但生产者未写入"的窗口里永久睡着。
const AUDIO_FETCH_TIMEOUT_NS: u64 = 500_000_000; // 500 ms

fn audio_fetch_blocking(frame: &mut SyscallFrame, inode: &alloc::sync::Arc<dyn vfs::inode::INode>) -> DispatchResult {
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        return done(pack_err(Error::WouldBlock));
    };
    // **注册超时定时器**（本轮补上的缺陷修复）。
    //
    // 初版本函数**没有任何超时**：`wake_audio_timeout` / `set_audio_timeout_timer`
    // / `clear_audio_timeout_timer` 三个函数在 task crate 里定义齐全并已导出，
    // 却**零调用点**——本路径忘了接上。后果是 `libsys::audio::fetch` 文档承诺的
    // "阻塞等待（有限超时）"根本不存在：驱动一旦在"已 attach 但生产者尚未写入"
    // 的窗口里 fetch（实测日志 `[audio] pid=4 fetch blocking on empty ring` →
    // `switched out (asleep)` → 之后才 `[dma] alloc`），就**永久睡着**，只能等
    // 生产者首次写入才被唤醒。驱动起流因此被推迟到生产者之后，ring 在等待期间
    // 被灌满并持续背压，播放从头就落在欠载边缘。
    //
    // 与 `event_wait_blocking` 同构（S15 单点：同一套超时纪律，不另造一套）：
    // 定时器到期经 `task::wake_audio_timeout` 把保存帧 rax 预置 `0`（超时无数据）
    // 并唤醒；记录 id 供 `wake_audio` 在数据唤醒时取消。本函数所有"立即返回"的
    // 路径亦显式取消并清 AUDIO_TIMER，杜绝 stale 定时器泄漏与级联污染（S18/S21）。
    // 定时器表满时静默退化——数据到达仍能唤醒，超时仅是对活性的兜底。
    let registered_timer =
        match klib::time::set_timeout(AUDIO_FETCH_TIMEOUT_NS, task::wake_audio_timeout, pid) {
            Some(tid) => {
                task::set_audio_timeout_timer(tid);
                Some(tid)
            }
            None => None,
        };
    // 返回前取消超时定时器并清 AUDIO_TIMER（仅"已确定交付/返回"的路径调用；
    // Switched 阻塞路径不清，交给数据唤醒取消或到期自然触发）。
    let cancel_timer = |registered: Option<u64>| {
        if let Some(tid) = registered {
            klib::time::cancel_timeout(tid);
        }
        task::clear_audio_timeout_timer();
    };
    // 重新登记前清理本进程残留的音频等待者身份（超时唤醒路径不清，见
    // clear_audio_waiter_if），否则本次 CAS 失败且 wake_audio 会误读本 pid。
    task::clear_audio_waiter_if(pid);
    let probe = inode.clone();
    // 诊断日志刻意保留两条（"进入阻塞"与"真的切走"）：音频阻塞是本批次唯一
    // 无法在启动期测试中覆盖的路径，留下运行期可见痕迹使 e2e 能区分
    // "确实入睡后被唤醒"与"根本没走到阻塞"——二者在结果上都是"拿到数据"，
    // 但只有前者验证了阻塞原语。
    //
    // **修正一处曾经的错误断言**：此处原写"日志量：每次空读两行，稳态下不在
    // 热路径"。该断言是**错的**——当消费者是"从开机起就持续跑"的 DMA 供粮
    // 循环（intel-hda 的 `stream_loop`）且暂无生产者时，空 ring 阻塞**恰恰就是
    // 稳态**：每 500ms（超时周期）稳定两行，永不停止。写这句时把它误当成
    // "异常瞬态"，因而没设任何抑制，实测表现为刷屏。
    //
    // **根治在调用方而非此处**：`stream_loop` 的职责是让 DMA 不断粮，拿不到
    // 数据就该立刻补静音续播，阻塞本身就是语义错误（还会推迟 BDL 填充、
    // 让硬件重播陈旧缓冲）。故本次修的是驱动侧的阻塞，这两行日志如实保留——
    // 它们仍会在"确有生产者却真的拿不到数据"时出现，可观测性不受损。
    // 不采用降级或节流：那只是让症状不显眼，根因仍在。
    klib::info!("[audio] pid={} fetch blocking on empty ring", pid);
    match task::block_for_audio(arch_frame(frame), move || !audio_ring_empty(&probe)) {
        task::SwitchOutcome::Switched => {
            klib::info!("[audio] pid={} switched out (asleep)", pid);
            DispatchResult::Switched
        }
        // 未入睡（数据已到 / 已有并发等待者）：如实返回 WouldBlock 让用户态
        // 重试。绝不在此伪造数据。
        task::SwitchOutcome::NotSwitched => {
            // 数据已在复检时就绪 / 已有并发等待者 → 如实 EAGAIN 让调用方重试。
            let r = done(pack_err(Error::WouldBlock));
            cancel_timer(registered_timer);
            r
        }
    }
}

/// 就绪探针：该节点当前是否已有可取数据。
///
/// 经 `read_at` 的实际语义判定而非旁路读 ring——保证"探针说有"与"读得到"
/// 同源（S15 单点）。用 1 字节零长探查：不消费数据、不推进读指针。
fn audio_ring_empty(inode: &alloc::sync::Arc<dyn vfs::inode::INode>) -> bool {
    // `is_seekable()==false` 且非交互的字符节点，其 read_at 在无数据时如实
    // WouldBlock、有数据时返回 >0——用元数据大小无法判定，故实际探一次。
    // peek 语义保证不消费（vfs::audio::DspNode::read_at 不推进读指针）。
    let mut one = [0u8; 1];
    !matches!(inode.read_at(0, &mut one), Ok(n) if n > 0)
}


// ---------- A2：音频管道 syscall（plan_audio_vfs.md 批次二）----------

/// 音频 dsp 节点的规范路径（S13：单点定义，不散落字面量）。
const AUDIO_DSP_PATH: &str = "/devices/audio/dsp";

/// 解析音频 dsp 节点。节点不存在（DevFS 未挂载/未构建）→ `NotFound`。
///
/// 每次调用都经真实挂载表解析，**不缓存**节点引用：缓存会把"节点被换掉"
/// 变成静默使用陈旧对象（S15：单一事实源是挂载表，不是模块内的影子指针）。
fn audio_dsp_node() -> Result<alloc::sync::Arc<dyn vfs::inode::INode>, Error> {
    crate::vfs_init::root().resolve(AUDIO_DSP_PATH, true)
}

/// `AUDIO_ATTACH()` → 0 / -errno（AUDIO 域 0xA1）。
///
/// 把**当前进程**注册为该音频节点的独占消费者。所有权校验用当前 pid，
/// 而非调用方传入的 id——不提供"替别人 attach"的能力（S12：不开特权后门）。
///
/// 已有消费者 → `Busy`(EBUSY)：结构性占用，重试不会成功（区别于 EAGAIN）。
///
/// **特权门禁（本批次补上，与 `driver_register`/`driver_claim` 同口径）**：
///
/// `ATTACH` 是 AUDIO 域里**唯一授予独占权**的动词——`FETCH`/`COMMIT` 都先要求
/// `is_attached()`，即"先拿到这个槽"才谈得上其它。没有门禁时，任意普通进程
/// 都能：
///   1. attach 后**永不 fetch** → DMA 断粮、音乐停摆；
///   2. 因槽位独占而**挡住真正的驱动**（`EBUSY`）——拒绝服务；
///   3. `detach` 是属主限定，故它会一直占着槽直到自己退出。
/// 这三条都不是"理论风险"，而是单消费者语义的**直接推论**。
///
/// 与 `driver_register`/`driver_claim` 同用 [`current_is_system`]：二者都授予
/// 对硬件资源的独占控制，权限语义应当一致，不应一个有一个没有（S13 单点）。
///
/// **不破坏现有调用方**：`intel-hda` / `audioe2e` 均由 init 经 `exec_path` 派生，
/// 而 `exec_path` 走 `compute_child_identity` 的**继承分支**（原样继承调用者身份），
/// init 本身由内核以 `ProcessIdentity::system(1)` 引导，故二者同为 `System`。
/// 「非 System 被拒」这条路径由单测 `test_audio_attach_privilege_gate` 覆盖
/// （内核启动期测试以 init 线程身份运行，天然是 System，无法自证拒绝分支）。
fn sys_audio_attach(frame: &mut SyscallFrame) -> u64 {
    let _ = frame;
    // 先做权限判定再解析节点：避免把"无权限"与"设备不存在"混为一谈，
    // 也避免让非特权调用者从返回码差异**探测**设备是否存在（信息泄露）。
    if !current_has_cap(Caps::DEVICE) {
        let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
        klib::info!("[audio] pid={} AUDIO_ATTACH denied (no CAP_DEVICE)", pid);
        return pack_err(Error::PermissionDenied);
    }
    let node = match audio_dsp_node() {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        return pack_err(Error::InvalidParam);
    };
    let ring = match audio_ring_of(&node) {
        Some(r) => r,
        None => return pack_err(Error::NotSupported),
    };
    match ring.attach(pid) {
        Ok(()) => {
            klib::info!("[audio] pid={} attached as PCM consumer", pid);
            pack_ok(0)
        }
        Err(e) => {
            klib::info!("[audio] pid={} attach denied: {:?}", pid, e);
            pack_err(e)
        }
    }
}

/// `AUDIO_DETACH()` → 0 / -errno（AUDIO 域 0xA2）。
///
/// 非属主调用 → `PermissionDenied` 且**槽位不变**（见 `AudioRing::detach` 的 CAS）。
fn sys_audio_detach(frame: &mut SyscallFrame) -> u64 {
    let _ = frame;
    let node = match audio_dsp_node() {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        return pack_err(Error::InvalidParam);
    };
    let ring = match audio_ring_of(&node) {
        Some(r) => r,
        None => return pack_err(Error::NotSupported),
    };
    match ring.detach(pid) {
        Ok(()) => {
            klib::info!("[audio] pid={} detached; ring released", pid);
            pack_ok(0)
        }
        Err(e) => pack_err(e),
    }
}

/// `AUDIO_COMMIT(n)` → 0 / -errno（AUDIO 域 0xA4）。
///
/// 推进读指针 n 字节，释放环形空间供写者继续。**仅属主可提交**（非属主
/// `PermissionDenied`）——否则任意进程都能"消费"掉别人的数据。
/// 越界（n > 当前水位）→ `InvalidParam`，绝不静默截断（S19）。
fn sys_audio_commit(frame: &mut SyscallFrame) -> u64 {
    let n = frame.a1;
    let node = match audio_dsp_node() {
        Ok(n) => n,
        Err(e) => return pack_err(e),
    };
    let Some(pid) = current_proc_mut().map(|p| p.pid()) else {
        return pack_err(Error::InvalidParam);
    };
    let ring = match audio_ring_of(&node) {
        Some(r) => r,
        None => return pack_err(Error::NotSupported),
    };
    // 属主门禁：与 detach 同源（consumer 槽即真相），不引入第二份状态。
    if ring.consumer() != Some(pid) {
        return pack_err(Error::PermissionDenied);
    }
    // S19：n 是用户可控 u64，窄化到 usize 前必须检查（32 位目标上两者不同宽）。
    let Ok(adv) = usize::try_from(n) else {
        return pack_err(Error::InvalidParam);
    };
    match ring.commit(adv) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `AUDIO_FETCH(buf_ptr, len)` → 实取字节数 / -errno（AUDIO 域 0xA3）。
///
/// **诚实性红线（S06/S09）**：无消费者 → `NotSupported`，绝不接受后丢弃；
/// 无数据且已附加 → 阻塞等待（有限超时），唤醒后用户态重试。
///
/// 与 `read(/devices/audio/dsp)` 的分工：`read` 是非阻塞取数（无数据即
/// `WouldBlock` 并自动进入阻塞等待），本动词是**显式**取数并允许调用方
/// 自控超时。两者最终都走 ring 的 peek/commit 两阶段语义，不产生第二条数据通路。
fn sys_audio_fetch(frame: &mut SyscallFrame) -> DispatchResult {
    let buf_ptr = frame.a1;
    let len = frame.a2;
    let node = match audio_dsp_node() {
        Ok(n) => n,
        Err(e) => return done(pack_err(e)),
    };
    let ring = match audio_ring_of(&node) {
        Some(r) => r,
        None => return done(pack_err(Error::NotSupported)),
    };
    // 无消费者：如实拒绝（不睡、不丢数据）。
    if !ring.is_attached() {
        return done(pack_err(Error::NotSupported));
    }
    let want = match usize::try_from(len) {
        Ok(v) => v,
        Err(_) => return done(pack_err(Error::InvalidParam)),
    };
    if want == 0 {
        return done(pack_ok(0));
    }
    // 取一帧到内核缓冲（peek 语义：不推进读指针，等用户态 COMMIT 才推进）。
    let n = match audio_peek_into(&node, want) {
        Ok(v) => v,
        Err(e) => return done(pack_err(e)),
    };
    if n == 0 {
        // 无数据：阻塞等待（复用 read 路径的同一条阻塞实现，单一语义源）。
        return audio_fetch_blocking(frame, &node);
    }
    // 有数据：拷回用户态。拷贝失败（野指针）如实报 Fault，不谎报已取。
    let mut kbuf = alloc::vec::Vec::new();
    if kbuf.try_reserve_exact(n).is_err() {
        return done(pack_err(Error::OutOfMemory));
    }
    kbuf.resize(n, 0);
    if let Err(e) = audio_peek_into_buf(&node, &mut kbuf) {
        return done(pack_err(e));
    }
    // 用户缓冲预校验（与 read/write 路径同一把门）：野指针在此如实拒绝，
    // 绝不放进 STAC 拷贝（内核态 #PF = 整机死机）。
    if let Err(e) = validate_user_range(buf_ptr, n as u64, UserAccess::Write) {
        return done(pack_err(e));
    }
    // SAFETY：上一步已逐页确认 [buf_ptr, buf_ptr+n) 已映射且可写；kbuf 长度
    // 为 n，二者等长，copy_to_user 内部走 STAC 短窗口。
    unsafe { arch_x86_64::mmio::copy_to_user(buf_ptr, kbuf.as_ptr(), n) };
    done(pack_ok(n as u64))
}

/// 从任意 `INode` 取回其音频 ring（若该节点是音频节点）。
///
/// 经 vfs 提供的**显式**下行转换取得，不做"凡是字符设备就假定是音频"的
/// 类型臆测（那会在将来接入第二个字符设备时静默错认节点）。
fn audio_ring_of(node: &alloc::sync::Arc<dyn vfs::inode::INode>) -> Option<alloc::sync::Arc<vfs::audio::AudioRing>> {
    vfs::audio::as_audio_node(node)
}

/// 探取（不消费）至多 `want` 字节。返回实际可用字节数（可为 0）。
fn audio_peek_into(node: &alloc::sync::Arc<dyn vfs::inode::INode>, want: usize) -> Result<usize, Error> {
    match vfs::audio::as_audio_node(node) {
        Some(r) => Ok(core::cmp::min(want, r.used())),
        None => Err(Error::NotSupported),
    }
}

/// 把至多 `dst.len()` 字节从 ring 探取到 `dst`（不推进读指针）。
fn audio_peek_into_buf(node: &alloc::sync::Arc<dyn vfs::inode::INode>, dst: &mut [u8]) -> Result<(), Error> {
    match vfs::audio::as_audio_node(node) {
        Some(r) => {
            let n = r.peek(dst);
            if n == dst.len() { Ok(()) } else { Err(Error::WouldBlock) }
        }
        None => Err(Error::NotSupported),
    }
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
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
            match root.resolve(&path, true) {
                Ok(inode) => {
                    // A1-1 / ADR-040：执行前强制——门禁位（原 system_only）
                    // + CAP_OWNER 豁免 + 策略求值（required = Execute）。
                    let identity = current_proc_mut()
                        .map(|p| p.identity())
                        .unwrap_or_else(ProcessIdentity::default_user);
                    if let Err(e) = enforce_open_permission(
                        identity,
                        &inode,
                        vfs::inode::PermBits::EXECUTE,
                    ) {
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

/// A1-2 / ADR-040（承 ADR-033）：计算派生子进程身份（单点决策，供 spawn_elf_image 与测试复用）。
///
/// - `idx_or_tag == BUILTIN_INDEX_INIT`：仅持 `CAP_SYSTEM` 的调用者可派生
///   init 子进程（`uid=1` + 全能力）；无 `CAP_SYSTEM` 者返回
///   `Err(PermissionDenied)`——防"任意进程经 exec(0,..) 未认证提权"（V2）。
/// - 其余分支：原样继承调用者身份（caller 已由调用方解析为 current 或默认）。
pub fn compute_child_identity(idx_or_tag: u64, caller: ProcessIdentity) -> Result<ProcessIdentity, Error> {
    if idx_or_tag == BUILTIN_INDEX_INIT {
        if !caller.caps.contains(Caps::SYSTEM) {
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
    /// 命令行伪装成完整交付。A11（owner 指令 2026-09-27）：512 → 4096。
    ///
    /// **缓冲必须在堆上**（S33；本决定晚于 A11，以 2026-09-28 的 B3 实证为准）：
    /// 本函数运行在**16 KiB 专用 syscall 栈**上（arch percpu.rs 的
    /// `SYSCALL_STACKS`），A11 当时按"内核栈 64KB"论证的 4 KiB 栈缓冲对该预算
    /// **不成立**。实测（3P4-1）：TLS 装配给这条调用链再加几百字节后，栈写穿
    /// SYSCALL_STACKS 池、返回地址被覆盖，症状为**内核态取指 Page Fault
    /// error=0x11**——与 percpu.rs 记录的 B3 案同型（那里的结论就是"栈上大对象
    /// 一律入堆"）。故改用堆分配；失败如实上抛，不静默截断、不降级。
    ///
    /// **3P4-2（ABI v2）：本门限即 loader 的 `MAX_CMDLINE_BYTES`（单点定义）**——此前
    /// 内核缓冲 4096 与 loader 字符串区 511 是两个门限，512..=4096 的命令行会被内核放行、
    /// 随后在 loader 被 E2BIG 拒绝（同一语义两处判断必然漂移）。现直接引用同一常量。
    const CMD_BUF_BYTES: usize = loader::MAX_CMDLINE_BYTES;
    // 注意：本门限只保证「内核缓冲放得下」。**入口字符串区的真实上限是
    // loader 的 `STR_OFF - 1 = 511` 字节**（docs/abi/syscall-abi.md §4），
    // 因此长度在 512..=4096 的命令行会在此放行、随后在 loader 里以 E2BIG
    // 拒绝——同一语义两个门限。两者收敛属 docs/TODO/3p.md 的 3P4-2
    // （ABI v2 提升命令行上限），届时以新布局为准统一。
    if arg_len as usize > CMD_BUF_BYTES {
        return pack_err(Error::ArgListTooLong);
    }
    // 拷命令行到内核缓冲（带 SMAP 安全的 copy_from_user）。空命令行 → 正常启动。
    // 堆分配（S33）：4 KiB 栈缓冲在 16 KiB syscall 栈上会写穿 SYSCALL_STACKS 池。
    let mut cmd: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if cmd.try_reserve_exact(CMD_BUF_BYTES).is_err() {
        return pack_err(Error::OutOfMemory);
    }
    cmd.resize(CMD_BUF_BYTES, 0);
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
    // `cmd` 是**整条命令行字符串**（不含程序名；shell 派生时已剥首词）。
    // 入口参数块 mini-ABI（argc/argv 语义、字符串区容量、无命令行形态）见
    // docs/abi/syscall-abi.md §4；布局算术的单点定义与行为锚点在
    // `loader::raw::entry_block()`（由 loader 侧 host 单测锚定）。
    // ABI v2（3P4-2）：第 4 参是 envp。本步先交付**空环境**（布局与传递链路已就位，
    // 内核侧环境合成与继承属 3P4-2 下一步）；空环境同样以 NULL 终结，语义自洽。
    let loaded = match loader::load(elf_bytes, &mut us, cmd, &[]) {
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
            // 3P4-1：主线程 TLS 的 FS base 由 loader 写进地址空间，spawn 已在
            // **入队前**把它写进 PCB——此处不再二次设置（那会有竞态窗口）。
            // 每进程一条的流程细节：降为 debug（默认不输出）。
            klib::debug!(
                "[syscall] exec prog={} -> pid={} (ppid={}) entry={:#x} tls_fs_base={:?}",
                prog_name,
                pid,
                parent_pid,
                loaded.entry,
                loaded.tls_fs_base
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

    // §6.11 所有者裁定 B（2026-10-04）：`target>0 && timeout>0` 是**有界等待**——
    // 最多等 `timeout_ns`，到期子进程仍在运行则**如实**返回 `WouldBlock`。
    //
    // **修掉一个 S09 诚实性缺陷**：此前本函数只处理 `target==0 && timeout>0`，
    // 故 `target>0 && timeout>0` 会**直接落到普通阻塞 waitpid，`timeout` 被静默忽略**
    // ——传超时进去不超时、也不报错，无限等下去。现该组合真正生效。
    let bounded = target_pid != 0 && timeout_ns > 0;
    let waited = if bounded {
        task::waitpid_timeout(target_pid, arch_frame(frame), timeout_ns)
    } else {
        task::waitpid(target_pid, arch_frame(frame))
    };
    match waited {
        Ok(task::Waited::Reaped { pid, code }) => {
            // 同步收尸：rax 交付退出码（既有语义），r10 经 aux_pid 交付被收尸
            // 子进程 pid——架构层在写回 rax 的同时把 aux_pid 写进返回帧 r10，
            // 与阻塞路径 `saved.r10=pid` 交付对齐，waitpid 两条路径一致返回
            // (rax=code, r10=pid)。
            frame.aux_pid = pid as u64;
            done(pack_ok(code))
        }
        Ok(task::Waited::Blocked) => DispatchResult::Switched,
        // §6.11 B：有界等待**超时**（仅 waitpid_timeout 路径产生）。
        // 子进程仍在运行，故**如实**交付 WouldBlock（errno 11 EAGAIN），
        // **绝不**编造退出码：用户态据此知道「没等到、可重试」，
        // 而不是把子进程误判为已退出。
        Ok(task::Waited::TimedOut) => done(pack_err(Error::WouldBlock)),
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
            klib::debug!(
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

/// `identity_query` 处理器（A2-1 / SYS_TASK_IDENTITY_QUERY / 0x3B）：把调用进程的
/// **真实** uid/gid/caps 写入用户缓冲。
///
/// 无权限门禁——查自己的身份不构成越权。**不提供**"查任意 pid"形态：那需要一套
/// 本项未被裁定的额外授权语义，开出来即是未被审计的越权面（S39 不做无据扩展）。
///
/// 失败模式（S20）：无当前进程（内核/驱动上下文）→ `PermissionDenied`（内核自身
/// 不是"进程"，不返回伪身份 0/0/0）；缓冲不可写 → ADR-018 三层校验如实 EFAULT。
fn sys_identity_query(frame: &mut SyscallFrame) -> u64 {
    let out_ptr = frame.a1;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::PermissionDenied);
    };
    let id = proc.identity();
    let info = IdentityInfo {
        uid: id.uid,
        gid: id.gid,
        caps: id.caps.bits() as u32,
    };
    let bytes = core::mem::size_of::<IdentityInfo>();
    if let Err(e) = validate_user_range(out_ptr, bytes as u64, UserAccess::Write) {
        return pack_err(e);
    }
    // 定长结构经 **SMAP 安全**的 copy_to_user 拷出（ADR-018 三层校验已在
    // 上方完成，此处不再有用户侧长度参与）。不得用裸指针直写用户地址：
    // 内核态直访用户页在 SMAP 下触发 #PF，而 arch 层对内核态 #PF 一律停机
    // ——放过一处就是放过整机死机（validate_user_range 文档 §406 同诫）。
    let raw = info;
    let kbuf = unsafe {
        core::slice::from_raw_parts(&raw as *const IdentityInfo as *const u8, bytes)
    };
    unsafe { arch_x86_64::mmio::copy_to_user(out_ptr, kbuf.as_ptr(), bytes) };
    pack_ok(0)
}

/// `identity_set` 处理器（A2-1 / SYS_TASK_IDENTITY_SET / 0x3C）：变更调用进程组身份。
///
/// **路线 B：完整 setuid 语义**（项目所有者 2026-09 裁定）。授权按 `CAP_SYSTEM` 二分，
/// 单点判定（S13）：
///
/// - **持 `CAP_SYSTEM`**：可设为任意 uid/gid/caps（login 认证通过后降权至目标用户——
///   这是 A2-7 登录闭环的唯一通道）。
/// - **无 `CAP_SYSTEM`**：只允许**降权或不变**——
///   ① uid 必须保持不变（改 uid = 变成别人，属提权，一律拒绝）；
///   ② caps 必须是原 caps 的**子集**（只减不增）。
///   注意 gid：同 uid 前提下允许变更 gid（组是 uid 内的归属再划分，不构成跨用户
///   越权）；若将来引入组账户表（A2-4）再收紧。
///
/// 任何不满足者一律 `PermissionDenied`，且**在写身份之前**拒绝——不许先写后校验。
///
/// 参数：`a1`=uid、`a2`=gid、`a3`=保留（必须 [`IDENTITY_SET_RESERVED_NONE`]）、
/// `a4`=目标 caps 位（定长数字，ADR-018/ADR-040 §2.10 零拷贝面）。保留位非 0 一律
/// `InvalidParam`（**绝不静默忽略**，同 DERIVE 纪律：静默忽略是能力谎言 S06/S09）。
fn sys_identity_set(frame: &mut SyscallFrame) -> u64 {
    let target_uid = frame.a1 as u32;
    let target_gid = frame.a2 as u32;
    let reserved = frame.a3;
    let target_caps_bits = frame.a4;

    if reserved != IDENTITY_SET_RESERVED_NONE {
        return pack_err(Error::InvalidParam);
    }
    // caps 位域只有 5 位（ADR-040 §2.3「无预留位」）：超出即为非法请求，如实拒绝
    // 而不是静默截断（后者会让调用方以为拿到了不存在的权限）。
    if target_caps_bits > u8::MAX as u64 {
        return pack_err(Error::InvalidParam);
    }
    let requested = Caps::from_bits(target_caps_bits as u8);
    // 位域合法性：越出 ALL 掩码的位是非法请求，如实拒绝（不静默丢弃）。
    if requested.bits() & !Caps::ALL.bits() != 0 {
        return pack_err(Error::InvalidParam);
    }

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::PermissionDenied);
    };
    let current = proc.identity();
    if !current.caps.contains(Caps::SYSTEM) {
        // 无 CAP_SYSTEM：只许降权。uid 不得改变、caps 不得新增位。
        if target_uid != current.uid {
            return pack_err(Error::PermissionDenied);
        }
        if requested.bits() & !current.caps.bits() != 0 {
            return pack_err(Error::PermissionDenied);
        }
    }
    // 组级写入（ThreadGroup 共享 identity，承 set_identity 组锁）。
    proc.set_identity(ProcessIdentity {
        uid: target_uid,
        gid: target_gid,
        groups: current.groups,
        caps: requested,
    });
    klib::info!(
        "[syscall] identity_set pid {}: {}:{} caps={} -> {}:{} caps={}",
        proc.pid(), current.uid, current.gid, current.caps.bits(),
        target_uid, target_gid, requested.bits()
    );
    pack_ok(0)
}

/// `groups_set` 处理器（A2-4 / SYS_TASK_GROUPS_SET / 0x3D）：设置调用进程组的补充组。
///
/// **数据流向**：`/config/groups.json`（纯用户态组表）由用户态读取并解析后，经本
/// syscall 装入进程身份——内核**不解析组表**（ADR-040 §2.9 同一分层原则）。
///
/// **授权（S13 单点，与 identity_set 同门禁）**：
/// - 持 `CAP_SYSTEM`：可设为任意组集合（供 login 按组表装配成员身份，A2-7）。
/// - 无 `CAP_SYSTEM`：只允许**收缩或不变**——请求集合必须是当前集合的子集；
///   新增任一组 → `PermissionDenied`（组是权限判据，自行加入即越权）。
///
/// 超限（> `Groups::MAX`）一律 `OutOfRange` **如实拒绝**，绝不静默截断（S09）——
/// 截断会让调用方以为自己加入了某个组，而实际没有，属能力谎言。
///
/// 参数：`a1`=组数组指针、`a2`=个数、`a3`=保留（必须 0）、`a4`=方向。
fn sys_task_groups_set(frame: &mut SyscallFrame) -> u64 {
    let ptr = frame.a1;
    let count = frame.a2;
    let reserved = frame.a3;
    let mode = frame.a4;

    if reserved != GROUPS_SET_RESERVED_NONE {
        return pack_err(Error::InvalidParam);
    }
    // 方向合法性：未知取值如实拒绝，不猜测（S09）。
    let clearing = match mode {
        GROUPS_SET_REPLACE => false,
        GROUPS_SET_CLEAR => true,
        _ => return pack_err(Error::InvalidParam),
    };
    if clearing {
        // 清空时不得同时给数组——语义冲突如实拒绝。
        if ptr != 0 || count != 0 {
            return pack_err(Error::InvalidParam);
        }
    }
    // 上限先行判定：超限是**调用方的请求非法**，与缓冲区无关，故先于 copy_in 判定
    // （避免为一个注定被拒的请求去触碰用户内存）。
    if count > task::Groups::MAX as u64 {
        return pack_err(Error::OutOfRange);
    }
    if !clearing && count > 0 && ptr == 0 {
        return pack_err(Error::InvalidParam);
    }

    // 逐元素读入（定长 u32）。ADR-018 三层校验先行：整段一次校验，
    // 再逐元素 copy_from_user（SMAP 安全）——不为每个元素重复校验。
    let total = match (count as usize).checked_mul(4) {
        Some(v) => v,
        None => return pack_err(Error::OutOfRange),
    };
    if total > 0 {
        if let Err(e) = validate_user_range(ptr, total as u64, UserAccess::Read) {
            return pack_err(e);
        }
    }
    let mut requested = task::Groups::empty();
    for i in 0..count {
        let mut raw = [0u8; 4];
        let src = ptr + i * 4;
        unsafe { arch_x86_64::mmio::copy_from_user(raw.as_mut_ptr(), src, 4) };
        let gid = u32::from_le_bytes(raw);
        if requested.push(gid).is_none() {
            // 重复值幂等（push 内部处理）；此处只可能因超限失败，而超限已先行拒绝。
            return pack_err(Error::OutOfRange);
        }
    }

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::PermissionDenied);
    };
    let current = proc.identity();
    if !current.caps.contains(Caps::SYSTEM) {
        // 无 CAP_SYSTEM：只许收缩或不变——请求集合必须是当前集合的子集。
        for gid in requested.iter() {
            if !current.groups.contains(gid) {
                return pack_err(Error::PermissionDenied);
            }
        }
    }
    // 组级写入（ThreadGroup 共享 identity，承 set_identity 组锁）。
    proc.set_identity(ProcessIdentity {
        uid: current.uid,
        gid: current.gid,
        groups: requested,
        caps: current.caps,
    });
    klib::info!(
        "[syscall] groups_set pid {}: {} -> {} supplementary group(s)",
        proc.pid(), current.groups.len(), requested.len()
    );

    // 回传实际生效集合（如实，供调用方确知结果）。
    let mut info = GroupsInfo { count: requested.len() as u32, reserved: 0, gids: [0; task::Groups::MAX] };
    for (i, gid) in requested.iter().enumerate() {
        info.gids[i] = gid;
    }
    pack_ok(0)
}

/// `derive` 处理器（ADR-038 / SYS_TASK_DERIVE / 0x3A）：**COW 派生子进程**。
///
/// # 返回语义（POSIX fork 铁律）
///
/// 父收新子进程 pid（> 0）、子收 0。实现方式：子进程的首跑帧在 `task::spawn_derived`
/// 内固定为**父帧的副本且 rax=0**；父侧则在本处理器内把 rax 写成 pid。父进程从本
/// syscall 返回后继续执行，子进程在其首次被调度时从同一用户态位置继续——两条路径
/// 各自看到 `rax` 的不同值，这正是「一次调用、两次返回」的实现机制。
///
/// # 参数校验（S31：对抗性输入）
///
/// `a1`(flags) / `a2`(entry_rsp) / `a3`(entry_rip) 首期必须全为 [`DERIVE_FLAGS_NONE`]
/// （= 0，表示「继承父当前 RIP/RSP」）。任一非 0 一律 `InvalidParam`——**绝不静默
/// 忽略**：静默忽略会让调用方以为「带入口的派生」已生效，而实际跑的是继承语义，
/// 是典型的能力谎言（S06/S09）。
///
/// # 与 `arch_frame` 的关系
///
/// 本处理器需要**读**当前 syscall 的完整用户态现场（RIP/RSP/RFLAGS/全部 GPR）来构造
/// 子进程的首跑帧。`arch_frame` 的文档限定「仅切换路径使用」——本处理器**不切换**
/// （返回 `done`），仅在一次调用内读取该现场并立即复制完毕，不把借用跨越任何调度
/// 调用，故不违反该纪律。
///
/// 失败一律不改动父帧（`pack_err`），父进程从 syscall 正常返回负值。
fn sys_task_derive(frame: &mut SyscallFrame) -> u64 {
    // 1. 保留位校验：任一非 0 → InvalidParam（见上方 S31 说明）。
    if frame.a1 != DERIVE_FLAGS_NONE || frame.a2 != DERIVE_FLAGS_NONE || frame.a3 != DERIVE_FLAGS_NONE
    {
        klib::warn!(
            "[derive] reserved args must be 0, got flags={:#x} rsp={:#x} rip={:#x}",
            frame.a1,
            frame.a2,
            frame.a3
        );
        return pack_err(Error::InvalidParam);
    }
    // 2. 取父 pid（借用立即结束，KA3：借用不跨越调度调用）。
    let Some(ppid) = current_proc_mut().map(|p| p.pid()) else {
        return pack_err(Error::NotFound);
    };
    // 3. 构造子进程首跑帧：**父当前用户态现场的完整副本**，仅 rax 置 0。
    //
    // `arch_frame(frame)` 是架构耦合边界（见其文档），此处只读一次并立刻 `*`
    // 复制成 owned 值——InterruptFrame 是 `Copy`，复制后借用即结束，
    // 不跨越下方任何 `task::*` 调用。
    let mut child_frame = *arch_frame(frame);
    // **POSIX fork 铁律**：子进程从本 syscall 返回 0。
    child_frame.rax = 0;
    // r10 也被清 0：既有约定里 r10 是 aux 输出槽（waitpid 用它送回被收尸 pid）。
    // 子进程没有「被收尸对象」可言，保留父的 r10 会泄漏一个无意义的 pid 给用户态，
    // 故一并清零，使子进程的返回寄存器状态是干净的。
    child_frame.r10 = 0;
    // 4. 调 task 层原语创建子进程（失败 → 父收负值，父帧不动）。
    match task::spawn_derived(ppid, "forked", child_frame) {
        Ok(pid) => {
            klib::debug!("[derive] pid={} derived child pid={}", ppid, pid);
            // 5. **父侧返回 pid**。rax 由 pack_ok 写入返回帧——与子侧的首跑帧
            //    rax=0 形成对照，完成「一次调用、两次返回」的分流。
            pack_ok(pid as u64)
        }
        // S34：失败必须可见。此前这里只 `pack_err(e)` 就返回——用户态只收到一个
        // 负 errno，内核侧**不留任何痕迹**，排查时无法区分是哪个失败点
        // （spawn_derived 有 NotFound / NotSupported / OutOfMemory / clone_cow 四类，
        // 各自映射到不同 errno，但用户态只看到一个数字）。实测正是被这个盲区挡住。
        // 用 warn!（而非 debug!）：derive 失败是调用方需要知道的事件，不是调试噪音。
        Err(e) => {
            klib::warn!("[derive] pid={} spawn_derived failed: {:?} (errno {})", ppid, e, e.to_errno());
            pack_err(e)
        }
    }
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
        // §6.11 B：有界等待**超时**（仅 waitpid_timeout 路径产生）。
        // 子进程仍在运行，故**如实**交付 WouldBlock（errno 11 EAGAIN），
        // **绝不**编造退出码：用户态据此知道「没等到、可重试」，
        // 而不是把子进程误判为已退出。
        Ok(task::Waited::TimedOut) => done(pack_err(Error::WouldBlock)),
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
        // 定时器表满（klib time.rs：有界静态槽位，MAX_TIMERS）：退化「开中断
        // 睡等」重试，不丢 sleep 语义。表满是**瞬时**状态（poll 持续回收到期
        // 槽），重试拿表位即可。
        // §6.12.5：此处与 FALLBACK 同处 syscall 关中断窗口，**绝不可**用
        // `sleep_nanos` 纯自旋（历史缺陷：1ms 分段忙等在单核独跑时间接
        // 闷死 IRQ0/IRQ1）。同款 `sti; hlt`：每个等待段都中断可投递。
        let deadline = klib::time::now_nanos()
            .expect("clock_ready checked")
            .saturating_add(timeout_ns);
        while klib::time::now_nanos().map_or(false, |n| n < deadline) {
            if klib::time::set_timeout(timeout_ns, task::wake, cur_pid).is_some() {
                // 拿到表位：到期由 wake 唤醒。但本进程此刻仍处 Running（未
                // 阻塞），wake 对非 Blocked 进程是 no-op——继续走到 deadline，
                // 拿到的表位到期后回调 no-op，无副作用；表位由 poll 正常回收。
            }
            // SAFETY: sti/hlt/cli 恒在 Ring0；sti-hlt 不丢中断窗由硬件保证。
            // `cli` 必须在 hlt 返回后立刻恢复 IF=0——理由同 FALLBACK 分支：
            // syscall 全程建立在「IF=0、持锁临界区不被中断」这条不变量上。
            unsafe {
                core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack, preserves_flags));
            }
        }
        return done(pack_ok(0));
    }
    // 原子阻塞：register 在调度锁内复检 deadline，消除 lost-wakeup。
    //
    // §6.12.6 修复：**禁止**在 NotSwitched 分支一次性忙等全部 timeout_ns。
    // 该忙等发生在 syscall 的关中断窗口内（syscall 经 IA32_FMASK 清 IF）——
    // 实测 userd 的 10s 对账睡眠恰逢就绪队列空时在此忙等 10 秒，IRQ0/IRQ1
    // 全程被屏蔽：BSP 周期中断停止、软件定时器全部停摆、键盘毫无响应，
    // 系统表现为间歇性「死机」（判定实验：[WAIT10] pid=4 ns=10s +
    // [SLP] remain=4.3s + 冻结期 RIP 98% 落在 sleep_nanos，RFL IF=0）。
    //
    // 正确做法：**重试阻塞**。NotSwitched 只表示「此刻就绪队列空/仅自身」，
    // 但其它核的进程仍在推进、中断仍在投递，队列随时可能被填充；每次重试
    // 前用 register 复检 deadline（已过则立即收工，定时器 wake 对 Running
    // 进程是 no-op，无重复唤醒风险）。两次重试之间**不再**自旋耗尽时长，
    // 而是让出多次机会，保证 IRQ 一直能进来。
    //
    // §6.12.5 追加修复（^C 失效的真正根因）：上述 1ms 分段忙等**自身仍处在
    // 关中断窗口内**——syscall 进入时 IA32_FMASK 已清 IF，`sleep_nanos` 是
    // 纯 `spin_loop` 自旋、从不开中断。单核 + 「系统此刻只有本进程可运行」
    // 时（典型：前台子进程 `sleep` 的 Blocked 期），分段忙等**背靠背衔接**，
    // 关中断占空比 100%：实测 spinburn 每 40ms 睡眠期间 BSP 的 IRQ0/IRQ1
    // **全部停止**（kdbg-irq0 slot0_ticks 冻结、poll_timeouts 冻结、
    // shell 的 10ms 定时器永不 fire、`^C` 永远无人消费）。文档原称
    // 「单段 ≤1ms 不会饿死中断」只在**多核**或**段间有其它进程插队**时
    // 成立，单核独跑场景不成立——这是该论证的盲区。
    //
    // 修法：NotSwitched 时不再自旋，改用 **`sti; hlt; cli` 开中断睡等**——
    // `sti` 从下一条指令边界才生效（硬件保证不丢中断窗），`hlt` 让核
    // 睡到下一个中断到达（IRQ0 tick / IRQ1 键盘 / 其它 IRQ 都能唤醒），
    // **`cli` 立刻把 IF 关回 0**。中断返回后回到本循环顶：复检 deadline
    // 并重试阻塞。这样**每一段等待都是中断可投递的**，单核独跑不再闷死
    // 系统，而段间的内核代码仍严格保持 IF=0。
    // hlt 的唤醒源不保证是定时器 tick（可能是别的 IRQ），故唤醒后先
    // 复检 deadline，未到就再睡——语义仍是「至多睡到 deadline」。
    let register = &mut || klib::time::now_nanos().map_or(false, |n| n < deadline);
    loop {
        // deadline 已过：立即返回（sleep 语义已完成；定时器 no-op 无副作用）。
        if !register() {
            return done(pack_ok(0));
        }
        match task::block_current_with(arch_frame(frame), register) {
            task::SwitchOutcome::Switched => return DispatchResult::Switched,
            task::SwitchOutcome::NotSwitched => {
                // 此刻无法安全切走（就绪队列空/仅自身）。**开中断睡等**：
                // `sti; hlt` 让本核睡到任一中断到达，随后**立刻 `cli`**。
                //
                // 【为何必须 cli 回来】syscall 经 `IA32_FMASK` 进入时 IF=0，
                // 内核**整段**建立在这条不变量上：`IrqSpinLock::irq_save`
                // 保存的旧状态恒为 IF=0，guard 析构的 `irq_restore` 也只恢复
                // IF=0，故持锁临界区**永不被中断打断**。若只 sti 而不 cli，
                // IF 会一直开到 sysret——后续每次 `irq_restore` 都把中断重新
                // 打开，等于**在持 `RUN`/`PROCESSES` 锁的临界区里放进 IRQ0**；
                // tick 链再进调度器取同一把锁 → 单核自旋死锁（持有者被中断
                // 挂起，永远无法释放）。实测证据：故障冻结现场的栈回溯含
                // `syscall_entry → sys_task_wait → yield_now → interrupt_dispatch
                // → soft_interrupt_bridge → syscall_entry → ... → yield_now →
                // enqueue_ready`，即 **syscall 在持锁态被中断重入**；RIP 停在
                // 锁的同核重入检测（`my_cpu_slot_array_path`），IF=0 且不前进。
                //
                // 中断到来（IRQ0 tick 喂 poll_timeouts → 定时器到期回；
                // IRQ1 键盘；或其它 IRQ）唤醒 hlt 后，本循环回顶部复检
                // deadline 并重试阻塞——段与段之间仍严格保持 IF=0。
                // SAFETY: sti/hlt/cli 是特权指令，本处恒在 Ring0；sti-hlt 的
                // 「不丢失中断窗」由硬件保证（SDM Vol.3 §8.10.2）——sti 后的
                // 下一条指令边界才生效，恰好让紧随的 hlt 不会漏掉中断。
                unsafe {
                    core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack, preserves_flags));
                }
            }
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
    klib::debug!("[syscall] process {} exit(code={})", pid, code);
    // SYSCALL-FAST-4 验收通道（仅自检构建）：用户程序把 write 失败计数作为
    // exit code 交付（0 = 全部 4 次 write 都返回 1）。debug! 在 release 被裁掉，
    // 故测试构建用 info! 显式留痕——这是用户态**自校验**结果的唯一交付通道
    //（scheduler::start 永不返回，内核无法事后读用户内存）。
    #[cfg(feature = "kernel-tests")]
    klib::info!("[test-fast4] process {} exit(code={}) -- 0 = all writes ok", pid, code);
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
/// 属**特权**操作：仅持 `CAP_SYSTEM` 的进程可发起，否则 `PermissionDenied`。
/// S5 电源关停信息未就绪（无 PM1a / DSDT 无 `_S5`）时返回 `NotSupported`——
/// 我们**绝不**在无凭据下猜测 SLP_TYP 写端口（宁缺毋假）。
///
/// 就绪后为终结路径：停其它核 → 写 PM1 触发断电（`power_off` 永不返回，
/// 断电后 CPU 停止）。故本条从不带现场回到调用进程。
fn sys_power_off(_frame: &mut SyscallFrame) -> DispatchResult {
    let priv_ok = current_proc_mut()
        .map(|p| p.identity().caps.contains(Caps::SYSTEM))
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
/// 属**特权**操作：仅持 `CAP_SYSTEM` 的进程可发起，否则 `PermissionDenied`。
/// 走 ACPI reset 寄存器（若固件提供，QEMU 通常无）或 8042 快速复位（0x64←0xFE，
/// QEMU/SeaBIOS 均支持）。终结路径：停其它核 → 触发复位（`reboot` 永不返回）。
fn sys_reboot(_frame: &mut SyscallFrame) -> DispatchResult {
    let priv_ok = current_proc_mut()
        .map(|p| p.identity().caps.contains(Caps::SYSTEM))
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
/// 特权门禁单点（A1-2 / ADR-040 §2.3，承 ADR-037 决策 5）：当前进程是否持有
/// 指定能力位。
///
/// `driver_register`/`driver_claim` 等直接授予设备认领与 MMIO 映射（内核级权限），
/// 无对应能力一律 `PermissionDenied`。单点判定，供本族特权 syscall 复用（S13：
/// 权限语义成文、不重复硬编码）。`driver_query`(读) / `driver_unregister`(释放自身
/// 持有) 不授予 MMIO，故不在门禁内。
///
/// 能力映射（ADR-040 §2.3 表）：设备认领/中断等待/AUDIO_ATTACH → `CAP_DEVICE`；
/// DMA 缓冲（设备内存分配与**物理地址披露**）→ `CAP_MEMORY`。
fn current_has_cap(cap: Caps) -> bool {
    current_proc_mut()
        .map(|p| p.identity().caps.contains(cap))
        .unwrap_or(false)
}

/// `driver_register(name_ptr, len) -> uio_id` (M11.1)
fn sys_driver_register(frame: &mut SyscallFrame) -> u64 {
    if !current_has_cap(Caps::DEVICE) {
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
    if !current_has_cap(Caps::DEVICE) {
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
    // 阻塞等待的超时上界（A10：1h 夹断删除，owner 指令 2026-09-27）。原
    // 「超长 timeout 无真实收益」的理由不成立——无限等待是合法语义；占用的
    // 定时器槽有完整回收闭环（到期自动 / 提前返回 / 被杀取消），无泄漏面。
    // 定时器表本身有全局软闸（TIMER_SOFT_CAP，A3）。
    const MAX_WAIT_TIMEOUT_NS: u64 = u64::MAX;
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
    // A10：同事件等待口径——1h 夹断删除（u64::MAX，回收闭环见上）。
    const MAX_WAIT_TIMEOUT_NS: u64 = u64::MAX;
    if !current_has_cap(Caps::DEVICE) {
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
    // 【本仓修订】等待端入口**每次**解屏蔽该 IRQ 线（与 device_irq_handler
    // 交付后的 mask_irq 成对，构成电平中断 half-drop 协议：交付即屏蔽，
    // 重等即解屏蔽）。8259 上电全屏蔽 + 内核只开键盘 IRQ1：用户态驱动此前
    // 从未真正收到设备中断。解屏蔽必须发生在等待端——认领时刻设备可能已有
    // 电平锁存，过早解屏蔽会在驱动就位前引发风暴（QEMU 实测启动卡死）。
    driver::irq_owner::unmask_irq(irq);
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
    if !current_has_cap(Caps::MEMORY) {
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
    if !current_has_cap(Caps::MEMORY) {
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
    if !current_has_cap(Caps::MEMORY) {
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
    // A2-9 / ADR-040 §3.5 G6：资源域权限门禁。挂载文件系统属**系统管理**
    // 操作，与 power/reboot、门禁位、INIT 派生同归 `CAP_SYSTEM`（§2.3）。
    // 补此门禁前本调用**零检查**——任意进程可挂载任意块设备（"机制就绪却
    // 未接线"，S13）。真实调用方 volumed 由 init(system(1)) 派生持全能力，
    // 故不受影响。单点判定（S13），不设第二条路径。
    if !current_has_cap(Caps::SYSTEM) {
        return pack_err(Error::PermissionDenied);
    }
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
    // A2-9 / ADR-040 §3.5 G6：同 `sys_volume_mount` 的资源域门禁（`CAP_SYSTEM`）。
    // 卸载是对全系统可见的破坏性操作，与挂载同域同判据。
    if !current_has_cap(Caps::SYSTEM) {
        return pack_err(Error::PermissionDenied);
    }
    let path_ptr = frame.a1;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let path = match absolute_path(&path) {
        Ok(a) => a,
        Err(e) => return pack_err(e),
    };
    // A2-3 / §3.4：目录遍历检查（每级父目录要求 x 位）——在任何解析/操作之前。
    {
        let identity = current_proc_mut()
            .map(|p| p.identity())
            .unwrap_or_else(ProcessIdentity::default_user);
        if let Err(e) = check_traverse_access(&identity, &path) {
            return pack_err(e);
        }
    }
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
        SYS_STREAM_FOCUS_SET => done(sys_stream_focus_set(frame)),

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
        SYS_TASK_IDENTITY_QUERY => done(sys_identity_query(frame)),
        SYS_TASK_IDENTITY_SET => done(sys_identity_set(frame)),
        SYS_TASK_GROUPS_SET => done(sys_task_groups_set(frame)),
        // derive：COW 派生子进程（ADR-038 / 0x3A）。非阻塞、返回两次语义
        // （父 rax=pid、子 rax=0），不切换——故返回 done。
        SYS_TASK_DERIVE => done(sys_task_derive(frame)),

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

        // AUDIO Domain (0xA0, plan_audio_vfs.md 批次二)：音频管道消费者动词。
        // 读/写 PCM 走 VFS 路径，本域只管流控（附加/注销/提交/显式取帧）。
        SYS_AUDIO_ATTACH => done(sys_audio_attach(frame)),
        SYS_AUDIO_DETACH => done(sys_audio_detach(frame)),
        SYS_AUDIO_FETCH => sys_audio_fetch(frame),
        SYS_AUDIO_COMMIT => done(sys_audio_commit(frame)),

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
