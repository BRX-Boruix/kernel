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

use task::current_proc_mut;

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
}

const fn nr(d: u32, o: u32) -> u32 {
    d | o
}

// ---------- 1. STREAM Domain (0x10) ----------
pub const SYS_STREAM_CREATE: u32 = nr(domain::STREAM, op::CREATE); // 0x11
pub const SYS_STREAM_READ: u32 = nr(domain::STREAM, op::READ); // 0x12
pub const SYS_STREAM_WRITE: u32 = nr(domain::STREAM, op::WRITE); // 0x13
pub const SYS_STREAM_CLOSE: u32 = nr(domain::STREAM, op::DELETE); // 0x14

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

// ---------- 4. VFS Domain (0x40) ----------
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

// ---------- 6. VOLUME Domain (0x60, ADR-030) ----------
pub const SYS_VOLUME_MOUNT: u32 = nr(domain::VOLUME, op::CREATE); // 0x61
pub const SYS_VOLUME_LIST: u32 = nr(domain::VOLUME, op::READ); // 0x62
pub const SYS_VOLUME_UPDATE: u32 = nr(domain::VOLUME, op::WRITE); // 0x63
pub const SYS_VOLUME_FORMAT: u32 = nr(domain::VOLUME, op::FORMAT); // 0x65
pub const SYS_VOLUME_UNMOUNT: u32 = nr(domain::VOLUME, op::UNMOUNT); // 0x66

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

/// `entry_update(path_ptr, new_path_ptr, flags)`：重命名/移动节点（ADR-014 0x43）。
///
/// 当前实现为**同目录重命名**：源与目标须在同一父目录（跨目录移动如实
/// `NotSupported`，宁缺毋假）。`flags` 保留（当前仅 0 接受，非 0 返回
/// `InvalidParam`）——ADR-014 允许其表达"更新元数据"等扩展，未实现前不静默忽略。
fn sys_entry_update(frame: &mut SyscallFrame) -> u64 {
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
        Some(vfs::file_handle::OpenHandle::Pipe { id }) => Some(*id),
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
        Some(vfs::file_handle::OpenHandle::Pipe { id }) => Some(*id),
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
const BUILTIN_INDEX_INIT: u64 = 0;
/// 内建程序索引：shell。
const BUILTIN_INDEX_SHELL: u64 = 1;

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
    match task::spawn_with_ppid(parent_pid, &prog_name, loaded.entry, loaded.user_stack_top, us) {
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
        let addr_space = proc.addr_space_mut();
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
        let addr_space = proc.addr_space_mut();
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
    match proc.addr_space_mut().mmap_user(size, pf) {
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
        return match ipc::shm_unmap::<arch_x86_64::paging::X86PageTable>(id, proc.addr_space_mut()) {
            Ok(_) => {
                klib::info!("[munmap] shm_unmap id={} at {:#x}", id, addr);
                pack_ok(0)
            }
            Err(_) => pack_err(Error::NotFound),
        };
    }
    match proc.addr_space_mut().munmap_anonymous(addr, size) {
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
    match proc.addr_space_mut().brk(new) {
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
        Ok(task::Waited::Code(code)) => done(pack_ok(code)),
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
    // 回调在 tick 中断的 `poll_timeouts`（锁外）执行，拿 SCHED 锁安全。
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
    // 自杀判定：target 即当前进程且是真实信号（非探活 sig=0）。init 自杀
    // 由 kill_pid 的 PID1 防护拒绝（此处不自行 exit，避免绕过防护）。
    let is_suicide = {
        let cur = task::current_proc_mut().map(|p| p.pid());
        cur == Some(target) && sig != 0 && target != task::init_pid()
    };
    if is_suicide {
        task::exit_current(arch_frame(frame), sig as u64);
        return DispatchResult::Switched;
    }
    match task::kill_pid(target, sig, arch_frame(frame)) {
        Ok(_) => done(pack_ok(0)),
        Err(e) => done(pack_err(e)),
    }
}

/// `driver_register(name_ptr, len) -> uio_id` (M11.1)
fn sys_driver_register(frame: &mut SyscallFrame) -> u64 {
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
    match proc.addr_space_mut().map_mmio_user(phys, len) {
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

/// `driver_unregister(slot) -> 0` (ADR-014 0x54)
///
/// 注销驱动（DELETE）：以 `uio_id` 释放注册槽位并解绑其设备。与 claim 同源
/// 授权——调用者必须就是注册者本人（他人 id 报 `PermissionDenied`，不存在的
/// id 报 `NotFound`）。
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

// ---------- VOLUME Domain (0x60, ADR-030) ----------

/// `volume_mount(dev_name_ptr) -> 0`（M4.2，0x61）。
///
/// 按块设备名把其首分区的 EXT2 挂载到 `/volumes/{label}`（复用 M1.2 链路），
/// 卷标命名/冲突消解由 [`MountTable::mount_volume`] 承担。成功返回 0；
/// 失败如实上抛（NotFound/Corrupt/NotSupported/ReadOnly），绝不伪挂成功。
fn sys_volume_mount(frame: &mut SyscallFrame) -> u64 {
    let dev_name_ptr = frame.a1;
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
            pack_ok(0)
        }
        Err(e) => {
            klib::info!("[volume] mount '{}' failed: {:?}", dev_name, e);
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
            klib::info!("[volume] unmounted {}", path);
            pack_ok(0)
        }
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

        // VOLUME Domain (0x60, ADR-030)
        SYS_VOLUME_MOUNT => done(sys_volume_mount(frame)),
        SYS_VOLUME_LIST => done(sys_volume_list(frame)),
        SYS_VOLUME_UPDATE => done(sys_volume_update(frame)),
        SYS_VOLUME_FORMAT => done(sys_volume_format(frame)),
        SYS_VOLUME_UNMOUNT => done(sys_volume_unmount(frame)),

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
            frame.result = ret;
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
