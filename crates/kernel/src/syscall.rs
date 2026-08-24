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

// ---------- syscall 号（域 + 操作二维编码） ----------

// ---------- 4 类资源域与 4 个动词 ----------

pub mod domain {
    pub const STREAM: u32 = 0x10;
    pub const MEMORY: u32 = 0x20;
    pub const TASK: u32 = 0x30;
    pub const VFS: u32 = 0x40;
    pub const DEVICE: u32 = 0x50;
}

pub mod op {
    pub const CREATE: u32 = 0x01;
    pub const READ: u32 = 0x02;
    pub const WRITE: u32 = 0x03;
    pub const DELETE: u32 = 0x04;
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

// ---------- 5. DEVICE Domain (0x50, UIO Sandboxing) ----------
pub const SYS_DRIVER_REGISTER: u32 = nr(domain::DEVICE, op::CREATE); // 0x51
pub const SYS_DRIVER_CLAIM: u32 = nr(domain::DEVICE, op::WRITE); // 0x53

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
fn copy_path_from_user(path_ptr: u64, max_len: usize) -> Result<alloc::string::String, Error> {
    if path_ptr < USER_BASE || path_ptr >= USER_TOP {
        return Err(Error::OutOfRange);
    }
    const PAGE_SIZE: u64 = 0x1000;
    let mut validated_page_end = path_ptr & !(PAGE_SIZE - 1);
    let mut bytes = alloc::vec::Vec::new();
    let mut cur = path_ptr;
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
            break;
        }
        bytes.push(byte[0]);
        cur += 1;
    }
    alloc::string::String::from_utf8(bytes).map_err(|_| Error::InvalidParam)
}

/// `open(path_ptr, flags_bits, perm_bits)`：打开或创建文件，返回 fd。
fn sys_open(frame: &mut InterruptFrame) -> u64 {
    let path_ptr = frame.rdi;
    let flags_bits = frame.rsi as u32;
    let perm_bits = frame.rdx as u32;

    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };

    let flags = vfs::file_handle::OpenFlags::from_bits(flags_bits);
    let perm = vfs::inode::Permissions::from_bits(perm_bits);
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
    match proc.alloc_fd(handle) {
        Ok(fd) => pack_ok(fd as u64),
        Err(e) => pack_err(e),
    }
}

/// `close(fd)`：关闭用户分配的文件描述符。
///
/// fd 0/1/2 是进程的保留标准流，不是可关闭的用户句柄；拒绝该操作并返回
/// `Error::NotSupported`（ENOTSUP），绝不以成功码掩盖未发生的状态变化。
fn sys_close(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    if fd < 3 {
        return pack_err(Error::NotSupported);
    }
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    if proc.close_fd(fd).is_some() {
        pack_ok(0)
    } else {
        pack_err(Error::NotFound)
    }
}

/// `mkdir(path_ptr, perm_bits)`：创建目录。
fn sys_mkdir(frame: &mut InterruptFrame) -> u64 {
    let path_ptr = frame.rdi;
    let perm_bits = frame.rsi as u32;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let perm = vfs::inode::Permissions::from_bits(perm_bits);
    let root = crate::vfs_init::root();
    match root.mkdir(&path, perm) {
        Ok(_) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `unlink(path_ptr)`：删除文件或空目录。
fn sys_unlink(frame: &mut InterruptFrame) -> u64 {
    let path_ptr = frame.rdi;
    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };
    let root = crate::vfs_init::root();
    match root.unlink(&path) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `readdir(path_ptr, buf_ptr, max_bytes)`：获取目录项列表（以 JSON 结构或固定格式写入用户缓冲）。
fn sys_readdir(frame: &mut InterruptFrame) -> u64 {
    let path_ptr = frame.rdi;
    let buf_ptr = frame.rsi;
    let max_bytes = frame.rdx as usize;

    let path = match copy_path_from_user(path_ptr, MAX_USER_PATH_BYTES) {
        Ok(p) => p,
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

    // 格式化为换行分隔的名字与大小列表。
    // 格式：`name:type:size\n`。KM5：只交付**完整行**——放不下整条的尾部
    // 条目整体省略，绝不把半行 `name:type:` 交给调用方破坏协议成帧；返回
    // 字节数 < 完整列表长度即表示还有剩余条目（分页语义，成文）。
    /// readdir 单条记录的类型标签（协议字段）。
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
    let mut out = alloc::string::String::new();
    for e in &entries {
        use core::fmt::Write;
        let mut line = alloc::string::String::new();
        if write!(line, "{}:{}:{}\n", e.name, type_tag(e.node_type), e.size).is_err() {
            // String 写入不可能失败（alloc::fmt 无分配错误路径），保守跳过。
            continue;
        }
        if out.len() + line.len() > max_bytes {
            break;
        }
        out.push_str(&line);
    }
    // 审计 B10：缓冲连**第一条**都放不下时返回 0 会与 EOF/空目录不可区分
    // ——大目录静默丢条目。按 POSIX getdents 惯例以 EINVAL 如实拒绝：调用
    // 方加大缓冲重试即可；只有 entries 为空（真 EOF）才返回 0。
    if out.is_empty() && !entries.is_empty() {
        return pack_err(Error::InvalidParam);
    }

    let bytes = out.as_bytes();
    let n = bytes.len();
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
fn sys_write(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;
    let offset = frame.r10;

    if len == 0 {
        return pack_ok(0);
    }

    // KM1：无 fd 号特判——1/2 与普通句柄走同一条路，stdout/stderr 节点在
    // write_at 内直发字节（K5 完全体：串口 sink 字节透明，文本 sink 自行
    // lossy），syscall 层零转换。
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd as usize) else {
        return pack_err(Error::InvalidParam);
    };
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
        let Some(fpos) = offset.checked_add(total) else {
            if total == 0 {
                return pack_err(Error::InvalidParam);
            }
            return pack_ok(total);
        };
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
fn sys_read(frame: &mut InterruptFrame) -> DispatchResult {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;
    let offset = frame.r10;
    if len == 0 {
        return done(pack_ok(0));
    }

    // KM1：无 fd 号特判——0 与普通句柄走同一条路。stdin 节点空读返回
    // WouldBlock，下方按节点真值（interactive_input）翻译为阻塞切换。
    let Some(proc) = current_proc_mut() else {
        return done(pack_err(Error::NotFound));
    };
    let Some(handle) = proc.get_fd(fd as usize) else {
        return done(pack_err(Error::InvalidParam));
    };
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
        let Some(fpos) = offset.checked_add(total) else {
            if total == 0 {
                return done(pack_err(Error::InvalidParam));
            }
            break;
        };
        let chunk = &mut kbuf[..n as usize];
        let got = if offset == STREAM_OFFSET_CURRENT {
            handle.read(chunk)
        } else {
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
                    return match task::block_for_kbd(frame) {
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
/// 程序索引，映射到 `/binaries/init.elf` / `/binaries/shell.elf`。ELF 数据
/// 唯一来源是真实磁盘 EXT2。
///
/// KM3：删除原"小索引 VFS resolve 失败后回退 program_elf(idx)"死亡分支——
/// 两者解析同一路径必然同样失败，且 `program_elf` 对 idx≥2 恒为 None；
/// 回退链只会把同一个 NotFound 伪装成两条路径都试过的假象。
/// KD8：同步删除无名魔数边界 `arg1 < 16`——内建索引实际只有 {0,1} 两项，
/// 2..15 恒失败；现在除两个命名内建索引外一切值都按其 ABI 本义（路径指针）
/// 处理，野指针由 copy_path_from_user 预校验如实拒绝。
fn sys_exec(frame: &mut InterruptFrame) -> u64 {
    let arg1 = frame.rdi;
    let arg_ptr = frame.rsi;
    let arg_len = frame.rdx;

    let root = crate::vfs_init::root();

    // 1. 获取 ELF 字节数据
    let elf_data: alloc::vec::Vec<u8> = match arg1 {
        BUILTIN_INDEX_INIT | BUILTIN_INDEX_SHELL => {
            let path = if arg1 == BUILTIN_INDEX_INIT {
                "/binaries/init.elf"
            } else {
                "/binaries/shell.elf"
            };
            match root.resolve(path, true) {
                Ok(inode) => {
                    let meta = match inode.metadata() {
                        Ok(m) => m,
                        Err(e) => return pack_err(e),
                    };
                    let mut buf = alloc::vec![0u8; meta.size as usize];
                    if let Err(e) = inode.read_at(0, &mut buf) {
                        return pack_err(e);
                    }
                    buf
                }
                Err(e) => return pack_err(e),
            }
        }
        // 路径字符串模式：arg1 即用户态路径指针
        _ => {
            let path = match copy_path_from_user(arg1, MAX_USER_PATH_BYTES) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            match root.resolve(&path, true) {
                Ok(inode) => {
                    let meta = match inode.metadata() {
                        Ok(m) => m,
                        Err(e) => return pack_err(e),
                    };
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
fn sys_mmap(frame: &mut InterruptFrame) -> u64 {
    let size = frame.rdi;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let flags = PageFlags::empty().writable().user();
    match proc.addr_space_mut().mmap_user(size, flags) {
        Ok(addr) => pack_ok(addr),
        Err(e) => pack_err(e),
    }
}

/// `munmap(addr, size)`：释放当前进程的一段匿名 mmap 地址区间。
///
/// ABI 使用 `rdi=addr`、`rsi=size`。地址与长度必须均为 4KiB 粒度，且整个范围
/// 必须属于单个匿名 mmap 区域；否则返回明确错误，绝不把无操作伪装成成功。
fn sys_munmap(frame: &mut InterruptFrame) -> u64 {
    let addr = frame.rdi;
    let size = frame.rsi;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
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
fn sys_memory_query(frame: &mut InterruptFrame) -> u64 {
    /// 查询结果位图：页表项 present。
    const MEMQ_PRESENT: u64 = 1 << 0;
    /// 查询结果位图：用户态可访问。
    const MEMQ_USER: u64 = 1 << 1;
    /// 查询结果位图：可写。
    const MEMQ_WRITABLE: u64 = 1 << 2;
    /// out_ptr 指向的位图字节数（u64）。
    const OUT_LEN: u64 = 8;

    let addr = frame.rdi;
    let out_ptr = frame.rsi;

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
fn sys_brk(frame: &mut InterruptFrame) -> u64 {
    let new = frame.rdi;
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
fn sys_task_wait(frame: &mut InterruptFrame) -> DispatchResult {
    let target_pid = frame.rdi as usize;
    let timeout_ns = frame.rsi;

    if target_pid == 0 && timeout_ns == 0 {
        // K1b/KA6：yield_now 返回 Switched 时 `*frame` 已被整体替换为下一进程
        // 保存帧（yield 返回值 0 由调度器写入被保存帧，scheduler.rs），此处若再以
        // Done(0) 收尾会把 rax=0 写穿目标进程现场。枚举强制穷尽匹配，漏翻
        // 编译期即不可能；NotSwitched 才是普通的 Done(0)。
        match task::yield_now(frame) {
            task::SwitchOutcome::Switched => return DispatchResult::Switched,
            task::SwitchOutcome::NotSwitched => return done(pack_ok(0)),
        }
    }

    if target_pid == 0 && timeout_ns > 0 {
        klib::time::sleep_nanos(timeout_ns);
        return done(pack_ok(0));
    }

    match task::waitpid(target_pid, frame) {
        Ok(task::Waited::Code(code)) => done(pack_ok(code)),
        Ok(task::Waited::Blocked) => DispatchResult::Switched,
        Err(e) => done(pack_err(e)),
    }
}

/// `exit(code)`：终止当前进程并调度到下一个就绪进程（多进程场景）。
///
/// 经 `scheduler::exit_current(frame, code)` 统一终止核心处理：有活父且父
/// 阻塞 waitpid 时交付退出码并唤醒父，否则 zombie 保留/按无父回收。若还有
/// 就绪进程，改写 `frame` 为下一个就绪进程的保存帧；返回后 `syscall_entry`
/// 的 iretq 进入目标进程。若所有进程都退出则 idle halt 等待。返回值为填充
/// 占位（当前进程已死，实际由 iretq 接管）。
fn sys_exit(frame: &mut InterruptFrame) -> u64 {
    let code = frame.rdi;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    klib::info!("[syscall] process {} exit(code={})", pid, code);
    task::exit_current(frame, code);
    0
}

/// `kill(pid, sig) -> 0`：向进程发送信号（终止 / 校验存在）。
fn sys_kill(frame: &mut InterruptFrame) -> u64 {
    let target = frame.rdi as usize;
    let sig = frame.rsi as u32;
    match task::kill_pid(target, sig, frame) {
        Ok(_) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `driver_register(name_ptr, len) -> uio_id` (M11.1)
fn sys_driver_register(frame: &mut InterruptFrame) -> u64 {
    let name_ptr = frame.rdi as *const u8;
    let len = frame.rsi as usize;
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
    match drv::uio_register_driver(pid, dev_name) {
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
fn sys_driver_claim(frame: &mut InterruptFrame) -> u64 {
    let uio_id = frame.rdi as usize;
    let _mmio_base = frame.rsi;
    let _size = frame.rdx;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    // 授权半程：id 存在性 + 归属校验。
    if let Err(e) = drv::uio_claim_device(uio_id, pid) {
        klib::info!(
            "[uio] driver_claim({}) denied for pid={}: {:?}",
            uio_id,
            pid,
            e
        );
        return pack_err(e);
    }
    // 从登记表取该设备（= 认领的设备名）的真实 MMIO 窗口。
    let Some((phys, len)) = drv::uio_device_window_of(uio_id) else {
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

// ---------- 分发 ----------

/// 分发结果：`Done(v)` = 正常返回值（写回 `frame.rax` 带回调用进程）；
/// `Switched` = 处理器已把 `*frame` **整体替换**为下一进程的保存帧并切换
/// （waitpid 阻塞 / exit 切换）。此时 `frame.rax` 属于目标进程语义
/// （如 waitpid 交付的退出码），入口**必须禁止**再写返回值——否则会用
/// 占位值覆盖交付结果/目标进程现场。
enum DispatchResult {
    Done(u64),
    Switched,
}

/// 普通处理器结果包装。
fn done(v: u64) -> DispatchResult {
    DispatchResult::Done(v)
}

/// 按系统调用号分发到具体实现。
fn dispatch(nr: u64, frame: &mut InterruptFrame) -> DispatchResult {
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
        SYS_TASK_SIGNAL => done(sys_kill(frame)),
        // exit 已切换到下一进程（或进入 idle），永不以正常值返回。
        SYS_TASK_EXIT => {
            sys_exit(frame);
            DispatchResult::Switched
        }

        // VFS Domain (0x40)
        SYS_ENTRY_CREATE => done(sys_mkdir(frame)),
        SYS_ENTRY_READ => done(sys_readdir(frame)),
        SYS_ENTRY_DELETE => done(sys_unlink(frame)),

        // DEVICE Domain (0x50)
        SYS_DRIVER_REGISTER => done(sys_driver_register(frame)),
        SYS_DRIVER_CLAIM => done(sys_driver_claim(frame)),

        _ => {
            klib::info!("[syscall] unknown nr={:#x}", nr);
            done(pack_err(Error::NotSupported))
        }
    }
}

// ---------- 软中断入口 ----------

/// `int 0x80` 软中断处理回调（注册为 `register_soft_interrupt_handler`）。
///
/// 从 `InterruptFrame` 读 `rax`（系统调用号）与参数寄存器，分发执行：
/// - [`DispatchResult::Done`]：把结果写回 `frame.rax`，iretq 带回调用进程；
/// - [`DispatchResult::Switched`]：`*frame` 已是下一进程保存帧，其 rax 由
///   调度语义负责（如 waitpid 交付的子进程退出码），不得覆盖。
///
/// 返回 `true` 让 `iretq` 把（可能的）新现场带回目标用户态。
pub extern "C" fn syscall_entry(frame: &mut InterruptFrame) -> bool {
    let nr = frame.rax;
    // 进入/返回 trace 仅在自检构建开启（避免每条 syscall 生产刷屏）。
    #[cfg(feature = "kernel-tests")]
    klib::info!(
        "[syscall] nr={:#x} a1={:#x} a2={:#x} a3={:#x}",
        nr,
        frame.rdi,
        frame.rsi,
        frame.rdx
    );
    match dispatch(nr, frame) {
        DispatchResult::Done(ret) => {
            #[cfg(feature = "kernel-tests")]
            klib::info!("[syscall] nr={:#x} -> {:#x}", nr, ret);
            frame.rax = ret;
        }
        DispatchResult::Switched => {
            #[cfg(feature = "kernel-tests")]
            klib::info!("[syscall] nr={:#x} -> <switched>", nr);
        }
    }
    true
}
