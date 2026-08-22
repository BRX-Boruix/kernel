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
use mm::user_space::{USER_BASE, USER_TOP};

use task::current_proc_mut;

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

/// 从用户空间拷贝以 null 结尾的路径字符串。
fn copy_path_from_user(path_ptr: u64, max_len: usize) -> Result<alloc::string::String, Error> {
    if path_ptr < USER_BASE || path_ptr >= USER_TOP {
        return Err(Error::OutOfRange);
    }
    let mut bytes = alloc::vec::Vec::new();
    let mut cur = path_ptr;
    while bytes.len() < max_len {
        if cur >= USER_TOP {
            return Err(Error::OutOfRange);
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

    let path = match copy_path_from_user(path_ptr, 4096) {
        Ok(p) => p,
        Err(e) => return pack_err(e),
    };

    let flags = vfs::file_handle::OpenFlags::from_bits(flags_bits);
    let perm = vfs::inode::Permissions::from_bits(perm_bits);
    let root = crate::vfs_init::root();

    let inode = match root.resolve(&path, true) {
        Ok(n) => {
            if flags.truncate && flags.write {
                let _ = n.truncate(0);
            }
            n
        }
        Err(Error::NotFound) if flags.create => match root.create_file(&path, perm) {
            Ok(n) => n,
            Err(e) => return pack_err(e),
        },
        Err(e) => return pack_err(e),
    };

    let handle = vfs::file_handle::FileHandle::new(inode, flags);
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let fd = proc.alloc_fd(handle);
    pack_ok(fd as u64)
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
    let path = match copy_path_from_user(path_ptr, 4096) {
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
    let path = match copy_path_from_user(path_ptr, 4096) {
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

    let path = match copy_path_from_user(path_ptr, 4096) {
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

    // 格式化为换行分隔的名字与大小列表（或直接写入紧凑字节流）
    // 格式：`name:type:size\n`
    let mut out = alloc::string::String::new();
    for e in &entries {
        use core::fmt::Write;
        let t = match e.node_type {
            vfs::inode::INodeType::Directory => "dir",
            vfs::inode::INodeType::RegularFile => "file",
            vfs::inode::INodeType::Symlink => "link",
            vfs::inode::INodeType::CharacterDevice => "chardev",
            vfs::inode::INodeType::BlockDevice => "blkdev",
            vfs::inode::INodeType::Fifo => "fifo",
        };
        let _ = write!(out, "{}:{}:{}\n", e.name, t, e.size);
    }

    let bytes = out.as_bytes();
    let n = bytes.len().min(max_bytes);
    if n > 0 {
        if buf_ptr < USER_BASE || buf_ptr + (n as u64) > USER_TOP {
            return pack_err(Error::OutOfRange);
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

    // 校验 [buf, buf+len) 完全落在用户半区，避免越界读内核地址。
    let Some(end) = buf.checked_add(len) else {
        return pack_err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return pack_err(Error::OutOfRange);
    }

    // 标准输出 / 标准错误
    if fd == 1 || fd == 2 {
        const CHUNK: usize = 4096;
        let mut chunk = [0u8; CHUNK];
        let mut off = 0usize;
        while off < len as usize {
            let n = core::cmp::min(len as usize - off, CHUNK);
            unsafe {
                arch_x86_64::mmio::copy_from_user(chunk.as_mut_ptr(), buf + off as u64, n);
            }
            let s = core::str::from_utf8(&chunk[..n]).unwrap_or("\u{FFFD}");
            klib::console::write_str(s);
            off += n;
        }
        return pack_ok(len);
    }

    // 普通文件描述符
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd as usize) else {
        return pack_err(Error::InvalidParam);
    };

    let mut kbuf = alloc::vec![0u8; len as usize];
    unsafe {
        arch_x86_64::mmio::copy_from_user(kbuf.as_mut_ptr(), buf, len as usize);
    }

    if offset == STREAM_OFFSET_CURRENT {
        match handle.write(&kbuf) {
            Ok(n) => pack_ok(n as u64),
            Err(e) => pack_err(e),
        }
    } else {
        match handle.pwrite(offset, &kbuf) {
            Ok(n) => pack_ok(n as u64),
            Err(e) => pack_err(e),
        }
    }
}

/// `read(fd, buf, len, offset)`：从 stdin 键盘或用户 FD 句柄读取。
///
/// ABI 约定：仅 [`STREAM_OFFSET_CURRENT`] 表示顺序读；`offset=0` 以及任意其他
/// 偏移均为定位读（`pread`），不会推进句柄当前位置。
fn sys_read(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;
    let offset = frame.r10;
    if len == 0 {
        return pack_ok(0);
    }
    // 校验 [buf, buf+len) 落在用户半区。
    let Some(end) = buf.checked_add(len) else {
        return pack_err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return pack_err(Error::OutOfRange);
    }

    // 标准输入 stdin (0)
    if fd == 0 {
        let mut got = 0usize;
        let mut tmp = [0u8; 64];
        while got < len as usize && got < tmp.len() {
            match arch_x86_64::keyboard::pop() {
                Some(ch) => {
                    tmp[got] = ch;
                    got += 1;
                }
                None => break,
            }
        }
        if got == 0 {
            task::block_for_kbd(frame);
            return pack_ok(0);
        }
        unsafe {
            arch_x86_64::mmio::copy_to_user(buf, tmp.as_ptr(), got);
        }
        return pack_ok(got as u64);
    }

    // 普通文件描述符
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd as usize) else {
        return pack_err(Error::InvalidParam);
    };

    let mut kbuf = alloc::vec![0u8; len as usize];
    if offset == STREAM_OFFSET_CURRENT {
        match handle.read(&mut kbuf) {
            Ok(n) => {
                unsafe {
                    arch_x86_64::mmio::copy_to_user(buf, kbuf.as_ptr(), n);
                }
                pack_ok(n as u64)
            }
            Err(e) => pack_err(e),
        }
    } else {
        match handle.pread(offset, &mut kbuf) {
            Ok(n) => {
                unsafe {
                    arch_x86_64::mmio::copy_to_user(buf, kbuf.as_ptr(), n);
                }
                pack_ok(n as u64)
            }
            Err(e) => pack_err(e),
        }
    }
}

/// `exec(prog, cmd)`：加载程序（可为 VFS 路径字符串指针，或内建索引）为新进程并运行。
///
/// 优先从 VFS（如 `/binaries/shell.elf`）读取 ELF 数据，全面升级为基于 VFS 的动态装载；
/// 如果参数为小数值索引（如 0, 1），则自动解析为对应内建路径 `/binaries/init.elf` / `/binaries/shell.elf`。
fn sys_exec(frame: &mut InterruptFrame) -> u64 {
    let arg1 = frame.rdi;
    let arg_ptr = frame.rsi;
    let arg_len = frame.rdx;

    let root = crate::vfs_init::root();

    // 1. 获取 ELF 字节数据
    let elf_data: alloc::vec::Vec<u8> = if arg1 < 16 {
        // 小索引模式兼容
        let path = match arg1 {
            0 => "/binaries/init.elf",
            1 => "/binaries/shell.elf",
            _ => {
                if let Some(bytes) = crate::program_elf(arg1 as usize) {
                    return spawn_elf_image(&bytes, arg_ptr, arg_len, arg1 as usize);
                }
                return pack_err(Error::InvalidParam);
            }
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
            Err(_) => {
                if let Some(bytes) = crate::program_elf(arg1 as usize) {
                    return spawn_elf_image(&bytes, arg_ptr, arg_len, arg1 as usize);
                }
                return pack_err(Error::NotFound);
            }
        }
    } else {
        // 路径字符串模式
        let path = match copy_path_from_user(arg1, 4096) {
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
    };

    spawn_elf_image(&elf_data, arg_ptr, arg_len, arg1 as usize)
}

fn spawn_elf_image(elf_bytes: &[u8], arg_ptr: u64, arg_len: u64, idx_or_tag: usize) -> u64 {
    // 拷命令行到内核缓冲（带 SMAP 安全的 copy_from_user）。空命令行 → 正常启动。
    let mut cmd = [0u8; 512];
    let cmd_len = if arg_len == 0 {
        0
    } else {
        if arg_ptr < USER_BASE || arg_ptr + arg_len > USER_TOP {
            return pack_err(Error::OutOfRange);
        }
        let l = core::cmp::min(arg_len as usize, cmd.len());
        unsafe {
            arch_x86_64::mmio::copy_from_user(cmd.as_mut_ptr(), arg_ptr, l);
        }
        l
    };
    let cmd = &cmd[..cmd_len];
    // C1.1：程序名取自真实加载来源（VFS 路径末段或内建索引名），非 pid 推断。
    let prog_name: alloc::string::String = match idx_or_tag {
        0 => alloc::string::String::from("init.elf"),
        1 => alloc::string::String::from("shell.elf"),
        tag if tag < 16 => alloc::format!("program-{tag}"),
        _ => {
            // 路径字符串模式：idx_or_tag 即用户态路径指针。
            let path = match copy_path_from_user(idx_or_tag as u64, 4096) {
                Ok(p) => p,
                Err(e) => return pack_err(e),
            };
            let trimmed = path.trim_end_matches('\0');
            let last = trimmed
                .rsplit('/')
                .find(|seg| !seg.is_empty())
                .unwrap_or(trimmed);
            if last.is_empty() || last.len() > 63 {
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
        task::yield_now(frame);
        return done(pack_ok(0));
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
    unsafe {
        arch_x86_64::mmio::copy_from_user(name_buf.as_mut_ptr(), name_ptr as u64, len);
    }
    let dev_name = match core::str::from_utf8(&name_buf[..len]) {
        Ok(s) => s,
        Err(_) => return pack_err(Error::InvalidParam),
    };
    match drv::uio_register_driver(pid, dev_name, 0, 0) {
        Ok(id) => pack_ok(id as u64),
        Err(e) => pack_err(e),
    }
}

/// `driver_claim(uio_id, mmio_base, size) -> user_vaddr` (M11.1)
fn sys_driver_claim(frame: &mut InterruptFrame) -> u64 {
    let _uio_id = frame.rdi as usize;
    let mmio_base = frame.rsi;
    let size = frame.rdx;

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };

    let flags = PageFlags::empty().writable().user();
    let user_vaddr = match proc.addr_space_mut().mmap_user(size, flags) {
        Ok(addr) => addr,
        Err(e) => return pack_err(e),
    };

    klib::info!(
        "[uio] claimed MMIO mapped: phys={:#x} -> user_vaddr={:#x} (size={})",
        mmio_base,
        user_vaddr,
        size
    );
    pack_ok(user_vaddr)
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
        SYS_STREAM_READ => done(sys_read(frame)),
        SYS_STREAM_WRITE => done(sys_write(frame)),
        SYS_STREAM_CLOSE => done(sys_close(frame)),

        // MEMORY Domain (0x20)
        SYS_MEMORY_MAP => done(sys_mmap(frame)),
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
