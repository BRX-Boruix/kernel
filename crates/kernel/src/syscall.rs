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

use crate::process::current_proc_mut;

// ---------- syscall 号（域 + 操作二维编码） ----------

/// 资源域（高字节）。
mod domain {
    pub const PROCESS: u32 = 0x00;
    pub const MEMORY: u32 = 0x10;
    pub const IO: u32 = 0x20;
    pub const TIME: u32 = 0x30;
    /// 预留域（syscall 表契约，后续实现 random 域 handler）。
    #[allow(dead_code)]
    pub const RANDOM: u32 = 0x40;
    /// 预留域（syscall 表契约，后续实现 device 域 handler）。
    #[allow(dead_code)]
    pub const DEVICE: u32 = 0x50;
    /// IPC 域（M5）：共享内存。
    pub const IPC_SHM: u32 = 0x60;
    /// IPC 域（M5）：管道。
    pub const IPC_PIPE: u32 = 0x61;
    pub const SYSTEM: u32 = 0xF0;
}

/// 统一操作码（低字节）：所有资源同一套 CRUD 语义（RESTful）。
mod op {
    pub const CREATE: u32 = 0x00; // 新建 / 打开
    pub const READ: u32 = 0x01; // 读 / 取当前值
    pub const WRITE: u32 = 0x02; // 写
    pub const CLOSE: u32 = 0x03; // 关闭 / 销毁
    /// 预留操作（syscall 表契约，后续实现 control/ctl 语义）。
    #[allow(dead_code)]
    pub const CONTROL: u32 = 0x04; // 控制
    pub const QUERY: u32 = 0x05; // 查询状态
}

/// 组合系统调用号：`(domain << 8) | op`。
const fn nr(d: u32, o: u32) -> u32 {
    (d << 8) | o
}

pub const SYS_OPEN: u32 = nr(domain::IO, op::CREATE); // 0x2000 open(path, flags, perm) -> fd
pub const SYS_READ: u32 = nr(domain::IO, op::READ); // 0x2001 read(fd, buf, len) -> n
pub const SYS_WRITE: u32 = nr(domain::IO, op::WRITE); // 0x2002 write(fd, buf, len) -> n
pub const SYS_CLOSE: u32 = nr(domain::IO, op::CLOSE); // 0x2003 close(fd) -> 0
pub const SYS_SEEK: u32 = nr(domain::IO, 0x04); // 0x2004 seek(fd, offset, whence) -> new_offset
pub const SYS_READDIR: u32 = nr(domain::IO, 0x05); // 0x2005 readdir(path, buf, cap) -> count
pub const SYS_MKDIR: u32 = nr(domain::IO, 0x06); // 0x2006 mkdir(path, perm) -> 0
pub const SYS_UNLINK: u32 = nr(domain::IO, 0x07); // 0x2007 unlink(path) -> 0
pub const SYS_PREAD: u32 = nr(domain::IO, 0x08); // 0x2008 pread(fd, buf, len, offset) -> n
pub const SYS_PWRITE: u32 = nr(domain::IO, 0x09); // 0x2009 pwrite(fd, buf, len, offset) -> n
pub const SYS_FLOCK: u32 = nr(domain::IO, 0x0A); // 0x200A flock(fd, op) -> 0
pub const SYS_EXEC: u32 = nr(domain::PROCESS, op::CREATE); // 0x0000 exec(prog) -> pid
pub const SYS_MMAP: u32 = nr(domain::MEMORY, op::CREATE); // 0x1000 mmap(size) -> addr
/// 预留 ABI 槽（后续实现 munmap）。
#[allow(dead_code)]
pub const SYS_MUNMAP: u32 = nr(domain::MEMORY, op::CLOSE); // 0x1003 munmap(addr, size)
pub const SYS_BRK: u32 = nr(domain::MEMORY, op::QUERY); // 0x1005 brk(new) -> break（0=查）
pub const SYS_EXIT: u32 = nr(domain::PROCESS, op::CLOSE); // 0x0003 exit(code) -> !
/// `yield()`：当前进程主动让出 CPU（切到下一个就绪进程）。
pub const SYS_YIELD: u32 = nr(domain::PROCESS, op::CONTROL); // 0x0004 yield()
pub const SYS_NOW: u32 = nr(domain::TIME, op::READ); // 0x3001 now() -> ns
pub const SYS_SLEEP: u32 = nr(domain::TIME, op::WRITE); // 0x3002 sleep(ns)
/// 预留 ABI 槽（后续实现 random 填充）。
#[allow(dead_code)]
pub const SYS_RANDOM: u32 = nr(domain::RANDOM, op::READ); // 0x4001 fill(buf, len)
pub const SYS_INFO: u32 = nr(domain::SYSTEM, op::QUERY); // 0xF005 info(what) -> u64

// ---- M5 IPC 共享内存 ----
/// `shm_create(size) -> id`：分配一组物理帧登记为共享对象。
pub const SYS_SHM_CREATE: u32 = nr(domain::IPC_SHM, op::CREATE); // 0x6000
/// `shm_unmap(id)`：解除当前进程映射，最后一次时释放帧并移除对象。
pub const SYS_SHM_UNMAP: u32 = nr(domain::IPC_SHM, op::CLOSE); // 0x6003
/// `shm_map(id) -> addr`：把对象帧映射进当前进程地址空间。
pub const SYS_SHM_MAP: u32 = nr(domain::IPC_SHM, op::QUERY); // 0x6005

// ---- M5 IPC 管道 ----
/// `pipe_create() -> id`：新建空管道。
pub const SYS_PIPE_CREATE: u32 = nr(domain::IPC_PIPE, op::CREATE); // 0x6100
/// `pipe_read(id, buf, len) -> n`：阻塞读。
pub const SYS_PIPE_READ: u32 = nr(domain::IPC_PIPE, op::READ); // 0x6101
/// `pipe_write(id, buf, len) -> n`：阻塞写。
pub const SYS_PIPE_WRITE: u32 = nr(domain::IPC_PIPE, op::WRITE); // 0x6102
/// `pipe_close(id)`：销毁管道。
pub const SYS_PIPE_CLOSE: u32 = nr(domain::IPC_PIPE, op::CLOSE); // 0x6103

// ---- 进程查询 / 信号 ----
/// `ps(buf, cap) -> count`：枚举存活进程快照写入用户缓冲（每条 8 字节）。
pub const SYS_PS: u32 = nr(domain::SYSTEM, 0x10); // 0xF010
/// `kill(pid, sig) -> 0`：向进程发送信号（9=SIGKILL / 15=SIGTERM 终止；0=校验存在）。
pub const SYS_KILL: u32 = nr(domain::SYSTEM, 0x20); // 0xF020

/// `sys::info` 查询项。
pub const INFO_VERSION: u64 = 0; // 内核版本号
pub const INFO_BOOT_MS: u64 = 1; // 启动以来毫秒数
pub const INFO_CPU_COUNT: u64 = 2; // CPU 数

/// 内核版本号（major<<16 | minor<<8 | patch）。
///
/// 与启动横幅保持一致：来源为 `CARGO_PKG_VERSION`（见 `kernel/Cargo.toml` 的
/// `version`，即 workspace 的 `0.1.0`），而非手填常量。编译期从 `env!` 取版本串
/// 并打包，保证 `version`/`uname` 命令与 `BORUIX KERNEL v.x.y.z` 横幅同源。
pub const KERNEL_VERSION: u64 = pack_pkg_version();

/// 把 `CARGO_PKG_VERSION`（如 `"0.1.0"`）解析并打包为
/// `major<<16 | minor<<8 | patch` 的 u64（编译期常量）。
const fn pack_pkg_version() -> u64 {
    let s = env!("CARGO_PKG_VERSION");
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut cur: u64 = 0;
    let mut major: u64 = 0;
    let mut minor: u64 = 0;
    let mut patch: u64 = 0;
    let mut which = 0u32; // 0=major 1=minor 2=patch
    while i < b.len() {
        if b[i] == b'.' {
            if which == 0 {
                major = cur;
            } else if which == 1 {
                minor = cur;
            }
            cur = 0;
            which += 1;
        } else if b[i].is_ascii_digit() {
            cur = cur * 10 + (b[i] - b'0') as u64;
        }
        i += 1;
    }
    // 收尾最后一段（无结尾 '.' 的情况）。
    if which == 0 {
        major = cur;
    } else if which == 1 {
        minor = cur;
    } else {
        patch = cur;
    }
    (major << 16) | (minor << 8) | patch
}

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
        Err(Error::NotFound) if flags.create => {
            match root.create_file(&path, perm) {
                Ok(n) => n,
                Err(e) => return pack_err(e),
            }
        }
        Err(e) => return pack_err(e),
    };

    let handle = vfs::file_handle::FileHandle::new(inode, flags);
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let fd = proc.alloc_fd(handle);
    pack_ok(fd as u64)
}

/// `close(fd)`：关闭文件描述符。
fn sys_close(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    if fd < 3 {
        // 标准流不支持 close
        return pack_ok(0);
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

/// `seek(fd, offset, whence)`：调整文件句柄游标。
fn sys_seek(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    let offset = frame.rsi as i64;
    let whence_raw = frame.rdx as u32;
    let whence = match whence_raw {
        0 => vfs::file_handle::SeekWhence::Set,
        1 => vfs::file_handle::SeekWhence::Current,
        2 => vfs::file_handle::SeekWhence::End,
        _ => return pack_err(Error::InvalidParam),
    };

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd) else {
        return pack_err(Error::NotFound);
    };
    match handle.seek(offset, whence) {
        Ok(new_off) => pack_ok(new_off),
        Err(e) => pack_err(e),
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

/// `pread(fd, buf, len, offset)`：显式无状态定位读。
fn sys_pread(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    let buf = frame.rsi;
    let len = frame.rdx as usize;
    let offset = frame.r10;

    let Some(end) = buf.checked_add(len as u64) else {
        return pack_err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return pack_err(Error::OutOfRange);
    };

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd) else {
        return pack_err(Error::NotFound);
    };

    let mut kbuf = alloc::vec![0u8; len];
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

/// `pwrite(fd, buf, len, offset)`：显式无状态定位写。
fn sys_pwrite(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    let buf = frame.rsi;
    let len = frame.rdx as usize;
    let offset = frame.r10;

    let Some(end) = buf.checked_add(len as u64) else {
        return pack_err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return pack_err(Error::OutOfRange);
    };

    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    let Some(handle) = proc.get_fd(fd) else {
        return pack_err(Error::NotFound);
    };

    let mut kbuf = alloc::vec![0u8; len];
    unsafe {
        arch_x86_64::mmio::copy_from_user(kbuf.as_mut_ptr(), buf, len);
    }
    match handle.pwrite(offset, &kbuf) {
        Ok(n) => pack_ok(n as u64),
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

/// `flock(fd, op)`：顾问文件锁。
fn sys_flock(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi as usize;
    let _op = frame.rsi as u32;
    let Some(proc) = current_proc_mut() else {
        return pack_err(Error::NotFound);
    };
    if proc.get_fd(fd).is_some() {
        pack_ok(0)
    } else {
        pack_err(Error::NotFound)
    }
}

/// `write(fd, buf, len)`：写入 stdout/stderr 或用户 FD 句柄。
fn sys_write(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;

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
    match handle.write(&kbuf) {
        Ok(n) => pack_ok(n as u64),
        Err(e) => pack_err(e),
    }
}

/// `read(fd, buf, len)`：从 stdin 键盘或用户 FD 句柄读取。
fn sys_read(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;
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
            crate::scheduler::block_for_kbd(frame);
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
    match handle.read(&mut kbuf) {
        Ok(n) => {
            unsafe {
                arch_x86_64::mmio::copy_to_user(buf, kbuf.as_ptr(), n);
            }
            pack_ok(n as u64)
        }
        Err(e) => pack_err(e),
    }
}

/// `exec(prog)`：加载内核嵌入的用户程序（`prog` 为嵌入池索引）为新进程并运行。
///
/// 复用 `elf::load` + `scheduler::spawn`（与启动 init 相同路径），返回新进程
/// pid。`prog` 越界或加载失败返回对应错误。新进程独立地址空间、独立内核栈，
/// 由调度器 RR 轮转调度（与 init 并存）。
fn sys_exec(frame: &mut InterruptFrame) -> u64 {
    let idx = frame.rdi as usize;
    let arg_ptr = frame.rsi;
    let arg_len = frame.rdx;
    let Some(elf_bytes) = crate::program_elf(idx) else {
        return pack_err(Error::InvalidParam);
    };
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
    let Ok(mut us) = mm::user_space::UserAddressSpace::<
        arch_x86_64::paging::X86PageTable,
    >::new()
    else {
        return pack_err(Error::OutOfMemory);
    };
    let loaded = match crate::elf::load(elf_bytes, &mut us, cmd) {
        Ok(l) => l,
        Err(e) => return pack_err(e),
    };
    match crate::scheduler::spawn(loaded.entry, loaded.user_stack_top, us) {
        Ok(pid) => {
            klib::info!(
                "[syscall] exec prog={} -> pid={} entry={:#x}",
                idx,
                pid,
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

/// `now()`：单调时钟，纳秒。
fn sys_now() -> u64 {
    pack_ok(klib::time::now_nanos())
}

/// `sleep(ns)`：忙等睡眠（单进程无调度，M4.2 改挂起）。
fn sys_sleep(frame: &mut InterruptFrame) -> u64 {
    klib::time::sleep_nanos(frame.rdi);
    pack_ok(0)
}

/// `yield()`：当前进程主动让出 CPU（切到下一个就绪进程；仅当前进程则立即返回）。
///
/// `scheduler::yield_now` 若切换了进程，会把 `frame` 整体改写为下一进程的保存帧；
/// 返回后 `syscall_entry` 把返回值 0 写回（对已让出的进程在下一次恢复时生效，
/// 对当前切换目标进程的 rax 置 0 无副作用）。`iretq` 即进入目标进程用户态。
fn sys_yield(frame: &mut InterruptFrame) -> u64 {
    crate::scheduler::yield_now(frame);
    pack_ok(0)
}

/// `info(what)`：查询内核信息。
fn sys_info(frame: &mut InterruptFrame) -> u64 {
    match frame.rdi {
        INFO_VERSION => pack_ok(KERNEL_VERSION),
        INFO_BOOT_MS => pack_ok(klib::time::now_millis()),
        INFO_CPU_COUNT => pack_ok(mm::cpu_count() as u64),
        _ => pack_err(Error::InvalidParam),
    }
}

// ---------- M5 IPC handlers ----------

/// 取当前进程的可变用户地址空间（失败返回 NotFound）。
fn cur_addr_space() -> Result<
    &'static mut mm::user_space::UserAddressSpace<arch_x86_64::paging::X86PageTable>,
    Error,
> {
    current_proc_mut()
        .map(|p| p.addr_space_mut())
        .ok_or(Error::NotFound)
}

/// `shm_create(size) -> id`。
fn sys_shm_create(frame: &mut InterruptFrame) -> u64 {
    match crate::ipc::shm_create(frame.rdi) {
        Ok(id) => pack_ok(id),
        Err(e) => pack_err(e),
    }
}

/// `shm_map(id) -> addr`。
fn sys_shm_map(frame: &mut InterruptFrame) -> u64 {
    let Ok(addr_space) = cur_addr_space() else {
        return pack_err(Error::NotFound);
    };
    match crate::ipc::shm_map(frame.rdi, addr_space) {
        Ok(a) => pack_ok(a),
        Err(e) => pack_err(e),
    }
}

/// `shm_unmap(id)`。
fn sys_shm_unmap(frame: &mut InterruptFrame) -> u64 {
    let Ok(addr_space) = cur_addr_space() else {
        return pack_err(Error::NotFound);
    };
    match crate::ipc::shm_unmap(frame.rdi, addr_space) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `pipe_create() -> id`。
fn sys_pipe_create(_frame: &mut InterruptFrame) -> u64 {
    match crate::ipc::pipe_create() {
        Ok(id) => pack_ok(id),
        Err(e) => pack_err(e),
    }
}

/// `pipe_read(id, buf, len) -> n`：阻塞读。
fn sys_pipe_read(frame: &mut InterruptFrame) -> u64 {
    match crate::ipc::pipe_read(frame, frame.rdi, frame.rsi, frame.rdx) {
        Ok(n) => pack_ok(n),
        Err(e) => pack_err(e),
    }
}

/// `pipe_write(id, buf, len) -> n`：阻塞写。
fn sys_pipe_write(frame: &mut InterruptFrame) -> u64 {
    match crate::ipc::pipe_write(frame, frame.rdi, frame.rsi, frame.rdx) {
        Ok(n) => pack_ok(n),
        Err(e) => pack_err(e),
    }
}

/// `pipe_close(id)`。
fn sys_pipe_close(frame: &mut InterruptFrame) -> u64 {
    match crate::ipc::pipe_close(frame.rdi) {
        Ok(()) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

/// `exit(code)`：终止当前进程并调度到下一个就绪进程（多进程场景）。
///
/// 经 `scheduler::exit_current` 回收当前进程槽位并改写 `frame` 为下一个就绪
/// 进程的保存帧；返回后 `syscall_entry` 的 iretq 进入目标进程。若所有进程都
/// 退出则停机。返回值为填充占位（当前进程已死，实际由 iretq 接管）。
fn sys_exit(frame: &mut InterruptFrame) -> u64 {
    let code = frame.rdi;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    klib::info!("[syscall] process {} exit(code={})", pid, code);
    crate::scheduler::exit_current(frame);
    0
}

/// `ps(buf, cap) -> count`：枚举存活进程快照写入用户缓冲（每条约 8 字节）。
fn sys_ps(frame: &mut InterruptFrame) -> u64 {
    let buf = frame.rdi as *mut u8;
    let cap = frame.rsi as usize;
    let n = crate::scheduler::ps_snapshot(buf, cap);
    pack_ok(n as u64)
}

/// `kill(pid, sig) -> 0`：向进程发送信号（终止 / 校验存在）。
fn sys_kill(frame: &mut InterruptFrame) -> u64 {
    let target = frame.rdi as usize;
    let sig = frame.rsi as u32;
    match crate::scheduler::kill_pid(target, sig, frame) {
        Ok(_) => pack_ok(0),
        Err(e) => pack_err(e),
    }
}

// ---------- 分发 ----------

/// 按系统调用号分发到具体实现。返回打包后的结果（写回 `frame.rax`）。
fn dispatch(nr: u64, frame: &mut InterruptFrame) -> u64 {
    match nr as u32 {
        SYS_OPEN => sys_open(frame),
        SYS_READ => sys_read(frame),
        SYS_WRITE => sys_write(frame),
        SYS_CLOSE => sys_close(frame),
        SYS_SEEK => sys_seek(frame),
        SYS_READDIR => sys_readdir(frame),
        SYS_MKDIR => sys_mkdir(frame),
        SYS_UNLINK => sys_unlink(frame),
        SYS_PREAD => sys_pread(frame),
        SYS_PWRITE => sys_pwrite(frame),
        SYS_FLOCK => sys_flock(frame),
        SYS_EXEC => sys_exec(frame),
        SYS_MMAP => sys_mmap(frame),
        SYS_BRK => sys_brk(frame),
        SYS_NOW => sys_now(),
        SYS_SLEEP => sys_sleep(frame),
        SYS_YIELD => sys_yield(frame),
        SYS_INFO => sys_info(frame),
        SYS_SHM_CREATE => sys_shm_create(frame),
        SYS_SHM_MAP => sys_shm_map(frame),
        SYS_SHM_UNMAP => sys_shm_unmap(frame),
        SYS_PIPE_CREATE => sys_pipe_create(frame),
        SYS_PIPE_READ => sys_pipe_read(frame),
        SYS_PIPE_WRITE => sys_pipe_write(frame),
        SYS_PIPE_CLOSE => sys_pipe_close(frame),
        SYS_PS => sys_ps(frame),
        SYS_KILL => sys_kill(frame),
        SYS_EXIT => sys_exit(frame),
        _ => {
            klib::info!("[syscall] unknown nr={:#x}", nr);
            pack_err(Error::NotSupported)
        }
    }
}

// ---------- 软中断入口 ----------

/// `int 0x80` 软中断处理回调（注册为 `register_soft_interrupt_handler`）。
///
/// 从 `InterruptFrame` 读 `rax`（系统调用号）与参数寄存器，分发执行后把结果
/// 写回 `frame.rax`，返回 `true` 让 `iretq` 把结果带回用户态。
/// `exit` 不返回（停机），故不会执行到返回语句。
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
    let ret = dispatch(nr, frame);
    #[cfg(feature = "kernel-tests")]
    klib::info!("[syscall] nr={:#x} -> {:#x}", nr, ret);
    frame.rax = ret;
    true
}
