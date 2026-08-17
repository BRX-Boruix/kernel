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

use crate::process::{clear_current_proc, current_proc_mut};

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

pub const SYS_WRITE: u32 = nr(domain::IO, op::WRITE); // 0x2002 write(fd, buf, len) -> n
/// 预留 ABI 槽（后续实现 read）。
#[allow(dead_code)]
pub const SYS_READ: u32 = nr(domain::IO, op::READ); // 0x2001 read(fd, buf, len) -> n
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

/// `sys::info` 查询项。
pub const INFO_VERSION: u64 = 0; // 内核版本号
pub const INFO_BOOT_MS: u64 = 1; // 启动以来毫秒数
pub const INFO_CPU_COUNT: u64 = 2; // CPU 数

/// 内核版本号（major<<16 | minor<<8 | patch）。
pub const KERNEL_VERSION: u64 = 0x0000_0401; // v0.4.1

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

/// `write(fd, buf, len)`：把用户缓冲输出到统一 console（fd 1=stdout）。
/// 分块拷贝（栈缓冲，no_std 无堆），校验缓冲位于用户半区。
fn sys_write(frame: &mut InterruptFrame) -> u64 {
    let fd = frame.rdi;
    let buf = frame.rsi;
    let len = frame.rdx;
    if fd != 1 && fd != 2 {
        return pack_err(Error::InvalidParam);
    }
    // 校验 [buf, buf+len) 完全落在用户半区，避免越界读内核地址。
    let Some(end) = buf.checked_add(len) else {
        return pack_err(Error::OutOfRange);
    };
    if buf < USER_BASE || end > USER_TOP {
        return pack_err(Error::OutOfRange);
    }
    const CHUNK: usize = 256;
    let mut chunk = [0u8; CHUNK];
    let mut off = 0usize;
    while off < len as usize {
        let n = core::cmp::min(len as usize - off, CHUNK);
        // 用户缓冲区位于用户半区（USER 权限页）；SMAP 下内核读取需 STAC 临时放行。
        unsafe {
            arch_x86_64::mmio::copy_from_user(chunk.as_mut_ptr(), buf + off as u64, n);
        }
        let s = core::str::from_utf8(&chunk[..n]).unwrap_or("\u{FFFD}");
        klib::console::write_str(s);
        off += n;
    }
    pack_ok(len)
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

/// `exit(code)`：终止当前进程（单进程无调度：清理后停机）。永不返回。
fn sys_exit(frame: &mut InterruptFrame) -> ! {
    let code = frame.rdi;
    let pid = current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    clear_current_proc();
    klib::info!("[syscall] process {} exit(code={})", pid, code);
    arch_x86_64::interrupts::disable();
    loop {
        arch_x86_64::interrupts::halt();
    }
}

// ---------- 分发 ----------

/// 按系统调用号分发到具体实现。返回打包后的结果（写回 `frame.rax`）。
fn dispatch(nr: u64, frame: &mut InterruptFrame) -> u64 {
    match nr as u32 {
        SYS_WRITE => sys_write(frame),
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
    klib::info!(
        "[syscall] nr={:#x} a1={:#x} a2={:#x} a3={:#x}",
        nr,
        frame.rdi,
        frame.rsi,
        frame.rdx
    );
    let ret = dispatch(nr, frame);
    klib::info!("[syscall] nr={:#x} -> {:#x}", nr, ret);
    frame.rax = ret;
    true
}
