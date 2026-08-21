//! 进程间通信（IPC）子系统（共享内存 shm + 管道 pipe，独立 Crate）。
//!
//! 设计（RESTful 资源观，对齐 syscall 二维编码 ADR-003）：
//! - **共享内存（shm）**：`shm_create(size) -> id` 分配一组物理帧登记为对象；
//!   `shm_map(id) -> addr` 把对象帧映射进调用进程地址空间；`shm_unmap(id)` 解除映射。
//! - **管道（pipe）**：`pipe_create() -> id` 建环形缓冲；`pipe_read` / `pipe_write` 阻塞读写。

#![no_std]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use arch_x86_64::interrupts::InterruptFrame;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

/// 管道默认容量（字节，环形缓冲）。
pub const PIPE_CAPACITY: usize = 4096;

/// 调度器与进程回调 Provider（解耦 IPC 与 Task/Scheduler 的循环依赖）。
pub trait IpcTaskNotifier: Send + Sync {
    fn current_pid(&self) -> usize;
    fn wake_process(&self, pid: usize);
    fn block_current_process(&self, frame: &mut InterruptFrame) -> bool;
}

static NOTIFIER: spin::Mutex<Option<&'static dyn IpcTaskNotifier>> = spin::Mutex::new(None);

pub fn set_ipc_notifier(notifier: &'static dyn IpcTaskNotifier) {
    *NOTIFIER.lock() = Some(notifier);
}

/// 共享内存对象：一组物理帧，可被多个进程共享映射。
struct ShmObject {
    size: u64,
    frames: Vec<u64>,
    refs: usize,
}

/// 管道对象：环形缓冲 + 读写阻塞等待者（按 pid 记）。
struct PipeObject {
    buf: VecDeque<u8>,
    read_waiters: Vec<usize>,
    write_waiters: Vec<usize>,
}

static SHM_TABLE: IrqSpinLock<BTreeMap<u64, ShmObject>> = IrqSpinLock::new(BTreeMap::new());
static PIPE_TABLE: IrqSpinLock<BTreeMap<u64, PipeObject>> = IrqSpinLock::new(BTreeMap::new());
static NEXT_SHM: AtomicU64 = AtomicU64::new(1);
static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

// ---------- 共享内存 ----------

/// `shm_create(size) -> id`：分配 `size`（向上取整到页）物理帧，登记为共享对象。
pub fn shm_create(size: u64) -> Result<u64, Error> {
    if size == 0 {
        return Err(Error::InvalidParam);
    }
    let size = (size + 0xFFF) & !0xFFF;
    let npages = (size / 0x1000) as usize;
    let mut frames = Vec::with_capacity(npages);
    for _ in 0..npages {
        let f = mm::allocate_frame().ok_or(Error::OutOfMemory)?;
        let off = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
        unsafe { core::ptr::write_bytes((f.start_paddr() + off) as *mut u8, 0, 0x1000) };
        frames.push(f.start_paddr());
    }
    let id = NEXT_SHM.fetch_add(1, Ordering::Relaxed);
    SHM_TABLE.lock().insert(
        id,
        ShmObject {
            size,
            frames,
            refs: 0,
        },
    );
    klib::info!("[ipc] shm_create id={} size={:#x}", id, size);
    Ok(id)
}

/// `shm_map(id) -> addr`：把 shm 对象帧映射进调用进程地址空间。
pub fn shm_map(
    id: u64,
    addr_space: &mut mm::user_space::UserAddressSpace<arch_x86_64::paging::X86PageTable>,
) -> Result<u64, Error> {
    let mut table = SHM_TABLE.lock();
    let obj = table.get_mut(&id).ok_or(Error::NotFound)?;
    let vaddr = addr_space.map_shm(id, &obj.frames, obj.size)?;
    obj.refs += 1;
    klib::info!("[ipc] shm_map id={} refs={} -> {:#x}", id, obj.refs, vaddr);
    Ok(vaddr)
}

/// `shm_unmap(id)`：解除调用进程对该 shm 对象的映射。
pub fn shm_unmap(
    id: u64,
    addr_space: &mut mm::user_space::UserAddressSpace<arch_x86_64::paging::X86PageTable>,
) -> Result<(), Error> {
    addr_space.unmap_shm(id)?;
    let mut table = SHM_TABLE.lock();
    let obj = table.get_mut(&id).ok_or(Error::NotFound)?;
    obj.refs = obj.refs.saturating_sub(1);
    if obj.refs == 0 {
        let obj = table.remove(&id).expect("just fetched");
        for &phys in obj.frames.iter() {
            mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(phys));
        }
        klib::info!(
            "[ipc] shm_unmap id={} freed {} frames",
            id,
            obj.frames.len()
        );
    } else {
        klib::info!("[ipc] shm_unmap id={} refs now {}", id, obj.refs);
    }
    Ok(())
}

// ---------- 管道 ----------

/// `pipe_create() -> id`：新建一个空管道。
pub fn pipe_create() -> Result<u64, Error> {
    let id = NEXT_PIPE.fetch_add(1, Ordering::Relaxed);
    PIPE_TABLE.lock().insert(
        id,
        PipeObject {
            buf: VecDeque::with_capacity(PIPE_CAPACITY),
            read_waiters: Vec::new(),
            write_waiters: Vec::new(),
        },
    );
    klib::info!("[ipc] pipe_create id={}", id);
    Ok(id)
}

fn try_block(frame: &mut InterruptFrame) -> bool {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.block_current_process(frame)
    } else {
        false
    }
}

fn current_pid() -> usize {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.current_pid()
    } else {
        0
    }
}

fn wake_proc(pid: usize) {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.wake_process(pid);
    }
}

/// `pipe_write(id, src, len)`：把 `len` 字节写入管道，必要时阻塞。
pub fn pipe_write(frame: &mut InterruptFrame, id: u64, src: u64, len: u64) -> Result<u64, Error> {
    let pid = current_pid();
    let len = len as usize;
    let mut written = 0usize;
    loop {
        {
            let mut table = PIPE_TABLE.lock();
            let Some(pipe) = table.get_mut(&id) else {
                return Err(Error::NotFound);
            };
            unsafe { arch_x86_64::mmio::stac() };
            while written < len && pipe.buf.len() < PIPE_CAPACITY {
                pipe.buf
                    .push_back(unsafe { *((src + written as u64) as *const u8) });
                written += 1;
            }
            unsafe { arch_x86_64::mmio::clac() };
            if written > 0 {
                for w in pipe.read_waiters.drain(..) {
                    wake_proc(w);
                }
            }
            if written == len {
                return Ok(written as u64);
            }
            pipe.write_waiters.push(pid);
        }
        if !try_block(frame) {
            return Err(Error::WouldBlock);
        }
    }
}

/// `pipe_read(id, dst, len)`：从管道读 `len` 字节，必要时阻塞。
pub fn pipe_read(frame: &mut InterruptFrame, id: u64, dst: u64, len: u64) -> Result<u64, Error> {
    let pid = current_pid();
    let len = len as usize;
    if len == 0 {
        return Ok(0);
    }
    let mut got = 0usize;
    loop {
        {
            let mut table = PIPE_TABLE.lock();
            let Some(pipe) = table.get_mut(&id) else {
                return Err(Error::NotFound);
            };
            unsafe { arch_x86_64::mmio::stac() };
            while got < len && !pipe.buf.is_empty() {
                let b = pipe.buf.pop_front().expect("nonempty");
                unsafe { *((dst + got as u64) as *mut u8) = b };
                got += 1;
            }
            unsafe { arch_x86_64::mmio::clac() };
            if got > 0 {
                for w in pipe.write_waiters.drain(..) {
                    wake_proc(w);
                }
            }
            if got > 0 {
                return Ok(got as u64);
            }
            pipe.read_waiters.push(pid);
        }
        if !try_block(frame) {
            return Err(Error::WouldBlock);
        }
    }
}

/// `pipe_close(id)`：销毁管道。
pub fn pipe_close(id: u64) -> Result<(), Error> {
    let mut table = PIPE_TABLE.lock();
    if table.remove(&id).is_none() {
        return Err(Error::NotFound);
    }
    klib::info!("[ipc] pipe_close id={}", id);
    Ok(())
}
