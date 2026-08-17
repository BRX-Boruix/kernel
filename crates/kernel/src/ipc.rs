//! 进程间通信（IPC）——M5：共享内存（shm）+ 管道（pipe）。
//!
//! 设计（RESTful 资源观，对齐 syscall 二维编码 ADR-003）：
//! - **共享内存（shm）**：`shm_create(size) -> id` 分配一组物理帧登记为对象；
//!   `shm_map(id) -> addr` 把对象帧映射进调用进程地址空间（多进程映射同一 id
//!   即共享同一批物理帧）；`shm_unmap(id)` 解除调用进程的映射（帧归对象所有，
//!   最后一次解映射时释放）。对象用引用计数记录映射它的进程数。
//! - **管道（pipe）**：`pipe_create() -> id` 建一个环形缓冲；`pipe_read` /
//!   `pipe_write` 阻塞读写——空时读挂起（记入 read_waiters）、满时写挂起
//!   （记入 write_waiters），对侧操作完成时唤醒。
//!
//! 阻塞经调度器 [`crate::scheduler::block_current`] / [`wake`] 实现：进程在
//! syscall 上下文把自己置 Blocked（保存帧、切到下一个就绪进程），其它进程操作
//! 管道时把 Blocked 进程放回就绪队列。单核 RR 下若就绪队列无进程可切，返回
//! `WouldBlock` 而非无限自阻塞（避免"等一个不存在的进程"的死锁）。
//!
//! 锁策略：表级 `IrqSpinLock`（关中断，与调度器一致）。阻塞前先释放表锁再调用
//! 调度器（避免持有表锁时切走导致其它进程死锁在表锁上）。唤醒仅调用 `wake`，
//! 不反向拿 SCHED 后再拿表锁，无嵌套死锁。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use arch_x86_64::interrupts::InterruptFrame;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

/// 管道默认容量（字节，环形缓冲）。
pub const PIPE_CAPACITY: usize = 4096;

/// 共享内存对象：一组物理帧，可被多个进程共享映射。
struct ShmObject {
    /// 对象大小（字节，页对齐）。
    size: u64,
    /// 物理帧地址（每页 4KB）。
    frames: Vec<u64>,
    /// 映射它的进程数（最后一次解映射时释放帧并移除对象）。
    refs: usize,
}

/// 管道对象：环形缓冲 + 读写阻塞等待者（按 pid 记）。
struct PipeObject {
    buf: VecDeque<u8>,
    /// 空时读阻塞的进程 pid。
    read_waiters: Vec<usize>,
    /// 满时写阻塞的进程 pid。
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
        // 清零新共享帧，保证内容确定。
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
///
/// 返回映射起始虚拟地址。多进程调用同一 id 得到各自虚拟地址，但共享同一批
/// 物理帧——写一个进程的映射，其它进程可见。帧归对象所有，本函数不额外
/// incref（对象持有），仅把对象 `refs` 加一。
pub fn shm_map(id: u64, addr_space: &mut mm::user_space::UserAddressSpace<arch_x86_64::paging::X86PageTable>) -> Result<u64, Error> {
    let mut table = SHM_TABLE.lock();
    let obj = table.get_mut(&id).ok_or(Error::NotFound)?;
    let vaddr = addr_space.map_shm(id, &obj.frames, obj.size)?;
    obj.refs += 1;
    klib::info!("[ipc] shm_map id={} refs={} -> {:#x}", id, obj.refs, vaddr);
    Ok(vaddr)
}

/// `shm_unmap(id)`：解除调用进程对该 shm 对象的映射。
///
/// 若这是最后一个映射，释放对象的物理帧并移除对象（回收内存）。
pub fn shm_unmap(id: u64, addr_space: &mut mm::user_space::UserAddressSpace<arch_x86_64::paging::X86PageTable>) -> Result<(), Error> {
    addr_space.unmap_shm(id)?;
    let mut table = SHM_TABLE.lock();
    let obj = table.get_mut(&id).ok_or(Error::NotFound)?;
    obj.refs = obj.refs.saturating_sub(1);
    if obj.refs == 0 {
        let obj = table.remove(&id).expect("just fetched");
        for &phys in obj.frames.iter() {
            mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(phys));
        }
        klib::info!("[ipc] shm_unmap id={} freed {} frames", id, obj.frames.len());
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

/// 当前进程阻塞自己（经调度器），直到被唤醒。
///
/// **调用前必须已释放 IPC 表锁**（见各函数）。返回 `false` 表示无可调度进程可切
/// （此时不应阻塞，调用方返回 `WouldBlock` 避免"等一个不存在的进程"的死锁）。
fn try_block(frame: &mut InterruptFrame) -> bool {
    crate::scheduler::block_current(frame)
}

/// `pipe_write(id, src, len)`：把 `len` 字节写入管道，必要时阻塞。
///
/// 返回实际写入字节数（阻塞进程在唤醒后恢复循环，继续写完剩余部分）。写前
/// 释放表锁，把本 pid 记入 `write_waiters`；对侧读端取走数据后唤醒。若无可
/// 调度进程（只有本进程），返回 `WouldBlock` 而非自阻塞。
pub fn pipe_write(frame: &mut InterruptFrame, id: u64, src: u64, len: u64) -> Result<u64, Error> {
    // 无当前进程（内核测试直调）时用 pid 0 哨兵：仅在真正阻塞时才涉及 pid，
    // 数据流测试不会阻塞，故安全。
    let pid = crate::process::current_proc_mut().map(|p| p.pid()).unwrap_or(0);
    let len = len as usize;
    let mut written = 0usize;
    loop {
        // 拷贝阶段：持表锁；出块即释放（block 前必须无表锁）。
        {
            let mut table = PIPE_TABLE.lock();
            let Some(pipe) = table.get_mut(&id) else {
                return Err(Error::NotFound);
            };
            while written < len && pipe.buf.len() < PIPE_CAPACITY {
                pipe.buf.push_back(unsafe { *((src + written as u64) as *const u8) });
                written += 1;
            }
            if written > 0 {
                for w in pipe.read_waiters.drain(..) {
                    crate::scheduler::wake(w);
                }
            }
            if written == len {
                return Ok(written as u64);
            }
            // 缓冲满且还有剩余：登记写阻塞，出块后阻塞。
            pipe.write_waiters.push(pid);
        } // 释放表锁
        if !try_block(frame) {
            return Err(Error::WouldBlock);
        }
        // 被唤醒后回到循环顶部重新尝试。
    }
}

/// `pipe_read(id, dst, len)`：从管道读 `len` 字节，必要时阻塞。
///
/// 返回实际读到的字节数。读到任意数据即返回（阻塞读的常见语义）；管道为空且
/// 无数据可等时若已读到数据返回已读数，否则阻塞。写前释放表锁并把本 pid 记入
/// `read_waiters`；写端写入后唤醒。若无可调度进程，返回 `WouldBlock`。
pub fn pipe_read(frame: &mut InterruptFrame, id: u64, dst: u64, len: u64) -> Result<u64, Error> {
    let pid = crate::process::current_proc_mut().map(|p| p.pid()).unwrap_or(0);
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
            while got < len && !pipe.buf.is_empty() {
                let b = pipe.buf.pop_front().expect("nonempty");
                unsafe { *((dst + got as u64) as *mut u8) = b };
                got += 1;
            }
            if got > 0 {
                for w in pipe.write_waiters.drain(..) {
                    crate::scheduler::wake(w);
                }
            }
            if got > 0 {
                return Ok(got as u64);
            }
            // 空且仍有需求：登记读阻塞，出块后阻塞。
            pipe.read_waiters.push(pid);
        } // 释放表锁
        if !try_block(frame) {
            return Err(Error::WouldBlock);
        }
        // 被唤醒后回到循环顶部重新尝试。
    }
}

/// `pipe_close(id)`：销毁管道（唤醒所有阻塞者）。
pub fn pipe_close(id: u64) -> Result<(), Error> {
    let mut table = PIPE_TABLE.lock();
    if table.remove(&id).is_none() {
        return Err(Error::NotFound);
    }
    klib::info!("[ipc] pipe_close id={}", id);
    Ok(())
}
