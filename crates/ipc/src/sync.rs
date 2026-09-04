//! SYNC 域同步字对象表（ADR-032 通用 futex 等待/唤醒原语）。
//!
//! 与 shm/pipe 同款手法（S28）：`IrqSpinLock<BTreeMap>` 表 + `AtomicU64` id 分配。
//! 本模块持有**数据与生命周期**（含 `refs` 记账 + 进程退出释放），阻塞/唤醒的平台
//! 接触点经 [`crate::IpcTaskNotifier`]（kernel 适配层注册）解耦，不反向依赖 task——
//! 依赖方向与 shm/pipe 一致：mm ← kernel → ipc 单向。
//!
//! ## refs 生命周期（S18 / ADR-032 §4.1/§4.4）
//!
//! `refs` 计"仍持有的引用数"：创建时 = 1（创建进程持有），[`sync_delete`] 显式释放一
//! 份，[`sync_release_process`] 在持有进程退出时释放其份额。refs 归零（且无等待者）才
//! 真正从表移除——无论走显式 delete 还是进程被 kill 的兜底清理，对象都不残留（S18）。
//! 内核不强制跨进程归属（id 即访问凭证，ADR-032 §4.1 声明），故 refs 实际只记创建者的
//! 那一份；共享方以 id 访问，随创建者释放而失效（如实符合"id 即凭证"的轻量模型）。
//!
//! ## 值域约束（S09 / S31 边界校验）
//!
//! sync 值经 syscall 错误编码约定（bit63 置位 = 负 errno）回传，故**任何写入同步字的
//! 值不得 bit63 置位**——否则用户态会把正常值误读为错误。[`sync_create`]/[`sync_wake`]
//! 在内核边界如实拒绝 bit63 置位的值（`InvalidParam`），不靠调用方自律（S31 对抗输入）。

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use arch_x86_64::interrupts::InterruptFrame;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

use crate::{wake_proc_with_value, BlockOutcome, NOTIFIER};

/// SYNC_WAIT 超时上界（同事件机制 1h，S13 具名常量）。
pub const SYNC_MAX_WAIT_TIMEOUT_NS: u64 = 3_600_000_000_000; // 1h

/// 单个同步字对象的等待者条目。
///
/// `timer` 为超时定时器 id（`0` = 无超时，阻塞至被唤醒）。同一 pid 至多出现
/// 一次（登记时查重，同 `MAX_PIPE_WAITERS` 不变式精神）；`expected` 供超时
/// 唤醒时把保存帧 rax 预置为原值（调用方见值未变即知超时）。
pub struct SyncWaiter {
    pub pid: usize,
    pub expected: u64,
    pub timer: u64,
}

/// 内核同步字对象（ADR-032 §3.1）：跨进程可被多进程并发等待的状态字。
pub struct SyncObject {
    /// 当前同步字值（用户可经 `sync_wake` 设置 / `sync_wait` 读取）。
    pub value: u64,
    /// 阻塞在此字上的进程等待队列（多等待者，允许并发）。
    pub waiters: Vec<SyncWaiter>,
    /// 存活引用数（ADR-032 §4.1：创建进程持有 1）。refs 归零才从表移除（S18）。
    pub refs: usize,
    /// 创建进程 pid（进程退出时释放其持有的那份 ref，S18 兜底清理）。
    pub owner: usize,
}

/// 同步字对象表 + id 分配。锁序为 `PROCS(调度进程池锁) → SYNC_TABLE`（等待者
/// 登记在调度域锁 PROCS 内持表锁；唤醒先取表锁收集等待者、释放后再经调度唤醒
/// ——无 SYNC_TABLE 持锁再取调度域锁的反向边，故与 shm/pipe 同为无环单向序）。
static SYNC_TABLE: IrqSpinLock<BTreeMap<u64, SyncObject>> = IrqSpinLock::new(BTreeMap::new());
/// id 从 1 起：0 预留给"无效句柄"哨兵语义（同 ipc NEXT_SHM/NEXT_PIPE）。
/// u64 回绕不可达论证同 ipc（每次分配伴随至少一次堆分配与一次表插入）。
static NEXT_SYNC: AtomicU64 = AtomicU64::new(1);

/// `sync_create(init_value, owner) -> sync_id`（SYS_SYNC_CREATE / 0x71）。
///
/// 分配 `SyncObject`（value=init_value, waiters=[], refs=1, owner），登记进表，返回 id。
/// 失败：`OutOfMemory`（对象/表分配失败）；`InvalidParam`（init_value 带 bit63）。
pub fn sync_create(init_value: u64, owner: usize) -> Result<u64, Error> {
    // S31 边界：bit63 置位的值会被用户态 syscall 错误编码误读为负 errno（S09 数据链路）。
    if init_value & (1 << 63) != 0 {
        return Err(Error::InvalidParam);
    }
    let mut obj = SyncObject {
        value: init_value,
        waiters: Vec::new(),
        refs: 1,
        owner,
    };
    if obj.waiters.try_reserve(1).is_err() {
        return Err(Error::OutOfMemory);
    }
    let id = NEXT_SYNC.fetch_add(1, Ordering::Relaxed);
    SYNC_TABLE.lock().insert(id, obj);
    klib::info!("[ipc/sync] create id={} init={:#x} owner={}", id, init_value, owner);
    Ok(id)
}

/// `sync_wait` 的返回形状（区分"已切走"与"正常返回值"，供 syscall 分发层收尾）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWaitResult {
    /// 非阻塞返回：携带当前值。
    Done(u64),
    /// 已阻塞并切走：`*frame` 是下一进程现场，调用方必须回 `DispatchResult::Switched`。
    Switched,
    /// 无可切换就绪同伴 / 登记被拒：如实 `WouldBlock`。
    WouldBlock,
    /// 对象不存在。
    NotFound,
    /// 超时越界。
    InvalidParam,
}

/// `sync_wait(id, expected, timeout_ns, frame)`（SYS_SYNC_WAIT / 0x72，可阻塞）。
///
/// 原子检查当前值：若 `!= expected` → 立即返回当前值（非阻塞）。若 `== expected` →
/// 把本 pid 登记进等待者队列并阻塞，直到被 `sync_wake` 唤醒（预置 rax 为新值）或
/// 超时（预置 rax 为 expected）。lost-wakeup 闭合同 pipe：登记点在调度锁内持表锁复检。
pub fn sync_wait(frame_ptr: usize, id: u64, expected: u64, timeout_ns: u64) -> SyncWaitResult {
    if timeout_ns > SYNC_MAX_WAIT_TIMEOUT_NS {
        return SyncWaitResult::InvalidParam;
    }
    let cur_pid = current_pid();
    // 阻塞要求有可切换的就绪同伴；无则如实拒绝（同 `sleep_blocking` 退化）。
    loop {
        // 阶段 1：持表锁读当前值，条件已满足则非阻塞返回。
        let value = {
            let t = SYNC_TABLE.lock();
            match t.get(&id) {
                Some(obj) => obj.value,
                None => return SyncWaitResult::NotFound,
            }
        };
        if value != expected {
            return SyncWaitResult::Done(value);
        }
        // 注册超时定时器（仅 timeout_ns>0 且时钟就绪；表满退化为无超时阻塞）。
        let timer = if timeout_ns > 0 && klib::time::clock_ready() {
            klib::time::set_timeout(timeout_ns, sync_timeout_cb, cur_pid)
        } else {
            None
        };
        // 阶段 2：在调度锁内登记等待者 + 复检值，随后阻塞或重试。
        let mut ready = false;
        let register = &mut || {
            let mut t = SYNC_TABLE.lock();
            match t.get_mut(&id) {
                Some(obj) => {
                    if obj.value != expected {
                        ready = true;
                        false
                    } else if obj.waiters.iter().any(|w| w.pid == cur_pid) {
                        false
                    } else {
                        obj.waiters.push(SyncWaiter {
                            pid: cur_pid,
                            expected,
                            timer: timer.unwrap_or(0),
                        });
                        true
                    }
                }
                None => false, // 对象已销毁
            }
        };
        match block_with_registration(frame_ptr, &mut *register) {
            BlockOutcome::Switched => return SyncWaitResult::Switched,
            BlockOutcome::Refused => {
                if let Some(t) = timer {
                    let _ = klib::time::cancel_timeout(t);
                }
                if ready {
                    continue;
                }
                return SyncWaitResult::WouldBlock;
            }
        }
    }
}

/// `sync_wake(id, value, n) -> (woken, removed)`（SYS_SYNC_WAKE / 0x73）。
///
/// 持表锁设 `value`，把 `waiters` 前 `n` 个弹出并返回（供调用方在锁外逐个带值唤醒）。
/// `n == 0` → 仅改值不唤醒。返回 `(实际唤醒数, 被移除的等待者)`。
/// 调用方必须在表锁外对每个 `removed` 调用 [`wake_proc_with_value`]（锁序纪律）。
pub fn sync_wake(id: u64, value: u64, n: usize) -> Result<(usize, Vec<SyncWaiter>), Error> {
    // S31 边界：bit63 置位的值会被误读为负 errno（S09 数据链路）。
    if value & (1 << 63) != 0 {
        return Err(Error::InvalidParam);
    }
    let removed: Vec<SyncWaiter> = {
        let mut t = SYNC_TABLE.lock();
        let Some(obj) = t.get_mut(&id) else {
            return Err(Error::NotFound);
        };
        obj.value = value;
        let take = core::cmp::min(n, obj.waiters.len());
        obj.waiters.drain(..take).collect()
    };
    let cnt = removed.len();
    klib::info!("[ipc/sync] wake id={} value={:#x} -> {} process(es)", id, value, cnt);
    Ok((cnt, removed))
}

/// `sync_delete(id)`（SYS_SYNC_DELETE / 0x74）。
///
/// 对象不存在 → `NotFound`；仍有阻塞等待者 → `Busy`；否则释放一份 ref，refs 归零
/// 才真正从表移除（ADR-032 §4.4，同 shm_destroy 的 refs 归零语义）。
pub fn sync_delete(id: u64) -> Result<(), Error> {
    let mut t = SYNC_TABLE.lock();
    let Some(obj) = t.get_mut(&id) else {
        return Err(Error::NotFound);
    };
    if !obj.waiters.is_empty() {
        return Err(Error::Busy);
    }
    obj.refs = obj.refs.saturating_sub(1);
    if obj.refs == 0 {
        t.remove(&id);
    }
    klib::info!("[ipc/sync] delete id={} refs={}", id, obj_refs(&t, &id));
    Ok(())
}

/// 进程退出兜底清理（S18）：释放进程持有的同步字资源。
///
/// 1. 移除该 pid 在所有同步字上的等待者条目（其正阻塞则退出即失效，且须取消其
///    超时定时器，避免悬挂回调）；
/// 2. 释放该 pid 作为创建者（owner）持有的那份 ref；refs 归零且无等待者即从表移除。
/// 在 task 的进程终止路径调用（`terminate_locked`）。
pub fn sync_release_process(pid: usize) {
    let mut to_cancel: Vec<u64> = Vec::new();
    let mut to_remove: Vec<u64> = Vec::new();
    {
        let mut t = SYNC_TABLE.lock();
        for (&id, obj) in t.iter_mut() {
            obj.waiters.retain(|w| {
                if w.pid == pid {
                    if w.timer != 0 {
                        to_cancel.push(w.timer);
                    }
                    false
                } else {
                    true
                }
            });
            if obj.owner == pid {
                obj.refs = obj.refs.saturating_sub(1);
            }
            if obj.refs == 0 && obj.waiters.is_empty() {
                to_remove.push(id);
            }
        }
        for id in &to_remove {
            t.remove(id);
        }
    }
    for tm in to_cancel {
        let _ = klib::time::cancel_timeout(tm);
    }
}

/// 同步字等待的超时唤醒回调（`klib::time::set_timeout` 回调，等待端注册）。
///
/// 在表中查找本 pid 的等待者条目并移除，捕获其 `expected`，再带值唤醒（超时返回原值，
/// 调用方见值未变即知超时）。O2 竞争消解同 `wake_event_timeout`：与 `sync_wake` 对
/// `saved.rax` 竞争时由 `wake_process_with_value` 的 `state == Blocked` 检查保证先到者胜。
fn sync_timeout_cb(pid: usize) {
    let expected = {
        let mut t = SYNC_TABLE.lock();
        let mut found = None;
        for (_, obj) in t.iter_mut() {
            if let Some(idx) = obj.waiters.iter().position(|w| w.pid == pid) {
                found = Some(obj.waiters.remove(idx).expected);
                break;
            }
        }
        found
    };
    if let Some(expected) = expected {
        wake_proc_with_value(pid, expected);
    }
}

fn current_pid() -> usize {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.current_pid()
    } else {
        0
    }
}

/// 仅在**真正阻塞/切换路径**解引用 `frame_ptr`（S21 契约：非切换路径不读 arch_frame）。
/// `frame_ptr` 是架构层填充的 `&mut InterruptFrame` 地址（来自 kernel 的 `SyscallFrame.arch_frame`）；
/// 非阻塞快路径永不触达这里，故调用方可用 0/无效值安全通过。
fn block_with_registration(frame_ptr: usize, register: &mut dyn FnMut() -> bool) -> BlockOutcome {
    if let Some(notifier) = *NOTIFIER.lock() {
        let frame = unsafe { &mut *(frame_ptr as *mut InterruptFrame) };
        notifier.block_with_registration(frame, register)
    } else {
        BlockOutcome::Refused
    }
}

fn obj_refs(t: &BTreeMap<u64, SyncObject>, id: &u64) -> usize {
    t.get(id).map(|o| o.refs).unwrap_or(0)
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：向同步字 `id` 登记一个**已阻塞**的等待者（模拟该 pid 已阻塞在此字上）。
pub fn debug_sync_add_waiter(sync_id: u64, pid: usize, expected: u64) -> bool {
    let mut t = SYNC_TABLE.lock();
    match t.get_mut(&sync_id) {
        Some(obj) => {
            if obj.waiters.iter().any(|w| w.pid == pid) {
                false
            } else {
                obj.waiters.push(SyncWaiter {
                    pid,
                    expected,
                    timer: 0,
                });
                true
            }
        }
        None => false,
    }
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：返回同步字 `id` 的当前值（None = 不存在）。
pub fn debug_sync_value(sync_id: u64) -> Option<u64> {
    SYNC_TABLE.lock().get(&sync_id).map(|o| o.value)
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：返回同步字 `id` 的等待者数量（None = 不存在）。
pub fn debug_sync_waiter_count(sync_id: u64) -> Option<usize> {
    SYNC_TABLE.lock().get(&sync_id).map(|o| o.waiters.len())
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：返回同步字 `id` 的 refs（None = 不存在）。
pub fn debug_sync_refs(sync_id: u64) -> Option<usize> {
    SYNC_TABLE.lock().get(&sync_id).map(|o| o.refs)
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：同步字 `id` 是否在册。
pub fn debug_sync_exists(sync_id: u64) -> bool {
    SYNC_TABLE.lock().contains_key(&sync_id)
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：清空同步字对象表（用例间清场）。
pub fn debug_sync_reset() {
    SYNC_TABLE.lock().clear();
}
