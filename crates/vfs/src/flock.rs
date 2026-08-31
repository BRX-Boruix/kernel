//! R6 flock 文件锁（ADR-014 STREAM_CLOSE 自动释放承诺）。
//!
//! ## 模型（todo.md D-VFS1-R6 设计草案 + ADR-033 身份模型）
//!
//! - owner：LockOwner { uid }，取自 A1 的 ProcessIdentity.uid（唯一事实来源）。
//!   同一 uid 的进程共享锁语义（flock 按打开者的身份，而非 pid）。
//! - 锁表：IrqSpinLock<BTreeMap<LockKey, LockRecord>>，与 ipc 的 shm/pipe/sync 同款手法。
//! - advisory：不阻断无锁读写——read_at/write_at 不查锁表；只有显式 flock_lock 才登记锁。
//!   冲突时返回 Error::Busy（不阻塞，调用方决定重试/放弃）。
//! - close 自动释放：flock_unlock 由 Process::close_fd 钩子在关闭某文件 fd 时调用，
//!   释放该 owner 在该 inode 上的锁——兑现 ADR-014 STREAM_CLOSE 承诺。
//!
//! ## 冲突矩阵（acceptance 1）
//!
//! 同 owner 重锁幂等（re-lock 不冲突）；异 owner 按冲突矩阵判定。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

use crate::inode::INode;

/// flock owner：A1 身份模型的 uid（ProcessIdentity.uid 的拷贝）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockOwner {
    pub uid: u32,
}

/// 锁模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    /// 共享锁（读锁）：与其他 Shared 兼容，与 Exclusive 冲突。
    Shared,
    /// 独占锁（写锁）：与任何锁冲突。
    Exclusive,
}

/// 锁表键：inode 指针身份 + owner uid。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LockKey {
    inode_addr: usize,
    owner_uid: u32,
}

/// 锁记录。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LockRecord {
    mode: LockMode,
}

/// 全局 flock 锁表。
static LOCK_TABLE: IrqSpinLock<BTreeMap<LockKey, LockRecord>> = IrqSpinLock::new(BTreeMap::new());

/// 取 inode 指针身份（Arc 稳定地址）。
fn inode_key(inode: &Arc<dyn INode>) -> usize {
    // dyn 胖指针先收窄为瘦指针再取地址（Rust 禁止直接 cast fat->usize）。
    Arc::as_ptr(inode) as *const () as usize
}

/// 获取锁（advisory）。冲突返回 Err(Error::Busy)。
///
/// - 同 owner 已持锁：
///   - 同模式 → 幂等 Ok；降级（Exclusive→Shared）→ 恒 Ok（降级不产生冲突）。
///   - 升级（Shared→Exclusive）→ 须先检查其他 owner 是否仍持锁；有则 Err(Busy)
///     （否则 Exclusive 会与其他 owner 的 Shared 并存，破坏互斥——K2）。
/// - 新锁（无同 owner 记录）→ 按冲突矩阵判：Exclusive 与任何锁冲突；Shared 与 Exclusive 冲突。
pub fn flock_lock(
    inode: &Arc<dyn INode>,
    owner: LockOwner,
    exclusive: bool,
) -> Result<(), Error> {
    let mode = if exclusive { LockMode::Exclusive } else { LockMode::Shared };
    let key = LockKey {
        inode_addr: inode_key(inode),
        owner_uid: owner.uid,
    };
    let mut table = LOCK_TABLE.lock();
    // 同 owner 已持锁：用不可变读确定升级/降级，避免持可变借用时再迭代表。
    if let Some(cur_mode) = table.get(&key).map(|r| r.mode) {
        if cur_mode == mode {
            return Ok(()); // 幂等
        }
        if mode == LockMode::Shared {
            // 降级（Exclusive→Shared）：任何冲突都不存在，直接成功。
            table.get_mut(&key).unwrap().mode = mode;
            return Ok(());
        }
        // 升级（Shared→Exclusive）：若有其他 owner 持此 inode 锁则拒绝（K2），
        // 否则 Exclusive 会与其他 owner 的 Shared 并存，破坏互斥。
        for (other_key, _) in table.iter() {
            if other_key.inode_addr == key.inode_addr && other_key.owner_uid != key.owner_uid {
                return Err(Error::Busy);
            }
        }
        table.get_mut(&key).unwrap().mode = mode;
        return Ok(());
    }
    // 新锁：冲突矩阵。
    for (other_key, rec) in table.iter() {
        if other_key.inode_addr != key.inode_addr {
            continue;
        }
        if other_key.owner_uid == key.owner_uid {
            continue;
        }
        if mode == LockMode::Exclusive || rec.mode == LockMode::Exclusive {
            return Err(Error::Busy);
        }
    }
    table.insert(key, LockRecord { mode });
    Ok(())
}

/// 释放该 owner 在该 inode 上的锁（close_fd 钩子调用）。幂等。
pub fn flock_unlock(inode: &Arc<dyn INode>, owner: LockOwner) {
    let key = LockKey {
        inode_addr: inode_key(inode),
        owner_uid: owner.uid,
    };
    LOCK_TABLE.lock().remove(&key);
}

/// 释放某 uid 持有的全部锁（进程退出兜底清理）。
pub fn flock_release_all_for_owner(uid: u32) {
    LOCK_TABLE.lock().retain(|k, _| k.owner_uid != uid);
}
