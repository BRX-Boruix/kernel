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

/// 锁表键：**稳定文件身份** + owner uid。
///
/// # 为什么不是 inode 的指针地址（原实现，已修）
///
/// 原实现用 `Arc::as_ptr(inode)` 当文件身份，即**内存布局的副产物**。这有两个
/// 致命问题：
///
/// 1. **同一文件可能有两个身份**。RamFS 的 `lookup` 返回子节点表里缓存的同一个
///    `Arc`（地址相同），而 EXT2 的 `lookup` 每次都 `Arc::new(Ext2Node { .. })`
///    （地址不同）。于是安装模式（根 = EXT2）下两次 `open` 同一文件得到两个键，
///    锁互不可见——**互斥静默失效**，`flock` 照样返回成功。
/// 2. **不同文件可能撞成同一个身份**。堆块释放后地址会被下一个 `Arc` 复用，
///    于是新建文件凭空继承已删除文件的锁记录（实测：`test_flock_syscall`
///    正是被前一个用例的残留锁以这种方式污染）。
///
/// 现在身份由文件系统自己提供（[`INode::stable_id`]）：EXT2 用盘上 `ino`，
/// RamFS 用构造时分配的不复用单调 id。键不再依赖内存布局。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LockKey {
    inode_id: u64,
    owner_uid: u32,
}

/// 锁记录。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LockRecord {
    mode: LockMode,
}

/// 全局 flock 锁表。
static LOCK_TABLE: IrqSpinLock<BTreeMap<LockKey, LockRecord>> = IrqSpinLock::new(BTreeMap::new());

/// 取 inode 的**稳定文件身份**（转调 [`INode::stable_id`]）。
///
/// 保留这个单行包装是为了让"锁身份从哪来"在锁表这一侧**只有一个定义点**
///（S15）——将来若身份模型再演进，只需改这里。
fn inode_key(inode: &Arc<dyn INode>) -> u64 {
    inode.stable_id()
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
        inode_id: inode_key(inode),
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
            if other_key.inode_id == key.inode_id && other_key.owner_uid != key.owner_uid {
                return Err(Error::Busy);
            }
        }
        table.get_mut(&key).unwrap().mode = mode;
        return Ok(());
    }
    // 新锁：冲突矩阵。
    for (other_key, rec) in table.iter() {
        if other_key.inode_id != key.inode_id {
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
        inode_id: inode_key(inode),
        owner_uid: owner.uid,
    };
    LOCK_TABLE.lock().remove(&key);
}

/// 释放某 uid 持有的全部锁（进程退出兜底清理）。
pub fn flock_release_all_for_owner(uid: u32) {
    LOCK_TABLE.lock().retain(|k, _| k.owner_uid != uid);
}
