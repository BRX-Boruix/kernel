use spin::Once;

use super::allocator_core::MAX_ORDER;

pub(crate) struct PerCpuCache {
    pub(crate) heads: [Option<usize>; MAX_ORDER],
    pub(crate) counts: [u16; MAX_ORDER],
}

impl PerCpuCache {
    pub(crate) const fn new() -> Self {
        Self {
            heads: [None; MAX_ORDER],
            counts: [0; MAX_ORDER],
        }
    }
}

/// per-CPU 缓存集合，按实际 CPU 数动态分配（自适应核数）。
/// 数组按紧凑 CPU 槽位（0..n）索引，槽位由 SMP 子系统分配并提供。
pub(crate) struct PerCpuCacheSet {
    caches: Once<&'static [PerCpuCache]>,
}

unsafe impl Sync for PerCpuCacheSet {}

impl PerCpuCacheSet {
    pub(crate) const fn new() -> Self {
        Self {
            caches: Once::new(),
        }
    }

    /// 依据实际 CPU 数初始化缓存数组（由内核注入 CPU 数后调用一次）。
    pub(crate) fn init(&self, caches: &'static [PerCpuCache]) {
        let _ = self.caches.call_once(|| caches);
    }

    /// 当前已初始化的 CPU 数（0 表示未初始化）。
    pub(crate) fn cpu_count(&self) -> usize {
        self.caches.get().map(|c| c.len()).unwrap_or(0)
    }

    /// 取 `cpu` 槽位的 per-CPU 缓存并施加 `f`。
    ///
    /// # 属主不变式（SMP 审计 S5）
    ///
    /// **`cpu` 必须是调用方自己的槽位**（即 `current_cpu_id()` 的结果）。
    ///
    /// 为什么这不只是约定：`PerCpuCache` 是裸结构体、**完全无同步**
    /// （`heads: [Option<usize>; MAX_ORDER]` / `counts: [u16; MAX_ORDER]` 都是
    /// 普通字段）。它的正确性**只**建立在「每个 CPU 独占访问自己的槽位」之上。
    /// 一旦有调用方传入别人的槽位，两个 CPU 会无锁并发改写同一组字段——
    /// 表现为帧链表被写坏、同一帧被发两次或永久丢失，且**没有任何症状能指向
    /// 这里**（损坏发生在若干次分配之后）。
    ///
    /// 当前所有调用方都传 `current_cpu_id()`（api/compact/percpu/stats 共 7 处），
    /// 故不是活跃缺陷；但该不变式此前**只存在于注释里**，一次误写即可静默破坏
    /// 内存管理。此断言把不变式变成机器可检查的事实（S21 并发显式化）。
    ///
    /// 限制：断言只在 `debug_assertions` 下生效（release 构建零开销）。
    /// 这是刻意的——release 下每次分配多读一次 LAPIC 不可接受；而越界与属主
    /// 违规都是**开发期**缺陷，自检构建（`--test`）即可全部暴露。
    pub(crate) fn with_cache<F, R>(&self, cpu: usize, f: F) -> R
    where
        F: FnOnce(&mut PerCpuCache) -> R,
    {
        let caches = self.caches.get().expect("per-CPU caches not initialized");
        // S19：cpu 越界是调用方 bug——防御性取模会把越界 cpu 静默映射到合法槽位，
        // 掩盖 bug 且让两个 CPU 共享同槽（数据竞争）；caches.len()==0 时 %0 还会
        // panic。改显式越界 panic（不可恢复的调用方缺陷），不静默错位。
        if cpu >= caches.len() {
            panic!("per-CPU slot out of range: {} >= {}", cpu, caches.len());
        }
        // S5：属主不变式——见上方文档。
        debug_assert_eq!(
            cpu,
            super::current_cpu_id(),
            "per-CPU cache may only be touched by its owning CPU (slot {} asked, caller owns {})",
            cpu,
            super::current_cpu_id()
        );
        unsafe { f(&mut *(caches.as_ptr().add(cpu) as *mut PerCpuCache)) }
    }
}

pub(crate) struct FreeList {
    pub(crate) head: Option<usize>,
}

impl FreeList {
    pub(crate) fn new() -> Self {
        Self { head: None }
    }
}

pub(crate) struct FreeListShards {
    /// 分片链表锁必须**中断安全**（审计 #5）：跨核排空 IPI 在目标核的
    /// 中断上下文里取这些锁合并空闲帧；若为普通 Mutex，目标核进程上下文
    /// 持任一分片锁瞬间被 IPI 打断即自旋等自己被抢占上下文的锁——该核
    /// 永久硬挂。IrqSpinLock 令持锁期间 IF=0，IPI 只能等锁释放后再入。
    pub(crate) shards: [klib::sync::irq::IrqSpinLock<FreeList>; super::allocator_core::SHARD_COUNT],
}

pub(crate) struct FreeListTable {
    pub(crate) orders: [FreeListShards; super::allocator_core::MAX_ORDER],
}

pub(crate) struct ReserveList {
    pub(crate) head: Option<usize>,
}

impl ReserveList {
    pub(crate) const fn new() -> Self {
        Self { head: None }
    }
}

impl FreeListShards {
    pub(crate) fn new() -> Self {
        let shards = core::array::from_fn(|_| klib::sync::irq::IrqSpinLock::new(FreeList::new()));
        Self { shards }
    }
}

impl FreeListTable {
    pub(crate) fn new() -> Self {
        let orders = core::array::from_fn(|_| FreeListShards::new());
        Self { orders }
    }
}
