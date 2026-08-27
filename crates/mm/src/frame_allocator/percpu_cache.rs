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
