use spin::{Mutex, Once};

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
        Self { caches: Once::new() }
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
        let cpu = cpu % caches.len(); // 防御性取模
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
    pub(crate) shards: [Mutex<FreeList>; super::allocator_core::SHARD_COUNT],
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
        let shards = core::array::from_fn(|_| Mutex::new(FreeList::new()));
        Self { shards }
    }
}

impl FreeListTable {
    pub(crate) fn new() -> Self {
        let orders = core::array::from_fn(|_| FreeListShards::new());
        Self { orders }
    }
}
