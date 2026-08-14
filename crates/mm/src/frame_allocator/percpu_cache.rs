use core::cell::UnsafeCell;
use spin::Mutex;

use super::allocator_core::MAX_CPUS;

pub(crate) struct PerCpuCache {
    pub(crate) heads: [Option<usize>; super::allocator_core::MAX_ORDER],
    pub(crate) counts: [u16; super::allocator_core::MAX_ORDER],
}

impl PerCpuCache {
    pub(crate) const fn new() -> Self {
        Self {
            heads: [None; super::allocator_core::MAX_ORDER],
            counts: [0; super::allocator_core::MAX_ORDER],
        }
    }
}

pub(crate) struct PerCpuCacheSet {
    inner: UnsafeCell<[PerCpuCache; MAX_CPUS]>,
}

unsafe impl Sync for PerCpuCacheSet {}

impl PerCpuCacheSet {
    pub(crate) const fn new() -> Self {
        Self {
            inner: UnsafeCell::new([const { PerCpuCache::new() }; MAX_CPUS]),
        }
    }

    pub(crate) fn with_cache<F, R>(&self, cpu: usize, f: F) -> R
    where
        F: FnOnce(&mut PerCpuCache) -> R,
    {
        let cpu = cpu % MAX_CPUS;
        unsafe { f(&mut (*self.inner.get())[cpu]) }
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
