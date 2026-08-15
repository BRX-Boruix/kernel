//! 空闲页压缩。
//!
//! 排空 per-CPU 缓存中的空闲页回收到全局 buddy 系统，从而合并出更大的连续块。

use core::sync::atomic::Ordering;

use klib::logln;

use super::allocator_core::{for_each_global_list, MAX_CPUS, MAX_ORDER};
use super::{ALLOCATOR, LazyBuddyAllocator, PER_CPU};

impl LazyBuddyAllocator {
    fn drain_percpu_all(&self) -> usize {
        let mut drained = 0usize;
        for cpu in 0..MAX_CPUS {
            for order in 0..MAX_ORDER {
                loop {
                    let pfn = self.percpu_pop_raw(cpu, order);
                    if let Some(pfn) = pfn {
                        self.free_and_merge(pfn, order);
                        drained = drained.saturating_add(1);
                    } else {
                        break;
                    }
                }
            }
        }
        drained
    }

    pub(crate) fn max_free_order(&self) -> usize {
        let mut free_global = [0usize; MAX_ORDER];
        for_each_global_list(|order, _shard, list| {
            let mut cur = list.head;
            while let Some(pfn) = cur {
                free_global[order] += 1;
                unsafe {
                    let frame = self.get_frame(pfn);
                    cur = frame.next;
                }
            }
        });
        let mut free_percpu = [0usize; MAX_ORDER];
        for cpu in 0..MAX_CPUS {
            PER_CPU.with_cache(cpu, |cache| {
                for order in 0..MAX_ORDER {
                    free_percpu[order] += cache.counts[order] as usize;
                }
            });
        }
        for order in (0..MAX_ORDER).rev() {
            if free_global[order] + free_percpu[order] > 0 {
                return order;
            }
        }
        0
    }

    pub(crate) fn compact(&self) {
        let before = self.max_free_order();
        self.compact_calls.fetch_add(1, Ordering::Relaxed);
        let drained = self.drain_percpu_all();
        self.compact_drained.fetch_add(drained, Ordering::Relaxed);
        let after = self.max_free_order();
        self.compact_last_before.store(before, Ordering::Relaxed);
        self.compact_last_after.store(after, Ordering::Relaxed);
        if after > before {
            self.compact_success.fetch_add(1, Ordering::Relaxed);
        }
        logln!("PMM: WARNING compact triggered drained={}", drained);
    }
}

pub fn compact_now() {
    ALLOCATOR.compact();
}
