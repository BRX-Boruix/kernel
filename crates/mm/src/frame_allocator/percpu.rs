//! per-CPU 页帧缓存。
//!
//! 维护每 CPU 的空闲链表：局部分配/释放、超过阈值的回填(排空)，
//! 以及从全局链表/uninit 区域批量 refill 到 per-CPU 缓存。

use core::sync::atomic::Ordering;

use super::allocator_core::FrameState;
use super::{LazyBuddyAllocator, PER_CPU};

impl LazyBuddyAllocator {
    fn per_cpu_limit(order: usize) -> u16 {
        match order {
            0..=1 => 64,
            2..=4 => 32,
            5..=8 => 16,
            9..=12 => 8,
            13..=16 => 4,
            _ => 2,
        }
    }

    fn per_cpu_batch(order: usize) -> u16 {
        let limit = Self::per_cpu_limit(order);
        if limit > 8 {
            8
        } else {
            limit
        }
    }

    pub(crate) fn percpu_pop_raw(&self, cpu: usize, order: usize) -> Option<usize> {
        PER_CPU.with_cache(cpu, |cache| {
            if let Some(head) = cache.heads[order] {
                unsafe {
                    let frame = self.frame_ptr(head);
                    cache.heads[order] = (*frame).next;
                    cache.counts[order] = cache.counts[order].saturating_sub(1);
                    self.reset_frame_with(frame, order as u8);
                }
                return Some(head);
            }
            None
        })
    }

    pub(crate) fn percpu_pop(&self, cpu: usize, order: usize) -> Option<usize> {
        let res = self.percpu_pop_raw(cpu, order);
        if res.is_some() {
            self.alloc_hit_percpu.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    fn percpu_push_raw(&self, cpu: usize, pfn: usize, order: usize) {
        PER_CPU.with_cache(cpu, |cache| {
            unsafe {
                self.link_frame_as(pfn, order as u8, FrameState::FreePerCpu, cache.heads[order]);
            }
            cache.heads[order] = Some(pfn);
            cache.counts[order] = cache.counts[order].saturating_add(1);
        });
    }

    pub(crate) fn percpu_push(&self, cpu: usize, pfn: usize, order: usize) {
        self.percpu_push_raw(cpu, pfn, order);
        let limit = Self::per_cpu_limit(order);
        let mut to_drain: u16 = 0;
        PER_CPU.with_cache(cpu, |cache| {
            if cache.counts[order] > limit {
                to_drain = cache.counts[order] - limit;
            }
        });
        while to_drain > 0 {
            if let Some(drained) = self.percpu_pop_raw(cpu, order) {
                self.free_and_merge(drained, order);
            } else {
                break;
            }
            to_drain -= 1;
        }
    }

    pub(crate) fn percpu_refill(&self, cpu: usize, order: usize) -> Option<usize> {
        let batch = Self::per_cpu_batch(order);
        let mut first: Option<usize> = None;
        for _ in 0..batch {
            if let Some(pfn) = self.alloc_global(order, cpu) {
                if first.is_none() {
                    first = Some(pfn);
                } else {
                    self.percpu_push_raw(cpu, pfn, order);
                }
            } else {
                break;
            }
        }
        if first.is_some() {
            self.alloc_refill.fetch_add(1, Ordering::Relaxed);
        }
        first
    }

    pub(crate) fn alloc_global(&self, order: usize, cpu: usize) -> Option<usize> {
        if let Some(idx) = self.alloc_from_list(order, cpu) {
            return Some(idx);
        }
        if let Some(idx) = self.alloc_from_uninit(order) {
            self.alloc_hit_uninit.fetch_add(1, Ordering::Relaxed);
            unsafe {
                self.reset_frame(idx, order as u8);
            }
            return Some(idx);
        }
        None
    }
}
