//! 内核堆分配器（基于虚拟内存的按需映射动态堆）。
//!
//! 基于 `buddy_system_allocator::Heap`：
//! - 堆耗尽（OOM）时自动调用增长逻辑，通过注入的物理帧分配器分配新的连续
//!   物理页、映射为虚拟地址，再 `add_to_heap` 增长堆。
//! - 早期（物理帧分配器就绪前）使用一块较小的静态引导堆保证基本分配安全；
//!   物理帧分配器就绪后，堆可无限按需增长，不再受固定 4MB 限制。
//!
//! 增长源（物理帧分配器）由内核在 `mm::init()` 后注入，因为 `klib` 是底层
//! crate，不依赖 `arch`/`mm`，故通过函数指针在运行时注入。

use buddy_system_allocator::Heap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 早期静态引导堆大小（物理帧分配器就绪前使用，够 flanterm 初始化与早期内核）。
const BOOT_HEAP_SIZE: usize = 1024 * 1024; // 1MB

/// 引导堆存储 wrapper（提供内部可变性并标记 Sync）。
struct BootHeapStorage(UnsafeCell<[u8; BOOT_HEAP_SIZE]>);
unsafe impl Sync for BootHeapStorage {}

/// 静态引导堆存储。
static BOOT_HEAP: BootHeapStorage = BootHeapStorage(UnsafeCell::new([0; BOOT_HEAP_SIZE]));

/// 堆增长源：`fn(order: u32) -> u64`。
///
/// 返回 `2^order` 个连续物理页**映射后的虚拟地址基址**（可直接读写），
/// 失败返回 0。由内核注入（内部调用物理帧分配器 + `phys_to_virt`）。
static GROW_ALLOC: AtomicUsize = AtomicUsize::new(0);

/// 注入堆增长源（内核在物理帧分配器就绪后调用）。
pub fn set_grow_allocator(f: fn(u32) -> u64) {
    GROW_ALLOC.store(f as usize, Ordering::SeqCst);
}

use crate::sync::spin::SpinMutex;

/// 全局堆：内部持有 buddy `Heap`，OOM 时按需增长。
struct KernelHeap {
    inner: SpinMutex<Heap<32>>,
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = self.inner.lock();
        // 首次尝试
        if let Ok(non_null) = heap.alloc(layout) {
            return non_null.as_ptr();
        }
        // OOM：反复增长并重试，直到成功或确认无法再增长。
        // 单次增长基于 layout 所需字节取最小能装下的 order，通常一次即够；
        // 极端情况下（如分配器内部碎片）多试几次可提高命中率。
        for _ in 0..8 {
            if grow_heap(&mut heap, &layout) {
                if let Ok(non_null) = heap.alloc(layout) {
                    return non_null.as_ptr();
                }
            } else {
                break; // 无法再增长（物理内存耗尽 / 增长源未注入）
            }
        }
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut heap = self.inner.lock();
        unsafe { heap.dealloc(core::ptr::NonNull::new_unchecked(ptr), layout) };
    }
}

/// 全局堆分配器（OOM 时自动按需增长）。
#[global_allocator]
static HEAP_ALLOCATOR: KernelHeap = KernelHeap {
    inner: SpinMutex::new(Heap::empty()),
};

/// 堆增长：当 buddy 堆 OOM 时，按需从物理帧分配器取页并加入堆。
/// 返回是否成功新增了堆内存（false 表示物理内存耗尽或增长源未注入）。
fn grow_heap(heap: &mut Heap<32>, layout: &Layout) -> bool {
    let f = GROW_ALLOC.load(Ordering::SeqCst);
    if f == 0 {
        return false; // 增长源未注入：无能为力
    }
    let alloc_fn: fn(u32) -> u64 = unsafe { core::mem::transmute(f) };

    // 需要多少字节（至少一页，向上取整到页）
    let need = layout.size().max(4096);
    let pages = need.div_ceil(4096);
    // 找一个能装下 pages 页的最小 order（2^order 页）。
    // 不再 clamp：物理帧分配器本身支持大 order，单次增长就能满足任意大小的
    // 连续需求（受限仅在于物理内存是否足够），避免一次性大分配反复失败。
    // 为减少碎片并提高命中率，额外放宽到能容纳 pages 的 2 倍（若 order 允许）。
    let mut order: u32 = if pages <= 1 {
        0
    } else {
        usize::BITS as u32 - 1 - (pages - 1).leading_zeros()
    };
    // 放宽一级以获得更大的连续块（降低碎片），但保持 32 位安全上限
    if order < 31 {
        order += 1;
    }

    let base = alloc_fn(order);
    if base == 0 {
        return false;
    }
    let bytes = (1usize << order) * 4096;
    // 把新页加入堆（buddy 内部切块管理，支持多次 add_to_heap 添加非连续区域）
    unsafe { heap.add_to_heap(base as usize, base as usize + bytes) };
    true
}

/// 初始化堆：加入静态引导区，保证物理帧分配器就绪前的基本分配安全。
///
/// 必须在任何堆分配发生前调用（kernel 入口早期）。
pub fn init() {
    let start = BOOT_HEAP.0.get() as usize;
    unsafe {
        HEAP_ALLOCATOR
            .inner
            .lock()
            .add_to_heap(start, start + BOOT_HEAP_SIZE);
    }
}
