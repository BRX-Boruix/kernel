//! 简单的 boot 堆分配器（bump allocator）。
//!
//! M0 阶段先提供一个最简堆，供 flanterm 的 `alloc`（Box/Vec）使用。
//! 不回收内存（引导阶段 flanterm 几乎不释放），后续用 ADR-009 的 lazybuddy 替换。

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 堆大小（4MB，供 flanterm 初始化使用；M0 阶段静态分配）
const HEAP_SIZE: usize = 4 * 1024 * 1024;
const HEAP_ALIGN: usize = 16;

/// bump 分配器的当前偏移
static OFFSET: AtomicUsize = AtomicUsize::new(0);

/// 堆存储 wrapper（提供内部可变性并标记 Sync）
struct HeapStorage(UnsafeCell<[u8; HEAP_SIZE]>);
unsafe impl Sync for HeapStorage {}

/// 静态堆存储
static HEAP: HeapStorage = HeapStorage(UnsafeCell::new([0; HEAP_SIZE]));

/// Boot 堆分配器（bump，不回收）
pub struct BootAllocator;

unsafe impl Sync for BootAllocator {}

impl BootAllocator {
    fn heap_ptr(&self) -> *mut u8 {
        HEAP.0.get() as *mut u8
    }
}

unsafe impl GlobalAlloc for BootAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(HEAP_ALIGN);
        let size = layout.size();

        // 对齐偏移
        let offset = OFFSET.load(Ordering::SeqCst);
        let aligned = (offset + align - 1) & !(align - 1);

        if aligned + size > HEAP_SIZE {
            // 堆耗尽
            return core::ptr::null_mut();
        }

        // 原子更新偏移
        OFFSET.store(aligned + size, Ordering::SeqCst);

        unsafe { self.heap_ptr().add(aligned) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump 分配器不回收（简化）；后续 lazybuddy 接管
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BootAllocator = BootAllocator;
