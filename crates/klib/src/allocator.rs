//! 内核堆分配器。
//!
//! 基于 `buddy_system_allocator` 的 `LockedHeap`，支持分配与释放（可重用），
//! 替换了早期不回收的 boot bump allocator。
//!
//! 当前用静态数组作为堆存储（暂不依赖虚拟内存映射）；M1 虚拟内存落地后，
//! 可改为按需映射物理页的动态堆。

use buddy_system_allocator::LockedHeap;
use core::cell::UnsafeCell;

/// 堆大小（4MB，够 flanterm 初始化与早期内核使用）
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// 堆存储 wrapper（提供内部可变性并标记 Sync）
struct HeapStorage(UnsafeCell<[u8; HEAP_SIZE]>);
unsafe impl Sync for HeapStorage {}

/// 静态堆存储
static HEAP_SPACE: HeapStorage = HeapStorage(UnsafeCell::new([0; HEAP_SIZE]));

/// 全局堆分配器（buddy，支持释放重用）
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

/// 初始化堆：把静态存储区域交给分配器。
///
/// 必须在任何堆分配发生前调用（kernel 入口早期）。
pub fn init() {
    let start = HEAP_SPACE.0.get() as usize;
    unsafe {
        HEAP_ALLOCATOR.lock().add_to_heap(start, start + HEAP_SIZE);
    }
}
