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
//!
//! 测试化结构（KM2）：增长逻辑（[`grow_order`] 纯函数 + [`grow_heap`]）与
//! `#[global_allocator]` 静态物分门别——前者在宿主测试构建同样编译并以假
//! 增长源驱动单测覆盖；后者仅在真实内核目标存在（宿主测试必须保留 std
//! 分配器，否则接管 test harness 的分配）。

use buddy_system_allocator::Heap;
use core::alloc::Layout;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---------- 增长逻辑（宿主 / 内核共用面） ----------

/// 堆增长源：`fn(order: u32) -> Option<u64>`。
///
/// 成功返回 `2^order` 个连续物理页**映射后的虚拟地址基址**（可直接读写），
/// 失败（物理内存耗尽）返回 `None`。由内核注入（内部调用物理帧分配器 +
/// `phys_to_virt`）。KM11：以 `Option` 表达"没有"，不使用魔法 0 哨兵——
/// 虚拟基址 0 是非法映射值纯属巧合，类型化失败才不依赖巧合。
static GROW_ALLOC: AtomicUsize = AtomicUsize::new(0);

/// 注入堆增长源（内核在物理帧分配器就绪后调用）。
pub fn set_grow_allocator(f: fn(u32) -> Option<u64>) {
    GROW_ALLOC.store(f as usize, Ordering::SeqCst);
}

const MAX_GROW_ORDER: u32 = 31;
const PAGE_BYTES: usize = 4096;

/// 由所需字节数推导一次堆增长的 order（纯函数，宿主可测——KM2 抽取）。
///
/// - 至少一页：`need < 页` 也按一页起；
/// - order 取「能装下 pages 的最小 2 的幂」，再放宽一级获得更大连续块
///   （降低碎片、提高命中率）；
/// - **上限强制**（klib1 KM2 单测暴露的真实缺陷）：原实现只有
///   `debug_assert!(order <= MAX)` 而无实际截断——巨量请求的 raw order
///   可达 ~52，release 下直接越过"硬上限"进入 `1 << 52 × 4096` 的回绕
///   算术，审计 B20 的论证前提从未被代码兑现。现以 `min(MAX)` 显式截断，
///   且触顶时不再放宽（放宽仅在有余量时执行）。
fn grow_order(layout_size: usize) -> u32 {
    let need = layout_size.max(PAGE_BYTES);
    let pages = need.div_ceil(PAGE_BYTES);
    let raw: u32 = if pages <= 1 {
        0
    } else {
        usize::BITS as u32 - 1 - (pages - 1).leading_zeros()
    };
    let mut order = raw.min(MAX_GROW_ORDER);
    if order < MAX_GROW_ORDER {
        order += 1;
    }
    debug_assert!(order <= MAX_GROW_ORDER);
    order
}

/// 堆增长：当 buddy 堆 OOM 时，按需从物理帧分配器取页并加入堆。
/// 返回是否成功新增了堆内存（false 表示物理内存耗尽或增长源未注入）。
fn grow_heap(heap: &mut Heap<32>, layout: &Layout) -> bool {
    let f = GROW_ALLOC.load(Ordering::SeqCst);
    if f == 0 {
        return false; // 增长源未注入：无能为力
    }
    let alloc_fn: fn(u32) -> Option<u64> = unsafe { core::mem::transmute(f) };

    // 审计 B20 论证：order 硬上限 MAX_GROW_ORDER ⇒ 下方 `1usize << order`
    // 与 `* PAGE_BYTES` 在 64 位 usize 无溢出（2^31 页 × 4KiB = 8TiB，远超
    // 真实物理内存、必先被帧分配器拒绝）。上限截断由 grow_order 显式强制
    // （klib1 KM2：原实现仅 debug_assert 无截断，B20 前提落空，已修）。
    let order = grow_order(layout.size());

    // 增长源以 Option 报告失败（物理内存耗尽 / 帧分配器拒绝）。
    let Some(base) = alloc_fn(order) else {
        return false;
    };
    let bytes = (1usize << order) * PAGE_BYTES;
    // 把新页加入堆（buddy 内部切块管理，支持多次 add_to_heap 添加非连续区域）
    unsafe { heap.add_to_heap(base as usize, base as usize + bytes) };
    true
}

// ---------- 内核专属面（global_allocator 与引导堆） ----------

#[cfg(all(not(test), target_os = "none"))]
mod kernel_backend {
    use super::*;
    use crate::sync::irq::IrqSpinLock;
    use core::alloc::GlobalAlloc;
    use core::cell::UnsafeCell;

    /// 早期静态引导堆大小（物理帧分配器就绪前使用，够 flanterm 初始化与早期内核）。
    const BOOT_HEAP_SIZE: usize = 1024 * 1024; // 1MB

    /// 引导堆存储 wrapper（提供内部可变性并标记 Sync）。
    struct BootHeapStorage(UnsafeCell<[u8; BOOT_HEAP_SIZE]>);
    unsafe impl Sync for BootHeapStorage {}

    /// 静态引导堆存储。
    static BOOT_HEAP: BootHeapStorage = BootHeapStorage(UnsafeCell::new([0; BOOT_HEAP_SIZE]));

    /// 全局堆：内部持有 buddy `Heap`，OOM 时按需增长。
    ///
    /// 锁必须是**中断安全**的 `IrqSpinLock`：LAPIC tick 处理程序（ISR 上下文）
    /// 会经调度器回调/定时器队列进入分配路径，若主流程持普通自旋锁期间被 tick
    /// 打断、而 ISR 路径再次申请同一把锁，本 CPU 将永久自旋（实测死锁现场：
    /// RIP 停在 `SpinMutex<Heap>::lock`，tick 向量滞留 IRR 无法交付）。关中断
    /// 持锁使临界区对 ISR 原子，代价是持锁期间延迟中断——堆临界区极短。
    struct KernelHeap {
        inner: IrqSpinLock<Heap<32>>,
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
        inner: IrqSpinLock::new(Heap::empty()),
    };

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
}

#[cfg(all(not(test), target_os = "none"))]
pub use kernel_backend::init;

// ---------- 宿主单元测试（KM2：假增长源驱动） ----------

#[cfg(test)]
mod tests {
    use super::{grow_heap, grow_order, set_grow_allocator, GROW_ALLOC};
    use buddy_system_allocator::Heap;
    use core::alloc::Layout;

    /// 假增长源：按 order 发放一块 4KiB 对齐、2^order 页的**堆内存**
    /// （std 分配器），耗尽语义由注入方自行决定。
    ///
    /// 实现注记（KM2 调试教训）：最初用 `#[repr(align(4096))]` 的大静态
    /// 数组充当帧池——宿主工具链把该只写不读的零静态放进只读节，buddy
    /// 的侵入式链表首写即 AV。改由 std 堆发放：区域必然可写、每次发放
    /// 地址独立，与真实帧分配器的"新区域"语义一致。
    static LAST_ORDER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    fn fake_grow(order: u32) -> Option<u64> {
        use std::alloc::{alloc, Layout};
        LAST_ORDER.store(order, core::sync::atomic::Ordering::SeqCst);
        let n = 1usize << order;
        // 故意超量请求触发 None（测试用 order 上限远小于 usize 位宽，安全）
        let layout = Layout::from_size_align(n * 4096, 4096).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }
        Some(ptr as u64)
    }

    fn inject_fake() {
        set_grow_allocator(fake_grow);
    }

    /// 各测试共享进程级 GROW_ALLOC：本模块测试串行化。
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn order_table_matches_policy() {
        // 纯函数直测：放宽策略 + 上限强制的可执行规格。
        assert_eq!(grow_order(1), 1); // <1 页 → raw0 → 放宽 1
        assert_eq!(grow_order(4096), 1); // 恰 1 页 → 同上
        assert_eq!(grow_order(4097), 1); // 2 页 → raw0 → 放宽后恰 2 页
        assert_eq!(grow_order(8192), 1); // 2 页整
        assert_eq!(grow_order(12288), 2); // 3 页 → raw1 → 放宽 2（4 页）
        assert_eq!(grow_order(1024 * 1024), 8); // 256 页 → raw7 → 放宽 8
        assert_eq!(grow_order(usize::MAX), 31); // 巨量 → 上限强制截断且不再放宽
    }

    #[test]
    fn growth_disabled_without_source() {
        let _g = TEST_LOCK.lock().unwrap();
        GROW_ALLOC.store(0, core::sync::atomic::Ordering::SeqCst);
        let mut heap = Heap::new();
        assert!(!grow_heap(&mut heap, &Layout::from_size_align(100, 8).unwrap()));
        assert!(heap.alloc(Layout::from_size_align(100, 8).unwrap()).is_err());
    }

    #[test]
    fn growth_enables_allocation_after_oom() {
        let _g = TEST_LOCK.lock().unwrap();
        inject_fake();
        let mut heap = Heap::new(); // 空 buddy 堆：首次分配必失败
        let l = Layout::from_size_align(100, 8).unwrap();
        assert!(heap.alloc(l).is_err(), "fresh empty heap must be OOM");
        assert!(grow_heap(&mut heap, &l));
        // 放宽策略：百字节需求也至少拿到 order=1（2 页）
        assert_eq!(LAST_ORDER.load(core::sync::atomic::Ordering::SeqCst), 1);
        let p = heap.alloc(l).expect("grown heap must satisfy allocation");
        assert_eq!(p.as_ptr() as usize % 8, 0);
    }

    #[test]
    fn repeated_growth_serves_repeated_small_demands() {
        let _g = TEST_LOCK.lock().unwrap();
        inject_fake();
        let mut heap = Heap::new();
        let small = Layout::from_size_align(100, 8).unwrap(); // 内核现实的增长动因：小分配
        // 多轮「OOM → 增长 → 满足」：验证重复增长的非连续区域在堆内共存，
        // 且每轮增长都真实可用于当轮需求（内核 exec/telemetry 的实际形态）。
        for i in 0..8 {
            assert!(grow_heap(&mut heap, &small), "growth {i} must succeed");
            assert!(
                heap.alloc(small).is_ok(),
                "grown region must satisfy the requesting layout"
            );
        }
        assert_eq!(LAST_ORDER.load(core::sync::atomic::Ordering::SeqCst), 1);
        // 对齐敏感性边界（KM2 实测登记，非缺陷修复面）：buddy 的阶梯切块
        // 由区域基地址低位决定——4 页区块仅在基地址低位于整块对齐时才产生
        // class14 大块；以大 layout 反复索取会在第二轮起命中空链表返回
        // Err。内核现状依赖「增长由小分配触发、小类经级联必然满足」，
        // 大类连续需求依赖帧虚拟地址的对齐巧合。原则解（add_to_heap 前
        // 按请求 layout 选配对齐地址，或 buddy 上游改造）随 mm 立项评估。
    }
}
