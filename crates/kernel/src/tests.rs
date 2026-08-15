//! 内核启动自检测试。
//!
//! 这些测试在内核初始化流程的特定阶段被调用，验证物理页帧分配器、
//! 虚拟内存页表、堆分配器与 LAPIC 时钟中断是否正确工作。
//! 与运行时代码分离，便于单独维护。

use klib::logln;

use arch::{PageFlags, PageSize, PageTable, PhysAddr, PhysFrame, VirtAddr};
use arch_x86_64::paging::X86PageTable;

/// 验证虚拟内存页表：4KB 映射 + 2MB 大页映射 + 真实内存读写（经 HHDM 写入，
/// 再通过 activate 切页表读出）。为安全，激活的页表会先复制当前内核页表的
/// 高半区映射，保证切换后内核/串口仍可访问。
pub fn test_paging() {
    // ---- 1. 4KB 页映射/翻译/解映射（逻辑验证）----
    let mut pt = X86PageTable::new_empty().expect("no page table frame");
    let phys4k = mm::allocate_frame().expect("no 4k frame").start_paddr();
    let vaddr4k = VirtAddr::new(0x0000_0000_4000_0000);
    pt.map(vaddr4k, PhysAddr::new(phys4k), PageSize::Size4K, PageFlags::empty().writable())
        .expect("4k map");
    logln!("[test-paging] 4K: mapped {} -> {}", vaddr4k.as_u64(), phys4k);
    logln!("[test-paging] 4K: translate -> {:#x}", pt.translate(vaddr4k).unwrap().as_u64());
    logln!("[test-paging] 4K: unmap -> {:#x}", pt.unmap(vaddr4k).unwrap().as_u64());
    mm::deallocate_frame(PhysFrame::from_paddr_raw(phys4k));

    // ---- 2. 2MB 大页映射（逻辑验证）----
    let mut pt2 = X86PageTable::new_empty().expect("no page table frame");
    let phys2m = mm::frame_allocator::allocate_frames(mm::frame_allocator::ORDER_2M)
        .expect("no 2M frame")
        .start_paddr();
    let vaddr2m = VirtAddr::new(0x0000_0000_5000_0000); // 2MB 对齐
    pt2.map(vaddr2m, PhysAddr::new(phys2m), PageSize::Size2M, PageFlags::empty().writable())
        .expect("2M map");
    logln!(
        "[test-paging] 2M: mapped {} -> {}",
        vaddr2m.as_u64(),
        phys2m
    );
    logln!("[test-paging] 2M: translate -> {:#x}", pt2.translate(vaddr2m).unwrap().as_u64());
    logln!("[test-paging] 2M: unmap -> {:#x}", pt2.unmap(vaddr2m).unwrap().as_u64());
    mm::deallocate_frame(PhysFrame::from_paddr_raw(phys2m));

    // ---- 3. MemorySet 地址空间抽象（经 arch 抽象层）----
    let ms = mm::memory_set::MemorySet::<X86PageTable>::new();
    let mut pt3 = X86PageTable::new_empty().expect("no pt3 frame");
    // 分配 3 个物理帧，映射 3 个 4K 页
    let frames: [u64; 3] = [
        mm::allocate_frame().expect("f1").start_paddr(),
        mm::allocate_frame().expect("f2").start_paddr(),
        mm::allocate_frame().expect("f3").start_paddr(),
    ];
    let start = VirtAddr::new(0x0000_0000_6000_0000);
    let end = VirtAddr::new(0x0000_0000_6000_3000);
    ms.map_range(
        &mut pt3,
        start,
        end,
        PageSize::Size4K,
        PageFlags::empty().writable(),
        &frames,
    )
    .expect("map_range");
    logln!("[test-paging] MemorySet areas={}", ms.areas());
    logln!(
        "[test-paging] MemorySet translate[1] -> {:#x}",
        pt3.translate(VirtAddr::new(0x0000_0000_6000_1000)).unwrap().as_u64()
    );
    for f in frames {
        mm::deallocate_frame(PhysFrame::from_paddr_raw(f));
    }

    logln!("[test-paging] PASS");
}

/// 验证堆分配器的分配/释放/重用逻辑。
pub fn test_heap() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    // Box 分配 + 解引用
    let b = Box::new(42u32);
    logln!("[test-heap] Box::new -> {}", *b);
    drop(b);

    // Vec 分配多个元素（会多次扩容，测试分配器稳定性）
    let mut v = Vec::new();
    for i in 0..100 {
        v.push(i);
    }
    let sum: i32 = v.iter().sum();
    logln!("[test-heap] Vec sum = {}", sum);
    drop(v);

    // 字符串（通过 alloc 的 String）
    let s = alloc::string::String::from("hello heap");
    logln!("[test-heap] String = {}", s);
    drop(s);

    logln!("[test-heap] heap tests passed");
}

/// 用 `sti`+`hlt` 等待 LAPIC 时钟中断，验证中断触发。
pub fn test_timer() {
    logln!("[timer] entering test_timer");

    let start = arch_x86_64::lapic::ticks();
    let mut rounds: u32 = 0;
    // sti+hlt 等待硬件 LAPIC 定时器中断唤醒。
    while arch_x86_64::lapic::ticks().wrapping_sub(start) < 20 {
        arch_x86_64::interrupts::enable();
        arch_x86_64::interrupts::halt();
        rounds += 1;
        if rounds % 50 == 0 {
            logln!("[timer] ... rounds={} ticks={}", rounds, arch_x86_64::lapic::ticks());
        }
        if rounds > 500 {
            logln!(
                "[timer] WARNING: no hw tick (rounds={}, ticks={})",
                rounds,
                arch_x86_64::lapic::ticks()
            );
            return;
        }
    }
    logln!(
        "[timer] confirmed: ticks={} (LAPIC timer interrupts OK)",
        arch_x86_64::lapic::ticks()
    );
}

/// 验证物理页帧分配器的分配/释放基本逻辑。
pub fn test_frame_alloc() {
    // 统计初始状态
    let s0 = mm::frame_stats();
    logln!(
        "[test-pmm] init: allocated={} alloc_calls={} fail={}",
        s0.allocated_frames, s0.alloc_calls, s0.alloc_fail
    );

    // 分配 3 个帧
    let f1 = mm::allocate_frame().expect("frame 1 alloc failed");
    let f2 = mm::allocate_frame().expect("frame 2 alloc failed");
    let f3 = mm::allocate_frame().expect("frame 3 alloc failed");
    logln!(
        "[test-pmm] allocated: f1={:?} f2={:?} f3={:?}",
        f1.start_address(),
        f2.start_address(),
        f3.start_address()
    );

    let s1 = mm::frame_stats();
    logln!(
        "[test-pmm] after alloc: allocated={} alloc_calls={} hit_uninit={} fail={}",
        s1.allocated_frames, s1.alloc_calls, s1.alloc_hit_uninit, s1.alloc_fail
    );

    // 释放一个，再分配，验证可重用
    mm::deallocate_frame(f2);
    logln!("[test-pmm] freed f2");
    let f2b = mm::allocate_frame().expect("re-alloc failed");
    logln!(
        "[test-pmm] re-allocated f2b={:?} (expect equals freed f2={:?})",
        f2b.start_address(),
        f2.start_address()
    );

    // 清理
    mm::deallocate_frame(f1);
    mm::deallocate_frame(f2b);
    mm::deallocate_frame(f3);
    logln!("[test-pmm] all frames freed");

    let s2 = mm::frame_stats();
    logln!(
        "[test-pmm] final: allocated={} alloc_calls={} fail={}",
        s2.allocated_frames, s2.alloc_calls, s2.alloc_fail
    );
}
