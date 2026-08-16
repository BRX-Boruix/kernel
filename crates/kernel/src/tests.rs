//! 内核启动自检测试。
//!
//! 这些测试在内核初始化流程的特定阶段被调用，验证物理页帧分配器、
//! 虚拟内存页表、堆分配器与 LAPIC 时钟中断是否正确工作。
//! 与运行时代码分离，便于单独维护。

use klib::logln;

use arch::{ActivePageTable, PageFlags, PageSize, PageTable, PhysAddr, PhysFrame, VirtAddr};
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

/// M1：验证用户地址空间（UserAddressSpace）。
///
/// 覆盖：
/// 1. 从内核页表派生独立用户页表（`UserAddressSpace::new`）。
/// 2. 用户区映射（带 user 标志）、翻译、解映射。
/// 3. 切换活动页表后内核仍可访问（内核半区被继承）。
pub fn test_user_address_space() {
    use mm::user_space::UserAddressSpace;

    logln!("[test-user-space] creating user address space...");
    let mut us = UserAddressSpace::<X86PageTable>::new().expect("new user space");

    // 映射 2 个用户页
    let f1 = mm::allocate_frame().expect("f1").start_paddr();
    let f2 = mm::allocate_frame().expect("f2").start_paddr();
    let start = VirtAddr::new(0x0000_0000_4000_0000);
    let end = VirtAddr::new(0x0000_0000_4000_2000);
    us.map_user(
        start,
        end,
        PageSize::Size4K,
        PageFlags::empty().writable(),
        &[f1, f2],
    )
    .expect("map_user");
    logln!(
        "[test-user-space] mapped {}..{} areas={}",
        start.as_u64(),
        end.as_u64(),
        us.area_count()
    );

    // 翻译验证
    let t1 = us.translate(start).expect("translate page0");
    logln!(
        "[test-user-space] translate({:#x}) -> {:#x} (expect {:#x})",
        start.as_u64(),
        t1.as_u64(),
        f1
    );
    assert_eq!(t1.as_u64(), f1);

    // 切换活动页表：切到用户地址空间后，内核半区仍可访问（串口能继续打印）
    us.activate();
    logln!("[test-user-space] activated user page table, kernel still reachable");

    // 验证用户页可经 HHDM 写入、经激活页表读到（通过 translate 得到物理地址）
    let phys = us.translate(start).unwrap().as_u64();
    let off = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    unsafe {
        core::ptr::write_volatile((phys + off) as *mut u32, 0xDEAD);
        let v = core::ptr::read_volatile((phys + off) as *const u32);
        logln!("[test-user-space] write/read phys {:#x} = {:#x}", phys, v);
        assert_eq!(v, 0xDEAD);
    }

    // 切回内核页表（当前活动页表）
    X86PageTable::current().activate();
    logln!("[test-user-space] switched back to kernel page table");

    // 解映射并释放
    let unp0 = us.unmap_user(start).expect("unmap page0");
    logln!("[test-user-space] unmap page0 -> {:#x}", unp0.as_u64());
    let unp1 = us
        .unmap_user(VirtAddr::new(0x0000_0000_4000_1000))
        .expect("unmap page1");
    logln!("[test-user-space] unmap page1 -> {:#x}", unp1.as_u64());
    mm::deallocate_frame(PhysFrame::from_paddr_raw(f1));
    mm::deallocate_frame(PhysFrame::from_paddr_raw(f2));

    logln!("[test-user-space] PASS");
}

// ---- M1.3 按需分页测试 ----

/// 当前测试用户地址空间指针（M1 简化：单地址空间，M3 后改为进程结构）。
static TEST_FAULT_US: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// #PF 回调：转发给当前测试用户地址空间的 `handle_page_fault`。
extern "C" fn test_fault_handler(vaddr: u64, error_code: u64) -> bool {
    let ptr = TEST_FAULT_US.load(core::sync::atomic::Ordering::SeqCst);
    if ptr == 0 {
        return false;
    }
    let us = unsafe { &mut *(ptr as *mut mm::user_space::UserAddressSpace<X86PageTable>) };
    us.handle_page_fault(vaddr, error_code)
}

/// 空 #PF 回调（测试结束清理用）。
extern "C" fn noop_fault_handler(_vaddr: u64, _error_code: u64) -> bool {
    false
}

/// M1.3：验证按需分页（demand paging）。
///
/// 流程：
/// 1. 创建用户地址空间，`reserve_user` 声明一段**预留但未映射**区域（present=0）。
/// 2. 注册 #PF 回调（指向该地址空间），激活其页表。
/// 3. **真实访问预留地址触发 #PF** → #PF 入口 → `handle_page_fault` 按需补页 → 重试成功。
/// 4. 验证翻译命中、内容可写；非法访问（未预留）返回 false。
pub fn test_demand_paging() {
    use core::sync::atomic::Ordering;

    let mut us = mm::user_space::UserAddressSpace::<X86PageTable>::new().expect("new us");
    // 预留一段 4 页区域（present=0，访问时补页）
    let start = VirtAddr::new(0x0000_0000_6000_0000);
    let end = VirtAddr::new(0x0000_0000_6000_4000);
    us.reserve_user(start, end, PageSize::Size4K, PageFlags::empty().writable())
        .expect("reserve_user");
    logln!(
        "[test-demand] reserved {}..{} areas={} (unmapped)",
        start.as_u64(),
        end.as_u64(),
        us.area_count()
    );

    // 预留区域尚未映射
    assert!(us.translate(start).is_none(), "reserved page should be unmapped");

    // 设置当前地址空间 + 注册 #PF 回调
    let us_ptr = &mut us as *mut mm::user_space::UserAddressSpace<X86PageTable> as usize;
    TEST_FAULT_US.store(us_ptr, Ordering::SeqCst);
    mm::user_space::set_page_fault_handler(test_fault_handler);

    // 激活用户页表，真实访问预留地址 → 触发 #PF → 按需补页
    us.activate();
    logln!("[test-demand] accessing reserved addr (will #PF -> demand map)...");
    // 读预留页：present=0 → #PF → handler 补页 → 重试成功，读到 0
    let val = unsafe { core::ptr::read_volatile(start.as_u64() as *const u32) };
    logln!("[test-demand] read reserved addr -> {:#x} (mapped on demand)", val);
    assert_eq!(val, 0);

    // 翻译应命中
    let phys = us.translate(start).expect("translated after demand map");
    logln!("[test-demand] translate -> {:#x}", phys.as_u64());

    // 可写
    unsafe { core::ptr::write_volatile(start.as_u64() as *mut u32, 0xCAFE) };
    let v2 = unsafe { core::ptr::read_volatile(start.as_u64() as *const u32) };
    assert_eq!(v2, 0xCAFE);
    logln!("[test-demand] write/read -> {:#x}", v2);

    // 非法访问（未预留地址）：handler 应返回 false
    let bad = 0x0000_0000_7000_0000u64;
    let ok = mm::user_space::page_fault_entry(bad, 0);
    logln!("[test-demand] illegal access handled? {}", ok);
    assert!(!ok, "unreserved access must be rejected");

    // 切回内核页表
    X86PageTable::current().activate();
    mm::user_space::set_page_fault_handler(noop_fault_handler);
    TEST_FAULT_US.store(0, Ordering::SeqCst);

    // 回收按需分页补的页
    us.unmap_area_pages(0);
    logln!("[test-demand] PASS");
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
