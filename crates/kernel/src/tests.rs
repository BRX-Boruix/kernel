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

/// M1.4：验证进程地址空间内部分配器（栈区 / mmap / brk）。
///
/// 覆盖：
/// 1. `setup_stack`：在固定栈顶下方预留栈区。
/// 2. `mmap_user`：在用户半区分配按需分页区间（不重叠）。
/// 3. `brk`：查询/扩展堆断点，堆区访问按需补页。
pub fn test_address_space_alloc() {
    use core::sync::atomic::Ordering;
    use mm::user_space::{
        USER_HEAP_BASE, USER_STACK_TOP, DEFAULT_STACK_SIZE,
    };

    let mut us = mm::user_space::UserAddressSpace::<X86PageTable>::new().expect("new us");
    logln!("[test-alloc] created user address space");

    // 1. 栈区
    let stack_top = us.setup_stack(DEFAULT_STACK_SIZE).expect("setup_stack");
    logln!(
        "[test-alloc] stack top={:#x}, size={}MiB (area 0)",
        stack_top,
        DEFAULT_STACK_SIZE / (1024 * 1024)
    );
    assert_eq!(stack_top, USER_STACK_TOP);
    assert_eq!(us.area_count(), 1);

    // 2. mmap 两段，验证不重叠且不与栈重叠
    let m1 = us.mmap_user(64 * 1024, arch::PageFlags::empty().writable()).expect("mmap1");
    let m2 = us.mmap_user(128 * 1024, arch::PageFlags::empty().writable()).expect("mmap2");
    logln!(
        "[test-alloc] mmap1={:#x}..{:#x}, mmap2={:#x}..{:#x}",
        m1,
        m1 + 64 * 1024,
        m2,
        m2 + 128 * 1024
    );
    assert!(m1 + 64 * 1024 <= m2, "mmap regions must not overlap");
    assert!(m2 + 128 * 1024 < USER_STACK_TOP, "mmap must be below stack");
    assert_eq!(us.area_count(), 3);

    // 3. brk：查询 → 扩展 → 再查询
    let b0 = us.brk(0).expect("brk query");
    assert_eq!(b0, USER_HEAP_BASE);
    let b1 = us.brk(USER_HEAP_BASE + 32 * 1024).expect("brk extend");
    logln!(
        "[test-alloc] brk {:#x} -> {:#x}",
        b0,
        b1
    );
    assert_eq!(b1, USER_HEAP_BASE + 32 * 1024);
    assert_eq!(us.heap_break(), b1);

    // 4. 访问栈区触发 #PF 按需补页（复用全局 handler 机制）
    let us_ptr = &mut us as *mut mm::user_space::UserAddressSpace<X86PageTable> as usize;
    TEST_FAULT_US.store(us_ptr, Ordering::SeqCst);
    mm::user_space::set_page_fault_handler(test_fault_handler);
    us.activate();

    // 栈底附近写（栈顶向下 4KiB 内）
    let sp = USER_STACK_TOP - 8;
    unsafe { core::ptr::write_volatile((sp - 4) as *mut u32, 0xBEEF) };
    let sv = unsafe { core::ptr::read_volatile((sp - 4) as *const u32) };
    logln!("[test-alloc] stack write/read -> {:#x}", sv);
    assert_eq!(sv, 0xBEEF);

    // mmap 区访问补页
    unsafe { core::ptr::write_volatile(m1 as *mut u32, 0x1234) };
    let mv = unsafe { core::ptr::read_volatile(m1 as *const u32) };
    logln!("[test-alloc] mmap write/read -> {:#x}", mv);
    assert_eq!(mv, 0x1234);

    // 堆区访问补页
    unsafe { core::ptr::write_volatile((USER_HEAP_BASE + 0x1000) as *mut u32, 0x5678) };
    let hv = unsafe { core::ptr::read_volatile((USER_HEAP_BASE + 0x1000) as *const u32) };
    logln!("[test-alloc] heap write/read -> {:#x}", hv);
    assert_eq!(hv, 0x5678);

    // 切回内核页表，清理
    X86PageTable::current().activate();
    mm::user_space::set_page_fault_handler(noop_fault_handler);
    TEST_FAULT_US.store(0, Ordering::SeqCst);
    logln!("[test-alloc] PASS");
}

// ---- M2 上下文切换测试 ----

/// 任务栈大小（16KB）。
const TASK_STACK_SIZE: usize = 16 * 1024;

// 静态任务栈（BSS 段，不占内核堆）
static mut TASK_STACK_A: [u8; TASK_STACK_SIZE] = [0; TASK_STACK_SIZE];
static mut TASK_STACK_B: [u8; TASK_STACK_SIZE] = [0; TASK_STACK_SIZE];

// 静态任务上下文
static mut TASK_CTX_A: arch::task::TaskContext = arch::task::TaskContext::empty();
static mut TASK_CTX_B: arch::task::TaskContext = arch::task::TaskContext::empty();

/// 主上下文（测试结束切回用）。
static mut MAIN_CTX: arch::task::TaskContext = arch::task::TaskContext::empty();

/// 切换轮次计数。
static SWITCH_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 任务 A 入口：循环打印并切到任务 B；第 4 次后切回主上下文结束。
extern "C" fn task_a_main() {
    use core::sync::atomic::Ordering;
    loop {
        let n = SWITCH_COUNT.fetch_add(1, Ordering::SeqCst);
        logln!("[test-switch] task A run #{} (stack intact)", n);
        // 通过 addr_of_mut 取上下文引用（避免 static_mut_refs lint）
        let ctx_a = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_A) };
        if n >= 4 {
            // 达到阈值：切回主上下文（结束测试）
            let main_ctx = unsafe { &mut *core::ptr::addr_of_mut!(MAIN_CTX) };
            arch::switch_to(ctx_a, main_ctx);
        } else {
            let ctx_b = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_B) };
            arch::switch_to(ctx_a, ctx_b);
        }
        // 从 switch_to 恢复后回到 loop 开头，不会自然返回（避免 ret 到垃圾栈）
    }
}

/// 任务 B 入口：循环打印并切到任务 A。
extern "C" fn task_b_main() {
    use core::sync::atomic::Ordering;
    loop {
        let n = SWITCH_COUNT.load(Ordering::SeqCst);
        logln!("[test-switch] task B run (count={})", n);
        let ctx_b = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_B) };
        let ctx_a = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_A) };
        arch::switch_to(ctx_b, ctx_a);
        // 从 switch_to 恢复后回到 loop 开头
    }
}

/// M2：验证上下文切换。
///
/// 两个任务（A/B）通过 `switch_to` 交替执行，各用独立栈。
/// 验证寄存器/栈正确保存恢复，无崩溃。
pub fn test_context_switch() {
    use core::sync::atomic::Ordering;

    // 任务 A/B 上下文：入口 + 独立栈顶部
    let stack_a_top = core::ptr::addr_of!(TASK_STACK_A) as usize + TASK_STACK_SIZE;
    let stack_b_top = core::ptr::addr_of!(TASK_STACK_B) as usize + TASK_STACK_SIZE;
    let ctx_a = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_A) };
    let ctx_b = unsafe { &mut *core::ptr::addr_of_mut!(TASK_CTX_B) };
    arch_x86_64::task::init_context(ctx_a, task_a_main, stack_a_top as u64);
    arch_x86_64::task::init_context(ctx_b, task_b_main, stack_b_top as u64);

    SWITCH_COUNT.store(0, Ordering::SeqCst);
    logln!("[test-switch] starting context switch...");

    // 从主切到任务 A（保存主上下文到 MAIN_CTX）
    let main_ctx = unsafe { &mut *core::ptr::addr_of_mut!(MAIN_CTX) };
    arch::switch_to(main_ctx, ctx_a);
    // 当任务 A 第 4 次切回 MAIN_CTX 时，控制流回到这里

    let n = SWITCH_COUNT.load(Ordering::SeqCst);
    logln!("[test-switch] back to main after {} switches", n);
    assert!(n >= 4, "expected >=4 switches, got {}", n);
    logln!("[test-switch] PASS");
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

// ---- M2.5 进入用户态基础准备测试 ----

/// M2.5.4 冒烟测试的常量地址（避免与既有测试冲突）。
///
/// - 用户代码页：`0x0000_0000_9000_0000`（可执行，立即映射）。
/// - 用户栈：`USER_STACK_TOP`（0x7fff_0000_0000，立即映射）。
/// - magic 地址：`0x0000_0000_9500_0000`（可写，立即映射）。
mod usermode {
    pub const CODE_ADDR: u64 = 0x0000_0000_9000_0000;
    pub const MAGIC_ADDR: u64 = 0x0000_0000_9500_0000;
    pub const MAGIC: u64 = 0xDEADBEEF;
}

/// M3.1：验证进程结构与进程表（PCB + pid 分配/回收）。
///
/// 验证点：
/// 1. `spawn` 装配进程（入口/用户栈顶/内核栈顶/地址空间），pid 单调递增。
/// 2. `get` / `get_mut` 访问进程字段与状态切换。
/// 3. `terminate` 回收 pid，再 `spawn` 复用该 pid。
pub fn test_process_table() {
    use crate::process::{ProcessTable, TaskState};
    use mm::user_space::UserAddressSpace;

    logln!("[test-process] === M3.1: process table + pid mgmt ===");

    let mut table = ProcessTable::<X86PageTable>::new();

    // 1. spawn 两个进程，pid 递增（1, 2）
    let us1 = UserAddressSpace::<X86PageTable>::new().expect("us1");
    let pid1 = table
        .spawn(0x9000_0000, 0x4000_0000, 0xffff_ffff_801b_0000, us1)
        .expect("spawn1");
    let us2 = UserAddressSpace::<X86PageTable>::new().expect("us2");
    let pid2 = table
        .spawn(0x9000_1000, 0x4000_2000, 0xffff_ffff_801c_0000, us2)
        .expect("spawn2");
    assert_eq!(pid1, 1, "first pid should be 1");
    assert_eq!(pid2, 2, "second pid should be 2");
    assert_eq!(table.len(), 2, "two live processes");
    assert_eq!(table.count_state(TaskState::Ready), 2, "both ready");

    // 2. get / get_mut 访问进程字段
    let p = table.get(pid1).expect("get pid1");
    assert_eq!(p.entry_rip(), 0x9000_0000);
    assert_eq!(p.user_stack_top(), 0x4000_0000);
    assert_eq!(p.kernel_stack_top(), 0xffff_ffff_801b_0000);
    assert_eq!(p.state(), TaskState::Ready);
    logln!(
        "[test-process] spawned pid1={} rip={:#x} user_sp={:#x} ksp={:#x} state={:?}",
        pid1,
        p.entry_rip(),
        p.user_stack_top(),
        p.kernel_stack_top(),
        p.state()
    );

    // 状态切换：Ready -> Running -> Blocked
    {
        let pm = table.get_mut(pid1).expect("get_mut pid1");
        pm.set_state(TaskState::Running);
    }
    assert_eq!(table.count_state(TaskState::Running), 1);
    {
        let pm = table.get_mut(pid1).expect("get_mut pid1");
        pm.set_state(TaskState::Blocked);
    }
    assert_eq!(table.count_state(TaskState::Blocked), 1);

    // 3. terminate 回收 pid，再 spawn 复用
    assert!(table.terminate(pid1), "terminate pid1");
    assert!(!table.get(pid1).is_some(), "pid1 slot freed");
    assert_eq!(table.len(), 1, "one process left");

    let us3 = UserAddressSpace::<X86PageTable>::new().expect("us3");
    let pid3 = table
        .spawn(0x9000_2000, 0x4000_3000, 0xffff_ffff_801d_0000, us3)
        .expect("spawn3");
    assert_eq!(pid3, pid1, "pid1 reused after terminate");

    // 终止不存在的 pid 返回 false；终止存在的 pid2 返回 true
    assert!(!table.terminate(999), "terminate nonexistent pid");
    assert!(table.terminate(pid2), "terminate pid2");

    logln!(
        "[test-process] final len={} (pid reuse verified: pid3={}==pid1={})",
        table.len(),
        pid3,
        pid1
    );
    logln!("[test-process] PASS");
}

/// 触发异常的用户态机器码：`mov rax, MAGIC` → `mov [MAGIC_ADDR], rax` → `ud2`。
///
/// `ud2`（0F 0B）是非法指令，用户态执行触发 #UD（vector 6）——用于 M3.3 验证
/// 用户态异常被"进程终止"处理，而非当作内核崩溃。
fn usermode_fault_code() -> [u8; 26] {
    use usermode::{MAGIC, MAGIC_ADDR};
    let mut c = [0u8; 26];
    c[0] = 0x48; c[1] = 0xB8; // mov rax, imm64
    c[2..10].copy_from_slice(&MAGIC.to_le_bytes());
    c[10] = 0x48; c[11] = 0xA3; // mov [moffs64], rax
    c[12..20].copy_from_slice(&MAGIC_ADDR.to_le_bytes());
    c[20] = 0x0F; c[21] = 0x0B; // ud2（非法指令 → #UD）
    c[22..].fill(0x90); // nop 填充
    c
}

/// M3.3 用户态异常处理器：用户态进程触发异常时终止该进程。
///
/// 不再当作内核崩溃（不 panic、不打印 CPU EXCEPTION），而是标记"用户进程异常终止"，
/// 单进程场景下停机。
extern "C" fn user_fault_handler(frame: &mut arch_x86_64::interrupts::InterruptFrame) {
    klib::logln!(
        "[test-fault] user process terminated by exception: vector={:#x} rip={:#x} cs={:#x}",
        frame.vector,
        frame.rip,
        frame.cs
    );
    // 进程终止：单进程场景下停机（不 panic、不 iretq 回用户态）。
    arch_x86_64::interrupts::disable();
    loop {
        arch_x86_64::interrupts::halt();
    }
}

/// M3.3：用户态进程触发异常（#UD）时，异常被"进程终止"处理而非内核崩溃。
///
/// 用户代码写 magic 后执行 `ud2` → #UD（用户态）→ `register_user_exception_handler`
/// 注册的处理器被调用 → 打印"用户进程异常终止"并停机。
pub fn test_spawn_user_fault() {
    use crate::process::ProcessTable;
    use mm::user_space::UserAddressSpace;
    use usermode::{CODE_ADDR, MAGIC_ADDR};

    logln!("[test-fault] === M3.3: user exception terminates process ===");

    let mut us = UserAddressSpace::<X86PageTable>::new().expect("new user space");
    let code_frame = mm::allocate_frame().expect("code frame").start_paddr();
    let magic_frame = mm::allocate_frame().expect("magic frame").start_paddr();
    let stack_frame = mm::allocate_frame().expect("stack frame").start_paddr();
    let off = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    let code = usermode_fault_code();
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            (code_frame + off) as *mut u8,
            code.len(),
        );
    }
    us.map_user(
        VirtAddr::new(CODE_ADDR),
        VirtAddr::new(CODE_ADDR + 0x1000),
        PageSize::Size4K,
        PageFlags::empty().writable().executable().user(),
        &[code_frame],
    )
    .expect("map code");
    us.map_user(
        VirtAddr::new(MAGIC_ADDR),
        VirtAddr::new(MAGIC_ADDR + 0x1000),
        PageSize::Size4K,
        PageFlags::empty().writable().user(),
        &[magic_frame],
    )
    .expect("map magic");
    let stack_top = 0x4000_0000u64;
    us.map_user(
        VirtAddr::new(stack_top - 0x1000),
        VirtAddr::new(stack_top),
        PageSize::Size4K,
        PageFlags::empty().writable().user(),
        &[stack_frame],
    )
    .expect("map stack");

    let mut table = ProcessTable::<X86PageTable>::new();
    let pid = table
        .spawn(CODE_ADDR, stack_top, 0xffff_ffff_801b_6910, us)
        .expect("spawn process");
    logln!("[test-fault] spawned pid={} (code: write magic then ud2)", pid);

    // 注册用户态异常处理器：终止崩溃进程。
    arch_x86_64::interrupts::register_user_exception_handler(user_fault_handler);

    // 进入用户态执行（永不返回；用户态 ud2 异常被终止）。
    table.get(pid).unwrap().addr_space().activate();
    table.run(pid);
}
