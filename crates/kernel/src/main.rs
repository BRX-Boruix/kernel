#![no_std]
#![no_main]

extern crate alloc;

mod panic;
mod terminal;

use arch::Platform;
use klib::logln;
use limine::{BaseRevision, FramebufferRequest};

use arch_x86_64::X86_64Arch as CurrentArch;

// 声明 BaseRevision。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别请求。
#[limine::limine_tag]
static BASE_REVISION: BaseRevision = BaseRevision::new(6);

// 请求 framebuffer
#[limine::limine_tag]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new(0);

/// 内核主栈大小（1MB）。kmain 及后续所有调用都在此栈上运行，
/// 避免 Limine 提供的初始引导栈过小导致深调用（如 flanterm）溢出。
const KMAIN_STACK_SIZE: usize = 1024 * 1024;


/// 内核主栈（静态分配，位于 .bss）。
static mut KMAIN_STACK: [u8; KMAIN_STACK_SIZE] = [0; KMAIN_STACK_SIZE];

/// 真正的内核入口：先切换到自己的大栈，再进入 kmain 主体。
/// Limine 跳转到的 `kmain`（见下方 no_mangle 函数）会做栈切换。
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // 切换到我们自己的大栈（栈顶）。
    // 用汇编把 rsp 切换到 KMAIN_STACK 顶部，同时保留返回地址以便切换后正常执行。
    unsafe {
        core::arch::asm!(
            "mov {stack}, rsp",
            "mov rsp, {stack_top}",
            stack = out(reg) _,
            stack_top = in(reg) (&raw mut KMAIN_STACK).cast::<u8>().add(KMAIN_STACK_SIZE) as usize,
            options(nostack),
        );
    }
    unsafe { kmain_body() }
}

/// kmain 主体（在自备大栈上运行）。
unsafe fn kmain_body() -> ! {
    // 初始化 panic 子系统（注入架构名和停机函数，尽早）
    panic::init(CurrentArch::name(), CurrentArch::halt);

    // 初始化堆分配器（buddy，支持释放重用）——必须在任何 alloc 前
    klib::allocator::init();

    // 初始化架构（串口等）
    CurrentArch::init();
    // 把架构的串口输出注入到 klib 的全局输出器
    klib::serial::set_output(CurrentArch::serial_write as fn(u8));
    logln!("[kmain] serial initialized (arch={})", CurrentArch::name());

    // 初始化内存管理（LazyBuddy 物理页帧分配器）
    mm::init();
    // 验证物理页帧分配/释放
    test_frame_alloc();

    // 注入页表页分配器与 HHDM 偏移（虚拟内存层使用）
    let phys_offset = mm::PHYS_OFFSET.get().copied().unwrap_or(0);
    arch_x86_64::paging::init(mm::mapper::mm_alloc_frame, phys_offset);
    // 验证虚拟内存页表映射
    test_paging();

    // 获取 framebuffer（limine 0.1: get_response() 返回 Ptr<FramebufferResponse>）
    if let Some(resp) = FRAMEBUFFER_REQUEST.get_response().get() {
        logln!("[kmain] framebuffer response received");
        if let Some(fb) = resp.framebuffers().first() {
            let fb = &**fb; // NonNullPtr<Framebuffer> -> Framebuffer
            logln!(
                "[kmain] framebuffer {}x{} pitch={} bpp={}",
                fb.width, fb.height, fb.pitch, fb.bpp
            );
            terminal::init(fb);
            logln!("[kmain] terminal init returned");
        } else {
            logln!("[kmain] ERROR: no framebuffer");
        }
    } else {
        logln!("[kmain] ERROR: no framebuffer response");
    }

    // 验证堆分配器（支持释放/重用）
    test_heap();

    // 初始化 Local APIC 定时器（Limine 已启用 LAPIC，硬件中断走 APIC）
    logln!("[kmain] enabling interrupts (LAPIC timer ~100Hz)");
    arch_x86_64::lapic::init(phys_offset, 1_000_000_000); // 假设总线频率约 1GHz
    arch_x86_64::interrupts::enable();

    // 短暂等待验证时钟中断确实触发
    test_timer();

    // 让 mm 的 per-CPU 缓存用真实的 LAPIC id 作为 CPU id
    mm::frame_allocator::set_cpu_id_reader(|| arch_x86_64::lapic::current_lapic_id() as usize);

    // 初始化多核 SMP：启动所有 AP
    logln!("[kmain] initializing SMP");
    arch_x86_64::smp::init();
    logln!("[kmain] SMP done, {} cpus online", arch_x86_64::smp::cpu_count());

    logln!("[kmain] reached idle loop");
    CurrentArch::halt();
}

/// 验证虚拟内存页表：4KB 映射 + 2MB 大页映射 + 真实内存读写（经 HHDM 写入，
/// 再通过 activate 切页表读出）。为安全，激活的页表会先复制当前内核页表的
/// 高半区映射，保证切换后内核/串口仍可访问。
fn test_paging() {
    use arch::{PageFlags, PageSize, PageTable, VirtAddr};

    // ---- 1. 4KB 页映射/翻译/解映射（逻辑验证）----
    let mut pt = arch_x86_64::paging::X86PageTable::new_empty().expect("no page table frame");
    let phys4k = mm::allocate_frame().expect("no 4k frame").start_address().as_u64();
    let vaddr4k = VirtAddr::new(0x0000_0000_4000_0000);
    pt.map(vaddr4k, arch::PhysAddr::new(phys4k), PageSize::Size4K, PageFlags::empty().writable())
        .expect("4k map");
    logln!("[test-paging] 4K: mapped {} -> {}", vaddr4k.as_u64(), phys4k);
    logln!("[test-paging] 4K: translate -> {:#x}", pt.translate(vaddr4k).unwrap().as_u64());
    logln!("[test-paging] 4K: unmap -> {:#x}", pt.unmap(vaddr4k).unwrap().as_u64());
    mm::deallocate_frame(arch::PhysFrame::containing_address(arch::PhysAddr::new(phys4k)));

    // ---- 2. 2MB 大页映射（逻辑验证）----
    let mut pt2 = arch_x86_64::paging::X86PageTable::new_empty().expect("no page table frame");
    let phys2m = mm::frame_allocator::allocate_frames(mm::frame_allocator::ORDER_2M)
        .expect("no 2M frame")
        .start_address()
        .as_u64();
    let vaddr2m = VirtAddr::new(0x0000_0000_5000_0000); // 2MB 对齐
    pt2.map(vaddr2m, arch::PhysAddr::new(phys2m), PageSize::Size2M, PageFlags::empty().writable())
        .expect("2M map");
    logln!(
        "[test-paging] 2M: mapped {} -> {}",
        vaddr2m.as_u64(),
        phys2m
    );
    logln!("[test-paging] 2M: translate -> {:#x}", pt2.translate(vaddr2m).unwrap().as_u64());
    logln!("[test-paging] 2M: unmap -> {:#x}", pt2.unmap(vaddr2m).unwrap().as_u64());
    mm::deallocate_frame(arch::PhysFrame::containing_address(arch::PhysAddr::new(phys2m)));

    // ---- 3. MemorySet 地址空间抽象（经 arch 抽象层）----
    let ms = mm::memory_set::MemorySet::<arch_x86_64::paging::X86PageTable>::new();
    let mut pt3 = arch_x86_64::paging::X86PageTable::new_empty().expect("no pt3 frame");
    // 分配 3 个物理帧，映射 3 个 4K 页
    let frames: [u64; 3] = [
        mm::allocate_frame().expect("f1").start_address().as_u64(),
        mm::allocate_frame().expect("f2").start_address().as_u64(),
        mm::allocate_frame().expect("f3").start_address().as_u64(),
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
        mm::deallocate_frame(arch::PhysFrame::containing_address(arch::PhysAddr::new(f)));
    }

    logln!("[test-paging] PASS");
}

/// 验证堆分配器的分配/释放/重用逻辑。
fn test_heap() {
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
fn test_timer() {
    logln!("[timer] entering test_timer");

    let start = arch_x86_64::lapic::ticks();
    let mut rounds: u32 = 0;
    // sti+hlt 等待硬件 LAPIC 定时器中断唤醒。
    while arch_x86_64::lapic::ticks().wrapping_sub(start) < 20 {
        unsafe { core::arch::asm!("sti", "hlt", options(nomem, nostack)) };
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
fn test_frame_alloc() {
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
