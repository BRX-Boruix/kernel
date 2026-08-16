#![no_std]
#![no_main]

extern crate alloc;

mod panic;
mod terminal;
mod tests;

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

/// 内核堆增长源：从物理帧分配器分配连续页并映射到虚拟地址。
/// 返回 `2^order` 个连续物理页映射后的虚拟地址基址（0 表示失败）。
fn heap_grow_source(order: u32) -> u64 {
    mm::frame_allocator::allocate_frames(order as usize)
        .map(|f| arch::phys_to_virt(f.start_paddr()))
        .unwrap_or(0)
}

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

    // 初始化堆分配器（按需映射动态堆）——必须在任何 alloc 前
    klib::allocator::init();

    // 初始化架构（串口等）
    CurrentArch::init();
    // 把架构的串口整串输出注入到 klib 的全局输出器（一次调用整串原子写）
    klib::serial::set_output(arch_x86_64::serial::write_str as fn(&str));
    logln!("[kmain] serial initialized (arch={})", CurrentArch::name());

    // 初始化内存管理（LazyBuddy 物理页帧分配器）
    mm::init();
    // 物理帧分配器就绪后，给堆注入增长源（按需映射动态堆），此后堆可无限增长
    klib::allocator::set_grow_allocator(heap_grow_source);

    // 依据 Limine SMP 响应预分配 per-CPU 页帧缓存（自适应核数）。
    // 依赖物理帧分配器，须在 mm::init() 之后调用。
    let total_cpus = arch_x86_64::smp::requested_cpu_count();
    mm::frame_allocator::init_percpu_caches(total_cpus);

    // 验证物理页帧分配/释放
    tests::test_frame_alloc();

    // 注入页表页分配器与 HHDM 偏移（虚拟内存层使用）
    let phys_offset = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    arch_x86_64::paging::init(mm::mapper::mm_alloc_frame, phys_offset);
    // 验证虚拟内存页表映射
    tests::test_paging();

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
    tests::test_heap();

    // 初始化 Local APIC 定时器（Limine 已启用 LAPIC，硬件中断走 APIC）
    logln!("[kmain] enabling interrupts (LAPIC timer ~100Hz)");
    arch_x86_64::lapic::init();
    arch_x86_64::interrupts::enable();

    // 短暂等待验证时钟中断确实触发
    tests::test_timer();

    // 让 mm 的 per-CPU 缓存用紧凑 CPU 槽位（而非裸 LAPIC id）作为索引，
    // 避免真机上稀疏 LAPIC id 对固定数取模产生缓存槽冲突。
    mm::frame_allocator::set_cpu_id_reader(|| {
        let lapic_id = arch_x86_64::lapic::current_lapic_id();
        arch_x86_64::smp::slot_of_lapic(lapic_id)
    });

    // 注入 AP 栈的物理帧分配器（arch 层经函数指针调用 mm，避免循环依赖）
    arch_x86_64::smp::set_frame_allocator(|order| {
        mm::frame_allocator::allocate_frames(order as usize)
            .map(|f| f.start_paddr())
            .unwrap_or(0)
    });

    // 初始化多核 SMP：启动所有 AP，并等待全部上线
    logln!("[kmain] initializing SMP");
    arch_x86_64::smp::init();
    let total = arch_x86_64::smp::total_cpus();
    // 等待所有 AP 上线，超时 2 秒（基于 LAPIC 定时器真实时间）
    let online = arch_x86_64::smp::wait_all_online(total, 2_000);
    logln!("[kmain] SMP done, {} cpus online (target {})", online, total);

    logln!("[kmain] reached idle loop");
    CurrentArch::halt();
}
