#![no_std]
#![no_main]

extern crate alloc;

mod acpi;
mod drivers;
mod panic;
mod pci;
mod process;
mod symbols;
mod terminal;
mod tests;

use arch::Platform;
use klib::{error, info};
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
    // 注入 panic 平台辅助：回退串口（独立于 klib console 层，确保早期 panic 可见）、
    // CPU id（LAPIC 未映射时返回 0，避免读未映射寄存器二次 #PF）、屏幕输出。
    panic::set_panic_output(
        arch_x86_64::serial::write_str as fn(&str),
        panic_cpu_id,
        terminal::write_str as fn(&str),
    );
    // T5/T6：初始化设备/驱动框架（ADR-008）：注册串口设备 + 驱动并探测。
    // 串口驱动 `init` 在此完成统一 console 串口 sink 的注册（不再手动接线），
    // 此后所有内核日志先汇聚到 console 再转发。
    drivers::init();
    info!("[kmain] serial initialized (arch={})", CurrentArch::name());

    // T6.1：枚举 PCI 总线（bus 0），把发现的设备登记到驱动框架。
    // 早于具体设备驱动使用；框架就绪后即可。
    pci::enumerate();

    // T4：探测 CPU 特性（CPUID/vendor/brand；BSP 单线程阶段，结果缓存到静态）。
    arch_x86_64::cpu::init();
    // 注入硬件熵源（RDRAND/RDSEED，无硬件时混合时钟垫底）并初始化熵池/全局 RNG。
    klib::random::set_entropy_source(arch_x86_64::cpu::entropy_u64);
    klib::random::reseed();

    // 注册页错误（#PF）处理器：缺页时按需补页（M1.3 demand paging）。
    // 尽早注册（IDT 加载后），确保任何用户态/内核态缺页都能被处理。
    arch_x86_64::interrupts::register_page_fault_handler(mm::user_space::page_fault_entry);

    // 注入系统 CPU 数读取器（供 mm 初始化 per-CPU 缓存；必须在 mm::init 前）。
    // 注：mm 自身不声明 Limine SMP 请求，避免与 arch-x86_64 的 SMP_REQUEST 冲突
    // 导致 Limine "Conflict detected for request ID" panic。
    mm::set_cpu_count_reader(arch_x86_64::smp::requested_cpu_count);

    // 初始化内存管理（LazyBuddy 物理页帧分配器 + per-CPU 缓存）
    mm::init();
    // 物理帧分配器就绪后，给堆注入增长源（按需映射动态堆），此后堆可无限增长
    klib::allocator::set_grow_allocator(heap_grow_source);

    // T6：解析 ACPI 表（RSDP → RSDT/XSDT → FADT），为 shutdown/reboot/
    // 电源管理铺路；登记 ACPI 设备到驱动框架。
    // 依赖 HHDM 物理映射（PHYS_OFFSET），须在 mm::init() 之后。
    acpi::init();

    // 验证物理页帧分配/释放
    tests::test_frame_alloc();

    // 注入页表页分配器/释放器与 HHDM 偏移（虚拟内存层使用）
    let phys_offset = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    arch_x86_64::paging::init(
        mm::mapper::mm_alloc_frame,
        mm::mapper::mm_dealloc_frame,
        phys_offset,
    );
    // T7：验证 4KB 页级通用 MMIO 映射（PCI BAR 等任意对齐小块设备寄存器用）。
    // 映射 VGA 文本缓冲（物理 0xB8000，4KB 对齐）到高半区虚拟地址并读写确认。
    // 需在 paging::init 之后（依赖页表页分配器注入）。
    arch_x86_64::mmio::test_map_phys_4k();

    // T3：初始化 HPET（高精度事件定时器）——ACPI 探测（基址/周期）+ 4KB MMIO
    // 映射 + 使能计数器，提供微秒级高精度单调时钟补充。ACPI 表在
    // acpi::init() 已解析（hpet_info）；映射依赖页表页分配器（paging::init）。
    // HPET 为备选：主时钟源仍是 LAPIC 100Hz，无 HPET 时优雅降级。
    {
        let (hpet_base, hpet_period) = acpi::hpet_info();
        arch_x86_64::hpet::init(hpet_base, hpet_period);
    }
    // 验证虚拟内存页表映射
    tests::test_paging();
    // M1：验证用户地址空间（独立页表 + 用户映射 + 切换）
    tests::test_user_address_space();
    // M1.3：验证按需分页（demand paging：#PF → 补页）
    tests::test_demand_paging();
    // M1.4：验证进程地址空间内部分配器（栈/mmap/brk）
    tests::test_address_space_alloc();
    // M2：验证 CPU 上下文切换（switch_to 交替执行）
    tests::test_context_switch();
    // M3.1：验证进程结构与进程表（PCB + pid 分配/回收）
    tests::test_process_table();

    // 获取 framebuffer（limine 0.1: get_response() 返回 Ptr<FramebufferResponse>）
    if let Some(resp) = FRAMEBUFFER_REQUEST.get_response().get() {
        info!("[kmain] framebuffer response received");
        if let Some(fb) = resp.framebuffers().first() {
            let fb = &**fb; // NonNullPtr<Framebuffer> -> Framebuffer
            info!(
                "[kmain] framebuffer {}x{} pitch={} bpp={}",
                fb.width, fb.height, fb.pitch, fb.bpp
            );
            // T6：把 framebuffer 登记为框架设备并绑定 framebuffer 驱动；
            // 驱动 init 在此完成 flanterm 终端初始化与屏幕 sink 注册
            // （不再手动接线）。
            drivers::register_framebuffer(fb);
            info!("[kmain] terminal init returned");
        } else {
            error!("[kmain] no framebuffer");
        }
    } else {
        error!("[kmain] no framebuffer response");
    }

    // 验证堆分配器（支持释放/重用）
    tests::test_heap();

    // 初始化 Local APIC 定时器（Limine 已启用 LAPIC，硬件中断走 APIC）
    info!("[kmain] enabling interrupts (LAPIC timer ~100Hz)");
    arch_x86_64::lapic::init();
    arch_x86_64::interrupts::enable();

    // 短暂等待验证时钟中断确实触发
    tests::test_timer();

    // T4：验证 CPU 特性探测（CPUID/vendor/brand）与熵池/PRNG（RDRAND/RDSEED）。
    // 不依赖 LAPIC tick（熵源与时钟垫底在 serial init 后已就绪），放在
    // time 测试之前，避免 QEMU/TCG 偶发的 LAPIC 校准偏差阻塞本梯队验收。
    tests::test_cpu_entropy();

    // 时钟源已注入：验证单调时钟换算 + 打印 RTC 墙钟（真实年月日时分秒）。
    let rtc = arch_x86_64::rtc::read_time();
    info!(
        "[kmain] RTC wall clock {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        rtc.year, rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second
    );
    info!(
        "[kmain] monotonic clock ready: now={} ns ({} ms since boot)",
        klib::time::now_nanos(),
        klib::time::now_millis()
    );
    // 验证 arch::Timer 抽象（now/sleep/set_timeout），依赖 LAPIC tick 驱动。
    tests::test_time_abstraction();

    // T3：验证 HPET 高精度事件定时器（备选时钟源）：计数器推进/周期换算/
    // 单调性/与 LAPIC tick 对齐。HPET 已在 paging::init 后初始化。
    tests::test_hpet();

    // T7：验证通用 IRQ 注册/分配（共享中断）：IRQ0 上已有 LAPIC 定时器 handler，
    // 再注册观察者共享同一 IRQ，验证多 handler 分发互不干扰。依赖 tick 运行。
    tests::test_shared_irq();

    // T7：验证嵌套控制与优先级：每 IRQ 软件优先级 + 全局嵌套开关，
    // 高优先级可打断低优先级处理、低优先级不能打断高优先级。依赖 tick 运行。
    tests::test_nested_irq_priority();

    // M2.5.4：从内核 iretq 进入用户态（Ring 3）执行一段用户代码并返回内核。
    // 依赖中断使能（int 0x80 软中断）与用户段 GDT，故放在定时器验证之后。
    // M3.2/M3.3：通过进程对象 spawn + 进入用户态；用户态异常被"进程终止"处理。
    // （M3.2 的正常 int 0x80 退出流程已单独验证，此处演进为异常上抛场景。）
    tests::test_spawn_user_fault();

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
    info!("[kmain] initializing SMP");
    arch_x86_64::smp::init();
    let total = arch_x86_64::smp::total_cpus();
    // 等待所有 AP 上线，超时 2 秒（基于 LAPIC 定时器真实时间）
    let online = arch_x86_64::smp::wait_all_online(total, 2_000);
    info!("[kmain] SMP done, {} cpus online (target {})", online, total);

    info!("[kmain] reached idle loop");
    CurrentArch::halt();
}

/// panic 时的 CPU id 读取器：LAPIC 已映射才读，否则返回 0（早期未就绪安全）。
fn panic_cpu_id() -> u32 {
    if arch_x86_64::lapic::is_mapped() {
        arch_x86_64::lapic::current_lapic_id()
    } else {
        0
    }
}
