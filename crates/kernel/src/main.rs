#![no_std]
#![no_main]

extern crate alloc;

// liveCD 内置用户程序 payload（SDK 构建生成，ADR-017）：无外部盘时
// 内核用其填充 /programs 完成启动；外部盘挂载后整体覆盖（盘优先）。
// 模块名 `binaries_payload` 为 SDK 生成产物契约名（见 sdk_build/build.py），
// 沿用历史命名，用户态可见路径一律是 /programs。
mod binaries_payload;
mod acpi;
mod drivers;
mod ipc_init;
mod panic;
mod symbols;
mod syscall;
mod vfs_init;

#[cfg(feature = "kernel-tests")]
mod tests;

use arch::interrupt::InterruptController;
use arch::syscall::SyscallEntry;
use arch::Platform;
use core::sync::atomic::{AtomicBool, Ordering};
use klib::{error, info, warn};
use limine::{BaseRevision, FramebufferRequest};

use arch_x86_64::X86_64Arch as CurrentArch;

// 声明 BaseRevision。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别请求。
#[limine::limine_tag]
static BASE_REVISION: BaseRevision = BaseRevision::new(6);

// 请求 framebuffer
#[limine::limine_tag]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new(0);

/// 内核堆增长源：从物理帧分配器分配连续页并映射到虚拟地址。
/// 成功返回 `2^order` 个连续物理页映射后的虚拟地址基址；耗尽返回 `None`
/// （KM11：类型化失败，不用魔法 0 哨兵）。
fn heap_grow_source(order: u32) -> Option<u64> {
    mm::frame_allocator::allocate_frames(order as usize)
        .map(|f| arch::phys_to_virt(f.start_paddr()))
}

// KA3：栈边界由链接器脚本唯一提供（.kernel_main_stack NOLOAD 段 + 紧贴
// 栈底的守护页）。Rust 侧只引用符号地址，不再持有任何栈数组静态——
// 数组静态的对齐/落位曾两次肇事（KD9 奇地址栈、KA3 无守护页）。
unsafe extern "C" {
    static __kstack_guard_base: u8;
    static __kstack_guard_top: u8;
    static __kstack_base: u8;
    static __kstack_top: u8;
}

/// 内核主栈大小（字节）：与 linker.ld `.kernel_main_stack` 段内的
/// `. += 0x100000` 配对。启动时经 [`assert_stack_layout`] 复核两侧一致。
const KMAIN_STACK_SIZE: usize = 1024 * 1024;

/// 启动期复核链接器给出的栈布局与 Rust 侧预期一致（KA3 防漂移）。
///
/// # 为什么不用异符号的直接相等断言
///
/// 原实现首条断言写 `guard_top == base`（`__kstack_guard_top` 与
/// `__kstack_base` 由 linker.ld 置于同一地址）。LLVM 语义假设**不同的 extern
/// 全局对象地址必然不同**，linker 让两个符号同址恰违反该假设；`-O`
/// （release）下 `ptrtoint(A) == ptrtoint(B)` 会被常折叠为 `false`
/// （2026-07 nightly 实测），整条断言恒失败，连带其后整段布防代码被判定
/// 死代码删除——release 内核必在启动期 panic、debug（-O0）却正常。
///
/// 本实现改为**与非零常量的跨度断言**（距离运算对优化器不透明，实测保留
/// 为运行期比较）：由 linker.ld 同一输出段内符号单调性（`. = ALIGN(..)` /
/// `. += ..` 只向后推进），跨度 ①守护页恰 4KiB、②守护页顶→栈顶恰 1MiB
/// 同时精确，即等价于原三条检查（`guard_top == base`、`top - base == 1MiB`、
/// `guard_top - guard_base == 4KiB`）——守护页与栈区之间出现任何间隙或重叠
/// 都会使跨度 ② 偏离 1MiB 被当场捕获。原义相等核对保留为 `debug_assert!`
/// （仅 debug 档编译，release 无此比较，天然无折叠窗口）。
fn assert_stack_layout() {
    let guard_base = core::ptr::addr_of!(__kstack_guard_base) as usize;
    let guard_top = core::ptr::addr_of!(__kstack_guard_top) as usize;
    let base = core::ptr::addr_of!(__kstack_base) as usize;
    let top = core::ptr::addr_of!(__kstack_top) as usize;
    // 同一输出段内符号必须单调（linker 只向后推进）；顺序断言防脚本重排。
    // 均为不同符号间的**大小**比较（>=），LLVM 无法折叠（仅 == 可折叠）。
    assert!(
        base >= guard_top && top >= base,
        "kernel stack layout mismatch: linker vs rust"
    );
    // 守护页恰为一页且紧贴栈底。页尺寸单一出处 = x86-64 页粒度（4KiB，
    // SDM Vol.3 §4.2）；linker.ld 的守护页段长按同一粒度编写，此处断言即
    // 两侧漂移的运行期哨兵（审计 B13：非独立魔法值，是跨侧一致性的检查点）。
    const PAGE_SIZE_BYTES: usize = 4096;
    assert!(
        guard_top - guard_base == PAGE_SIZE_BYTES,
        "guard page must be one page"
    );
    // 守护页顶→栈顶恰为 1MiB 主栈（见函数头等价性论证）。
    assert!(
        top - guard_top == KMAIN_STACK_SIZE,
        "kernel stack layout mismatch: linker vs rust"
    );
    // 原义「守护页紧贴栈底」核对。`==` 比较仅保留在 debug 档：release 该
    // 表达式不编译，规避上述 LLVM 折叠；跨度断言已承担同义防漂移职责。
    debug_assert!(base == guard_top, "guard page must abut stack base");
}

/// 真正的内核入口：先切换到自己的大栈，再进入 kmain 主体。
/// Limine 跳转到的 `kmain`（见下方 no_mangle 函数）会做栈切换。
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // 切换到我们自己的大栈（链接器符号 __kstack_top）。
    unsafe {
        core::arch::asm!(
            "mov {stack}, rsp",
            "mov rsp, {stack_top}",
            stack = out(reg) _,
            stack_top = in(reg) (core::ptr::addr_of!(__kstack_top) as usize),
            options(nostack),
        );
    }
    unsafe { kmain_body() }
}

/// kmain 主体（在自备大栈上运行）。
unsafe fn kmain_body() -> ! {
    // 初始化 panic 子系统（注入架构名和停机函数，尽早）
    panic::init(CurrentArch::name(), CurrentArch::halt);

    // MD4：快照内核根页表（此刻 CR3 指向 Limine 建立的内核表，且尚无任何
    // 用户地址空间存在）。此后所有进程表的高半区都派生自它——销毁活动地址
    // 空间前切回此表即可安全归还顶层页表，不再慢性泄漏。必须在任何
    // activate() 之前；重复调用会被 debug_assert 拦下。
    arch_x86_64::paging::snapshot_kernel_root();

    // 初始化堆分配器（按需映射动态堆）——必须在任何 alloc 前
    klib::allocator::init();

    // 初始化架构（串口等）
    CurrentArch::init();
    // 注入 panic 平台辅助：回退串口（独立于 klib console 层，确保早期 panic 可见）、
    // CPU id（LAPIC 未映射时返回 0，避免读未映射寄存器二次 #PF）、屏幕输出，
    // 以及 panic 入口的静默动作（本 CPU 关中断，KA1）。
    panic::set_panic_output(
        arch_x86_64::serial::write_str as fn(&str),
        panic_cpu_id,
        term::write_str as fn(&str),
    );
    panic::set_panic_quiesce(
        <arch_x86_64::interrupt::X86InterruptController as InterruptController>::disable,
    );
    // 显示前置要素（堆分配器 + Limine framebuffer + 驱动框架）均已就绪：
    // 立即启动 framebuffer 终端，比任何 test 都靠前，方便屏幕实时看日志。
    init_display();
    // T5/T6：初始化设备/驱动框架（ADR-008）：注册串口设备 + 驱动并探测。
    // 串口驱动 `init` 在此完成统一 console 串口 sink 的注册（不再手动接线），
    // 此后所有内核日志先汇聚到 console 再转发。
    drivers::init();
    // term1 T8：产品横幅由调用方持有（表现层库不做产品文案），经统一
    // console 下发——串口与屏幕同步可见。
    klib::console::write_str("Hello, BORUIX!\r\n");
    klib::console::write_str("Kernel M0 is running.\r\n");
    info!(
        "[kmain] serial & driver hub initialized (arch={})",
        CurrentArch::name()
    );

    // T4：探测 CPU 特性（CPUID/vendor/brand；BSP 单线程阶段，结果缓存到静态）。
    arch_x86_64::cpu::init();
    // 开启 SMEP/SMAP（内核/用户地址空间严格隔离）。须在分页已启用、长模式下、
    // 任何内核访问用户内存之前调用；内核访问用户缓冲区（syscall 参数拷贝等）
    // 已由 STAC/CLAC 包裹，SMAP 下安全放行。
    arch_x86_64::cpu::enable_smep_smap();
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
    #[cfg(feature = "kernel-tests")]
    tests::test_frame_alloc();

    // 注入页表页分配器/释放器（KA5：HHDM 偏移不再经死参数传递——它由
    // mm::init 从 Limine HHDM response 写入 arch::PHYS_OFFSET，paging::init
    // 内部以 debug_assert 固化"已就绪"前置，顺序回归即刻可见）。
    arch_x86_64::paging::init(mm::mapper::mm_alloc_frame, mm::mapper::mm_dealloc_frame);

    // KA3：内核栈守护页生效三步——
    // ① 复核链接器布局与 Rust 预期一致；
    // ② 注册内核态 #PF 检查器（识别守护页命中并显式停机报告）；
    // ③ 解映射守护页。必须放在 paging::init 之后：Limine 以 2MB 大页映射
    //    内核映像，解映射单页需要 unmap 的**大页拆分**能力，而拆分要分配
    //    页表页帧——帧分配注入完成前调用必然失败。
    // 此后派生的所有进程页表继承该空洞，守护对所有执行流生效。
    assert_stack_layout();
    arch_x86_64::interrupts::register_kernel_fault_inspector(kernel_fault_inspect);
    {
        use arch::PageTable as _;
        let guard_base = core::ptr::addr_of!(__kstack_guard_base) as u64;
        // 包装当前活动页表（CR3）执行解映射；unmap 内含 TLB 失效（AM6）。
        let mut pt = <arch_x86_64::paging::X86PageTable as arch::ActivePageTable>::current();
        // 解映射失败即启动失败：守护页失效等价于放弃溢出检测面，宁可不带病运行。
        pt.unmap(arch::VirtAddr::new(guard_base))
            .expect("failed to unmap kernel stack guard page");
        klib::info!(
            "[kmain] kernel stack guard armed at {:#x}..{:#x}",
            guard_base,
            core::ptr::addr_of!(__kstack_guard_top) as u64
        );
    }
    // T7：验证 4KB 页级通用 MMIO 映射（PCI BAR 等任意对齐小块设备寄存器用）。
    // 映射 VGA 文本缓冲（物理 0xB8000，4KB 对齐）到高半区虚拟地址并读写确认。
    // 需在 paging::init 之后（依赖页表页分配器注入）。
    arch_x86_64::mmio::test_map_phys_4k();

    // T3：初始化 HPET（高精度事件定时器）——ACPI 探测（基址/周期）+ 4KB MMIO
    // 映射 + 使能计数器，提供微秒级高精度单调时钟补充。ACPI 表在
    // acpi::init() 已解析（hpet_info）；映射依赖页表页分配器（paging::init）。
    // HPET 为备选：主时钟源仍是 LAPIC 100Hz，无 HPET 时优雅降级。
    {
        match acpi::hpet_info() {
            Some((hpet_base, hpet_period)) => {
                let _ready = arch_x86_64::hpet::init(hpet_base, hpet_period);
            }
            // KM11：无 HPET 表是独立状态（Option），不再以 (0,0) 哨兵表达。
            None => info!("[kmain] no HPET table; keeping LAPIC timer as sole clock source"),
        }
    }
    // 验证虚拟内存页表映射
    #[cfg(feature = "kernel-tests")]
    tests::test_paging();
    // M1：验证用户地址空间（独立页表 + 用户映射 + 切换）
    #[cfg(feature = "kernel-tests")]
    tests::test_user_address_space();
    // KA7 第二层（RLIMIT_AS 语义）：区域总量配额——超限 NoSpace、拒绝零副作用。
    #[cfg(feature = "kernel-tests")]
    tests::test_user_addr_quota();
    // M1.3：验证按需分页（demand paging：#PF → 补页）
    #[cfg(feature = "kernel-tests")]
    tests::test_demand_paging();
    // M1.4：验证进程地址空间内部分配器（栈/mmap/brk）
    #[cfg(feature = "kernel-tests")]
    tests::test_address_space_alloc();
    // M2：验证 CPU 上下文切换（switch_to 交替执行）
    #[cfg(feature = "kernel-tests")]
    tests::test_context_switch();
    // M3.1：验证进程结构与进程表（PCB + pid 分配/回收）
    #[cfg(feature = "kernel-tests")]
    tests::test_process_table();

    // 验证堆分配器（支持释放/重用）
    #[cfg(feature = "kernel-tests")]
    tests::test_heap();

    // 初始化 Local APIC 定时器（Limine 已启用 LAPIC，硬件中断走 APIC）
    info!("[kmain] enabling interrupts (LAPIC timer ~100Hz)");
    arch_x86_64::lapic::init();
    <arch_x86_64::interrupt::X86InterruptController as InterruptController>::enable();

    // 短暂等待验证时钟中断确实触发
    #[cfg(feature = "kernel-tests")]
    tests::test_timer();

    // T4：验证 CPU 特性探测（CPUID/vendor/brand）与熵池/PRNG（RDRAND/RDSEED）。
    // 不依赖 LAPIC tick（熵源与时钟垫底在 serial init 后已就绪），放在
    // time 测试之前，避免 QEMU/TCG 偶发的 LAPIC 校准偏差阻塞本梯队验收。
    #[cfg(feature = "kernel-tests")]
    tests::test_cpu_entropy();

    // 时钟源已注入：验证单调时钟换算 + 打印 RTC 墙钟（真实年月日时分秒）。
    let rtc = arch_x86_64::rtc::read_time();
    info!(
        "[kmain] RTC wall clock {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        rtc.year, rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second
    );
    // 此时 LAPIC 定时器已注入时钟源，now_* 必为 Some。
    info!(
        "[kmain] monotonic clock ready: now={} ns ({} ms since boot)",
        klib::time::now_nanos().expect("clock ready at kmain log"),
        klib::time::now_millis().expect("clock ready at kmain log")
    );
    // 验证 arch::Timer 抽象（now/sleep/set_timeout），依赖 LAPIC tick 驱动。
    #[cfg(feature = "kernel-tests")]
    tests::test_time_abstraction();

    // 验证 sleep_nanos 真实阻塞（后台作业 sleep 正确性前提）。
    #[cfg(feature = "kernel-tests")]
    tests::test_sleep_accuracy();

    // T3：验证 HPET 高精度事件定时器（备选时钟源）：计数器推进/周期换算/
    // 单调性/与 LAPIC tick 对齐。HPET 已在 paging::init 后初始化。
    #[cfg(feature = "kernel-tests")]
    tests::test_hpet();
    // 审计 B25：ACPI 表解析（FADT 短表分级 + HPET 布局探测）真固件端到端断言。
    #[cfg(feature = "kernel-tests")]
    tests::test_acpi_parse_tables();

    // S33 量化验收（mm1.md benchmark 设施立项）：PMM 标准负载基准——
    // 结构断言定成败，时延/时钟换算指标如实打印供审阅。以 HPET 为测量钟，
    // 故排在 test_hpet 之后。
    #[cfg(feature = "kernel-tests")]
    tests::test_pmm_bench();

    // T7 / ADR-007：验证 arch::InterruptController trait 与底层 IRQ 表/中断
    // 开关联动（同一份状态，不重复实现）。依赖中断已使能。
    #[cfg(feature = "kernel-tests")]
    tests::test_arch_interrupt_controller_trait();

    // T7：验证通用 IRQ 注册/分配（共享中断）：IRQ0 上已有 LAPIC 定时器 handler，
    // 再注册观察者共享同一 IRQ，验证多 handler 分发互不干扰。依赖 tick 运行。
    #[cfg(feature = "kernel-tests")]
    tests::test_shared_irq();

    // T7：验证嵌套控制与优先级：每 IRQ 软件优先级 + 全局嵌套开关，
    // 高优先级可打断低优先级处理、低优先级不能打断高优先级。依赖 tick 运行。
    #[cfg(feature = "kernel-tests")]
    tests::test_nested_irq_priority();

    // M2.5.4：从内核 iretq 进入用户态（Ring 3）执行一段用户代码并返回内核。
    // 依赖中断使能（int 0x80 软中断）与用户段 GDT，故放在定时器验证之后。
    // M3.2/M3.3：通过进程对象 spawn + 进入用户态；用户态异常被"进程终止"处理。
    // （M3.2 的正常 int 0x80 退出流程已单独验证，此处演进为异常上抛场景。）
    // M3.3 为停机验收（跑完即停、不返回主流程），故单独用 kernel-test-m33
    // feature 门控：仅 SDK `--test-m3.3` 显式启用时才执行。
    #[cfg(feature = "kernel-test-m33")]
    tests::test_spawn_user_fault();

    // M4.1：注册 syscall 软中断入口（用户态 `int 0x80` → 内核 syscall 分发）。
    // 经 ADR-007 的 `arch::SyscallEntry` 抽象接入：x86-64 层把 `int 0x80`
    // 的 `InterruptFrame` 翻译成可移植 `SyscallFrame` 后调用本入口。
    // 与 `mod syscall` 同步 gate：生产构建（无 kernel-tests）不编译 syscall 机制。
    <arch_x86_64::syscall::X86SyscallEntry as SyscallEntry>::register(syscall::syscall_entry);

    // M4.1 syscall 验收：用户代码经 `int 0x80` 调用 write/exit 等（停机验收，
    // 不返回主流程），故单独用 kernel-test-m41 feature 门控。
    #[cfg(feature = "kernel-test-m41")]
    tests::test_syscall();

    // 注册运行时用户进程的缺页处理函数（处理用户态按需分页与 COW）。
    mm::user_space::set_page_fault_handler(task::process_page_fault_handler);

    // 初始化 IPC 与 Task 调度粘合
    ipc_init::init_ipc();

    // M4.2：注册调度器 tick（LAPIC IRQ0 每 10ms 触发 → RR 轮转）。
    // 生产化后无条件注册（用户进程依赖 tick 轮转）；仅在 BSP 上生效（arch 层过滤）。
    arch_x86_64::interrupts::register_scheduler_tick(task::tick);

    // M4.2 调度验收：多进程 RR 轮转（停机验收，不返回主流程），单独 gate。
    #[cfg(feature = "kernel-test-m42")]
    tests::test_scheduler();

    // M4.3 静态 ELF 加载验收：解析并加载 ELF 镜像到用户空间，spawn 运行
    // （停机验收，不返回主流程），单独 gate。
    #[cfg(feature = "kernel-test-m43")]
    tests::test_elf_loader();

    // M4.4 真实用户程序验收：加载 libsys+init 编译出的真实 ELF（停机验收，
    // 不返回主流程），单独 gate。
    #[cfg(feature = "kernel-test-m44")]
    tests::test_userspace_elf();

    // M5 写时复制（COW）：`clone_cow` 派生共享用户区的子地址空间（纯内存
    // 逻辑验收，不进入用户态、不依赖 tick，返回主流程继续启动）。单独 gate。
    #[cfg(feature = "kernel-test-m5")]
    tests::test_cow_clone();
    #[cfg(feature = "kernel-test-m5")]
    tests::test_ipc();
    #[cfg(feature = "kernel-test-m5")]
    tests::test_process_reclaim();

    // M6.1：初始化 VFS 根挂载表与 RESTful 目录骨架。
    vfs_init::init();

    // KM1：标准流数据链路接线——stdin 源 = 键盘缓冲、stdout/stderr sink =
    // console。此后 fd 0/1/2 是每进程 fd 表内的真实句柄，syscall 层无任何
    // fd 号特判。
    vfs::stdio::set_stdin_source(stdin_source);
    vfs::stdio::set_stdout_sink(klib::console::write_bytes);

    // vfs1 A2/D4（ADR-023 §1/§7）：全局页缓存与 RamFS 内存水位钩子接线。
    // - 全局缓存注入后，一切 FileHandle 写都经 write_cached 写穿并作废受
    //   影响缓存块——失效一致性策略的唯一合法写通道自此闭合；
    // - 水位钩子以 mm 紧急预留池真值为信号（低于容量 1/4 = 紧张），RamFS
    //   大跨度增长据此先驱逐缓存再试，仍紧张如实 OutOfMemory。
    {
        use core::sync::atomic::{AtomicBool, Ordering};
        static KERNEL_PAGE_CACHE: spin::Once<vfs::PageCache> = spin::Once::new();
        let cache: &'static vfs::PageCache =
            KERNEL_PAGE_CACHE.call_once(|| vfs::PageCache::new());
        vfs::set_global_page_cache(cache);

        /// 紧张阈值：紧急池容量（mm RESERVE_CAP_PAGES=32）的四分之一。
        /// 低于它说明分配器已在吃兜底页，继续放任堆增长是自欺。
        const RESERVE_TIGHT_FLOOR_PAGES: usize = mm::frame_allocator::RESERVE_CAP_PAGES / 4;
        static WATERMARK_WARNED: AtomicBool = AtomicBool::new(false);
        vfs::set_ramfs_memory_tight_hook(|| {
            let count = mm::frame_stats().reserve_count;
            if count < RESERVE_TIGHT_FLOOR_PAGES
                && !WATERMARK_WARNED.swap(true, Ordering::Relaxed)
            {
                klib::warn!(
                    "[vfs] memory watermark tight: reserve pool {} < {} pages",
                    count,
                    RESERVE_TIGHT_FLOOR_PAGES
                );
            }
            count < RESERVE_TIGHT_FLOOR_PAGES
        });
    }

    // 审计 B14/B21：SYS_MEMORY_QUERY 全链路覆盖 + stdin Busy→EAGAIN 语义 +
    // fd 表 MAX_FDS 上限拒绝。（必须在 stdio 接线之后：B21 臂依赖真实的
    // stdin 源——接线前 StdinNode 读路径如实 NotSupported。）
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_memquery_and_stdin_busy();

    // 运行 M6.1 / M6.2 / M6.3 / M6.4 / M6.5 VFS 自检测试（在 kernel-tests feature 启用时）。
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m61();
    // ADR-012 §3.2.1：卷重名冲突自动自增后缀（卷重名消解）。
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_volume_collision();
    // 词法规范 v2（ADR-005）命名 linter：根命名空间词表契约。
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_lexicon();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m62();
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_std_stream_close();
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_munmap();
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_usercopy_faults();
    // S19：顺序读写超过单块上限不得截断（>1MiB 顺序 write 回绕短交付回归）。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_seq_large_io();
    // ADR-014 SYS_ENTRY_UPDATE (0x43)：move/rename 节点。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_entry_update();
    // ADR-014 SYS_STREAM_CREATE FLAG_PIPE (0x11)：匿名管道端。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_pipe();
    // ADR-014 SYS_ENTRY_READ (0x42)：标准紧凑 JSON 输出。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_entry_read_json();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m63();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m64();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m65();
    #[cfg(feature = "kernel-tests")]
    tests::test_driver_hub_m72();
    #[cfg(feature = "kernel-tests")]
    tests::test_ata_tail_probe();

    // C7.1/#7：waitpid 核心机制单测（纯表级，返回主流程继续启动）。
    #[cfg(feature = "kernel-tests")]
    tests::test_waitpid_core();

    // PID 1 契约验收（WAIT_ANY / PID 1 防护 / 孤儿过继，纯表级）。
    #[cfg(feature = "kernel-tests")]
    tests::test_init_contract();

    // task1：K1 抢占门控（ADR-017）/ K3 内核栈回收 / K2 FPU 隔离
    // （纯表级 + 钩子驱动，返回主流程继续启动）。
    #[cfg(feature = "kernel-tests")]
    tests::test_task_tick_gate();
    #[cfg(feature = "kernel-tests")]
    tests::test_task_kstack_reclaim();
    #[cfg(feature = "kernel-tests")]
    tests::test_task_fpu_isolation();
    #[cfg(feature = "kernel-tests")]
    tests::test_task_block_fpu_handoff();
    #[cfg(feature = "kernel-tests")]
    tests::test_ipc1_semantics();

    // S26 回归：block_current_with 登记点失败时已弹出的就绪进程必须重新入队。
    // KS1: 必须放在 test_task_kstack_reclaim 之后，否则该测试的帧计数
    // 对前序 spawn 敏感（顺序依赖）。
    #[cfg(feature = "kernel-tests")]
    tests::test_block_register_false_keeps_ready();

    // loader1/LA4：ELF 加载器恶意镜像拒绝面对抗自检（纯加载验证，不 spawn，
    // 返回主流程继续启动；放在 SMP 之前保持单核确定性）。
    #[cfg(feature = "kernel-tests")]
    tests::test_loader_adversarial();

    // drv1 整改自检（ADR-022）：注册表契约/候选呈现/事件丢弃账目。
    // **必须位于测试序列末位**——驱动表填满验证不可逆（见函数文档）。
    #[cfg(feature = "kernel-tests")]
    tests::test_drv1_remediation();

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
    // KD4：AP 上线等待上界常量化。时基是 LAPIC 定时器真实时间；2s 足够
    // 覆盖 TCG 慢速启动与真机 INIT-SIPI 延迟，超时按实际在线数降级继续。
    const AP_ONLINE_TIMEOUT_MS: usize = 2_000;
    let online = arch_x86_64::smp::wait_all_online(total, AP_ONLINE_TIMEOUT_MS);
    info!(
        "[kmain] SMP done, {} cpus online (target {})",
        online, total
    );

    // MA1b：IPI 邮箱接线——跨核 per-CPU 缓存排空。mm 保持架构中立，经
    // 函数指针注入投递通道（LAPIC Fixed ICI + 槽位反查）；目标核侧的
    // "排空本核缓存"回调注册进 arch 中断分发（向量 0x40）。须在 SMP 完成
    // 之后注册，保证所有槽位的 LAPIC id 反查已就绪。
    mm::set_remote_drain(remote_drain_via_ipi);
    arch_x86_64::interrupts::register_ipi_handler(mm::ipi_drain_current_cpu);

    // KA1：panic 跨核停机接线（向量 0x41）——诊断输出前停住其它在线核，
    // 防止它们继续分配/拿锁/交错输出。同样依赖 SMP 完成后的槽位反查。
    panic::set_cross_core_halt(halt_other_cpus_via_ipi);

    // 内核全部组件加载完成（测试若开启也已全部通过）：打印版本横幅。
    info!("============================================================");
    info!("BORUIX KERNEL v.{}", env!("CARGO_PKG_VERSION"));
    info!("Git Commit: {}", env!("BORUIX_GIT_COMMIT"));
    info!("Build Timestamp: {}", env!("BORUIX_BUILD_TIMESTAMP"));
    info!("============================================================");
    // KM13：符号表快照溯源。直连 cargo build 会使用 checked-in 快照——
    // .text 布局漂移后 panic 回溯给出错误函数名，比空表更有害；此处如实
    // 告警而非静默放行。SDK 构建路径两遍编译同纪元，不触发。
    if symbols::snapshot_stale() {
        warn!(
            "[kmain] symbol snapshot stale (epoch {} != build {}): panic backtrace \
             names may be wrong; rebuild via SDK (`sdk.main.py build`) to refresh",
            symbols::SYMBOLS_EPOCH,
            env!("BORUIX_SYMBOLS_BUILD_EPOCH")
        );
    }

    // 阶段 B：使能外部中断路由（IMCR 切回 PIC 模式，8259 输出经 LINT0 进
    // LAPIC）并初始化 PS/2 8042 键盘驱动（注册 IRQ1 handler → 扫描码译码 →
    // 输入缓冲）。放在所有测试之后（避免干扰 LAPIC tick 时序测试）、进入
    // init 之前，使 shell REPL 能接收键盘输入。
    // AD2：原 `ioapic::init` 改名 `imcr::switch_to_pic_mode`——该调用从不
    // 编程 I/O APIC，真实职责只有 IMCR 切换。
    arch_x86_64::imcr::switch_to_pic_mode();
    // IMCR 切到 PIC 模式会让 QEMU 重置 8259 掩码，须在切换后重新解屏蔽键盘
    // IRQ1（其余保持屏蔽：IRQ0 timer 由 LAPIC 接管）。否则键盘中断被 8259 屏蔽。
    // KD4：掩码位型常量化——8259 掩码寄存器按位取"1=屏蔽"，仅清 IRQ1 位。
    const PIC_MASK_ALL_EXCEPT_IRQ1: u16 = !(1u16 << 1);
    arch_x86_64::pic::set_mask(PIC_MASK_ALL_EXCEPT_IRQ1);
    arch_x86_64::keyboard::init();
    // 注册键盘输入回调：有按键时唤醒阻塞在 `read` 的进程（如 shell）。arch 层
    // 不反向依赖 kernel，经函数指针解耦（指向 `task::wake_kbd`）。
    arch_x86_64::keyboard::set_input_callback(task::wake_kbd);

    // C7.1/#7：waitpid 真实父子链停机验收（kernel-test-waitpid 显式启用；
    // 验收后停机、不返回主流程，故必须放在 start_init 之前）。
    #[cfg(feature = "kernel-test-waitpid")]
    tests::test_waitpid_e2e(); // 永不返回

    // 生产化：进入用户态 init（PID 1），而非内核 idle 停机。加载 init.elf →
    // spawn → `scheduler::start` 永不返回；init 经 syscall 与内核交互、退出。
    start_init();
}

/// 尽早启动 framebuffer 终端显示（显示前置要素就绪后立即调用，早于一切测试）。
///
/// 前置要素（均已在调用前完成）：
/// - `klib::allocator::init()`：flanterm 上下文需要堆分配；
/// - Limine framebuffer 请求：bootloader 已将 framebuffer 映射进页表，可直接写；
/// - 驱动框架（`drv` 静态注册表）：无需额外初始化；
/// - `panic::set_panic_output`：早期 panic 的屏幕输出已接线。
///
/// 成功初始化后，屏幕 sink 注册进 console，后续所有内核日志同时输出到串口与屏幕。
// KA3：内核态 #PF 检查器——CR2 落在守护页即"内核主栈向下溢出"。
// 返回 true 表示已处置（裸串口报告 + 停机），中断分发不再走通用致命路径。
// 裸串口输出：溢出现场可能正是 console/堆/锁损坏，诊断必须走最短依赖路径
// （与 AM7 同一纪律）。
fn kernel_fault_inspect(cr2: u64) -> bool {
    let gbase = core::ptr::addr_of!(__kstack_guard_base) as u64;
    let gtop = core::ptr::addr_of!(__kstack_guard_top) as u64;
    if cr2 >= gbase && cr2 < gtop {
        arch_x86_64::serial::write_str(
            "\n========== KERNEL STACK OVERFLOW ==========\n",
        );
        arch_x86_64::serial::write_str("kernel main stack guard page hit (downward overflow)\n");
        arch_x86_64::serial::write_str("===========================================\n");
        CurrentArch::halt();
    }
    false
}

// MA1b：跨核排空投递适配——槽位 → LAPIC id 反查后发 Fixed IPI（向量 0x40）。
// 返回 false = 槽位未上线或发送队列超限，mm 侧按"跳过该核"降级。
fn remote_drain_via_ipi(slot: usize) -> bool {
    match arch_x86_64::smp::lapic_id_of_slot(slot) {
        Some(lapic_id) => arch_x86_64::lapic::send_fixed_ipi(lapic_id, arch_x86_64::interrupts::IPI_VECTOR),
        None => false,
    }
}

// KA1：panic 跨核停机——向除本核外的全部已上线槽位广播停机 IPI（0x41）。
// 发送失败（目标失联）静默跳过：panic 路径上无法恢复，诊断照常输出。
fn halt_other_cpus_via_ipi() {
    let me = arch_x86_64::lapic::current_lapic_id();
    let count = arch_x86_64::smp::cpu_count();
    for slot in 0..count {
        if let Some(id) = arch_x86_64::smp::lapic_id_of_slot(slot) {
            if id != me {
                let _ = arch_x86_64::lapic::send_fixed_ipi(
                    id,
                    arch_x86_64::interrupts::IPI_HALT_VECTOR,
                );
            }
        }
    }
}

// KM1：stdin 批量源适配——把键盘单字符 pop 排空进调用方缓冲，返回读取
// 字节数（0 = 缓冲空，vfs::stdio::StdinNode 据此返回 WouldBlock）。
//
// DM5 单一消费点纪律（ADR-022 §8）：键盘队列唯一合法消费点是 DriverHub
// 注册的 ps2-keyboard 设备 read。stdin 经 Hub 按名转发到同一扇门。
//
// S14 显式降级策略：设备缺席（框架未就绪等）时回退直连 arch pop，且
// 仅此一次告警。两条路径**互斥**——Hub 命中即 return，绝不落到回退，
// 故不存在同一数据源被两条消费点并发排空的竞态；回退仅在 ps2-keyboard
// 注册之前的早期阶段可达（届时 Hub 尚未登记该设备）。内核内部不存在
// 第二条绕过设备的隐藏通道。
fn stdin_source(buf: &mut [u8]) -> usize {
    use driver::drivers::keyboard::PS2_KEYBOARD_DEVICE_NAME;

    let count = driver::DriverHub::device_count();
    for i in 0..count {
        if let Some(info) = driver::DriverHub::device_info_at(i) {
            if info.name == PS2_KEYBOARD_DEVICE_NAME {
                if let Some(ops) = driver::DriverHub::device_at(i) {
                    return ops.read(buf);
                }
            }
        }
    }
    static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);
    if !FALLBACK_WARNED.swap(true, Ordering::SeqCst) {
        warn!(
            "[stdin] '{}' not found in DriverHub; falling back to direct keyboard queue",
            PS2_KEYBOARD_DEVICE_NAME
        );
    }
    let mut n = 0usize;
    while n < buf.len() {
        match arch_x86_64::keyboard::pop() {
            Some(ch) => {
                buf[n] = ch;
                n += 1;
            }
            None => break,
        }
    }
    n
}

fn init_display() {
    // 获取 framebuffer（limine 0.1: get_response() 返回 Ptr<FramebufferResponse>）
    let Some(resp) = FRAMEBUFFER_REQUEST.get_response().get() else {
        error!("[display] no framebuffer response");
        return;
    };
    info!("[display] framebuffer response received");
    let Some(fb) = resp.framebuffers().first() else {
        error!("[display] no framebuffer");
        return;
    };
    let fb = &**fb; // NonNullPtr<Framebuffer> -> Framebuffer
    info!(
        "[display] framebuffer {}x{} pitch={} bpp={}",
        fb.width, fb.height, fb.pitch, fb.bpp
    );
    // T6：把 framebuffer 登记为框架设备并绑定 framebuffer 驱动；
    // 驱动 init 在此完成 flanterm 终端初始化与屏幕 sink 注册（不再手动接线）。
    drivers::register_framebuffer(fb);
    info!("[display] terminal init returned");
}

/// 从 /programs/<name> 经 VFS 读出完整文件内容；任何失败返回 None（可见、不伪造）。
/// KM3：原 program_elf(idx) 已删除——它与 sys_exec 小索引模式解析同一路径，
/// 回退链是死亡分支；内建程序加载统一走 sys_exec 的 VFS 路径。
pub fn read_binary_from_programs(name: &str) -> Option<alloc::vec::Vec<u8>> {
    let root = crate::vfs_init::root();
    let path = alloc::format!("/programs/{}", name);
    let node = root.resolve(&path, true).ok()?;
    let size = node.metadata().ok()?.size as usize;
    if size == 0 {
        return None;
    }
    // S31：按 metadata().size 无界分配内核堆——超大文件（含损坏元数据声称的
    // 巨尺寸）会 OOM abort。显式上限与 sys_exec 的 MAX_SYSCALL_BUF_BYTES
    // 同源（64 MiB），超限即拒绝加载，绝不无界分配。
    const MAX_PROGRAM_BYTES: usize = 64 * 1024 * 1024;
    if size > MAX_PROGRAM_BYTES {
        klib::error!(
            "[programs] {} exceeds max loadable size {} bytes (declared {}), rejected",
            path,
            MAX_PROGRAM_BYTES,
            size
        );
        return None;
    }
    let mut buf = alloc::vec![0u8; size];
    let n = node.read_at(0, &mut buf).ok()?;
    // KM4：短读不是部分成功——元数据声称 size 字节而设备只交付 n<size 时
    // 显式报错（错误可见），绝不静默截断后把残缺镜像喂给 ELF 加载器。
    if n != size {
        klib::error!(
            "[programs] short read on {}: metadata size={} but device returned {}",
            path,
            size,
            n
        );
        return None;
    }
    Some(buf)
}

/// ADR-017 双源读取：先经 VFS `/programs/<name>` 读取（外部盘挂载时读到
/// 盘内容，盘优先）；VFS 不可得（盘遮蔽但盘中缺该文件 / 无盘但 payload
/// 缺失）时回退到构建期内置 liveCD payload。两源皆缺返回 None。
///
/// 这不是 KM3 禁止的"同路重试"：KM3 删的是"同一 /programs 路径 resolve
/// 两次"的死亡分支（必然同样失败）；此处两源是**不同数据载体**（VFS/
/// 磁盘 vs 内核静态内存），回退有真实语义。回退经 warn 日志如实披露
/// （S10：来源不捏造、不静默）。
pub fn read_binary_dual_source(name: &str, builtin: &'static [u8]) -> Option<alloc::vec::Vec<u8>> {
    if let Some(v) = read_binary_from_programs(name) {
        return Some(v);
    }
    if builtin.is_empty() {
        return None;
    }
    klib::warn!(
        "[programs] {} unavailable via /programs; falling back to built-in liveCD payload ({} bytes)",
        name,
        builtin.len()
    );
    Some(builtin.to_vec())
}

/// panic 时的 CPU id 读取器：LAPIC 已映射才读，否则返回 0（早期未就绪安全）。
fn panic_cpu_id() -> u32 {
    if arch_x86_64::lapic::is_mapped() {
        arch_x86_64::lapic::current_lapic_id()
    } else {
        0
    }
}

/// 生产化启动：加载 init 用户程序（PID 1）并进入调度器，永不返回。
///
/// init.elf 由 SDK 在构建时编译 `libsys` + `init` 生成，经磁盘链路加载
/// （KD1 修正：旧注释称"经 include_bytes! 编译期嵌入"——嵌入副本已退役，
/// 现存 include_bytes! 仅在 test_userspace_elf 测试中引用 ../init.elf）。
/// 流程：解析 ELF → 装载到用户地址空间 → `scheduler::spawn`
/// 创建 PID 1 → `scheduler::start` 进入 init 用户态（tick 轮转，init 经 syscall
/// 交互/退出）。init 加载/生成任一环节失败则回退到内核 idle 循环停机（错误
/// 可见，不 panic）——保证启动失败时行为可观测、不静默。
fn start_init() -> ! {
    use arch_x86_64::paging::X86PageTable;
    use mm::user_space::UserAddressSpace;

    info!("[kmain] booting user init (PID 1) ...");
    // ADR-017（liveCD）：init.elf 双源——构建期内置 payload 垫底（ramfs
    // /programs，无盘可启动）；外部盘（disk.img → ATA → MBR → EXT2）挂载
    // 成功后将其遮蔽（盘优先），盘中缺失该文件时经 read_binary_dual_source
    // 文件级回退内置（数据盘插上不会搞挂 liveCD）。两源皆缺才失败并 idle
    // 停机（错误可见、不 panic）。
    let Some(elf_bytes) = read_binary_dual_source("init.elf", crate::binaries_payload::INIT_ELF) else {
        error!("[kmain] init: /programs/init.elf unavailable (neither built-in liveCD payload nor external disk)");
        info!("[kmain] reached idle loop");
        CurrentArch::halt();
    };
    info!(
        "[kmain] init: loaded {} bytes of init.elf from /programs",
        elf_bytes.len()
    );

    let mut us = match UserAddressSpace::<X86PageTable>::new() {
        Ok(us) => us,
        Err(e) => {
            error!("[kmain] init: new user address space failed: {:?}", e);
            info!("[kmain] reached idle loop");
            CurrentArch::halt();
        }
    };
    let loaded = match loader::load(&elf_bytes, &mut us, &[]) {
        Ok(l) => l,
        Err(e) => {
            error!("[kmain] init: load init.elf failed: {:?}", e);
            info!("[kmain] reached idle loop");
            CurrentArch::halt();
        }
    };
    info!(
        "[kmain] init: entry={:#x} stack_top={:#x}",
        loaded.entry, loaded.user_stack_top
    );
    let pid = match task::spawn("init.elf", loaded.entry, loaded.user_stack_top, us) {
        Ok(p) => p,
        Err(e) => {
            error!("[kmain] init: spawn failed: {:?}", e);
            info!("[kmain] reached idle loop");
            CurrentArch::halt();
        }
    };
    info!("[kmain] init: spawned pid={} from init.elf", pid);
    // 登记 init PID（PID 1 契约使用）。
    task::set_init_pid(pid);
    // 启动调度器（永不返回）：进入 init 用户态，tick 轮转，init 经 syscall 退出。
    task::start();
}
