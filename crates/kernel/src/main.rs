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

// 请求内核文件信息（ADR-029 M2.1：boot 来源检测）。
//
// Limine 12.5.2 协议里不存在 `BootVolumeRequest`——boot 来源经
// `KernelFileRequest` 的响应 `File` 携带：`media_type`（1=optical 即 ISO
// 启动，0=generic 即磁盘启动）、`partition_index`（1-based 分区号）、
// `mbr_disk_id`（MBR 盘签名 @0x1B8）。这是 ADR-029 落地前实核对结论。
#[limine::limine_tag]
static KERNEL_FILE_REQUEST: limine::KernelFileRequest = limine::KernelFileRequest::new(0);

/// Limine `File.media_type` 值（`common/protos/limine.c` 的 `get_file`）。
/// 0=generic（磁盘/可引导分区）、1=optical（ISO/CD）、2=tftp。
const LIMINE_MEDIA_GENERIC: u32 = 0;
const LIMINE_MEDIA_OPTICAL: u32 = 1;

/// boot 来源（ADR-029 §决策3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSource {
    /// 从 ISO/CD 启动（media_type=optical）→ liveCD 模式，root 为 RAMFS。
    LiveCd,
    /// 从磁盘启动（media_type=generic）→ 安装模式，启动盘分区为 root。
    /// 携带 MBR 盘签名（@0x1B8）与 1-based 分区号用于定位本位盘。
    Disk { mbr_disk_id: u32, partition_index: u32 },
    /// 无法判定（未取得内核文件响应）→ 保守退化为 liveCD 兜底。
    Unknown,
}

/// 读取 boot 来源（M2.1）。
///
/// 响应不可得（bootloader 未填）时如实返回 [`BootSource::Unknown`]，由调用方
/// 走 liveCD 兜底——绝不伪造"磁盘启动"（那会导致把错误的盘当系统池挂为
/// 根，S09 宁缺毋假）。
pub fn boot_source() -> BootSource {
    let Some(resp) = KERNEL_FILE_REQUEST.get_response().get() else {
        klib::warn!("[boot] KernelFileRequest response unavailable; falling back to liveCD");
        return BootSource::Unknown;
    };
    let Some(file) = resp.kernel_file.get() else {
        klib::warn!("[boot] kernel_file unavailable; falling back to liveCD");
        return BootSource::Unknown;
    };
    if file.media_type == LIMINE_MEDIA_OPTICAL {
        BootSource::LiveCd
    } else if file.media_type == LIMINE_MEDIA_GENERIC {
        BootSource::Disk {
            mbr_disk_id: file.mbr_disk_id,
            partition_index: file.partition_index,
        }
    } else {
        // tftp(2) 或未知 media_type：本内核只支持 optical/generic，如实降级。
        klib::warn!(
            "[boot] unsupported media_type={}; falling back to liveCD",
            file.media_type
        );
        BootSource::Unknown
    }
}

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

    // S1-11：注册用户态异常 → 信号投递处理器（ADR-034 §2.8）。用户态 #PF/#UD/#GP
    // 若有 handler 则携 siginfo 投递进用户 handler；否则终止进程（不再当内核崩溃）。
    // 注意：`register_user_exception_handler` 是 spin::Once——独立的停机验收构建
    // （kernel-test-m33 / kernel-test-pre2）需要注册各自专用处理器（验证终止语义/
    // CR2 透传），故本生产处理器在这些专用构建里不注册，避免抢占测试处理器。
    #[cfg(not(any(feature = "kernel-test-m33", feature = "kernel-test-pre2")))]
    arch_x86_64::interrupts::register_user_exception_handler(crate::syscall::user_exception_signal_handler);

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

    // STORAGE-AHCI-2：块存储栈在此启动，**必须在 mm::init + paging::init 之后**。
    //
    // 为什么不能放在 `drivers::init()`（上方 line ~215）：块驱动需要分配物理
    // 连续帧（DMA 描述符/数据缓冲）并把 ABAR 映射进内核地址空间，而 DriverHub
    // 的全部阶段都早于内存管理初始化——在那里初始化会撞 `PHYS_OFFSET not
    // initialized` panic（实测复现）。
    //
    // 顺序：AHCI 优先（真 DMA），未找到 SATA 盘时 ATA PIO 接管（兼容路径）。
    let storage_disks = driver::drivers::ahci::late_storage_init();
    info!(
        "[kmain] storage stack ready: {} AHCI disk(s)",
        storage_disks
    );

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
    // 中断现已开启：重新武装 AHCI 的中断完成路径。`late_storage_init` 跑在
    // `sti` **之前**，那段窗口内等不到中断会触发自适应退让；此处让中断优先
    // 在真正可用的阶段重新生效（幂等；无控制器时为空操作）。
    driver::drivers::ahci::rearm_interrupt_completion();

    // SYSCALL-FAST-1：建立 GS per-CPU 地基。
    //
    // **必须在 `lapic::init()` 之后**：槽位来源 `my_cpu_slot()` 依赖 LAPIC 已映射
    // （未映射时恒回退 BSP 槽，会把 AP 错认成 0 号核）。
    //
    // 此刻只建立**地基**（GS base + per-CPU 结构），**不改变**任何既有 per-CPU
    // 访问路径——`my_cpu_slot()` 的裸数组路径原样保留，两条路径由 FAST-1 的
    // 对拍测试验证一致。真正切换到 GS 路径在 FAST-2/4 完成帧与 ABI 之后。
    {
        let slot = arch_x86_64::cpu::my_cpu_slot_array_path();
        // 本核内核栈顶：取当前 RSP 所在栈的基址（`syscall` 入口将切到此栈）。
        let kstack_top = arch_x86_64::cpu::current_kernel_stack_top();
        let ok = arch_x86_64::percpu::init_current(slot, kstack_top);
        if ok {
            info!(
                "[percpu] GS foundation enabled on slot {} (gs_base={:#x}, kstack_top={:#x})",
                slot,
                arch_x86_64::percpu::read_gs_base(),
                kstack_top
            );
        } else {
            // S09：不伪装成功——地基未建立时如实上报，后续 FAST-2/4 依赖它。
            warn!("[percpu] GS foundation NOT enabled (slot {} out of range)", slot);
        }
    }

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
    // 注入 wall clock 源（RTC → Unix epoch 秒）：EXT2 写盘时间戳、任何需要
    // 真实时刻的路径从此刻起可用 `klib::time::wall_clock_secs()`。RTC 时间
    // 无效（字段越界）时 read_epoch_secs 返回 None，wall_clock_secs 亦为 None，
    // 调用方诚实降级（S09：绝不伪造时间）。
    klib::time::set_wall_clock_source(arch_x86_64::rtc::read_epoch_secs);
    if let Some(epoch) = klib::time::wall_clock_secs() {
        info!("[kmain] wall clock epoch = {} (Unix secs)", epoch);
    } else {
        klib::warn!("[kmain] RTC time invalid; wall clock unavailable (EXT2 timestamps fall back to monotonic)");
    }
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

    // ADR-034 PRE-2：用户态 #PF 时 CR2 透传进 user_fault_handler（停机验收，
    // 跑完即停、不返回主流程，故单独 feature 门控）。
    #[cfg(feature = "kernel-test-pre2")]
    tests::test_pre2_cr2_pass_through();

    // M4.1：注册 syscall 软中断入口（用户态 `int 0x80` → 内核 syscall 分发）。
    // 经 ADR-007 的 `arch::SyscallEntry` 抽象接入：x86-64 层把 `int 0x80`
    // 的 `InterruptFrame` 翻译成可移植 `SyscallFrame` 后调用本入口。
    // 与 `mod syscall` 同步 gate：生产构建（无 kernel-tests）不编译 syscall 机制。
    <arch_x86_64::syscall::X86SyscallEntry as SyscallEntry>::register(syscall::syscall_entry);

    // M4.1 syscall 验收：用户代码经 `int 0x80` 调用 write/exit 等（停机验收，
    // 不返回主流程），故单独用 kernel-test-m41 feature 门控。
    #[cfg(feature = "kernel-test-m41")]
    tests::test_syscall();

    // ADR-034 S1-13/S1-11：真实用户态进程捕获信号 → handler → restorer →
    // rt_sigreturn 恢复现场（停机验收，跑完即停，单独 feature 门控）。
    // 须在 syscall 入口注册之后执行（用户代码经 int 0x80 触发投递）。
    // 停机验收互斥：一次 build 只编译并运行一个 halt 测试。由 sdk 的
    // `--test-signal --signal-halt nested|handler|fault` 选择启用哪个 feature。
    #[cfg(feature = "kernel-test-signal-handler")]
    tests::test_signal_handler_called();
    #[cfg(feature = "kernel-test-signal-fault")]
    tests::test_signal_fault_to_handler();
    #[cfg(feature = "kernel-test-signal-nested")]
    tests::test_signal_nested_handler();

    // 注册运行时用户进程的缺页处理函数（处理用户态按需分页与 COW）。
    mm::user_space::set_page_fault_handler(task::process_page_fault_handler);

    // 初始化 IPC 与 Task 调度粘合
    ipc_init::init_ipc();

    // M4.2：注册调度器 tick（LAPIC IRQ0 每 10ms 触发 → RR 轮转）。
    // 生产化后无条件注册（用户进程依赖 tick 轮转）；每个核自己的 IRQ0 都会触发。
    arch_x86_64::interrupts::register_scheduler_tick(task::tick);

    // M4.2 调度验收：多进程 RR 轮转（停机验收，不返回主流程），单独 gate。
    #[cfg(feature = "kernel-test-m42")]
    tests::test_scheduler();

    // SCHED-EEVDF-1：vruntime 时间基准的实测取证（HPET 直读 vs per-CPU TSC）。
    // 放在调度测试之前：它只读时间源、不依赖调度状态，且结论是 2/3 的前提。
    tests::test_sched_eevdf1_time_source_cost();

    // SCHED-EEVDF-2：vruntime 有序就绪队列的契约（TDD 红先行的产物）。
    tests::test_sched_eevdf2_vruntime_queue_contract();

    // SCHED-EEVDF-3：nice 权重语义（纯函数方向 + 端到端接线）。
    tests::test_sched_eevdf3_nice_weights();
    tests::test_sched_eevdf3_nice_affects_scheduling();
    tests::test_sched_eevdf3_interactive_latency();

    // SYSCALL-FAST-1：GS per-CPU 地基（一致性 / 配对性 / 嵌套纪律）。
    tests::test_syscall_fast1_percpu_gs_contract();

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
    // 行缓冲的 CPU 序号来源：接 arch 的当前核槽位（每 CPU 一份缓冲的前提）。
    klib::console::set_line_cpu_hint(arch_x86_64::lapic::my_slot);
    vfs::stdio::set_stdin_source(stdin_source);
    // stdout sink 用**行缓冲**版（修复多核输出互相插行）：
    // 用户程序按片段写（文本/数字/换行分多次 write），write_bytes 的原子
    // 边界是单次调用，另一核的输出会插进一行中间（实测横幅被切成碎片、
    // 提示符里插进 [audiod] 行）。行缓冲把原子边界升到"行"。
    // 内核自己的日志仍走 write_bytes/write_fmt（中断上下文不能持行锁）。
    vfs::stdio::set_stdout_sink(klib::console::write_line_buffered);

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
    // ADR-032 SYNC 域 (0x70)：通用 futex 等待/唤醒 syscall 验收。
    #[cfg(feature = "kernel-tests")]
    tests::test_sync_syscalls();
    // A1/ADR-033 进程身份模型：身份机制单测 + system_only 权限强制停机级验收。
    #[cfg(feature = "kernel-tests")]
    tests::test_identity_inherit();
    #[cfg(feature = "kernel-tests")]
    tests::test_perm_system_only();
    // PRE-1 / ADR-037 决策 5：UIO driver_register/driver_claim 特权门禁（System-only）。
    #[cfg(feature = "kernel-tests")]
    tests::test_driver_uio_privilege_gate();
    // 批次三：AUDIO_ATTACH 特权门禁（System-only，与 UIO 门禁同口径）。
    // 必须**单独**测：启动期测试跑在 init 线程上，而 init 是 System 身份，
    // 天然无法覆盖「非 System 被拒」这条路径（S29）。
    #[cfg(feature = "kernel-tests")]
    tests::test_audio_attach_privilege_gate();
    // 设备 DMA 前端探针：内核态写 BDL/PCM 起 HDA 流，隔离用户态变量。
    #[cfg(all(feature = "kernel-tests", feature = "hda-probe"))]
    tests::test_hda_device_dma_probe();
    // R6 flock：冲突矩阵 + close 自动释放（ADR-014 承诺）。
    #[cfg(feature = "kernel-tests")]
    klib::info!("[boot] before test_flock_matrix");
    #[cfg(feature = "kernel-tests")]
    tests::test_flock_matrix();
    #[cfg(feature = "kernel-tests")]
    tests::test_flock_close_release();
    #[cfg(feature = "kernel-tests")]
    tests::test_flock_syscall();
    // flock 锁身份必须与文件系统实现无关（RamFS 缓存 Arc / EXT2 每次新建）。
    // 须在 test_flock_syscall 之后：两者共用 /scratch 与 uid 空间。
    #[cfg(feature = "kernel-tests")]
    tests::test_flock_identity_is_filesystem_independent();
    // ADR-014 SYS_ENTRY_READ (0x42)：标准紧凑 JSON 输出。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_entry_read_json();
    // ADR-014 SYS_ENTRY_CREATE (0x41)：kind 参数解析。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_entry_create_kind();
    // ADR-014 DRIVER 域补全：0x52 driver_query + 0x54 driver_unregister。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_driver_query_unregister();
    // ADR-014 §4.2 MEMORY_MAP 共享语义。
    #[cfg(feature = "kernel-tests")]
    tests::test_syscall_memory_map_shared();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m63();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m64();
    #[cfg(feature = "kernel-tests")]
    tests::test_vfs_m65();
    #[cfg(feature = "kernel-tests")]
    tests::test_bench_ds32(); // D-S32: cycle-counter + page-cache hit-rate/throughput benchmark
    #[cfg(feature = "kernel-tests")]
    tests::test_driver_hub_m72();
    // A2：音频管道 syscall 域（消费者注册表/两阶段 IO/退出清理）。
    #[cfg(feature = "kernel-tests")]
    tests::test_audio_pipe_a2();
    // 阶段一：设备中断投递基础设施（IRQ 归属表/闩锁/冲突/PCI irq_line 捕获）。
    #[cfg(feature = "kernel-tests")]
    tests::test_driver_irq_owner();

    // STORAGE-AHCI-6a：内核态块驱动的有界中断等待原语。
    #[cfg(feature = "kernel-tests")]
    tests::test_ahci6a_bounded_irq_wait();

    // STORAGE-AHCI-6b：中断驱动完成路径（替代长自旋）。
    #[cfg(feature = "kernel-tests")]
    tests::test_ahci6b_interrupt_completion();

    // STORAGE-AHCI-6d：中断 vs 轮询的同启动真 A/B 基准。
    #[cfg(feature = "kernel-tests")]
    tests::test_storage_ahci6d_irq_vs_polling_benchmark();
    // 阶段二：用户态驱动 DMA 一致性物理缓冲原语。
    #[cfg(feature = "kernel-tests")]
    tests::test_driver_dma_buf();
    #[cfg(feature = "kernel-tests")]
    tests::test_ata_tail_probe();

    // ADR-034 前期工作：信号集 + 默认处置 + 硬信号强制（纯逻辑，返回主流程）。
    #[cfg(feature = "kernel-tests")]
    tests::test_signal_foundation();

    // ADR-034 S1-13：屏蔽延迟投递 + SIGKILL 不可捕获/屏蔽（表级，返回主流程）。
    #[cfg(feature = "kernel-tests")]
    tests::test_signal_block_defer();

    // S1-9/S1-10：kill_pid 多信号扩展 + 权限强制（表级，返回主流程）。
    #[cfg(feature = "kernel-tests")]
    tests::test_kill_extension_and_perm();

    // C7.1/#7：waitpid 核心机制单测（纯表级，返回主流程继续启动）。
    #[cfg(feature = "kernel-tests")]
    tests::test_waitpid_core();

    // 跨核收尸竞态（DESIGN §3.2/§9）：就绪进程被选中后被另一核收尸/置 Exit，
    // 切换路径丢弃重选不 panic（纯表级，返回主流程继续启动）。
    #[cfg(feature = "kernel-tests")]
    tests::test_cross_core_reap_safety();


    // SMP 审计 S2：地址空间销毁前必须能确认没有别的核仍持有其 CR3。
    // 红证：修复前只有本核视角的 `current_paddr()`，别的核悬着时中间页表页被
    // 提前归还 → 取指缺页 → #DF → 三重故障（纯值级，不切表、不依赖多核）。
    #[cfg(feature = "kernel-tests")]
    tests::test_s2_destroy_requires_no_active_cr3_holders();

    // SMP 审计 S1：跨核改页表后必须能请求全系统 TLB 失效。
    // 红证：`flush_tlb` 只发 `invlpg`（只作用本核），而线程已跨核分布；
    // 缺此能力则 munmap/mprotect 后别的核可能沿用陈旧翻译 → 静默内存破坏。
    #[cfg(feature = "kernel-tests")]
    tests::test_s1_tlb_shootdown_capability();

    // SMP 审计 S3：DMA 缓冲分配阶数必须与释放阶数一致（分配-释放帧守恒）。
    #[cfg(feature = "kernel-tests")]
    tests::test_s3_dma_alloc_free_frame_conservation();

    // STORAGE-AHCI-1：内核态 DMA 缓冲的真实性（HHDM 对应 + 可写可读）与资源守恒。
    #[cfg(feature = "kernel-tests")]
    tests::test_ahci1_kernel_dma_buffer_truth_and_conservation();

    // STORAGE-AHCI-2：AHCI 盘真读真写（DMA 读写回环 + MBR 签名独立证据）。
    #[cfg(feature = "kernel-tests")]
    tests::test_ahci2_real_read_write_roundtrip();

    // STORAGE-AHCI-4：PIO vs AHCI 量化对比（rdtsc 实测，不估算）。
    #[cfg(feature = "kernel-tests")]
    tests::test_storage_ahci4_pio_vs_ahci_benchmark();

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
    tests::test_event_wait_mechanism();
    #[cfg(feature = "kernel-tests")]
    tests::test_ipc1_semantics();

    // T1-1 线程派生结构验收（ADR-035 D1/D2 / threads.md T1-1）：组共享容器 +
    // 独立 pid/kstack/tgid 单核检查（表级，返回主流程；调度切换留 T1-8）。
    #[cfg(feature = "kernel-tests")]
    tests::test_thread_derive();

    // T1-2 线程组成员关系查询（ADR-035 D2 / threads.md T1-2）：组内遍历 + 组长识别。
    #[cfg(feature = "kernel-tests")]
    tests::test_t1_2_group();

    // T1-3 组退出语义（ADR-035 D3/P1 / threads.md T1-3）：组员单体 exit + 组长退整组
    // 随退并 notify 父。单核表级验收（表级自检，返回主流程；跨核脱机留 T1-8/SMP）。
    #[cfg(feature = "kernel-tests")]
    tests::test_t1_3();

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

    // D-VFS1-R4 第一阶段：真·物理大页直通缓存。**置于测试序列末位**——
    // 本组测试大量分配/归还 ORDER_2M 物理大页并churn物理内存，会影响依赖
    // 特定物理内存可用性的早期测试（如 test-loader 的配额/帧账断言）；
    // 放在所有既有测试之后运行，避免扰动它们的记账假设。
    #[cfg(feature = "kernel-tests")]
    tests::test_huge_page_direct_r4(); // R4-1/R4-2/R4-4: physical huge-page direct cache + evidence
    #[cfg(feature = "kernel-tests")]
    tests::test_huge_page_bench_r43(); // R4-3: huge-page vs heap-cache cycle benchmark

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

    // SMP 审计 S4：跨核唤醒必须无条件投递重调度 IPI。
    //
    // 放**此处**而非早期测试块：投递 IPI 需要目标核已在线且槽位已登记，
    // 而 `smp::init` 之前只有 BSP，`lapic_id_of_slot(1)` 返回 `None`，投递
    // 必然失败。早期块只断言"尝试过"（机制），这里断言"真的送到"
    // （投递计数 0 -> 1）。
    #[cfg(feature = "kernel-tests")]
    tests::test_s4_wake_enqueue_ipi_is_unconditional();
    // SMP 审计 S6：LAPIC→槽位查表必须区分「已登记」与「未登记」。
    //
    // 同上："已登记"那半边（BSP -> 槽 0、各在线槽位往返）只有 `smp::init`
    // 之后才有意义。
    #[cfg(feature = "kernel-tests")]
    tests::test_s6_lapic_slot_sentinel();

    // 阶段 0：SMP 冒烟测试——须在 smp::init + wait_all_online + IPI 接线
    // （mm::ipi_drain_current_cpu 已占向量 0x40 分发槽位）之后运行：测试需
    // 临时换装 IPI handler 做跨核往返并恢复原位。单核（无 -smp）下仅校验
    // 映射表自洽后跳过 IPI 往返，不报错。
    #[cfg(feature = "kernel-tests")]
    tests::test_smp_smoke();

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
    // 注意：**IRQ2 级联位不在此解屏蔽**。AHCI 的 SATA 中断线（实测 IRQ11）
    // 在从片上，需要 IRQ2 级联，但「是否需要 + 具体哪条线」要等 PCI 枚举读到
    // 控制器的 0x3C 才知道，故由 AHCI 驱动在 `late_storage_init` 中按实测值
    // 解屏蔽（见 `arch_x86_64::pic::unmask_irq` 与 ahci.rs 的调用点）。
    // 此处只保证键盘可用。
    const PIC_MASK_ALL_EXCEPT_IRQ1: u16 = !(1u16 << 1);
    arch_x86_64::pic::set_mask(PIC_MASK_ALL_EXCEPT_IRQ1);
    arch_x86_64::keyboard::init();
    // 注册键盘输入回调：有按键时唤醒阻塞在 `read` 的进程（如 shell）。arch 层
    // 不反向依赖 kernel，经函数指针解耦（指向 `task::wake_kbd`）。
    arch_x86_64::keyboard::set_input_callback(task::wake_kbd);
    // 注册设备事件唤醒回调（interrupt-to-futex）：`driver::event::publish_event`
    // 发布硬件拓扑事件时唤醒阻塞在事件等待的进程（volumed 的 SYS_DRIVER_EVENT_NEXT
    // 阻塞态）。driver 不反向依赖 task，经函数指针解耦（指向 `task::wake_event`）。
    driver::event::set_event_wake_callback(task::wake_event);
    // 注册设备中断定向唤醒回调（阶段一：PCI IRQ → 认领它的用户驱动）：
    // 某设备 IRQ 触发且其归属驱动阻塞在 driver_irq_wait 时，把该驱动进程唤醒
    // 并预置返回值 1（有中断待服务）。driver 不反向依赖 task，经函数指针解耦。
    driver::irq_owner::set_irq_wake_callback(kernel_irq_wake_pid);

    // C7.1/#7：waitpid 真实父子链停机验收（kernel-test-waitpid 显式启用；
    // 验收后停机、不返回主流程，故必须放在 start_init 之前）。
    #[cfg(feature = "kernel-test-waitpid")]
    tests::test_waitpid_e2e(); // 永不返回

    // 生产化：进入用户态 init（PID 1），而非内核 idle 停机。加载 init.elf →
    // spawn → `scheduler::start` 永不返回；init 经 syscall 与内核交互、退出。
    start_init();
}

/// 设备中断定向唤醒回调（注入 `driver::irq_owner::set_irq_wake_callback`）。
///
/// 设备 IRQ 触发且归属驱动阻塞在 `driver_irq_wait` 时被调用：把该 pid 唤醒
/// 并把其保存帧 rax 预置为 1（= 有中断待服务）。driver 不反向依赖 task，经
/// 本回调解耦（与 `driver::event` → `task::wake_event` 同款函数指针模式）。
fn kernel_irq_wake_pid(pid: usize) {
    task::wake_with_value(pid, 1);
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
pub(crate) fn halt_other_cpus_via_ipi() {
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
                    if let Some(io) = ops.as_io() {
                        return io.read(buf);
                    }
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

/// ADR-028 单源读取：`/programs/<name>` 是**唯一**程序来源。
///
/// `/programs` 只由构建期内置 liveCD payload 填充（`vfs_init` 的
/// `populate_builtin_programs`），外部盘不再遮蔽 `/programs`（ADR-025 的
/// "盘优先"双源机制已废除，见 ADR-028 §决策1/3）。故本函数读到的恒是
/// 内置 payload；任何失败（文件缺失/短读/超限）返回 None，由调用方显式
/// 失败，绝不伪造成功、绝不回退到第二条来源。
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
    // ADR-028（单源）：init.elf 只从 `/programs/init.elf` 读取——`/programs`
    // 由构建期内置 liveCD payload 填充（无盘可启动），外部盘不再遮蔽
    // `/programs`（盘优先双源已废除）。读取失败即显式失败并 idle 停机
    // （错误可见、不 panic），绝不伪造成功、绝不回退到第二来源。
    let Some(elf_bytes) = read_binary_from_programs("init.elf") else {
        error!("[kmain] init: /programs/init.elf unavailable (built-in liveCD payload missing)");
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
    // A1 / ADR-033 (V1 fix): init 由内核自己拉起，必须显式以 System/uid=1 引导。
    // 不得走默认 User 身份的 task::spawn——否则可信引导进程拿不到 System 特权。
    // ADR-034 PRE-3：init 也经 exec 语义安装信号 restorer（handler 返回后
    // 经 restorer 调 rt_sigreturn）。安装失败如实上报，不静默缺 restorer。
    let trampoline = match us.install_signal_restorer() {
        Ok(addr) => addr,
        Err(_) => {
            error!("[kmain] init: install signal restorer failed");
            info!("[kmain] reached idle loop");
            CurrentArch::halt();
        }
    };
    let pid = match task::spawn_with_ppid_fds(
        0, "init.elf", loaded.entry, loaded.user_stack_top, us, trampoline, None, task::ProcessIdentity::system(1),
    ) {
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
    // 阶段2（对称多处理）：进入生产前把各 AP 切换到 per-CPU 调度空闲循环——
    // 每个在线 AP 从此刻起运行 task::start()，在本核 IRQ0 上调度本核就绪队列
    // （init 已在 BSP 槽，其子进程经 round-robin 分发到各在线 AP 队列）。须在
    // init spawn 后、BSP 进入
    // 调度器前启用，保证 AP 与 BSP 同步进入调度（AP 空队则空转，不抢 init）。
    arch_x86_64::smp::enable_ap_scheduling(task::start);
    // 阶段2（M4）：开启跨核 spawn 轮转——init 已在 BSP（其父=0 于使能前创建），
    // 其后续子进程（shell 等）将轮转落到在线 AP 队列，由该 AP 真正调度执行，
    // 以实证"每核 AP 调度自己的就绪队列"的对称多处理。
    task::set_distribute_across_cpus(true);
    // 启动调度器（永不返回）：进入 init 用户态，tick 轮转，init 经 syscall 退出。
    task::start();
}
