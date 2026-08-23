//! Panic 处理。
//!
//! 内核 panic 时输出完整诊断信息（消息、位置、架构、CPU、栈回溯）到串口，
//! 并在串口输出完成后尝试输出到 framebuffer 屏幕，最后停机。
//! 架构相关的信息（架构名、停机方式、回退串口、CPU id、屏幕输出）由入口
//! crate 通过 `init`/`set_panic_output` 注入，保持本模块架构无关。
//!
//! KM14：注入槽位全部为 [`spin::Once`]——早期单线程阶段一次性写入，之后
//! 只读。`Once::get()` 对已完成的 Once 是无锁原子读，panic 路径不会阻塞在
/// 任何锁上；原 `AtomicUsize` + 裸 `transmute` 往返（fn↔usize ×5、架构名
/// ptr+len 原子对）整类不安全转换随之消除。

use spin::Once;

use crate::symbols;

/// 停机函数（由入口注入，绑定具体架构的 halt）。
type HaltFn = fn() -> !;
static HALT_FN: Once<HaltFn> = Once::new();

/// 架构名字符串（由入口注入）。
static ARCH_NAME: Once<&'static str> = Once::new();

/// 回退串口写函数 `fn(&str)`（绕过 klib 的 console 层，保证早期 panic 可见）。
static SERIAL_WRITE: Once<fn(&str)> = Once::new();
/// 当前 CPU id 读取器 `fn() -> u32`（未注入/未就绪时返回 0）。
static CPU_ID_READER: Once<fn() -> u32> = Once::new();
/// framebuffer 屏幕输出 `fn(&str)`（未初始化/未注入时静默跳过）。
static SCREEN_WRITE: Once<fn(&str)> = Once::new();
/// 静默函数 `fn()`（关本 CPU 中断；未注入时跳过——早期 panic 本就无中断可关）。
///
/// kernel1.md KA1：panic 处理全程必须在本 CPU 关中断下进行。中断开着时，
/// dump_crash_log / 屏幕输出路径上的锁（日志环形缓冲、终端锁）可能被被打断
/// 的持有者占着，或 LAPIC tick 在 panic 现场上再次触发调度改写现场。
static QUIESCE_FN: Once<fn()> = Once::new();

/// 跨核停机函数 `fn()`（KA1：向其它在线 CPU 广播停机 IPI；未注入/单核跳过）。
///
/// 多核 panic 现场上其它核仍在跑：继续分配内存、拿锁、改共享状态，甚至
/// 也进入 panic 交错输出。诊断输出前先停住它们。
static CROSS_HALT_FN: Once<fn()> = Once::new();

/// 默认停机（未注入前：死循环）
fn default_halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// 初始化 panic 子系统：注入架构名和停机函数。应在内核早期调用。
pub fn init(arch_name: &'static str, halt: HaltFn) {
    ARCH_NAME.call_once(|| arch_name);
    HALT_FN.call_once(|| halt);
}

/// 注入 panic 时的平台辅助：回退串口、CPU id、屏幕输出。
///
/// 回退串口独立于 `klib` 的 console 层，确保在 console 尚未注册 sink 时 panic 依然可见。
/// `cpu_id` 返回当前 CPU 的 LAPIC id（未就绪时须自行返回 0，避免读未映射寄存器）。
/// `screen` 向 framebuffer 输出（未初始化时可安全空操作）。
pub fn set_panic_output(serial: fn(&str), cpu_id: fn() -> u32, screen: fn(&str)) {
    SERIAL_WRITE.call_once(|| serial);
    CPU_ID_READER.call_once(|| cpu_id);
    SCREEN_WRITE.call_once(|| screen);
}

/// 注入 panic 静默函数（本 CPU 关中断）。由入口 crate 在中断子系统就绪后接线；
/// 未注入时 panic 入口跳过（早期阶段无中断可关）。
pub fn set_panic_quiesce(f: fn()) {
    QUIESCE_FN.call_once(|| f);
}

/// 注入跨核停机函数（KA1）。由入口 crate 在 SMP 初始化完成后接线；
/// 未注入时 panic 入口跳过（单核/极早期无其它核可停）。
pub fn set_cross_core_halt(f: fn()) {
    CROSS_HALT_FN.call_once(|| f);
}

fn halt() -> ! {
    match HALT_FN.get().copied() {
        None => default_halt(),
        Some(f) => f(),
    }
}

fn arch_name() -> &'static str {
    ARCH_NAME.get().copied().unwrap_or("unknown")
}

/// 取回退串口函数（未注入则 None）。
fn serial_write() -> Option<fn(&str)> {
    SERIAL_WRITE.get().copied()
}

/// 当前 CPU id（未注入/未就绪返回 0）。
fn cpu_id() -> u32 {
    CPU_ID_READER.get().map(|f| f()).unwrap_or(0)
}

/// 屏幕输出（未注入则跳过）。
fn screen_write() -> Option<fn(&str)> {
    SCREEN_WRITE.get().copied()
}

/// 把 panic 信息（架构、CPU、消息、位置）格式化为单条消息。
fn build_msg<'a>(buf: &'a mut [u8], info: &core::panic::PanicInfo) -> &'a str {
    use core::fmt::Write as _;
    let mut w = symbols::BufWriter { buf, len: 0 };
    let _ = write!(w, "arch: {}\n", arch_name());
    let _ = write!(w, "cpu:  {}\n", cpu_id());
    let _ = write!(w, "message: {}", info.message());
    if let Some(loc) = info.location() {
        let _ = write!(
            w,
            "\nlocation: {}:{}:{}",
            loc.file(),
            loc.line(),
            loc.column()
        );
    }
    let len = w.len;
    drop(w); // 结束对 buf 的可变借用
    core::str::from_utf8(&buf[..len]).unwrap_or("<invalid panic message>")
}

/// x86_64 栈回溯：沿 rbp 帧指针链遍历，把回溯写进 `out`（栈上缓冲）。
///
/// 注意：要求编译开启帧指针（`-C force-frame-pointers=yes`，见 .cargo/config.toml），
/// 否则链可能不完整。
/// 防御：帧指针必须严格向上增长且不为 0，避免栈损坏时无限循环。
/// 全程零堆分配，panic 发生在堆分配器初始化之前也能安全回溯。
fn write_backtrace(out: &mut [u8]) -> &str {
    use core::fmt::Write as _;
    let mut w = symbols::BufWriter { buf: out, len: 0 };
    let mut rbp: usize;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
    }
    let mut valid = 0usize;
    // KD4：回溯帧数上限常量化。内核调用链深度远小于此值；上限同时防御
    // 损坏帧链导致的长时间空转（配合下方单调性检查双保险）。
    const BACKTRACE_MAX_FRAMES: usize = 32;
    for i in 0..BACKTRACE_MAX_FRAMES {
        let next: usize;
        let ret: usize;
        unsafe {
            next = core::ptr::read_volatile(rbp as *const usize);
            ret = core::ptr::read_volatile((rbp as *const usize).add(1));
        }
        // 仅处理合理的内核高半区返回地址，过滤垃圾帧
        if (ret >> 48) == 0xffff {
            let _ = write!(w, "  #{:02}  {:#018x}  ", i, ret);
            // 符号化写入临时缓冲后追加（避免借用冲突）
            let mut sym = [0u8; 128];
            let s = symbols::symbolize(ret as u64, &mut sym);
            let _ = w.write_str(s);
            let _ = w.write_str("\n");
            valid += 1;
        }
        if next == 0 || next <= rbp {
            break;
        }
        rbp = next;
    }
    if valid == 0 {
        let _ = w.write_str("  (empty backtrace - frame pointers may be disabled)\n");
    }
    let len = w.len;
    drop(w); // 结束对 out 的可变借用
    core::str::from_utf8(&out[..len]).unwrap_or("")
}

/// Panic handler：关中断（KA1）、打印诊断信息到串口与屏幕，然后停机。
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // 0. 本 CPU 关中断：后续诊断路径会拿日志环形缓冲锁 / 终端锁，且 tick
    //    不得再在 panic 现场上触发调度。未注入（极早期）时跳过。
    if let Some(f) = QUIESCE_FN.get().copied() {
        f();
    }
    // 0.5 跨核停机（KA1）：其它核仍在跑会继续分配/拿锁/改共享状态，甚至
    //     进入 panic 交错输出——诊断输出前先停住它们。须在本 CPU 关中断
    //     之后（现场稳定）执行；未注入/单核跳过。
    if let Some(f) = CROSS_HALT_FN.get().copied() {
        f();
    }

    let mut buf = [0u8; 2048];
    let msg = build_msg(&mut buf, info);

    // 1. 回退串口：绕过 klib console 层，确保早期 panic 可见。
    //    注意：只走这一条串口通道（不再用 klib::info!），因为两者最终指向同一
    //    串口，重复调用会打印两遍。
    let mut bt = [0u8; 4096];
    let bt = write_backtrace(&mut bt);
    serial_write().map(|f| {
        f("========== KERNEL PANIC ==========\n");
        f(msg);
        f("\nstack backtrace:\n");
        f(bt);
        f("==================================\n");
    });

    // 2. 崩溃回读：把环形日志缓冲中的最后 N 条日志输出到统一 console
    //    （串口 + 屏幕，按已注册 sink 顺序）。console 未注册 sink（早期
    //    panic）时为空操作，不影响诊断。
    klib::log::dump_crash_log();

    // 3. 屏幕输出：串口输出完后，在 framebuffer 上再打印，防止用户看不到
    if let Some(f) = screen_write() {
        f("========== KERNEL PANIC ==========\r\n");
        f(msg);
        f("\r\n==================================\r\n");
    }

    halt();
}
