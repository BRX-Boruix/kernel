//! Panic 处理。
//!
//! 内核 panic 时输出完整诊断信息（消息、位置、架构、CPU、栈回溯）到串口，
//! 并在串口输出完成后尝试输出到 framebuffer 屏幕，最后停机。
//! 架构相关的信息（架构名、停机方式、回退串口、CPU id、屏幕输出）由入口
//! crate 通过 `init`/`set_panic_output` 注入，保持本模块架构无关。

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::symbols;

/// 停机函数（由入口注入，绑定具体架构的 halt）
type HaltFn = fn() -> !;
static HALT_FN: AtomicUsize = AtomicUsize::new(0);

/// 架构名字符串（指针 + 长度，由入口注入）
static ARCH_NAME_PTR: AtomicUsize = AtomicUsize::new(0);
static ARCH_NAME_LEN: AtomicUsize = AtomicUsize::new(0);

/// 回退串口写函数 `fn(&str)`（绕过 klib 的 OUTPUT 注入，保证早期 panic 可见）。
static SERIAL_WRITE: AtomicUsize = AtomicUsize::new(0);
/// 当前 CPU id 读取器 `fn() -> u32`（未注入/未就绪时返回 0）。
static CPU_ID_READER: AtomicUsize = AtomicUsize::new(0);
/// framebuffer 屏幕输出 `fn(&str)`（未初始化/未注入时为 0，静默跳过）。
static SCREEN_WRITE: AtomicUsize = AtomicUsize::new(0);

/// 默认停机（未注入前：死循环）
fn default_halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// 初始化 panic 子系统：注入架构名和停机函数。应在内核早期调用。
pub fn init(arch_name: &'static str, halt: HaltFn) {
    ARCH_NAME_PTR.store(arch_name.as_ptr() as usize, Ordering::SeqCst);
    ARCH_NAME_LEN.store(arch_name.len(), Ordering::SeqCst);
    HALT_FN.store(halt as usize, Ordering::SeqCst);
}

/// 注入 panic 时的平台辅助：回退串口、CPU id、屏幕输出。
///
/// 回退串口独立于 `klib::set_output`，确保在 OUTPUT 尚未注入时 panic 依然可见。
/// `cpu_id` 返回当前 CPU 的 LAPIC id（未就绪时须自行返回 0，避免读未映射寄存器）。
/// `screen` 向 framebuffer 输出（未初始化时可安全空操作）。
pub fn set_panic_output(serial: fn(&str), cpu_id: fn() -> u32, screen: fn(&str)) {
    SERIAL_WRITE.store(serial as usize, Ordering::SeqCst);
    CPU_ID_READER.store(cpu_id as usize, Ordering::SeqCst);
    SCREEN_WRITE.store(screen as usize, Ordering::SeqCst);
}

fn halt() -> ! {
    let f = HALT_FN.load(Ordering::SeqCst);
    if f == 0 {
        default_halt()
    } else {
        unsafe { core::mem::transmute::<usize, HaltFn>(f)() }
    }
}

fn arch_name() -> &'static str {
    let ptr = ARCH_NAME_PTR.load(Ordering::SeqCst);
    let len = ARCH_NAME_LEN.load(Ordering::SeqCst);
    if ptr == 0 {
        "unknown"
    } else {
        unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr as *const u8, len)) }
    }
}

/// 取回退串口函数（未注入则 None）。
fn serial_write() -> Option<fn(&str)> {
    let f = SERIAL_WRITE.load(Ordering::SeqCst);
    if f == 0 {
        None
    } else {
        Some(unsafe { core::mem::transmute::<usize, fn(&str)>(f) })
    }
}

/// 当前 CPU id（未注入/未就绪返回 0）。
fn cpu_id() -> u32 {
    let f = CPU_ID_READER.load(Ordering::SeqCst);
    if f == 0 {
        0
    } else {
        unsafe { core::mem::transmute::<usize, fn() -> u32>(f)() }
    }
}

/// 屏幕输出（未注入则跳过）。
fn screen_write() -> Option<fn(&str)> {
    let f = SCREEN_WRITE.load(Ordering::SeqCst);
    if f == 0 {
        None
    } else {
        Some(unsafe { core::mem::transmute::<usize, fn(&str)>(f) })
    }
}

/// 把 panic 信息（架构、CPU、消息、位置）格式化为单条消息。
fn build_msg<'a>(buf: &'a mut [u8], info: &core::panic::PanicInfo) -> &'a str {
    use core::fmt::Write as _;
    let mut w = symbols::BufWriter { buf, len: 0 };
    let _ = write!(w, "arch: {}\n", arch_name());
    let _ = write!(w, "cpu:  {}\n", cpu_id());
    let _ = write!(w, "message: {}", info.message());
    if let Some(loc) = info.location() {
        let _ = write!(w, "\nlocation: {}:{}:{}", loc.file(), loc.line(), loc.column());
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
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack)); }
    let mut valid = 0usize;
    for i in 0..32 {
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

/// Panic handler：打印诊断信息到串口与屏幕，然后停机。
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut buf = [0u8; 2048];
    let msg = build_msg(&mut buf, info);

    // 1. 回退串口：绕过 klib OUTPUT，确保早期 panic 可见。
    //    注意：只走这一条串口通道（不再用 klib::logln），因为两者最终指向同一
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

    // 3. 屏幕输出：串口输出完后，在 framebuffer 上再打印，防止用户看不到
    if let Some(f) = screen_write() {
        f("========== KERNEL PANIC ==========\r\n");
        f(msg);
        f("\r\n==================================\r\n");
    }

    halt();
}
