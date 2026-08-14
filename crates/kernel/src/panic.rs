//! Panic 处理。
//!
//! 内核 panic 时打印完整错误信息到串口，然后停机。
//! 架构相关的信息（架构名、停机方式）由入口 crate 通过 `init` 注入，
//! 保持本模块架构无关。

use core::sync::atomic::{AtomicUsize, Ordering};

use klib::logln;

/// 停机函数（由入口注入，绑定具体架构的 halt）
type HaltFn = fn() -> !;
static HALT_FN: AtomicUsize = AtomicUsize::new(0);

/// 架构名字符串（指针 + 长度，由入口注入）
static ARCH_NAME_PTR: AtomicUsize = AtomicUsize::new(0);
static ARCH_NAME_LEN: AtomicUsize = AtomicUsize::new(0);

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

/// Panic handler：打印错误信息到串口，然后停机。
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    logln!("");
    logln!("========== KERNEL PANIC ==========");
    logln!("arch: {}", arch_name());
    logln!("message: {}", info.message());
    if let Some(loc) = info.location() {
        logln!("location: {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    logln!("==================================");
    logln!("");

    halt();
}
