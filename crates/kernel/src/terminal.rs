//! framebuffer 终端（flanterm）初始化与输出。
//!
//! 负责从 Limine 提供的 framebuffer 创建 flanterm 终端上下文，并在屏幕上打印文本。
//! 上下文被全局持有（`'static`），供 `panic` 等场景在任意时刻向屏幕输出。

use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};

use flanterm_rust::FlantermContext;
use klib::{error, info};

/// 全局 framebuffer 终端上下文指针（由 `init` 保存，未初始化时为 0）。
///
/// 用 `AtomicUsize` 存裸地址，避免要求 `FlantermContext: Sync`；
/// 访问均在串口已停机/单核的 panic 场景进行，无并发竞争。
static TERMINAL_PTR: AtomicUsize = AtomicUsize::new(0);

/// 用 flanterm 初始化终端并在屏幕上打印文本。
///
/// `fb` 是 Limine 提供的 framebuffer。成功后上下文被 leak 为 `'static` 并全局持有。
pub fn init(fb: &limine::Framebuffer) {
    // framebuffer 地址（u32*）与参数
    let Some(addr) = fb.address.as_ptr() else {
        error!("[terminal] ERROR: framebuffer address is null");
        return;
    };
    let fb_ptr = addr as *mut u32;
    let width = fb.width as usize;
    let height = fb.height as usize;
    let pitch = fb.pitch as usize;

    // 颜色掩码（limine 提供）
    let rms = fb.red_mask_size;
    let rsh = fb.red_mask_shift;
    let gms = fb.green_mask_size;
    let gsh = fb.green_mask_shift;
    let bms = fb.blue_mask_size;
    let bsh = fb.blue_mask_shift;

    info!(
        "[terminal] init fb={:#x} {}x{} pitch={} bpp={}",
        fb_ptr as usize, width, height, pitch, fb.bpp
    );
    // 初始化 flanterm framebuffer 后端
    let ctx = unsafe {
        flanterm_rust::flanterm_fb_init(
            fb_ptr, width, height, pitch,
            rms, rsh, gms, gsh, bms, bsh,
            core::ptr::null_mut(), // canvas
            core::ptr::null_mut(), // ansi_colours
            core::ptr::null_mut(), // ansi_bright_colours
            core::ptr::null_mut(), // default_bg
            core::ptr::null_mut(), // default_fg
            core::ptr::null_mut(), // default_bg_bright
            core::ptr::null_mut(), // default_fg_bright
            core::ptr::null_mut(), // font
            0, 0, 0,                // font_width, font_height, font_spacing
            1, 1,                   // font_scale_x, font_scale_y
            0,                      // margin
            flanterm_rust::FLANTERM_FB_ROTATE_0,
        )
    };
    info!("[terminal] flanterm_fb_init done, ctx.is_some={}", ctx.is_some());

    if let Some(ctx) = ctx {
        // leak 为 'static，供 panic 等全局场景使用
        let ctx: &'static mut FlantermContext = Box::leak(ctx);
        TERMINAL_PTR.store(ctx as *mut FlantermContext as usize, Ordering::Release);
        // 写入文本
        write_str("Hello, BORUIX!\r\n");
        write_str("Kernel M0 is running.\r\n");
        info!("[terminal] wrote text done");
    } else {
        error!("[terminal] ERROR: flanterm_fb_init returned None");
    }
}

/// 向 framebuffer 终端写文本（`\n` 自动转 `\r\n`）。未初始化则静默。
pub fn write_str(s: &str) {
    let p = TERMINAL_PTR.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    let ctx = unsafe { &mut *(p as *mut FlantermContext) };
    let bytes = s.as_bytes();
    let mut start = 0usize;
    for i in 0..=bytes.len() {
        if i == bytes.len() || bytes[i] == b'\n' {
            if i > start {
                flanterm_rust::flanterm_write(ctx, &bytes[start..i]);
            }
            if i < bytes.len() {
                flanterm_rust::flanterm_write(ctx, b"\r\n");
            }
            start = i + 1;
        }
    }
}

/// framebuffer 终端控制台：`klib::console::Console` 的实现
/// （统一 console 的屏幕 sink，可与其他 sink 并存）。
pub struct TerminalConsole;

/// 全局终端控制台实例（供 `klib::console::register_console` 注册）。
pub static TERMINAL_CONSOLE: TerminalConsole = TerminalConsole;

impl klib::console::Console for TerminalConsole {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn write_str(&self, s: &str) {
        write_str(s);
    }
    fn write_byte(&self, b: u8) {
        let s = core::str::from_utf8(core::slice::from_ref(&b)).unwrap_or("\u{FFFD}");
        write_str(s);
    }
    fn flush(&self) {}
}
