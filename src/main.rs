#![no_std]
#![no_main]

mod allocator;
mod serial;

use limine::request::FramebufferRequest;
use limine::{RequestsEndMarker, RequestsStartMarker};

// 请求 framebuffer，用于图形输出
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

// 请求列表的起始/结束标记，供 Limine 扫描
static START_MARKER: RequestsStartMarker = RequestsStartMarker::new();
static END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

// 将请求放入特定段，引导器才能定位到它们
#[used]
#[unsafe(link_section = ".requests")]
static START_MARKER_SECTION: &RequestsStartMarker = &START_MARKER;
#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST_SECTION: &FramebufferRequest = &FRAMEBUFFER_REQUEST;
#[used]
#[unsafe(link_section = ".requests")]
static END_MARKER_SECTION: &RequestsEndMarker = &END_MARKER;

/// 内核入口（由 Limine 引导器跳转）
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // 先初始化串口，尽早输出日志
    serial::init();
    logln!("[kmain] serial initialized");

    // 获取 framebuffer
    match FRAMEBUFFER_REQUEST.response() {
        Some(resp) => {
            logln!("[kmain] framebuffer response received");
            if let Some(fb) = resp.framebuffers().first() {
                logln!(
                    "[kmain] framebuffer {}x{} pitch={} bpp={}",
                    fb.width,
                    fb.height,
                    fb.pitch,
                    fb.bpp
                );
                unsafe { init_terminal(fb) };
                logln!("[kmain] terminal init returned");
            } else {
                logln!("[kmain] ERROR: no framebuffer");
            }
        }
        None => {
            logln!("[kmain] ERROR: no framebuffer response");
        }
    }

    logln!("[kmain] reached idle loop");
    hcf();
}

/// 用 flanterm 初始化终端并在屏幕上打印文本
unsafe fn init_terminal(fb: &limine::framebuffer::Framebuffer) {
    // framebuffer 地址（u32*）与参数
    let fb_ptr = fb.address() as *mut u32;
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

        logln!(
        "[terminal] init fb={:#x} {}x{} pitch={} bpp={}",
        fb_ptr as usize, width, height, pitch, fb.bpp
    );
    // 初始化 flanterm framebuffer 后端（参数与参考项目 kernel_driver_hub::terminal::init 一致）
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
    logln!("[terminal] flanterm_fb_init done, ctx.is_some={}", ctx.is_some());

    if let Some(mut ctx) = ctx {
        // 写入文本（flanterm 需要 \r\n 换行）
        flanterm_rust::flanterm_write(&mut ctx, b"Hello, BORUIX!\r\n");
        flanterm_rust::flanterm_write(&mut ctx, b"Kernel M0 is running.\r\n");
        // 刷新
        flanterm_rust::flanterm_flush(&mut ctx);
        logln!("[terminal] wrote text + flush done");
    } else {
        logln!("[terminal] ERROR: flanterm_fb_init returned None");
    }
}

/// CPU 停机
fn hcf() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

/// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    hcf();
}
