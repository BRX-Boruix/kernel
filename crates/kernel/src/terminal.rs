//! framebuffer 终端（flanterm）初始化与输出。
//!
//! 负责从 Limine 提供的 framebuffer 创建 flanterm 终端上下文，并在屏幕上打印文本。

use klib::logln;

/// 用 flanterm 初始化终端并在屏幕上打印文本。
///
/// `fb` 是 Limine 提供的 framebuffer。
pub fn init(fb: &limine::Framebuffer) {
    // framebuffer 地址（u32*）与参数
    let Some(addr) = fb.address.as_ptr() else {
        logln!("[terminal] ERROR: framebuffer address is null");
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

    logln!(
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
    logln!("[terminal] flanterm_fb_init done, ctx.is_some={}", ctx.is_some());

    if let Some(mut ctx) = ctx {
        // 写入文本
        flanterm_rust::flanterm_write(&mut ctx, b"Hello, BORUIX!\r\n");
        flanterm_rust::flanterm_write(&mut ctx, b"Kernel M0 is running.\r\n");
        logln!("[terminal] wrote text done");
    } else {
        logln!("[terminal] ERROR: flanterm_fb_init returned None");
    }
}
