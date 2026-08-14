#![no_std]
#![no_main]

mod allocator;
mod serial;

use limine::FramebufferRequest;

// 请求 framebuffer（limine 0.1 用 #[no_mangle] static + get_response()）
#[unsafe(no_mangle)]
#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new(0);

/// 内核入口（由 Limine 引导器跳转）
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // 先初始化串口，尽早输出日志
    serial::init();
    logln!("[kmain] serial initialized");

    // 获取 framebuffer（limine 0.1: get_response() 返回 Ptr<FramebufferResponse>）
    if let Some(resp) = FRAMEBUFFER_REQUEST.get_response().get() {
        logln!("[kmain] framebuffer response received");
        if let Some(fb) = resp.framebuffers().first() {
            let fb = &**fb; // NonNullPtr<Framebuffer> -> Framebuffer
            logln!(
                "[kmain] framebuffer {}x{} pitch={} bpp={}",
                fb.width, fb.height, fb.pitch, fb.bpp
            );
            init_terminal(fb);
            logln!("[kmain] terminal init returned");
        } else {
            logln!("[kmain] ERROR: no framebuffer");
        }
    } else {
        logln!("[kmain] ERROR: no framebuffer response");
    }

    logln!("[kmain] reached idle loop");
    hcf();
}

/// 用 flanterm 初始化终端并在屏幕上打印文本
fn init_terminal(fb: &limine::Framebuffer) {
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
        // 写入文本（参考项目：\n 转 \r\n）
        flanterm_rust::flanterm_write(&mut ctx, b"Hello, BORUIX!\r\n");
        flanterm_rust::flanterm_write(&mut ctx, b"Kernel M0 is running.\r\n");
        logln!("[terminal] wrote text done");
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
