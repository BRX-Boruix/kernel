#![no_std]
#![no_main]

mod panic;
mod terminal;

use arch::Platform;
use klib::logln;
use limine::{BaseRevision, FramebufferRequest};

use arch_x86_64::X86_64Arch as CurrentArch;

// 声明 BaseRevision。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别请求。
#[limine::limine_tag]
static BASE_REVISION: BaseRevision = BaseRevision::new(6);

// 请求 framebuffer
#[limine::limine_tag]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new(0);

/// 内核入口（由 Limine 引导器跳转）
#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    // 初始化 panic 子系统（注入架构名和停机函数，尽早）
    panic::init(CurrentArch::name(), CurrentArch::halt);

    // 初始化架构（串口等）
    CurrentArch::init();
    // 把架构的串口输出注入到 klib 的全局输出器
    klib::serial::set_output(CurrentArch::serial_write as fn(u8));
    logln!("[kmain] serial initialized (arch={})", CurrentArch::name());

    // 获取 framebuffer（limine 0.1: get_response() 返回 Ptr<FramebufferResponse>）
    if let Some(resp) = FRAMEBUFFER_REQUEST.get_response().get() {
        logln!("[kmain] framebuffer response received");
        if let Some(fb) = resp.framebuffers().first() {
            let fb = &**fb; // NonNullPtr<Framebuffer> -> Framebuffer
            logln!(
                "[kmain] framebuffer {}x{} pitch={} bpp={}",
                fb.width, fb.height, fb.pitch, fb.bpp
            );
            terminal::init(fb);
            logln!("[kmain] terminal init returned");
        } else {
            logln!("[kmain] ERROR: no framebuffer");
        }
    } else {
        logln!("[kmain] ERROR: no framebuffer response");
    }

    logln!("[kmain] reached idle loop");
    CurrentArch::halt();
}
