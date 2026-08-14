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

    // 初始化内存管理（LazyBuddy 物理页帧分配器）
    mm::init();
    // 验证物理页帧分配/释放
    test_frame_alloc();

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

/// 验证物理页帧分配器的分配/释放基本逻辑。
fn test_frame_alloc() {
    // 统计初始状态
    let s0 = mm::frame_stats();
    logln!(
        "[test-pmm] init: allocated={} alloc_calls={} fail={}",
        s0.allocated_frames, s0.alloc_calls, s0.alloc_fail
    );

    // 分配 3 个帧
    let f1 = mm::allocate_frame().expect("frame 1 alloc failed");
    let f2 = mm::allocate_frame().expect("frame 2 alloc failed");
    let f3 = mm::allocate_frame().expect("frame 3 alloc failed");
    logln!(
        "[test-pmm] allocated: f1={:?} f2={:?} f3={:?}",
        f1.start_address(),
        f2.start_address(),
        f3.start_address()
    );

    let s1 = mm::frame_stats();
    logln!(
        "[test-pmm] after alloc: allocated={} alloc_calls={} hit_uninit={} fail={}",
        s1.allocated_frames, s1.alloc_calls, s1.alloc_hit_uninit, s1.alloc_fail
    );

    // 释放一个，再分配，验证可重用
    mm::deallocate_frame(f2);
    logln!("[test-pmm] freed f2");
    let f2b = mm::allocate_frame().expect("re-alloc failed");
    logln!(
        "[test-pmm] re-allocated f2b={:?} (expect equals freed f2={:?})",
        f2b.start_address(),
        f2.start_address()
    );

    // 清理
    mm::deallocate_frame(f1);
    mm::deallocate_frame(f2b);
    mm::deallocate_frame(f3);
    logln!("[test-pmm] all frames freed");

    let s2 = mm::frame_stats();
    logln!(
        "[test-pmm] final: allocated={} alloc_calls={} fail={}",
        s2.allocated_frames, s2.alloc_calls, s2.alloc_fail
    );
}
