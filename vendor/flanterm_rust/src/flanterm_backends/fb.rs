use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{copy_nonoverlapping, write_unaligned};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::flanterm::{flanterm_context_new, flanterm_context_reinit, BackendOps, FlantermCore};
use crate::generated::BUILTIN_FONT;

pub const FLANTERM_FB_ROTATE_0: i32 = 0;
pub const FLANTERM_FB_ROTATE_90: i32 = 1;
pub const FLANTERM_FB_ROTATE_180: i32 = 2;
pub const FLANTERM_FB_ROTATE_270: i32 = 3;

const FLANTERM_FB_FONT_GLYPHS: usize = 256;

// S16：自动字体缩放的分辨率阈值（见 flanterm_fb_init 的自动缩放分支）。
// 2.5K(2560×1440) 与 4K(5120×2880=2×2560 逻辑跨度) 为高分屏经验档。
const SCALE2_MIN_WIDTH: usize = 1920 + 1920 / 3; // 2560
const SCALE2_MIN_HEIGHT: usize = 1080 + 1080 / 3; // 1440
const SCALE4_MIN_WIDTH: usize = 3840 + 3840 / 3; // 5120
const SCALE4_MIN_HEIGHT: usize = 2160 + 2160 / 3; // 2880

/// "透明/默认"颜色哨兵（S13：0xffff_ffff 散落 8+ 处，统一为具名常量）。
///
/// 已知冲突边界：在 16/8/8 大色深掩码 framebuffer 上，`convert_colour_fb`
/// 可能把某合法默认色转成 0xffffffff，与哨兵撞值——canvas 模式下默认背景
/// 会被误绘成画布像素。真彩色（8/8/8）下 `convert_colour_fb` 不会输出
/// 0xffffffff（r/g/b 各 8 位拼不出全 1 的 alpha 通道位），冲突仅在 16 位色
/// 深路径存在；属既有语义，记录于注释供后续统一。
pub const FLANTERM_FB_TRANSPARENT: u32 = 0xffff_ffff;

/// 一次性诊断标志：若在绘制时发现 `framebuffer` 指针为 0，置位。
///
/// `framebuffer` 仅在 `flanterm_fb_init` 构造时写入一次，之后无任何代码清零；
/// 变 0 说明 leaked 的 `FlantermContext` 被内核堆踩踏。经 [`fb_null_seen`]
/// 查询接口对外披露（term1 T12：诊断状态以函数暴露而非公开全局，读取方
/// 与置位方解耦，后续可替换为事件回调而不破坏 API）。
static FB_NULL_SEEN: AtomicBool = AtomicBool::new(false);

/// 查询「绘制时是否遇到过 NULL framebuffer 指针」（一次性闩，置位不复位）。
pub fn fb_null_seen() -> bool {
    FB_NULL_SEEN.load(Ordering::Relaxed)
}

#[derive(Copy, Clone)]
struct FlantermFbChar {
    c: u32,
    fg: u32,
    bg: u32,
}

#[derive(Copy, Clone)]
struct FlantermFbQueueItem {
    x: usize,
    y: usize,
    c: FlantermFbChar,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum PlotMode {
    ScaledCanvas,
    ScaledNoCanvas,
    UnscaledCanvas,
    UnscaledNoCanvas,
}

type FlushCallback = Option<unsafe fn(*const u8, usize)>;

pub struct FbBackend {
    plot_mode: PlotMode,
    flush_callback: FlushCallback,

    font_width: usize,
    font_height: usize,
    glyph_width: usize,
    glyph_height: usize,

    font_scale_x: usize,
    font_scale_y: usize,

    offset_x: usize,
    offset_y: usize,

    framebuffer: *mut u32,
    pitch: usize,
    width: usize,
    height: usize,
    phys_height: usize,

    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,

    rotation: i32,

    font_bits: Vec<u8>,
    font_bool: Vec<u8>,

    ansi_colours: [u32; 8],
    ansi_bright_colours: [u32; 8],
    default_fg: u32,
    default_bg: u32,
    default_fg_bright: u32,
    default_bg_bright: u32,

    canvas: Option<Vec<u32>>,

    grid: Vec<FlantermFbChar>,
    queue: Vec<FlantermFbQueueItem>,
    queue_i: usize,
    map: Vec<Option<usize>>,

    text_fg: u32,
    text_bg: u32,
    cursor_x: usize,
    cursor_y: usize,

    saved_state_text_fg: u32,
    saved_state_text_bg: u32,
    saved_state_cursor_x: usize,
    saved_state_cursor_y: usize,

    old_cursor_x: usize,
    old_cursor_y: usize,

    /// 【本仓修订：光标闪烁】当前闪烁相位（true = 光标格显示反转色）。
    /// 由 [`flanterm_fb_blink_toggle`] 周期翻转；`draw_cursor` 仅在相位为
    /// true 时绘制反转光标。非闪烁语义（本修订前）恒为 true 等价。
    cursor_blink_on: bool,

    /// S32：滚动快照复用缓冲——每次滚动都新建 Vec 是热路径上的常驻分配
    /// 且堆耗尽会 OOM abort。此缓冲按需增长一次后复用，消除逐次分配。
    scroll_scratch: Vec<FlantermFbChar>,
}

pub type FlantermContext = FlantermCore<FbBackend>;

#[inline(always)]
fn convert_colour_fb(fb: &FbBackend, colour: u32) -> u32 {
    let r = (colour >> 16) & 0xff;
    let g = (colour >> 8) & 0xff;
    let b = colour & 0xff;
    let mut ret = (r << fb.red_mask_shift) | (g << fb.green_mask_shift) | (b << fb.blue_mask_shift);

    if fb.red_mask_size > 8 {
        ret |= (r >> (16 - fb.red_mask_size)) << (fb.red_mask_shift + 8);
    }
    if fb.green_mask_size > 8 {
        ret |= (g >> (16 - fb.green_mask_size)) << (fb.green_mask_shift + 8);
    }
    if fb.blue_mask_size > 8 {
        ret |= (b >> (16 - fb.blue_mask_size)) << (fb.blue_mask_shift + 8);
    }

    ret
}

fn flanterm_fb_save_state(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.saved_state_text_fg = fb.text_fg;
    fb.saved_state_text_bg = fb.text_bg;
    fb.saved_state_cursor_x = fb.cursor_x;
    fb.saved_state_cursor_y = fb.cursor_y;
}

fn flanterm_fb_restore_state(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.text_fg = fb.saved_state_text_fg;
    fb.text_bg = fb.saved_state_text_bg;
    fb.cursor_x = fb.saved_state_cursor_x;
    fb.cursor_y = fb.saved_state_cursor_y;
}

fn flanterm_fb_swap_palette(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    let tmp = fb.text_bg;
    fb.text_bg = fb.text_fg;
    fb.text_fg = tmp;
    if fb.text_fg == FLANTERM_FB_TRANSPARENT {
        fb.text_fg = fb.default_bg;
    }
    if fb.text_bg == fb.default_bg {
        fb.text_bg = FLANTERM_FB_TRANSPARENT;
    }
}

#[inline(always)]
unsafe fn plot_char(
    fb: &FbBackend,
    cols: usize,
    rows: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    // 防御性保护：framebuffer 指针若为 null（疑似内核堆被踩），记录一次性标志
    // 并跳过绘制，避免 page fault 崩溃。正常情形下由 limine 提供且非 null。
    // 上层经 fb_null_seen() 查询并向日志报告（term1 T2：只观测、不自愈）。
    if fb.framebuffer.is_null() {
        FB_NULL_SEEN.store(true, Ordering::Relaxed);
        return;
    }
    // S19：在入口统一钳制 glyph 索引到内置字体表范围（256）——NoCanvas 变体
    // 此前直接 `c.c as usize * font_height * font_width` 无界偏移 font_bool，
    // Canvas 变体有 glyph_idx<256 防御而 NoCanvas 没有，防御不一致。统一到
    // 入口后四路全部受保护；越界字符绘为空白（内联为全 0，等价跳过）。
    if (c.c as usize) >= FLANTERM_FB_FONT_GLYPHS {
        return;
    }
    match fb.plot_mode {
        PlotMode::ScaledCanvas => plot_char_scaled_canvas(fb, cols, rows, c, x, y),
        PlotMode::ScaledNoCanvas => plot_char_scaled_uncanvas(fb, cols, rows, c, x, y),
        PlotMode::UnscaledCanvas => plot_char_unscaled_canvas(fb, cols, rows, c, x, y),
        PlotMode::UnscaledNoCanvas => plot_char_unscaled_uncanvas(fb, cols, rows, c, x, y),
    }
}

unsafe fn plot_char_scaled_canvas(
    fb: &FbBackend,
    cols: usize,
    rows: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    if x >= cols || y >= rows {
        return;
    }

    let x = fb.offset_x + x * fb.glyph_width;
    let y = fb.offset_y + y * fb.glyph_height;

    // 防御：字符码越界时按空格处理，避免 `font_bool` 越界访问导致偶发崩溃
    let glyph_idx = c.c as usize;
    let glyph = if glyph_idx < FLANTERM_FB_FONT_GLYPHS {
        fb.font_bool
            .as_ptr()
            .add(glyph_idx * fb.font_height * fb.font_width)
    } else {
        fb.font_bool.as_ptr()
    };
    let canvas_ptr = fb.canvas.as_ref().unwrap().as_ptr();

    let mut dest: *mut u32;
    let outer_stride: isize;
    let inner_stride: isize;

    match fb.rotation {
        FLANTERM_FB_ROTATE_0 => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
        FLANTERM_FB_ROTATE_90 => {
            dest = fb.framebuffer.add((fb.height - 1 - y) + x * (fb.pitch / 4));
            outer_stride = -1;
            inner_stride = (fb.pitch / 4) as isize;
        }
        FLANTERM_FB_ROTATE_180 => {
            dest = fb
                .framebuffer
                .add((fb.width - 1 - x) + (fb.height - 1 - y) * (fb.pitch / 4));
            outer_stride = -((fb.pitch / 4) as isize);
            inner_stride = -1;
        }
        FLANTERM_FB_ROTATE_270 => {
            dest = fb.framebuffer.add(y + (fb.width - 1 - x) * (fb.pitch / 4));
            outer_stride = 1;
            inner_stride = -((fb.pitch / 4) as isize);
        }
        _ => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
    }

    for gy in 0..fb.glyph_height {
        let fy = (gy / fb.font_scale_y) as usize;
        let mut fb_line = dest;
        let canvas_line = canvas_ptr.add(x + (y + gy) * fb.width);
        let mut glyph_pointer = glyph.add(fy * fb.font_width);
        for fx in 0..fb.font_width {
            for i in 0..fb.font_scale_x {
                let gx = fb.font_scale_x * fx + i;
                let bg = if c.bg == FLANTERM_FB_TRANSPARENT {
                    *canvas_line.add(gx)
                } else {
                    c.bg
                };
                let fg = if c.fg == FLANTERM_FB_TRANSPARENT {
                    *canvas_line.add(gx)
                } else {
                    c.fg
                };
                let pixel = if *glyph_pointer != 0 { fg } else { bg };
                unsafe {
                    write_unaligned(fb_line, pixel);
                }
                fb_line = unsafe { fb_line.offset(inner_stride) };
            }
            glyph_pointer = unsafe { glyph_pointer.add(1) };
        }
        dest = dest.offset(outer_stride);
    }
}

unsafe fn plot_char_scaled_uncanvas(
    fb: &FbBackend,
    cols: usize,
    rows: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    if x >= cols || y >= rows {
        return;
    }

    let default_bg = fb.default_bg;
    let bg = if c.bg == FLANTERM_FB_TRANSPARENT {
        default_bg
    } else {
        c.bg
    };
    let fg = if c.fg == FLANTERM_FB_TRANSPARENT {
        fb.default_fg
    } else {
        c.fg
    };

    let x = fb.offset_x + x * fb.glyph_width;
    let y = fb.offset_y + y * fb.glyph_height;

    let glyph = fb
        .font_bool
        .as_ptr()
        .add(c.c as usize * fb.font_height * fb.font_width);

    let mut dest: *mut u32;
    let outer_stride: isize;
    let inner_stride: isize;

    match fb.rotation {
        FLANTERM_FB_ROTATE_0 => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
        FLANTERM_FB_ROTATE_90 => {
            dest = fb.framebuffer.add((fb.height - 1 - y) + x * (fb.pitch / 4));
            outer_stride = -1;
            inner_stride = (fb.pitch / 4) as isize;
        }
        FLANTERM_FB_ROTATE_180 => {
            dest = fb
                .framebuffer
                .add((fb.width - 1 - x) + (fb.height - 1 - y) * (fb.pitch / 4));
            outer_stride = -((fb.pitch / 4) as isize);
            inner_stride = -1;
        }
        FLANTERM_FB_ROTATE_270 => {
            dest = fb.framebuffer.add(y + (fb.width - 1 - x) * (fb.pitch / 4));
            outer_stride = 1;
            inner_stride = -((fb.pitch / 4) as isize);
        }
        _ => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
    }

    for gy in 0..fb.glyph_height {
        let fy = (gy / fb.font_scale_y) as usize;
        let mut fb_line = dest;
        let mut glyph_pointer = glyph.add(fy * fb.font_width);
        for _fx in 0..fb.font_width {
            for _ in 0..fb.font_scale_x {
                let pixel = if *glyph_pointer != 0 { fg } else { bg };
                unsafe {
                    write_unaligned(fb_line, pixel);
                }
                fb_line = unsafe { fb_line.offset(inner_stride) };
            }
            glyph_pointer = unsafe { glyph_pointer.add(1) };
        }
        dest = dest.offset(outer_stride);
    }
}

unsafe fn plot_char_unscaled_canvas(
    fb: &FbBackend,
    cols: usize,
    rows: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    if x >= cols || y >= rows {
        return;
    }

    let x = fb.offset_x + x * fb.glyph_width;
    let y = fb.offset_y + y * fb.glyph_height;

    // 防御：字符码越界时按空格处理，避免 `font_bool` 越界访问导致偶发崩溃
    let glyph_idx = c.c as usize;
    let glyph = if glyph_idx < FLANTERM_FB_FONT_GLYPHS {
        fb.font_bool
            .as_ptr()
            .add(glyph_idx * fb.font_height * fb.font_width)
    } else {
        fb.font_bool.as_ptr()
    };
    let canvas_ptr = fb.canvas.as_ref().unwrap().as_ptr();

    let mut dest: *mut u32;
    let outer_stride: isize;
    let inner_stride: isize;

    match fb.rotation {
        FLANTERM_FB_ROTATE_0 => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
        FLANTERM_FB_ROTATE_90 => {
            dest = fb.framebuffer.add((fb.height - 1 - y) + x * (fb.pitch / 4));
            outer_stride = -1;
            inner_stride = (fb.pitch / 4) as isize;
        }
        FLANTERM_FB_ROTATE_180 => {
            dest = fb
                .framebuffer
                .add((fb.width - 1 - x) + (fb.height - 1 - y) * (fb.pitch / 4));
            outer_stride = -((fb.pitch / 4) as isize);
            inner_stride = -1;
        }
        FLANTERM_FB_ROTATE_270 => {
            dest = fb.framebuffer.add(y + (fb.width - 1 - x) * (fb.pitch / 4));
            outer_stride = 1;
            inner_stride = -((fb.pitch / 4) as isize);
        }
        _ => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
    }

    for gy in 0..fb.glyph_height {
        let mut fb_line = dest;
        let canvas_line = canvas_ptr.add(x + (y + gy) * fb.width);
        let mut glyph_pointer = glyph.add(gy * fb.font_width);
        for fx in 0..fb.font_width {
            let bg = if c.bg == FLANTERM_FB_TRANSPARENT {
                *canvas_line.add(fx)
            } else {
                c.bg
            };
            let fg = if c.fg == FLANTERM_FB_TRANSPARENT {
                *canvas_line.add(fx)
            } else {
                c.fg
            };
            let pixel = if *glyph_pointer != 0 { fg } else { bg };
            unsafe {
                write_unaligned(fb_line, pixel);
            }
            fb_line = unsafe { fb_line.offset(inner_stride) };
            glyph_pointer = unsafe { glyph_pointer.add(1) };
        }
        dest = dest.offset(outer_stride);
    }
}

unsafe fn plot_char_unscaled_uncanvas(
    fb: &FbBackend,
    cols: usize,
    rows: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    if x >= cols || y >= rows {
        return;
    }

    let default_bg = fb.default_bg;
    let bg = if c.bg == FLANTERM_FB_TRANSPARENT {
        default_bg
    } else {
        c.bg
    };
    let fg = if c.fg == FLANTERM_FB_TRANSPARENT {
        fb.default_fg
    } else {
        c.fg
    };

    let x = fb.offset_x + x * fb.glyph_width;
    let y = fb.offset_y + y * fb.glyph_height;

    let glyph = fb
        .font_bool
        .as_ptr()
        .add(c.c as usize * fb.font_height * fb.font_width);

    let mut dest: *mut u32;
    let outer_stride: isize;
    let inner_stride: isize;

    match fb.rotation {
        FLANTERM_FB_ROTATE_0 => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
        FLANTERM_FB_ROTATE_90 => {
            dest = fb.framebuffer.add((fb.height - 1 - y) + x * (fb.pitch / 4));
            outer_stride = -1;
            inner_stride = (fb.pitch / 4) as isize;
        }
        FLANTERM_FB_ROTATE_180 => {
            dest = fb
                .framebuffer
                .add((fb.width - 1 - x) + (fb.height - 1 - y) * (fb.pitch / 4));
            outer_stride = -((fb.pitch / 4) as isize);
            inner_stride = -1;
        }
        FLANTERM_FB_ROTATE_270 => {
            dest = fb.framebuffer.add(y + (fb.width - 1 - x) * (fb.pitch / 4));
            outer_stride = 1;
            inner_stride = -((fb.pitch / 4) as isize);
        }
        _ => {
            dest = fb.framebuffer.add(x + y * (fb.pitch / 4));
            outer_stride = (fb.pitch / 4) as isize;
            inner_stride = 1;
        }
    }

    for gy in 0..fb.glyph_height {
        let mut fb_line = dest;
        let mut glyph_pointer = glyph.add(gy * fb.font_width);
        for _fx in 0..fb.font_width {
            let pixel = if *glyph_pointer != 0 { fg } else { bg };
            unsafe {
                write_unaligned(fb_line, pixel);
            }
            fb_line = unsafe { fb_line.offset(inner_stride) };
            glyph_pointer = unsafe { glyph_pointer.add(1) };
        }
        dest = dest.offset(outer_stride);
    }
}

#[inline(always)]
fn compare_char(a: &FlantermFbChar, b: &FlantermFbChar) -> bool {
    a.c == b.c && a.bg == b.bg && a.fg == b.fg
}

fn push_to_queue(
    fb: &mut FbBackend,
    rows: usize,
    cols: usize,
    c: &FlantermFbChar,
    x: usize,
    y: usize,
) {
    if x >= cols || y >= rows {
        return;
    }

    let i = y * cols + x;
    let mut q_idx = fb.map[i];

    if q_idx.is_none() {
        if compare_char(&fb.grid[i], c) {
            return;
        }
        if fb.queue_i == rows * cols {
            return;
        }
        let idx = fb.queue_i;
        fb.queue_i += 1;
        if fb.queue.len() <= idx {
            fb.queue.push(FlantermFbQueueItem { x, y, c: *c });
        } else {
            fb.queue[idx].x = x;
            fb.queue[idx].y = y;
            fb.queue[idx].c = *c;
        }
        fb.map[i] = Some(idx);
        q_idx = Some(idx);
    }

    if let Some(idx) = q_idx {
        fb.queue[idx].c = *c;
    }
}

fn flanterm_fb_revscroll(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let top = ctx.scroll_top_margin;
    let bot = ctx.scroll_bottom_margin;
    if top >= bot || bot > rows {
        return;
    }

    let fb = &mut ctx.backend;

    // S32：快照复用缓冲（同 scroll——热路径不逐次新建 Vec、分配失败降级
    // 而非 OOM abort）。
    let need = (bot - top) * cols;
    if fb.scroll_scratch.len() < need {
        if fb.scroll_scratch.try_reserve(need - fb.scroll_scratch.len()).is_err() {
            return;
        }
        fb.scroll_scratch.resize(need, FlantermFbChar { c: 0, fg: 0, bg: 0 });
    }
    for i in 0..need {
        let src = top * cols + i;
        fb.scroll_scratch[i] = if let Some(idx) = fb.map[src] {
            fb.queue[idx].c
        } else {
            fb.grid[src]
        };
    }

    // 向下移动 (bot - 1 down to top + 1)
    for y in (top + 1..bot).rev() {
        let src_rel_y = y - 1 - top;
        for x in 0..cols {
            let c_val = fb.scroll_scratch[src_rel_y * cols + x];
            push_to_queue(fb, rows, cols, &c_val, x, y);
        }
    }

    // 顶行填充空格
    let empty = FlantermFbChar {
        c: b' ' as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    for x in 0..cols {
        push_to_queue(fb, rows, cols, &empty, x, top);
    }
}

fn flanterm_fb_scroll(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let top = ctx.scroll_top_margin;
    let bot = ctx.scroll_bottom_margin;
    if top >= bot || bot > rows {
        return;
    }

    let fb = &mut ctx.backend;

    // S32：快照复用缓冲。滚动是热路径（满屏滚动=每行一次），逐次新建 Vec
    // 既常驻分配又堆耗尽 OOM abort。改用 `scroll_scratch` 复用缓冲并按需
    // try_reserve 增长——分配失败时**降级**为直接滚动失败（保持可见性），
    // 而非中止整个内核。
    let need = (bot - top) * cols;
    if fb.scroll_scratch.len() < need {
        if fb.scroll_scratch.try_reserve(need - fb.scroll_scratch.len()).is_err() {
            return;
        }
        fb.scroll_scratch.resize(need, FlantermFbChar { c: 0, fg: 0, bg: 0 });
    }
    for i in 0..need {
        let src = top * cols + i;
        fb.scroll_scratch[i] = if let Some(idx) = fb.map[src] {
            fb.queue[idx].c
        } else {
            fb.grid[src]
        };
    }

    // 向上移动 (top up to bot - 1)
    for y in top..(bot - 1) {
        let src_rel_y = y + 1 - top;
        for x in 0..cols {
            let c_val = fb.scroll_scratch[src_rel_y * cols + x];
            push_to_queue(fb, rows, cols, &c_val, x, y);
        }
    }

    // 底行填充空格
    let empty = FlantermFbChar {
        c: b' ' as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    for x in 0..cols {
        push_to_queue(fb, rows, cols, &empty, x, bot - 1);
    }
}

fn flanterm_fb_clear(ctx: &mut FlantermContext, move_cursor: bool) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let fb = &mut ctx.backend;
    let empty = FlantermFbChar {
        c: b' ' as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    for i in 0..(rows * cols) {
        push_to_queue(fb, rows, cols, &empty, i % cols, i / cols);
    }

    if move_cursor {
        fb.cursor_x = 0;
        fb.cursor_y = 0;
    }
}

fn flanterm_fb_set_cursor_pos(ctx: &mut FlantermContext, mut x: usize, mut y: usize) {
    let fb = &mut ctx.backend;
    if x >= ctx.cols {
        if x > usize::MAX / 2 {
            x = 0;
        } else {
            x = ctx.cols - 1;
        }
    }
    if y >= ctx.rows {
        if y > usize::MAX / 2 {
            y = 0;
        } else {
            y = ctx.rows - 1;
        }
    }
    fb.cursor_x = x;
    fb.cursor_y = y;
}

fn flanterm_fb_get_cursor_pos(ctx: &mut FlantermContext, x: &mut usize, y: &mut usize) {
    let fb = &mut ctx.backend;
    *x = if fb.cursor_x >= ctx.cols {
        ctx.cols - 1
    } else {
        fb.cursor_x
    };
    *y = if fb.cursor_y >= ctx.rows {
        ctx.rows - 1
    } else {
        fb.cursor_y
    };
}

fn flanterm_fb_move_character(
    ctx: &mut FlantermContext,
    new_x: usize,
    new_y: usize,
    old_x: usize,
    old_y: usize,
) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let fb = &mut ctx.backend;
    if old_x >= cols || old_y >= rows || new_x >= cols || new_y >= rows {
        return;
    }
    let i = old_x + old_y * cols;
    let c_val = if let Some(idx) = fb.map[i] {
        fb.queue[idx].c
    } else {
        fb.grid[i]
    };
    push_to_queue(fb, rows, cols, &c_val, new_x, new_y);
}

fn flanterm_fb_set_text_fg(ctx: &mut FlantermContext, fg: usize) {
    let fb = &mut ctx.backend;
    fb.text_fg = fb.ansi_colours[fg];
}

fn flanterm_fb_set_text_bg(ctx: &mut FlantermContext, bg: usize) {
    let fb = &mut ctx.backend;
    fb.text_bg = fb.ansi_colours[bg];
}

fn flanterm_fb_set_text_fg_bright(ctx: &mut FlantermContext, fg: usize) {
    let fb = &mut ctx.backend;
    fb.text_fg = fb.ansi_bright_colours[fg];
}

fn flanterm_fb_set_text_bg_bright(ctx: &mut FlantermContext, bg: usize) {
    let fb = &mut ctx.backend;
    fb.text_bg = fb.ansi_bright_colours[bg];
}

fn flanterm_fb_set_text_fg_rgb(ctx: &mut FlantermContext, fg: u32) {
    let fb = &mut ctx.backend;
    fb.text_fg = convert_colour_fb(fb, fg);
}

fn flanterm_fb_set_text_bg_rgb(ctx: &mut FlantermContext, bg: u32) {
    let fb = &mut ctx.backend;
    fb.text_bg = convert_colour_fb(fb, bg);
}

fn flanterm_fb_set_text_fg_default(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.text_fg = fb.default_fg;
}

fn flanterm_fb_set_text_bg_default(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.text_bg = FLANTERM_FB_TRANSPARENT;
}

fn flanterm_fb_set_text_fg_default_bright(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.text_fg = fb.default_fg_bright;
}

fn flanterm_fb_set_text_bg_default_bright(ctx: &mut FlantermContext) {
    let fb = &mut ctx.backend;
    fb.text_bg = fb.default_bg_bright;
}

fn draw_cursor(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let fb = &mut ctx.backend;
    // 【本仓修订：闪烁相位】相位为 off 时不画反转光标（该格保持真实字符，
    // 由下方 erase/restore 路径保证已擦除此前画上的反转色）。
    if !fb.cursor_blink_on {
        return;
    }
    if fb.cursor_x >= cols || fb.cursor_y >= rows {
        return;
    }
    let i = fb.cursor_x + fb.cursor_y * cols;
    let mut c = if let Some(idx) = fb.map[i] {
        fb.queue[idx].c
    } else {
        fb.grid[i]
    };
    // 【本仓修订：反转前先落实颜色】旧实现直接交换 fg/bg：默认色字符的
    // fg 是 TRANSPARENT（0xffff_ffff），交换后落入 plot_char 的 NoCanvas
    // 透明分支——glyph 用 default_fg 绘在 default_fg 背景上，**字形与背景
    // 同色即不可见**（提示符/普通输入全是默认色，正是"光标所在处文字
    // 不显示"的病灶）。先透明→默认色落实，再交换，得到真正的反转：
    // default_bg 底 + default_fg 字 → default_fg 底 + default_bg 字。
    let fg = if c.fg == FLANTERM_FB_TRANSPARENT {
        fb.default_fg
    } else {
        c.fg
    };
    let bg = if c.bg == FLANTERM_FB_TRANSPARENT {
        fb.default_bg
    } else {
        c.bg
    };
    c.fg = bg;
    c.bg = fg;
    unsafe {
        plot_char(fb, cols, rows, &c, fb.cursor_x, fb.cursor_y);
    }
    // S20：不得在此吸收（清空）光标格的 pending 项。若光标正落在有待刷
    // 新字符的格上，此处只画反转色光标，**保留** `map[i]=Some(idx)`，让
    // 随后的 double_buffer_flush 循环画出该格的真实颜色。旧实现在此把
    // `grid[i]=queue[idx].c` 并 `map[i]=None`，导致 flush 循环以
    // `map.is_none()` 跳过该格——真实颜色永远不被绘制，屏幕残留反转
    // 字符（`write("A\x1b[H")` 可复现）。
}

fn flanterm_fb_double_buffer_flush(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;

    if ctx.cursor_enabled {
        draw_cursor(ctx);
    }

    {
        let fb = &mut ctx.backend;
        for i in 0..fb.queue_i {
            let (qx, qy, qc) = {
                let q = &fb.queue[i];
                (q.x, q.y, q.c)
            };
            let offset = qy * cols + qx;
            if fb.map[offset].is_none() {
                continue;
            }
            unsafe {
                plot_char(fb, cols, rows, &qc, qx, qy);
            }
            fb.grid[offset] = qc;
            fb.map[offset] = None;
        }

        if (fb.old_cursor_x != fb.cursor_x || fb.old_cursor_y != fb.cursor_y) || !ctx.cursor_enabled
        {
            if fb.old_cursor_x < cols && fb.old_cursor_y < rows {
                let idx = fb.old_cursor_x + fb.old_cursor_y * cols;
                let c = &fb.grid[idx];
                unsafe {
                    plot_char(fb, cols, rows, c, fb.old_cursor_x, fb.old_cursor_y);
                }
            }
        }

        fb.old_cursor_x = fb.cursor_x;
        fb.old_cursor_y = fb.cursor_y;
        fb.queue_i = 0;

        if let Some(cb) = fb.flush_callback {
            unsafe {
                cb(fb.framebuffer as *const u8, fb.pitch * fb.phys_height);
            }
        }
    }
}

/// 【本仓修订：光标闪烁】翻转闪烁相位并重绘受影响的两格。
///
/// 由表现层（term crate）经周期定时器调用（当前 500ms）。步骤：
/// 1. 先在 (old_cursor_x, old_cursor_y) 重画**真实字符**——无条件擦除该格
///    可能残留的反转光标（相位 on→off 时这是唯一的擦除路径；普通 flush 的
///    restore 分支只在光标移动时触发，覆盖不到原地闪烁）；
/// 2. 翻转 `cursor_blink_on`；
/// 3. 相位翻为 on 时在当前光标位画反转色。
///
/// 调用方须自行持有终端锁（term 侧 TERM_LOCK）；本函数不碰队列状态，
/// 与 `flanterm_write` 的 flush 语义正交。中断上下文调用安全：只做
/// framebuffer 定点写与回调，无分配、无自旋等待。
pub fn flanterm_fb_blink_toggle(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    {
        let fb = &mut ctx.backend;
        if fb.old_cursor_x < cols && fb.old_cursor_y < rows {
            let idx = fb.old_cursor_x + fb.old_cursor_y * cols;
            let c = fb.grid[idx];
            unsafe {
                plot_char(fb, cols, rows, &c, fb.old_cursor_x, fb.old_cursor_y);
            }
        }
        fb.cursor_blink_on = !fb.cursor_blink_on;
    }
    if ctx.cursor_enabled {
        draw_cursor(ctx);
    }
    let cb = ctx.backend.flush_callback;
    if let Some(cb) = cb {
        unsafe {
            cb(ctx.backend.framebuffer as *const u8, ctx.backend.pitch * ctx.backend.phys_height);
        }
    }
}

fn flanterm_fb_raw_putchar(ctx: &mut FlantermContext, c: u8) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let mut need_scroll = false;

    {
        let fb = &mut ctx.backend;
        if fb.cursor_x >= cols {
            if ctx.wrap_enabled
                && (fb.cursor_y < ctx.scroll_bottom_margin - 1 || ctx.scroll_enabled)
            {
                fb.cursor_x = 0;
                fb.cursor_y += 1;
                if fb.cursor_y == ctx.scroll_bottom_margin {
                    fb.cursor_y -= 1;
                    need_scroll = true;
                }
                if fb.cursor_y >= rows {
                    fb.cursor_y = rows - 1;
                }
            } else {
                fb.cursor_x = cols - 1;
            }
        }
    }

    if need_scroll {
        flanterm_fb_scroll(ctx);
    }

    let fb = &mut ctx.backend;
    let ch = FlantermFbChar {
        c: c as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    push_to_queue(fb, rows, cols, &ch, fb.cursor_x, fb.cursor_y);
    fb.cursor_x += 1;
}

fn flanterm_fb_full_refresh(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let (framebuffer, pitch, phys_height, flush_callback) = {
        let fb = &mut ctx.backend;
        let default_bg = fb.default_bg;
        let rotation = fb.rotation;
        let width = fb.width;
        let height = fb.height;

        for y in 0..height {
            for x in 0..width {
                let (px, py) = match rotation {
                    FLANTERM_FB_ROTATE_0 => (x, y),
                    FLANTERM_FB_ROTATE_90 => (height - 1 - y, x),
                    FLANTERM_FB_ROTATE_180 => (width - 1 - x, height - 1 - y),
                    FLANTERM_FB_ROTATE_270 => (y, width - 1 - x),
                    _ => (x, y),
                };
                let offset = py * (fb.pitch / size_of::<u32>()) + px;
                if let Some(canvas) = fb.canvas.as_ref() {
                    let val = canvas[y * width + x];
                    unsafe {
                        write_unaligned(fb.framebuffer.add(offset), val);
                    }
                } else {
                    unsafe {
                        write_unaligned(fb.framebuffer.add(offset), default_bg);
                    }
                }
            }
        }

        for i in 0..(rows * cols) {
            let x = i % cols;
            let y = i / cols;
            unsafe {
                plot_char(fb, cols, rows, &fb.grid[i], x, y);
            }
        }

        (fb.framebuffer, fb.pitch, fb.phys_height, fb.flush_callback)
    };

    if ctx.cursor_enabled {
        draw_cursor(ctx);
    }

    if let Some(cb) = flush_callback {
        unsafe {
            cb(framebuffer as *const u8, pitch * phys_height);
        }
    }
}

impl BackendOps for FbBackend {
    fn raw_putchar(ctx: &mut FlantermCore<FbBackend>, c: u8) {
        flanterm_fb_raw_putchar(ctx, c);
    }

    fn clear(ctx: &mut FlantermCore<FbBackend>, move_cursor: bool) {
        flanterm_fb_clear(ctx, move_cursor);
    }

    fn set_cursor_pos(ctx: &mut FlantermCore<FbBackend>, x: usize, y: usize) {
        flanterm_fb_set_cursor_pos(ctx, x, y);
    }

    fn get_cursor_pos(ctx: &mut FlantermCore<FbBackend>, x: &mut usize, y: &mut usize) {
        flanterm_fb_get_cursor_pos(ctx, x, y);
    }

    fn set_text_fg(ctx: &mut FlantermCore<FbBackend>, fg: usize) {
        flanterm_fb_set_text_fg(ctx, fg);
    }

    fn set_text_bg(ctx: &mut FlantermCore<FbBackend>, bg: usize) {
        flanterm_fb_set_text_bg(ctx, bg);
    }

    fn set_text_fg_bright(ctx: &mut FlantermCore<FbBackend>, fg: usize) {
        flanterm_fb_set_text_fg_bright(ctx, fg);
    }

    fn set_text_bg_bright(ctx: &mut FlantermCore<FbBackend>, bg: usize) {
        flanterm_fb_set_text_bg_bright(ctx, bg);
    }

    fn set_text_fg_rgb(ctx: &mut FlantermCore<FbBackend>, fg: u32) {
        flanterm_fb_set_text_fg_rgb(ctx, fg);
    }

    fn set_text_bg_rgb(ctx: &mut FlantermCore<FbBackend>, bg: u32) {
        flanterm_fb_set_text_bg_rgb(ctx, bg);
    }

    fn set_text_fg_default(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_set_text_fg_default(ctx);
    }

    fn set_text_bg_default(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_set_text_bg_default(ctx);
    }

    fn set_text_fg_default_bright(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_set_text_fg_default_bright(ctx);
    }

    fn set_text_bg_default_bright(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_set_text_bg_default_bright(ctx);
    }

    fn move_character(
        ctx: &mut FlantermCore<FbBackend>,
        new_x: usize,
        new_y: usize,
        old_x: usize,
        old_y: usize,
    ) {
        flanterm_fb_move_character(ctx, new_x, new_y, old_x, old_y);
    }

    fn scroll(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_scroll(ctx);
    }

    fn revscroll(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_revscroll(ctx);
    }

    fn swap_palette(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_swap_palette(ctx);
    }

    fn save_state(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_save_state(ctx);
    }

    fn restore_state(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_restore_state(ctx);
    }

    fn double_buffer_flush(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_double_buffer_flush(ctx);
    }

    fn full_refresh(ctx: &mut FlantermCore<FbBackend>) {
        flanterm_fb_full_refresh(ctx);
    }
}

/// # Safety
///
/// - `framebuffer` must point to a valid, writable framebuffer of at least
///   `pitch * height` bytes (for the native rotation) or `pitch * phys_height`
///   bytes (when rotation is 90/270).
/// - `canvas` must be either null or point to a valid writable buffer of
///   size `width * height * 4` bytes (in the post-rotation coordinate system).
/// - `ansi_colours`, `ansi_bright_colours`, `default_bg`, `default_fg`,
///   `default_bg_bright`, `default_fg_bright` must be null or point to valid
///   writable `u32` values.
/// - `font` must be null (a built-in default is used) or point to a valid font
///   bitmap of sufficient size for the specified `font_width × font_height`.
/// - All pointer arguments must remain valid for the lifetime of the returned
///   `FlantermContext`.
/// - The caller is responsible for ensuring that the framebuffer and canvas
///   are not aliased by any other mutable reference.
pub unsafe fn flanterm_fb_init(
    framebuffer: *mut u32,
    mut width: usize,
    mut height: usize,
    pitch: usize,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
    canvas: *mut u32,
    ansi_colours: *mut u32,
    ansi_bright_colours: *mut u32,
    default_bg: *mut u32,
    default_fg: *mut u32,
    default_bg_bright: *mut u32,
    default_fg_bright: *mut u32,
    font: *mut u8,
    mut font_width: usize,
    mut font_height: usize,
    mut font_spacing: usize,
    mut font_scale_x: usize,
    mut font_scale_y: usize,
    margin: usize,
    rotation: i32,
) -> Option<Box<FlantermContext>> {
    let phys_height = height;

    if rotation == FLANTERM_FB_ROTATE_90 || rotation == FLANTERM_FB_ROTATE_270 {
        let tmp = width;
        width = height;
        height = tmp;
    }

    if font_scale_x == 0 || font_scale_y == 0 {
        font_scale_x = 1;
        font_scale_y = 1;
        // S16：自动缩放阈值具名并注释来源——4K(3840×2160) 与 2.5K(2560×1440)
        // 为常见高分屏档位，此阈值源自 C 版 flanterm 的既有行为（沿袭原语义，
        // 未记录具体出处，属"高清屏放大以保可读性"的经验档）。分辨率达到
        // 该档即放大，否则 1x。
        // 0/非 0 混传语义：任一为 0 即视为"请求自动"，两轴都被重置为自动——
        // 不单独尊重另一轴的手动值（既有行为，注释记录）。
        if width >= SCALE2_MIN_WIDTH && height >= SCALE2_MIN_HEIGHT {
            font_scale_x = 2;
            font_scale_y = 2;
        }
        if width >= SCALE4_MIN_WIDTH && height >= SCALE4_MIN_HEIGHT {
            font_scale_x = 4;
            font_scale_y = 4;
        }
    }

    if red_mask_size < 8 || red_mask_size != green_mask_size || red_mask_size != blue_mask_size {
        return None;
    }

    if font.is_null() {
        font_width = 8;
        font_height = 16;
        font_spacing = 1;
    }

    let font_width_with_spacing = font_width + font_spacing;
    let glyph_width = font_width_with_spacing * font_scale_x;
    let glyph_height = font_height * font_scale_y;
    let cols = (width - margin * 2) / glyph_width;
    let rows = (height - margin * 2) / glyph_height;

    // S17: 小分辨率 / 大边距 framebuffer 会算出 rows==0 或 cols==0。空终端
    // 构造后 `scroll_bottom_margin-1` / `cols-1` 立即下溢 panic（debug）或
    // 回绕成巨大值（release）。此处如实拒绝（返回 None），绝不构造一个
    // 必然在下游崩溃的空上下文。
    if rows == 0 || cols == 0 {
        return None;
    }
    let offset_x = margin + ((width - margin * 2) % glyph_width) / 2;
    let offset_y = margin + ((height - margin * 2) % glyph_height) / 2;

    let backend = FbBackend {
        plot_mode: PlotMode::UnscaledNoCanvas,
        flush_callback: None,
        font_width: font_width_with_spacing,
        font_height,
        glyph_width,
        glyph_height,
        font_scale_x,
        font_scale_y,
        offset_x,
        offset_y,
        framebuffer,
        pitch,
        width,
        height,
        phys_height,
        red_mask_size,
        red_mask_shift: red_mask_shift + (red_mask_size - 8),
        green_mask_size,
        green_mask_shift: green_mask_shift + (green_mask_size - 8),
        blue_mask_size,
        blue_mask_shift: blue_mask_shift + (blue_mask_size - 8),
        rotation,
        font_bits: Vec::new(),
        font_bool: Vec::new(),
        ansi_colours: [0; 8],
        ansi_bright_colours: [0; 8],
        default_fg: 0,
        default_bg: 0,
        default_fg_bright: 0,
        default_bg_bright: 0,
        canvas: None,
        grid: Vec::new(),
        queue: Vec::new(),
        queue_i: 0,
        map: Vec::new(),
        text_fg: 0,
        text_bg: FLANTERM_FB_TRANSPARENT,
        cursor_x: 0,
        cursor_y: 0,
        saved_state_text_fg: 0,
        saved_state_text_bg: 0,
        saved_state_cursor_x: 0,
        saved_state_cursor_y: 0,
        old_cursor_x: 0,
        old_cursor_y: 0,
        cursor_blink_on: true,
        scroll_scratch: Vec::new(),
    };

    let mut ctx = Box::new(flanterm_context_new(backend, rows, cols));
    let fb = &mut ctx.backend;

    if !ansi_colours.is_null() {
        for i in 0..8 {
            fb.ansi_colours[i] = convert_colour_fb(fb, *ansi_colours.add(i));
        }
    } else {
        fb.ansi_colours[0] = convert_colour_fb(fb, 0x0000_0000);
        fb.ansi_colours[1] = convert_colour_fb(fb, 0x00aa_0000);
        fb.ansi_colours[2] = convert_colour_fb(fb, 0x0000_aa00);
        fb.ansi_colours[3] = convert_colour_fb(fb, 0x00aa_5500);
        fb.ansi_colours[4] = convert_colour_fb(fb, 0x0000_00aa);
        fb.ansi_colours[5] = convert_colour_fb(fb, 0x00aa_00aa);
        fb.ansi_colours[6] = convert_colour_fb(fb, 0x0000_aaaa);
        fb.ansi_colours[7] = convert_colour_fb(fb, 0x00aa_aaaa);
    }

    if !ansi_bright_colours.is_null() {
        for i in 0..8 {
            fb.ansi_bright_colours[i] = convert_colour_fb(fb, *ansi_bright_colours.add(i));
        }
    } else {
        fb.ansi_bright_colours[0] = convert_colour_fb(fb, 0x0055_5555);
        fb.ansi_bright_colours[1] = convert_colour_fb(fb, 0x00ff_5555);
        fb.ansi_bright_colours[2] = convert_colour_fb(fb, 0x0055_ff55);
        fb.ansi_bright_colours[3] = convert_colour_fb(fb, 0x00ff_ff55);
        fb.ansi_bright_colours[4] = convert_colour_fb(fb, 0x0055_55ff);
        fb.ansi_bright_colours[5] = convert_colour_fb(fb, 0x00ff_55ff);
        fb.ansi_bright_colours[6] = convert_colour_fb(fb, 0x0055_ffff);
        fb.ansi_bright_colours[7] = convert_colour_fb(fb, 0x00ff_ffff);
    }

    if !default_bg.is_null() {
        fb.default_bg = convert_colour_fb(fb, *default_bg);
    } else {
        fb.default_bg = 0x0000_0000;
    }

    if !default_fg.is_null() {
        fb.default_fg = convert_colour_fb(fb, *default_fg);
    } else {
        fb.default_fg = convert_colour_fb(fb, 0x00aa_aaaa);
    }

    if !default_bg_bright.is_null() {
        fb.default_bg_bright = convert_colour_fb(fb, *default_bg_bright);
    } else {
        fb.default_bg_bright = convert_colour_fb(fb, 0x0055_5555);
    }

    if !default_fg_bright.is_null() {
        fb.default_fg_bright = convert_colour_fb(fb, *default_fg_bright);
    } else {
        fb.default_fg_bright = convert_colour_fb(fb, 0x00ff_ffff);
    }

    fb.text_fg = fb.default_fg;
    fb.text_bg = FLANTERM_FB_TRANSPARENT;

    if !font.is_null() {
        let font_bytes = font_height * FLANTERM_FB_FONT_GLYPHS;
        fb.font_bits = vec![0u8; font_bytes];
        copy_nonoverlapping(font, fb.font_bits.as_mut_ptr(), font_bytes);
    } else {
        let font_bytes = font_height * FLANTERM_FB_FONT_GLYPHS;
        fb.font_bits = vec![0u8; font_bytes];
        copy_nonoverlapping(BUILTIN_FONT.as_ptr(), fb.font_bits.as_mut_ptr(), font_bytes);
    }

    fb.font_bool = vec![0u8; FLANTERM_FB_FONT_GLYPHS * font_height * fb.font_width];

    for i in 0..FLANTERM_FB_FONT_GLYPHS {
        let glyph = fb.font_bits.as_ptr().add(i * font_height);
        for y in 0..font_height {
            for x in 0..8 {
                let offset = i * font_height * fb.font_width + y * fb.font_width + x;
                let bit = (*glyph.add(y) & (0x80 >> x)) != 0;
                fb.font_bool[offset] = if bit { 1 } else { 0 };
            }
            for x in 8..fb.font_width {
                let offset = i * font_height * fb.font_width + y * fb.font_width + x;
                let bit = if (0xc0..=0xdf).contains(&i) {
                    (*glyph.add(y) & 1) != 0
                } else {
                    false
                };
                fb.font_bool[offset] = if bit { 1 } else { 0 };
            }
        }
    }

    fb.grid = vec![
        FlantermFbChar {
            c: b' ' as u32,
            fg: fb.text_fg,
            bg: fb.text_bg
        };
        rows * cols
    ];
    fb.queue = vec![
        FlantermFbQueueItem {
            x: 0,
            y: 0,
            c: FlantermFbChar {
                c: b' ' as u32,
                fg: fb.text_fg,
                bg: fb.text_bg
            }
        };
        rows * cols
    ];
    fb.queue_i = 0;
    fb.map = vec![None; rows * cols];

    if !canvas.is_null() {
        let mut canvas_buf = vec![0u32; width * height];
        for i in 0..(width * height) {
            canvas_buf[i] = convert_colour_fb(fb, *canvas.add(i));
        }
        fb.canvas = Some(canvas_buf);
    }

    if font_scale_x == 1 && font_scale_y == 1 {
        if canvas.is_null() {
            (*fb).plot_mode = PlotMode::UnscaledNoCanvas;
        } else {
            (*fb).plot_mode = PlotMode::UnscaledCanvas;
        }
    } else if canvas.is_null() {
        (*fb).plot_mode = PlotMode::ScaledNoCanvas;
    } else {
        (*fb).plot_mode = PlotMode::ScaledCanvas;
    }
    flanterm_context_reinit(&mut *ctx);
    flanterm_fb_full_refresh(&mut *ctx);

    Some(ctx)
}

pub fn flanterm_fb_set_flush_callback(ctx: &mut FlantermContext, flush_callback: FlushCallback) {
    ctx.backend.flush_callback = flush_callback;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小可绘制 FbBackend：实帧缓冲、实心字形（全 0xFF），
    /// 使 `plot_char` 把整个字形格涂成 `fg` 色，便于直接断言像素。
    fn test_backend(width: usize, height: usize) -> (FbBackend, Vec<u32>) {
        let mut fb_buf = vec![0u32; width * height];
        let fb_ptr = fb_buf.as_mut_ptr();
        let font_bool = vec![0xFFu8; 8 * 16]; // 实心字形
        let backend = FbBackend {
            plot_mode: PlotMode::UnscaledNoCanvas,
            flush_callback: None,
            font_width: 8,
            font_height: 16,
            glyph_width: 8,
            glyph_height: 16,
            font_scale_x: 1,
            font_scale_y: 1,
            offset_x: 0,
            offset_y: 0,
            framebuffer: fb_ptr,
            pitch: width * 4,
            width,
            height,
            phys_height: height,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
            rotation: FLANTERM_FB_ROTATE_0,
            font_bits: Vec::new(),
            font_bool,
            ansi_colours: [0; 8],
            ansi_bright_colours: [0; 8],
            default_fg: 0x00aa_aaaa,
            default_bg: 0x0000_0000,
            default_fg_bright: 0x00ff_ffff,
            default_bg_bright: 0x0055_5555,
            canvas: None,
            grid: vec![
                FlantermFbChar {
                    c: 0,
                    fg: 0x00aa_aaaa,
                    bg: 0x0000_0000,
                };
                (width / 8) * (height / 16)
            ],
            queue: Vec::new(),
            queue_i: 0,
            map: vec![None; (width / 8) * (height / 16)],
            text_fg: 0x00aa_aaaa,
            text_bg: FLANTERM_FB_TRANSPARENT,
            cursor_x: 0,
            cursor_y: 0,
            saved_state_text_fg: 0,
            saved_state_text_bg: 0,
            saved_state_cursor_x: 0,
            saved_state_cursor_y: 0,
            old_cursor_x: 0,
            old_cursor_y: 0,
            cursor_blink_on: true,
            scroll_scratch: Vec::new(),
        };
        (backend, fb_buf)
    }

    /// 构造一个已启用光标的 FlantermContext（rows×cols 网格）。
    fn test_ctx(width: usize, height: usize) -> (FlantermContext, Vec<u32>) {
        let (backend, fb_buf) = test_backend(width, height);
        let cols = width / 8;
        let rows = height / 16;
        let mut ctx = Box::new(flanterm_context_new(backend, rows, cols));
        ctx.cursor_enabled = true;
        ctx.autoflush = false;
        (*ctx, fb_buf)
    }

    /// S20 回归：flush 不得吞掉光标格上的真实字符颜色。
    ///
    /// 复现 `write("A\x1b[H")`：在光标格 (0,0) 放入 pending 项（真实 fg=RED,
    /// bg=BLUE），光标也停在 (0,0)。旧实现 `draw_cursor` 先执行：画出
    /// **反转色**（fg=BLUE）并吸收该 pending 项（map 置 None），随后 flush
    /// 循环因 `map[offset].is_none()` 跳过该格——真实颜色永远不被绘制，
    /// 屏幕残留反转 'A'。修复后 flush 必须画出真实 fg=RED。
    #[test]
    fn flush_does_not_swallow_cursor_cell_real_color() {
        let (mut ctx, fb_buf) = test_ctx(80, 160); // 10 列 × 10 行
        let cols = ctx.cols;
        let real = FlantermFbChar {
            c: 0,
            fg: 0x00ff_0000, // RED
            bg: 0x0000_00ff, // BLUE
        };
        // 在光标格 (0,0) 放一个 pending 项，并把光标也放在 (0,0)。
        ctx.backend.queue.push(FlantermFbQueueItem {
            x: 0,
            y: 0,
            c: real,
        });
        ctx.backend.queue_i = 1;
        ctx.backend.map[0] = Some(0);
        ctx.backend.grid[0] = FlantermFbChar {
            c: 0,
            fg: 0,
            bg: 0,
        };
        ctx.backend.cursor_x = 0;
        ctx.backend.cursor_y = 0;

        // 刷新：draw_cursor + flush 循环。
        flanterm_fb_double_buffer_flush(&mut ctx);

        // 首像素应已是真实 fg=RED（实心字形全涂 fg）。
        let pixel = fb_buf[0];
        assert_eq!(
            pixel, 0x00ff_0000,
            "S20: flush must draw the real cursor-cell color, not swallow it as reversed"
        );
    }

    /// S17 回归：小分辨率/大边距 framebuffer 会算出 rows==0 或 cols==0，
    /// 构造出空终端后 `scroll_bottom_margin-1`/`cols-1` 下溢 panic。
    /// `flanterm_fb_init` 必须在 rows/cols 非正时返回 None（拒绝构造），
    /// 而非返回一个必然在下游下溢的空上下文。
    #[test]
    fn fb_init_rejects_zero_rows_or_cols() {
        // 8×16 字形、margin=8：宽 16、高 32 → (16-16)/8=0 列、(32-16)/16=1 行。
        // 至少有一维为 0，必须被拒绝。
        let mut fb = [0u32; 16 * 32];
        unsafe {
            let r = flanterm_fb_init(
                fb.as_mut_ptr(),
                16,     // width
                32,     // height
                16 * 4, // pitch
                8, 0, 8, 8, 8, 16, // masks
                core::ptr::null_mut(), // canvas
                core::ptr::null_mut(), // ansi_colours
                core::ptr::null_mut(), // ansi_bright_colours
                core::ptr::null_mut(), // default_bg
                core::ptr::null_mut(), // default_fg
                core::ptr::null_mut(), // default_bg_bright
                core::ptr::null_mut(), // default_fg_bright
                core::ptr::null_mut(), // font
                8, 16, 1, // font w/h/spacing
                1, 1, // scale
                8,    // margin
                FLANTERM_FB_ROTATE_0,
            );
            assert!(
                r.is_none(),
                "S17: fb_init must reject a framebuffer too small to hold any glyph"
            );
        }
    }

    /// S32 回归：向上滚动后内容整体上移、底行变空格，且滚动可正确读写
    /// map/queue/grid 三层状态（快照逻辑不得踩踏）。
    #[test]
    fn scroll_moves_rows_up_and_blank_bottom() {
        let (mut ctx, _fb) = test_ctx(80, 160); // 10 列 × 10 行
        let cols = ctx.cols;
        // 第 1 行（y=1）放一个字符 'A'（fg 固定），其余行空格。
        let a = FlantermFbChar {
            c: b'A' as u32,
            fg: 0x00ff_0000,
            bg: 0,
        };
        // 通过 push_to_queue 写入 (0,1)，让 grid/map/queue 一致。
        push_to_queue(&mut ctx.backend, ctx.rows, cols, &a, 0, 1);
        // 触发一次向上滚动。
        ctx.scroll_top_margin = 0;
        ctx.scroll_bottom_margin = ctx.rows;
        flanterm_fb_scroll(&mut ctx);

        // 滚动后原 (0,1) 的 'A' 应出现在 (0,0)（内容上移一行）。
        let cell = visible(&ctx.backend, cols, 0, 0);
        assert_eq!(cell.c, b'A' as u32, "scroll should move row 1 content up to row 0");
        // 底行应为空格。
        let last = visible(&ctx.backend, cols, 0, ctx.rows - 1);
        assert_eq!(last.c, b' ' as u32, "scroll should blank the bottom row");
    }

    /// 读取某格当前可见字符（map 优先于 grid）。
    fn visible(fb: &FbBackend, cols: usize, x: usize, y: usize) -> FlantermFbChar {
        let i = y * cols + x;
        if let Some(idx) = fb.map[i] {
            fb.queue[idx].c
        } else {
            fb.grid[i]
        }
    }
}
