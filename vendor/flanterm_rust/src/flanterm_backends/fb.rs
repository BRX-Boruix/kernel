use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{copy_nonoverlapping, write_volatile};

use crate::flanterm::{flanterm_context_new, flanterm_context_reinit, BackendOps, FlantermCore};
use crate::generated::BUILTIN_FONT;

pub const FLANTERM_FB_ROTATE_0: i32 = 0;
pub const FLANTERM_FB_ROTATE_90: i32 = 1;
pub const FLANTERM_FB_ROTATE_180: i32 = 2;
pub const FLANTERM_FB_ROTATE_270: i32 = 3;

const FLANTERM_FB_FONT_GLYPHS: usize = 256;

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
    if fb.text_fg == 0xffff_ffff {
        fb.text_fg = fb.default_bg;
    }
    if fb.text_bg == fb.default_bg {
        fb.text_bg = 0xffff_ffff;
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

    let glyph = fb
        .font_bool
        .as_ptr()
        .add(c.c as usize * fb.font_height * fb.font_width);
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
                let bg = if c.bg == 0xffff_ffff {
                    *canvas_line.add(gx)
                } else {
                    c.bg
                };
                let fg = if c.fg == 0xffff_ffff {
                    *canvas_line.add(gx)
                } else {
                    c.fg
                };
                let pixel = if *glyph_pointer != 0 { fg } else { bg };
                unsafe {
                    write_volatile(fb_line, pixel);
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
    let bg = if c.bg == 0xffff_ffff {
        default_bg
    } else {
        c.bg
    };
    let fg = if c.fg == 0xffff_ffff {
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
                    write_volatile(fb_line, pixel);
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

    let glyph = fb
        .font_bool
        .as_ptr()
        .add(c.c as usize * fb.font_height * fb.font_width);
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
            let bg = if c.bg == 0xffff_ffff {
                *canvas_line.add(fx)
            } else {
                c.bg
            };
            let fg = if c.fg == 0xffff_ffff {
                *canvas_line.add(fx)
            } else {
                c.fg
            };
            let pixel = if *glyph_pointer != 0 { fg } else { bg };
            unsafe {
                write_volatile(fb_line, pixel);
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
    let bg = if c.bg == 0xffff_ffff {
        default_bg
    } else {
        c.bg
    };
    let fg = if c.fg == 0xffff_ffff {
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
                write_volatile(fb_line, pixel);
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
    let start = ctx.scroll_top_margin * cols;
    let end = (ctx.scroll_bottom_margin - 1) * cols;
    let fb = &mut ctx.backend;
    let mut i = end;
    while i > start {
        i -= 1;
        let c_val = if let Some(idx) = fb.map[i] {
            fb.queue[idx].c
        } else {
            fb.grid[i]
        };
        push_to_queue(fb, rows, cols, &c_val, (i + cols) % cols, (i + cols) / cols);
    }

    let empty = FlantermFbChar {
        c: b' ' as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    for i in 0..cols {
        push_to_queue(fb, rows, cols, &empty, i, ctx.scroll_top_margin);
    }
}

fn flanterm_fb_scroll(ctx: &mut FlantermContext) {
    let rows = ctx.rows;
    let cols = ctx.cols;
    let start = (ctx.scroll_top_margin + 1) * cols;
    let end = ctx.scroll_bottom_margin * cols;
    let fb = &mut ctx.backend;
    for i in start..end {
        let c_val = if let Some(idx) = fb.map[i] {
            fb.queue[idx].c
        } else {
            fb.grid[i]
        };
        push_to_queue(fb, rows, cols, &c_val, (i - cols) % cols, (i - cols) / cols);
    }

    let empty = FlantermFbChar {
        c: b' ' as u32,
        fg: fb.text_fg,
        bg: fb.text_bg,
    };
    for i in 0..cols {
        push_to_queue(fb, rows, cols, &empty, i, ctx.scroll_bottom_margin - 1);
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
    fb.text_bg = 0xffff_ffff;
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
    if fb.cursor_x >= cols || fb.cursor_y >= rows {
        return;
    }
    let i = fb.cursor_x + fb.cursor_y * cols;
    let mut c = if let Some(idx) = fb.map[i] {
        fb.queue[idx].c
    } else {
        fb.grid[i]
    };
    let tmp = c.fg;
    c.fg = c.bg;
    c.bg = tmp;
    unsafe {
        plot_char(fb, cols, rows, &c, fb.cursor_x, fb.cursor_y);
    }
    if let Some(idx) = fb.map[i] {
        fb.grid[i] = fb.queue[idx].c;
        fb.map[i] = None;
    }
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
                        write_volatile(fb.framebuffer.add(offset), val);
                    }
                } else {
                    unsafe {
                        write_volatile(fb.framebuffer.add(offset), default_bg);
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
        if width >= (1920 + 1920 / 3) && height >= (1080 + 1080 / 3) {
            font_scale_x = 2;
            font_scale_y = 2;
        }
        if width >= (3840 + 3840 / 3) && height >= (2160 + 2160 / 3) {
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
        text_bg: 0xffff_ffff,
        cursor_x: 0,
        cursor_y: 0,
        saved_state_text_fg: 0,
        saved_state_text_bg: 0,
        saved_state_cursor_x: 0,
        saved_state_cursor_y: 0,
        old_cursor_x: 0,
        old_cursor_y: 0,
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
    fb.text_bg = 0xffff_ffff;

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
