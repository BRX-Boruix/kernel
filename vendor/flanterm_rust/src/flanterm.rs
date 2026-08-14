use crate::generated::{Interval, COL256, COMBINING, WIDE};
use crate::unicode_map::unicode_to_cp437;

pub const FLANTERM_CB_DEC: u64 = 10;
pub const FLANTERM_CB_BELL: u64 = 20;
pub const FLANTERM_CB_PRIVATE_ID: u64 = 30;
pub const FLANTERM_CB_STATUS_REPORT: u64 = 40;
pub const FLANTERM_CB_POS_REPORT: u64 = 50;
pub const FLANTERM_CB_KBD_LEDS: u64 = 60;
pub const FLANTERM_CB_MODE: u64 = 70;
pub const FLANTERM_CB_LINUX: u64 = 80;
pub const FLANTERM_CB_OSC: u64 = 90;

pub const FLANTERM_MAX_ESC_VALUES: usize = 16;

const CHARSET_DEFAULT: u8 = 0;
const CHARSET_DEC_SPECIAL: u8 = 1;

const COLOR_DEFAULT: usize = usize::MAX;
const COLOR_RGB: usize = usize::MAX - 1;

pub enum FlantermCallback<'a> {
    Dec { params: &'a [u32], suffix: u8 },
    Bell,
    PrivateId,
    StatusReport,
    PosReport { x: usize, y: usize },
    KbdLeds { value: u32 },
    Mode { params: &'a [u32], suffix: u8 },
    Linux { params: &'a [u32] },
    Osc { id: u64, data: &'a [u8] },
}

pub type FlantermCallbackFn<B> = Option<for<'a> fn(&mut FlantermCore<B>, FlantermCallback<'a>)>;

pub trait BackendOps {
    fn raw_putchar(ctx: &mut FlantermCore<Self>, c: u8)
    where
        Self: Sized;
    fn clear(ctx: &mut FlantermCore<Self>, move_cursor: bool)
    where
        Self: Sized;
    fn set_cursor_pos(ctx: &mut FlantermCore<Self>, x: usize, y: usize)
    where
        Self: Sized;
    fn get_cursor_pos(ctx: &mut FlantermCore<Self>, x: &mut usize, y: &mut usize)
    where
        Self: Sized;
    fn set_text_fg(ctx: &mut FlantermCore<Self>, fg: usize)
    where
        Self: Sized;
    fn set_text_bg(ctx: &mut FlantermCore<Self>, bg: usize)
    where
        Self: Sized;
    fn set_text_fg_bright(ctx: &mut FlantermCore<Self>, fg: usize)
    where
        Self: Sized;
    fn set_text_bg_bright(ctx: &mut FlantermCore<Self>, bg: usize)
    where
        Self: Sized;
    fn set_text_fg_rgb(ctx: &mut FlantermCore<Self>, fg: u32)
    where
        Self: Sized;
    fn set_text_bg_rgb(ctx: &mut FlantermCore<Self>, bg: u32)
    where
        Self: Sized;
    fn set_text_fg_default(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn set_text_bg_default(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn set_text_fg_default_bright(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn set_text_bg_default_bright(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn move_character(
        ctx: &mut FlantermCore<Self>,
        new_x: usize,
        new_y: usize,
        old_x: usize,
        old_y: usize,
    ) where
        Self: Sized;
    fn scroll(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn revscroll(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn swap_palette(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn save_state(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn restore_state(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn double_buffer_flush(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
    fn full_refresh(ctx: &mut FlantermCore<Self>)
    where
        Self: Sized;
}

pub struct FlantermCore<B: BackendOps> {
    pub tab_size: usize,
    pub autoflush: bool,
    pub cursor_enabled: bool,
    pub scroll_enabled: bool,
    pub wrap_enabled: bool,
    pub origin_mode: bool,
    pub control_sequence: bool,
    pub escape: bool,
    pub osc: bool,
    pub osc_escape: bool,
    pub osc_buf_i: usize,
    pub osc_buf: [u8; 256],
    pub rrr: bool,
    pub discard_next: bool,
    pub bold: bool,
    pub bg_bold: bool,
    pub reverse_video: bool,
    pub dec_private: bool,
    pub insert_mode: bool,
    pub csi_unhandled: bool,
    pub code_point: u64,
    pub unicode_remaining: usize,
    pub g_select: u8,
    pub charsets: [u8; 2],
    pub current_charset: usize,
    pub escape_offset: usize,
    pub esc_values_i: usize,
    pub saved_cursor_x: usize,
    pub saved_cursor_y: usize,
    pub current_primary: usize,
    pub current_bg: usize,
    pub scroll_top_margin: usize,
    pub scroll_bottom_margin: usize,
    pub esc_values: [u32; FLANTERM_MAX_ESC_VALUES],
    pub last_printed_char: u8,
    pub last_was_graphic: bool,
    pub saved_state_bold: bool,
    pub saved_state_bg_bold: bool,
    pub saved_state_reverse_video: bool,
    pub saved_state_origin_mode: bool,
    pub saved_state_wrap_enabled: bool,
    pub saved_state_current_charset: usize,
    pub saved_state_charsets: [u8; 2],
    pub saved_state_current_primary: usize,
    pub saved_state_current_bg: usize,

    pub rows: usize,
    pub cols: usize,

    pub backend: B,

    pub callback: FlantermCallbackFn<B>,
}

impl<B: BackendOps> FlantermCore<B> {
    #[inline(always)]
    fn with_backend<R>(&mut self, f: impl FnOnce(&mut B, &mut FlantermCore<B>) -> R) -> R {
        let self_ptr = self as *mut FlantermCore<B>;
        unsafe { f(&mut (*self_ptr).backend, &mut *self_ptr) }
    }

    #[inline(always)]
    fn raw_putchar(&mut self, c: u8) {
        self.with_backend(|_, ctx| B::raw_putchar(ctx, c));
    }

    #[inline(always)]
    fn clear(&mut self, move_cursor: bool) {
        self.with_backend(|_, ctx| B::clear(ctx, move_cursor));
    }

    #[inline(always)]
    fn set_cursor_pos(&mut self, x: usize, y: usize) {
        self.with_backend(|_, ctx| B::set_cursor_pos(ctx, x, y));
    }

    #[inline(always)]
    fn get_cursor_pos(&mut self, x: &mut usize, y: &mut usize) {
        self.with_backend(|_, ctx| B::get_cursor_pos(ctx, x, y));
    }

    #[inline(always)]
    fn set_text_fg(&mut self, fg: usize) {
        self.with_backend(|_, ctx| B::set_text_fg(ctx, fg));
    }

    #[inline(always)]
    fn set_text_bg(&mut self, bg: usize) {
        self.with_backend(|_, ctx| B::set_text_bg(ctx, bg));
    }

    #[inline(always)]
    fn set_text_fg_bright(&mut self, fg: usize) {
        self.with_backend(|_, ctx| B::set_text_fg_bright(ctx, fg));
    }

    #[inline(always)]
    fn set_text_bg_bright(&mut self, bg: usize) {
        self.with_backend(|_, ctx| B::set_text_bg_bright(ctx, bg));
    }

    #[inline(always)]
    fn set_text_fg_rgb(&mut self, fg: u32) {
        self.with_backend(|_, ctx| B::set_text_fg_rgb(ctx, fg));
    }

    #[inline(always)]
    fn set_text_bg_rgb(&mut self, bg: u32) {
        self.with_backend(|_, ctx| B::set_text_bg_rgb(ctx, bg));
    }

    #[inline(always)]
    fn set_text_fg_default(&mut self) {
        self.with_backend(|_, ctx| B::set_text_fg_default(ctx));
    }

    #[inline(always)]
    fn set_text_bg_default(&mut self) {
        self.with_backend(|_, ctx| B::set_text_bg_default(ctx));
    }

    #[inline(always)]
    fn set_text_fg_default_bright(&mut self) {
        self.with_backend(|_, ctx| B::set_text_fg_default_bright(ctx));
    }

    #[inline(always)]
    fn set_text_bg_default_bright(&mut self) {
        self.with_backend(|_, ctx| B::set_text_bg_default_bright(ctx));
    }

    #[inline(always)]
    fn move_character(&mut self, new_x: usize, new_y: usize, old_x: usize, old_y: usize) {
        self.with_backend(|_, ctx| B::move_character(ctx, new_x, new_y, old_x, old_y));
    }

    #[inline(always)]
    fn scroll(&mut self) {
        self.with_backend(|_, ctx| B::scroll(ctx));
    }

    #[inline(always)]
    fn revscroll(&mut self) {
        self.with_backend(|_, ctx| B::revscroll(ctx));
    }

    #[inline(always)]
    fn swap_palette(&mut self) {
        self.with_backend(|_, ctx| B::swap_palette(ctx));
    }

    #[inline(always)]
    fn save_state(&mut self) {
        self.with_backend(|_, ctx| B::save_state(ctx));
    }

    #[inline(always)]
    fn restore_state(&mut self) {
        self.with_backend(|_, ctx| B::restore_state(ctx));
    }

    #[inline(always)]
    fn double_buffer_flush(&mut self) {
        self.with_backend(|_, ctx| B::double_buffer_flush(ctx));
    }

    #[inline(always)]
    fn full_refresh(&mut self) {
        self.with_backend(|_, ctx| B::full_refresh(ctx));
    }

    #[inline(always)]
    fn callback(&mut self, cb: FlantermCallback<'_>) {
        if let Some(cb_fn) = self.callback {
            cb_fn(self, cb);
        }
    }
}

pub fn flanterm_context_new<B: BackendOps>(
    backend: B,
    rows: usize,
    cols: usize,
) -> FlantermCore<B> {
    let mut ctx = FlantermCore {
        tab_size: 0,
        autoflush: false,
        cursor_enabled: false,
        scroll_enabled: false,
        wrap_enabled: false,
        origin_mode: false,
        control_sequence: false,
        escape: false,
        osc: false,
        osc_escape: false,
        osc_buf_i: 0,
        osc_buf: [0; 256],
        rrr: false,
        discard_next: false,
        bold: false,
        bg_bold: false,
        reverse_video: false,
        dec_private: false,
        insert_mode: false,
        csi_unhandled: false,
        code_point: 0,
        unicode_remaining: 0,
        g_select: 0,
        charsets: [0; 2],
        current_charset: 0,
        escape_offset: 0,
        esc_values_i: 0,
        saved_cursor_x: 0,
        saved_cursor_y: 0,
        current_primary: 0,
        current_bg: 0,
        scroll_top_margin: 0,
        scroll_bottom_margin: rows,
        esc_values: [0; FLANTERM_MAX_ESC_VALUES],
        last_printed_char: 0,
        last_was_graphic: false,
        saved_state_bold: false,
        saved_state_bg_bold: false,
        saved_state_reverse_video: false,
        saved_state_origin_mode: false,
        saved_state_wrap_enabled: false,
        saved_state_current_charset: 0,
        saved_state_charsets: [0; 2],
        saved_state_current_primary: 0,
        saved_state_current_bg: 0,
        rows,
        cols,
        backend,
        callback: None,
    };

    flanterm_context_reinit(&mut ctx);
    ctx
}

pub fn flanterm_context_reinit<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    ctx.tab_size = 8;
    ctx.autoflush = true;
    ctx.cursor_enabled = true;
    ctx.scroll_enabled = true;
    ctx.wrap_enabled = true;
    ctx.origin_mode = false;
    ctx.control_sequence = false;
    ctx.escape = false;
    ctx.osc = false;
    ctx.osc_escape = false;
    ctx.rrr = false;
    ctx.discard_next = false;
    ctx.bold = false;
    ctx.bg_bold = false;
    ctx.reverse_video = false;
    ctx.dec_private = false;
    ctx.insert_mode = false;
    ctx.csi_unhandled = false;
    ctx.unicode_remaining = 0;
    ctx.g_select = 0;
    ctx.charsets[0] = CHARSET_DEFAULT;
    ctx.charsets[1] = CHARSET_DEC_SPECIAL;
    ctx.current_charset = 0;
    ctx.escape_offset = 0;
    ctx.esc_values_i = 0;
    ctx.saved_cursor_x = 0;
    ctx.saved_cursor_y = 0;
    ctx.current_primary = COLOR_DEFAULT;
    ctx.current_bg = COLOR_DEFAULT;
    ctx.saved_state_current_primary = COLOR_DEFAULT;
    ctx.saved_state_current_bg = COLOR_DEFAULT;
    ctx.last_printed_char = b' ';
    ctx.last_was_graphic = false;
    ctx.scroll_top_margin = 0;
    ctx.scroll_bottom_margin = ctx.rows;
}

pub fn flanterm_write<B: BackendOps>(ctx: &mut FlantermCore<B>, buf: &[u8]) {
    for &c in buf {
        flanterm_putchar(ctx, c);
    }

    if ctx.autoflush {
        ctx.double_buffer_flush();
    }
}

fn sgr<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    let mut i = 0usize;

    if ctx.esc_values_i == 0 {
        if ctx.reverse_video {
            ctx.reverse_video = false;
            ctx.swap_palette();
        }
        ctx.bold = false;
        ctx.bg_bold = false;
        ctx.current_primary = COLOR_DEFAULT;
        ctx.current_bg = COLOR_DEFAULT;
        ctx.set_text_bg_default();
        ctx.set_text_fg_default();
        return;
    }

    while i < ctx.esc_values_i {
        let v = ctx.esc_values[i];
        if v == 0 {
            if ctx.reverse_video {
                ctx.reverse_video = false;
                ctx.swap_palette();
            }
            ctx.bold = false;
            ctx.bg_bold = false;
            ctx.current_primary = COLOR_DEFAULT;
            ctx.current_bg = COLOR_DEFAULT;
            ctx.set_text_bg_default();
            ctx.set_text_fg_default();
            i += 1;
            continue;
        } else if v == 1 {
            ctx.bold = true;
            if ctx.current_primary == COLOR_RGB {
                // RGB/256-color; bold does not alter the colour
            } else if ctx.current_primary != COLOR_DEFAULT {
                if !ctx.reverse_video {
                    ctx.set_text_fg_bright(ctx.current_primary);
                } else {
                    ctx.set_text_bg_bright(ctx.current_primary);
                }
            } else {
                if !ctx.reverse_video {
                    ctx.set_text_fg_default_bright();
                } else {
                    ctx.set_text_bg_default_bright();
                }
            }
            i += 1;
            continue;
        } else if v == 2 || v == 3 || v == 4 || v == 8 {
            i += 1;
            continue;
        } else if v == 5 {
            ctx.bg_bold = true;
            if ctx.current_bg == COLOR_RGB {
                // RGB/256-color; bold does not alter the colour
            } else if ctx.current_bg != COLOR_DEFAULT {
                if !ctx.reverse_video {
                    ctx.set_text_bg_bright(ctx.current_bg);
                } else {
                    ctx.set_text_fg_bright(ctx.current_bg);
                }
            } else {
                if !ctx.reverse_video {
                    ctx.set_text_bg_default_bright();
                } else {
                    ctx.set_text_fg_default_bright();
                }
            }
            i += 1;
            continue;
        } else if v == 22 {
            ctx.bold = false;
            if ctx.current_primary == COLOR_RGB {
                // RGB/256-color; unbold does not alter the colour
            } else if ctx.current_primary != COLOR_DEFAULT {
                if !ctx.reverse_video {
                    ctx.set_text_fg(ctx.current_primary);
                } else {
                    ctx.set_text_bg(ctx.current_primary);
                }
            } else {
                if !ctx.reverse_video {
                    ctx.set_text_fg_default();
                } else {
                    ctx.set_text_bg_default();
                }
            }
            i += 1;
            continue;
        } else if v == 23 || v == 24 || v == 28 {
            i += 1;
            continue;
        } else if v == 25 {
            ctx.bg_bold = false;
            if ctx.current_bg == COLOR_RGB {
                // RGB/256-color; unbold does not alter the colour
            } else if ctx.current_bg != COLOR_DEFAULT {
                if !ctx.reverse_video {
                    ctx.set_text_bg(ctx.current_bg);
                } else {
                    ctx.set_text_fg(ctx.current_bg);
                }
            } else {
                if !ctx.reverse_video {
                    ctx.set_text_bg_default();
                } else {
                    ctx.set_text_fg_default();
                }
            }
            i += 1;
            continue;
        } else if (30..=37).contains(&v) {
            let offset = 30u32;
            ctx.current_primary = (v - offset) as usize;
            if ctx.reverse_video {
                // set_bg
                if (ctx.bold && ctx.reverse_video) || (ctx.bg_bold && !ctx.reverse_video) {
                    ctx.set_text_bg_bright((v - offset) as usize);
                } else {
                    ctx.set_text_bg((v - offset) as usize);
                }
            } else {
                if (ctx.bold && !ctx.reverse_video) || (ctx.bg_bold && ctx.reverse_video) {
                    ctx.set_text_fg_bright((v - offset) as usize);
                } else {
                    ctx.set_text_fg((v - offset) as usize);
                }
            }
            i += 1;
            continue;
        } else if (40..=47).contains(&v) {
            let offset = 40u32;
            ctx.current_bg = (v - offset) as usize;
            if ctx.reverse_video {
                if (ctx.bold && !ctx.reverse_video) || (ctx.bg_bold && ctx.reverse_video) {
                    ctx.set_text_fg_bright((v - offset) as usize);
                } else {
                    ctx.set_text_fg((v - offset) as usize);
                }
            } else {
                if (ctx.bold && ctx.reverse_video) || (ctx.bg_bold && !ctx.reverse_video) {
                    ctx.set_text_bg_bright((v - offset) as usize);
                } else {
                    ctx.set_text_bg((v - offset) as usize);
                }
            }
            i += 1;
            continue;
        } else if (90..=97).contains(&v) {
            let offset = 90u32;
            ctx.current_primary = (v - offset) as usize;
            if ctx.reverse_video {
                ctx.set_text_bg_bright((v - offset) as usize);
            } else {
                ctx.set_text_fg_bright((v - offset) as usize);
            }
            i += 1;
            continue;
        } else if (100..=107).contains(&v) {
            let offset = 100u32;
            ctx.current_bg = (v - offset) as usize;
            if ctx.reverse_video {
                ctx.set_text_fg_bright((v - offset) as usize);
            } else {
                ctx.set_text_bg_bright((v - offset) as usize);
            }
            i += 1;
            continue;
        } else if v == 39 {
            ctx.current_primary = COLOR_DEFAULT;
            if ctx.reverse_video {
                ctx.swap_palette();
            }
            if !ctx.bold {
                ctx.set_text_fg_default();
            } else {
                ctx.set_text_fg_default_bright();
            }
            if ctx.reverse_video {
                ctx.swap_palette();
            }
            i += 1;
            continue;
        } else if v == 49 {
            ctx.current_bg = COLOR_DEFAULT;
            if ctx.reverse_video {
                ctx.swap_palette();
            }
            if !ctx.bg_bold {
                ctx.set_text_bg_default();
            } else {
                ctx.set_text_bg_default_bright();
            }
            if ctx.reverse_video {
                ctx.swap_palette();
            }
            i += 1;
            continue;
        } else if v == 7 {
            if !ctx.reverse_video {
                ctx.reverse_video = true;
                ctx.swap_palette();
            }
            i += 1;
            continue;
        } else if v == 27 {
            if ctx.reverse_video {
                ctx.reverse_video = false;
                ctx.swap_palette();
            }
            i += 1;
            continue;
        } else if v == 38 || v == 48 {
            let mut fg = v == 38;
            if ctx.reverse_video {
                fg = !fg;
            }
            i += 1;
            if i >= ctx.esc_values_i {
                break;
            }
            match ctx.esc_values[i] {
                2 => {
                    if i + 3 >= ctx.esc_values_i {
                        break;
                    }
                    let mut rgb_value: u32 = 0;
                    rgb_value |= (ctx.esc_values[i + 1] & 0xff) << 16;
                    rgb_value |= (ctx.esc_values[i + 2] & 0xff) << 8;
                    rgb_value |= ctx.esc_values[i + 3] & 0xff;
                    i += 3;
                    if fg {
                        ctx.current_primary = COLOR_RGB;
                    } else {
                        ctx.current_bg = COLOR_RGB;
                    }
                    if fg {
                        ctx.set_text_fg_rgb(rgb_value);
                    } else {
                        ctx.set_text_bg_rgb(rgb_value);
                    }
                }
                5 => {
                    if i + 1 >= ctx.esc_values_i {
                        break;
                    }
                    let col = ctx.esc_values[i + 1];
                    i += 1;
                    if col < 8 {
                        if fg {
                            ctx.current_primary = col as usize;
                            ctx.set_text_fg(col as usize);
                        } else {
                            ctx.current_bg = col as usize;
                            ctx.set_text_bg(col as usize);
                        }
                    } else if col < 16 {
                        if fg {
                            ctx.current_primary = (col - 8) as usize;
                            ctx.set_text_fg_bright((col - 8) as usize);
                        } else {
                            ctx.current_bg = (col - 8) as usize;
                            ctx.set_text_bg_bright((col - 8) as usize);
                        }
                    } else if col < 256 {
                        if fg {
                            ctx.current_primary = COLOR_RGB;
                        } else {
                            ctx.current_bg = COLOR_RGB;
                        }
                        let rgb_value = COL256[(col - 16) as usize];
                        if fg {
                            ctx.set_text_fg_rgb(rgb_value);
                        } else {
                            ctx.set_text_bg_rgb(rgb_value);
                        }
                    }
                }
                _ => {}
            }
            i += 1;
            continue;
        }

        i += 1;
    }
}

fn dec_private_parse<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) {
    ctx.dec_private = false;
    if ctx.esc_values_i == 0 {
        return;
    }

    let set = match c {
        b'h' => true,
        b'l' => false,
        _ => return,
    };

    for i in 0..ctx.esc_values_i {
        match ctx.esc_values[i] {
            6 => {
                ctx.origin_mode = set;
                ctx.set_cursor_pos(0, if set { ctx.scroll_top_margin } else { 0 });
            }
            7 => {
                ctx.wrap_enabled = set;
            }
            25 => {
                ctx.cursor_enabled = set;
            }
            1049 => {
                if set {
                    ctx.clear(true);
                } else {
                    if ctx.reverse_video {
                        ctx.reverse_video = false;
                        ctx.swap_palette();
                    }
                    ctx.bold = false;
                    ctx.bg_bold = false;
                    ctx.current_primary = COLOR_DEFAULT;
                    ctx.current_bg = COLOR_DEFAULT;
                    ctx.set_text_bg_default();
                    ctx.set_text_fg_default();
                    ctx.clear(true);
                }
            }
            _ => {}
        }
    }

    let mut params_buf = [0u32; FLANTERM_MAX_ESC_VALUES];
    params_buf[..ctx.esc_values_i].copy_from_slice(&ctx.esc_values[..ctx.esc_values_i]);
    ctx.callback(FlantermCallback::Dec {
        params: &params_buf[..ctx.esc_values_i],
        suffix: c,
    });
}

fn linux_private_parse<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    if ctx.esc_values_i == 0 {
        return;
    }
    let mut params_buf = [0u32; FLANTERM_MAX_ESC_VALUES];
    params_buf[..ctx.esc_values_i].copy_from_slice(&ctx.esc_values[..ctx.esc_values_i]);
    ctx.callback(FlantermCallback::Linux {
        params: &params_buf[..ctx.esc_values_i],
    });
}

fn mode_toggle<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) {
    if ctx.esc_values_i == 0 {
        return;
    }

    let set = match c {
        b'h' => true,
        b'l' => false,
        _ => return,
    };

    match ctx.esc_values[0] {
        4 => {
            ctx.insert_mode = set;
            return;
        }
        _ => {}
    }

    let mut params_buf = [0u32; FLANTERM_MAX_ESC_VALUES];
    params_buf[..ctx.esc_values_i].copy_from_slice(&ctx.esc_values[..ctx.esc_values_i]);
    ctx.callback(FlantermCallback::Mode {
        params: &params_buf[..ctx.esc_values_i],
        suffix: c,
    });
}

fn osc_finalize<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    if ctx.callback.is_some() {
        let mut osc_num: u64 = 0;
        let mut i = 0usize;
        while i < ctx.osc_buf_i && (b'0'..=b'9').contains(&ctx.osc_buf[i]) {
            osc_num = osc_num * 10 + (ctx.osc_buf[i] - b'0') as u64;
            i += 1;
        }
        if i < ctx.osc_buf_i && ctx.osc_buf[i] == b';' {
            i += 1;
        }
        let mut osc_buf = [0u8; 256];
        osc_buf[..ctx.osc_buf_i].copy_from_slice(&ctx.osc_buf[..ctx.osc_buf_i]);
        let data = &osc_buf[i..ctx.osc_buf_i];
        ctx.callback(FlantermCallback::Osc { id: osc_num, data });
    }
}

fn osc_parse<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) -> bool {
    if ctx.osc_escape {
        if c == b'\\' {
            osc_finalize(ctx);
            ctx.osc = false;
            ctx.osc_escape = false;
            ctx.escape = false;
            return true;
        } else {
            ctx.osc_escape = false;
            ctx.osc = false;
            return false;
        }
    }
    match c {
        0x1b => {
            ctx.osc_escape = true;
        }
        0x07 => {
            osc_finalize(ctx);
            ctx.osc_escape = false;
            ctx.osc = false;
            ctx.escape = false;
        }
        _ => {
            if ctx.osc_buf_i < ctx.osc_buf.len() {
                ctx.osc_buf[ctx.osc_buf_i] = c;
                ctx.osc_buf_i += 1;
            }
        }
    }
    true
}

fn control_sequence_parse<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) {
    if ctx.escape_offset == 2 {
        match c {
            b'[' => {
                ctx.discard_next = true;
                ctx.control_sequence = false;
                ctx.escape = false;
                return;
            }
            b'?' => {
                ctx.dec_private = true;
                return;
            }
            _ => {}
        }
    }

    if c < 0x20 && c != 0x1b {
        let mut x = 0usize;
        let mut y = 0usize;
        ctx.get_cursor_pos(&mut x, &mut y);
        match c {
            0x07 => ctx.callback(FlantermCallback::Bell),
            0x08 => {
                if x > 0 {
                    ctx.set_cursor_pos(x - 1, y);
                }
            }
            b'\t' => {
                x = (x / ctx.tab_size + 1) * ctx.tab_size;
                if x >= ctx.cols {
                    x = ctx.cols - 1;
                }
                ctx.set_cursor_pos(x, y);
            }
            0x0b | 0x0c | b'\n' => {
                if y == ctx.scroll_bottom_margin - 1 {
                    ctx.scroll();
                    ctx.set_cursor_pos(x, y);
                } else {
                    ctx.set_cursor_pos(x, y + 1);
                }
            }
            b'\r' => ctx.set_cursor_pos(0, y),
            14 => ctx.current_charset = 1,
            15 => ctx.current_charset = 0,
            _ => {}
        }
        return;
    }

    if (b'0'..=b'9').contains(&c) {
        if ctx.esc_values_i == FLANTERM_MAX_ESC_VALUES {
            return;
        }
        ctx.rrr = true;
        if ctx.esc_values[ctx.esc_values_i] > u32::MAX / 10 {
            return;
        }
        ctx.esc_values[ctx.esc_values_i] *= 10;
        ctx.esc_values[ctx.esc_values_i] += (c - b'0') as u32;
        return;
    }

    if ctx.rrr {
        ctx.esc_values_i += 1;
        ctx.rrr = false;
        if c == b';' {
            return;
        }
    } else if c == b';' {
        if ctx.esc_values_i == FLANTERM_MAX_ESC_VALUES {
            return;
        }
        ctx.esc_values[ctx.esc_values_i] = 0;
        ctx.esc_values_i += 1;
        return;
    }

    let esc_default = match c {
        b'J' | b'K' | b'q' | b'm' | b'c' | b']' => 0,
        _ => 1,
    };

    for i in ctx.esc_values_i..FLANTERM_MAX_ESC_VALUES {
        ctx.esc_values[i] = esc_default;
    }

    if esc_default != 0 {
        for i in 0..ctx.esc_values_i {
            if ctx.esc_values[i] == 0 {
                ctx.esc_values[i] = esc_default;
            }
        }
    }

    if ctx.dec_private {
        dec_private_parse(ctx, c);
        ctx.control_sequence = false;
        ctx.escape = false;
        return;
    }

    if ctx.csi_unhandled {
        if (0x40..=0x7e).contains(&c) {
            ctx.csi_unhandled = false;
            ctx.control_sequence = false;
            ctx.escape = false;
        }
        return;
    }

    let r = ctx.scroll_enabled;
    ctx.scroll_enabled = false;
    let mut x = 0usize;
    let mut y = 0usize;
    ctx.get_cursor_pos(&mut x, &mut y);

    match c {
        0x1b => {
            ctx.scroll_enabled = r;
            ctx.control_sequence = false;
            ctx.escape_offset = 0;
            return;
        }
        b'F' | b'A' => {
            if c == b'F' {
                x = 0;
            }
            if ctx.esc_values[0] as usize > y {
                ctx.esc_values[0] = y as u32;
            }
            let mut dest_y = y - ctx.esc_values[0] as usize;
            let min_y = if ctx.origin_mode {
                ctx.scroll_top_margin
            } else {
                0
            };
            if dest_y < min_y {
                dest_y = min_y;
            }
            ctx.set_cursor_pos(x, dest_y);
        }
        b'E' | b'e' | b'B' => {
            if c == b'E' {
                x = 0;
            }
            if y + ctx.esc_values[0] as usize > ctx.rows - 1 {
                ctx.esc_values[0] = (ctx.rows - 1 - y) as u32;
            }
            let mut dest_y = y + ctx.esc_values[0] as usize;
            let max_y = if ctx.origin_mode {
                ctx.scroll_bottom_margin
            } else {
                ctx.rows
            };
            if dest_y >= max_y {
                dest_y = max_y - 1;
            }
            ctx.set_cursor_pos(x, dest_y);
        }
        b'a' | b'C' => {
            if x + ctx.esc_values[0] as usize > ctx.cols - 1 {
                ctx.esc_values[0] = (ctx.cols - 1 - x) as u32;
            }
            ctx.set_cursor_pos(x + ctx.esc_values[0] as usize, y);
        }
        b'D' => {
            if ctx.esc_values[0] as usize > x {
                ctx.esc_values[0] = x as u32;
            }
            ctx.set_cursor_pos(x - ctx.esc_values[0] as usize, y);
        }
        b'c' => ctx.callback(FlantermCallback::PrivateId),
        b'd' => {
            if ctx.esc_values[0] != 0 {
                ctx.esc_values[0] -= 1;
            }
            let mut max_row = ctx.rows;
            let mut row_offset = 0usize;
            if ctx.origin_mode {
                max_row = ctx.scroll_bottom_margin - ctx.scroll_top_margin;
                row_offset = ctx.scroll_top_margin;
            }
            if ctx.esc_values[0] as usize >= max_row {
                ctx.esc_values[0] = (max_row - 1) as u32;
            }
            ctx.set_cursor_pos(x, ctx.esc_values[0] as usize + row_offset);
        }
        b'G' | b'`' => {
            if ctx.esc_values[0] != 0 {
                ctx.esc_values[0] -= 1;
            }
            if ctx.esc_values[0] as usize >= ctx.cols {
                ctx.esc_values[0] = (ctx.cols - 1) as u32;
            }
            ctx.set_cursor_pos(ctx.esc_values[0] as usize, y);
        }
        b'H' | b'f' => {
            if ctx.esc_values[0] != 0 {
                ctx.esc_values[0] -= 1;
            }
            if ctx.esc_values[1] != 0 {
                ctx.esc_values[1] -= 1;
            }
            let mut max_row = ctx.rows;
            let mut row_offset = 0usize;
            if ctx.origin_mode {
                max_row = ctx.scroll_bottom_margin - ctx.scroll_top_margin;
                row_offset = ctx.scroll_top_margin;
            }
            if ctx.esc_values[1] as usize >= ctx.cols {
                ctx.esc_values[1] = (ctx.cols - 1) as u32;
            }
            if ctx.esc_values[0] as usize >= max_row {
                ctx.esc_values[0] = (max_row - 1) as u32;
            }
            ctx.set_cursor_pos(
                ctx.esc_values[1] as usize,
                ctx.esc_values[0] as usize + row_offset,
            );
        }
        b'M' => {
            if y >= ctx.scroll_top_margin && y < ctx.scroll_bottom_margin {
                let old_scroll_top_margin = ctx.scroll_top_margin;
                ctx.scroll_top_margin = y;
                let max_count = ctx.scroll_bottom_margin - y;
                let count = ctx.esc_values[0] as usize;
                let count = if count > max_count { max_count } else { count };
                for _ in 0..count {
                    ctx.scroll();
                }
                ctx.scroll_top_margin = old_scroll_top_margin;
            }
        }
        b'L' => {
            if y >= ctx.scroll_top_margin && y < ctx.scroll_bottom_margin {
                let old_scroll_top_margin = ctx.scroll_top_margin;
                ctx.scroll_top_margin = y;
                let max_count = ctx.scroll_bottom_margin - y;
                let count = ctx.esc_values[0] as usize;
                let count = if count > max_count { max_count } else { count };
                for _ in 0..count {
                    ctx.revscroll();
                }
                ctx.scroll_top_margin = old_scroll_top_margin;
            }
        }
        b'n' => match ctx.esc_values[0] {
            5 => ctx.callback(FlantermCallback::StatusReport),
            6 => {
                let report_y = if ctx.origin_mode && y >= ctx.scroll_top_margin {
                    y - ctx.scroll_top_margin
                } else {
                    y
                };
                ctx.callback(FlantermCallback::PosReport {
                    x: x + 1,
                    y: report_y + 1,
                });
            }
            _ => {}
        },
        b'q' => ctx.callback(FlantermCallback::KbdLeds {
            value: ctx.esc_values[0],
        }),
        b'J' => match ctx.esc_values[0] {
            0 => {
                ctx.set_cursor_pos(x, y);
                for _ in x..ctx.cols {
                    ctx.raw_putchar(b' ');
                }
                for yc in (y + 1)..ctx.rows {
                    ctx.set_cursor_pos(0, yc);
                    for _ in 0..ctx.cols {
                        ctx.raw_putchar(b' ');
                    }
                }
                ctx.set_cursor_pos(x, y);
            }
            1 => {
                for yc in 0..y {
                    ctx.set_cursor_pos(0, yc);
                    for _ in 0..ctx.cols {
                        ctx.raw_putchar(b' ');
                    }
                }
                ctx.set_cursor_pos(0, y);
                for _ in 0..=x {
                    ctx.raw_putchar(b' ');
                }
                ctx.set_cursor_pos(x, y);
            }
            2 | 3 => ctx.clear(false),
            _ => {}
        },
        b'@' => {
            let mut n = ctx.esc_values[0] as usize;
            if n > ctx.cols - x {
                n = ctx.cols - x;
            }
            let mut i = ctx.cols - 1;
            loop {
                if i < x + n {
                    break;
                }
                ctx.move_character(i, y, i - n, y);
                if i == 0 {
                    break;
                }
                i -= 1;
            }
            ctx.set_cursor_pos(x, y);
            for _ in 0..n {
                ctx.raw_putchar(b' ');
            }
            ctx.set_cursor_pos(x, y);
        }
        b'P' => {
            if ctx.esc_values[0] as usize > ctx.cols - x {
                ctx.esc_values[0] = (ctx.cols - x) as u32;
            }
            let count = ctx.esc_values[0] as usize;
            for i in (x + count)..ctx.cols {
                ctx.move_character(i - count, y, i, y);
            }
            ctx.set_cursor_pos(ctx.cols - count, y);
            // fallthrough to X
            let mut cx = 0usize;
            let mut cy = 0usize;
            ctx.get_cursor_pos(&mut cx, &mut cy);
            ctx.set_cursor_pos(cx, cy);
            let remaining = ctx.cols - cx;
            let count = if ctx.esc_values[0] as usize > remaining {
                remaining
            } else {
                ctx.esc_values[0] as usize
            };
            for _ in 0..count {
                ctx.raw_putchar(b' ');
            }
            ctx.set_cursor_pos(x, y);
        }
        b'X' => {
            let mut cx = 0usize;
            let mut cy = 0usize;
            ctx.get_cursor_pos(&mut cx, &mut cy);
            ctx.set_cursor_pos(cx, cy);
            let remaining = ctx.cols - cx;
            let count = if ctx.esc_values[0] as usize > remaining {
                remaining
            } else {
                ctx.esc_values[0] as usize
            };
            for _ in 0..count {
                ctx.raw_putchar(b' ');
            }
            ctx.set_cursor_pos(x, y);
        }
        b'm' => sgr(ctx),
        b's' => {
            let mut sx = 0usize;
            let mut sy = 0usize;
            ctx.get_cursor_pos(&mut sx, &mut sy);
            ctx.saved_cursor_x = sx;
            ctx.saved_cursor_y = sy;
        }
        b'u' => ctx.set_cursor_pos(ctx.saved_cursor_x, ctx.saved_cursor_y),
        b'K' => match ctx.esc_values[0] {
            0 => {
                ctx.set_cursor_pos(x, y);
                for _ in x..ctx.cols {
                    ctx.raw_putchar(b' ');
                }
                ctx.set_cursor_pos(x, y);
            }
            1 => {
                ctx.set_cursor_pos(0, y);
                for _ in 0..=x {
                    ctx.raw_putchar(b' ');
                }
                ctx.set_cursor_pos(x, y);
            }
            2 => {
                ctx.set_cursor_pos(0, y);
                for _ in 0..ctx.cols {
                    ctx.raw_putchar(b' ');
                }
                ctx.set_cursor_pos(x, y);
            }
            _ => {}
        },
        b'r' => {
            ctx.scroll_top_margin = 0;
            ctx.scroll_bottom_margin = ctx.rows;
            if ctx.esc_values_i > 0 {
                ctx.scroll_top_margin = ctx.esc_values[0].saturating_sub(1) as usize;
            }
            if ctx.esc_values_i > 1 {
                ctx.scroll_bottom_margin = ctx.esc_values[1] as usize;
            }
            if ctx.scroll_top_margin >= ctx.rows
                || ctx.scroll_bottom_margin > ctx.rows
                || ctx.scroll_top_margin >= ctx.scroll_bottom_margin.saturating_sub(1)
            {
                ctx.scroll_top_margin = 0;
                ctx.scroll_bottom_margin = ctx.rows;
            }
            ctx.set_cursor_pos(
                0,
                if ctx.origin_mode {
                    ctx.scroll_top_margin
                } else {
                    0
                },
            );
        }
        b'l' | b'h' => mode_toggle(ctx, c),
        b'S' => {
            let region = ctx.scroll_bottom_margin - ctx.scroll_top_margin;
            let count = ctx.esc_values[0] as usize;
            let count = if count > region { region } else { count };
            for _ in 0..count {
                ctx.scroll();
            }
        }
        b'T' => {
            let region = ctx.scroll_bottom_margin - ctx.scroll_top_margin;
            let count = ctx.esc_values[0] as usize;
            let count = if count > region { region } else { count };
            for _ in 0..count {
                ctx.revscroll();
            }
        }
        b'b' => {
            if !ctx.last_was_graphic {
                ctx.scroll_enabled = r;
                ctx.control_sequence = false;
                ctx.escape = false;
                return;
            }
            ctx.scroll_enabled = r;
            let mut count = ctx.esc_values[0] as usize;
            if count > 65535 {
                count = 65535;
            }
            for _ in 0..count {
                if ctx.insert_mode {
                    let mut ix = 0usize;
                    let mut iy = 0usize;
                    ctx.get_cursor_pos(&mut ix, &mut iy);
                    let mut j = ctx.cols - 1;
                    while j > ix {
                        ctx.move_character(j, iy, j - 1, iy);
                        j -= 1;
                    }
                }
                ctx.raw_putchar(ctx.last_printed_char);
            }
        }
        b']' => linux_private_parse(ctx),
        _ => {
            if (0x40..=0x7e).contains(&c) {
                // ignore
            } else {
                ctx.scroll_enabled = r;
                ctx.csi_unhandled = true;
                return;
            }
        }
    }

    ctx.scroll_enabled = r;
    ctx.control_sequence = false;
    ctx.escape = false;
}

fn restore_state<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    ctx.bold = ctx.saved_state_bold;
    ctx.bg_bold = ctx.saved_state_bg_bold;
    ctx.reverse_video = ctx.saved_state_reverse_video;
    ctx.origin_mode = ctx.saved_state_origin_mode;
    ctx.wrap_enabled = ctx.saved_state_wrap_enabled;
    ctx.current_charset = ctx.saved_state_current_charset;
    ctx.charsets[0] = ctx.saved_state_charsets[0];
    ctx.charsets[1] = ctx.saved_state_charsets[1];
    ctx.current_primary = ctx.saved_state_current_primary;
    ctx.current_bg = ctx.saved_state_current_bg;
    ctx.restore_state();
}

fn save_state<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    ctx.save_state();
    ctx.saved_state_bold = ctx.bold;
    ctx.saved_state_bg_bold = ctx.bg_bold;
    ctx.saved_state_reverse_video = ctx.reverse_video;
    ctx.saved_state_origin_mode = ctx.origin_mode;
    ctx.saved_state_wrap_enabled = ctx.wrap_enabled;
    ctx.saved_state_current_charset = ctx.current_charset;
    ctx.saved_state_charsets[0] = ctx.charsets[0];
    ctx.saved_state_charsets[1] = ctx.charsets[1];
    ctx.saved_state_current_primary = ctx.current_primary;
    ctx.saved_state_current_bg = ctx.current_bg;
}

fn escape_parse<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) {
    ctx.escape_offset += 1;

    if ctx.osc {
        if osc_parse(ctx, c) {
            return;
        }
        ctx.escape_offset = 1;
    }

    if ctx.control_sequence {
        control_sequence_parse(ctx, c);
        return;
    }

    let mut x = 0usize;
    let mut y = 0usize;
    ctx.get_cursor_pos(&mut x, &mut y);

    match c {
        0x1b => {
            ctx.escape_offset = 0;
            return;
        }
        b']' => {
            ctx.osc_escape = false;
            ctx.osc = true;
            ctx.osc_buf_i = 0;
            return;
        }
        b'[' => {
            for i in 0..FLANTERM_MAX_ESC_VALUES {
                ctx.esc_values[i] = 0;
            }
            ctx.esc_values_i = 0;
            ctx.rrr = false;
            ctx.csi_unhandled = false;
            ctx.control_sequence = true;
            return;
        }
        b'7' => save_state(ctx),
        b'8' => restore_state(ctx),
        b'c' => {
            if ctx.reverse_video {
                ctx.swap_palette();
            }
            flanterm_context_reinit(ctx);
            ctx.set_text_bg_default();
            ctx.set_text_fg_default();
            ctx.clear(true);
        }
        b'D' => {
            if y == ctx.scroll_bottom_margin - 1 {
                ctx.scroll();
                ctx.set_cursor_pos(x, y);
            } else if y < ctx.rows - 1 {
                ctx.set_cursor_pos(x, y + 1);
            }
        }
        b'E' => {
            if y == ctx.scroll_bottom_margin - 1 {
                ctx.scroll();
                ctx.set_cursor_pos(0, y);
            } else if y < ctx.rows - 1 {
                ctx.set_cursor_pos(0, y + 1);
            } else {
                ctx.set_cursor_pos(0, y);
            }
        }
        b'M' => {
            if y == ctx.scroll_top_margin {
                ctx.revscroll();
                ctx.set_cursor_pos(x, y);
            } else if y > 0 {
                ctx.set_cursor_pos(x, y - 1);
            }
        }
        b'Z' => ctx.callback(FlantermCallback::PrivateId),
        b'(' | b')' => {
            ctx.g_select = c - b'\'';
        }
        _ => {}
    }

    ctx.escape = false;
}

fn dec_special_print<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) -> bool {
    macro_rules! dec_spcl_prn {
        ($v:expr) => {{
            ctx.last_printed_char = $v;
            ctx.last_was_graphic = true;
            ctx.raw_putchar($v);
            return true;
        }};
    }

    match c {
        b'`' => dec_spcl_prn!(0x04),
        b'0' => dec_spcl_prn!(0xdb),
        b'-' => dec_spcl_prn!(0x18),
        b',' => dec_spcl_prn!(0x1b),
        b'.' => dec_spcl_prn!(0x19),
        b'a' => dec_spcl_prn!(0xb1),
        b'f' => dec_spcl_prn!(0xf8),
        b'g' => dec_spcl_prn!(0xf1),
        b'h' => dec_spcl_prn!(0xb0),
        b'j' => dec_spcl_prn!(0xd9),
        b'k' => dec_spcl_prn!(0xbf),
        b'l' => dec_spcl_prn!(0xda),
        b'm' => dec_spcl_prn!(0xc0),
        b'n' => dec_spcl_prn!(0xc5),
        b'q' => dec_spcl_prn!(0xc4),
        b's' => dec_spcl_prn!(0x5f),
        b't' => dec_spcl_prn!(0xc3),
        b'u' => dec_spcl_prn!(0xb4),
        b'v' => dec_spcl_prn!(0xc1),
        b'w' => dec_spcl_prn!(0xc2),
        b'x' => dec_spcl_prn!(0xb3),
        b'y' => dec_spcl_prn!(0xf3),
        b'z' => dec_spcl_prn!(0xf2),
        b'~' => dec_spcl_prn!(0xfa),
        b'_' => dec_spcl_prn!(0xff),
        b'+' => dec_spcl_prn!(0x1a),
        b'{' => dec_spcl_prn!(0xe3),
        b'}' => dec_spcl_prn!(0x9c),
        _ => {}
    }

    false
}

fn bisearch(ucs: u32, table: &[Interval]) -> bool {
    if ucs < table[0].first || ucs > table[table.len() - 1].last {
        return false;
    }
    let mut min: i32 = 0;
    let mut max: i32 = (table.len() - 1) as i32;
    while max >= min {
        let mid = (min + max) / 2;
        let v = table[mid as usize];
        if ucs > v.last {
            min = mid + 1;
        } else if ucs < v.first {
            max = mid - 1;
        } else {
            return true;
        }
    }
    false
}

fn mk_wcwidth(ucs: u32) -> i32 {
    if ucs == 0 {
        return 0;
    }
    if ucs < 32 || (ucs >= 0x7f && ucs < 0xa0) {
        return -1;
    }

    if bisearch(ucs, &COMBINING) {
        return 0;
    }

    if bisearch(ucs, &WIDE) {
        return 2;
    }

    1
}

fn flanterm_putchar<B: BackendOps>(ctx: &mut FlantermCore<B>, c: u8) {
    if ctx.discard_next || c == 0x18 || c == 0x1a {
        ctx.discard_next = false;
        ctx.escape = false;
        ctx.control_sequence = false;
        ctx.unicode_remaining = 0;
        ctx.osc = false;
        ctx.osc_escape = false;
        ctx.g_select = 0;
        ctx.last_was_graphic = false;
        return;
    }

    if ctx.unicode_remaining != 0 {
        let mut unicode_error = false;
        if (c & 0xc0) != 0x80 {
            ctx.unicode_remaining = 0;
            ctx.raw_putchar(0xfe);
            unicode_error = true;
        } else {
            ctx.unicode_remaining -= 1;
            ctx.code_point |= (c as u64 & 0x3f) << (6 * ctx.unicode_remaining);

            if ctx.unicode_remaining == 1 && ctx.code_point < 0x800 {
                ctx.unicode_remaining = 0;
                unicode_error = true;
            }
            if ctx.unicode_remaining == 2 && ctx.code_point < 0x10000 {
                ctx.unicode_remaining = 0;
                unicode_error = true;
            }
            if ctx.unicode_remaining == 2 && ctx.code_point > 0x10ffff {
                ctx.unicode_remaining = 0;
                unicode_error = true;
            }

            if !unicode_error && ctx.unicode_remaining != 0 {
                return;
            }

            if !unicode_error && (0xd800..=0xdfff).contains(&ctx.code_point) {
                unicode_error = true;
            }

            if !unicode_error {
                let cc = unicode_to_cp437(ctx.code_point);
                if cc == -1 {
                    let replacement_width = mk_wcwidth(ctx.code_point as u32);
                    if replacement_width > 0 {
                        ctx.last_printed_char = 0xfe;
                        ctx.last_was_graphic = true;
                        ctx.raw_putchar(0xfe);
                    }
                    for _ in 1..replacement_width {
                        ctx.raw_putchar(b' ');
                    }
                } else {
                    ctx.last_printed_char = cc as u8;
                    ctx.last_was_graphic = true;
                    ctx.raw_putchar(cc as u8);
                }
                return;
            }
        }
        // unicode_error fallthrough
        if !unicode_error {
            return;
        }
    }
    if (0xc2..=0xf4).contains(&c) {
        ctx.g_select = 0;
        if c <= 0xdf {
            ctx.unicode_remaining = 1;
            ctx.code_point = (c as u64 & 0x1f) << 6;
        } else if c <= 0xef {
            ctx.unicode_remaining = 2;
            ctx.code_point = (c as u64 & 0x0f) << (6 * 2);
        } else {
            ctx.unicode_remaining = 3;
            ctx.code_point = (c as u64 & 0x07) << (6 * 3);
        }
        return;
    }

    if ctx.escape {
        escape_parse(ctx, c);
        return;
    }

    if ctx.g_select != 0 {
        if c <= 0x1f || c == 0x7f {
            ctx.g_select = 0;
        } else {
            ctx.g_select -= 1;
            match c {
                b'B' => ctx.charsets[ctx.g_select as usize] = CHARSET_DEFAULT,
                b'0' => ctx.charsets[ctx.g_select as usize] = CHARSET_DEC_SPECIAL,
                _ => {}
            }
            ctx.g_select = 0;
            return;
        }
    }

    if (c <= 0x1f && c != 0x1b) || c == 0x7f {
        ctx.last_was_graphic = false;
    }

    let mut x = 0usize;
    let mut y = 0usize;
    ctx.get_cursor_pos(&mut x, &mut y);

    match c {
        0x00 | 0x7f => return,
        0x1b => {
            ctx.escape_offset = 0;
            ctx.escape = true;
            return;
        }
        b'\t' => {
            let next_tab = (x / ctx.tab_size + 1) * ctx.tab_size;
            if next_tab >= ctx.cols {
                ctx.set_cursor_pos(ctx.cols - 1, y);
                return;
            }
            ctx.set_cursor_pos(next_tab, y);
            return;
        }
        0x0b | 0x0c | b'\n' => {
            if y == ctx.scroll_bottom_margin - 1 {
                ctx.scroll();
                ctx.set_cursor_pos(x, y);
            } else {
                ctx.set_cursor_pos(x, y + 1);
            }
            return;
        }
        0x08 => {
            if x > 0 {
                ctx.set_cursor_pos(x - 1, y);
            }
            return;
        }
        b'\r' => {
            ctx.set_cursor_pos(0, y);
            return;
        }
        0x07 => {
            ctx.callback(FlantermCallback::Bell);
            return;
        }
        14 => {
            ctx.current_charset = 1;
            return;
        }
        15 => {
            ctx.current_charset = 0;
            return;
        }
        _ => {}
    }

    if ctx.insert_mode {
        let mut i = ctx.cols - 1;
        while i > x {
            ctx.move_character(i, y, i - 1, y);
            i -= 1;
        }
    }

    match ctx.charsets[ctx.current_charset] {
        CHARSET_DEFAULT => {}
        CHARSET_DEC_SPECIAL => {
            if dec_special_print(ctx, c) {
                return;
            }
        }
        _ => {}
    }

    if (0x20..=0x7e).contains(&c) {
        ctx.last_printed_char = c;
        ctx.last_was_graphic = true;
        ctx.raw_putchar(c);
    } else if c >= 0x80 {
        ctx.last_printed_char = 0xfe;
        ctx.last_was_graphic = true;
        ctx.raw_putchar(0xfe);
    }
}

pub fn flanterm_flush<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    ctx.double_buffer_flush();
}

pub fn flanterm_full_refresh<B: BackendOps>(ctx: &mut FlantermCore<B>) {
    ctx.full_refresh();
}

pub fn flanterm_get_dimensions<B: BackendOps>(
    ctx: &mut FlantermCore<B>,
    cols: &mut usize,
    rows: &mut usize,
) {
    *cols = ctx.cols;
    *rows = ctx.rows;
}

pub fn flanterm_set_autoflush<B: BackendOps>(ctx: &mut FlantermCore<B>, state: bool) {
    ctx.autoflush = state;
}

pub fn flanterm_set_callback<B: BackendOps>(
    ctx: &mut FlantermCore<B>,
    callback: FlantermCallbackFn<B>,
) {
    ctx.callback = callback;
}
