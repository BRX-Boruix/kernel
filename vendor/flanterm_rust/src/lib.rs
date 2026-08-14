#![no_std]

extern crate alloc;

mod flanterm;
mod generated;
mod unicode_map;

pub mod flanterm_backends;

pub use flanterm::{
    flanterm_context_reinit, flanterm_flush, flanterm_full_refresh, flanterm_get_dimensions,
    flanterm_set_autoflush, flanterm_set_callback, flanterm_write, BackendOps, FlantermCallback,
    FlantermCallbackFn, FlantermCore, FLANTERM_CB_BELL, FLANTERM_CB_DEC, FLANTERM_CB_KBD_LEDS,
    FLANTERM_CB_LINUX, FLANTERM_CB_MODE, FLANTERM_CB_OSC, FLANTERM_CB_POS_REPORT,
    FLANTERM_CB_PRIVATE_ID, FLANTERM_CB_STATUS_REPORT,
};

pub use flanterm_backends::fb::{
    flanterm_fb_init, flanterm_fb_set_flush_callback, FbBackend, FlantermContext,
    FLANTERM_FB_ROTATE_0, FLANTERM_FB_ROTATE_180, FLANTERM_FB_ROTATE_270, FLANTERM_FB_ROTATE_90,
};
