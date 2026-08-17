//! 简单信号机制雏形。
//!
//! 雏形阶段仅定义信号号与「CPU 异常 → 信号」的映射，供用户态异常处理器
//! 把进程的异常终止归类为可读的信号名（SIGSEGV/SIGILL 等），替代原本裸的
//! `vector=` 打印。完整的信号派发 / 用户 handler 回调（sigaction、向进程投递
//! 信号）留待 M5 进程回收与信号框架补齐。
#![allow(dead_code)]

/// SIGILL：非法指令（#UD / #II / #BR / #OF）。
pub const SIGILL: u32 = 4;
/// SIGBUS：总线错误（预留映射）。
pub const SIGBUS: u32 = 7;
/// SIGFPE：算术/浮点异常（#DE 除零等）。
pub const SIGFPE: u32 = 8;
/// SIGSEGV：段错误（#PF / #GP / #SS / #NP / #AC）。
pub const SIGSEGV: u32 = 11;
/// SIGTERM：兜底终止（未知异常）。
pub const SIGTERM: u32 = 15;

/// CPU 异常 vector → 信号号（雏形映射，仅用户态异常使用）。
pub const fn signal_for_exception(vector: u64) -> u32 {
    match vector {
        0 => SIGFPE,            // #DE 除零
        4 | 5 | 6 => SIGILL,    // #OF / #BR / #UD
        8 => SIGFPE,            // #DF（兜底按算术）
        11 | 12 | 13 => SIGSEGV, // #NP / #SS / #GP
        14 => SIGSEGV,          // #PF 页错误
        17 => SIGSEGV,          // #AC 对齐检查
        _ => SIGTERM,           // 其余未知异常 → 兜底终止
    }
}

/// 信号号 → 名称（打印用）。
pub const fn signal_name(sig: u32) -> &'static str {
    match sig {
        SIGILL => "SIGILL",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGSEGV => "SIGSEGV",
        _ => "SIGTERM",
    }
}
