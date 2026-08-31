//! 信号号定义与「CPU 异常 → 信号」映射（task1 KM1/KM2/KD2 整改后形态）。
//!
//! 本模块是全内核**信号号常量**的单点定义（S13），承载：
//! - POSIX 对齐的信号号常量（`SIG*`）；
//! - `signal_for_exception`：CPU 异常 vector → 信号号映射；
//! - `signal_name`：信号号 → 名称表（打印用）。
//!
//! ADR-034（现代信号机制）在此基础上扩展：信号号取值全部对齐 POSIX
//! （signal(7)），覆盖可捕获（SIGUSR1/2、SIGPIPE、SIGALRM、SIGCHLD）、
//! 硬信号（SIGKILL、SIGSTOP/SIGCONT）与异常映射信号。信号集的位图数学、
//! 默认处置表与派发逻辑分别见 [`crate::signal_set`] 与 [`crate::signal`]。

/// SIGINT：终端中断（Ctrl-C，POSIX 2）。
pub const SIGINT: u32 = 2;
/// SIGILL：非法指令（#UD / #II / #BR / #OF）。
///
/// 信号号取值全部对齐 POSIX（signal(7)），来源唯一：本模块是全内核信号
/// 常量的单点定义（S13）。
pub const SIGILL: u32 = 4;
/// SIGBUS：总线错误（#DF 双故障映射，见 [`signal_for_exception`]）。
pub const SIGBUS: u32 = 7;
/// SIGFPE：算术/浮点异常（#DE 除零等）。
pub const SIGFPE: u32 = 8;
/// SIGKILL：不可捕获、不可忽略、不可屏蔽的立即终止（POSIX 9）。
///
/// 硬信号：`sigaction` 拒绝对其设 handler/ignore，屏蔽集强制置位不可解除
/// （ADR-034 §2.2/§2.6）。
pub const SIGKILL: u32 = 9;
/// SIGUSR1：用户自定义信号 1（POSIX 10，应用可捕获）。
pub const SIGUSR1: u32 = 10;
/// SIGSEGV：段错误（#PF / #GP / #SS / #NP / #AC）。
pub const SIGSEGV: u32 = 11;
/// SIGUSR2：用户自定义信号 2（POSIX 12，应用可捕获）。
pub const SIGUSR2: u32 = 12;
/// SIGPIPE：向已关闭读端的管道写数据（POSIX 13，默认终止）。
pub const SIGPIPE: u32 = 13;
/// SIGALRM：用户态定时器到期（POSIX 14，默认终止）。
pub const SIGALRM: u32 = 14;
/// SIGTERM：兜底终止（未知异常 / 请求终止）。
pub const SIGTERM: u32 = 15;
/// SIGCHLD：子进程停止/退出通知父进程（POSIX 17）。
pub const SIGCHLD: u32 = 17;
/// SIGCONT：让被 SIGSTOP 暂停的进程继续（POSIX 18）。
pub const SIGCONT: u32 = 18;
/// SIGSTOP：暂停进程（POSIX 19，硬信号：不可捕获/忽略）。
pub const SIGSTOP: u32 = 19;

/// CPU 异常 vector → 信号号（仅用户态异常使用）。
///
/// #DF（vector 8，双故障）映射 SIGBUS 而非 SIGFPE：双故障通常是栈溢出/
/// 硬件层灾难（IDT/IST 失守、栈越界），"算术异常"语义牵强（KD2）；
/// SIGBUS 的"访问了不该访问的底层资源"语义最接近。其余映射见各分支注释。
pub const fn signal_for_exception(vector: u64) -> u32 {
    match vector {
        0 => SIGFPE,             // #DE 除零
        4 | 5 | 6 => SIGILL,     // #OF / #BR / #UD
        8 => SIGBUS,             // #DF 双故障（栈/硬件层灾难）
        11 | 12 | 13 => SIGSEGV, // #NP / #SS / #GP
        14 => SIGSEGV,           // #PF 页错误
        17 => SIGSEGV,           // #AC 对齐检查
        _ => SIGTERM,            // 其余未知异常 → 兜底终止
    }
}

/// 信号号 → 名称（打印用）。
///
/// 未知信号号如实返回 `"SIGUNKNOWN"`——绝不把未知值贴成某个具体信号的
/// 标签（误导性标签 ≈ 伪数据，task1 KM2）。覆盖 ADR-034 §2.1 全部新号。
pub const fn signal_name(sig: u32) -> &'static str {
    match sig {
        SIGINT => "SIGINT",
        SIGILL => "SIGILL",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGUSR1 => "SIGUSR1",
        SIGSEGV => "SIGSEGV",
        SIGUSR2 => "SIGUSR2",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGCHLD => "SIGCHLD",
        SIGCONT => "SIGCONT",
        SIGSTOP => "SIGSTOP",
        _ => "SIGUNKNOWN",
    }
}
