//! 信号号定义与「CPU 异常 → 信号」映射（task1 KM1/KM2/KD2 整改后形态）。
//!
//! 当前仅定义信号号、名称表与异常映射，供用户态异常处理器把进程的异常终止
//! 归类为可读的信号名（SIGSEGV/SIGILL 等）与 kill 路径做常量化校验。
//! 完整的信号派发 / 用户 handler 回调（sigaction、向进程投递信号）留待
//! 信号框架里程碑补齐。

/// SIGILL：非法指令（#UD / #II / #BR / #OF）。
///
/// 信号号取值全部对齐 POSIX（signal(7)），来源唯一：本模块是全内核信号
/// 常量的单点定义（S13）。
pub const SIGILL: u32 = 4;
/// SIGBUS：总线错误（#DF 双故障映射，见 [`signal_for_exception`]）。
pub const SIGBUS: u32 = 7;
/// SIGFPE：算术/浮点异常（#DE 除零等）。
pub const SIGFPE: u32 = 8;
/// SIGKILL：不可捕获、不可忽略的立即终止（POSIX 9）。
pub const SIGKILL: u32 = 9;
/// SIGSEGV：段错误（#PF / #GP / #SS / #NP / #AC）。
pub const SIGSEGV: u32 = 11;
/// SIGTERM：兜底终止（未知异常 / 请求终止）。
pub const SIGTERM: u32 = 15;

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
/// 标签（误导性标签 ≈ 伪数据，task1 KM2）。
pub const fn signal_name(sig: u32) -> &'static str {
    match sig {
        SIGILL => "SIGILL",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGSEGV => "SIGSEGV",
        SIGTERM => "SIGTERM",
        _ => "SIGUNKNOWN",
    }
}
