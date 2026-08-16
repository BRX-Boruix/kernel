//! 内核日志级别宏。
//!
//! 统一输出到 [`crate::console`]，最终转发到所有已注册 sink（串口、屏幕等）。
//!
//! 级别划分（T2 将在此之上加级别过滤与环形日志缓冲，届时只需改宏内实现，
//! 全部调用点零改动）：
//! - [`debug!`]：细节/调试信息（测试输出、寄存器状态等）
//! - [`info!`]：正常流程的关键节点（boot 进度、资源初始化完成等）
//! - [`warn!`]：可恢复的异常（降级、重试、资源不足但已处理）
//! - [`error!`]：错误（功能不可用、路径失败、硬件异常 dump 等）

/// `debug!`：细节/调试信息。
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::console::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `info!`：正常流程的关键节点。
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::console::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `warn!`：可恢复的异常。
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::console::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `error!`：错误。
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::console::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}
