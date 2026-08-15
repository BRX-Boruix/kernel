//! 诊断格式化输出（十进制/十六进制）。
//!
//! 薄封装，复用 `klib::serial` 的格式化输出，供 lapic、mmio、interrupts、smp
//! 等模块使用，避免重复实现整数转字符串逻辑。每次输出拼接成一段 `&str` 后
//! 整串写入，保证在 `serial` 锁下原子输出，避免多核交错。

/// 以十进制写 `value` 到串口（无前导零，`0` 输出单个 `0`）。
pub use klib::serial::write_dec;

/// 以十六进制写 `value` 到串口（不带 0x 前缀，固定 16 位宽度）。
pub use klib::serial::write_hex_raw as write_hex_u64;

/// 以十六进制写 `value` 到串口，带 `0x` 前缀。
pub use klib::serial::write_hex;
