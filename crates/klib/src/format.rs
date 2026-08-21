//! 架构无关的格式化输出（C 风格 printf 核心）。
//!
//! 提供类 C `printf` 的格式化解析器，支持：
//! - 转换说明符：`%d`/`%i`（有符号十进制）、`%u`（无符号）、`%x`/`%X`（十六进制）、
//!   `%o`（八进制）、`%b`（二进制）、`%p`（指针）、`%s`（字符串）、`%c`（字符）、`%%`（字面 `%`）
//! - 标志：`-`（左对齐）、`0`（零填充）、`+`（显式符号）、` `（正数前空格）、`#`（前缀 `0x`/`0`）
//! - 宽度（如 `%08x`、`%5d`）与精度（如 `%.4x`、`%.5s`）
//!
//! 由于 `no_std` 且不依赖 `alloc`，格式化结果写入调用方提供的字节缓冲
//! （`format_into`），或写入任意 `fmt::Write`（`format_to`）。
//!
//! 参数通过统一的 `FmtArg` 枚举传入；`kfmt_args!` 宏把多个不同类型的表达式
//! 自动折叠成 `&[FmtArg]`，供 `kprint`/`kprintln` 等宏使用。

use core::fmt;

// ---------- 参数抽象 ----------

/// 格式化参数的统一表示。
///
/// 通过 `From` 从常见标量/引用转换而来。整数值同时保留"有符号视图"与
/// "无符号视图"：`%d` 取有符号视图，`%u`/`%x` 等取无符号视图。
#[derive(Clone, Copy)]
pub enum FmtArg {
    /// 有符号整数。
    Int(i128),
    /// 无符号整数。
    UInt(u128),
    /// 字符串（'static，多用于字符串字面量）。
    Str(&'static str),
    /// 字符。
    Char(char),
    /// 布尔值（`%s` 时打印 true/false）。
    Bool(bool),
}

impl FmtArg {
    /// 无符号视图（`%u`/`%x`/`%o`/`%b`/`%p` 使用）。
    ///
    /// `%d`/`%i` 也以此传入 `emit_number`，由 `signed` 标志在内部重解释为有符号。
    #[inline]
    fn as_u128(self) -> u128 {
        match self {
            FmtArg::UInt(v) => v,
            FmtArg::Int(v) => v as u128,
            FmtArg::Bool(b) => b as u128,
            _ => 0,
        }
    }
}

impl From<i8> for FmtArg {
    fn from(v: i8) -> Self {
        FmtArg::Int(v as i128)
    }
}
impl From<i16> for FmtArg {
    fn from(v: i16) -> Self {
        FmtArg::Int(v as i128)
    }
}
impl From<i32> for FmtArg {
    fn from(v: i32) -> Self {
        FmtArg::Int(v as i128)
    }
}
impl From<i64> for FmtArg {
    fn from(v: i64) -> Self {
        FmtArg::Int(v as i128)
    }
}
impl From<i128> for FmtArg {
    fn from(v: i128) -> Self {
        FmtArg::Int(v)
    }
}
impl From<isize> for FmtArg {
    fn from(v: isize) -> Self {
        FmtArg::Int(v as i128)
    }
}
impl From<u8> for FmtArg {
    fn from(v: u8) -> Self {
        FmtArg::UInt(v as u128)
    }
}
impl From<u16> for FmtArg {
    fn from(v: u16) -> Self {
        FmtArg::UInt(v as u128)
    }
}
impl From<u32> for FmtArg {
    fn from(v: u32) -> Self {
        FmtArg::UInt(v as u128)
    }
}
impl From<u64> for FmtArg {
    fn from(v: u64) -> Self {
        FmtArg::UInt(v as u128)
    }
}
impl From<u128> for FmtArg {
    fn from(v: u128) -> Self {
        FmtArg::UInt(v)
    }
}
impl From<usize> for FmtArg {
    fn from(v: usize) -> Self {
        FmtArg::UInt(v as u128)
    }
}
impl From<char> for FmtArg {
    fn from(v: char) -> Self {
        FmtArg::Char(v)
    }
}
impl From<bool> for FmtArg {
    fn from(v: bool) -> Self {
        FmtArg::Bool(v)
    }
}
impl From<&'static str> for FmtArg {
    fn from(v: &'static str) -> Self {
        FmtArg::Str(v)
    }
}

// ---------- 数字转换表 ----------

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

// ---------- 格式化核心 ----------

/// 把 `fmt` 中的 C 风格转换说明符，用 `args` 展开后写入 `out`。
///
/// `args` 中的参数按格式串中出现的顺序消费；不足时输出 `%<spec>` 原样。
pub fn format_to(out: &mut dyn fmt::Write, fmt: &str, args: &[FmtArg]) -> fmt::Result {
    let bytes = fmt.as_bytes();
    let mut i = 0usize;
    let mut arg_i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b != b'%' {
            out.write_char(b as char)?;
            i += 1;
            continue;
        }

        // 已遇到 '%'，解析 flags / width / precision / spec。
        i += 1;
        let mut left = false;
        let mut zero = false;
        let mut plus = false;
        let mut space = false;
        let mut alt = false;
        loop {
            match bytes.get(i).copied() {
                Some(b'-') => {
                    left = true;
                    i += 1;
                }
                Some(b'0') => {
                    zero = true;
                    i += 1;
                }
                Some(b'+') => {
                    plus = true;
                    i += 1;
                }
                Some(b' ') => {
                    space = true;
                    i += 1;
                }
                Some(b'#') => {
                    alt = true;
                    i += 1;
                }
                _ => break,
            }
        }

        let mut width = 0usize;
        while let Some(d) = bytes.get(i).copied() {
            if d.is_ascii_digit() {
                width = width * 10 + (d - b'0') as usize;
                i += 1;
            } else {
                break;
            }
        }

        let mut precision: Option<usize> = None;
        if bytes.get(i).copied() == Some(b'.') {
            i += 1;
            let mut p = 0usize;
            while let Some(d) = bytes.get(i).copied() {
                if d.is_ascii_digit() {
                    p = p * 10 + (d - b'0') as usize;
                    i += 1;
                } else {
                    break;
                }
            }
            precision = Some(p);
        }

        let Some(&spec) = bytes.get(i) else {
            // 格式串在 '%' 后结束：输出字面 '%'
            out.write_char('%')?;
            break;
        };
        i += 1;

        if spec == b'%' {
            out.write_char('%')?;
            continue;
        }

        let arg = args.get(arg_i).copied();
        if let Some(arg) = arg {
            arg_i += 1;
            match spec {
                b'd' | b'i' => emit_number(
                    out,
                    arg.as_u128(),
                    10,
                    false,
                    true,
                    plus,
                    space,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'u' => emit_number(
                    out,
                    arg.as_u128(),
                    10,
                    false,
                    false,
                    false,
                    false,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'x' => emit_number(
                    out,
                    arg.as_u128(),
                    16,
                    false,
                    false,
                    false,
                    false,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'X' => emit_number(
                    out,
                    arg.as_u128(),
                    16,
                    true,
                    false,
                    false,
                    false,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'o' => emit_number(
                    out,
                    arg.as_u128(),
                    8,
                    false,
                    false,
                    false,
                    false,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'b' => emit_number(
                    out,
                    arg.as_u128(),
                    2,
                    false,
                    false,
                    false,
                    false,
                    alt,
                    width,
                    zero,
                    left,
                    precision,
                )?,
                b'p' => emit_pointer(out, arg, width, zero, left)?,
                b's' => emit_string(out, arg, width, left, precision)?,
                b'c' => emit_char(out, arg, width, left)?,
                _ => {
                    // 未知说明符：原样输出
                    out.write_char('%')?;
                    out.write_char(spec as char)?;
                }
            }
        } else {
            // 参数不足
            out.write_char('%')?;
            out.write_char(spec as char)?;
        }
    }
    Ok(())
}

/// 输出字符串参数（`%s`）。若参数是整数则视为 ASCII 码字符。
fn emit_string(
    out: &mut dyn fmt::Write,
    arg: FmtArg,
    width: usize,
    left: bool,
    precision: Option<usize>,
) -> fmt::Result {
    let s = match arg {
        FmtArg::Str(s) => s,
        FmtArg::Bool(b) => {
            if b {
                "true"
            } else {
                "false"
            }
        }
        FmtArg::Char(_c) => return emit_char(out, arg, width, left),
        other => {
            // 非字符串参数：退化为单字符
            let c = (other.as_u128() & 0xff) as u8;
            return emit_char(out, FmtArg::Char(c as char), width, left);
        }
    };
    let visible = precision.map_or(s.len(), |p| p.min(s.len()));
    let pad = width.saturating_sub(visible);
    if !left {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    out.write_str(&s[..visible])?;
    if left {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    Ok(())
}

/// 输出字符参数（`%c`）。整数参数取低 8 位作为字符码。
fn emit_char(out: &mut dyn fmt::Write, arg: FmtArg, width: usize, left: bool) -> fmt::Result {
    let c = match arg {
        FmtArg::Char(c) => c,
        other => ((other.as_u128() & 0xff) as u8) as char,
    };
    let pad = width.saturating_sub(1);
    if !left {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    out.write_char(c)?;
    if left {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    Ok(())
}

/// 输出指针参数（`%p`）：`0x` + 十六进制。
fn emit_pointer(
    out: &mut dyn fmt::Write,
    arg: FmtArg,
    width: usize,
    zero: bool,
    left: bool,
) -> fmt::Result {
    let v = arg.as_u128();
    let digits = count_digits(v, 16);
    let total = 2 + digits; // "0x" + hex
    let pad = width.saturating_sub(total);
    if !left && !zero {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    out.write_str("0x")?;
    if zero && !left {
        for _ in 0..pad {
            out.write_char('0')?;
        }
    }
    write_uint_raw(out, v, 16, false)?;
    if left {
        for _ in 0..pad {
            out.write_char(' ')?;
        }
    }
    Ok(())
}

/// 数字输出核心。
///
/// `value` 始终以无符号视图传入；`signed` 为真时按有符号重解释（`%d`）。
#[allow(clippy::too_many_arguments)]
fn emit_number(
    out: &mut dyn fmt::Write,
    value: u128,
    base: u32,
    upper: bool,
    signed: bool,
    plus: bool,
    space: bool,
    alt: bool,
    width: usize,
    zero: bool,
    left: bool,
    precision: Option<usize>,
) -> fmt::Result {
    // 符号
    let sign: Option<char> = if signed {
        let v = value as i128;
        if v < 0 {
            Some('-')
        } else if plus {
            Some('+')
        } else if space {
            Some(' ')
        } else {
            None
        }
    } else if plus {
        Some('+')
    } else if space {
        Some(' ')
    } else {
        None
    };

    // 前缀（`#` 标志）
    let prefix: &str = if alt {
        match base {
            16 => {
                if upper {
                    "0X"
                } else {
                    "0x"
                }
            }
            8 => "0",
            _ => "",
        }
    } else {
        ""
    };

    // 取绝对值（有符号负数）
    let mag: u128 = if signed {
        (value as i128).unsigned_abs()
    } else {
        value
    };

    let n = count_digits(mag, base);
    let prec_pad = precision.map_or(0, |p| p.saturating_sub(n));
    let visible_len = sign.is_some() as usize + prefix.len() + prec_pad + n;

    // 零填充（仅在未指定 precision 时生效，符合 C 语义）
    let zero_pad = if zero && precision.is_none() {
        width.saturating_sub(visible_len)
    } else {
        0
    };
    let space_pad = width.saturating_sub(visible_len + zero_pad);

    if !left {
        if zero {
            // 零填充：sign + prefix + 0* + prec* + digits
            if let Some(s) = sign {
                out.write_char(s)?;
            }
            out.write_str(prefix)?;
            for _ in 0..zero_pad {
                out.write_char('0')?;
            }
            for _ in 0..prec_pad {
                out.write_char('0')?;
            }
            write_uint_raw(out, mag, base, upper)?;
        } else {
            // 空格填充：pad + sign + prefix + prec + digits
            for _ in 0..space_pad {
                out.write_char(' ')?;
            }
            if let Some(s) = sign {
                out.write_char(s)?;
            }
            out.write_str(prefix)?;
            for _ in 0..prec_pad {
                out.write_char('0')?;
            }
            write_uint_raw(out, mag, base, upper)?;
        }
    } else {
        // 左对齐：sign + prefix + prec + digits + pad
        if let Some(s) = sign {
            out.write_char(s)?;
        }
        out.write_str(prefix)?;
        for _ in 0..prec_pad {
            out.write_char('0')?;
        }
        write_uint_raw(out, mag, base, upper)?;
        for _ in 0..space_pad {
            out.write_char(' ')?;
        }
    }
    Ok(())
}

/// 计算 `value` 在 `base` 进制下的数字位数（`0` 记为 1 位）。
fn count_digits(mut value: u128, base: u32) -> usize {
    let mut n = 0usize;
    if value == 0 {
        return 1;
    }
    let base = base as u128;
    while value > 0 {
        value /= base;
        n += 1;
    }
    n
}

/// 直接输出 `value` 的 `base` 进制表示（低位先算，倒序写出）。
fn write_uint_raw(
    out: &mut dyn fmt::Write,
    mut value: u128,
    base: u32,
    upper: bool,
) -> fmt::Result {
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    let base = base as u128;
    if value == 0 {
        out.write_char('0')?;
        return Ok(());
    }
    while value > 0 {
        let d = (value % base) as u8;
        buf[n] = if d < 10 {
            b'0' + d
        } else if upper {
            HEX_UPPER[d as usize]
        } else {
            HEX_LOWER[d as usize]
        };
        n += 1;
        value /= base;
    }
    for k in (0..n).rev() {
        out.write_char(buf[k] as char)?;
    }
    Ok(())
}

// ---------- 输出到字节缓冲 ----------

/// 写入固定字节缓冲的 `fmt::Write`。
struct ByteWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl fmt::Write for ByteWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len();
        if self.len + n > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + n].copy_from_slice(s.as_bytes());
        self.len += n;
        Ok(())
    }
}

/// 把 C 风格格式化结果写入 `buf`，返回写入的字节数（不含终止符）。
///
/// 缓冲不足时截断返回（返回实际写入长度，不报错）。
pub fn format_into(buf: &mut [u8], fmt: &str, args: &[FmtArg]) -> usize {
    let mut w = ByteWriter { buf, len: 0 };
    // 忽略 fmt::Error（仅用于截断检测）
    let _ = format_to(&mut w, fmt, args);
    w.len
}

// ---------- 便捷封装 ----------

/// 打印 C 风格格式化字符串（追加换行）。
///
/// 用法：`kprintln!("val=%d 0x%08x %s", a, b, "hi")`。
#[macro_export]
macro_rules! kprintln {
    () => { $crate::serial::write_str("\n") };
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        let mut __buf = [0u8; 1024];
        let __n = $crate::format::format_into(
            &mut __buf,
            $fmt,
            $crate::kfmt_args!($($arg),*),
        );
        $crate::serial::write_str(core::str::from_utf8(&__buf[..__n]).unwrap_or(""));
        $crate::serial::write_str("\n");
    }};
}

/// 打印 C 风格格式化字符串（不追加换行）。
#[macro_export]
macro_rules! kprint {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        let mut __buf = [0u8; 1024];
        let __n = $crate::format::format_into(
            &mut __buf,
            $fmt,
            $crate::kfmt_args!($($arg),*),
        );
        $crate::serial::write_str(core::str::from_utf8(&__buf[..__n]).unwrap_or(""));
    }};
}

/// 把多个不同类型的表达式折叠为 `&[FmtArg]`。
#[macro_export]
macro_rules! kfmt_args {
    ($($arg:expr),* $(,)?) => {
        &[ $($crate::format::FmtArg::from($arg)),* ]
    };
}

// ---------- 原有兼容接口 ----------

/// 把 `value` 以十进制转成字节数组（无前导零，`0` 为单个 `0`）。
/// 返回 `(缓冲区, 有效长度)`。
pub fn dec_bytes(value: u128) -> ([u8; 40], usize) {
    let mut buf = [0u8; 40];
    let mut n = 0;
    let mut v = value;
    if v == 0 {
        buf[n] = b'0';
        n += 1;
    }
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    // 逆序后拷贝到输出缓冲
    let mut out = [0u8; 40];
    let mut o = 0;
    while n > 0 {
        n -= 1;
        out[o] = buf[n];
        o += 1;
    }
    (out, o)
}

/// 把 `value` 以十六进制转成固定 16 位字节数组（小写，高位在前）。
pub fn hex_bytes(value: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX_LOWER[((value >> shift) & 0xF) as usize];
    }
    buf
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::{FmtArg, format_into};

    /// 格式化到调用方提供的栈缓冲，返回借用该缓冲的 `&str`，便于断言。
    ///
    /// 刻意不依赖堆分配（klib 的 `#[global_allocator]` 在测试环境下未初始化，
    /// 任何 `String`/`Vec` 分配都会失败）。
    fn fmt<'a>(s: &str, args: &[FmtArg], buf: &'a mut [u8; 256]) -> &'a str {
        let n = format_into(buf, s, args);
        core::str::from_utf8(&buf[..n]).unwrap()
    }

    #[test]
    fn test_decimal() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("x=%d y=%d", kfmt_args!(42, -7), &mut b), "x=42 y=-7");
    }

    #[test]
    fn test_unsigned_hex() {
        let mut b = [0u8; 256];
        assert_eq!(
            fmt("hex=%x UPPER=%X", kfmt_args!(255u32, 255u32), &mut b),
            "hex=ff UPPER=FF"
        );
    }

    #[test]
    fn test_zero_pad_width() {
        let mut b = [0u8; 256];
        assert_eq!(
            fmt("0x%08x", kfmt_args!(0xdeadbeefu64), &mut b),
            "0xdeadbeef"
        );
        let mut c = [0u8; 256];
        assert_eq!(fmt("%08x", kfmt_args!(0xabu32), &mut c), "000000ab");
    }

    #[test]
    fn test_width_and_left_align() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("[%5d]", kfmt_args!(42), &mut b), "[   42]");
        let mut c = [0u8; 256];
        assert_eq!(fmt("[%-5d]", kfmt_args!(42), &mut c), "[42   ]");
    }

    #[test]
    fn test_string_precision() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("[%.3s]", kfmt_args!("hello"), &mut b), "[hel]");
        let mut c = [0u8; 256];
        assert_eq!(fmt("[%10s]", kfmt_args!("hi"), &mut c), "[        hi]");
    }

    #[test]
    fn test_pointer() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("ptr=%p", kfmt_args!(0x1234u64), &mut b), "ptr=0x1234");
    }

    #[test]
    fn test_char_and_percent() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("%c %% done", kfmt_args!('A'), &mut b), "A % done");
    }

    #[test]
    fn test_signed_neg_hex() {
        // %x 对负数取补码无符号视图
        let mut b = [0u8; 256];
        assert_eq!(
            fmt("%x", kfmt_args!(-1i32), &mut b),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_octal_binary() {
        let mut b = [0u8; 256];
        assert_eq!(fmt("%o %b", kfmt_args!(8u32, 5u32), &mut b), "10 101");
    }

    #[test]
    fn test_alt_prefix() {
        let mut b = [0u8; 256];
        assert_eq!(
            fmt("%#x %#X", kfmt_args!(255u32, 255u32), &mut b),
            "0xff 0XFF"
        );
    }
}
