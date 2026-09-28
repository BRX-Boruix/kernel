//! 符号表：把返回地址解析为函数名（供 panic 栈回溯使用）。
//!
//! 符号表数据由构建脚本 `tools/tools_build/symbols.py` 从内核 ELF 提取生成，
//! 内容为 `symbols_generated.rs`（按地址升序排列的 `(addr, name)` 数组）。
//! 若未生成（首次构建）则为空表，`symbolize` 退化为仅返回十六进制地址。
//!
//! 注意：本模块必须**零堆分配**，因为栈回溯可能发生在堆分配器初始化之前。

use core::fmt;
use core::str;

include!("symbols_generated.rs");

/// 符号表快照是否陈旧（KM13）。
///
/// `SYMBOLS_EPOCH` 由 SDK 构建路径写入生成文件（本次构建的唯一标识），
/// `BORUIX_SYMBOLS_BUILD_EPOCH` 由 build.rs 从同一构建的环境注入。两者相等
/// 才能证明"嵌入符号表与本二进制同源"。直连 `cargo build` 使用 checked-in
/// 快照时两者必然失配——此时 .text 布局可能已漂移，panic 回溯会给出**错误
/// 函数名**（比空表更有害），故必须在启动横幅如实告警。
pub fn snapshot_stale() -> bool {
    /// 环境变量缺失/不可解析时的裁决值（审计 B11）：取 u64::MAX = **恒判
    /// 陈旧**。解析失败意味着构建环境注入链断裂，符号表来源不可证——
    /// 宁可每次启动多打一条陈旧告警（诚实），也绝不借"恰好等于 0"静默
    /// 伪装成同源（S09：解析失败归零与真值 0 混淆正是该红线禁止的）。
    /// 与 parse_ms 的编译期 assert 同一纪律家族。
    const UNPARSEABLE_EPOCH: u64 = u64::MAX;
    const BUILD_EPOCH: u64 = match u64::from_str_radix(env!("BORUIX_SYMBOLS_BUILD_EPOCH"), 10) {
        Ok(v) => v,
        Err(_) => UNPARSEABLE_EPOCH,
    };
    SYMBOLS_EPOCH != BUILD_EPOCH
}

/// 一个 `fmt::Write`，写入固定大小的字节缓冲（栈上）。
pub struct BufWriter<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
}

impl fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let space = self.buf.len().saturating_sub(self.len);
        if space == 0 {
            return Err(fmt::Error);
        }
        let n = s.len().min(space);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// 把返回地址解析为 "name+0xoff" 形式写入 `out`（栈缓冲），返回写入的子串。
///
/// 未命中符号时写入十六进制地址。永不 panic、不分配堆。
pub fn symbolize<'a>(addr: u64, out: &'a mut [u8]) -> &'a str {
    use core::fmt::Write as _;
    // 二分查找：找到最后一个符号起始地址 <= addr 的条目。
    let mut lo = 0usize;
    let mut hi = SYMBOLS.len(); // [lo, hi)
    while lo < hi {
        let mid = (lo + hi) / 2;
        if SYMBOLS[mid].0 <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut w = BufWriter { buf: out, len: 0 };
    if lo == 0 {
        // 没有 <= addr 的符号，退化为十六进制地址
        let _ = write!(w, "{:#x}", addr);
    } else {
        let (base, name) = SYMBOLS[lo - 1];
        let off = addr - base;
        if off == 0 {
            let _ = w.write_str(name);
        } else {
            let _ = write!(w, "{}+{:#x}", name, off);
        }
    }
    // 仅在有效 UTF-8 时返回；否则回退为空串
    str::from_utf8(&w.buf[..w.len]).unwrap_or("")
}
