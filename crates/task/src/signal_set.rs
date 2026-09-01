//! 信号集（SignalSet）——ADR-034 §2.1。
//!
//! 以 `u64` 位图表示一个信号集合：每位对应一个信号号（`sig` 号即位偏移）。
//! - 信号号上限 `SIGSTOP=19 < 64`，`u64` 位图足够；`NSIG=64` 固定（S04 拒绝越界）。
//! - O(1)、`Copy`、无堆分配（S31 最小足迹）。
//!
//! 硬信号不可屏蔽/不可捕获语义由**语义层**强制（单一事实来源）：
//! - 不可屏蔽：`mask`（sigprocmask）对 `SIGKILL` 恒做清除（`remove`），故屏蔽集
//!   永不含 SIGKILL（ADR-034 §2.6/§3.2）；
//! - 不可捕获：`validate_disposition` 拒绝给 SIGKILL 设 handler/ignore。
//! 位图本身是纯 bitmask，无按信号的硬编码不变量（S3 整改：消除 FORCED/force_hard
//! 与 mask force_clear 的双重事实来源）。
//!
//! 本模块只承载信号集数学与硬信号强制；默认处置表见 [`crate::signal`]，
//! 信号号常量见 [`crate::signals`]。

/// 信号号上限：固定 64（POSIX 常用信号号 `1..=19` 全部容纳，含余量）。
pub const NSIG: u32 = 64;


/// 一个信号集（u64 位图）。
///
/// `Copy` + 位运算：信号集在进程 PCB 中按值传递/更新，无需堆分配。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SignalSet(pub u64);

impl SignalSet {
    /// 空信号集。
    pub const fn empty() -> Self {
        SignalSet(0)
    }

    /// 全置位（0..NSIG 全部为 1）。
    ///
    /// NSIG==64：全部 64 位即 `u64::MAX`（`1u64 << 64` 会溢出，须整型字面量）。
    pub const fn all() -> Self {
        SignalSet(u64::MAX)
    }

    /// 仅含指定信号的集合。`sig >= NSIG` 时如实返回空集（不 panic，S19）。
    pub const fn of(sig: u32) -> Self {
        if sig >= NSIG {
            SignalSet(0)
        } else {
            SignalSet(1u64 << sig)
        }
    }

    /// 原始位图值。
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// 是否为空。
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// 是否含指定信号。`sig >= NSIG` 恒为 false。
    pub const fn contains(self, sig: u32) -> bool {
        sig < NSIG && (self.0 >> sig) & 1 != 0
    }

    /// 置位指定信号。`sig >= NSIG` 无效果。
    pub fn insert(&mut self, sig: u32) {
        if sig < NSIG {
            self.0 |= 1u64 << sig;
        }
    }

    /// 清除指定信号（纯 bitmask 操作）。`sig >= NSIG` 无效果。
    ///
    /// 硬信号不可屏蔽由语义层（`mask`/`validate_disposition`）保证，不在此
    /// 硬编码 SIGKILL 不变量（S3 整改：位图无按信号特判，消除双重事实来源）。
    pub fn remove(&mut self, sig: u32) {
        if sig < NSIG {
            self.0 &= !(1u64 << sig);
        }
    }

    /// 并集（位或）。
    pub const fn union(self, other: SignalSet) -> SignalSet {
        SignalSet(self.0 | other.0)
    }

    /// 交集（位与）。
    pub const fn intersection(self, other: SignalSet) -> SignalSet {
        SignalSet(self.0 & other.0)
    }

    /// 差集（`self` 清除 `other` 中的位）。纯 bitmask 操作（S3 整改：
    /// 无 SIGKILL 特判，硬信号不可屏蔽由语义层保证）。
    pub fn difference(&mut self, other: SignalSet) {
        self.0 &= !other.0;
    }

    /// 求补集（0..NSIG 范围内取反）。
    pub const fn complement(self) -> SignalSet {
        SignalSet((!self.0) & Self::all().0)
    }

    /// 未决集最低信号号（ADR-034 §2.4：派发取号顺序确定）。
    ///
    /// 返回集合中**最低**的置位信号号；空集返回 `None`。这是投递机制取号的
    /// 单点定义（S13）——派发层 `deliver_on_return` 与测试均经此取最低号，
    /// 不得在调用方各自重复实现。
    pub const fn lowest_pending(self) -> Option<u32> {
        if self.0 == 0 {
            return None;
        }
        Some(self.0.trailing_zeros() as u32)
    }
}
