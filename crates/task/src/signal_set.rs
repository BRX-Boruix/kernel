//! 信号集（SignalSet）——ADR-034 §2.1。
//!
//! 以 `u64` 位图表示一个信号集合：每位对应一个信号号（`sig` 号即位偏移）。
//! - 信号号上限 `SIGSTOP=19 < 64`，`u64` 位图足够；`NSIG=64` 固定（S04 拒绝越界）。
//! - O(1)、`Copy`、无堆分配（S31 最小足迹）。
//! - 硬信号语义：`SIGKILL` 位**不可清除**（`clear`/差集对其是 no-op）；
//!   屏蔽集强制置位由 `FORCED` 集合 + `force_hard` 承担（ADR-034 §2.2/§2.6/§3.2）。
//!
//! 本模块只承载信号集数学与硬信号强制；默认处置表见 [`crate::signal`]，
//! 信号号常量见 [`crate::signals`]。

use crate::signals::{SIGKILL, SIGSTOP};

/// 信号号上限：固定 64（POSIX 常用信号号 `1..=19` 全部容纳，含余量）。
pub const NSIG: u32 = 64;

/// 硬信号集合：屏蔽集里恒置位、不可解除（sigprocmask 强制，ADR-034 §2.2）。
///
/// 目前含 `SIGKILL` 与 `SIGSTOP`。`SIGSTOP` 首期以 `NotSupported` 诚实拒绝，
/// 但屏蔽强制语义按 ADR 成文先行（§4.4：不伪造停止语义，仅保留位不变量）。
pub const FORCED: SignalSet = SignalSet(
    (1u64 << SIGKILL) | (1u64 << SIGSTOP),
);

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

    /// 清除指定信号。`SIGKILL` 不可清除（硬信号，ADR-034 §2.2）——对
    /// SIGKILL 是 no-op；`sig >= NSIG` 无效果。
    pub fn remove(&mut self, sig: u32) {
        if sig == SIGKILL {
            return;
        }
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

    /// 差集（`self` 清除 `other` 中的位）。`SIGKILL` 位不可被差集清除
    /// （与 [`SignalSet::remove`] 同一不变量：硬信号不可清除）。
    ///
    /// 与 `remove(SIGKILL)` 一致，仅**保持** SIGKILL 原状态，绝不无条件
    /// 伪造置位——若原集未含 SIGKILL，差集后仍不含（S07/S09）。
    pub fn difference(&mut self, other: SignalSet) {
        // 清除 other 中除 SIGKILL 外的全部位；SIGKILL 位不受影响。
        self.0 &= !(other.0 & !(1u64 << SIGKILL));
    }

    /// 求补集（0..NSIG 范围内取反）。
    pub const fn complement(self) -> SignalSet {
        SignalSet((!self.0) & Self::all().0)
    }

    /// 强制硬信号置位（sigprocmask UNBLOCK 后调用）：`SIGKILL`/`SIGSTOP`
    /// 恒在屏蔽集中（ADR-034 §3.2）。返回新集合（self 含全部 FORCED 位）。
    pub const fn force_hard(mut self) -> SignalSet {
        self.0 |= FORCED.0;
        self
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
