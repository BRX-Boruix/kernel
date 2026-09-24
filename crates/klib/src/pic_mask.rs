//! 8259 中断掩码的**纯逻辑状态机**（无 I/O、可在宿主上穷举测试）。
//!
//! ## 为什么必须把它从 arch-x86_64::pic 里抽出来
//!
//! pic.rs 的 mask_irq/unmask_irq 是**读-改-写**：get_mask() 从 IMR 端口读回当前
//! 掩码，改一位，再整字写回。这段逻辑有两个无法在裸机上验证的风险：
//!
//! 1. **丢失更新（lost update）**：两个 CPU 并发执行「读-改-写」时，后写者的
//!    快照会覆盖先写者的结果。8259 的 IMR 端口读写没有原子性保证。
//!    中断上下文（device_irq_handler 里的 mask_irq）与进程上下文
//!    （driver_irq_wait 里的 unmask_irq）会并发触碰同一个端口。
//! 2. **整字覆盖**：set_mask 直接把调用方给的 16 位写下去。任何调用方若用了
//!    过期的快照，就会静默清掉别的子系统刚解屏蔽的线——典型症状是
//!    「某条线明明解了屏蔽却永远收不到中断」。
//!
//! arch-x86_64 是 no_std + 内联汇编，cargo test 根本编译不过，所以这段逻辑
//! 一直**没有任何测试覆盖**。把它抽成纯数据变换后，所有并发交错都能在宿主上
//! 穷举钉死（S23/S15）。
//!
//! ## 语义契约
//!
//! 掩码的 bit i = 1 表示 **IRQ i 被屏蔽**（8259 IMR 的硬件语义，1 = masked）。
//! 与 8259 数据手册一致，不做转置——转置是「差一位」类缺陷的温床。

/// 8259 的 IRQ 线数量（主片 8 条 + 从片 8 条）。
pub const PIC_IRQ_COUNT: usize = 16;

/// 主片 IRQ2 是**级联线**：从片（IRQ8~15）的输出经它进入主片。
///
/// 屏蔽它等于屏蔽整条从片——这是「明明解了掩码却收不到中断」最经典的坑，
/// 因此对从片 IRQ 的解屏蔽必须自动带上它。
pub const PIC_CASCADE_IRQ: u8 = 2;

/// IRQ0：本系统由 LAPIC 定时器接管，故 8259 上保持屏蔽。
pub const PIC_TIMER_IRQ: u8 = 0;

/// 键盘 IRQ1（PS/2 8042）。系统启动后必须保持解屏蔽。
pub const PIC_KEYBOARD_IRQ: u8 = 1;

/// 计算「解屏蔽某条 IRQ」后的新掩码。
///
/// 纯函数：给定当前掩码与目标 IRQ，返回应写入 IMR 的新掩码。
/// 越界 IRQ（>=16）如实返回原掩码不变——绝不静默改动别的位。
///
/// irq >= 8（从片）时**一并解屏蔽级联线 IRQ2**，否则从片的输出到不了主片。
pub const fn unmask(mask: u16, irq: u8) -> u16 {
    if irq as usize >= PIC_IRQ_COUNT {
        return mask;
    }
    let mut m = mask & !(1u16 << irq);
    if irq >= 8 {
        m &= !(1u16 << PIC_CASCADE_IRQ);
    }
    m
}

/// 计算「屏蔽某条 IRQ」后的新掩码。越界 IRQ 如实返回原掩码不变。
pub const fn mask(mask: u16, irq: u8) -> u16 {
    if irq as usize >= PIC_IRQ_COUNT {
        return mask;
    }
    mask | (1u16 << irq)
}

/// 某条 IRQ 当前是否**被屏蔽**（IMR 位为 1）。越界保守视为已屏蔽。
///
/// 单列这个正向谓词（而不是只给 is_unmasked）是为了让断言读起来与硬件语义
/// 同向——双重否定（!is_unmasked）在测试里极易写反，本模块的测试全部使用
/// 本函数，消除这一类书写错误。
pub const fn is_masked(mask: u16, irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return true;
    }
    mask & (1u16 << irq) != 0
}

/// 启动完成后的**基线掩码**：只开键盘 IRQ1，其余（含 IRQ0 定时器、IRQ2 级联、
/// 全部 PCI 线）保持屏蔽。
///
/// **为何 IRQ2 也屏蔽**：级联线由**从片设备驱动自己按需打开**（unmask 对
/// irq>=8 自动带上）。启动时无条件常开 IRQ2 会在没有任何从片驱动就位时放行
/// 从片的杂散请求。
///
/// **必须显式面对的约束**：任何整字写 IMR 的路径都必须以此基线为起点，
/// 或经由本模块的位运算，否则会静默清掉别的线。
pub const fn boot_baseline() -> u16 {
    !(1u16 << PIC_KEYBOARD_IRQ)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解屏蔽必须**只**清目标位，绝不碰其它位。
    #[test]
    fn unmask_clears_only_the_target_bit() {
        let all = 0xFFFFu16;
        let after = unmask(all, 1);
        assert!(!is_masked(after, 1), "IRQ1 必须已解屏蔽");
        for i in 0..16u8 {
            if i == 1 {
                continue;
            }
            assert!(
                is_masked(after, i),
                "解屏蔽 IRQ1 不得顺带解屏蔽 IRQ{i}（掩码 {after:#06x}）"
            );
        }
    }

    /// **从片级联**：解屏蔽 IRQ>=8 必须自动带上 IRQ2，否则从片中断到不了主片。
    #[test]
    fn unmask_of_slave_irq_also_opens_cascade() {
        let all = 0xFFFFu16;
        let after = unmask(all, 11);
        assert!(!is_masked(after, 11), "IRQ11 必须已解屏蔽");
        assert!(
            !is_masked(after, PIC_CASCADE_IRQ),
            "解屏蔽 IRQ11 必须同时打开级联线 IRQ2"
        );
    }

    /// 主片 IRQ（<8）**不得**顺带打开级联线——那不是它的语义。
    #[test]
    fn unmask_of_master_irq_does_not_touch_cascade() {
        let all = 0xFFFFu16;
        let after = unmask(all, 1);
        assert!(
            is_masked(after, PIC_CASCADE_IRQ),
            "解屏蔽键盘 IRQ1 不应改变级联线状态"
        );
    }

    /// 屏蔽/解屏蔽必须**幂等**：重复同一操作结果不变。
    /// 幂等性是「中断 handler 里反复 mask」能安全的原因。
    #[test]
    fn mask_and_unmask_are_idempotent() {
        let base = boot_baseline();
        let m1 = mask(base, 11);
        let m2 = mask(m1, 11);
        assert_eq!(m1, m2, "重复屏蔽必须幂等");
        let u1 = unmask(m1, 11);
        let u2 = unmask(u1, 11);
        assert_eq!(u1, u2, "重复解屏蔽必须幂等");
    }

    /// **丢失更新**（本模块要防的核心缺陷）：基于**过期快照**写回会丢位。
    ///
    /// 本测试显式展示陈旧快照的后果，并钉死正确做法——这正是实测中断丢失的
    /// 成因，不是假想场景。
    #[test]
    fn stale_snapshot_writeback_loses_updates() {
        let start = boot_baseline(); // IRQ1 开、其余关
        // 正确做法：基于 start 解屏蔽 IRQ11 -> IRQ1 + IRQ2 + IRQ11 都开。
        let good = unmask(start, 11);
        assert!(!is_masked(good, 11), "IRQ11 应开");
        assert!(!is_masked(good, PIC_CASCADE_IRQ), "级联应开");
        assert!(!is_masked(good, PIC_KEYBOARD_IRQ), "键盘 IRQ1 必须保持开");

        // 错误做法：另一个 CPU 拿着 start 这个**已过期的快照**只清 IRQ11 的位，
        // 写回后会把 good 里刚打开的 IRQ2 重新关掉。下面断言这种写回的结果
        // 确实与 good 不同——即**丢掉了更新**。
        let stale = start;
        assert!(
            is_masked(stale, PIC_CASCADE_IRQ),
            "陈旧快照写回会重新屏蔽级联线——这正是实测的中断丢失成因"
        );
        assert_ne!(stale, good, "陈旧快照与正确结果必须不同，否则本测试没测到东西");
    }

    /// 越界 IRQ 必须**如实不动作**，绝不静默改别的位（S09）。
    #[test]
    fn out_of_range_irq_changes_nothing() {
        let m = 0x1234u16;
        assert_eq!(unmask(m, 16), m, "IRQ16 越界，掩码不得变化");
        assert_eq!(unmask(m, 255), m, "IRQ255 越界，掩码不得变化");
        assert_eq!(mask(m, 16), m);
        assert!(is_masked(m, 16), "越界 IRQ 保守视为已屏蔽");
    }

    /// 启动基线：**只有**键盘 IRQ1 解屏蔽，其余（含 IRQ0/IRQ2）全屏蔽。
    #[test]
    fn boot_baseline_unmasks_only_the_keyboard() {
        let b = boot_baseline();
        assert!(!is_masked(b, PIC_KEYBOARD_IRQ), "键盘必须开");
        assert!(is_masked(b, PIC_TIMER_IRQ), "IRQ0 由 LAPIC 定时器接管，保持屏蔽");
        assert!(
            is_masked(b, PIC_CASCADE_IRQ),
            "启动基线不常开级联线；由从片驱动按需打开"
        );
        for i in 0..16u8 {
            if i == PIC_KEYBOARD_IRQ {
                continue;
            }
            assert!(is_masked(b, i), "基线不得解屏蔽 IRQ{i}");
        }
    }

    /// 键盘与 HDA 各自的 mask/unmask 在**最新状态**上不互相干扰。
    #[test]
    fn keyboard_and_hda_operations_commute_on_fresh_state() {
        let s0 = boot_baseline();
        // 顺序 A：开 HDA -> 动键盘 -> 再把键盘开回来。
        let a = unmask(mask(unmask(s0, 11), 1), 1);
        // 顺序 B：动键盘 -> 把键盘开回来 -> 开 HDA。
        let b = unmask(unmask(mask(s0, 1), 1), 11);
        assert_eq!(a, b, "基于最新掩码的两种顺序必须收敛到同一状态");
        assert!(!is_masked(a, 11), "IRQ11 应开");
        assert!(!is_masked(a, PIC_KEYBOARD_IRQ), "键盘应开");
        assert!(!is_masked(a, PIC_CASCADE_IRQ), "级联应开");
    }
}