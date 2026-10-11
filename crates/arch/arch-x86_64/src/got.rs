//! 内核 `.got` 审计（诊断用）。
//!
//! ## 为什么需要它
//!
//! 内核是 **PIE**（ELF 类型 DYN），跨 CGU 的调用经 `callq *GOT[n]` 间接进行；
//! GOT 槽在 ELF 里是 0，靠加载期的 `R_X86_64_RELATIVE` 重定位填成真实地址。
//! 2026-10 机内实测到一类**内核态取指异常**（`#PF`/`#GP`，`rip` 落在镜像之外或等于
//! 日志文本的 ASCII 字节），现场指向一次 GOT 间接调用返回了垃圾。
//!
//! 该异常间歇出现，而**启动期 GOT 必定是填好的**（否则第一行串口输出就会炸）。
//! 故唯一能区分「没填」与「被改写」的办法是：把 GOT 的**零值槽**在启动时数一遍，
//! 再在异常时数一遍——两次都记下来，比较即可判定 GOT 是否被运行期改写。
//!
//! 只做只读扫描，不分配、不加锁、不经 console（异常路径可用）。

/// GOT 起止（由 kernel 的链接脚本提供；见 `linker.ld` 的 `.got` 输出段）。
unsafe extern "C" {
    static __got_start: u8;
    static __got_end: u8;
}

/// 审计结果：`(零值槽数, 总槽数, 首个零值槽的地址或 0)`。
pub struct GotAudit {
    pub zero_slots: usize,
    pub total_slots: usize,
    pub first_zero: usize,
}

/// 扫描整个 `.got`，统计零值槽。
///
/// **读的是链接期符号定出的真实区间**，不硬编码地址——布局随构建变化，硬编码必然漂移。
pub fn audit() -> GotAudit {
    // SAFETY：两个符号由链接脚本在 `.got` 输出段内定义，start < end 且该区间在本次
    // 扫描期间一直有效（内核镜像常驻、只读扫描、不改状态）。
    let start = unsafe { &__got_start as *const u8 as usize };
    let end = unsafe { &__got_end as *const u8 as usize };
    let mut zero = 0usize;
    let mut total = 0usize;
    let mut first_zero = 0usize;
    let mut p = start;
    while p + 8 <= end {
        let v = unsafe { core::ptr::read_volatile(p as *const u64) };
        total += 1;
        if v == 0 {
            if zero == 0 {
                first_zero = p;
            }
            zero += 1;
        }
        p += 8;
    }
    GotAudit {
        zero_slots: zero,
        total_slots: total,
        first_zero,
    }
}
