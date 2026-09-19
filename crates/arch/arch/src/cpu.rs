//! CPU 特性与熵源架构抽象（ADR-007）。
//!
//! 通用内核代码只依赖本 trait，由各具体架构实现：
//! - `vendor_id`/`brand_string`/`max_basic_leaf`：厂商与型号识别；
//! - `has_feature`：运行时特性探测（x86 走 CPUID，RISC-V 走 misa/isa
//!   字符串，AArch64 走 ID 寄存器），实现方负责把探测结果缓存；
//! - `rdrand64`/`rdseed64`/`entropy_u64`：硬件熵读取（供 `klib::random`
//!   熵池混合），`entropy_u64` 返回 `Option<u64>`——`None` 表示无可用
//!   硬件熵源（S09/S07：绝不返回确定性数据冒充硬件熵）。
//!
//! 探测结果建议在 `init()`（BSP 单线程阶段）缓存，后续查询走缓存，
//! 避免反复执行慢指令（如 x86 CPUID/RDSEED）。

/// 跨架构通用的 CPU 特性位。
///
/// 各架构实现把"自己的探测方式"（CPUID 位 / CSR 位 / ID 寄存器位）映射到
/// 本枚举的索引；索引即特征位号（`1u64 << (feature as u32)`）。
/// 无法探测的特性返回 `false`，不影响正确性。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CpuFeature {
    Mmx = 0,
    Sse = 1,
    Sse2 = 2,
    Sse3 = 3,
    Ssse3 = 4,
    Sse41 = 5,
    Sse42 = 6,
    Popcnt = 7,
    Fma = 8,
    Avx = 9,
    Avx2 = 10,
    Xsave = 11,
    Aes = 12,
    Pclmulqdq = 13,
    Rdrand = 14,
    Rdseed = 15,
    Adx = 16,
    Bmi1 = 17,
    Bmi2 = 18,
    Sha = 19,
    Syscall = 20,
    Nx = 21,
    Abm = 22,
    Sse4a = 23,
    /// Supervisor Mode Execution Prevention (x86 CPUID.7.0:EBX[20]).
    Smep = 24,
    /// Supervisor Mode Access Prevention (x86 CPUID.7.0:EBX[7]).
    Smap = 25,
    /// **不变 TSC**（x86 `CPUID.80000007H:EDX[8]`，AMD 称 `InvariantTSC`，
    /// Intel 称 `Invariant TSC` / 常与 `ConstantTsc`+`NonstopTsc` 并列）。
    ///
    /// **为什么它必须被探测**：`rdtsc` 是 **per-CPU** 计数器。没有该位时，
    /// 各核的 TSC 可能**不同步、且频率随 P-state 变化**——把它当**跨核全局**
    /// 时间基准（如 vruntime）会得到不可比的读数。有该位则保证 TSC 以恒定
    /// 频率运行且各核同源，可安全作跨核单调时钟。
    ///
    /// 本位的探测直接决定 SCHED-EEVDF-1 的选型：无该位就不能选 TSC 做 vruntime
    /// 基准（须退回 HPET 或 per-CPU 校准），故选型结论必须引用它而非假定。
    InvariantTsc = 26,
}

impl CpuFeature {
    /// 特性名（调试打印用）。
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mmx => "mmx",
            Self::Sse => "sse",
            Self::Sse2 => "sse2",
            Self::Sse3 => "sse3",
            Self::Ssse3 => "ssse3",
            Self::Sse41 => "sse4.1",
            Self::Sse42 => "sse4.2",
            Self::Popcnt => "popcnt",
            Self::Fma => "fma",
            Self::Avx => "avx",
            Self::Avx2 => "avx2",
            Self::Xsave => "xsave",
            Self::Aes => "aes",
            Self::Pclmulqdq => "pclmulqdq",
            Self::Rdrand => "rdrand",
            Self::Rdseed => "rdseed",
            Self::Adx => "adx",
            Self::Bmi1 => "bmi1",
            Self::Bmi2 => "bmi2",
            Self::Sha => "sha",
            Self::Syscall => "syscall",
            Self::Nx => "nx",
            Self::Abm => "abm",
            Self::Sse4a => "sse4a",
            Self::Smep => "smep",
            Self::Smap => "smap",
            Self::InvariantTsc => "invariant_tsc",
        }
    }

    /// 本枚举覆盖的全部特性（按索引顺序，可遍历打印/探测）。
    pub const ALL: [CpuFeature; 26] = [
        Self::Mmx,
        Self::Sse,
        Self::Sse2,
        Self::Sse3,
        Self::Ssse3,
        Self::Sse41,
        Self::Sse42,
        Self::Popcnt,
        Self::Fma,
        Self::Avx,
        Self::Avx2,
        Self::Xsave,
        Self::Aes,
        Self::Pclmulqdq,
        Self::Rdrand,
        Self::Rdseed,
        Self::Adx,
        Self::Bmi1,
        Self::Bmi2,
        Self::Sha,
        Self::Syscall,
        Self::Nx,
        Self::Abm,
        Self::Sse4a,
        Self::Smep,
        Self::Smap,
    ];
}

// S04：编译期断言 ALL 与枚举判别式一一对应（覆盖全部 0..=Smap 判别式，
// 且按升序无遗漏/重复）。新增枚举变体而忘同步 ALL 时此处编译失败，
// 杜绝"新特性静默漏探测"。
const _: () = {
    let mut i = 0;
    while i < CpuFeature::ALL.len() {
        if CpuFeature::ALL[i] as u8 != i as u8 {
            panic!("CpuFeature::ALL out of order or missing discriminant");
        }
        i += 1;
    }
    if CpuFeature::ALL.len() != CpuFeature::Smap as usize + 1 {
        panic!("CpuFeature::ALL must cover every discriminant 0..=Smap");
    }
};

/// CPU 特性/熵抽象接口（全静态方法，风格与 [`crate::Platform`] 一致）。
pub trait Cpu {
    /// 探测并缓存 CPU 特性（应在 BSP 单线程阶段调用一次）。
    fn init();

    /// 厂商 ID 字符串（如 "GenuineIntel"、"AuthenticAMD"）。
    fn vendor_id() -> &'static str;

    /// 品牌/型号字符串（如 "Intel(R) Core(TM) i7-9700K"）。
    fn brand_string() -> &'static str;

    /// 基础特性探测最大 leaf（调试/兼容用，x86 CPUID leaf 0）。
    fn max_basic_leaf() -> u32;

    /// 是否支持指定特性。
    fn has_feature(feature: CpuFeature) -> bool;

    /// 从硬件真随机数发生器读 64 位（指令不可用或失败时 `None`）。
    fn rdrand64() -> Option<u64>;

    /// 从硬件种子发生器读 64 位（`RDSEED`；指令不可用或失败时 `None`）。
    fn rdseed64() -> Option<u64>;

    /// 尽力从硬件熵源取 64 位（rdseed 优先，其次 rdrand；均不可用返回 `None`）。
    ///
    /// 熵池注入用此接口；无硬件熵源的架构应返回 `None`（S09/S07/S10：绝不
    /// 以确定性数据冒充硬件熵——宁可无源，不注伪熵），而非返回 0 或时间戳垫底。
    fn entropy_u64() -> Option<u64> {
        // 默认实现：尝试 rdseed 和 rdrand；均不可用则如实表达无源。
        // 架构可覆盖（如 x86-64 可混合时钟噪声作最差保底，但必须明确标注）
        // 且不可用于密钥。
        Self::rdseed64().or_else(|| Self::rdrand64())
    }
}
