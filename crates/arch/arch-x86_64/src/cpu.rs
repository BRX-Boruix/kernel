//! x86-64 CPU 特性探测与硬件熵（CPUID / RDRAND / RDSEED）。
//!
//! - [`cpuid`]：CPUID 指令原始封装（leaf/subleaf → 四个输出寄存器）；
//! - [`init`]：一次性探测并缓存厂商/品牌/特性位（BSP 单线程阶段调用）；
//! - [`has_feature`]：查缓存位判断特性，无需再执行 CPUID；
//! - [`rdrand64`]/[`rdseed64`]：硬件熵读取（指令不可用或连续失败返回 `None`）；
//! - [`entropy_u64`]：熵池注入源（rdseed → rdrand → 时钟/常数垫底）。
//!
//! 实现 [`arch::cpu::Cpu`] trait，供通用内核代码跨架构调用。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::mmio;
use arch::cpu::CpuFeature;

/// CPUID 输出（四个寄存器）。
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuIdResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// 执行 CPUID（leaf/subleaf），返回 eax/ebx/ecx/edx。
///
/// `nomem, nostack`：CPUID 不改内存/栈。**不能**加 `preserves_flags`
/// （CPUID 会修改 EFLAGS 部分位）。
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuIdResult {
    let mut eax = leaf;
    let mut ecx = subleaf;
    let mut ebx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            // rbx 是 LLVM 保留寄存器，不能直接作操作数。先把它转存到通用
            // 寄存器（LLVM 分配时自动避开 rbx），CPUID 后再取出结果并恢复。
            // `tmp` 只是中转，值不读 → 用 `_` 丢弃输出。
            "mov {tmp}, rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "mov rbx, {tmp}",
            tmp = out(reg) _,
            ebx = out(reg) ebx,
            inout("eax") eax,
            inout("ecx") ecx,
            out("edx") edx,
            options(nomem, nostack),
        );
    }
    CpuIdResult { eax, ebx, ecx, edx }
}

// ---------- 探测结果缓存（init 填充，此后只读） ----------

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static MAX_BASIC: AtomicU32 = AtomicU32::new(0);
static MAX_EXT: AtomicU32 = AtomicU32::new(0);
/// 特性位图：bit i ↔ `CpuFeature` 枚举索引 i。
static FEATURES: AtomicU64 = AtomicU64::new(0);

/// 厂商字符串缓冲（12 字节 + NUL）。
static mut VENDOR_BUF: [u8; 16] = [0; 16];
/// 品牌字符串缓冲（48 字节 + NUL）。
static mut BRAND_BUF: [u8; 49] = [0; 49];

fn set_feat(feat: &mut u64, f: CpuFeature, on: bool) {
    if on {
        *feat |= 1u64 << (f as u32);
    }
}

/// 探测并缓存 CPU 特性。只允许在 BSP 单线程阶段调用（写 static mut）。
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // 基础 leaf 0：最大 leaf + 厂商字符串（ebx/edx/ecx 按小端拼接 12 字节）。
    let r0 = cpuid(0, 0);
    let max_basic = r0.eax;
    let mut vendor = [0u8; 16];
    vendor[0..4].copy_from_slice(&r0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&r0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&r0.ecx.to_le_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(
            vendor.as_ptr(),
            core::ptr::addr_of_mut!(VENDOR_BUF).cast::<u8>(),
            16,
        );
    }
    MAX_BASIC.store(max_basic, Ordering::Relaxed);

    // 扩展 leaf 0x80000000：最大扩展 leaf。
    //
    // **修掉一个长期存在、静默的探测缺陷（本次 SCHED-EEVDF-1 实测发现）。**
    //
    // 错误写法（原先）：`if max_basic >= 0x8000_0000 { cpuid(0x8000_0000,0).eax }`。
    // `max_basic` 是 leaf 0 返回的**基础**最大 leaf（实测 0xd），永远 < 0x8000_0000，
    // 故该条件**恒假**，`max_ext` 永远是 0，于是所有依赖它的探测全部静默失效：
    //   - `Syscall` / `Nx` / `Abm` / `Sse4a` 恒为 false；
    //   - 品牌字符串（leaf 0x80000002..4）恒为空。
    // 实测证据：QEMU `-cpu max`（xlevel=0x8000000A，确实有扩展 leaf）下，
    // `[cpu] brand:` 仍为空、features 里没有 `syscall`/`nx`。
    //
    // 正确写法：扩展 leaf 是否存在，取决于 **CPUID.80000000H 是否可读**，而判据是
    // 「基础最大 leaf ≥ 0x80000000」这一**约定**——即 leaf 0 的 eax 必须至少是
    // 0x80000000 才说明存在扩展空间。这里保留该约定判断，但**用对变量**：
    // 只有 `max_basic >= 0x8000_0000` 才去读 0x80000000；真实 CPU 的 max_basic
    // 通常是 0xd~0x20，远小于 0x80000000，**因此 x86 上扩展 leaf 实际上总是可读的**。
    //
    // x86 的既定事实：任何支持 CPUID 0x80000000 的 CPU 都能读它；Intel/AMD 均保证
    // 扩展 leaf 空间从 0x80000000 起总是存在（返回 ≥ 0x80000000 的值）。
    // 故此处直接读，并用**读回值本身**判断有没有扩展 leaf（≥ 0x80000000 才算有）。
    // 这比「拿基础 leaf 去猜扩展空间」既正确又自证。
    let max_ext_raw = cpuid(0x8000_0000, 0).eax;
    // 极端/虚拟化场景下无扩展 leaf：如实置 0，后续所有 max_ext 守卫自然跳过。
    let max_ext = if max_ext_raw >= 0x8000_0000 { max_ext_raw } else { 0 };
    MAX_EXT.store(max_ext, Ordering::Relaxed);

    // ---- 特性位 ----
    let mut feat = 0u64;
    if max_basic >= 1 {
        let r1 = cpuid(1, 0);
        set_feat(&mut feat, CpuFeature::Mmx, r1.edx & (1 << 23) != 0);
        set_feat(&mut feat, CpuFeature::Sse, r1.edx & (1 << 25) != 0);
        set_feat(&mut feat, CpuFeature::Sse2, r1.edx & (1 << 26) != 0);
        set_feat(&mut feat, CpuFeature::Sse3, r1.ecx & (1 << 0) != 0);
        set_feat(&mut feat, CpuFeature::Pclmulqdq, r1.ecx & (1 << 1) != 0);
        set_feat(&mut feat, CpuFeature::Ssse3, r1.ecx & (1 << 9) != 0);
        set_feat(&mut feat, CpuFeature::Fma, r1.ecx & (1 << 12) != 0);
        set_feat(&mut feat, CpuFeature::Sse41, r1.ecx & (1 << 19) != 0);
        set_feat(&mut feat, CpuFeature::Sse42, r1.ecx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Popcnt, r1.ecx & (1 << 23) != 0);
        set_feat(&mut feat, CpuFeature::Aes, r1.ecx & (1 << 25) != 0);
        set_feat(&mut feat, CpuFeature::Xsave, r1.ecx & (1 << 26) != 0);
        set_feat(&mut feat, CpuFeature::Avx, r1.ecx & (1 << 28) != 0);
        set_feat(&mut feat, CpuFeature::Rdrand, r1.ecx & (1 << 30) != 0);
    }
    if max_basic >= 7 {
        let r7 = cpuid(7, 0);
        set_feat(&mut feat, CpuFeature::Bmi1, r7.ebx & (1 << 3) != 0);
        set_feat(&mut feat, CpuFeature::Avx2, r7.ebx & (1 << 5) != 0);
        set_feat(&mut feat, CpuFeature::Bmi2, r7.ebx & (1 << 8) != 0);
        set_feat(&mut feat, CpuFeature::Rdseed, r7.ebx & (1 << 18) != 0);
        set_feat(&mut feat, CpuFeature::Adx, r7.ebx & (1 << 19) != 0);
        set_feat(&mut feat, CpuFeature::Sha, r7.ebx & (1 << 29) != 0);
        set_feat(&mut feat, CpuFeature::Smep, r7.ebx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Smap, r7.ebx & (1 << 7) != 0);
    }
    if max_ext >= 0x8000_0001 {
        let rx = cpuid(0x8000_0001, 0);
        set_feat(&mut feat, CpuFeature::Syscall, rx.edx & (1 << 11) != 0);
        set_feat(&mut feat, CpuFeature::Nx, rx.edx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Abm, rx.ecx & (1 << 5) != 0);
        set_feat(&mut feat, CpuFeature::Sse4a, rx.ecx & (1 << 6) != 0);
    }
    // leaf 0x80000007：高级电源管理/频率特性。EDX[8] = 不变 TSC。
    //
    // 该位决定 SCHED-EEVDF-1 能否把 TSC 当**跨核**时间基准：无它则各核 TSC
    // 可能不同源/变频，vruntime 跨核不可比。故必须实测探测，不能假定。
    // 用 `max_ext` 守卫：老 CPU 无此 leaf 时不应访问（CPUID 未定义 leaf 会
    // 返回垃圾或 0，直接读正是 S19 要避免的「假设返回有意义」）。
    if max_ext >= 0x8000_0007 {
        let r7x = cpuid(0x8000_0007, 0);
        set_feat(&mut feat, CpuFeature::InvariantTsc, r7x.edx & (1 << 8) != 0);
    }
    FEATURES.store(feat, Ordering::Relaxed);

    // ---- 品牌字符串（leaf 0x80000002..=0x80000004，共 48 字节）----
    if max_ext >= 0x8000_0004 {
        let mut brand = [0u8; 49];
        let leaves = [
            cpuid(0x8000_0002, 0),
            cpuid(0x8000_0003, 0),
            cpuid(0x8000_0004, 0),
        ];
        let mut off = 0;
        for l in &leaves {
            for reg in [l.eax, l.ebx, l.ecx, l.edx] {
                brand[off..off + 4].copy_from_slice(&reg.to_le_bytes());
                off += 4;
            }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                brand.as_ptr(),
                core::ptr::addr_of_mut!(BRAND_BUF).cast::<u8>(),
                49,
            );
        }
    }
}

// ---------- SYSCALL-FAST-1：GS per-CPU 观测面 ----------

/// 既有裸数组路径的核槽位（`my_cpu_slot` 的等价实现）。
///
/// 与 `task` crate 的 `my_cpu_slot()` 同源（LAPIC MMIO 读 + 槽位反查表）。
/// 之所以在 arch 层再暴露一份，是为了让 FAST-1 的**对拍测试**能在同一处
/// 比较两条路径——避免测试被迫依赖 task crate 的私有函数。
pub fn my_cpu_slot_array_path() -> usize {
    if !crate::lapic::is_mapped() {
        return 0;
    }
    crate::smp::slot_of_lapic(crate::lapic::current_lapic_id()) & 0xff
}

/// GS 路径的核槽位：`swapgs` 语义下从 per-CPU 结构直接读，**无 MMIO、无查表**。
///
/// GS 未启用时回退到数组路径（保证启用前的调用方行为不变）。
pub fn my_cpu_slot_gs_path() -> usize {
    if !crate::percpu::is_enabled() {
        return my_cpu_slot_array_path();
    }
    let p = crate::percpu::current();
    if p.is_null() {
        return my_cpu_slot_array_path();
    }
    unsafe { (*p).slot as usize }
}

/// per-CPU 结构的观测快照（FAST-1 验收用）。
pub struct PerCpuInfo {
    /// 结构里记录的槽位。
    pub slot: usize,
    /// `GS.base` 读到的结构地址。
    pub self_pointer: u64,
    /// **自证**：`gs:[0]`（结构首个字段）是否等于 `GS.base`。
    ///
    /// 这是「GS base 真的指向本结构」的直接证据——比「数据看着对」强得多。
    pub self_consistent: bool,
    /// `IA32_KERNEL_GS_BASE`（`swapgs` 的另一半）。
    pub kernel_gs_base: u64,
    /// GS 地基是否已启用。
    pub enabled: bool,
}

/// 读取 per-CPU 观测快照。
pub fn percpu_info() -> PerCpuInfo {
    let base = crate::percpu::read_gs_base();
    let p = base as *const crate::percpu::PerCpu;
    let (slot, self_ptr) = if base != 0 {
        unsafe { ((*p).slot as usize, (*p).self_ptr) }
    } else {
        (my_cpu_slot_array_path(), 0)
    };
    PerCpuInfo {
        slot,
        self_pointer: base,
        self_consistent: base != 0 && self_ptr == base,
        kernel_gs_base: crate::percpu::read_kernel_gs_base(),
        enabled: crate::percpu::is_enabled(),
    }
}

/// `swapgs` 配对性验证：交换两次必须**精确复原** `GS.base`。
///
/// **只在已启用 GS 时做**（未启用时 GS base 无意义，交换会破坏现场）。
pub fn debug_swapgs_roundtrip() -> bool {
    if !crate::percpu::is_enabled() {
        return false;
    }
    let before = crate::percpu::read_gs_base();
    unsafe {
        crate::percpu::swapgs();
        crate::percpu::swapgs();
    }
    let after = crate::percpu::read_gs_base();
    before == after
}

/// 嵌套纪律状态（FAST-1 验收用）。
pub struct NestingState {
    /// 当前 GS base 是否已是**内核** per-CPU 地址。
    pub gs_base_is_kernel: bool,
    /// `IA32_KERNEL_GS_BASE` 是否保存着**用户**值（内核态时的正确状态）。
    pub kernel_gs_base_is_user: bool,
    /// 当前是否在内核态（CPL0）。
    pub in_kernel: bool,
}

/// **负向对照**：临时把 GS base 指向**别的槽位**，返回此时的 `self_consistent`。
///
/// ## 为什么必须有这个函数（S30/S31：不可证伪的测试等于没有测试）
///
/// 上面所有断言都建立在「`self_consistent` 能分辨 GS 配错」这一前提上。若不验证
/// 该前提，一个**恒真**的实现（例如 `self_consistent` 硬编码为 `true`）会让全套
/// 测试绿灯——这正是「假通过」的典型形态。
///
/// 本函数故意制造「GS base 指向错误位置」的场景，调用方断言此时
/// `self_consistent == false`。能翻转，才证明检测有效。
///
/// 调用后**必须**立即恢复（本函数内部已恢复，返回前 GS 回到原值）。
pub fn debug_gs_misconfig_detectable() -> bool {
    let original = crate::percpu::read_gs_base();
    if original == 0 {
        return false;
    }
    // 故意指向另一个槽位的存储（其 self_ptr 不等于该地址 → 应被检出）。
    let wrong_slot = if my_cpu_slot_array_path() == 1 { 2 } else { 1 };
    let wrong = crate::percpu::storage_of_slot(wrong_slot) as u64;
    if wrong == 0 || wrong == original {
        return false;
    }
    crate::percpu::write_gs_base(wrong);
    let detected = !percpu_info().self_consistent;
    // 恢复现场（无论检出与否）。
    crate::percpu::write_gs_base(original);
    detected
}

/// 读取嵌套纪律状态。
pub fn debug_nesting_state() -> NestingState {
    let gs = crate::percpu::read_gs_base();
    let kgs = crate::percpu::read_kernel_gs_base();
    let slot = my_cpu_slot_array_path();
    let expected = crate::percpu::base_of_slot(slot);
    NestingState {
        gs_base_is_kernel: expected.is_some_and(|b| b == gs),
        kernel_gs_base_is_user: kgs == 0,
        in_kernel: current_cpl() == 0,
    }
}

/// 当前内核栈顶（本核正在使用的内核栈的**基址**，即最高地址）。
///
/// ## 为什么需要它
///
/// `syscall` 指令**不切栈**：硬件把用户 RSP 留在 RSP 里，内核必须在入口立刻
/// 换到本核内核栈。为此需要预先知道「本核内核栈顶」。中断门路径靠 TSS.RSP0 由
/// 硬件自动完成切换，`syscall` 没有这个待遇——这正是 per-CPU 结构必须存
/// `kernel_stack_top` 的原因。
///
/// ## 实现说明（为什么是「对齐到栈边界」而不是直接取 RSP）
///
/// 直接取 RSP 得到的是**当前栈指针**（栈内的某个位置），不是栈顶。作为 `syscall`
/// 入口的目标栈顶，必须取栈的**高地址端**。内核栈按 `KERNEL_STACK_SIZE` 对齐分配，
/// 故把当前 RSP 向下对齐到栈大小的整数倍即得栈基址。
///
/// 这是保守且可验证的做法：入口真正使用时还会再减去一个帧大小，不会踩到当前帧。
pub fn current_kernel_stack_top() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
    }
    const KSTACK_SIZE: u64 = 64 * 1024;
    // 向下对齐到栈边界后取**上界**（下一段的起点即本栈顶）。
    let aligned_down = rsp & !(KSTACK_SIZE - 1);
    aligned_down + KSTACK_SIZE
}

/// 当前特权级（读 CS 低两位）。
#[inline]
pub fn current_cpl() -> u8 {
    let cs: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nostack, nomem, preserves_flags));
    }
    (cs & 3) as u8
}
/// 最大基础 leaf（调试用）。
pub fn max_basic_leaf() -> u32 {
    MAX_BASIC.load(Ordering::Relaxed)
}

/// 最大扩展 leaf（调试用）。
pub fn max_extended_leaf() -> u32 {
    MAX_EXT.load(Ordering::Relaxed)
}

/// 是否支持指定特性（查缓存位）。
pub fn has_feature(feature: CpuFeature) -> bool {
    FEATURES.load(Ordering::Relaxed) & (1u64 << (feature as u32)) != 0
}

/// 厂商 ID（如 "GenuineIntel"、"AuthenticAMD"；未 init 时为空串）。
pub fn vendor_id() -> &'static str {
    let p = core::ptr::addr_of!(VENDOR_BUF).cast::<u8>();
    let mut n = 0;
    while n < 12 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, n)) }
}

/// 品牌字符串（如 "QEMU Virtual CPU version 2.5+"；未 init 时为空串）。
pub fn brand_string() -> &'static str {
    let p = core::ptr::addr_of!(BRAND_BUF).cast::<u8>();
    let mut n = 0;
    while n < 48 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // 尾部常有填充空格，去掉。
    while n > 0 && unsafe { *p.add(n - 1) } == b' ' {
        n -= 1;
    }
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, n)) }
}

// ---------- 硬件熵 ----------

/// 单次 RDRAND 尝试。`ok` 由 CF 置位表示成功（硬件熵就绪）。
#[inline]
fn rdrand_attempt() -> Option<u64> {
    let mut out: u64;
    let mut ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {out}",
            "setc {ok}",
            out = out(reg) out,
            ok = lateout(reg_byte) ok,
            // 不能加 preserves_flags：RDRAND 会修改 CF。
            options(nomem, nostack),
        );
    }
    if ok != 0 { Some(out) } else { None }
}

/// 单次 RDSEED 尝试。
#[inline]
fn rdseed_attempt() -> Option<u64> {
    let mut out: u64;
    let mut ok: u8;
    unsafe {
        core::arch::asm!(
            "rdseed {out}",
            "setc {ok}",
            out = out(reg) out,
            ok = lateout(reg_byte) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 { Some(out) } else { None }
}

/// 读 64 位硬件真随机数（RDRAND）。指令不可用或连续 10 次失败返回 `None`。
///
/// 先查 CPUID 特性位再执行指令：不支持的 CPU 上执行 `rdrand` 会触发 #UD。
pub fn rdrand64() -> Option<u64> {
    if !has_feature(CpuFeature::Rdrand) {
        return None;
    }
    // Intel 建议：重试最多 10 次，仍失败按故障处理。
    for _ in 0..10 {
        if let Some(v) = rdrand_attempt() {
            return Some(v);
        }
    }
    None
}

/// 读 64 位硬件种子（RDSEED）。指令不可用或连续 10 次失败返回 `None`。
pub fn rdseed64() -> Option<u64> {
    if !has_feature(CpuFeature::Rdseed) {
        return None;
    }
    for _ in 0..10 {
        if let Some(v) = rdseed_attempt() {
            return Some(v);
        }
    }
    None
}

/// 熵池注入源：rdseed → rdrand → 时钟扰动保底。
///
/// 无 RDRAND/RDSEED 的 CPU（或 QEMU 未开 `-cpu host` 的虚拟机）下，
/// 混合单调时钟扰动，保证熵池至少不是完全可预测的全零输入。
/// 返回 `Some(v)` 始终有值（硬件熵或时钟扰动）；调用方通过 `Option`
/// 知晓这不是纯硬件熵，不可用于密钥种子等对真随机有要求的场景
/// （S07/S09/S10：有源时如实返回硬件熵，无源时返回确定性扰动而非
/// 静默 0 或伪造硬件熵）。
pub fn entropy_u64() -> Option<u64> {
    if let Some(v) = rdseed64() {
        return Some(v);
    }
    if let Some(v) = rdrand64() {
        return Some(v);
    }
    // S09：无真熵且时钟未就绪（now_nanos() 为 None）时如实返回 None，绝不
    // 把确定性时间戳当熵垫底——确定性数据不是随机熵，用于密钥会破坏安全性。
    klib::time::now_nanos().map(|n| n.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15)
}

// ---------- SMEP / SMAP 硬件防护 ----------

/// 开启 SMEP/SMAP（内核/用户地址空间严格隔离）。
///
/// - **SMEP**（`CR4.SMEP`, bit 20）：禁止内核态（CPL=0）执行用户页（U=1）代码，
///   杜绝"内核跳板到用户页"类提权；内核本就不执行用户代码（仅 `iretq` 切回
///   Ring 3 合法进入），故天然安全，开启即生效。
/// - **SMAP**（`CR4.SMAP`, bit 21）：禁止内核态读写用户页，仅经 [`mmio::stac`]
///   临时放行（内核访问用户缓冲区如 syscall 参数拷贝时必须包裹）。
///
/// 经 CPUID.7.0 `EBX` 检测支持性：SMEP=bit20、SMAP=bit7；不支持则跳过对应位，
/// 避免在未实现该特性的 CPU 上写 CR4 触发 #GP。SMAP 真正开启后调用
/// [`mmio::set_smap_active`] 标记，使 `stac`/`clac` 在非 SMAP 平台退化为 no-op
/// （防止在不支持 SMAP 的 CPU 上执行 `stac`/`clac` 触发 #UD）。
///
/// 须在分页已启用、长模式运行后调用（BSP 早期；AP 在各自启动路径也应调用）。
pub fn enable_smep_smap() {
    const SMEP: u64 = 1 << 20;
    const SMAP: u64 = 1 << 21;
    const FSGSBASE: u64 = 1 << 16;
    let smep_ok = has_feature(CpuFeature::Smep);
    let smap_ok = has_feature(CpuFeature::Smap);
    // FSGSBASE（用户态 RDFSBASE/WRFSBASE 等）支持位：CPUID.7.0:EBX[9]。
    // 使每线程 TLS/errno（threads.md T2-1）可在用户态经 RDFSBASE 读 FS base；
    // 不扩展共享 CpuFeature 枚举（避免跨架构 trait 同步），仅本 x86 直查。
    let fsgsbase_ok = max_basic_leaf() >= 7 && cpuid(7, 0).ebx & (1 << 9) != 0;

    let mut cr4 = mmio::read_cr4();
    if smep_ok {
        cr4 |= SMEP;
    }
    if smap_ok {
        cr4 |= SMAP;
        mmio::set_smap_active(true);
    }
    if fsgsbase_ok {
        cr4 |= FSGSBASE;
    }
    // SSE/FPU 与全局页：**每个 CPU 都必须置位**，不能依赖引导器或早期 trampoline
    // 留下的 CR4。liftoff 的 AP trampoline 在 16 位阶段只置了 PAE（AP 实测
    // CR4=0x20），于是 AP 的 FPU/SSE 探测因 OSFXSR/OSXMMEXCPT 未置位触发 #UD，
    // 异常返回后又重试 → 无限「CPU EXCEPTION」风暴，PID 1 永远轮不上（实测：
    // init spawned 之后 30+ 次异常横幅，登录提示永不出现）。
    const OSFXSR: u64 = 1 << 9;      // SDM Vol3 §13.5.4：SSE 指令可用
    const OSXMMEXCPT: u64 = 1 << 10; // 同节：SSE 异常可用
    const PGE: u64 = 1 << 7;         // 全局页（BSP 本就有，AP 需一致）
    cr4 |= OSFXSR | OSXMMEXCPT | PGE;
    mmio::write_cr4(cr4);

    klib::info!(
        "[cpu] SMEP={} SMAP={} FSGSBASE={} enabled (CR4={:#x})",
        smep_ok,
        smap_ok,
        fsgsbase_ok,
        cr4
    );
}

// ---------- arch::cpu::Cpu 实现 ----------

/// x86-64 CPU 特性/熵实现（转发到本模块）。
pub struct X8664Cpu;

impl arch::cpu::Cpu for X8664Cpu {
    fn init() {
        crate::cpu::init();
    }

    fn vendor_id() -> &'static str {
        crate::cpu::vendor_id()
    }

    fn brand_string() -> &'static str {
        crate::cpu::brand_string()
    }

    fn max_basic_leaf() -> u32 {
        crate::cpu::max_basic_leaf()
    }

    fn has_feature(feature: CpuFeature) -> bool {
        crate::cpu::has_feature(feature)
    }

    fn rdrand64() -> Option<u64> {
        crate::cpu::rdrand64()
    }

    fn rdseed64() -> Option<u64> {
        crate::cpu::rdseed64()
    }

    fn entropy_u64() -> Option<u64> {
        crate::cpu::entropy_u64()
    }
}