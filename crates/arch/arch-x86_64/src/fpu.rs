//! FPU/SSE 上下文保存设施（task1 K2）。
//!
//! 设计：**eager 全量保存**——每次任务切出执行 [`save`]（fxsave64），切入执行
//! [`restore`]（fxrstor64）。否决 CR0.TS 惰性切换方案（#NM 路径 + FPU 所属权
//! 跟踪状态，正确性论证面更大）；eager 的代价是每次切换一次 512B 硬件快照 +
//! 每进程 512B 保存区，单核 RR 下可忽略（无 benchmark 级优化诉求，属正确性机制
//! 而非性能机制）。
//!
//! 硬件前提（[`crate::interrupts::enable_fpu`] 在 IDT 初始化时一次性保证）：
//! CR0.TS=0、CR0.EM=0、CR4.OSFXSR=1。若该前提被未来改动破坏，本模块首条
//! 浮点指令即触发 #NM/#UD——按"宁可报错"原则不做运行时防御性检查，
//! 故障直接暴露在出错现场。

/// 单个任务的 x87/SSE/MMX 状态保存区（FXSAVE 格式，512 字节，16 字节对齐）。
///
/// 对齐由 `repr(align)` 静态保证——FXSAVE/FXRSTOR 要求内存操作数 16 字节对齐，
/// 违反即 #GP；把对齐焊死在类型上使调用方无法构造出未对齐用例。
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FpuArea {
    bytes: [u8; 512],
}

impl FpuArea {
    /// 零值区。仅在随后必然被 [`init_template`] 或 [`save`] 完整覆写时使用；
    /// 直接 [`restore`] 一个零值区是编程错误（MXCSR=0 非法，将 #GP）。
    pub const fn zeroed() -> Self {
        Self { bytes: [0; 512] }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

/// 把当前 CPU 的 x87/SSE 状态快照写入 `area`。
///
/// 前置：TS=0/EM=0/OSFXSR=1（模块文档）。调用方须保证当前执行流此后不再
/// 使用浮点状态直至下一次 [`restore`]（调度器语义：切出点之后 CPU 归下一任务）。
///
/// 本指令只读寄存器、写内存，无需向编译器声明寄存器破坏。
#[inline]
pub fn save(area: &mut FpuArea) {
    // 默认（无 nomem）告知编译器本指令读写未知内存，禁止重排缓存；
    // 对齐由 FpuArea 类型保证，非法地址由调用方生命周期保证。
    unsafe {
        core::arch::asm!(
            "fxsave64 [{}]",
            in(reg) area.as_mut_ptr(),
            options(nostack)
        );
    }
}

/// 从 `area` 恢复 x87/SSE 状态到当前 CPU。
///
/// **破坏声明是正确性的一部分**：fxrstor64 覆写全部 XMM 寄存器与 x87 栈。
/// 若不声明，编译器有权假定跨本语句存活的 SSE 中间值仍然有效（x86_64
/// 目标默认启用 SSE，代码生成可能真实持有此类值）——那是静默腐坏。显式
/// 列出全部 XMM 为破坏 + `clobber_abi("C")` 强制编译器把任何跨语句浮点值
/// 落回内存并在其后重载；恢复后的 x87 栈为空标签，与 SysV ABI"调用边界
/// x87 栈空"约定一致。
#[inline]
pub fn restore(area: &FpuArea) {
    unsafe {
        core::arch::asm!(
            "fxrstor64 [{}]",
            in(reg) area.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            clobber_abi("C"),
            options(nostack)
        );
    }
}

/// 初始化一个"干净 exec 态"模板：FNINIT 复位 x87 状态字/标签字/控制字，
/// **pxor 强零化全部 XMM**，再把复位后的完整状态快照进 `area`。新进程 PCB
/// 以此为初始 FPU 现场——等价 POSIX exec 语义：新映像从归零/初始化的向量
/// 状态起步。
///
/// 审计 R5-F2 语义修正记录：FNINIT 不清 XMM，仅靠它的快照会携带模板生成
/// 瞬间内核执行现场的寄存器残渣，子进程首读即见他人数据（伪现场/泄漏面，
/// S09 族）。现于 FNINIT 后 pxor 强零化再快照；成本一次性摊销在模板缓存
/// （懒单例）上，非每切换开销。前提同 [`save`]；破坏声明与 [`restore`]
/// 同理按 S21 成文。
pub fn init_template(area: &mut FpuArea) {
    unsafe {
        core::arch::asm!(
            "fninit",
            "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2",
            "pxor xmm3, xmm3", "pxor xmm4, xmm4", "pxor xmm5, xmm5",
            "pxor xmm6, xmm6", "pxor xmm7, xmm7", "pxor xmm8, xmm8",
            "pxor xmm9, xmm9", "pxor xmm10, xmm10", "pxor xmm11, xmm11",
            "pxor xmm12, xmm12", "pxor xmm13, xmm13", "pxor xmm14, xmm14",
            "pxor xmm15, xmm15",
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            clobber_abi("C"),
            options(nostack)
        );
    }
    save(area);
}
