//! 系统调用（syscall）入口抽象（ADR-007）。
//!
//! 统一成"一次可移植的 syscall 调用上下文 + 注册分发入口"的抽象。各架构
//! 在软中断/陷入（如 x86 的 `int 0x80`）时把架构寄存器现场翻译成本 crate
//! 的 [`SyscallFrame`]，调用已注册的分发入口；业务层只读/写 [`SyscallFrame`]，
//! 不接触架构寄存器知识。
//!
//! 覆盖 ADR-007 的 `SyscallEntry` trait 与可移植的调用上下文。

/// 一次系统调用的可移植调用上下文（寄存器窗口）。
///
/// 架构实现把 `int 0x80`（或等价陷入）的寄存器现场翻译成此结构：
/// - `nr` / `a1..a5`：系统调用号与参数（由架构从寄存器填入）；
/// - `result`：分发入口写回的结果（架构层读回并写回调用进程返回值寄存器）；
/// - `switched`：是否已切换到另一进程现场。`true` 时 `result` 无意义，架构层
///   必须**不得**把 `result` 写回调用进程（现场已是下一进程的保存帧，其
///   返回值由调度语义负责，如 waitpid 交付的退出码）。
///
/// `arch_frame` 为底层架构中断帧的**不透明句柄**（`usize`）。仅当分发入口
/// 需要切换现场（阻塞/让出/yield，Switched 路径）时，经架构提供的原语把它
/// 还原为真实架构帧使用；业务层不直接解释其内容，非切换路径不读取。
#[repr(C)]
pub struct SyscallFrame {
    /// 系统调用号。
    pub nr: u64,
    /// 参数 1（架构约定第 1 个参数寄存器）。
    pub a1: u64,
    /// 参数 2。
    pub a2: u64,
    /// 参数 3。
    pub a3: u64,
    /// 参数 4。
    pub a4: u64,
    /// 参数 5。
    pub a5: u64,
    /// 分发入口写回的结果（Switched 时无意义）。
    pub result: u64,
    /// 是否已切换到另一进程现场。
    pub switched: bool,
    /// 辅助返回寄存器（r10）值：仅 waitpid 同步收尸路径设置，携带被收尸
    /// 子进程 pid；其余 syscall 保持 0（r10 不被改写）。架构层在 `rax` 写回
    /// 的同时把此值写进返回帧 r10，与阻塞路径 `saved.r10=pid` 交付对齐，
    /// 使 waitpid 在同步/阻塞两条路径都向用户态交付同一对 (rax=code, r10=pid)。
    pub aux_pid: u64,
    /// 底层架构中断帧不透明句柄（切换路径用；业务层不解释）。
    pub arch_frame: usize,
}

/// 系统调用分发入口：`fn(&mut SyscallFrame) -> bool`。
///
/// 返回 `true` 表示处理完成（架构层按 `frame.result` / `frame.switched`
/// 决定是否写回返回值寄存器）；`false` 表示未处理。
pub type SyscallEntryFn = extern "C" fn(&mut SyscallFrame) -> bool;

/// 系统调用入口抽象接口（全静态方法，风格与 [`crate::Platform`] 一致）。
pub trait SyscallEntry {
    /// 注册内核的 syscall 分发入口。架构在软中断（如 x86 `int 0x80`）时
    /// 构造 [`SyscallFrame`] 并调用该入口。
    ///
    /// 分发入口须为 `'static`（`extern "C"` 静态函数），启动期单次注册。
    fn register(entry: SyscallEntryFn);
}
