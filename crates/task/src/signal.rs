//! 每进程信号处置——ADR-034 §2.2。
//!
//! 承载每信号的处置（`SigDisposition`）与"默认处置查表"（`default_disposition`）。
//! - `SigDisposition`：Default / Ignore / Handler(fn)。`SIGKILL`/`SIGSTOP`
//!   处置**恒为 Default**（`sigaction` 拒绝对其设 handler/ignore，映射 klib
//!   `InvalidParam`）。
//! - `default_disposition(sig)`：Default 处置落到哪个默认动作（Terminate /
//!   Ignore / Stop / Cont），查表。
//!
//! 本模块只承载处置类型与默认表；信号集位图见 [`crate::signal_set`]，
//! 信号号常量见 [`crate::signals`]。
//!
//! 本模块为纯逻辑（无内核硬件依赖），其数学正确性由 kernel crate 的
//! `test_signal_foundation`（kernel-tests，QEMU 实机）覆盖——任务 crate
//! 因依赖含 x86_64 内联汇编的 arch-x86_64 无法宿主 `cargo test`，故按
//! ADR-033 先例把纯逻辑验收放到 QEMU kernel-tests（S06：不留宿主导向的
//! `#[cfg(test)]` 死代码）。

use arch_x86_64::interrupts::InterruptFrame;
use crate::process::Process;
use crate::signal_set::{NSIG, SignalSet};
use crate::signals::{SIGCHLD, SIGCONT, SIGKILL, SIGSTOP};

/// 一个信号的处置方式（ADR-034 §2.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigDisposition {
    /// 默认处置（终止/忽略/停止/继续，查 [`default_disposition`]）。
    Default,
    /// 忽略该信号。
    Ignore,
    /// 用户态 handler 函数指针。
    Handler(u64),
}

/// "Default" 处置对应的默认动作（ADR-034 §2.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// 终止进程。
    Terminate,
    /// 忽略（不投递、不动作）。
    Ignore,
    /// 暂停进程（SIGSTOP，首期以 NotSupported 诚实拒绝，§4.4）。
    Stop,
    /// 恢复暂停的进程（SIGCONT）。
    Cont,
}

/// 默认处置查表：`sig` 的 Default 动作。
///
/// 取值对齐 POSIX 默认语义（signal(7)）与 ADR-034 §2.2。未知信号号（`>= NSIG`
/// 或未列举）如实返回 Terminate（兜底终止，S09 不伪造）。
pub const fn default_disposition(sig: u32) -> DefaultAction {
    match sig {
        SIGCHLD => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Cont,
        SIGSTOP => DefaultAction::Stop,
        // 其余（含 SIGKILL/SIGINT/SIGILL/SIGBUS/SIGFPE/SIGUSR1/SIGSEGV/
        // SIGUSR2/SIGPIPE/SIGALRM/SIGTERM 及未知号）默认终止。
        _ => DefaultAction::Terminate,
    }
}

/// 该信号是否"硬信号"（处置恒 Default、不可设 handler/ignore）。
///
/// 目前为 `SIGKILL` 与 `SIGSTOP`（ADR-034 §2.2/§2.6）。
pub const fn is_hard_signal(sig: u32) -> bool {
    sig == SIGKILL || sig == SIGSTOP
}

/// 校验 `sigaction` 设置的处置：硬信号不可设 Handler/Ignore（恒 Default），
/// 越界信号号拒绝。
///
/// - `sig >= NSIG`：越界信号号（`OutOfRange`，ERANGE）——不允许对其设处置
///   （与 `default_disposition`/`SignalSet::of` 对越界的处理不同：处置设置是
///   真实的状态写入，越界必须如实拒绝而非静默忽略，S09）；
/// - 硬信号（SIGKILL/SIGSTOP）设 Handler/Ignore：`InvalidParam`（EINVAL，ADR-034 §2.2）；
/// - 否则 `Ok(())`。
pub fn validate_disposition(sig: u32, disp: SigDisposition) -> Result<(), klib::error::Error> {
    use crate::signal_set::NSIG;
    if sig >= NSIG {
        return Err(klib::error::Error::OutOfRange);
    }
    if is_hard_signal(sig) && !matches!(disp, SigDisposition::Default) {
        return Err(klib::error::Error::InvalidParam);
    }
    Ok(())
}

/// 每进程信号状态（ADR-034 §2.2）——挂载于 `Process.signal`。
///
/// 承载每信号的处置（`handlers`）、屏蔽集（`blocked`）、未决集（`pending`）、
/// 重入守卫（`signal_depth`）与 restorer 地址（`trampoline`）。派发/投递/恢复
/// 均在调度 per-pid 锁（含其下 per-CPU RUN[my] 当前槽；无全局进程池锁）内串行访问（§2.9，S21）。
///
/// `signal_depth` 记录当前压栈的 handler 层数（嵌套深度），用于 ADR-034 §6.1
/// 的嵌套上限守卫（S04 防资源耗尽）：进入 handler 递增、sigreturn 递减；
/// `in_signal()` = `signal_depth > 0`。
#[derive(Clone)]
pub struct SignalState {
    handlers: [SigDisposition; NSIG as usize],
    blocked: SignalSet,
    pending: SignalSet,
    signal_depth: u32,
    /// 「有一次异步投递打断了系统调用」（ADR-051）：投递点置位、阻塞前取用。
    /// 不能只看 pending——投递（尤其调度 tick 那条）会消费 pending 位。
    interrupted: bool,
    trampoline: u64,
}

impl SignalState {
    /// 新建：全部信号 Default 处置、空屏蔽/未决、未在 handler 中、无 trampoline。
    pub fn new() -> Self {
        SignalState {
            handlers: [SigDisposition::Default; NSIG as usize],
            blocked: SignalSet::empty(),
            pending: SignalSet::empty(),
            signal_depth: 0,
        interrupted: false,
            trampoline: 0,
        }
    }

    /// 查某信号的处置。
    pub fn disposition(&self, sig: u32) -> Option<SigDisposition> {
        if sig >= NSIG {
            return None;
        }
        Some(self.handlers[sig as usize])
    }

    /// 设置某信号处置（含越界/硬信号校验，ADR-034 §2.2/§2.6）。返回旧处置。
    pub fn set_disposition(
        &mut self,
        sig: u32,
        disp: SigDisposition,
    ) -> Result<Option<SigDisposition>, klib::error::Error> {
        validate_disposition(sig, disp)?;
        let old = self.handlers[sig as usize];
        self.handlers[sig as usize] = disp;
        Ok(Some(old))
    }

    /// 当前屏蔽集。
    pub fn blocked(&self) -> SignalSet {
        self.blocked
    }

    /// 当前未决集。
    pub fn pending(&self) -> SignalSet {
        self.pending
    }

    /// 是否正在 handler 中（重入守卫；嵌套深度 > 0）。
    pub fn in_signal(&self) -> bool {
        self.signal_depth > 0
    }

    /// 当前 handler 嵌套深度（ADR-034 §6.1 上限守卫用）。
    pub fn nesting_depth(&self) -> u32 {
        self.signal_depth
    }

    /// 进入一个 handler：若已达嵌套上限则拒绝（返回 false），否则递增并返回 true。
    pub fn enter_handler(&mut self) -> bool {
        if self.signal_depth >= MAX_SIGNAL_NESTING {
            return false;
        }
        self.signal_depth += 1;
        true
    }

    /// 退出一个 handler（sigreturn 时调用）：递减（下限 0）。
    pub fn exit_handler(&mut self) {
        self.signal_depth = self.signal_depth.saturating_sub(1);
    }

    /// restorer 地址（exec 时安装）。
    pub fn trampoline(&self) -> u64 {
        self.trampoline
    }

    /// 设置 restorer 地址。
    pub fn set_trampoline(&mut self, addr: u64) {
        self.trampoline = addr;
    }

    /// sigprocmask：按 `how`（0=SET,1=BLOCK,2=UNBLOCK）更新屏蔽集，
    /// 返回**旧**屏蔽集。`SIGKILL` 恒不可屏蔽（ADR-034 §3.2）：无论 SET/BLOCK
    /// 如何请求，屏蔽集恒清除 SIGKILL 位，保证其始终可投递（S3 统一硬信号语义）。
    pub fn mask(&mut self, how: u32, set: SignalSet) -> Result<SignalSet, klib::error::Error> {
        use crate::signals::SIGSTOP;
        let old = self.blocked;
        let new = match how {
            // SET：blocked = set
            0 => set,
            // BLOCK：blocked |= set
            1 => self.blocked.union(set),
            // UNBLOCK：blocked &= !set
            2 => {
                let mut b = self.blocked;
                b.difference(set);
                b
            }
            _ => return Err(klib::error::Error::InvalidParam),
        };
        // SIGKILL 不可屏蔽：强制清其位（始终允许投递）。`remove` 现已为纯
        // bitmask 操作（S3 整改），直接清除 SIGKILL 位即可。
        let mut b = new;
        b.remove(SIGKILL);
        // SIGSTOP 首期 NotSupported（ADR-034 §4.4）：屏蔽位不强制，由 kill
        // 路径诚实拒绝停止语义（不伪造 stopped 状态机）。
        let _ = SIGSTOP;
        self.blocked = b;
        Ok(old)
    }

    /// 投递一个信号到未决集（`raise`/外部 `kill` 复用）。
    ///
    /// - `SIGKILL`：不可屏蔽、优先级最高——即使 blocked 也置入未决（由派发层
    ///   强制处理终止，ADR-034 §2.6）；
    /// - 其余信号：加入未决集。
    pub fn raise(&mut self, sig: u32) {
        // 注意：此处**不**置 interrupted 标记——
        // 标记表达的是「投递真的打断了某次阻塞」，由投递点（deliver_on_return）置位。
        if sig >= NSIG {
            return;
        }
        self.pending.insert(sig);
        if sig == SIGKILL {
            // SIGKILL 即使屏蔽也投递：清其屏蔽位保证派发层可见（§2.6）。
            self.blocked.remove(SIGKILL);
        }
    }

    /// 取下一个**未屏蔽**的待投递信号（最低号优先，ADR-034 §2.4）。
    ///
    /// SIGKILL 特殊：即使 blocked 也返回（§2.6 最高优先级）。返回后从 pending 清除。
    pub fn take_unblocked(&mut self) -> Option<u32> {
        // SIGKILL 最高优先级：即使屏蔽也投递。
        if self.pending.contains(SIGKILL) {
            self.pending.remove(SIGKILL);
            return Some(SIGKILL);
        }
        let unblocked = self.pending.intersection(self.blocked.complement());
        match unblocked.lowest_pending() {
            Some(sig) => {
                self.pending.remove(sig);
                Some(sig)
            }
            None => None,
        }
    }

    /// 记录"本进程有一次异步信号投递打断了系统调用"（ADR-051）。
    ///
    /// 为什么需要它：投递可能发生在**调度 tick**（三处触发点之一），此时 pending 位已
    /// 被消费、handler 已进——等到阻塞循环重入 `try_block` 时，光看 pending 会**看不到**
    /// 打断发生过，于是又睡回去（实测症状：父进程 read 永不返回）。故投递时置位、阻塞前取用。
    pub fn mark_interrupted(&mut self) {
        self.interrupted = true;
    }

    /// 取用并清除"被打断"标记（阻塞前预检）。
    pub fn take_interrupted(&mut self) -> bool {
        let v = self.interrupted;
        self.interrupted = false;
        v
    }

    /// 是否有**会被投递给用户 handler** 的待决信号（ADR-051 EINTR 判据，**不消费**）。
    ///
    /// 与 [`Self::take_unblocked`] 的区别：本查询只读，不摘除任何位——供阻塞前预检。
    /// 只认 `Handler(f)`（f != 0）：`Ignore` 不打断阻塞（POSIX），`Default` 的终止/停止
    /// 动作由返回路径的 [`deliver_on_return`] 处置（届时进程已被处置，EINTR 无意义）。
    pub fn has_handler_pending(&self) -> bool {
        let unblocked = self.pending.intersection(self.blocked.complement());
        let mut bits = unblocked.bits();
        while bits != 0 {
            let sig = bits.trailing_zeros();
            bits &= bits - 1;
            if matches!(self.disposition(sig), Some(SigDisposition::Handler(f)) if f != 0) {
                return true;
            }
        }
        false
    }

    /// 设置/清除"正在 handler 中"守卫（兼容 setter：true→深度 1，false→0）。
    /// 生产路径用 [`Self::enter_handler`]/[`Self::exit_handler`] 维护真实深度。
    pub fn set_in_signal(&mut self, v: bool) {
        self.signal_depth = if v { 1 } else { 0 };
    }
}

// ---------- 投递：信号帧 + restorer + sigreturn（ADR-034 §2.5/§2.6） ----------

/// SignalFrame 帧魔法数（sigreturn 帧校验，S09/S29）。
pub const SIGNAL_FRAME_MAGIC: u64 = 0x5349_474e_414c_5f46; // "SIGNAL_F"

/// siginfo：投递给 handler 的信号细节（ADR-034 §2.8）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SigInfo {
    /// 信号号。
    pub sig: u32,
    /// 触发异常的 CPU 向量（非异常信号填 0）。
    pub vector: u32,
    /// 异常错误码（非异常填 0）。
    pub error_code: u64,
    /// #PF 出错线性地址（CR2；非 #PF 填 0）。
    pub fault_addr: u64,
    /// 投递方 pid。
    pub pid: u64,
}

/// 用户栈上压入的信号帧（ADR-034 §2.5）。
///
/// `repr(C)` 字段按低→高地址排列。投递时把整帧写到用户栈顶之下，新 rsp 指向
/// `restorer_return`（handler 的返回地址）；handler 正常 `ret` 弹该值跳到
/// restorer，restorer 调 `rt_sigreturn`（此时 syscall 帧内 rsp 恰指向 `magic`）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalFrame {
    /// 指向 restorer（handler 的返回地址）。
    pub restorer_return: u64,
    /// 帧魔法数（sigreturn 校验）。
    pub magic: u64,
    /// siginfo（handler 的 rsi 指向此处）。
    pub siginfo: SigInfo,
    /// 被打断的完整现场（sigreturn 恢复用）。
    pub saved: InterruptFrame,
}

impl SignalFrame {
    /// 该帧占用的用户栈字节数（8 字节对齐）。
    pub const fn size() -> usize {
        core::mem::size_of::<SignalFrame>()
    }
}

/// 同步异常信号投递的默认嵌套深度上限（ADR-034 §6.1；S04 防资源耗尽）。
pub const MAX_SIGNAL_NESTING: u32 = 32;

/// 校验用户地址区 `[addr, addr+len)` 全部为"已映射 + user + 可写"页
/// （投递写帧前预校验，防内核态 #PF 停机，S09/S29）。经进程地址空间逐页查询。
fn user_range_writable<PT: arch::PageTable>(
    addr: u64,
    len: u64,
    aspace: &mm::user_space::UserAddressSpace<PT>,
) -> bool {
    if len == 0 {
        return false;
    }
    if addr < mm::user_space::USER_BASE
        || addr.checked_add(len).map_or(true, |e| e > mm::user_space::USER_TOP)
    {
        return false;
    }
    let mut a = addr;
    let end = addr + len;
    while a < end {
        match aspace.query_page(a) {
            Some(q) if q.user && q.writable => {}
            _ => return false,
        }
        a = a.saturating_add(4096);
    }
    true
}

/// 投递结果：通知调用方当前进程是否已被默认动作终止（切换由调度接管）。
pub enum DeliveryOutcome {
    /// 未终止（投递了 handler 或无事发生），照常 iretq 回用户态。
    Continue,
    /// 进程已被默认动作终止（`exit_current` 已切走），调用方不得再 iretq 回原帧。
    Terminated,
}

/// 投递一个 `Handler(f)` 信号：压 SignalFrame 并改写帧（ADR-034 §2.5）。
///
/// - `handler`：目标函数指针；`sig`/siginfo 由调用方预填。
/// - 若用户栈写帧失败（越界/不可写）→ 返回 `false`，调用方应终止（无法安全投递）。
///
/// 公开：异常→信号路径（S1-11）需要注入带 CR2/vector/error_code 的 siginfo，
/// 而非走通用 `deliver_on_return` 的默认 siginfo。
pub fn deliver_handler<PT: arch::PageTable>(
    proc: &mut Process<PT>,
    frame: &mut InterruptFrame,
    sig: u32,
    handler: u64,
    siginfo: SigInfo,
    restorer: u64,
) -> bool {
    // 计算新栈顶：当前 rsp 之下压整帧，8 字节对齐。
    let frame_bytes = SignalFrame::size() as u64;
    let new_rsp = frame.rsp - frame_bytes;
    let sframe = SignalFrame {
        restorer_return: restorer,
        magic: SIGNAL_FRAME_MAGIC,
        siginfo,
        saved: *frame,
    };
    // 预校验目标栈区可写（防 #PF 停机）。
    if !user_range_writable(new_rsp, frame_bytes, proc.addr_space()) {
        return false;
    }
    // 把帧写到用户栈（当前进程地址空间已激活）。
    unsafe {
        arch_x86_64::mmio::copy_to_user(new_rsp, (&sframe as *const SignalFrame) as *const u8, frame_bytes as usize);
    }
    // ADR-034 §6.1 嵌套深度上限：已达上限则拒绝投递（返回 false）。
    // 调用方（deliver_on_return 预检 / 异常路径）据此决定：异步信号挂回 pending
    // 等栈展开；同步异常无法延迟则终止（防异常风暴，S30）。
    if !proc.signal_mut().enter_handler() {
        return false;
    }
    // 改写帧：进 handler。
    frame.rip = handler;
    frame.rsp = new_rsp;
    frame.rdi = sig as u64;
    frame.rsi = new_rsp + core::mem::offset_of!(SignalFrame, siginfo) as u64;
    frame.rdx = 0; // ucontext 未实现（ADR-034 §4.3），诚实留 0。
    // 清 TF 防单步进 handler（ADR-034 §2.5）。
    frame.rflags &= !0x100;
    true
}
/// 派发：返回用户态前检查并投递当前进程的可投递信号（ADR-034 §2.4，心脏）。
///
/// 由三处触发点（syscall 返回 / 调度 tick / 异常返回）在**未持调度域锁**时调用
/// （因默认动作 Terminate 经 [`crate::scheduler::exit_current`] 会内部加锁）。
/// 循环直到无可投递信号：
/// - `Ignore` → 跳过；
/// - `Default` → 查默认动作：Ignore 跳过、Terminate 终止、Stop/Cont 首期跳过（NotSupported）；
/// - `Handler(f)` → 压 SignalFrame 进 handler（需 restorer 已安装，见 PRE-3/S1-7）。
///
/// 返回 [`DeliveryOutcome`] 告知调用方进程是否已被终止。
pub fn deliver_on_return<PT: arch::PageTable>(
    proc: &mut Process<PT>,
    frame: &mut InterruptFrame,
) -> DeliveryOutcome {
    use crate::signals::SIGSTOP;
    loop {
        let sig = match proc.signal_mut().take_unblocked() {
            Some(s) => s,
            None => return DeliveryOutcome::Continue,
        };
        match proc.signal().disposition(sig) {
            Some(SigDisposition::Ignore) => {
                // 忽略：继续下一个。同步异常的 Ignore 防风暴由异常路径（S1-11）
                // 特判等价 Default 终止，不在此处理。
                continue;
            }
            Some(SigDisposition::Default) => match default_disposition(sig) {
                DefaultAction::Ignore => continue,
                DefaultAction::Terminate => {
                    crate::scheduler::exit_current(frame, sig as u64);
                    return DeliveryOutcome::Terminated;
                }
                DefaultAction::Stop | DefaultAction::Cont => {
                    // SIGSTOP/SIGCONT 首期以 NotSupported 诚实拒绝（ADR-034 §4.4），
                    // 不伪造停止语义：跳过。位不变量保留（见 SignalState::mask）。
                    let _ = SIGSTOP;
                    continue;
                }
            },
            Some(SigDisposition::Handler(f)) => {
                // SIGKILL/SIGSTOP 处置恒 Default（validate_disposition 保证），不会到 Handler。
                // ADR-034 §6.1：已达嵌套深度上限则不投递——重新挂回 pending，返回用户态
                //（仍在 handler 中），等栈经 sigreturn 展开后再投递（S04 防栈耗尽）。
                if proc.signal().nesting_depth() >= MAX_SIGNAL_NESTING {
                    proc.signal_mut().raise(sig);
                    return DeliveryOutcome::Continue;
                }
                let restorer = proc.signal().trampoline();
                if restorer == 0 {
                    // 无 restorer（PRE-3/S1-7 未装）：无法安全进 handler，兜底终止。
                    crate::scheduler::exit_current(frame, sig as u64);
                    return DeliveryOutcome::Terminated;
                }
                let siginfo = SigInfo {
                    sig,
                    vector: 0,
                    error_code: 0,
                    fault_addr: 0,
                    pid: proc.pid() as u64,
                };
                if !deliver_handler(proc, frame, sig, f, siginfo, restorer) {
                    // 用户栈写帧失败（越界/不可写）：无法安全投递，终止兜底。
                    crate::scheduler::exit_current(frame, sig as u64);
                    return DeliveryOutcome::Terminated;
                }
                // ADR-051：若投递发生在进程**阻塞**期间（调度 tick 那条触发点），本次投递
                // 打断的正是它的阻塞 syscall——置位供阻塞前预检取用（pending 位已被本次
                // 投递消费，光看 pending 会看不到打断发生过）。若进程正在运行（syscall 返回
                // 点那条），系统调用已结束，不置位——否则会误伤下一次阻塞调用。
                if proc.state() == crate::TaskState::Blocked {
                    proc.signal_mut().mark_interrupted();
                }
                return DeliveryOutcome::Continue;
            }
            None => continue, // 越界信号号（take_unblocked 已保证 < NSIG，防御）。
        }
    }
}

/// `rt_sigreturn`：handler 返回后从用户栈读回 SignalFrame 恢复现场（ADR-034 §2.5）。
///
/// 帧内 `rsp` 指向 `SignalFrame.magic`（handler `ret` 弹 `restorer_return` 后）。
/// 校验魔法数与地址范围（防伪造/越界，S09/S29），随后把 `saved` 整体写回当前
/// 帧，清 `in_signal` 守卫。恢复后调用方照常 iretq 回被打断的 RIP。
pub fn sigreturn<PT: arch::PageTable>(
    proc: Option<&mut Process<PT>>,
    frame: &mut InterruptFrame,
) -> Result<(), klib::error::Error> {
    use klib::error::Error;
    // rsp 指向 magic 字段；整帧基址 = rsp - magic 偏移。
    let base = frame
        .rsp
        .checked_sub(core::mem::offset_of!(SignalFrame, magic) as u64)
        .ok_or(Error::InvalidParam)?;
    let frame_bytes = SignalFrame::size() as u64;
    // 校验整帧在读范围（用户可读），防越界/未映射读。
    {
        let aspace = match proc.as_ref() {
            Some(p) => p.addr_space(),
            None => return Err(Error::NotSupported),
        };
        if !user_range_readable(base, frame_bytes, aspace) {
            return Err(Error::InvalidParam);
        }
    }
    // 读回整帧。
    let mut sframe = SignalFrame {
        restorer_return: 0,
        magic: 0,
        siginfo: SigInfo { sig: 0, vector: 0, error_code: 0, fault_addr: 0, pid: 0 },
        saved: *frame,
    };
    unsafe {
        arch_x86_64::mmio::copy_from_user(
            (&mut sframe as *mut SignalFrame) as *mut u8,
            base,
            frame_bytes as usize,
        );
    }
    // 魔法数校验（防伪造/错位）。
    if sframe.magic != SIGNAL_FRAME_MAGIC {
        return Err(Error::InvalidParam);
    }
    // 恢复现场。
    *frame = sframe.saved;
    if let Some(p) = proc {
        p.signal_mut().exit_handler();
    }
    Ok(())
}

/// 校验用户地址区 `[addr, addr+len)` 全部为"已映射 + user"页（可读）。
fn user_range_readable<PT: arch::PageTable>(
    addr: u64,
    len: u64,
    aspace: &mm::user_space::UserAddressSpace<PT>,
) -> bool {
    if len == 0 {
        return false;
    }
    if addr < mm::user_space::USER_BASE
        || addr.checked_add(len).map_or(true, |e| e > mm::user_space::USER_TOP)
    {
        return false;
    }
    let mut a = addr;
    let end = addr + len;
    while a < end {
        match aspace.query_page(a) {
            Some(q) if q.user => {}
            _ => return false,
        }
        a = a.saturating_add(4096);
    }
    true
}


