//! 进程间通信与调度器 / 所有权钩子的粘合注入。

use arch_x86_64::interrupts::InterruptFrame;
use ipc::BlockOutcome;

struct KernelIpcNotifier;

impl ipc::IpcTaskNotifier for KernelIpcNotifier {
    fn current_pid(&self) -> usize {
        task::current_proc_mut().map(|p| p.pid()).unwrap_or(0)
    }

    fn wake_process(&self, pid: usize) {
        task::wake(pid);
    }

    fn wake_process_with_value(&self, pid: usize, value: u64) {
        task::wake_with_value(pid, value);
    }

    /// 词汇表翻译：task 的 `SwitchOutcome` → ipc 的 `BlockOutcome`。
    /// 两侧各自拥有语义枚举、由本适配层一次性映射——bool 可无视的旧形状
    /// 不再跨任何 crate 边界（KA6）。
    ///
    /// IA2a：`register` 闭包在 task 调度域锁内执行（per-pid 调度锁 → IPC 表锁，单向，无全局池锁），
    /// 把"登记等待者"与"置 Blocked"合并为对唤醒方原子的一步——经典
    /// lost-wakeup 窗口在协议层不存在。
    fn block_with_registration(
        &self,
        frame: &mut InterruptFrame,
        register: &mut dyn FnMut() -> bool,
    ) -> BlockOutcome {
        // ADR-051：阻塞**前**预检可投递的 handler 信号——命中即不入册、不阻塞，
        // 由调用方以 EINTR 收场（信号本身照常在 syscall 返回点投递给用户 handler）。
        // 预检与阻塞之间若恰好到达信号，投递路径会 wake 本进程，阻塞循环重入本函数
        // 时再次命中——该窗口由循环重入闭合，无需在调度锁内联查。
        // ADR-052：**被唤醒的阻塞 syscall 的返回值**。
        //
        // 本系统的"阻塞"由帧交换实现（commit_same_lock 做 *frame = next.saved 后 iretq），
        // **没有内核上下文切换**——因此被唤醒的 syscall **不会继续执行**，它回到用户态时
        // 用的是进入阻塞时保存的帧。若不做处理，rax 仍是进入时的 **syscall 调用号**，
        // 用户会拿到一个纯属伪造的成功值（实测：阻塞 read 返回 18 = 0x12 = SYS_STREAM_READ）。
        //
        // 诚实语义：本次调用**没有**完成阻塞等待，如实返回 WouldBlock（EAGAIN，"请重试"）。
        // 调用方重试时会重新进入本函数：若此时信号已待决，预检直接给出 Interrupted（EINTR），
        // 从而让"被信号打断"与"被事件唤醒"两条路都收敛到正确结果。
        //
        // 这里在**保存帧之前**写 rax：task 侧 slot.saved = *frame 会原样捕获该值。
        frame.rax = crate::syscall::pack_err(klib::error::Error::WouldBlock);
        if let Some(cur) = task::current_proc_mut() {
            // 两个来源都要看：pending（信号刚到、还没投递）与 interrupted（投递已经
            // 发生并消费了 pending 位——典型是调度 tick 那条触发点）。
            let pending = cur.signal().has_handler_pending();
            let interrupted = cur.signal_mut().take_interrupted();
            if pending || interrupted {
                return BlockOutcome::Interrupted;
            }
        }
        match task::block_current_with(frame, register) {
            task::SwitchOutcome::Switched => BlockOutcome::Switched,
            task::SwitchOutcome::NotSwitched => BlockOutcome::Refused,
        }
    }
}

static NOTIFIER: KernelIpcNotifier = KernelIpcNotifier;

/// shm 映射所有权钩子适配（ipc1 IA1 / ADR-019）：mm 的 fork/destroy 事件
/// 翻译为 ipc 对象表的 refs 增减。mm 不反向依赖 ipc——依赖方向经本层保持
/// mm ← kernel → ipc 单向。
struct ShmOwnershipHooks;

impl mm::user_space::ShmMappingHooks for ShmOwnershipHooks {
    fn on_mappings_acquired(&self, ids: &[u64]) {
        ipc::shm_on_mappings_acquired(ids);
    }

    fn on_mappings_released(&self, ids: &[u64]) {
        ipc::shm_on_mappings_released(ids);
    }
}

static SHM_HOOKS: ShmOwnershipHooks = ShmOwnershipHooks;

/// fd 句柄释放适配（3P4-3b）：进程退出 drain fd 表时，把管道端引用归还 ipc 层。
/// vfs 定义钩子点、本层装配——依赖方向 vfs ← kernel → ipc 保持单向（同 SHM_HOOKS 手法）。
struct FdReleaseAdapter;

impl vfs::file_handle::FdReleaseHooks for FdReleaseAdapter {
    fn on_handle_released(&self, handle: &vfs::file_handle::OpenHandle) {
        // 只有管道端需要归还引用；文件句柄的 inode 由 Arc 自然回收。
        if let vfs::file_handle::OpenHandle::Pipe { id, writer, .. } = handle {
            // 归零即销毁管道对象——退出路径无需据此决策，故忽略返回值。
            let _ = ipc::pipe_ref_dec(*id, *writer);
        }
    }
}

static FD_HOOKS: FdReleaseAdapter = FdReleaseAdapter;

pub fn init_ipc() {
    ipc::set_ipc_notifier(&NOTIFIER);
    mm::user_space::set_shm_mapping_hooks(&SHM_HOOKS);
    vfs::file_handle::set_fd_release_hooks(&FD_HOOKS);
}
