//! 进程间通信与调度器粘合注入。

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

    /// 词汇表翻译：task 的 `SwitchOutcome` → ipc 的 `BlockOutcome`。
    /// 两侧各自拥有语义枚举、由本适配层一次性映射——bool 可无视的旧形状
    /// 不再跨任何 crate 边界（KA6）。
    fn block_current_process(&self, frame: &mut InterruptFrame) -> BlockOutcome {
        match task::block_current(frame) {
            task::SwitchOutcome::Switched => BlockOutcome::Switched,
            task::SwitchOutcome::NotSwitched => BlockOutcome::Refused,
        }
    }
}

static NOTIFIER: KernelIpcNotifier = KernelIpcNotifier;

pub fn init_ipc() {
    ipc::set_ipc_notifier(&NOTIFIER);
}
