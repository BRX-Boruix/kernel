//! 进程间通信与调度器粘合注入。

use arch_x86_64::interrupts::InterruptFrame;

struct KernelIpcNotifier;

impl ipc::IpcTaskNotifier for KernelIpcNotifier {
    fn current_pid(&self) -> usize {
        task::current_proc_mut().map(|p| p.pid()).unwrap_or(0)
    }

    fn wake_process(&self, pid: usize) {
        task::wake(pid);
    }

    fn block_current_process(&self, frame: &mut InterruptFrame) -> bool {
        task::block_current(frame)
    }
}

static NOTIFIER: KernelIpcNotifier = KernelIpcNotifier;

pub fn init_ipc() {
    ipc::set_ipc_notifier(&NOTIFIER);
}
