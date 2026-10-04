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

pub fn init_ipc() {
    ipc::set_ipc_notifier(&NOTIFIER);
    mm::user_space::set_shm_mapping_hooks(&SHM_HOOKS);
}
