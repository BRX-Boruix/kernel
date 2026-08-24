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

    /// 词汇表翻译：task 的 `SwitchOutcome` → ipc 的 `BlockOutcome`。
    /// 两侧各自拥有语义枚举、由本适配层一次性映射——bool 可无视的旧形状
    /// 不再跨任何 crate 边界（KA6）。
    ///
    /// IA2a：`register` 闭包在 task 调度锁内执行（SCHED → IPC 表锁，单向），
    /// 把"登记等待者"与"置 Blocked"合并为对唤醒方原子的一步——经典
    /// lost-wakeup 窗口在协议层不存在。
    fn block_with_registration(
        &self,
        frame: &mut InterruptFrame,
        register: &mut dyn FnMut() -> bool,
    ) -> BlockOutcome {
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
