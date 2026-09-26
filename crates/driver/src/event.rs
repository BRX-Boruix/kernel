//! 硬件拓扑事件环形日志（Hardware Topology Event Ring Log，M9.1 裁剪版）。
//!
//! ADR-022 §7 / ADR-030 §决策3：本模块是**单唤醒订阅者的环形拓扑日志**——
//! hub 的注册/拔除路径把真实拓扑事实写入定长环，消费方（用户态 `volumed`）
//! 经 [`pop_event`] 顺序排空。为避免"消费方空等轮询"，发布路径（[`publish_event`]）
//! 在入队后经 [`set_event_wake_callback`] 注册的回调（指向 `task::wake_event`）
//! 唤醒内核侧事件等待者（interrupt-to-futex）：设备注册/拔除中断直达用户态
//! 等待者，取代有界休眠轮询。原"订阅发布机制"因零订阅者被裁剪后，本回调即
//! 第一个真实订阅者形态（先成文锁序再编码）：`publish_event` 先入队再唤醒来
//! 唤醒（唤醒者复检队列必见事件），等待端在调度 per-pid 锁（+ per-CPU RUN[my]）
//! 内登记+复检消除 lost-wakeup。
//!
//! **单消费者前提**：本环是 FIFO，且 [`peek_event`]/[`pop_event`] 作为"先
//! 量测再消费"的一对操作**不是原子**（peek 与 pop 分别持锁、两次独立的临界
//! 区）。跨调用者并发下会出现 TOCTOU：进程 A peek 到 X、进程 B 也 peek 到 X，
//! 随后 A pop 拿 X、B pop 拿 Y——A 会把按 X 序列化的字节与"消费 Y"错配。当前
//! 唯一消费者是用户态 `volumed`（单进程单线程，顺序排空），故该错配不可达。
//! 若将来引入第二个并发消费者，须把"peek 量测 + pop 消费"纳入同一个
//! `Mutex` 临界区（或提供带回调的原子取件），先成文锁序再编码。

use crate::device::DeviceInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// 硬件拓扑事件类型（ADR-022 §7：只保留有真实发布点的变体）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    /// 硬件设备接入/上线（Hotplug In）。发布点：`DriverHub::register_device_info`。
    DeviceArrived(DeviceInfo),
    /// 硬件设备拔除/下线（Hotplug Out）。发布点：`DriverHub::unregister_device_by_name`。
    DeviceDeparted(DeviceInfo),
}

/// 事件环形队列容量（S13 理由成文）。
///
/// 取 64：它 ≥ 启动期可能集中发布的拓扑事件积压（内核 boot 阶段注册的所有
/// 设备 arrived 事件数量级为 O(10)，见 DriverHub 注册路径），足以承接启动
/// 积压不淘汰最旧；同时很小，环缓冲整体为一个 64×Option<DeviceEvent> 数组，
/// 栈/静态占用量可忽略。事件是 fire-and-forget 日志语义，超容量时淘汰最旧并
/// 经 [`dropped_event_count`] 留下可观测账目（AM4 纪律），故容量不追求"永不
/// 满"——真实热插拔高频源接入时按实测扩容量并保持丢弃账目即可。
pub const EVENT_QUEUE_CAPACITY: usize = 64;

/// 因队列满而被淘汰的最旧事件累计数（单调递增）。
///
/// 拓扑事件静默蒸发不可接受（AM4 同款纪律）：满队列覆盖最旧条目时必须
/// 在此留下计数痕迹，诊断方据此知道观测窗口发生过截断。
static DROPPED_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// 全局事件环形缓冲区。
struct EventRingBuffer {
    events: [Option<DeviceEvent>; EVENT_QUEUE_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}

impl EventRingBuffer {
    const fn new() -> Self {
        Self {
            events: [None; EVENT_QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: DeviceEvent) {
        if self.count >= EVENT_QUEUE_CAPACITY {
            // 队列满：淘汰最旧事件并计入丢弃账目（ADR-022 §7）。
            self.events[self.tail].take();
            self.tail = (self.tail + 1) % EVENT_QUEUE_CAPACITY;
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
        } else {
            self.count += 1;
        }
        self.events[self.head] = Some(event);
        self.head = (self.head + 1) % EVENT_QUEUE_CAPACITY;
    }

    fn pop(&mut self) -> Option<DeviceEvent> {
        if self.count == 0 {
            return None;
        }
        let ev = self.events[self.tail].take();
        self.tail = (self.tail + 1) % EVENT_QUEUE_CAPACITY;
        self.count -= 1;
        ev
    }

    fn len(&self) -> usize {
        self.count
    }
}

static EVENT_QUEUE: Mutex<EventRingBuffer> = Mutex::new(EventRingBuffer::new());

/// 事件唤醒回调（interrupt-to-futex）：`publish_event` 发布新事件后，若有阻塞
/// 等待事件投递的进程（`task::block_for_event` 挂起的 volumed），调用此回调把
/// 其唤醒。kernel 经 [`set_event_wake_callback`] 注入（指向 `task::wake_event`）。
///
/// 用函数指针而非直接依赖 task crate：driver 不反向依赖 task（与键盘
/// 同 arch 键盘驱动的函数指针解耦手法；原 `set_input_callback(task::wake_kbd)`
/// 已随 I-EVENTS P5 退役，本回调是同款解耦的现役形态）。直接以 `Mutex<Option<fn()>>`
/// 承载 `fn()` 本身（函数指针是 `Copy + Send + Sync`），**不做任何函数指针↔数据
/// 指针/整数的 transmute 或强转**（S04/S21：不依赖平台指针宽巧合）。初始化后在
/// 启动早期设置一次，此后每次发布只读。持锁时间极短（仅拷贝一个 fn 指针）。
static EVENT_WAKE_CB: Mutex<Option<fn()>> = Mutex::new(None);

/// 注册事件唤醒回调（kernel 启动期调用一次，指向 `task::wake_event`）。
/// 回调签名 `fn()`（plain Rust fn，同步调用，无需 C ABI）。
pub fn set_event_wake_callback(cb: fn()) {
    *EVENT_WAKE_CB.lock() = Some(cb);
}

/// 发布一个硬件拓扑事件（fire-and-forget 日志语义）。
///
/// 队列满时淘汰最旧事件，淘汰量经 [`dropped_event_count`] 可观测；本函数不
/// 阻塞、不分发回调、不持有跨模块锁。事件入队后唤醒阻塞等待事件投递的进程
/// （若有登记），使"设备注册/拔除中断"直达用户态等待者（interrupt-to-futex，
/// ADR-030 §决策3 事件驱动取代轮询）。
pub fn publish_event(event: DeviceEvent) {
    EVENT_QUEUE.lock().push(event);
    // 唤醒等待者：入队后才唤醒，保证等待者复检队列时必见事件（lost-wakeup
    // 由 block_for_event 的锁内复检 + 本处"先入队后唤醒"共同闭合）。
    // 先拷贝 fn 指针再释放锁再调用回调——回调执行期间不持 EVENT_WAKE_CB 锁
    // （避免回调路径意外重入本锁造成自旋死锁）。
    // `*EVENT_WAKE_CB.lock()` 复制 `Option<fn()>`（Copy）后，临时 guard 在语句
    // 末尾释放，故 cb() 执行时锁已释放。
    let cb = *EVENT_WAKE_CB.lock();
    if let Some(cb) = cb {
        cb();
    }
}

/// 消费/读取最旧的一个硬件拓扑事件。
pub fn pop_event() -> Option<DeviceEvent> {
    EVENT_QUEUE.lock().pop()
}

/// 窥视最旧的一个硬件拓扑事件（**不消费**），返回其**按值拷贝**。
///
/// `DeviceEvent` 为 `Copy`（`DeviceInfo` 全原始字段 + `&'static str`），返回
/// 独立拷贝不持有环内引用，完全无野指针/借用面——消费方先据拷贝量测/序列化，
/// 再决定是否 `pop_event`，避免"先消费再因缓冲不足而丢弃"的事件丢失面
/// （`sys_driver_event_next` 的 S18 健壮性：cap 不足时不丢事件，重试可再取）。
/// 锁仅在拷贝期间持有，返回即释放。
pub fn peek_event() -> Option<DeviceEvent> {
    let q = EVENT_QUEUE.lock();
    if q.count == 0 {
        return None;
    }
    // DeviceEvent: Copy —— `q.events[q.tail]` 为 `Option<DeviceEvent>`，整体拷贝即出。
    q.events[q.tail]
}

/// 返回当前未消费的事件数量。
pub fn pending_event_count() -> usize {
    EVENT_QUEUE.lock().len()
}

/// 返回至今因队列满被淘汰的事件总数（单调递增）。
pub fn dropped_event_count() -> usize {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}
