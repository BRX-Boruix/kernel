//! 硬件拓扑事件环形日志（Hardware Topology Event Ring Log，M9.1 裁剪版）。
//!
//! ADR-022 §7：本模块是**无订阅者的环形拓扑日志**——hub 的注册/拔除路径把
//! 真实拓扑事实写入定长环，消费方经 [`pop_event`] 顺序排空。原"订阅发布
//! 机制"（`subscribe_events` + publish 持锁同步分发）因全项目零订阅者、
//! `DeviceError`/`PowerStateChanged` 变体零发布点、且持 `SpinMutex` 分发
//! 回调存在重入自旋死锁面而被整体裁剪；出现第一个真实订阅者时按新设计
//! 重建（先成文锁序再编码），不在返工轮伪造中间态。

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

/// 发布一个硬件拓扑事件（fire-and-forget 日志语义）。
///
/// 队列满时淘汰最旧事件，淘汰量经 [`dropped_event_count`] 可观测；
/// 本函数不阻塞、不分发回调、不持有跨模块锁。
pub fn publish_event(event: DeviceEvent) {
    EVENT_QUEUE.lock().push(event);
}

/// 消费/读取最旧的一个硬件拓扑事件。
pub fn pop_event() -> Option<DeviceEvent> {
    EVENT_QUEUE.lock().pop()
}

/// 返回当前未消费的事件数量。
pub fn pending_event_count() -> usize {
    EVENT_QUEUE.lock().len()
}

/// 返回至今因队列满被淘汰的事件总数（单调递增）。
pub fn dropped_event_count() -> usize {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}
