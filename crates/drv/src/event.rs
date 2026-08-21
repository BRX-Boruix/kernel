//! 硬件拓扑事件总线（Hardware Topology Event Bus）。
//!
//! 提供无锁/原子环形队列的硬件插拔、状态变更与异常事件流订阅发布机制（M9.1）。

use crate::device::DeviceInfo;
use spin::Mutex;

/// 硬件拓扑事件类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    /// 硬件设备接入/上线（Hotplug In）
    DeviceArrived(DeviceInfo),
    /// 硬件设备拔除/下线（Hotplug Out）
    DeviceDeparted(DeviceInfo),
    /// 硬件运行态错误/异常告警
    DeviceError { dev: DeviceInfo, code: u32 },
    /// 硬件电源状态变更（D0 运行, D1/D2 待机, D3 关闭）
    PowerStateChanged { dev: DeviceInfo, new_state: u8 },
}

pub const EVENT_QUEUE_CAPACITY: usize = 64;

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
            // 队列满时覆盖最旧事件（推进 tail）
            self.tail = (self.tail + 1) % EVENT_QUEUE_CAPACITY;
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

pub type EventSubscriber = fn(&DeviceEvent);
pub const MAX_SUBSCRIBERS: usize = 8;
static SUBSCRIBERS: Mutex<[Option<EventSubscriber>; MAX_SUBSCRIBERS]> =
    Mutex::new([None; MAX_SUBSCRIBERS]);

/// 发布一个硬件拓扑事件。
pub fn publish_event(event: DeviceEvent) {
    EVENT_QUEUE.lock().push(event);

    // 同步分发给所有订阅者（如 DevFS 动态目录投影）
    let subs = SUBSCRIBERS.lock();
    for sub in subs.iter().flatten() {
        sub(&event);
    }
}

/// 消费/读取最旧的一个硬件事件。
pub fn pop_event() -> Option<DeviceEvent> {
    EVENT_QUEUE.lock().pop()
}

/// 返回当前未消费的事件数量。
pub fn pending_event_count() -> usize {
    EVENT_QUEUE.lock().len()
}

/// 注册硬件事件总线订阅者。
pub fn subscribe_events(subscriber: EventSubscriber) -> bool {
    let mut subs = SUBSCRIBERS.lock();
    for slot in subs.iter_mut() {
        if slot.is_none() {
            *slot = Some(subscriber);
            return true;
        }
    }
    false
}
