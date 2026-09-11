//! 音频哑管道（plan_audio_vfs.md 批次一 A1）。
//!
//! ## 设计定位
//!
//! 内核**不懂音频**。本模块只搬字节，不认识采样率、格式、声道的物理含义——
//! 那些是用户态驱动的事（intel-hda）。`/devices/audio/dsp` 是一条
//! **单向 PCM 管道**：写者写入，音频驱动取走。
//!
//! ## 诚实性红线（S06/S07/S09）
//!
//! **没有消费者附加时，写入必须失败可见（`NotSupported`），绝不接受后丢弃。**
//! "接受数据然后扔掉"会让写者以为播放成功，是最典型的伪链路。
//!
//! ## 并发模型（S21）
//!
//! 单生产者单消费者：生产者是写者进程，消费者是音频驱动进程。
//! 两端各只写自己的指针、只读对方的指针，故无锁、无自旋、无死锁风险。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Once;
use klib::error::Error;
use klib::json::{JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{DirEntry, FileMetadata, INode, INodeType, Permissions};

/// PCM ring 缓冲容量（字节）。
///
/// **S17 默认值理由**：48kHz/2ch/16bit = 192000 B/s，64 KiB 约合 341 ms。
/// 下限约束：必须显著大于一次典型 write 的块大小，否则写者每轮都要阻塞；
/// 上限约束：过大则"写完到出声"的延迟不可接受。341 ms 是两者的工程折中。
pub const AUDIO_RING_CAPACITY: usize = 64 * 1024;

/// 支持的采样格式（S13：业务语义常量集中定义，避免散落漂移）。
pub const AUDIO_FORMAT_S16LE: &str = "s16le";
/// 支持的声道数文本。
pub const AUDIO_CHANNELS_STEREO: &str = "2";
/// 支持的采样率文本（Hz）。
pub const AUDIO_RATE_48000: &str = "48000";

/// 消费者注册槽的空值哨兵（无消费者）。
///
/// **S19 论证**：pid 是进程槽表下标，容量远小于 2^32，恒可无损装入 u32；
/// `u32::MAX` 与任何合法 pid 不相交（同 `KBD_WAITER`/`EVENT_WAITER` 的哨兵
/// 约定，`scheduler.rs:1284`/`:1439`）。
pub const NO_CONSUMER: u32 = u32::MAX;

/// 经 `INode::as_audio_ring` 取回节点的音频 ring（非音频节点返回 `None`）。
///
/// **S15 单点定义**：`INode::as_audio_ring` 是"这个节点有没有音频 ring"的
/// **唯一**判定处。syscall 层不比对路径字符串、也不臆测"字符设备即音频"——
/// 那两种做法都会在接入第二个字符设备时静默错认节点（把别人的 ring 当音频）。
///
/// **为何不用 `Arc::downcast`**：那要求 `INode: Any`，会给一个被十余种节点
/// 实现的 trait 增加全局约束（牵动 ramfs/procfs/sysfs/stdio 等无关类型）。
/// 显式访问器保持 trait object-safe，且把"暴露音频 ring"变成**被声明的能力**
/// 而非运行时类型试探——后者在类型不匹配时只能返回 None，无法区分"不是音频
/// 节点"与"是音频节点但暂不可用"。
pub fn as_audio_node(node: &Arc<dyn INode>) -> Option<Arc<AudioRing>> {
    node.as_audio_ring()
}


/// 全局音频 ring 登记槽（`Once`：系统只有一个音频节点）。
///
/// **S15 单点定义 + S18 可达性**：进程退出清理路径（调度器）必须能**不依赖**
/// 挂载表就找到音频 ring——挂载表在 kernel crate，而调度器不应反向依赖它。
/// 故由音频节点在构造时把自己登记于此，退出路径直接读该槽。
///
/// **为何不用挂载表查找**：退出路径上做路径解析会引入一个"解析失败怎么办"
/// 的失败分支——而清理**必须**成功（否则死进程永久独占节点）。无失败分支的
/// 设计在这里是正确性优势，不是简化。
static AUDIO_RING_SLOT: Once<Arc<AudioRing>> = Once::new();

/// 进程退出时的音频资源回收入口（S18）。
///
/// 由调度器在进程回收路径调用（与 `flock_release_all_for_owner` 同点）。
/// 释放该 pid 占用的音频消费者槽——**必须**做，否则进程死亡后音频节点会被
/// 一个不存在的进程永久独占，所有后续驱动 attach 都得到 Busy，且现象沉默
/// （没有任何错误指向"死进程仍持有"），极难排查。
///
/// 幂等：可重复调用；对本进程未持有槽的情况是无操作。
pub fn audio_on_process_exit(pid: usize) {
    match AUDIO_RING_SLOT.get() {
        Some(ring) => ring.detach_any(pid),
        // 音频节点从未构造（未启用）：无可回收，正确且无副作用。
        None => {}
    }
}


/// 数据到达回调槽（`Once`：系统只有一个音频节点）。
///
/// **为何用回调而非直接调 `task::wake_audio`**：vfs 是 task 的**下游**
/// （task 依赖 vfs，见 task/Cargo.toml），vfs 反向调用 task 会形成循环依赖。
/// 回调把"什么时候唤醒"（vfs 知道：数据刚落进 ring）与"怎么唤醒"
/// （task 知道：置 Ready 入就绪队列）解耦——两侧各自掌握自己那份知识。
///
/// **未安装时的行为**：静默不唤醒。这不丢数据（数据已在 ring 里），只是读者
/// 要等自己的有限超时。内核启动时必然安装（vfs_init），故生产路径上恒有。
static AUDIO_WAKE_HOOK: Once<fn()> = Once::new();

/// 安装数据到达回调（由内核启动期调用一次）。
///
/// `call_once`：重复安装不覆盖（与 AUDIO_RING_SLOT 同规约）。
pub fn set_wake_hook(hook: fn()) {
    AUDIO_WAKE_HOOK.call_once(|| hook);
}

/// 通知"PCM 已到达"，唤醒可能正在等待的读者。
///
/// **必须在数据**真正进入 ring **之后**调用**——顺序颠倒会让被唤醒的读者
/// 复检时仍见空 ring，于是再次入睡（本次唤醒白费，且若写者不再写就永久挂起）。
fn notify_data_ready() {
    if let Some(hook) = AUDIO_WAKE_HOOK.get() {
        hook();
    }
}

/// 单生产者单消费者（SPSC）环形字节缓冲。
///
/// **S21 并发显式化**：
/// - 生产者 = 写者进程（VFS `write_at`），只推进 `write_pos`；
/// - 消费者 = 音频驱动（`AUDIO_FETCH`/`AUDIO_COMMIT`），只推进 `read_pos`；
/// - 两端各只写自己的指针、只读对方指针——**无锁、无自旋、无等待环**；
/// - 因为只有两个原子量而没有锁，**不存在锁获取顺序与死锁风险**；
/// - 内存序：写指针用 `Release`，读指针用 `Acquire`，构成 SPSC 标准配对；
/// - 数据区经 `UnsafeCell` 共享，但可达区间由两个指针隔离：生产者只写
///   `[write_pos, write_pos+n)`，消费者只读 `[read_pos, read_pos+m)`，
///   且 `n + m <= capacity`，故两端永不触碰同一字节。
pub struct AudioRing {
    buf: core::cell::UnsafeCell<Vec<u8>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
    /// 消费者注册槽：持有 pid，`NO_CONSUMER` 表示空闲。
    ///
    /// **S15 单点定义**：这是"谁在消费"的**唯一**真相来源——写路径门禁
    /// （`is_attached`）、`status` 字段、syscall 层权限校验全部读它，
    /// 不存在第二份状态可与之分裂。
    consumer: AtomicU32,
    /// 欠载计数（消费者取不到数据即 +1；如实披露，不隐藏）。
    underruns: AtomicU64,
}

// SAFETY（S18/S21）：共享状态全部由原子量协调，SPSC 语义保证两端永不
// 并发触碰同一字节。底层 Vec 一经构造长度即固定（capacity），全程不做
// realloc——故裸数据指针在实例生命周期内稳定。
unsafe impl Send for AudioRing {}
unsafe impl Sync for AudioRing {}

impl AudioRing {
    /// 构造容量为 `capacity` 的清零 ring。
    pub fn with_capacity(capacity: usize) -> Self {
        let mut v = Vec::new();
        v.resize(capacity, 0u8);
        Self {
            buf: core::cell::UnsafeCell::new(v),
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            consumer: AtomicU32::new(NO_CONSUMER),
            underruns: AtomicU64::new(0),
        }
    }

    /// 已占用字节数（写入但消费者尚未提交的部分）。
    pub fn used(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        w.wrapping_sub(r)
    }

    /// 剩余可写空间（字节）。
    pub fn free(&self) -> usize {
        self.capacity - self.used()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前消费者 pid；无消费者返回 `None`。
    pub fn consumer(&self) -> Option<usize> {
        match self.consumer.load(Ordering::Acquire) {
            NO_CONSUMER => None,
            pid => Some(pid as usize),
        }
    }

    /// 是否已有消费者附加。写路径门禁与 `status` 均以此为准（S15 单点）。
    pub fn is_attached(&self) -> bool {
        self.consumer.load(Ordering::Acquire) != NO_CONSUMER
    }

    /// 注册为消费者（**独占**，plan §3.6）。
    ///
    /// **S21 并发论证**：CAS 从 `NO_CONSUMER` 到 `pid` 是原子的，故两个并发
    /// attach **必有且仅有一个**成功，失败方得到 `Busy`——不存在"都以为自己是
    /// 消费者"的窗口，也不存在把已注册者静默顶掉的可能。
    ///
    /// 语义选择（S17 理由）：同一 pid 重复 attach **也返回 `Busy`**，不做幂等。
    /// 理由：重复 attach 意味着调用方状态机有误（已持有却再申请），静默成功会
    /// 掩盖该错误；`Busy` 让问题在调用点可见。
    pub fn attach(&self, pid: usize) -> Result<(), Error> {
        // S19：pid 必须能无损装入 u32，且不得撞上哨兵。
        if pid >= NO_CONSUMER as usize {
            return Err(Error::InvalidParam);
        }
        self.consumer
            .compare_exchange(
                NO_CONSUMER,
                pid as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| Error::Busy)
    }

    /// 注销消费者，**仅属主可注销**。
    ///
    /// **S21**：CAS 只在槽内仍是 `pid` 时清空，故非属主调用无法清除他人注册
    /// （返回 `PermissionDenied` 且槽位不变）。
    pub fn detach(&self, pid: usize) -> Result<(), Error> {
        if pid >= NO_CONSUMER as usize {
            return Err(Error::InvalidParam);
        }
        self.consumer
            .compare_exchange(pid as u32, NO_CONSUMER, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Error::PermissionDenied)
    }

    /// 进程退出时的无条件清理：若槽内正是 `pid` 则清空，否则**静默不动**。
    ///
    /// **S18 资源释放**：进程死亡必须释放其占用的消费者槽，否则音频节点会被
    /// 一个不存在的进程永久独占（拒绝所有后续驱动）。
    /// **幂等**：可重复调用；对非属主调用是无操作而非错误——进程正在消亡，
    /// 此时报错没有可交付的接收方。
    pub fn detach_any(&self, pid: usize) {
        if pid >= NO_CONSUMER as usize {
            return;
        }
        let _ = self.consumer.compare_exchange(
            pid as u32,
            NO_CONSUMER,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn underruns(&self) -> u64 {
        self.underruns.load(Ordering::Acquire)
    }

    pub fn note_underrun(&self) {
        self.underruns.fetch_add(1, Ordering::AcqRel);
    }

    /// 生产：把 `src` 拷入空闲区，返回实际写入字节数（可能短写）。
    ///
    /// **S20 失败模式优先**：返回 0 表示当前无空间。本函数**自身不阻塞**，
    /// 是否等待由调用方（syscall 层）决定。
    pub fn push(&self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.free());
        if n == 0 {
            return 0;
        }
        let w = self.write_pos.load(Ordering::Acquire);
        let cap = self.capacity;
        // S19：`buf.get()` 得到的是 `*mut Vec<u8>`（**Vec 头部地址**），必须
        // 先解引用再取 `as_mut_ptr()`——直接 `as *mut u8` 会指向 Vec 的
        // ptr/len/cap 字段本身，写入即破坏堆（实测 STATUS_HEAP_CORRUPTION）。
        let base = unsafe { (*self.buf.get()).as_mut_ptr() };
        let start = w % cap;
        let first = core::cmp::min(n, cap - start);
        // SAFETY：start + first <= cap；该区间不在消费者可达范围内（见类型文档）。
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), base.add(start), first);
            if n > first {
                core::ptr::copy_nonoverlapping(src.as_ptr().add(first), base, n - first);
            }
        }
        // Release：保证数据写入对消费者的 Acquire 读取可见。
        self.write_pos.store(w + n, Ordering::Release);
        n
    }

    /// 消费：取出至多 `dst.len()` 字节，**不推进读指针**。
    ///
    /// 读指针由 [`AudioRing::commit`] 推进，以支持"取走 → 喂硬件 →
    /// 播完 → 提交"的两阶段语义（plan_audio_vfs.md §3.2）。
    pub fn peek(&self, dst: &mut [u8]) -> usize {
        let r = self.read_pos.load(Ordering::Acquire);
        let w = self.write_pos.load(Ordering::Acquire);
        let avail = w.wrapping_sub(r);
        let n = core::cmp::min(dst.len(), avail);
        if n == 0 {
            return 0;
        }
        let cap = self.capacity;
        // S19：同 push——先解引用 Vec 再取数据指针，否则读到的是 Vec 头部。
        let base = unsafe { (*self.buf.get()).as_ptr() };
        let start = r % cap;
        let first = core::cmp::min(n, cap - start);
        // SAFETY：读区与生产者写区不相交（同上）。
        unsafe {
            core::ptr::copy_nonoverlapping(base.add(start), dst.as_mut_ptr(), first);
            if n > first {
                core::ptr::copy_nonoverlapping(base, dst.as_mut_ptr().add(first), n - first);
            }
        }
        n
    }

    /// 提交：推进读指针 `n` 字节，把空间交还生产者。
    ///
    /// **S19 边界论证**：`n` 超过"已取未提交"量时**如实拒绝**，绝不静默
    /// 截断——静默截断会让读指针越过写指针，`used()` 回绕成巨额数值，
    /// 进而把 ring 永久堵死。
    pub fn commit(&self, n: usize) -> Result<(), Error> {
        let r = self.read_pos.load(Ordering::Acquire);
        let w = self.write_pos.load(Ordering::Acquire);
        if n > w.wrapping_sub(r) {
            return Err(Error::InvalidParam);
        }
        self.read_pos.store(r + n, Ordering::Release);
        Ok(())
    }
}

/// `/devices/audio/dsp` 节点：PCM 哑管道 + 属性子目录。
///
/// 结构照 `SerialDeviceNode`（devfs.rs）：主数据流 + `DynamicDirNode` 承载
/// 属性子文件。区别在于数据流是**内核内 ring**而非硬件透传。
pub struct DspNode {
    /// ring 以 `Arc` 持有：`status` 属性回调需要共享同一实例，
    /// 用裸指针自引用是脆弱的（S18/S26 自审否决），裸 Arc 克隆才是正道。
    ring: Arc<AudioRing>,
    children: DynamicDirNode,
}

impl DspNode {
    pub fn new() -> Self {
        Self::with_capacity(AUDIO_RING_CAPACITY)
    }

    /// 以指定容量构造（测试用小容量以便快速触达边界）。
    pub fn with_capacity(capacity: usize) -> Self {
        let children = DynamicDirNode::new();
        let ring = Arc::new(AudioRing::with_capacity(capacity));

        // ---- format 属性：读写，第一版仅 s16le ----
        // S16：当前无"自动协商"，格式由写者显式声明；不被支持的格式
        // 如实 NotSupported，绝不静默转换为支持格式（那会伪造音质）。
        let fmt_node = DynamicFileNode::read_write(
            || {
                let mut v = String::from(AUDIO_FORMAT_S16LE).into_bytes();
                v.push(b'\n');
                v
            },
            |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                if s.trim() == AUDIO_FORMAT_S16LE {
                    Ok(buf.len())
                } else {
                    // 语义：格式合法但本实现不支持 → NotSupported。
                    Err(Error::NotSupported)
                }
            },
        );
        children.add_child("format", Arc::new(fmt_node));

        // ---- channels 属性 ----
        let ch_node = DynamicFileNode::read_write(
            || {
                let mut v = String::from(AUDIO_CHANNELS_STEREO).into_bytes();
                v.push(b'\n');
                v
            },
            |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                if s.trim() == AUDIO_CHANNELS_STEREO {
                    Ok(buf.len())
                } else {
                    Err(Error::NotSupported)
                }
            },
        );
        children.add_child("channels", Arc::new(ch_node));

        // ---- rate 属性 ----
        // 非数字输入如实 InvalidParam（输入非法），数字但不受支持则
        // NotSupported（输入合法、实现不支持）——两者语义不同，不得含混。
        let rate_node = DynamicFileNode::read_write(
            || {
                let mut v = String::from(AUDIO_RATE_48000).into_bytes();
                v.push(b'\n');
                v
            },
            |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                let t = s.trim();
                // S19：解析为 u32 失败即 InvalidParam，不做 default 兜底。
                let _n: u32 = t.parse().map_err(|_| Error::InvalidParam)?;
                if t == AUDIO_RATE_48000 {
                    Ok(buf.len())
                } else {
                    Err(Error::NotSupported)
                }
            },
        );
        children.add_child("rate", Arc::new(rate_node));

        // ---- status 属性：只读 JSON，如实披露真实运行态 ----
        // S10：全部字段取自 ring 的实际原子量，无一处编造。
        let ring_for_status = ring.clone();
        let st_node = DynamicFileNode::read_only(move || {
            let ring = &*ring_for_status;
            let mut target = VecTarget::new();
            let mut w = JsonWriter::new(&mut target);
            if let Ok(mut obj) = w.start_object() {
                let _ = obj.field_bool("attached", ring.is_attached());
                // A2：consumer 现在是**真实**数据（A1 时无消费者身份概念，
                // 故当时如实省略而非编造占位值；见 unittodo9 A1.4）。
                match ring.consumer() {
                    Some(pid) => {
                        let _ = obj.field_u64("consumer", pid as u64);
                    }
                    None => {
                        let _ = obj.field_null("consumer");
                    }
                }
                let _ = obj.field_u64("capacity", ring.capacity() as u64);
                let _ = obj.field_u64("used", ring.used() as u64);
                let _ = obj.field_u64("free", ring.free() as u64);
                let _ = obj.field_u64("underruns", ring.underruns());
                let _ = obj.end();
            }
            let mut bytes = target.into_bytes();
            bytes.push(b'\n');
            bytes
        });
        children.add_child("status", Arc::new(st_node));

        // S15/S18：登记自身供进程退出清理路径 O(1) 可达（见 AUDIO_RING_SLOT）。
        // `call_once`：测试中会多次构造（各自独立 ring），首个登记的即系统节点，
        // 后续不覆盖——退出清理是全局唯一资源回收，语义上只应有一个目标。
        let registered = ring.clone();
        AUDIO_RING_SLOT.call_once(|| registered);

        Self { ring, children }
    }

    /// 供 syscall 层（批次二）访问底层 ring。
    pub fn ring(&self) -> Arc<AudioRing> {
        self.ring.clone()
    }
}

impl INode for DspNode {
    /// 读：从 ring 取走数据（两阶段之一：取走但**不**提交）。
    ///
    /// 读指针由 [`AudioRing::commit`] 推进，以支持"取走 → 喂硬件 → 播完 →
    /// 提交"的两阶段语义（plan_audio_vfs.md §3.2 AUDIO_FETCH/AUDIO_COMMIT）。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let n = self.ring.peek(buf);
        if n == 0 {
            // S20：无数据即如实 WouldBlock，由 syscall 层决定是否阻塞。
            //
            // 欠载计数的语义边界（S26 自审修正）：`underruns` 表示
            // **已附加的消费者取不到数据**——即"有人正在等这份数据却等不到"。
            // 未附加时的空读只是"当前无数据"，不是欠载；若不加区分，
            // 任意进程读一次本节点就会污染该计数，使之失去意义。
            if self.ring.is_attached() {
                self.ring.note_underrun();
            }
            return Err(Error::WouldBlock);
        }
        Ok(n)
    }

    /// 写：背压语义三分支（plan_audio_vfs.md §3.4）。
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        // 分支 1（诚实性红线 S06/S07/S09）：无消费者附加 → 如实失败。
        // "接受后丢弃"会让写者以为播放成功，是最典型的伪链路。
        if !self.ring.is_attached() {
            return Err(Error::NotSupported);
        }
        // 分支 2：有空间 → 拷入，返回实写量。
        let n = self.ring.push(buf);
        if n == 0 {
            // 分支 3：ring 满 → WouldBlock（EAGAIN 语义），绝不静默丢弃。
            return Err(Error::WouldBlock);
        }
        // 数据**已**进入 ring，此刻才通知等待者醒来取数（顺序不可颠倒：若先
        // 唤醒再入队，被唤醒的读者复检时仍见空 ring，会再次入睡而白等一场）。
        //
        // 这一行是 audio 阻塞往返的**闭环点**——没有它，block_for_audio 的读者
        // 永远等不到唤醒（本缺陷由 A2 e2e 设计阶段自查发现，非测试捕获）。
        notify_data_ready();
        Ok(n)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
            node_type: INodeType::CharacterDevice,
            permissions: Permissions::read_write(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    /// A5：字符设备判型零成本。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    /// KM17/KM1：字符流不可定位。syscall 层据此对非顺序偏移如实报
    /// `IllegalSeek`，而不是靠 fd 号魔法数字判断。
    fn is_seekable(&self) -> bool {
        false
    }

    /// A2：空读时应当阻塞等待（等待源是 PCM 数据到达，非键盘）。
    ///
    /// **诚实性（S06/S09）**：仅当**确有消费者**时才声明可阻塞。无消费者时
    /// `read_at` 的 `WouldBlock` 不是"稍后会有"而是"没人会产生"——此时声明
    /// 可阻塞会让调用者永久睡眠等待一个永远不会到来的数据源。这正是
    /// `blocks_when_empty` 语义归节点所有的价值：只有节点自己知道它此刻是否
    /// 真的会有数据。
    fn blocks_when_empty(&self) -> bool {
        self.ring.is_attached()
    }

    /// A2：本节点确实暴露音频 ring——如实声明（这使 syscall 层无需类型试探）。
    fn as_audio_ring(&self) -> Option<Arc<AudioRing>> {
        Some(self.ring.clone())
    }

    /// M17（ADR-023 §6）：字符流截断语义不存在——返回成功码会掩盖
    /// "什么都没发生"，如实 NotSupported。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        self.children.list_dir()
    }
}
