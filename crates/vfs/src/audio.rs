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

/// 混音器输入路数（`/devices/audio/stream/0..N-1`）。
///
/// **取值理由**：4 路足以覆盖"多路并发混音"的验证需求（M2 至少要 2 路才能
/// 证明相加语义），同时每路 64 KiB 的 ring 共 256 KiB，相对本项目的内核内存
/// 预算很小。路数是**编译期常量**而非运行时配置——M1/M2 还没有"动态增删输入"
/// 的需求，提前做成可配置只会引入未经验证的分支（S39 反对装饰性灵活性）。
/// 将来真需要时，改这一处即可（挂载循环已按本常量驱动）。
pub const AUDIO_STREAM_COUNT: usize = 4;

/// 支持的采样格式（S13：业务语义常量集中定义，避免散落漂移）。
pub const AUDIO_FORMAT_S16LE: &str = "s16le";
/// 支持的声道数文本。
pub const AUDIO_CHANNELS_STEREO: &str = "2";
/// 支持的采样率文本（Hz）。
pub const AUDIO_RATE_48000: &str = "48000";

/// 输入端 `stream/N` 可接受的采样率（文本形式，与属性文件一致）。
///
/// 必须与用户态 `audiod` 的 `SUPPORTED_INPUT_RATES` 保持同一集合。两者不一致
/// 时生产者会收到 `NotSupported` —— 一个**可见的**拒绝，而不是被静默按错误
/// 速度播放。这条约束是有意保留的：宁可写失败，也不要听不出原因的走音。
///
/// 输出端 `dsp` **不**使用本表：它直通硬件，codec 固定 48000。
pub const AUDIO_INPUT_RATES: &[&str] = &["48000", "44100", "32000", "22050", "16000"];

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
/// - 消费者 = 音频驱动（`AUDIO_FETCH`/`AUDIO_COMMIT`），只推进 `read_pos`
///   （取数时经 `reserved_pos` 中转，见该字段说明）；
/// - 两端各只写自己的指针、只读对方指针——**无锁、无自旋、无等待环**；
/// - 因只有原子量而没有锁，**不存在锁获取顺序与死锁风险**；
/// - 内存序：写侧一律 `Release`，读侧一律 `Acquire`，构成 SPSC 标准配对；
/// - 数据区经 `UnsafeCell` 共享，但可达区间由三个指针隔离：生产者只写
///   `[write_pos, write_pos+n)`，消费者只读 `[read_pos, read_pos+m)`，
///   且任一时刻 `已写未提交 + 可写 <= capacity`，故两端永不触碰同一字节。
///
/// ## 三个指针的分工（**本类型的关键不变量**）
///
/// ```text
/// read_pos == reserved_pos == write_pos   空
///    |             |              |
///    |             |              +-- 生产者已写入的全部数据上界
///    |             +-- 消费者已"取走"（借出）的上界，尚未确认播完
///    +-- 消费者已"确认播完"的上界；此前的空间已交还生产者
/// ```
///
/// - `[read_pos, reserved_pos)` = **已借出、尚未确认播完**（在硬件手里）；
/// - `[reserved_pos, write_pos)` = **已写入、尚未被借出**（等着被取）。
///
/// **为何必须有 `reserved_pos`**（本字段的引入理由，属缺陷修复而非装饰）：
/// 初版只有 `read_pos`/`write_pos` 两个指针，`peek` 不推进任何指针，
/// 于是"这一字节已经被取走"这件事**只存在于消费者自己的记账里**
/// （intel-hda 的 `chunk_filled[]`），内核完全无从知晓。后果有三：
///   1. 同一个消费者可以**反复 peek 到同一段字节**（第二次取到的是第一次的
///      副本），驱动若少 commit 一次就直接把同一段声音播两遍——这正是实测
///      "播放特别卡、有重复"的根因；
///   2. `commit(n)` 的合法性只能拿 `write_pos - read_pos` 校验，而该量
///      **同时包含"已借出"和"未借出"两部分**，内核分不清二者，于是
///      "本类型"与"消费者账本"成为两个可分裂的真相源（违反 S15 单点）；
///   3. 借出量一旦超过 `write_pos - read_pos`，commit 被如实拒绝，但读指针
///      停滞会让后续 peek 继续返回同一段，错误自我放大。
/// 引入 `reserved_pos` 后**借出本身就是 ring 的一等状态**：同一字节在
/// 被 commit 前不可能被第二次借出，commit 的边界校验也有了精确依据。
pub struct AudioRing {
    buf: core::cell::UnsafeCell<Vec<u8>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
    /// 已借出（peek 取走）但尚未确认播完的上界。
    ///
    /// 只有消费者推进它（peek 时），只有 `commit` 让它回落到 `read_pos`。
    /// 语义与 `read_pos` 同为单调递增的"绝对位置"（不回绕，取模只在访问
    /// 缓冲区时做），故三者的差值恒为可解释的正数。
    reserved_pos: AtomicUsize,
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
            reserved_pos: AtomicUsize::new(0),
            consumer: AtomicU32::new(NO_CONSUMER),
            underruns: AtomicU64::new(0),
        }
    }

    /// 已占用字节数（写入但消费者尚未确认播完的部分）。
    ///
    /// **S15 单点**：这是"ring 里还有多少数据没被确认消费"的**唯一**定义，
    /// 生产者背压（`free`）与 `status` 披露都读它。已借出未提交的部分
    /// **计入已占用**——那些字节仍在缓冲区内、生产者不得覆盖它们。
    pub fn used(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        w.wrapping_sub(r)
    }

    /// 剩余可写空间（字节）。
    pub fn free(&self) -> usize {
        self.capacity - self.used()
    }

    /// 已借出（peek 取走）但尚未 `commit` 确认播完的字节数。
    ///
    /// 供 `status` 披露与诊断使用；`commit` 的边界校验亦以此为准
    /// （而不是拿 `used()` 兜底——后者含"尚未借出"的部分，会把
    /// "提交了从未取走的数据"这种错误一并放行）。
    pub fn reserved(&self) -> usize {
        let p = self.reserved_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        p.wrapping_sub(r)
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

    /// 消费：取出至多 `dst.len()` 字节，**只推进** `reserved_pos`（借出），
    /// **不推进** `read_pos`。
    ///
    /// 两阶段语义（plan_audio_vfs.md §3.2）：取走 → 喂硬件 → 播完 → 提交。
    /// `read_pos` 仍只由 [`AudioRing::commit`] 推进，故"取走后未确认播完"的
    /// 数据不会丢失。**但借出本身必须被记录**：本函数推进 `reserved_pos`，
    /// 使同一字节在被 `commit` 之前**不可能被第二次借出**。
    ///
    /// **S21 并发论证**：本函数只被**唯一**消费者调用（`attach` 的独占槽
    /// 保证同一时刻至多一个消费进程），故对 `reserved_pos` 的
    /// load-then-store 不存在竞争；生产者只读它、从不写，也不会与之冲突。
    /// 若将来允许并发消费者，此处须改为 CAS 循环——该前提由独占槽强制，
    /// 不是"恰好只有一个"的巧合。
    pub fn peek(&self, dst: &mut [u8]) -> usize {
        // 从**借出上界**而非读上界起读：已被借出但未提交的字节不重复交付。
        let r = self.reserved_pos.load(Ordering::Acquire);
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
        // Release：记录借出。必须在数据拷出**之后**发布——否则消费者可能
        // 先看到"已借出"再读数据，而数据拷贝尚未完成（S21 顺序纪律）。
        self.reserved_pos.store(r + n, Ordering::Release);
        n
    }

    /// 提交：推进读指针 `n` 字节，把空间交还生产者。
    ///
    /// **S19 边界论证（已修正）**：`n` 超过"**已借出**未提交"量时如实拒绝，
    /// 绝不静默截断。校验基准是 `reserved()`（=`reserved_pos - read_pos`），
    /// **不是** `used()`（=`write_pos - read_pos`）。
    ///
    /// 初版用 `used()` 校验，语义上放行了"提交从未取走的数据"：`used()`
    /// 含尚未借出的部分，故消费者可以 commit 一段它根本没 peek 过的字节，
    /// 读指针随之越过借出上界——而 `reserved_pos` 不跟进，二者永久错位，
    /// 后续 `peek` 会从错误位置继续取数据。以 `reserved()` 为准后，
    /// "能提交的"与"已取走的"成为同一个量（S15 单点），该错误结构性消失。
    ///
    /// 不变式：`read_pos <= reserved_pos <= write_pos` 恒成立——本函数只
    /// 把 `read_pos` 推进到**不超过** `reserved_pos` 的位置，`peek` 只把
    /// `reserved_pos` 推进到不超过 `write_pos` 的位置。
    pub fn commit(&self, n: usize) -> Result<(), Error> {
        let r = self.read_pos.load(Ordering::Acquire);
        let p = self.reserved_pos.load(Ordering::Acquire);
        if n > p.wrapping_sub(r) {
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
    /// 写入门禁策略（见 [`WriteGate`]）。显式构造参数，**不是**运行时按路径猜。
    gate: WriteGate,
}

/// 写入路径的门禁策略。
///
/// **为何需要两种模式（不是权宜之计，而是两类节点的本质差异）**：
///
/// - [`WriteGate::RequireConsumer`] — **输出端** `dsp`。数据一旦写入就交给硬件、
///   出系统了。若无消费者，写入等于"把数据扔进虚空"：写者以为播了，实际没人取。
///   A1 故如实拒绝（`NotSupported`），这是**诚实性红线**（S06/S07/S09）。
///
/// - [`WriteGate::Open`] — **输入端** `stream/N`（批次四 M1）。它是混音器的输入
///   缓冲，数据留在 ring 里等 `audiod` 来取。它**没有**"消费者"概念，也不需要：
///   写入的意义不依赖是否有人正在读。若照搬 `dsp` 的门禁，生产者将**永远写不进去**。
///
/// **放宽的只是"要不要消费者"，不是"满了怎么办"**：两种模式下 ring 满都如实
/// `WouldBlock` 背压，绝不静默丢弃或覆盖（A1 红线在 `stream` 上延续）。
/// 该区分由 `test_audio_stream_backpressure_when_full` 单独钉死。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteGate {
    /// 无消费者附加时拒绝写入（`dsp`：输出端）。
    RequireConsumer,
    /// 无需消费者，接受写入；满则背压（`stream/N`：输入端）。
    Open,
}

impl DspNode {
    pub fn new() -> Self {
        Self::with_capacity(AUDIO_RING_CAPACITY)
    }

    /// 构造一路混音器**输入**节点（`stream/N`，批次四 M1）。
    ///
    /// 与 [`DspNode::new`] 的唯一差别是 [`WriteGate::Open`]——见该枚举的论证。
    /// 容量刻意与 `dsp` 一致（`AUDIO_RING_CAPACITY`）：二者都是 PCM 缓冲，
    /// 没有理由让输入端比输出端小，那只会更早触发背压（S17 默认值需有理由）。
    pub fn stream() -> Self {
        Self::stream_with_capacity(AUDIO_RING_CAPACITY)
    }

    /// 以指定容量的**输入**节点构造（测试用小容量以便快速触达背压边界）。
    pub fn stream_with_capacity(capacity: usize) -> Self {
        Self::build(capacity, WriteGate::Open)
    }

    /// 以指定容量构造（测试用小容量以便快速触达边界）。
    pub fn with_capacity(capacity: usize) -> Self {
        Self::build(capacity, WriteGate::RequireConsumer)
    }

    /// 实际构造函数：容量 + 门禁策略（S15 单点——两种模式共用全部逻辑）。
    fn build(capacity: usize, gate: WriteGate) -> Self {
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
        // 可接受的采样率集合由**门禁模式**决定，而不是全局写死一个：
        //
        // - 输出端 `dsp`（RequireConsumer）：数据直通硬件，codec 固定 48000。
        //   允许别的 rate 等于写下一个**内核无法兑现的承诺** —— 说 44100 实际
        //   按 48000 播，声音变快，而链路上没有任何一处会报错。故只接受 48000。
        //
        // - 输入端 `stream/N`（Open）：这是混音器的**输入**，可以带自己的采样率。
        //   批次五 M5 让 audiod 按 rate 属性重采样到总线速率，所以这里放开是
        //   **有实现支撑**的，不是放空。集合必须与 audiod 的 `SUPPORTED_INPUT_RATES`
        //   一致；不一致时生产者的写会被拒（而不是被静默按错误速度播放），
        //   故不一致是**可见的**失败，不是隐性错误。
        let allowed_rates: &[&str] = match gate {
            WriteGate::RequireConsumer => &[AUDIO_RATE_48000],
            WriteGate::Open => AUDIO_INPUT_RATES,
        };
        let rate_node = DynamicFileNode::read_write(
            || {
                let mut v = String::from(AUDIO_RATE_48000).into_bytes();
                v.push(b'\n');
                v
            },
            move |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                let t = s.trim();
                // S19：解析为 u32 失败即 InvalidParam，不做 default 兜底。
                let _n: u32 = t.parse().map_err(|_| Error::InvalidParam)?;
                // 字符串比较而非数值比较：属性本身是文本，这样 "48000 " 与
                // "048000" 之类的写法既不会绕过也不会被误判为合法。
                if allowed_rates.contains(&t) {
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
                // 已借出（peek 取走）但尚未 commit 确认播完的字节数。
                // 如实披露：它是"驱动手里攥着多少还没归还"的直接证据，
                // 恒 <= used()。稳态下应约为一个 BDL 周期（16 KiB）。
                let _ = obj.field_u64("reserved", ring.reserved() as u64);
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

        Self {
            ring,
            children,
            gate,
        }
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
    /// **两种模式，与写入门的区分同源**（见 [`WriteGate`]）：
    ///
    /// - 输出端 `dsp`（[`WriteGate::RequireConsumer`]）：`peek` + 由 AUDIO_COMMIT
    ///   推进读指针。这是 A2/A3 已验收的**两阶段**语义，必须保持——取走的数据
    ///   要**先喂给硬件、播完**再提交，中途崩溃才不会把没播的音频静默丢掉。
    ///
    /// - 输入端 `stream/N`（[`WriteGate::Open`]）：读走即取走（peek + commit）。
    ///   它是混音器的输入缓冲，没有硬件、没有"播完"的概念，两阶段毫无意义。
    ///
    /// **本条修的是一个真实缺陷（批次四 M2 发现）**：此前 `read_at` 对两者
    /// 一律 `peek`，而推进读指针的 `commit` 只经 AUDIO_COMMIT 抵达，该路径
    /// **硬编码 `/devices/audio/dsp`**（syscall.rs `AUDIO_DSP_PATH`）——
    /// 于是 `stream/N` **根本没有任何途径**推进读指针。
    ///
    /// 后果隐蔽而严重：audiod 每轮读到的是**同一批**数据，输出成了"一段缓冲
    /// 无限重复"，不是流式音频；却因为重复得连续而听不出异常。M1 的逐字节
    /// 校验**照样通过**（peek 返回的正是写进去的那些字节），直到 M2 引入
    /// 第二路与断开场景，`live_inputs` 始终不下降才把它暴露出来。
    ///
    /// 教训已固化为测试：`test_audio_stream_read_consumes_data` 断言读后
    /// `used()==0`，`test_audio_dsp_read_still_peeks_until_commit` 防反向
    /// 回归（把所有读都改成消费会破坏驱动契约）。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let n = self.ring.peek(buf);
        if n > 0 && self.gate == WriteGate::Open {
            // 输入端：读走即取走。commit 在 peek **之后**、返回之前完成，
            // 故调用方拿到的就是被消费掉的那一段（原子性对调用方可见）。
            // commit 失败属内部不变量破裂：如实上抛，不假装读成功。
            self.ring.commit(n)?;
            return Ok(n);
        }
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
    ///
    /// 分支 1 依 [`WriteGate`] 而定——输出端要求消费者，输入端不要求。
    /// **无论哪种模式**，分支 2/3（落盘或背压）完全一致：门禁处理的是"要不要
    /// 有人接收"，不是"满了怎么办"。
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        // 分支 1（诚实性红线 S06/S07/S09）：输出端无消费者附加 → 如实失败。
        // "接受后丢弃"会让写者以为播放成功，是最典型的伪链路。
        if self.gate == WriteGate::RequireConsumer && !self.ring.is_attached() {
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
