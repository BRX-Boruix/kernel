//! console 设备节点（§6.15 P2，甲-a 架构的**字节端**）。
//!
//! [ADR-045] §3 阶段 3 的目标形态：stdin 终将指向「console 对象的字节读端」，
//! 字节由**用户态常驻转换者 consoled**（P3）从事件流（P1 的每读者流）转换后
//! 写入本节点的写端。本节点就是那个「console 对象」：
//!
//! - **读端**（fd 0 的未来归属）：从 SPSC 字节环取字节；空环返回 `Ok(0)`
//!   （「此刻无字节」，终端语义下稍后必有），阻塞语义由 syscall 层经
//!   [`INode::console_stream`] 真值 + `CONSOLE_WAITER` 等待者接管——本节点
//!   与 audio `DspNode` 同构（S28 不重造轮子），但**无超时**（终端的生产者
//!   是常驻 consoled，不存在「驱动已死」；与 `input_event_stream` 的无限期
//!   理由同源）。
//! - **写端**（consoled 专属）：写入 SPSC 环；环满时**短写**（写入能容纳的
//!   前缀）——丢弃字节 = 伪造「用户没按键」（S09），阻塞写会让 consoled 的
//!   单线程循环被慢读者卡死（它与事件流读者是同一进程），故如实短写 +
//!   `dropped` 计数披露，与事件环的流控哲学（§6.14.4b）一致。
//! - **就绪探针**（S15 单点）：「有没有字节」的真值经 [`INode::as_console_ring`]
//!   暴露环句柄、由 syscall 层读 `used()` 判定——**非消费**（探针取走字节 =
//!   交付给探针而非读者，S09 丢字节）。audio 的 `audio_ring_empty` 同款形态。
//! - **status 子文件**：遥测如实披露（S09 可观察）。
//!
//! [ADR-045]: ../docs/adr/045-input-event-stream.md

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use klib::error::Error;
use klib::json::{JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{AccessPolicy, DirEntry, FileMetadata, INode, INodeType};

/// console 字节环容量（字节）。
///
/// 键入速率（人手 ≤ 50 B/s 量级）与 consoled 的转换延迟相比，4 KiB 足以
/// 吸收「读者被挂起数秒」的积压；与事件环（128 条 × 16 B = 2 KiB）同量级，
/// 不放大内核内存驻留。溢出策略是短写 + 计数（见模块文档），不是覆盖。
pub const CONSOLE_RING_CAPACITY: usize = 4096;

// ---------- SPSC 字节环（audio::AudioRing 的极简同构，S28） ----------
//
// 与 audio 的三指针环相比，console 无「借出/提交」语义（字节取走即消费，
// 无硬件确认步），故退回经典双指针 SPSC：write_pos / read_pos 均为**绝对
// 位置**（单调递增，取模只在访问数据区时做）。

/// console 字节环：consoled 写入、fd 0 读者取走。
///
/// S21 并发模型与 `audio::AudioRing` 逐条同构：生产者只写 `write_pos`、
/// 消费者只写 `read_pos`，两端各读对方指针构成 SPSC 配对（写 Release /
/// 读 Acquire）；数据区经 `UnsafeCell` 共享但可达区间被指针隔离，永不
/// 触碰同一字节。多读者并存是 P4 切换后的 fd 继承形态（同一读端被 dup2
/// 共享），语义上仍是单消费点（多个 fd = 同一读者的多个名字）。
pub struct ConsoleRing {
    buf: UnsafeCell<Vec<u8>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
    /// 环满导致的丢弃字节计数（S09 如实披露，不隐藏）。
    dropped: AtomicU64,
    /// write_at 累计调用数（consoled 活性观测）。
    writes: AtomicU64,
    /// read_at 累计「空读」次数（读者等待强度观测）。
    empty_reads: AtomicU64,
}

// SAFETY（S18/S21）：共享状态全部由原子量协调，SPSC 语义保证两端永不
// 并发触碰同一字节；底层 Vec 一经构造长度即固定，全程不做 realloc——
// 裸数据指针在实例生命周期内稳定。
unsafe impl Send for ConsoleRing {}
unsafe impl Sync for ConsoleRing {}

impl ConsoleRing {
    /// 构造容量为 [`CONSOLE_RING_CAPACITY`] 的清零环。
    pub fn new() -> Self {
        let mut v = Vec::new();
        v.resize(CONSOLE_RING_CAPACITY, 0u8);
        Self {
            buf: UnsafeCell::new(v),
            capacity: CONSOLE_RING_CAPACITY,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            empty_reads: AtomicU64::new(0),
        }
    }

    /// 已占用字节数（S15 单点：环水位的唯一定义）。
    ///
    /// 就绪探针（syscall 层的阻塞复检）与交付路径（`read` 的可读量）都读
    /// 它——「探针说有」与「读得到」同源，绝不另设第二真相源。
    pub fn used(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        w.wrapping_sub(r)
    }

    fn free(&self) -> usize {
        self.capacity - self.used()
    }

    /// 写入至多 `data.len()` 字节，返回实际写入数（短写语义，见模块文档）。
    fn write(&self, data: &[u8]) -> usize {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let w = self.write_pos.load(Ordering::Relaxed);
        let n = core::cmp::min(data.len(), self.free());
        if n < data.len() {
            self.dropped
                .fetch_add((data.len() - n) as u64, Ordering::Relaxed);
        }
        if n > 0 {
            // SAFETY：[w, w+n) 由 free() 保证不与读端可达区间重叠（SPSC 不变量）。
            let base = unsafe { &mut *self.buf.get() };
            for i in 0..n {
                base[(w + i) % self.capacity] = data[i];
            }
            self.write_pos.store(w.wrapping_add(n), Ordering::Release);
        }
        n
    }

    /// 取走至多 `out.len()` 字节；空环返回 0（不消费、不伪造）。
    fn read(&self, out: &mut [u8]) -> usize {
        let r = self.read_pos.load(Ordering::Relaxed);
        let avail = self.used();
        if avail == 0 {
            self.empty_reads.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        let n = core::cmp::min(out.len(), avail);
        // SAFETY：[r, r+n) ⊆ [read_pos, write_pos)，由 used() 保证可读。
        let base = unsafe { &*self.buf.get() };
        for i in 0..n {
            out[i] = base[(r + i) % self.capacity];
        }
        self.read_pos.store(r.wrapping_add(n), Ordering::Release);
        n
    }

    /// 遥测快照（status JSON 用）：（write_pos, read_pos, dropped, writes）。
    fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.write_pos.load(Ordering::Relaxed) as u64,
            self.read_pos.load(Ordering::Relaxed) as u64,
            self.dropped.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
        )
    }
}

// ---------- 数据到达回调（audio::AUDIO_WAKE_HOOK 同构，S28） ----------

use spin::Once;

/// 数据到达回调槽（`Once`：系统只有一个 console 节点）。
///
/// **为何用回调而非直接调 `task::wake_console`**：vfs 是 task 的**下游**
/// （task 依赖 vfs），vfs 反向调用 task 会形成循环依赖——与 audio 模块
/// 的 `AUDIO_WAKE_HOOK` 完全同构（S28），理由逐字成立。
///
/// **未安装时的行为**：静默不唤醒。数据已在环里不丢；P4 切换前读者走
/// 轮询路径（现状），切换后内核启动必然安装（vfs_init）。
static CONSOLE_WAKE_HOOK: Once<fn()> = Once::new();

/// 安装数据到达回调（由内核启动期调用一次；重复安装不覆盖）。
pub fn set_wake_hook(hook: fn()) {
    CONSOLE_WAKE_HOOK.call_once(|| hook);
}

/// 通知「字节已到达」，唤醒可能正在等待的读者。
///
/// **必须在字节真正进入环之后调用**——顺序颠倒会让被唤醒的读者复检时
/// 仍见空环、再次入睡（audio 的 `notify_data_ready` 同款纪律）。
fn notify_data_ready() {
    if let Some(hook) = CONSOLE_WAKE_HOOK.get() {
        hook();
    }
}

// ---------- 节点 ----------

/// console 设备节点（§6.15 P2）。
///
/// 主节点 `/devices/console`：**读端**（`read_at` 取字节）与**写端**
/// （`write_at` 喂字节）共用节点持有的一个 SPSC 环（形态与 `DspNode` 的
/// `ring: Arc<AudioRing>` 同构，S28）。P3（consoled）写、P4 切换后 fd 0
/// 读者读——在切换落地前本节点无任何既有读者，属纯新增（回归零风险）。
/// `status` 子文件如实披露环水位与丢弃计数。
pub struct ConsoleNode {
    ring: Arc<ConsoleRing>,
    children: DynamicDirNode,
}

impl ConsoleNode {
    pub fn new() -> Self {
        let ring = Arc::new(ConsoleRing::new());
        let children = DynamicDirNode::new();
        let status_ring = ring.clone();
        let status_node = DynamicFileNode::read_only(move || {
            let (wp, rp, dropped, writes) = status_ring.snapshot();
            let mut target = VecTarget::new();
            let mut writer = JsonWriter::new(&mut target);
            if let Ok(mut obj) = writer.start_object() {
                let _ = obj.field_u64("write_pos", wp);
                let _ = obj.field_u64("read_pos", rp);
                let _ = obj.field_u64("used", wp.wrapping_sub(rp));
                let _ = obj.field_u64("dropped", dropped);
                let _ = obj.field_u64("writes", writes);
                let _ = obj.field_u64("capacity", CONSOLE_RING_CAPACITY as u64);
                let _ = obj.end();
            }
            let mut bytes = target.into_bytes();
            bytes.push(b'\n');
            bytes
        });
        children.add_child("status", Arc::new(status_node));
        Self { ring, children }
    }
}

impl INode for ConsoleNode {
    /// 从环取走至多 `buf.len()` 字节；空环 `Ok(0)`（终端语义「此刻无字节」，
    /// 非阻塞形态；阻塞由 syscall 层经 `console_stream` 真值接管）。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        Ok(self.ring.read(buf))
    }

    /// consoled 写入字节。**忽略 offset**（字节流无定位语义——终端不是
    /// 随机访问设备）。环满短写 + dropped 计数（理由见模块文档）。
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.ring.write(buf);
        // 先落环后唤醒（顺序颠倒 = 唤醒的读者复检见空环，白醒一轮）。
        if n > 0 {
            notify_data_ready();
        }
        Ok(n)
    }

    /// 本节点是 console 字节流：空读表示「consoled 尚未喂入」而非 EOF，
    /// syscall 层据此接 `CONSOLE_WAITER`（`write_at` → wake 钩子唤醒）。
    fn console_stream(&self) -> bool {
        true
    }

    /// A2 同款声明式能力（S15/S17）：本节点确实暴露 console 字节环——
    /// syscall 层的就绪探针经它读 `used()`（**非消费**）判定，与交付
    /// 路径同源。不 downcast（`INode: Any` 会给 trait 加全局约束，
    /// `as_audio_ring` 同款理由）。
    fn as_console_ring(&self) -> Option<Arc<ConsoleRing>> {
        Some(self.ring.clone())
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
            node_type: INodeType::CharacterDevice,
            // 0777 形态（rw + 遍历 x）：本节点身兼**三个角色**，每个角色
            // 各需一位（S15 一处成文）——
            //   读端（P4 切换后 fd 0）需要 r；
            //   写端（consoled）需要 w：sys_open 对写打开强制求值 WRITE 位
            //   （A1-1 open 强制，syscall.rs「required 由 open 位」），
            //   0555 会让 consoled 的写端被 PermissionDenied 拒掉——
            //   P3 真机验收时发现（S09：设计审查阶段揪出，未浪费一次真机跑）；
            //   status 子文件的**遍历父级**需要 x（A2-3：每级父目录要求 x 位，
            //   0444/0555 均已含 x，但前两位角色要求扩到 0777）。
            // DspNode 是 0666：它没有子文件，不需要遍历位——形态差异如实反映
            // 节点职责差异，不是不一致（S41：新节点直接带上正确形态）。
            permissions: AccessPolicy::from_classic(0o777),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    /// KM17/KM1：字符流不可定位（终端不是随机访问设备）——syscall 层
    /// 据此对非顺序偏移如实报 `IllegalSeek`，不靠 fd 号猜测。
    fn is_seekable(&self) -> bool {
        false
    }

    /// 字符流无截断语义（M17）。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    /// 容器型字符设备（`status` 子文件可达）——与 `InputEventsNode`/
    /// `DspNode` 同型的 `allows_traversal` 覆写（S41：该形态缺陷的教训，
    /// 新节点直接带上）。
    fn allows_traversal(&self) -> bool {
        true
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        self.children.list_dir()
    }
}
