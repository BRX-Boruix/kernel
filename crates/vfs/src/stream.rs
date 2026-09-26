//! 键盘事件流的**多读者**层（I-EVENTS P1，ADR-045 阶段 3 前置，§6.15）。
//!
//! 阶段 1/2 的事件环（`arch_x86_64::keyboard` 的 EVQ）是 **SPSC**：单读指针
//! `EVQ_READ`，`pop_event` 是唯一 pop 点。甲-a（consoled 常驻转换者）落地后，
//! 事件流出现**常驻读者**；诊断程序（evsrcdemo 等）也要能打开同一节点而不偷走
//! consoled 的按键——第二个读者与单读指针互相抢占即静默丢事件（§6.14.4b 实核）。
//! 本模块把「多读者」做成事件流的**结构属性**：
//!
//! * **每个读者一把游标**：游标挂在读者自己的 `FileHandle` 上（经
//!   [`EventReaderToken`]，语义恰是「打开期间的读位置」），非阻塞热路径零分配；
//! * **注册表只做一件事**：维护**最慢读者**下界（回收墙）——环满判定必须以
//!   最慢读者为界，否则新事件会覆盖慢读者的未读数据；
//! * **关闭即收敛**：读者关闭后其游标不再参与下界（Weak 注册表：强引用归零
//!   即自动出局，无僵尸条目），读墙推进到新的最慢者。
//!
//! **交付纪律（S09/S15）**：`take` 与 backlog 读路径都**绝不把读墙推进到越过
//! 最慢读者**——快读者只消费自己游标处的记录并前移自己的游标；读墙（全局
//! `EVQ_READ`）由「最慢者下界」单点驱动（`stream_advance_read` 经 Provider）。
//! 否则快读者会偷走慢读者尚未消费的记录（多读者语义破产）。
//!
//! **无全局注入缝**：token 持有自己的 `Provider`（打开时从节点铸造），`take`/
//! 探针/回收全部走自己的 provider——vfs 不依赖 arch_x86_64（KM1 同纪律），
//! 测试注入（FakeProvider）天然成立，不存在「测试忘还原全局态」的跨用例污染
//! （S21）。注册表是唯一的模块级状态，按 `Arc` 身份（ptr_eq）登记——同游标的
//! 两名独立读者各占一条（按值去重会让先关闭者把后读者的下界一并注销）。
//!
//! **与阻塞唤醒的关系**：`IN_EVENT_WAITER` 单槽在多读者下会仲裁失败
//! （Busy → 空读），内核 syscall/task 侧同提交升级为等待者表；非阻塞读者
//! 不依赖唤醒，不受影响。
//!
//! **语义红线（S09）**：记录对每个读者**恰好交付一次**；无人读的记录最终被
//! 流控（环满丢新、`dropped_events` 可见）而非无限积压——与 SPSC 环同族，
//! 差异仅在「丢弃的裁决者」（原：唯一读者；今：最慢读者）。

use crate::devfs::DeviceInfoProvider;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// 事件记录定长（ADR-047 §2.1 布局；与 `arch_x86_64::keyboard` 侧一致，
/// 相等性由 kernel 自检断言——vfs 看不见 arch，单点重述 + 测试闭合）。
pub const EVENT_RECORD_SIZE: usize = 16;

/// 游标：单调递增的记录序号（wrapping），与内核环 EVQ_WRITE/READ 同语义。
type Cursor = u64;

// ---------- 活跃读者注册表（只做最慢下界；Weak 条目，按 Arc 身份登记） ----------

struct ReaderRegistry {
    cursors: RwLock<Vec<Weak<AtomicU64>>>,
}

impl ReaderRegistry {
    const fn new() -> Self {
        Self { cursors: RwLock::new(Vec::new()) }
    }
    /// 最慢读者游标（回收墙裁决者）。顺带清账：强引用归零的条目就地剔除
    /// （Drop 已收敛其游标，不再参与下界；无需显式注销，Drop 与 Registry
    /// 解耦——内核对象删除顺序自由）。表空 → `None`（读墙可推进到写指针）。
    fn slowest(&self) -> Option<Cursor> {
        let mut v = self.cursors.write();
        v.retain(|w| w.strong_count() > 0);
        v.iter().filter_map(|w| w.upgrade())
            .map(|c| c.load(Ordering::Acquire))
            .min()
    }
    /// 登记一名读者（按 Arc 身份去重：dup2 共享同一游标 Arc，重复登记幂等）。
    fn add(&self, c: &Arc<AtomicU64>) {
        let mut v = self.cursors.write();
        if !v
            .iter()
            .any(|w| w.upgrade().map_or(false, |x| Arc::ptr_eq(&x, c)))
        {
            v.push(Arc::downgrade(c));
        }
    }
}

static READERS: ReaderRegistry = ReaderRegistry::new();

/// 活跃读者计数（status 遥测 `stream_readers`：多读者是否真发生，S09 可观察）。
pub fn reader_count() -> u64 {
    READERS.slowest();
    let v = READERS.cursors.read();
    v.len() as u64
}

// ---------- 读者令牌 ----------

/// 读者令牌：挂在 `FileHandle` 上的**读位置**，绑定本节点的 Provider。
///
/// * `Clone` = 共享同一游标与同一 provider（dup2/fork 继承「读走过的就是
///   读走了」的终端语义；注册表按 Arc 身份去重）；
/// * `Drop` = 游标收敛到写指针 + 环读指针回馈到新的最慢者（无 panic 路径；
///   注册表条目随强引用归零自动出局）；
/// * 构造只经 [`open_reader`]（铸造游标 + 登记），保证注册/收敛配平。
pub struct EventReaderToken {
    cursor: Arc<AtomicU64>,
    provider: Arc<dyn DeviceInfoProvider>,
}

impl Clone for EventReaderToken {
    fn clone(&self) -> Self {
        Self {
            cursor: Arc::clone(&self.cursor),
            provider: Arc::clone(&self.provider),
        }
    }
}

impl EventReaderToken {
    /// 非阻塞取走**下一条**整条记录（`rec` 必须 ≥ 16 字节）。
    ///
    /// 交付路径（S15 单点）：peek 本读者游标处 → 推进本读者游标 → 把回收墙
    /// 推进到**新的最慢读者**（快读者绝不越过慢读者——墙的目标恒为最慢者，
    /// 慢读者的未读记录不被回收；全体读者都消费过后墙才前进）。返回 0 =
    /// 本读者游标处暂无记录。
    ///
    /// 槽位有效性：本游标落在 `[读墙, 写指针)` 区间内的槽位**不可能被覆盖**
    /// （生产者流控以最慢读者为界，本游标 ≥ 最慢者），故 peek 命中即完整记录；
    /// 多核撕裂窗由 Provider `stream_peek_event` 返回 `None` 的实现纪律闭合。
    pub fn take(&self, rec: &mut [u8]) -> usize {
        TK_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if rec.len() < EVENT_RECORD_SIZE {
            return 0;
        }
        let cur = self.cursor.load(Ordering::Acquire);
        let mut tmp = [0u8; EVENT_RECORD_SIZE];
        if !self.provider.stream_peek_event(cur, &mut tmp) {
            return 0;
        }
        rec[..EVENT_RECORD_SIZE].copy_from_slice(&tmp);
        TK_BYTES.fetch_add(EVENT_RECORD_SIZE as u64, core::sync::atomic::Ordering::Relaxed);
        // 游标只被本读者链推进（同一 Arc 无第二写者——独立读者各有各的 Arc），
        // 故推进用 Relaxed 足够；Acquire 载入保证看到自己链上的最新值。
        self.cursor.fetch_add(1, Ordering::Relaxed);
        // 读墙回馈：推进到新的最慢读者。没有这一步，常驻读者消费完积压后
        // 墙永不前进，生产者会撞上环满而丢新事件（尽管所有读者都已消费）。
        advance_wall_to_slowest(&self.provider);
        EVENT_RECORD_SIZE
    }

    /// 该读者的当前游标（遥测/阻塞探针/测试用）。
    pub fn cursor(&self) -> u64 {
        self.cursor.load(Ordering::Acquire)
    }

    /// 「本读者游标处是否已有记录」——阻塞路径的**锁内复检探针**（lost-wakeup
    /// 防线）。按**该读者自己的游标**判定而非全局 `has_event`：多读者下环里
    /// 可有被慢读者钉住的记录，全局真值会让快读者复检-重读死循环（§6.13
    /// 同族紧循环）。`cursor < w` 即本读者有新数据（游标单调、wrapping）。
    pub fn has_data(&self) -> bool {
        match self.provider.stream_ring_write_index() {
            Some(w) => self.cursor() < w,
            None => false,
        }
    }
}

/// 把回收墙推进到当前最慢读者（回收「全体读者都已消费」的记录）。
///
/// 快读者绝不偷走慢读者未交付的记录（S09/S15）——墙的目标恒为最慢读者
/// 游标，慢读者在场时墙停在它那里。无读者时不动（Drop 路径里调用时
/// 本读者仍在注册表内——其字段随 drop 体之后才销毁，strong_count ≥ 1，
/// 故 `slowest()` 必含自己；最后一名 Drop 者的游标已收敛到写指针，墙
/// 由此推进到写指针，积压全部可回收）。
fn advance_wall_to_slowest(provider: &Arc<dyn DeviceInfoProvider>) {
    let Some(s) = READERS.slowest() else { return };
    let Some(r) = provider.stream_ring_read_index() else { return };
    let n = s.wrapping_sub(r);
    // 游标/墙同为单调 wrapping 序号：s ≥ r 的合法差必 < 2^63；越界视为
    // 不变量被破坏，不推进（宁可不回收，不可错误回收——S17）。
    if n > 0 && n < (1u64 << 63) {
        provider.stream_advance_read(n);
    }
}

impl Drop for EventReaderToken {
    fn drop(&mut self) {
        // 【P1 缺陷修复（§6.15 r13 真机定位）】临时克隆**不得**收敛。
        //
        // 值语义句柄传递（`ProcessTable::get_fd` 按值克隆 `OpenHandle`，
        // sys_read/write 每次调用都制造一个临时克隆）会让本 Drop 在**每次
        // 系统调用**后触发。若无判别地把共享游标收敛到写指针：唤醒后读者
        // 尚未 take，游标就被弹到写指针、跳过刚到达的记录，读墙随之推进
        // 把它回收——记录凭空蒸发（真机症状：每次唤醒恰好「消费」1 条、
        // TK_BYTES 恒 0、take 恒 PEEK0、demo 零输出）。
        //
        // 判据（Arc 强计数惯用法）：强计数 > 1 = fd 表本体（或并发快照）
        // 仍持引用，本 drop 只是 shrink 掉一份克隆，**不是**读者出局——
        // 直接返回。只有最后一份克隆消失（真实 close/进程退出）才执行
        // 收敛——与类型文档「最后一个克隆消失（close）时游标收敛」逐字
        // 一致（文档如此承诺，初版实现漏了判别）。注册表条目是 Weak，
        // 临时克隆的生灭不影响读者登记；强计数归零时条目自然出局。
        if Arc::strong_count(&self.cursor) > 1 {
            return;
        }
        // 游标收敛到写指针：本读者的未读数据已无人需要（其身份即将消失），
        // 收敛让它不再拖住读墙。注册表条目随强引用归零自动出局（Weak）。
        if let Some(w) = self.provider.stream_ring_write_index() {
            self.cursor.store(w, Ordering::Release);
        }
        // 环读指针回馈：注销（或即将注销）后最慢者可能变化，把新近可达的
        // 部分回收；最后一名读者 Drop 时墙推进到写指针。
        advance_wall_to_slowest(&self.provider);
    }
}

/// 打开一名事件流读者：铸造游标并登记（`provider` 来自节点的
/// `event_stream_reader()` 钩子——语义归节点所有，本函数不猜）。
///
/// 初值 = **读墙**：墙 = min(全体读者游标)（尚未被任何读者消费的最老记录），
/// 故新读者既不重看已回收历史（墙后），也不跳过未消费积压（终端语义
/// 「打开即读到已按键」，与阶段 1/2 的 pop 行为逐位一致）。无读者时墙在
/// 环头，首读者读到全部积压——正是阶段 1/2 单读者的既有行为。
pub fn open_reader(provider: Arc<dyn DeviceInfoProvider>) -> EventReaderToken {
    let cur = provider.stream_ring_read_index().unwrap_or(0);
    let cursor = Arc::new(AtomicU64::new(cur));
    READERS.add(&cursor);
    EventReaderToken { cursor, provider }
}

// ---------- backlog 读者（无句柄语义的 read_at 用） ----------

/// 从**全局读墙**取走下一条记录（`read_at` 的 backlog 语义：「把此刻已投递
/// 的记录一次读走」，`cat`/自检形态）。不注册、不占等待者；读墙推进仍受
/// 最慢读者约束——有句柄读者在场时 backlog 读不到它们游标之后的记录
/// （偷读即违约）。
pub(crate) fn stream_pop_next(
    provider: &Arc<dyn DeviceInfoProvider>,
    rec: &mut [u8],
) -> bool {
    if rec.len() < EVENT_RECORD_SIZE {
        return false;
    }
    let (Some(r), Some(w)) = (
        provider.stream_ring_read_index(),
        provider.stream_ring_write_index(),
    ) else {
        return false;
    };
    // 墙 = min(最慢读者, 写指针)：有句柄读者在场时 backlog 只能消费到
    // 最慢读者的游标为止（偷读其游标之后的记录即违约）；无读者时到写指针。
    let limit = w.min(READERS.slowest().unwrap_or(w));
    if r >= limit {
        return false;
    }
    if !provider.stream_peek_event(r, rec) {
        return false;
    }
    provider.stream_advance_read(1);
    true
}

/// backlog 读路径的**阻塞探针游标**（「下一个 backlog 可读的记录序号」）。
/// 判定与 [`stream_pop_next`] 的可用判据**逐位同源**（S15）：读墙 <
/// `min(最慢读者, 写指针)` 即有 backlog 可读——探针说有，pop 必然 pop 得到；
/// 探针说无，pop 也 pop 不到。环不存在时 `None`。
pub fn backlog_probe_cursor(provider: &Arc<dyn DeviceInfoProvider>) -> Option<u64> {
    let (Some(r), Some(w)) = (
        provider.stream_ring_read_index(),
        provider.stream_ring_write_index(),
    ) else {
        return None;
    };
    let limit = w.min(READERS.slowest().unwrap_or(w));
    (r < limit).then_some(r)
}

/// 遥测（S09 可观察）：当前最慢读者游标（无读者 = `None`）。status JSON 用。
pub fn debug_slowest_cursor() -> Option<u64> {
    READERS.slowest()
}
// ---------- 测试/自检注流与观察 ----------

/// 测试与自检注流：向 provider 的环投递一条记录（真实内核走 IRQ1 同一条
/// `push_event` 环路径——含流控与唤醒；FakeProvider 则注入其仿真环）。
/// 生产路径从不调用本函数。
pub fn test_push_record(
    provider: &Arc<dyn DeviceInfoProvider>,
    rec: &[u8; EVENT_RECORD_SIZE],
) -> bool {
    provider.stream_push_event(rec)
}

/// 观察全局读墙（回收墙下游；测试断言流控用）。环不存在时 `None`。
pub fn test_stream_wall(provider: &Arc<dyn DeviceInfoProvider>) -> Option<u64> {
    provider.stream_ring_read_index()
}

static TK_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TK_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 遥测（S09 可观察）：`take` 累计调用数与交付字节总数（16 的倍数）。
/// status JSON 常设字段（`tk_calls`/`tk_bytes`），供运行期判读读者交付量。
pub fn take_stats() -> (u64, u64) {
    (
        TK_CALLS.load(core::sync::atomic::Ordering::Relaxed),
        TK_BYTES.load(core::sync::atomic::Ordering::Relaxed),
    )
}
