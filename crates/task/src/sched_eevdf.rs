//! EEVDF 就绪队列：按 vruntime 排序的**最小堆**（SCHED-EEVDF-2）。
//!
//! ## 为什么是堆而不是红黑树（S32：先定判据再看数据）
//!
//! EEVDF 的就绪队列只需要两个操作：
//!   - **插入**一个 (pid, vruntime)；
//!   - **取出 vruntime 最小者**。
//!
//! **不需要**前驱/后继、区间查询、按 key 删除以外的任何有序结构能力。
//! 红黑树为这些额外能力付出了旋转 + 着色不变式的复杂度（原评估提到的「417 行」
//! 正是这类实现）。最小堆：插入 O(log n) 上浮、取最小 O(log n) 下沉，常数更小、
//! 不变式只有一条（父 ≤ 子），失败面显著更窄。
//!
//! 且本队列**有意不做**「按 pid 任意删除」——删除通过惰性方式处理（见 [`remove`]
//! 与调度器的 `exclude` 语义），避免在下标堆里实现 O(n) 定位 + 修复。
//!
//! ## 溢出与饱和（S19：不静默回绕）
//!
//! vruntime 是累加量，理论上有溢出可能。全部累加走 [`vruntime_add`]：饱和到
//! `u64::MAX` 而非回绕。回绕会让「跑了很久的进程」突然变成 vruntime 最小者、
//! 从而被无限优先调度——这是必须防的正确性问题，不是理论洁癖。
//!
//! ## 锁语义（S21）
//!
//! 本类型**自身不持锁**：它总是被包在调用方的 per-CPU `RUN[slot]` 锁域内使用。
//! 这样避免「锁中锁」与锁序问题——调度器已有的锁序（pid → RUN[slot]）保持不变。

use alloc::vec::Vec;

/// 就绪队列条目：(pid, vruntime)。
pub type Entry = (usize, u64);

/// 按 vruntime 排序的最小堆就绪队列。
///
/// 不变式：对任意 `i > 0`，`heap[parent(i)].1 <= heap[i].1`。
#[derive(Default)]
pub struct VruntimeQueue {
    /// 隐式二叉堆（下标 0 为根 = vruntime 最小者）。
    heap: Vec<Entry>,
}

/// vruntime 加法：饱和不回绕（S19）。
///
/// **为什么必须饱和**：vruntime 是跨进程比较的**排序键**。若回绕，一个运行极久
/// 的进程会突然拥有极小的 vruntime，从而被反复优先调度，饿死其它进程——这是
/// 静默的调度不公平，比崩溃更难发现。饱和到 `u64::MAX` 的语义是「最不值得再
/// 调度」，方向正确。
#[inline]
pub fn vruntime_add(base: u64, delta: u64) -> u64 {
    base.saturating_add(delta)
}

// ---------- SCHED-EEVDF-3：nice -> 权重 ----------

/// nice 0 的基准权重（对齐 Linux CFS 的 `NICE_0_LOAD`，便于对照其既有数据）。
pub const NICE_0_WEIGHT: u64 = 1024;

/// 权重表：nice -20..=19 共 40 档，**索引 = nice + 20**。
///
/// **为什么用查表而不是公式**：
///   1. 逐档可直接审阅，不存在「浮点/幂运算在 no_std 下的精度与确定性」问题；
///   2. 调度路径上是一次数组索引，无乘除（`weight_charge` 里那一次除法是必须的
///      折算，属不可避免）；
///   3. 数值取自 Linux CFS 的 `sched_prio_to_weight[]`——**采用业已广泛验证的
///      取值**比自创一套曲线更可辩护，也使本实现的行为可与既有 EEVDF/CFS 资料对照。
///
/// 单调性由测试 `test_sched_eevdf3_nice_weights` 断言（权重随 nice 递减）。
const WEIGHT_TABLE: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, // nice -20..-16
    29154, 23254, 18705, 14949, 11916, // nice -15..-11
    9548, 7620, 6100, 4904, 3906, // nice -10..-6
    3121, 2501, 1991, 1586, 1277, // nice -5..-1
    1024, // nice 0
    820, 655, 526, 423, // nice 1..4
    335, 272, 215, 172, // nice 5..8
    137, 110, 87, 70, // nice 9..12
    56, 45, 36, 29, // nice 13..16
    23, 18, 15, // nice 17..19
];

/// nice（-20..=19）-> 权重。超范围**钳制**到边界（S18：不 panic、不静默错值）。
///
/// 钳制而非报错：nice 来自用户态，越界输入不应能打挂内核；
/// 钳到最近合法档是「最接近用户意图」的确定性行为。
#[inline]
pub fn nice_to_weight(nice: i32) -> u64 {
    let idx = (nice + 20).clamp(0, 39) as usize;
    WEIGHT_TABLE[idx]
}

/// vruntime 的**定点缩放因子**（2^20）。
///
/// ## 为什么必须缩放（这是一个真实缺陷的修复，不是洁癖）
///
/// 朴素写法 `delta = elapsed * NICE_0_WEIGHT / weight` 在**整数除法**下有致命截断：
/// 当 `weight > NICE_0_WEIGHT`（即高优先级，如 nice=-20 的 88761）时，
/// `1 * 1024 / 88761 == 0` —— **每个 tick 记账为 0**。
///
/// 后果是**饿死全部其它进程**：一个 nice=-20 的进程 vruntime 永远停在原值，
/// 永远是最小者，永远被优先选中，其它进程再也拿不到 CPU。
///
/// 实测暴露：`nice=-20` 进程跑 10 个 tick 后 `vt=0`，而 `nice=0` 的对照是 `vt=10`。
/// 这个 0 看着「像高优先级的正确表现」，实则是截断错误——**必须靠质疑可疑数值**
/// 才能发现，功能测试不会报错。
///
/// 修复：把 vruntime 记在**放大 2^20 的定点单位**里。
const VRUNTIME_SHIFT: u32 = 20;

/// 定点单位下的基准权重（`NICE_0_WEIGHT << VRUNTIME_SHIFT`）。
const SCALED_NICE_0_WEIGHT: u64 = NICE_0_WEIGHT << VRUNTIME_SHIFT;

/// 按权重折算 `elapsed` 个 tick 对应的 vruntime 增量（**定点**）。
///
/// 公式：`delta = elapsed * (NICE_0_WEIGHT << SHIFT) / weight`。
///
/// 先乘后除（`u128` 中间量），使商在权重高达 88761 时仍 >= 1：
/// `1 * (1024 << 20) / 88761 == 12090`，远大于 0，**不再截断**。
///
/// **方向（易写反，故测试钉死）**：权重越大 → `delta` 越小 → vruntime 增长越慢
/// → 越常被选中 → 分到更多 CPU。故「高优先级」= 高权重 = nice 小。
///
/// 边界：`weight == 0` 时按 `NICE_0_WEIGHT` 处理（防除零）；末端饱和到
/// `u64::MAX`（S19：不静默回绕）。
///
/// **量纲说明**：返回值是定点单位（1 个 tick 在 nice=0 下 = 2^20）。
/// 内部比较只看相对大小，故量纲不影响正确性。
#[inline]
pub fn weight_charge(elapsed_ticks: u64, weight: u64) -> u64 {
    let w = if weight == 0 { NICE_0_WEIGHT } else { weight };
    let v = (elapsed_ticks as u128) * (SCALED_NICE_0_WEIGHT as u128) / (w as u128);
    if v > u64::MAX as u128 { u64::MAX } else { v as u64 }
}

impl VruntimeQueue {
    /// 新建空队列（`const`，可作 static 初始化）。
    pub const fn new() -> Self {
        Self { heap: Vec::new() }
    }

    /// 队列长度。
    #[inline]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// 是否为空。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// 是否已含某 pid（O(n)，仅用于调度器的「避免重复入队」判定）。
    #[inline]
    pub fn contains(&self, pid: usize) -> bool {
        self.heap.iter().any(|e| e.0 == pid)
    }

    /// 遍历所有 pid（顺序不保证；供诊断与既有 `retain`/`any` 语义复用）。
    pub fn iter_pids(&self) -> impl Iterator<Item = usize> + '_ {
        self.heap.iter().map(|e| e.0)
    }

    /// 插入或更新一个进程的 vruntime。
    ///
    /// **同 pid 重复入队会被收敛为一条**（取较小 vruntime）：重复条目会让同一
    /// 进程被调度两次，破坏「取最小者」语义并造成不公平。语义上是 upsert。
    pub fn insert(&mut self, pid: usize, vruntime: u64) {
        if let Some(i) = self.heap.iter().position(|e| e.0 == pid) {
            // 已存在：更新为更小的 vruntime（更值得调度），并修复堆。
            if vruntime < self.heap[i].1 {
                self.heap[i].1 = vruntime;
                self.sift_up(i);
            }
            return;
        }
        self.heap.push((pid, vruntime));
        self.sift_up(self.heap.len() - 1);
    }

    /// 取出并返回 vruntime 最小者；空队列返回 `None`（**绝不 panic**）。
    ///
    /// 平局（vruntime 相等）时按 pid 升序——保证确定性，使并发下的调度决策
    /// 可复现（否则相同输入可能产生不同调度顺序，测试无法稳定判定）。
    pub fn pop_min(&mut self) -> Option<Entry> {
        if self.heap.is_empty() {
            return None;
        }
        let last = self.heap.len() - 1;
        self.heap.swap(0, last);
        let out = self.heap.pop();
        if !self.heap.is_empty() {
            self.sift_down(0);
        }
        out
    }

    /// 查看最小者但不移除。
    #[inline]
    pub fn peek_min(&self) -> Option<Entry> {
        self.heap.first().copied()
    }

    /// 移除指定 pid（惰性语义：O(n) 定位 + 修复）。返回是否确实移除。
    ///
    /// **为什么不用懒惰标记**：调度器在 `exclude`/跨核 reap 场景需要「立刻」从
    /// 队列移除，留下已死 pid 会在下一次 pop 时才被发现，其间它可能已被计入
    /// 「还有别的就绪者」判定，导致错误地不切换（A3 类竞态的死灰复燃）。
    /// 队列长度是就绪进程数级（数十~数百），O(n) 完全可接受。
    pub fn remove(&mut self, pid: usize) -> bool {
        let Some(i) = self.heap.iter().position(|e| e.0 == pid) else {
            return false;
        };
        let last = self.heap.len() - 1;
        self.heap.swap(i, last);
        self.heap.pop();
        if i < self.heap.len() {
            // 交换后 i 处可能是新的较大或较小值，两侧都尝试修复。
            self.sift_up(i);
            self.sift_down(i);
        }
        true
    }

    /// 保留满足谓词的条目（复用既有 `retain` 调用点的语义）。
    pub fn retain<F: FnMut(usize) -> bool>(&mut self, mut f: F) {
        self.heap.retain(|e| f(e.0));
        self.rebuild();
    }
    
    /// 清空。
    pub fn clear(&mut self) {
        self.heap.clear();
    }

    /// 读取某 pid 的 vruntime（不存在返回 None）。
    pub fn vruntime_of(&self, pid: usize) -> Option<u64> {
        self.heap.iter().find(|e| e.0 == pid).map(|e| e.1)
    }

    /// 就绪队列中最小的 vruntime（用于 EEVDF 的「最小 vruntime 基准」）。
    #[inline]
    pub fn min_vruntime(&self) -> Option<u64> {
        self.heap.first().map(|e| e.1)
    }

    /// 重建堆不变式（`retain` 后调用）。
    fn rebuild(&mut self) {
        if self.heap.len() < 2 {
            return;
        }
        for i in (0..self.heap.len() / 2).rev() {
            self.sift_down(i);
        }
    }

    /// 比较：vruntime 小者优先；平局按 pid 升序（确定性）。
    #[inline]
    fn less(a: Entry, b: Entry) -> bool {
        (a.1, a.0) < (b.1, b.0)
    }

    /// 上浮：把下标 i 的元素向根方向移动到正确位置。
    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if Self::less(self.heap[i], self.heap[parent]) {
                self.heap.swap(i, parent);
                i = parent;
            } else {
                break;
            }
        }
    }

    /// 下沉：把下标 i 的元素向叶方向移动到正确位置。
    fn sift_down(&mut self, mut i: usize) {
        let n = self.heap.len();
        loop {
            let l = 2 * i + 1;
            let r = 2 * i + 2;
            let mut smallest = i;
            if l < n && Self::less(self.heap[l], self.heap[smallest]) {
                smallest = l;
            }
            if r < n && Self::less(self.heap[r], self.heap[smallest]) {
                smallest = r;
            }
            if smallest == i {
                break;
            }
            self.heap.swap(i, smallest);
            i = smallest;
        }
    }
}