//! 块设备读写缓存（性能根治轮）。
//!
//! ## 为什么需要（实测根因，非推测）
//!
//! 用项目已有的遥测（`/devices/storage/primary/status` 的 `sectors_read`）实测：
//!
//! | 场景 | sectors read | 增量 |
//! |---|---|---|
//! | 启动完成 | 13,925 | — |
//! | `ls /`（11 项） | 30,327 | **+7,518 = 3.85 MB** |
//!
//! 一个 11 项的目录列表读 3.85 MB，因为 ATA PIO 下**每个扇区**都要
//! 256 次端口访问（每次是一次 VM exit），且当时 ext2 之上**无块缓存**——
//! 路径解析每一级都重新打盘读同样的元数据块。
//!
//! **时态注**：本节是立项动机的存档，描述的是本模块落地**前**的实测状态；
//! 本模块落地后该陈述自然不再成立，勿把它当作现状引用。
//!
//! ## 为什么放在 fs 层而非 driver 层
//!
//! `fs` 明确不依赖 `drv`/`arch`（见本 crate 模块头），块设备访问只经
//! [`ByteDevice`] 注入。缓存包在这一层：三处接线点
//! （`vfs_init.rs` 的 `cached_bridge_for`）都构造 `Arc<dyn ByteDevice>`，
//! 包在构造处即**全覆盖**，无站点特例；driver 层加缓存则 ramdisk / 未来
//! NVMe 各要一份，职责重叠且易漏。
//!
//! ## 一致性：为什么从 write-through 改成 write-back（写回）
//!
//! 2026-10 实测（原始串口证据见 `docs/TODO/3p.md`）：写直通下 tcc 链接
//! `libc.a`（`shnum = 4049` 个节）耗时 **84.1 秒**。根因不是字循环——
//! `rep insw/outsw` 只快 1.25 倍；时间花在**磁盘操作次数 × 单次等待**
//! （实测每次小写 ~8.9 ms，等 QEMU 的 IDE 仿真，`wait_not_busy` 每次轮询
//! 1,100~2,100 次）。⇒ 唯一的根治是**减少磁盘操作次数**，即写回。
//!
//! 写回的正确性由四条不变式保证（每条都有对应的宿主测试，见
//! `lib.rs` 的 `mod tests`）：
//!
//! 1. **淘汰必回写**：任何槽位被**另一个块**占用前，若它是脏的，必须先把
//!    旧内容写回设备。两条淘汰路径（读触发、写触发）各有一个测试。
//! 2. **写未命中必先读整块**：写只覆盖块内一段时，未覆盖的字节必须来自设备
//!    真值，否则回写会把它们变成 0——那是伪造数据（S09）。
//! 3. **锁外做设备 I/O，装回时校验版本**：槽位带 `seq` 版本号。锁外 I/O
//!    期间槽位若被他人改动，本次安装作废并重试，绝不覆盖更新的内容。
//! 4. **失败绝不静默**：回写短写计入 `writeback_errors` 并**保持脏标志**，
//!    由 [`CachingByteDevice::flush_dirty`] 的返回值与统计如实暴露。
//!
//! **诚实边界（必须一并满足，否则写回就是数据丢失）**：写回把数据留在内存，
//! 因此卸载/关机路径**必须**显式冲刷。`flush_dirty` 有生产调用者
//! （`vfs_init::release_device_cache` 在释放缓存前冲刷）——这是写回的
//! 前提条件，不是可选清理。

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use klib::sync::irq::IrqSpinLock;

use crate::ByteDevice;

/// 缓存块粒度（字节）。
///
/// 取设备扇区大小 512：`ByteDevice` 是**字节**接口，不知道上层 ext2 的
/// `block_size`（1024/2048/4096）；512 是设备层唯一已知的确定粒度
/// （`driver::BlockDevice::block_size` 默认值）。上层读一个 4 KiB 块时会
/// 顺序命中 8 个缓存块，效果等同按块缓存。
pub const CACHE_BLOCK_BYTES: usize = 512;

/// 缓存块数量（4096 x 512 B = 2 MiB）。
///
/// 取值理由（S17）：ext2 元数据工作集远小于此；宿主 RAM 512 MB，2 MiB 占
/// 0.4%，内存代价可忽略。取 2 的幂以便用位掩码取模（避免除法与魔法数）。
pub const CACHE_BLOCK_COUNT: usize = 4096;

/// 空槽哨兵。设备块号不可能取该值：u64::MAX 个 512 B 块 = 8 ZiB，
/// 远超 ATA LBA28 的 2^28 与任何真实设备。
const EMPTY_TAG: u64 = u64::MAX;

/// 单次槽位操作的**最大重试次数**。
///
/// 只在"锁外做设备 I/O 期间槽位被他人改动"时消耗。正常路径（命中、
/// 空槽、无竞争）一次成功。重试耗尽不是静默失败：读路径退化为直接读设备，
/// 写路径退化为直接写设备，且计入 `direct_writes` 统计。
const SLOT_RETRIES: usize = 8;

/// 单个缓存槽。
struct Slot {
    /// 该槽当前缓存的设备块号；`EMPTY_TAG` = 空。
    tag: u64,
    /// 内容是否比设备新（尚未落盘）。
    dirty: bool,
    /// 内容版本号：每次内容变更 +1。
    ///
    /// 用途：锁外做设备 I/O 后重新加锁时，用它判定"槽位是否已被他人改动"。
    /// 只比较 `tag` 不够——同一块被他人重写后 `tag` 不变，但内容已不同，
    /// 直接覆盖会丢掉那次写。
    seq: u64,
    data: Box<[u8; CACHE_BLOCK_BYTES]>,
}

impl Slot {
    fn new() -> Self {
        Self {
            tag: EMPTY_TAG,
            dirty: false,
            seq: 0,
            data: Box::new([0u8; CACHE_BLOCK_BYTES]),
        }
    }
}

/// 槽位内容的快照（在锁内拷出，锁外使用）。
///
/// 用定长数组而非 `Box`：快照在**持锁期间**构造，不能分配内存。
struct Occupant {
    tag: u64,
    dirty: bool,
    seq: u64,
    data: [u8; CACHE_BLOCK_BYTES],
}

/// 缓存统计。**全部是真实计数**，不做任何修饰（诚实性红线）：
/// 命中率低就如实低，绝不因为"加了缓存"就编造改善。
#[derive(Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    /// 写入命中缓存块的次数（写回下不落盘）。
    write_touches: AtomicU64,
    /// 成功写回设备的块数。
    writebacks: AtomicU64,
    /// 写回**失败**（底层短写）的次数。非零即意味着有数据尚未落盘，
    /// 必须由上层如实报告，绝不静默丢弃。
    writeback_errors: AtomicU64,
    /// 因无法缓存而直接落盘的写次数（设备末端短块，或槽位竞争重试耗尽）。
    direct_writes: AtomicU64,
}

impl CacheStats {
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
    pub fn write_touches(&self) -> u64 {
        self.write_touches.load(Ordering::Relaxed)
    }
    pub fn writebacks(&self) -> u64 {
        self.writebacks.load(Ordering::Relaxed)
    }
    pub fn writeback_errors(&self) -> u64 {
        self.writeback_errors.load(Ordering::Relaxed)
    }
    pub fn direct_writes(&self) -> u64 {
        self.direct_writes.load(Ordering::Relaxed)
    }
    /// 命中率（0.0-1.0）。无访问时返回 0.0（不返回 NaN，也不伪造值）。
    pub fn hit_ratio(&self) -> f64 {
        let (h, m) = (self.hits(), self.misses());
        let total = h + m;
        if total == 0 {
            0.0
        } else {
            h as f64 / total as f64
        }
    }
}

/// 缓存表本体（由一把中断安全锁保护）。
struct CacheTable {
    slots: Vec<Slot>,
}

/// 直接映射读写缓存包装器。包裹任意 [`ByteDevice`]。
///
/// **直接映射**（`index = block_no % CACHE_BLOCK_COUNT`）而非 LRU：
/// 无链表、无锁内分配、查找 O(1)。代价是冲突率高于 LRU，但主场景
/// （路径解析重复读同一批小工作集元数据块）冲突极少，足够（S39）。
pub struct CachingByteDevice {
    inner: Arc<dyn ByteDevice>,
    table: IrqSpinLock<CacheTable>,
    stats: CacheStats,
}

impl CachingByteDevice {
    /// 包裹 `inner`。分配 2 MiB 定长槽数组（一次性，挂载期）。
    pub fn new(inner: Arc<dyn ByteDevice>) -> Self {
        let mut slots = Vec::with_capacity(CACHE_BLOCK_COUNT);
        for _ in 0..CACHE_BLOCK_COUNT {
            slots.push(Slot::new());
        }
        Self {
            inner,
            table: IrqSpinLock::new(CacheTable { slots }),
            stats: CacheStats::default(),
        }
    }

    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// 设备块号 -> 槽下标（2 的幂 ⇒ 位掩码，无除法）。
    #[inline]
    fn index_of(block: u64) -> usize {
        (block & (CACHE_BLOCK_COUNT as u64 - 1)) as usize
    }

    /// 设备块号 -> 设备字节偏移。块号是**设备绝对**块号（ext2 传入的
    /// 偏移已含分区起点），读写两侧同一套换算，不存在相对/绝对混用。
    #[inline]
    fn offset_of(block: u64) -> u64 {
        block * CACHE_BLOCK_BYTES as u64
    }

    /// 锁内快照一个非空槽位。
    #[inline]
    fn snapshot(slot: &Slot) -> Occupant {
        let mut data = [0u8; CACHE_BLOCK_BYTES];
        data.copy_from_slice(&slot.data[..]);
        Occupant {
            tag: slot.tag,
            dirty: slot.dirty,
            seq: slot.seq,
            data,
        }
    }

    /// 锁内：若槽位自快照以来未被改动，则把 `block` 装进去。
    ///
    /// 返回是否安装成功。失败意味着槽位已被他人改动，调用方必须**重试**
    /// 而不是覆盖——覆盖会丢掉他人的写（S21 顺序显式化）。
    #[inline]
    fn install_if_unchanged(
        slot: &mut Slot,
        occ: &Option<Occupant>,
        block: u64,
        data: &[u8; CACHE_BLOCK_BYTES],
        dirty: bool,
    ) -> bool {
        let unchanged = match occ {
            None => slot.tag == EMPTY_TAG,
            Some(o) => slot.tag == o.tag && slot.seq == o.seq,
        };
        if unchanged {
            slot.tag = block;
            slot.dirty = dirty;
            slot.seq = slot.seq.wrapping_add(1);
            slot.data.copy_from_slice(data);
        }
        unchanged
    }

    /// **锁外**：把一个块的内容写回底层设备。
    ///
    /// 短写计入 `writeback_errors` 并返回 false——调用方必须**保持脏标志**，
    /// 使数据在后续淘汰或显式冲刷时再次尝试，绝不静默丢弃（S09）。
    fn writeback_block(&self, block: u64, data: &[u8; CACHE_BLOCK_BYTES]) -> bool {
        let n = self.inner.write_bytes(Self::offset_of(block), data);
        if n == CACHE_BLOCK_BYTES {
            self.stats.writebacks.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.stats.writeback_errors.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// 取一个完整缓存块到 `buf`，返回真实读到的字节数（短读如实返回）。
    ///
    /// **锁纪律（S21）**：锁只覆盖查表与拷贝；未命中时在**锁外**读设备。
    /// 若持锁做设备 I/O，缓存自身就变成新的全局串行点——那正是要消灭的东西。
    /// 由于 ATA PIO 下一次块读可能耗时数百微秒甚至更久，这条纪律是硬要求。
    fn fetch_block(&self, block: u64, buf: &mut [u8; CACHE_BLOCK_BYTES]) -> usize {
        let idx = Self::index_of(block);
        let mut miss_counted = false;
        for _ in 0..SLOT_RETRIES {
            let occ: Option<Occupant> = {
                let table = self.table.lock();
                let slot = &table.slots[idx];
                if slot.tag == block {
                    buf.copy_from_slice(&slot.data[..]);
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return CACHE_BLOCK_BYTES;
                }
                if !miss_counted {
                    miss_counted = true;
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                }
                if slot.tag == EMPTY_TAG {
                    None
                } else {
                    Some(Self::snapshot(slot))
                }
            };
            // 锁外读设备。
            let got = self.inner.read_bytes(Self::offset_of(block), buf);
            // 锁外回写被淘汰的脏块（不变式 1：淘汰必回写）。
            if let Some(o) = &occ {
                if o.dirty {
                    self.writeback_block(o.tag, &o.data);
                }
            }
            // 只有整块读全才缓存。短读的块若缓存下去，会把"设备末端数据不完整"
            // 固化成一个看起来正常的满块，后续读再也看不到真实长度（S19/S09）。
            if got != CACHE_BLOCK_BYTES {
                return got;
            }
            let mut table = self.table.lock();
            if Self::install_if_unchanged(&mut table.slots[idx], &occ, block, buf, false) {
                return got;
            }
            // 槽位被他人改动：重试，绝不覆盖更新的内容。
        }
        // 重试耗尽：不缓存，但如实返回设备真值（正确性优先于缓存收益）。
        self.inner.read_bytes(Self::offset_of(block), buf)
    }

    /// 把块内一段字节写入缓存（写回语义）。返回是否**已进缓存**。
    ///
    /// 未命中时必须先把整块读进来（不变式 2：保留未覆盖字节），否则回写会把
    /// 未写到的部分变成 0——那是伪造数据（S09）。返回 false 表示无法缓存
    /// （设备末端短块，或槽位竞争重试耗尽），调用方必须直接落盘。
    fn write_block_part(&self, block: u64, in_block: usize, src: &[u8]) -> bool {
        let idx = Self::index_of(block);
        for _ in 0..SLOT_RETRIES {
            let occ: Option<Occupant> = {
                let mut table = self.table.lock();
                let slot = &mut table.slots[idx];
                if slot.tag == block {
                    // 命中：原地更新并标脏，不落盘（写回的全部收益在此）。
                    slot.data[in_block..in_block + src.len()].copy_from_slice(src);
                    slot.dirty = true;
                    slot.seq = slot.seq.wrapping_add(1);
                    self.stats.write_touches.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                if slot.tag == EMPTY_TAG {
                    None
                } else {
                    Some(Self::snapshot(slot))
                }
            };
            // 锁外取本块内容。
            //
            // **整块覆盖（in_block == 0 且长度恰为一块）时绝不读设备**：整块都被
            // 覆盖，没有任何「未覆盖字节」需要保留，读一次是**纯粹的浪费**。
            // 这不是微优化——2026-10 机内实测（tools/diskfiles/3p/fswrite.c）：
            // 数据盘上的**追加写**恒为 ~130,000 cycles/**字节**，与调用粒度无关
            // （64B x 512 次与 16KiB x 2 次同为 ~130k cyc/byte）；而同偏移覆盖只要
            // 680 cyc/byte @4096B。成本全在**新块首次触碰**的设备访问上，而 ext2
            // 每次 write_block 都是整块写 ⇒ 每分配一个新块都白付一条 ATA PIO 命令
            // （数据相位 + wait_drq 轮询，代价与有效命令同量级）。
            //
            // **前提守卫**：只有「块完整落在设备长度内」才走这条快路。设备长度未知
            // 或块越出设备末端时仍走读路径——那条路径用短读**如实发现**越界，
            // 直接缓存会把一次注定短写的写伪装成成功（S09）。
            let mut buf = [0u8; CACHE_BLOCK_BYTES];
            let full_block = in_block == 0 && src.len() == CACHE_BLOCK_BYTES;
            let within_device = match self.inner.byte_len() {
                Some(len) => Self::offset_of(block) + CACHE_BLOCK_BYTES as u64 <= len,
                None => false,
            };
            if full_block && within_device {
                buf.copy_from_slice(src);
            } else {
                // 部分块：必须先读旧内容，否则回写会把未覆盖字节写成 0（伪造数据，S09）。
                let got = self.inner.read_bytes(Self::offset_of(block), &mut buf);
                if got != CACHE_BLOCK_BYTES {
                    // 设备末端短块：整块化会伪造尾部数据，交给直接写路径。
                    return false;
                }
                buf[in_block..in_block + src.len()].copy_from_slice(src);
            }
            if let Some(o) = &occ {
                if o.dirty {
                    self.writeback_block(o.tag, &o.data);
                }
            }
            let mut table = self.table.lock();
            if Self::install_if_unchanged(&mut table.slots[idx], &occ, block, &buf, true) {
                self.stats.write_touches.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// 把所有脏块落盘。返回 (成功落盘数, 调用结束时仍脏的块数)。
    ///
    /// **失败绝不静默**：写回失败的块保持脏标志（后续淘汰或再次冲刷会重试），
    /// 并计入 `writeback_errors`；调用方应据返回值判断是否真的全部持久化。
    ///
    /// **生产前提**：卸载/关机路径必须调用本方法，否则脏数据随缓存实例消失
    /// ——那是静默丢数据。
    pub fn flush_dirty(&self) -> (usize, usize) {
        let mut flushed = 0usize;
        for idx in 0..CACHE_BLOCK_COUNT {
            for _ in 0..SLOT_RETRIES {
                let occ = {
                    let table = self.table.lock();
                    let slot = &table.slots[idx];
                    if slot.dirty && slot.tag != EMPTY_TAG {
                        Some(Self::snapshot(slot))
                    } else {
                        None
                    }
                };
                let Some(o) = occ else { break };
                if !self.writeback_block(o.tag, &o.data) {
                    // 保持脏：不静默丢弃。
                    break;
                }
                let mut table = self.table.lock();
                let slot = &mut table.slots[idx];
                if slot.tag == o.tag && slot.seq == o.seq {
                    slot.dirty = false;
                    flushed += 1;
                    break;
                }
                // 期间被改写：保持脏，重试。
            }
        }
        (flushed, self.dirty_count())
    }

    /// 当前脏块数（尚未落盘的块）。用于观测与验收，不做修饰。
    pub fn dirty_count(&self) -> usize {
        let table = self.table.lock();
        table
            .slots
            .iter()
            .filter(|s| s.dirty && s.tag != EMPTY_TAG)
            .count()
    }
}

impl ByteDevice for CachingByteDevice {
    /// 按缓存块粒度逐块服务任意 `(offset, len)` 请求。
    ///
    /// **为什么必须支持任意对齐**：ext2 会以非块对齐偏移读（如
    /// `part_start + 1024` 读超级块、`+ group*32` 读组描述符、
    /// inode 表内任意 inode 偏移）。分区起始恒为 512 对齐
    /// （`mbr::PartitionEntry::start_lba` 以扇区计），故块划分有意义。
    ///
    /// 返回真实读到的字节数：任一块短读即停止并返回已读量，
    /// 绝不补零充数（S09）。
    fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize {
        let bs = CACHE_BLOCK_BYTES as u64;
        // 设备长度（若有）：用于**提前截断请求**，避免发出注定读不到数据的
        // 命令。这不是微优化：ATA PIO 下一条注定失败的读命令仍要走完整流程
        // （数据相位 + wait_not_busy 轮询），代价与成功命令同量级。
        let dev_len = self.inner.byte_len();
        let mut done = 0usize;
        let mut block = offset / bs;
        let mut in_block = (offset % bs) as usize;
        let mut buf = [0u8; CACHE_BLOCK_BYTES];
        while done < out.len() {
            if let Some(len) = dev_len {
                if Self::offset_of(block) >= len {
                    break;
                }
            }
            let got = self.fetch_block(block, &mut buf);
            if got <= in_block {
                // 该块在此偏移处已无数据（设备末端/短读）：如实停止。
                break;
            }
            let take = core::cmp::min(out.len() - done, got - in_block);
            out[done..done + take].copy_from_slice(&buf[in_block..in_block + take]);
            done += take;
            block += 1;
            in_block = 0;
        }
        done
    }

    /// 写回（write-back）。
    ///
    /// 写入进缓存并标脏，**不立即落盘**；数据在三种时机落盘：
    /// 1. 槽位被另一个块淘汰时（`fetch_block` / `write_block_part`）；
    /// 2. 显式 [`CachingByteDevice::flush_dirty`]（卸载/关机路径必须调用）；
    /// 3. 无法缓存时直接落盘（设备末端短块、槽位竞争重试耗尽）。
    ///
    /// 返回请求写入的字节数——按 POSIX 语义，写成功不等于已持久化，
    /// 持久化由 flush 保证；本方法**不**把"进了缓存"伪装成"已落盘"。
    /// 只有底层直接写路径真的短写时才如实返回短计数。
    fn write_bytes(&self, offset: u64, data: &[u8]) -> usize {
        let bs = CACHE_BLOCK_BYTES as u64;
        let mut pos = 0usize;
        while pos < data.len() {
            let abs = offset + pos as u64;
            let block = abs / bs;
            let in_block = (abs % bs) as usize;
            let take = core::cmp::min(data.len() - pos, CACHE_BLOCK_BYTES - in_block);
            if self.write_block_part(block, in_block, &data[pos..pos + take]) {
                pos += take;
                continue;
            }
            // 兜底：无法缓存 ⇒ 直接落盘（如实、且可观测），绝不假装进了缓存。
            let n = self.inner.write_bytes(abs, &data[pos..pos + take]);
            self.stats.direct_writes.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                return pos;
            }
            pos += n;
            if n < take {
                return pos;
            }
        }
        pos
    }

    fn byte_len(&self) -> Option<u64> {
        self.inner.byte_len()
    }
}
