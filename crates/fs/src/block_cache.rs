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
//! 256 次 `inw`（每次是一次 VM exit，见 `ata_pio.rs` 原注释），
//! 且 ext2 **无块缓存**——路径解析每一级都重新打盘读同样的元数据块
//! （旁证：一次**失败**的路径查找同样读取 8,884 扇区）。
//!
//! 本模块消除其中的**重复读取**部分。它不改变单次传输的成本
//! （那是 ATA PIO -> AHCI 的事），只保证同一字节不被反复取。
//!
//! ## 为什么放在 fs 层而非 driver 层
//!
//! `fs` 明确不依赖 `drv`/`arch`（见本 crate 模块头），块设备访问只经
//! [`ByteDevice`] 注入。缓存包在这一层：
//! - 三个接线点（`vfs_init.rs` 的 :878/:1321/:1452）都构造
//!   `Arc<dyn ByteDevice>`，包在构造处即**全覆盖**，无站点特例（S15）；
//! - driver 层加缓存则 ramdisk / 未来 NVMe 各要一份，职责重叠且易漏。
//!
//! ## 一致性：为什么是 write-through 而不是 write-back
//!
//! 已核验：ext2 的**所有**写入都汇集到单一 choke point
//! `ByteDevice::write_bytes`（`ext2.rs:757`，:918/:933/:949/:965/:1023 亦经它），
//! 不存在绕过本层的直接盘访问（`vfs_init.rs:790` 的裸 `read_at` 是挂载前的
//! 一次性 MBR 探测，只读、且发生在任何缓存建立之前）。
//!
//! 因此 write-through 在此结构下**可按构造成立**：写直通落盘，命中的副本
//! 同步更新，未命中的不插入（避免写大文件把整盘灌进缓存）。
//!
//! 不用 write-back 的理由：崩电丢失窗口与"不静默丢数据"的诚实性红线冲突，
//! 且 write-back 需要脏页回写机制——本轮收益来自**消除重复读**，
//! 不需要引入这个复杂度（S39 不做无理由的灵活性）。

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
/// 取值理由（S17）：ext2 元数据工作集远小于此（`ls /` 的 3.85 MB 读量
/// **含大量重复**，去重后是数百 KB 量级）；宿主 RAM 512 MB，2 MiB 占 0.4%，
/// 内存代价可忽略。取 2 的幂以便用位掩码取模（避免除法与魔法数）。
pub const CACHE_BLOCK_COUNT: usize = 4096;

/// 空槽哨兵。设备块号不可能取该值：u64::MAX 个 512 B 块 = 8 ZiB，
/// 远超 ATA LBA28 的 2^28 与任何真实设备。
const EMPTY_TAG: u64 = u64::MAX;

/// 单个缓存槽。
struct Slot {
    /// 该槽当前缓存的设备块号；`EMPTY_TAG` = 空。
    tag: u64,
    data: Box<[u8; CACHE_BLOCK_BYTES]>,
}

impl Slot {
    fn new() -> Self {
        Self { tag: EMPTY_TAG, data: Box::new([0u8; CACHE_BLOCK_BYTES]) }
    }
}

/// 缓存统计。**全部是真实计数**，不做任何修饰（诚实性红线）：
/// 命中率低就如实低，绝不因为"加了缓存"就编造改善。
#[derive(Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    /// 因写直通而更新了缓存副本的次数。
    write_touches: AtomicU64,
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

    /// 取一个完整缓存块到 `buf`，返回真实读到的字节数（短读如实返回）。
    ///
    /// **锁纪律（S21）**：锁只覆盖查表与拷贝；未命中时在**锁外**读设备。
    /// 若持锁做设备 I/O，缓存自身就变成新的全局串行点——那正是要消灭的东西。
    /// 由于 ATA PIO 下一次块读可能耗时数百微秒甚至更久，这条纪律是硬要求。
    fn fetch_block(&self, block: u64, buf: &mut [u8; CACHE_BLOCK_BYTES]) -> usize {
        let idx = Self::index_of(block);
        // 快路径：命中。锁仅覆盖比较 + memcpy，随即释放。
        let hit = {
            let table = self.table.lock();
            let slot = &table.slots[idx];
            if slot.tag == block {
                buf.copy_from_slice(&slot.data[..]);
                true
            } else {
                false
            }
        };
        if hit {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return CACHE_BLOCK_BYTES;
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        // 锁外做设备 I/O。
        let off = block * CACHE_BLOCK_BYTES as u64;
        let got = self.inner.read_bytes(off, buf);
        // 只有整块读全才缓存。短读的块若缓存下去，会把"设备末端数据不完整"
        // 固化成一个看起来正常的满块，后续读再也看不到真实长度（S19/S09）。
        if got == CACHE_BLOCK_BYTES {
            let mut table = self.table.lock();
            let slot = &mut table.slots[idx];
            // 仅在槽为空或仍是同块时写入。若锁外期间已被他人换成**不同**块，
            // 那属于更新的内容，丢弃自己这份，绝不用旧副本覆盖新数据。
            if slot.tag == EMPTY_TAG || slot.tag == block {
                slot.tag = block;
                slot.data.copy_from_slice(&buf[..]);
            }
        }
        got
    }

    /// 写直通后更新缓存（仅更新**已存在且同块**的副本）。
    ///
    /// 不插入新块：写大文件时若逐块插入，会把整个文件内容灌进缓存，
    /// 逐出掉真正有用的元数据块（污染），得不偿失。
    fn apply_write(&self, offset: u64, data: &[u8]) {
        let bs = CACHE_BLOCK_BYTES as u64;
        let mut pos = 0usize;
        while pos < data.len() {
            let abs = offset + pos as u64;
            let block = abs / bs;
            let in_block = (abs % bs) as usize;
            let take = core::cmp::min(data.len() - pos, CACHE_BLOCK_BYTES - in_block);
            let idx = Self::index_of(block);
            let mut table = self.table.lock();
            let slot = &mut table.slots[idx];
            if slot.tag == block {
                slot.data[in_block..in_block + take]
                    .copy_from_slice(&data[pos..pos + take]);
                self.stats.write_touches.fetch_add(1, Ordering::Relaxed);
            }
            drop(table);
            pos += take;
        }
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
        // （256 次 inw 的数据相位 + wait_not_busy 轮询），代价与成功命令同量级。
        // ext2 的超级块（偏移 1024）、inode 表尾等读很容易触到盘末端。
        // 无长度能力（None）时退化为按实际短读停止，语义不变（S09 不猜长度）。
        let dev_len = self.inner.byte_len();
        let mut done = 0usize;
        let mut block = offset / bs;
        let mut in_block = (offset % bs) as usize;
        let mut buf = [0u8; CACHE_BLOCK_BYTES];
        while done < out.len() {
            if let Some(len) = dev_len {
                if block * bs >= len {
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

    /// 写直通（write-through）。
    ///
    /// 顺序很关键（S21）：**先落盘、成功后才更新缓存**。
    /// 若先更新缓存再落盘而落盘失败，缓存里就会留下一个设备上没有的值，
    /// 后续读会拿到从未真正持久化的数据——那是典型的"伪造成功"。
    ///
    /// 返回底层真实写入的字节数（短写如实返回，不伪装全量成功）。
    fn write_bytes(&self, offset: u64, data: &[u8]) -> usize {
        let n = self.inner.write_bytes(offset, data);
        if n > 0 {
            self.apply_write(offset, &data[..n]);
        }
        n
    }

    fn byte_len(&self) -> Option<u64> {
        self.inner.byte_len()
    }
}
