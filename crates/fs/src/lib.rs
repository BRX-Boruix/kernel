//! 真实磁盘文件系统层（C13.1 / C13.2）。
//!
//! 本 crate 只依赖 vfs/klib，**不得**依赖 drv 或 arch——块设备访问经
//! [`ByteDevice`] 最小抽象注入，宿主测试用内存 mock，内核侧由 kernel crate
//! 提供 drv 适配器。MBR 解析（[`mbr`]) 为纯逻辑，EXT2 只读驱动随后落地。

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod block_cache;
pub mod ext2;
pub mod iso9660;
pub mod mbr;

/// 块设备字节读后端最小抽象。
///
/// 语义对齐 driver::IoDevice::read_at：返回实际读取字节数，短读/越界返回
/// 少于请求值或 0。fs 层据此实现重试与边界判定，绝不假设请求必然满足。
pub trait ByteDevice: Send + Sync {
    fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize;
    /// 写字节到后端（M0.2，PRE-1 写桥接）。
    ///
    /// 语义对齐 driver::IoDevice::write_at：返回实际写入字节数，短写/越界
    /// 返回少于请求值或 0。默认返回 0 以兼容既有的只读实现（如宿主 mock
    /// 或未来只读介质）——EXT2 只读挂载阶段不提供写路径，调用方把 0 解释
    /// 为"不可写/短写"而非伪成功。
    fn write_bytes(&self, _offset: u64, _data: &[u8]) -> usize {
        0
    }
    fn byte_len(&self) -> Option<u64>;
}

/// 测试与宿主验证用的内存字节设备。
///
/// fs1 FD4：仅存在于测试域（`#[cfg(test)]`）——内核侧生产编译不含此结构
/// （内核经 DrvByteBridge 注入真实 drv 适配器，从未引用 Mock），宿主测试
/// 由本 crate 的 tests 模块使用。零死代码纪律。
#[cfg(test)]
pub struct MockByteDevice {
    data: spin::Mutex<alloc::vec::Vec<u8>>,
}

#[cfg(test)]
impl MockByteDevice {
    pub fn new(data: alloc::vec::Vec<u8>) -> Self {
        Self {
            data: spin::Mutex::new(data),
        }
    }
}

#[cfg(test)]
impl ByteDevice for MockByteDevice {
    fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize {
        let data = self.data.lock();
        let Ok(off) = usize::try_from(offset) else {
            return 0;
        };
        if off >= data.len() {
            return 0;
        }
        let n = core::cmp::min(out.len(), data.len() - off);
        out[..n].copy_from_slice(&data[off..off + n]);
        n
    }

    fn write_bytes(&self, offset: u64, src: &[u8]) -> usize {
        let mut data = self.data.lock();
        let Ok(off) = usize::try_from(offset) else {
            return 0;
        };
        if off >= data.len() {
            return 0;
        }
        let n = core::cmp::min(src.len(), data.len() - off);
        data[off..off + n].copy_from_slice(&src[..n]);
        n
    }

    fn byte_len(&self) -> Option<u64> {
        Some(self.data.lock().len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    /// M0.2：MockByteDevice 写路径——写读回一致、越界短写、越界读 0。
    #[test]
    fn test_mock_byte_device_write_readback() {
        let dev = Arc::new(MockByteDevice::new(alloc::vec![0u8; 1024]));
        let payload = b"write-through block device";
        // 定位写。
        let n = dev.write_bytes(100, payload);
        assert_eq!(n, payload.len());
        let mut back = [0u8; 64];
        let rn = dev.read_bytes(100, &mut back[..payload.len()]);
        assert_eq!(rn, payload.len());
        assert_eq!(&back[..payload.len()], payload);
        // 越界短写：offset 接近末尾，只写能容纳的部分。
        let tail = [0xABu8; 32];
        let tn = dev.write_bytes(1024 - 10, &tail);
        assert_eq!(tn, 10, "short write at device tail");
        // 越界读返回 0。
        assert_eq!(dev.read_bytes(4096, &mut back), 0);
        // try_from 失败（超大偏移）写返回 0。
        assert_eq!(dev.write_bytes(u64::MAX, &tail), 0);
    }

    // ---------- 块缓存（block_cache）----------

    /// 计数设备：记录 read_bytes/write_bytes 被调用的**真实**次数，
    /// 用于断言缓存确实减少了设备访问（而不是只看结果对不对）。
    struct CountingDevice {
        /// 内部可变性必须用 `spin::Mutex`（与 MockByteDevice 一致）。
        ///
        /// **曾经的缺陷（本轮实测）**：这里原本是裸 `Vec<u8>`，写入经
        /// `self.data.as_ptr() as *mut u8` 的裸指针完成——在 Rust 别名规则下
        /// 是 UB（`&self` 不提供可变性保证），编译器**可以正当地**把后续的
        /// 设备读提升到写之前，于是"写回后设备上是新值"的断言会随机假失败。
        /// 这类假失败会污染对缓存本身的判断，必须消除。
        data: spin::Mutex<alloc::vec::Vec<u8>>,
        reads: core::sync::atomic::AtomicUsize,
        writes: core::sync::atomic::AtomicUsize,
    }

    impl CountingDevice {
        fn new(len: usize) -> Self {
            // 内容取可辨识模式：byte i = (i * 7 + 3) as u8。
            let data = (0..len).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
            Self {
                data: spin::Mutex::new(data),
                reads: core::sync::atomic::AtomicUsize::new(0),
                writes: core::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn reads(&self) -> usize {
            self.reads.load(core::sync::atomic::Ordering::Relaxed)
        }
        fn writes(&self) -> usize {
            self.writes.load(core::sync::atomic::Ordering::Relaxed)
        }
    }

    impl ByteDevice for CountingDevice {
        fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize {
            self.reads.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let data = self.data.lock();
            let Ok(off) = usize::try_from(offset) else { return 0 };
            if off >= data.len() { return 0; }
            let n = core::cmp::min(out.len(), data.len() - off);
            out[..n].copy_from_slice(&data[off..off + n]);
            n
        }
        fn write_bytes(&self, offset: u64, src: &[u8]) -> usize {
            self.writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let mut data = self.data.lock();
            let Ok(off) = usize::try_from(offset) else { return 0 };
            if off >= data.len() { return 0; }
            let n = core::cmp::min(src.len(), data.len() - off);
            data[off..off + n].copy_from_slice(&src[..n]);
            n
        }
        fn byte_len(&self) -> Option<u64> {
            Some(self.data.lock().len() as u64)
        }
    }

    /// 重复读同一区域必须只落盘一次（本轮根治的核心断言）。
    #[test]
    fn test_cache_repeated_read_hits_device_once() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut a = [0u8; 4096];
        let mut b = [0u8; 4096];
        cache.read_bytes(8192, &mut a);
        cache.read_bytes(8192, &mut b);
        assert_eq!(a, b, "same offset must return same bytes");
        // 第一次 4096/512 = 8 块；第二次应全部命中。
        assert_eq!(dev.reads(), 8, "second read must be fully cached");
        assert_eq!(cache.stats().hits(), 8);
        assert_eq!(cache.stats().misses(), 8);
    }

    /// 内容正确性：缓存返回的字节必须与设备本身逐字节一致，
    /// 覆盖**非对齐**偏移（ext2 以 part_start+1024、+group*32 等偏移读）。
    #[test]
    fn test_cache_unaligned_read_matches_device() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let mut direct = [0u8; 3000];
        let n_direct = dev.read_bytes(1024 + 37, &mut direct);
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut via_cache = [0u8; 3000];
        let n_cache = cache.read_bytes(1024 + 37, &mut via_cache);
        assert_eq!(n_direct, n_cache);
        assert_eq!(direct, via_cache, "unaligned read must match device exactly");
    }

    /// 跨块边界读：起点在块内、长度跨多块，首尾只取需要的部分。
    #[test]
    fn test_cache_read_spanning_blocks() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut direct = [0u8; 2000];
        dev.read_bytes(400, &mut direct);
        let mut via = [0u8; 2000];
        let n = cache.read_bytes(400, &mut via);
        assert_eq!(n, 2000);
        assert_eq!(direct, via);
        // 400..2400 覆盖块 0..=4 -> 5 块（另加 1 次直接读）。
        assert_eq!(dev.reads(), 6, "cache must fetch exactly 5 blocks");
    }

    /// 写到**命中**的块：缓存立刻反映新值，且**不落盘**（write-back 的核心收益）。
    /// 显式 flush 后才落盘一次，设备真值与缓存一致。
    #[test]
    fn test_cache_write_back_visible_to_cache() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut buf = [0u8; 512];
        cache.read_bytes(0, &mut buf); // 填充块 0
        let n = cache.write_bytes(100, b"HELLO");
        assert_eq!(n, 5);
        assert_eq!(dev.writes(), 0, "write-back must not touch the device yet");
        let mut back = [0u8; 5];
        cache.read_bytes(100, &mut back);
        assert_eq!(&back, b"HELLO", "cache must reflect own write");
        assert_eq!(cache.dirty_count(), 1);
        let (flushed, dirty) = cache.flush_dirty();
        assert_eq!((flushed, dirty), (1, 0));
        assert_eq!(dev.writes(), 1, "flush must persist exactly once");
        let mut on_dev = [0u8; 5];
        dev.read_bytes(100, &mut on_dev);
        assert_eq!(&on_dev, b"HELLO", "flushed bytes must be on the device");
    }

    /// 写**未命中**的块：必须先把整块读进来再改（否则回写会把未覆盖的字节
    /// 写成 0——伪造数据，S09）。断言未覆盖部分仍是设备真值。
    #[test]
    fn test_cache_write_miss_fetches_block_and_is_readback_consistent() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let truth: alloc::vec::Vec<u8> =
            (0..64 * 1024).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
        let off = 32 * 1024 + 16;
        let payload = [0xABu8; 16];
        let n = cache.write_bytes(off as u64, &payload);
        assert_eq!(n, 16);
        assert_eq!(dev.writes(), 0, "write-back must not touch the device yet");
        let mut b = [0u8; 512];
        assert_eq!(cache.read_bytes((32 * 1024) as u64, &mut b), 512);
        // 期望值 = 设备原内容（同一公式）+ 覆盖的那 16 字节。
        let mut expect = truth[32 * 1024..32 * 1024 + 512].to_vec();
        expect[16..32].copy_from_slice(&payload);
        assert_eq!(
            &b[..],
            &expect[..],
            "read-modify-write must preserve untouched bytes"
        );
        assert_eq!(cache.flush_dirty().1, 0);
        let mut on_dev = [0u8; 512];
        assert_eq!(dev.read_bytes((32 * 1024) as u64, &mut on_dev), 512);
        assert_eq!(&on_dev[..], &expect[..], "flushed block must match device");
    }

    /// 写**整块**（长度恰为 CACHE_BLOCK_BYTES、且块内偏移为 0）且**未命中**时，
    /// **不得**读设备——整块都被覆盖，没有任何「未覆盖字节」需要保留。
    ///
    /// 这条为什么不是微优化（2026-10 机内实测，tools/diskfiles/3p/fswrite.c）：
    /// 数据盘上**追加写**的代价恒为 ~130,000 cycles/**字节**，与调用粒度无关
    /// （64B x 512 次与 16KiB x 2 次都是 ~130k cyc/byte）；而**同偏移覆盖**只要
    /// 680 cyc/byte @4096B、742 cyc/byte 到 /tmp —— 相差约 200 倍。
    /// ⇒ 成本在**新块首次触碰**的设备访问上。ext2 每次 write_block 都是整块写，
    /// 而缓存在未命中时**无条件**先读设备，于是每分配一个新块都白付一条读命令
    /// （ATA PIO 下一条命令 = 数据相位 + wait_drq 轮询，代价与有效命令同量级）。
    #[test]
    fn test_cache_full_block_write_miss_does_not_read_device() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let block = [0x5Au8; block_cache::CACHE_BLOCK_BYTES];
        let n = cache.write_bytes(4096, &block);
        assert_eq!(n, block_cache::CACHE_BLOCK_BYTES);
        assert_eq!(
            dev.reads(),
            0,
            "整块覆盖写不需要读设备（没有未覆盖字节要保留）"
        );
        // 内容仍然正确：写进缓存的必须恰好是这次写的内容（不得被旧设备内容污染）。
        let mut back = [0u8; block_cache::CACHE_BLOCK_BYTES];
        assert_eq!(
            cache.read_bytes(4096, &mut back),
            block_cache::CACHE_BLOCK_BYTES
        );
        assert_eq!(back, block, "整块写的缓存内容必须与写入一致");
        assert_eq!(cache.flush_dirty().1, 0);
        let mut on_dev = [0u8; block_cache::CACHE_BLOCK_BYTES];
        assert_eq!(
            dev.read_bytes(4096, &mut on_dev),
            block_cache::CACHE_BLOCK_BYTES
        );
        assert_eq!(on_dev, block, "回写后设备真值必须与写入一致");
    }

    /// 短读（设备末端）绝不能被缓存成"看似完整的满块"（S19/S09）。
    #[test]
    fn test_cache_tail_short_read_not_cached() {
        // 设备仅 600 字节：块 1 只有 88 字节有效。
        let dev = Arc::new(CountingDevice::new(600));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut out = [0u8; 512];
        let n = cache.read_bytes(512, &mut out);
        assert_eq!(n, 88, "tail read must report true length");
        // 第一次调用：块 1 短读（88 != 512，不缓存）即停止，不再请求块 2
        // —— byte_len 守卫在块 2 起始处（1024 >= 600）提前截断，省掉一条注定
        // 无数据的设备命令。故恰好 1 次设备读。
        assert_eq!(dev.reads(), 1, "must not issue a doomed read past device end");
        // 再读一次：短块未被缓存，必须重新落盘，且仍如实返回 88。
        let mut out2 = [0u8; 512];
        let n2 = cache.read_bytes(512, &mut out2);
        assert_eq!(n2, 88);
        assert_eq!(dev.reads(), 2, "short block must not be cached");
    }

    /// 完全越界的读返回 0，绝不伪造数据（S09）。
    #[test]
    fn test_cache_out_of_range_returns_zero() {
        let dev = Arc::new(CountingDevice::new(4096));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut out = [0u8; 64];
        assert_eq!(cache.read_bytes(1024 * 1024, &mut out), 0);
    }

    /// 直接映射冲突：两块映射同槽时，后读的块正确覆盖；
    /// 先前那个块再读必须重新落盘，**不得返回陈旧数据**。
    #[test]
    fn test_cache_direct_map_conflict_no_stale_data() {
        let dev = Arc::new(CountingDevice::new(8 * 1024 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let blocks = block_cache::CACHE_BLOCK_COUNT as u64;
        let a = 1u64;
        let b = 1u64 + blocks; // 与 a 同槽
        let mut va = [0u8; 512];
        let mut vb = [0u8; 512];
        cache.read_bytes(a * 512, &mut va);
        cache.read_bytes(b * 512, &mut vb);
        let mut va2 = [0u8; 512];
        cache.read_bytes(a * 512, &mut va2);
        assert_eq!(va, va2, "conflicting slot must not serve stale bytes");
        let mut truth = [0u8; 512];
        dev.read_bytes(a * 512, &mut truth);
        assert_eq!(va2, truth);
    }

    /// byte_len 必须透传底层真值（不因缓存而丢失设备长度语义）。
    #[test]
    fn test_cache_byte_len_passthrough() {
        let dev = Arc::new(CountingDevice::new(12345));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        assert_eq!(cache.byte_len(), Some(12345));
    }

    /// 底层无长度能力时必须如实透传 None，绝不编造长度（S09）。
    #[test]
    fn test_cache_len_none_passthrough() {
        struct NoLen;
        impl ByteDevice for NoLen {
            fn read_bytes(&self, _o: u64, _out: &mut [u8]) -> usize { 0 }
            fn byte_len(&self) -> Option<u64> { None }
        }
        let cache = block_cache::CachingByteDevice::new(Arc::new(NoLen));
        assert_eq!(cache.byte_len(), None);
    }

    // ---------- write-back 不变式（淘汰必回写 / 冲刷持久化 / 对抗性交错）----------

    /// 不变式 1（**写触发**淘汰）：脏块被同槽的另一个块挤出前必须先回写设备。
    /// 不回写 = 数据永久丢失（这正是本轮 host 测试抓到的第一个真实缺陷）。
    #[test]
    fn test_write_back_survives_eviction() {
        let dev = Arc::new(CountingDevice::new(8 * 1024 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        // 写块 0 的前 8 字节（未命中 ⇒ 先读整块再改）。
        let payload = [0xA5u8; 8];
        assert_eq!(cache.write_bytes(0, &payload), 8);
        // 用 4096 个不同块填满所有槽位：块 4096 与块 0 同槽，必淘汰块 0。
        let filler = [0x11u8; 512];
        for b in 1..=4096u64 {
            assert_eq!(cache.write_bytes(b * 512, &filler), 512);
        }
        let mut on_dev = [0u8; 8];
        dev.read_bytes(0, &mut on_dev);
        assert_eq!(on_dev, payload, "淘汰脏块必须先回写，否则数据永久丢失");
    }

    /// 不变式 1（**读触发**淘汰）：覆盖另一条淘汰路径（读未命中挤掉脏块）。
    #[test]
    fn test_write_back_survives_read_triggered_eviction() {
        let dev = Arc::new(CountingDevice::new(8 * 1024 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let payload = [0x5Au8; 8];
        assert_eq!(cache.write_bytes(0, &payload), 8);
        let mut sink = [0u8; 512];
        for b in 1..=4096u64 {
            assert_eq!(cache.read_bytes(b * 512, &mut sink), 512);
        }
        let mut on_dev = [0u8; 8];
        dev.read_bytes(0, &mut on_dev);
        assert_eq!(on_dev, payload, "读触发淘汰同样必须先回写");
    }

    /// 显式冲刷：所有脏块必须整体落盘，返回 (成功数, 仍脏数)，仍脏必须为 0。
    #[test]
    fn test_write_back_flush_persists_every_dirty_block() {
        let dev = Arc::new(CountingDevice::new(8 * 1024 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut expect: alloc::vec::Vec<(u64, [u8; 512])> = alloc::vec::Vec::new();
        for b in 0..64u64 {
            let payload = [b as u8; 512];
            assert_eq!(cache.write_bytes(b * 512, &payload), 512);
            expect.push((b, payload));
        }
        assert_eq!(dev.writes(), 0, "write-back must not touch the device yet");
        assert_eq!(cache.dirty_count(), 64);
        let (flushed, dirty) = cache.flush_dirty();
        assert_eq!((flushed, dirty), (64, 0));
        for (b, payload) in expect {
            let mut on_dev = [0u8; 512];
            dev.read_bytes(b * 512, &mut on_dev);
            assert_eq!(on_dev, payload, "块 {} 冲刷后必须持久化", b);
        }
    }

    /// **对抗性测试**（本轮方法学更正的核心）：随机但确定的读/写/冲刷交错，
    /// 在 8 MiB 设备上制造大量同槽冲突与淘汰；缓存读必须始终等于影子真值，
    /// 冲刷后设备对应区域必须等于影子真值，最后整体比对。
    ///
    /// 为什么必须有它：机内实测的失败形态（写回下文件大小对、内容全 0）
    /// 既有的单点测试都没覆盖——它们不制造"写 → 淘汰 → 再读"的交错。
    #[test]
    fn test_write_back_adversarial_interleaved_matches_shadow() {
        const LEN: usize = 8 * 1024 * 1024;
        let mut shadow: alloc::vec::Vec<u8> =
            (0..LEN).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
        let dev = Arc::new(MockByteDevice::new(shadow.clone()));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        let mut rbuf = [0u8; 2048];
        let mut full = alloc::vec![0u8; LEN];
        for step in 0..20_000usize {
            let op = next() % 4;
            let off = next() % (LEN - 4096);
            let len = 1 + next() % 1500;
            match op {
                0 | 1 => {
                    let payload: alloc::vec::Vec<u8> =
                        (0..len).map(|k| ((off + k + step) & 0xFF) as u8).collect();
                    let n = cache.write_bytes(off as u64, &payload);
                    assert_eq!(n, len, "step {}: 写必须被整段接受", step);
                    shadow[off..off + len].copy_from_slice(&payload);
                }
                2 => {
                    let n = cache.read_bytes(off as u64, &mut rbuf[..len]);
                    assert_eq!(n, len, "step {}: 读必须整段服务", step);
                    assert_eq!(
                        &rbuf[..len],
                        &shadow[off..off + len],
                        "step {}: 缓存读与影子真值分叉",
                        step
                    );
                }
                _ => {
                    let (_flushed, dirty) = cache.flush_dirty();
                    assert_eq!(dirty, 0, "step {}: 冲刷后仍有脏块", step);
                    let n = dev.read_bytes(off as u64, &mut rbuf[..len]);
                    assert_eq!(n, len);
                    assert_eq!(
                        &rbuf[..len],
                        &shadow[off..off + len],
                        "step {}: 冲刷后设备与影子真值分叉",
                        step
                    );
                }
            }
        }
        let (_f, dirty) = cache.flush_dirty();
        assert_eq!(dirty, 0, "最终冲刷后不得残留脏块");
        dev.read_bytes(0, &mut full);
        assert_eq!(full, shadow, "最终设备内容必须整体等于影子真值");
    }
}
