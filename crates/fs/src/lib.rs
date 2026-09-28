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
        data: alloc::vec::Vec<u8>,
        reads: core::sync::atomic::AtomicUsize,
        writes: core::sync::atomic::AtomicUsize,
    }

    impl CountingDevice {
        fn new(len: usize) -> Self {
            // 内容取可辨识模式：byte i = (i * 7 + 3) as u8。
            let data = (0..len).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
            Self {
                data,
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
            let Ok(off) = usize::try_from(offset) else { return 0 };
            if off >= self.data.len() { return 0; }
            let n = core::cmp::min(out.len(), self.data.len() - off);
            out[..n].copy_from_slice(&self.data[off..off + n]);
            n
        }
        fn write_bytes(&self, offset: u64, src: &[u8]) -> usize {
            self.writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let Ok(off) = usize::try_from(offset) else { return 0 };
            if off >= self.data.len() { return 0; }
            let n = core::cmp::min(src.len(), self.data.len() - off);
            // 测试专用：设备代表可写介质，经裸指针写入（不引入 Cell 包装）。
            let base = self.data.as_ptr() as *mut u8;
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), base.add(off), n) };
            n
        }
        fn byte_len(&self) -> Option<u64> {
            Some(self.data.len() as u64)
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

    /// 写到**命中**的块必须使缓存反映新值（write-through 的自读一致性）。
    #[test]
    fn test_cache_write_through_visible_to_cache() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        let mut buf = [0u8; 512];
        cache.read_bytes(0, &mut buf); // 填充块 0
        let n = cache.write_bytes(100, b"HELLO");
        assert_eq!(n, 5);
        assert_eq!(dev.writes(), 1, "write must reach the device (write-through)");
        let mut back = [0u8; 5];
        cache.read_bytes(100, &mut back);
        assert_eq!(&back, b"HELLO", "cache must reflect own write");
    }

    /// 写到**未命中**的块不得把它拉进缓存（避免大文件写入污染元数据工作集）。
    #[test]
    fn test_cache_write_miss_does_not_allocate() {
        let dev = Arc::new(CountingDevice::new(64 * 1024));
        let cache = block_cache::CachingByteDevice::new(dev.clone());
        cache.write_bytes(32 * 1024, &[0xAB; 512]);
        let mut b = [0u8; 512];
        cache.read_bytes(32 * 1024, &mut b);
        assert_eq!(dev.reads(), 1, "write must not pre-populate the cache");
        assert_eq!(cache.stats().misses(), 1);
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
}
