//! 真实磁盘文件系统层（C13.1 / C13.2）。
//!
//! 本 crate 只依赖 vfs/klib，**不得**依赖 drv 或 arch——块设备访问经
//! [`ByteDevice`] 最小抽象注入，宿主测试用内存 mock，内核侧由 kernel crate
//! 提供 drv 适配器。MBR 解析（[`mbr`]) 为纯逻辑，EXT2 只读驱动随后落地。

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod ext2;
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
}
