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

    fn byte_len(&self) -> Option<u64> {
        Some(self.data.lock().len() as u64)
    }
}
