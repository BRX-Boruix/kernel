//! 标准流节点（KM1：stdio 并入 fd 表，消除分裂脑）。
//!
//! 此前 fd 0/1/2 是 syscall 层的魔法数字专线：1/2 直通 console、0 直通键盘，
//! 从未装入任何进程的 fd 表——"保留 0/1/2"只是跨 crate 的心照不宣（task1
//! KA4 / kernel1 KM1）。本模块把三条标准流做成**真实 INode**：
//!
//! - fd 0 = [`stdin_handle`]（键盘源，空时 `WouldBlock`，由调度层据此阻塞）
//! - fd 1 = [`stdout_handle`]（console 字节通道，K5 完全体：原始字节直达
//!   字节透明 sink，零销毁）
//! - fd 2 = [`stderr_handle`]（同 stdout sink；二者当前共享同一输出通道）
//!
//! 进程创建时装入 fd 表，syscall 层不再有任何 fd 号特判。
//!
//! ## 分层与注入
//!
//! vfs 保持架构中立：键盘读取与 console 输出经 [`set_stdin_source`] /
//! [`set_stdout_sink`] 函数指针注入（与 panic::set_panic_output、
//! IpcTaskNotifier 同一解耦模式），由内核启动路径接线。未注入时操作如实
//! 返回 `NotSupported`，绝不静默吞数据。stdout 注入目标是 `fn(&[u8])`
//! 字节接口（klib::console::write_bytes）——字节透明性由各 sink 自行声明，
//! 本层不做任何 UTF-8 转换。

use alloc::sync::Arc;
use klib::error::Error;
use spin::Once;

use crate::file_handle::{FileHandle, OpenFlags};
use crate::inode::{FileMetadata, INodeType};
use crate::inode::{INode, Permissions};

/// stdout 单次写入的块大小（与原 syscall 路径一致的分块粒度）。
const STDOUT_CHUNK: usize = 4096;

type StdinSource = fn(&mut [u8]) -> usize;
type StdoutSink = fn(&[u8]);

static STDIN_SOURCE: Once<StdinSource> = Once::new();
static STDOUT_SINK: Once<StdoutSink> = Once::new();

/// 注入键盘源（内核启动路径调用一次）。`src` 返回本次读到的字节数，0 = 暂无输入。
pub fn set_stdin_source(src: StdinSource) {
    let _ = STDIN_SOURCE.call_once(|| src);
}

/// 注入 console 输出通道（内核启动路径调用一次）。
pub fn set_stdout_sink(sink: StdoutSink) {
    let _ = STDOUT_SINK.call_once(|| sink);
}

fn stdin_source() -> Option<StdinSource> {
    STDIN_SOURCE.get().copied()
}

fn stdout_sink() -> Option<StdoutSink> {
    STDOUT_SINK.get().copied()
}

/// 标准流元数据：字符设备、零长度（时间戳 0 = 无文件系统出生时刻，与
/// devfs 设备节点同一约定；权限与各端真实读写能力一致）。
fn stream_metadata(read: bool, write: bool) -> Result<FileMetadata, Error> {
    Ok(FileMetadata {
        size: 0,
        node_type: INodeType::CharacterDevice,
        permissions: Permissions {
            readable: read,
            writable: write,
            executable: false,
            system_only: false,
        },
        created_time: 0,
        modified_time: 0,
        changed_time: 0,
    })
}

// ---------------------------------------------------------------------------
// 节点
// ---------------------------------------------------------------------------

/// 标准输入：键盘字符流的只读端。
pub struct StdinNode;

impl INode for StdinNode {
    /// 审计 B29 语义边界：`buf` 为空（len==0）与"键盘缓冲空"在本层共用
    /// `WouldBlock` 通道，前者偏离 POSIX `read(fd,buf,0)==0`——但该偏差
    /// **经 syscall 层不可达**：sys_read 对 len==0 直接短路交付 0（字节
    /// 透明契约），本层的空缓冲分支只有内核内直调方才会触达；现无此类
    /// 直调方。若未来出现，调用方必须自行先拦 len==0。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        // 字符流没有可定位的"位置"（KM17）；offset 由句柄维护但对 FIFO 无意义。
        let src = stdin_source().ok_or(Error::NotSupported)?;
        let n = src(buf);
        if n == 0 {
            // 缓冲空：以 WouldBlock 交还调用方——调度层据此登记唯一等待者
            // 并阻塞切走（KM15/K1a 语义在 syscall 层落地）。
            return Err(Error::WouldBlock);
        }
        Ok(n)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::PermissionDenied)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        stream_metadata(true, false)
    }

    fn is_seekable(&self) -> bool {
        false
    }

    fn interactive_input(&self) -> bool {
        true
    }
}

/// 标准输出 / 标准错误：console 字节流的只写端（K5 完全体：字节透明）。
pub struct StdoutNode;

impl INode for StdoutNode {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::PermissionDenied)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        let sink = stdout_sink().ok_or(Error::NotSupported)?;
        // 原始字节分块直发——本层零转换。文本介质的 lossy 是 sink 侧
        // （Console::write_bytes 缺省实现）的固有约束，不再是数据路径决策。
        let mut off = 0usize;
        while off < buf.len() {
            let n = core::cmp::min(buf.len() - off, STDOUT_CHUNK);
            sink(&buf[off..off + n]);
            off += n;
        }
        Ok(buf.len())
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        stream_metadata(false, true)
    }

    fn is_seekable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// 句柄构造（进程创建时装入 fd 表 0/1/2 槽位）
// ---------------------------------------------------------------------------

/// fd 0：标准输入句柄（只读）。
pub fn stdin_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdinNode), OpenFlags::READ_ONLY)
}

/// fd 1：标准输出句柄（只写）。
pub fn stdout_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode), OpenFlags::WRITE_ONLY)
}

/// fd 2：标准错误句柄（只写；当前与 stdout 共享 console 通道）。
pub fn stderr_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode), OpenFlags::WRITE_ONLY)
}
