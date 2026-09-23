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
use crate::inode::{AccessPolicy, INode};

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
        // A1-1：经典三段同值（读写端能力如实披露；无执行语义）。
        permissions: AccessPolicy::from_classic({
            let mut m = 0o444;
            if write { m |= 0o222; }
            m
        }),
        created_time: 0,
        modified_time: 0,
        changed_time: 0,
    })
}

// ---------------------------------------------------------------------------
// 节点
// ---------------------------------------------------------------------------

/// 标准输入：键盘字符流的只读端。
///
/// **J-TOKEN-B（ADR-044 §1.3）**：本节点现持有 `owner`——即**当前持有该
/// console 令牌的 pid**（`0` = 无主/未知）。
///
/// **为何是「节点持 owner」而不是拆全局单例**（实核更正）：本节点**从来不是
/// 单例**——`stdin_handle()` 每次都 `Arc::new` 新建（见下方句柄构造节）。
/// 故本项是**把无状态单元结构体改为持 owner 的节点**，让「每打开实例一份
/// owner」真正有地方放；不是把某个共享对象拆开。
///
/// **owner 由谁改**：内核**不隐式更新**（ADR-044 §1.4 / ADR-043 决策 2a）。
/// 用户态经既有路径决定谁持令牌、何时移交（J-TOKEN-C 策略层）。
pub struct StdinNode {
    /// 当前持有本 console 令牌的 pid；`0` = 无主/未知（S17 安全侧默认）。
    owner: u64,
}

impl StdinNode {
    /// 无主的标准输入节点（向后兼容既有调用点；行为与改造前一致）。
    pub fn new() -> Self {
        Self { owner: 0 }
    }

    /// 指定 owner 的标准输入节点（J-TOKEN-B：console 令牌的落点）。
    pub fn with_owner(owner: u64) -> Self {
        Self { owner }
    }
}

impl Default for StdinNode {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// A5：字符设备判型零成本。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    fn interactive_input(&self) -> bool {
        true
    }

    /// A2：stdin 的空读同样满足"应当睡眠"的通用语义（等待源为 PS/2 键盘中断）。
    /// 两个方法都返回 true 是**如实**的：语义确有重叠，但来源不同——
    /// `interactive_input` 描述"是谁"，`blocks_when_empty` 描述"怎么办"。
    fn blocks_when_empty(&self) -> bool {
        true
    }
    /// ADR-044 §1.2（J-TOKEN-A）：stdin 是**终端**（键盘 + console）。
    fn is_terminal(&self) -> bool {
        true
    }
    /// ADR-044 §1.3（J-TOKEN-B）：本 console 令牌的持有者（节点自述，S15）。
    ///
    /// 用户态经既有 stat/fstat 读到本值；`0` = 无主/未知。
    fn console_owner(&self) -> u64 {
        self.owner
    }
}

/// 标准输出 / 标准错误：console 字节流的只写端（K5 完全体：字节透明）。
///
/// **J-TOKEN-B（ADR-044 §1.3）**：持 `owner`，语义同 [`StdinNode`]。
/// 输出权与输入权是**同一个 console 对象**的两端，故 owner 概念共用；
/// 但当前实现**不做**「输入 owner 与输出 owner 必须一致」的强制——
/// 用户态可分别持有（ADR-043 §2.1 把该策略留给用户态）。
pub struct StdoutNode {
    /// 当前持有本 console 输出令牌的 pid；`0` = 无主/未知。
    owner: u64,
}

impl StdoutNode {
    /// 无主的标准输出节点（向后兼容既有调用点）。
    pub fn new() -> Self {
        Self { owner: 0 }
    }

    /// 指定 owner 的标准输出节点。
    pub fn with_owner(owner: u64) -> Self {
        Self { owner }
    }
}

impl Default for StdoutNode {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// A5：字符设备判型零成本。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }
    /// ADR-044 §1.2（J-TOKEN-A）：stdout 是**终端**。
    ///
    /// **诚实边界**：本节点被 fd 1/2 共用（stderr 见 `stderr_handle`）。
    /// 当前实现下 fd 1/2 **永远是本节点**（重定向只经 `dup2` 换成别的节点，
    /// 换掉后 `is_terminal()` 就是那个新节点的真值——这正是本设计的意义：
    /// 终端性跟着**节点**走，不跟着 fd 号走）。
    fn is_terminal(&self) -> bool {
        true
    }
    /// ADR-044 §1.3（J-TOKEN-B）：本 console 输出令牌的持有者（节点自述）。
    fn console_owner(&self) -> u64 {
        self.owner
    }
}

// ---------------------------------------------------------------------------
// 句柄构造（进程创建时装入 fd 表 0/1/2 槽位）
// ---------------------------------------------------------------------------

/// fd 0：标准输入句柄（只读）。
///
/// `expect` 断言的是结构不变式：StdinNode::metadata 恒 Ok（字面量构造，
/// 无错误路径），`FileHandle::new` 的 Result 化（vfs1 M3/M4）不为其引入
/// 可达失败分支。若未来该不变式被破坏，此处 panic 即契约违反的诚实暴露。
pub fn stdin_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdinNode::new()), OpenFlags::READ_ONLY)
        .expect("stdin stream metadata is structurally infallible")
}

/// fd 1：标准输出句柄（只写）。不变式论证同 [`stdin_handle`]。
pub fn stdout_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode::new()), OpenFlags::WRITE_ONLY)
        .expect("stdout stream metadata is structurally infallible")
}

/// fd 2：标准错误句柄（只写；当前与 stdout 共享 console 通道）。
pub fn stderr_handle() -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode::new()), OpenFlags::WRITE_ONLY)
        .expect("stderr stream metadata is structurally infallible")
}

// ---------------------------------------------------------------------------
// J-TOKEN-B：带 owner 的标准流句柄（ADR-044 §1.3）
//
// **与上面三个的区别**：上面是「无主」句柄（owner=0），行为与改造前完全一致，
// 供既有调用点继续使用；下面三者为 console 令牌的**落点**——调用方在创建
// 标准流时把「谁持令牌」写进节点。
//
// **为何不需要新通道**（ADR-044 §0.1）：`FileHandle` 已持 `Arc<dyn INode>`，
// 「每个打开实例一份 owner」天然就是节点的一个字段，不需要额外映射或同步机制。
//
// **内核不隐式更新 owner**（ADR-044 §1.4）：本函数只**照调用方给的 pid 落笔**，
// 不做「谁读键盘谁是前台」的推断（ADR-043 决策 2a 拒绝隐式魔法）。
// ---------------------------------------------------------------------------

/// fd 0（带 owner）：标准输入句柄，owner = `owner`。
pub fn stdin_handle_owned(owner: u64) -> FileHandle {
    FileHandle::new(Arc::new(StdinNode::with_owner(owner)), OpenFlags::READ_ONLY)
        .expect("stdin stream metadata is structurally infallible")
}

/// fd 1（带 owner）：标准输出句柄，owner = `owner`。
pub fn stdout_handle_owned(owner: u64) -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode::with_owner(owner)), OpenFlags::WRITE_ONLY)
        .expect("stdout stream metadata is structurally infallible")
}

/// fd 2（带 owner）：标准错误句柄，owner = `owner`。
pub fn stderr_handle_owned(owner: u64) -> FileHandle {
    FileHandle::new(Arc::new(StdoutNode::with_owner(owner)), OpenFlags::WRITE_ONLY)
        .expect("stderr stream metadata is structurally infallible")
}

