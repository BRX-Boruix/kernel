//! 打开文件句柄（FileHandle）与打开标志（OpenFlags）（ADR-011 方案 A）。

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use klib::error::Error;

use crate::inode::{FileMetadata, INode};

/// 打开标志。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
    pub directory: bool,
    /// FLAG_PIPE（ADR-014 §4.1）：配合空路径，经 `SYS_STREAM_CREATE` 分配
    /// 一对匿名管道流句柄，而非打开文件节点。
    pub pipe: bool,
    /// FLAG_CLOEXEC（3P4-3）：本 fd 在 **exec 派生新映像时不继承**（POSIX
    /// `FD_CLOEXEC` 语义）。位分配 = bit 7（见 `from_bits`/`to_bits`）。
    ///
    /// 为什么需要它：没有它，父进程为内部用途打开的管道/文件端会被每个子进程
    /// 继承并持住引用——父进程关闭写端后，**子进程仍持有写端**，读端永远读不到
    /// EOF（管道场景的经典死锁）。这是 fd 泄漏在语义层面的表现，不只是资源浪费。
    ///
    /// 归属：这是**每 fd** 的标志（不是每"打开文件描述"），本系统每个 fd 槽各自
    /// 持一份 `OpenHandle`（`dup2` 值拷贝标志、共享偏移），故放在这里即可。
    pub cloexec: bool,
    /// FLAG_EXCL（O_EXCL）：**独占创建**——`create` 与 `exclusive` 同时置位时，
    /// 若路径已存在则 open 以 `AlreadyExists`（EEXIST）失败，绝不打开已有文件。
    /// 位分配 = bit 8（用户侧同一事实见 `libsys::io::OpenFlags`，线格式单点解码在
    /// `kernel::syscall::sys_open`）。
    ///
    /// 语义归属：**判定必须与创建在同一 syscall 内完成**，否则用户态只能「先 stat
    /// 再 create」，两步之间的 TOCTOU 窗口会让 `mkstemp` 类调用互相覆盖临时文件。
    /// 故本标志的解释点在 sys_open（内核侧），而不是用户态。
    pub exclusive: bool,
}

impl OpenFlags {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        create: false,
        truncate: false,
        append: false,
        directory: false,
        pipe: false,
        cloexec: false,
        exclusive: false,
    };

    pub const WRITE_ONLY: Self = Self {
        read: false,
        write: true,
        create: false,
        truncate: false,
        append: false,
        directory: false,
        pipe: false,
        cloexec: false,
        exclusive: false,
    };

    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: false,
        directory: false,
        pipe: false,
        cloexec: false,
        exclusive: false,
    };

    pub const CREATE_OR_TRUNCATE: Self = Self {
        read: true,
        write: true,
        create: true,
        truncate: true,
        append: false,
        directory: false,
        pipe: false,
        cloexec: false,
        exclusive: false,
    };

    /// 追加写（O_APPEND 语义）：每次 write 的落点锚定当前真实大小。
    pub const READ_WRITE_APPEND: Self = Self {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: true,
        directory: false,
        pipe: false,
        cloexec: false,
        exclusive: false,
    };

    pub const fn to_bits(self) -> u32 {
        let mut bits = 0;
        if self.read {
            bits |= 1 << 0;
        }
        if self.write {
            bits |= 1 << 1;
        }
        if self.create {
            bits |= 1 << 2;
        }
        if self.truncate {
            bits |= 1 << 3;
        }
        if self.append {
            bits |= 1 << 4;
        }
        if self.directory {
            bits |= 1 << 5;
        }
        if self.pipe {
            bits |= 1 << 6;
        }
        if self.cloexec {
            bits |= 1 << 7;
        }
        if self.exclusive {
            bits |= 1 << 8;
        }
        bits
    }

    /// 按位解码打开标志。
    ///
    /// KD7 成文策略（宽松掩码）：`bits` 中不属于本 ABI 的未知高位被**静默
    /// 忽略**（逐位提取，不做 EINVAL）。这是有意选择而非疏漏——标志集随内核
    /// 版本演进，旧二进制携带新内核不认识的位不应导致打开失败；调用方如需
    /// 严格校验可先经 [`Self::to_bits`] 往返比对丢弃的位。位分配见 [`Self::to_bits`]。
    pub const fn from_bits(bits: u32) -> Self {
        Self {
            read: (bits & (1 << 0)) != 0,
            write: (bits & (1 << 1)) != 0,
            create: (bits & (1 << 2)) != 0,
            truncate: (bits & (1 << 3)) != 0,
            append: (bits & (1 << 4)) != 0,
            directory: (bits & (1 << 5)) != 0,
            pipe: (bits & (1 << 6)) != 0,
            cloexec: (bits & (1 << 7)) != 0,
            exclusive: (bits & (1 << 8)) != 0,
        }
    }
}

/// 进程打开文件句柄（持有底层 INode + 独立读写偏移量 offset + 打开标志）。
///
/// `Clone` 供 `dup2`/spawn fd 继承共享同一文件描述（`Arc<dyn INode>` 与
/// `AtomicU64 offset` 共享，`OpenFlags` 值拷贝）——Unix dup2 语义：副本与
/// 原句柄指向同一文件、共享读写偏移（pipe-features 方案 A）。
pub struct FileHandle {
    /// 事件流读者令牌（I-EVENTS P1，§6.15）：仅当本句柄是对**每读者流**节点
    /// （当前 = `/devices/input/events`）执行过 `open_stream` 时为 `Some`。
    /// 游标语义：句柄的读位置——`Clone`（dup2/fork）共享同一游标（读走过的
    /// 就是读走了），最后一个克隆消失（close）时游标收敛、读者出局。
    /// 非事件流句柄恒 `None`，零额外开销。铸造单点在 `sys_open`（S15），
    /// 故除该点外本字段恒为 `None`——构造点零改动。
    pub stream_token: Option<crate::stream::EventReaderToken>,
    pub inode: Arc<dyn INode>,
    /// 读写偏移量。用 `Arc<AtomicU64>` 承载：dup2 副本共享**同一**文件描述
    /// （同一偏移计数器，跨副本同步推进）——Unix dup2 语义（pipe-features
    /// 方案 A）。`AtomicU64` 本身非 `Clone`，包一层 `Arc` 使 clone 共享之。
    pub offset: Arc<AtomicU64>,
    pub flags: OpenFlags,
}

impl Clone for FileHandle {
    fn clone(&self) -> Self {
        // dup2 语义：副本共享同一 INode（Arc）与同一读写偏移（Arc<AtomicU64>
        // 共享，跨副本读写推进同一计数器）。事件流令牌（若在）同样克隆：
        // 共享同一游标 Arc——与 offset 同一继承哲学。
        Self {
            stream_token: self.stream_token.clone(),
            inode: Arc::clone(&self.inode),
            offset: Arc::clone(&self.offset),
            flags: self.flags,
        }
    }
}

/// 进程 fd 表槽位可持有的句柄种类（ADR-014 §4.1）。
///
/// 当前为「文件句柄」与「匿名管道端」。管道端不持有 INode——读写经
/// `ipc::pipe_read/pipe_write` 直接路由到 ipc crate 的环形缓冲（阻塞/等待
/// 语义属 ipc 层，见 `kernel/crates/ipc`），故 fd 表不再假设每个槽位都是
/// 文件节点句柄。
///
/// `Clone` 是**结构性**拷贝（pipe 端仅复制 `id`、file 共享 `Arc`）。注意
/// `Pipe { id }` 被复制进一个新 fd 时，**调用方必须同步 `ipc::pipe_ref_inc(id)`**
/// 维持引用计数（每个持有该 id 的 fd 端记 1 个 ref），关闭副本时经
/// `ipc::pipe_ref_dec` 释放——否则管道会在仍有 fd 端引用时被销毁（UAF）。
/// vfs 不反向依赖 ipc，故 ref 递增由 kernel syscall 层（dup2 / spawn 继承）负责。
#[derive(Clone)]
pub enum OpenHandle {
    /// 普通文件/设备/流节点句柄（原有语义）。
    File(FileHandle),
    /// 匿名管道端：`id` 为 ipc 管道表主键。同一管道可被多个 fd 引用
    /// （FLAG_PIPE 一次创建一对读写端），引用计数在 ipc 层维护。
    ///
    /// `flags`（3P4-3）：管道端同样需要承载**每 fd** 的标志（当前只有
    /// `cloexec` 有意义——方向由"拿到的是读端还是写端"决定，不由位标志表达）。
    /// 查询一律走 `OpenHandle::flags()`（单一访问点）。
    Pipe {
        id: u64,
        flags: OpenFlags,
        /// **是否为写端**（3P4-3a）：管道 EOF 语义依赖「每端方向」的存活记账——
        /// 最后一个写端关闭后，读端必须读到 0。dup2/继承都原样传递本字段。
        writer: bool,
    },
}

impl OpenHandle {
    /// 本 fd 的打开标志——**CLOEXEC 的唯一查询点**（3P4-3）。
    pub fn flags(&self) -> OpenFlags {
        match self {
            OpenHandle::File(f) => f.flags,
            OpenHandle::Pipe { flags, .. } => *flags,
        }
    }
}

// ---------- fd 句柄释放钩子（3P4-3b） ----------

/// fd 句柄**永久释放**钩子：进程退出 drain fd 表时逐个交付。

/// 为什么需要钩子：`OpenHandle::Pipe` 的**端引用计数在 ipc 层**维护，而释放点是
/// task 的进程终止路径——vfs 不该反向依赖 ipc。形状与 `mm::user_space::ShmMappingHooks`
/// 同族：vfs 定义钩子点，kernel 侧装配 ipc 实现（依赖方向 vfs ← kernel → ipc）。
///
/// **边界**（有意为之，非重复造轮子）：syscall 侧的 close/dup2/exec 继承仍显式调用
/// `ipc::pipe_ref_dec` —— 那些路径需要**销毁结果**（refs 归零即销毁对象）来决定后续动作，
/// 而本钩子只表达"这个句柄永久没了"，返回值为空。两处语义不同，故不强行合并。
pub trait FdReleaseHooks: Send + Sync {
    /// 一个 fd 句柄被永久释放（当前唯一来源：进程退出 drain fd 表）。
    fn on_handle_released(&self, handle: &OpenHandle);
}

static FD_RELEASE_HOOKS: klib::sync::irq::IrqSpinLock<Option<&'static dyn FdReleaseHooks>> =
    klib::sync::irq::IrqSpinLock::new(None);

/// 装配钩子实现（kernel 侧引导期调用一次）。
pub fn set_fd_release_hooks(hooks: &'static dyn FdReleaseHooks) {
    *FD_RELEASE_HOOKS.lock() = Some(hooks);
}

/// 交付一个被释放的句柄给钩子。未装配时无副作用（引导早期 / host 单测）。
pub fn release_handle(handle: &OpenHandle) {
    if let Some(h) = *FD_RELEASE_HOOKS.lock() {
        h.on_handle_released(handle);
    }
}

impl FileHandle {
    /// 构造句柄（ADR-023 §5）。
    ///
    /// - **M4**：`flags.directory`（O_DIRECTORY）在此强制——目标非目录即
    ///   `NotDirectory`。解析后无人执行的旗标等于不存在；
    /// - **M3**：append 初始 offset 取自 inode 真实 size，metadata 失败
    ///   如实上抛——旧 `unwrap_or(0)` 会把追加起点静默落回文件头，
    ///   第一次写入就覆盖既有内容。
    pub fn new(inode: Arc<dyn INode>, flags: OpenFlags) -> Result<Self, Error> {
        if flags.directory && inode.node_type()? != crate::inode::INodeType::Directory {
            return Err(Error::NotDirectory);
        }
        let initial_offset = if flags.append {
            inode.metadata()?.size
        } else {
            0
        };
        Ok(Self {
            stream_token: None,
            inode,
            offset: Arc::new(AtomicU64::new(initial_offset)),
            flags,
        })
    }

    /// 把本句柄登记为**每读者事件流**的读者（I-EVENTS P1，§6.15）。
    ///
    /// 仅对自述 `event_stream_reader()` 有流后端的节点有效；铸造
    /// [`EventReaderToken`]（游标 = `min(写指针, 最慢读者)`，见
    /// `vfs::stream::open_reader`）并挂在句柄上。重复铸造以
    /// `AlreadyExists` 拒绝——一个句柄一名读者；`Err` 原样透传（流后端
    /// 缺失等），调用方决定语义。
    ///
    /// 失败时**不留半登记态**：铸造成功才写回字段；字段为 None 时 Drop 无事
    /// 发生，注册/收敛天然配平（S21 显式化）。
    pub fn attach_event_reader(&mut self) -> Result<(), Error> {
        if self.stream_token.is_some() {
            return Err(Error::AlreadyExists);
        }
        let backend = self.inode.event_stream_reader().ok_or(Error::NotSupported)?;
        self.stream_token = Some(crate::stream::open_reader(backend));
        Ok(())
    }

    /// 流式读（自动推进 offset）。
    ///
    /// **每读者事件流分支（I-EVENTS P1）**：持有 `stream_token` 的句柄走
    /// 令牌的独立游标（读位置语义），不触 offset、不触 `read_at`；返回 0 =
    /// 本读者游标处暂无新记录（syscall 层按节点真值接阻塞/非阻塞语义）。
    /// 其余句柄逐位保持原语义。
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.flags.read {
            return Err(Error::PermissionDenied);
        }
        if let Some(tok) = &self.stream_token {
            // 整环填满（与 read_at 的 backlog 形态同款「读走尽可能多的整条」）：
            // 每次取一条，直到源空或装不下。返回 0 = 本读者游标处暂无记录。
            if buf.len() < 16 {
                return Ok(0);
            }
            let mut total = 0usize;
            while total + 16 <= buf.len() {
                let got = tok.take(&mut buf[total..]);
                if got == 0 {
                    break;
                }
                total += got;
            }
            return Ok(total);
        }
        let cur = self.offset.load(Ordering::SeqCst);
        let n = self.inode.read_at(cur, buf)?;
        self.offset.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// 流式写（自动推进 offset）。
    ///
    /// ADR-023 §1：注入全局页缓存时经 [`PageCache::write_cached`] 写穿
    /// 并作废受影响缓存块（失效一致性策略的唯一合法写通道）；未注入时
    /// 直写 inode。
    pub fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        let cur = if self.flags.append {
            // S21：append 的"读 size + 写"非原子——两个并发 append 可能读到
            // 相同 size 相互覆盖，丢失 O_APPEND 追加原子性。成文假设：当前
            // 内核单 CPU、同一文件的并发 append 不存在（VFS 层无对同句柄的
            // 跨进程并发写语义）；未来引入多写者时须把 size 读取+写入纳入
            // 同一把 content 锁。
            let size = self.inode.metadata()?.size;
            self.offset.store(size, Ordering::SeqCst);
            size
        } else {
            self.offset.load(Ordering::SeqCst)
        };
        let n = self.write_coordinated(cur, buf)?;
        self.offset.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// 无状态定位读（pread，不影响句柄内部 offset）。
    pub fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.flags.read {
            return Err(Error::PermissionDenied);
        }
        self.inode.read_at(offset, buf)
    }

    /// 无状态定位写（pwrite，不影响句柄内部 offset）。一致性语义同 [`Self::write`]。
    pub fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        self.write_coordinated(offset, buf)
    }

    /// 经全局缓存（若注入）的协调写落点。
    fn write_coordinated(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        match crate::page_cache::global_page_cache() {
            Some(cache) => cache.write_cached(&self.inode, offset, buf),
            None => self.inode.write_at(offset, buf),
        }
    }

    /// 调整偏移量（Seek）。
    pub fn seek(&self, offset: i64, whence: SeekWhence) -> Result<u64, Error> {
        let meta = self.inode.metadata()?;
        let cur = self.offset.load(Ordering::SeqCst);
        let target = match whence {
            SeekWhence::Set => {
                if offset < 0 {
                    return Err(Error::OutOfRange);
                }
                offset as u64
            }
            SeekWhence::Current => {
                if offset < 0 {
                    // S19：`-offset` 在 offset==i64::MIN 时溢出 panic；
                    // unsigned_abs() 对全部负值安全。
                    let neg = offset.unsigned_abs();
                    cur.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    cur.checked_add(offset as u64).ok_or(Error::OutOfRange)?
                }
            }
            SeekWhence::End => {
                if offset < 0 {
                    let neg = offset.unsigned_abs();
                    meta.size.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    meta.size
                        .checked_add(offset as u64)
                        .ok_or(Error::OutOfRange)?
                }
            }
        };
        self.offset.store(target, Ordering::SeqCst);
        Ok(target)
    }

    /// 获取元数据。
    pub fn metadata(&self) -> Result<FileMetadata, Error> {
        self.inode.metadata()
    }
}

/// Seek 模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    Set = 0,
    Current = 1,
    End = 2,
}
