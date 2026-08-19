//! 内核统一错误码（ADR-010）。
//!
//! 取代 `&'static str` 作为 `Result` 的 `Err` 类型，支撑程序化错误处理
//! （`match` / 重试 / 降级 / 回收资源），并为 ADR-003 的 syscall 错误码
//! 边界铺路（[`Error::to_errno`]）。
//!
//! 设计要点：
//! - 零分配：全部变体为 unit / `&'static str`，`Copy` 语义，可在中断上下文使用；
//! - 过渡兼容：[`Error::Msg`] 保留迁移期间的原始字符串信息，`From<&'static str>`
//!   保证旧调用点 `"..."`.into()` 不破坏编译；迁移完成后移除；
//! - 动态上下文（地址、长度、id 等运行时数值）由调用方经 `klib::log` 输出，
//!   不塞进 `Err`（保持错误零分配、可比较）。

/// 内核统一错误码。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// 内存耗尽（物理帧 / 堆分配失败）。
    OutOfMemory,
    /// 参数非法。
    InvalidParam,
    /// 数值越界（地址、大小等超出允许范围）。
    OutOfRange,
    /// 目标不存在（设备、加载器、映射缺失等）。
    NotFound,
    /// 目标已存在（重复注册、区域重叠等）。
    AlreadyExists,
    /// 不支持的操作（硬件/功能未实现）。
    NotSupported,
    /// 非阻塞操作无法立即完成（需重试或等待）。
    WouldBlock,
    /// 空间不足（表满、无空闲地址区间等）。
    NoSpace,
    /// 设备 I/O 错误。
    Io,
    /// 并非目录（试图对文件执行 lookup/readdir 等）。
    NotDirectory,
    /// 是目录（试图对目录执行非目录文件操作）。
    IsDirectory,
    /// 权限拒绝。
    PermissionDenied,
    /// 目录非空（删除非空目录）。
    NotEmpty,
    /// 文件名或路径超长。
    NameTooLong,
    /// 软链接层级过深（死循环）。
    TooManySymlinks,
    /// 过渡用：携带原始错误描述字符串（迁移完成后移除）。
    Msg(&'static str),
}

impl Error {
    /// 转为 POSIX errno 风格数值（ADR-003 syscall 边界铺路，可后续直接映射）。
    pub fn to_errno(self) -> i32 {
        match self {
            Error::OutOfMemory => 12,        // ENOMEM
            Error::InvalidParam => 22,       // EINVAL
            Error::OutOfRange => 34,         // ERANGE
            Error::NotFound => 2,            // ENOENT
            Error::AlreadyExists => 17,      // EEXIST
            Error::NotSupported => 95,       // ENOTSUP
            Error::WouldBlock => 11,         // EAGAIN
            Error::NoSpace => 28,            // ENOSPC
            Error::Io => 5,                  // EIO
            Error::NotDirectory => 20,       // ENOTDIR
            Error::IsDirectory => 21,        // EISDIR
            Error::PermissionDenied => 13,   // EACCES
            Error::NotEmpty => 39,           // ENOTEMPTY
            Error::NameTooLong => 36,        // ENAMETOOLONG
            Error::TooManySymlinks => 40,    // ELOOP
            Error::Msg(_) => 22,             // EINVAL
        }
    }
}

impl From<&'static str> for Error {
    /// 过渡映射：旧调用点 `"...".into()` 直接可用，信息保留在 [`Error::Msg`]。
    fn from(s: &'static str) -> Self {
        Error::Msg(s)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::OutOfMemory => f.write_str("out of memory"),
            Error::InvalidParam => f.write_str("invalid parameter"),
            Error::OutOfRange => f.write_str("out of range"),
            Error::NotFound => f.write_str("not found"),
            Error::AlreadyExists => f.write_str("already exists"),
            Error::NotSupported => f.write_str("not supported"),
            Error::WouldBlock => f.write_str("would block"),
            Error::NoSpace => f.write_str("no space"),
            Error::Io => f.write_str("i/o error"),
            Error::NotDirectory => f.write_str("not a directory"),
            Error::IsDirectory => f.write_str("is a directory"),
            Error::PermissionDenied => f.write_str("permission denied"),
            Error::NotEmpty => f.write_str("directory not empty"),
            Error::NameTooLong => f.write_str("name too long"),
            Error::TooManySymlinks => f.write_str("too many levels of symbolic links"),
            Error::Msg(s) => f.write_str(s),
        }
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    #[test]
    fn variants_equality() {
        assert_eq!(Error::OutOfMemory, Error::OutOfMemory);
        assert_ne!(Error::OutOfMemory, Error::InvalidParam);
        assert_ne!(Error::Msg("a"), Error::Msg("b"));
        assert_eq!(Error::Msg("a"), Error::Msg("a"));
    }

    #[test]
    fn display_text() {
        assert_eq!(format!("{}", Error::OutOfMemory), "out of memory");
        assert_eq!(format!("{}", Error::NoSpace), "no space");
        assert_eq!(format!("{}", Error::Msg("no free mmap region")), "no free mmap region");
    }

    #[test]
    fn from_static_str_preserves_message() {
        let e: Error = "stack too large".into();
        assert_eq!(e, Error::Msg("stack too large"));
    }

    #[test]
    fn to_errno_mapping() {
        assert_eq!(Error::OutOfMemory.to_errno(), 12); // ENOMEM
        assert_eq!(Error::InvalidParam.to_errno(), 22); // EINVAL
        assert_eq!(Error::NotFound.to_errno(), 2); // ENOENT
        assert_eq!(Error::AlreadyExists.to_errno(), 17); // EEXIST
        assert_eq!(Error::NoSpace.to_errno(), 28); // ENOSPC
        assert_eq!(Error::Io.to_errno(), 5); // EIO
        assert_eq!(Error::Msg("x").to_errno(), 22); // EINVAL
    }

    #[test]
    fn copy_and_clone() {
        let e = Error::OutOfRange;
        let e2 = e; // Copy
        assert_eq!(e, e2);
        let e3 = e.clone();
        assert_eq!(e, e3);
    }

    #[test]
    fn usable_in_result() {
        let r: Result<(), Error> = Err("user region out of range".into());
        assert!(r.is_err());
        let r2: Result<(), Error> = Err(Error::OutOfMemory);
        assert_eq!(r2.unwrap_err(), Error::OutOfMemory);
    }
}
