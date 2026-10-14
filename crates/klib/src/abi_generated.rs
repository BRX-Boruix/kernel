//! **自动生成，请勿手改。**
//!
//! 源：tools/abi/constants.json
//! 生成：python tools/abi/generate.py
//! 门禁：python tools/abi/generate.py --check（已登记进 tools/checks/run_all.py）
//!
//! 手改本文件会被门禁发现；要改数值请改 JSON 再重新生成。

// ---------- Error -> errno ----------

pub const fn to_errno(e: crate::error::Error) -> i32 {
    match e {
        crate::error::Error::OutOfMemory => 12, // ENOMEM
        crate::error::Error::InvalidParam => 22, // EINVAL
        crate::error::Error::OutOfRange => 34, // ERANGE
        crate::error::Error::NotFound => 2, // ENOENT
        crate::error::Error::AlreadyExists => 17, // EEXIST
        crate::error::Error::NotSupported => 95, // ENOTSUP
        crate::error::Error::WouldBlock => 11, // EAGAIN
        crate::error::Error::Interrupted => 4, // EINTR
        crate::error::Error::NoSpace => 28, // ENOSPC
        crate::error::Error::Io => 5, // EIO
        crate::error::Error::NotDirectory => 20, // ENOTDIR
        crate::error::Error::IsDirectory => 21, // EISDIR
        crate::error::Error::PermissionDenied => 13, // EACCES
        crate::error::Error::BadAddress => 14, // EFAULT
        crate::error::Error::NotEmpty => 39, // ENOTEMPTY
        crate::error::Error::NameTooLong => 36, // ENAMETOOLONG
        crate::error::Error::ArgListTooLong => 7, // E2BIG
        crate::error::Error::TooManySymlinks => 40, // ELOOP
        crate::error::Error::IllegalSeek => 29, // ESPIPE
        crate::error::Error::ExecFormat => 8, // ENOEXEC
        crate::error::Error::ReadOnly => 30, // EROFS
        crate::error::Error::Corrupt => 117, // EUCLEAN
        crate::error::Error::Busy => 16, // EBUSY
    }
}
