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
        crate::error::Error::BadFd => 9, // EBADF
    }
}

// ---------- 跨边界 wire 常量（内核 <-> libsys） ----------

pub const ACE_PRINCIPAL_NAMED_GID: u32 = 2;
pub const ACE_PRINCIPAL_NAMED_UID: u32 = 1;
pub const ACE_PRINCIPAL_OTHER: u32 = 3;
pub const ACE_PRINCIPAL_OWNER: u32 = 0;
pub const ACE_WIRE_MAX: usize = 64;
pub const ACE_WIRE_SIZE: usize = 24;
pub const AT_EXECFN: u64 = 31;
pub const AT_NULL: u64 = 0;
pub const DERIVE_FLAGS_NONE: u64 = 0;
pub const ENTRY_KIND_DIRECTORY: u64 = 0;
pub const ENTRY_KIND_FILE: u64 = 1;
pub const ENTRY_READ_ACES: u64 = 2;
pub const ENTRY_READ_READDIR: u64 = 0;
pub const ENTRY_READ_STAT: u64 = 1;
pub const ENTRY_UPDATE_CHMOD: u64 = 1;
pub const ENTRY_UPDATE_CHOWN: u64 = 2;
pub const ENTRY_UPDATE_RENAME: u64 = 0;
pub const ENTRY_UPDATE_SET_ACES: u64 = 3;
pub const EVENT_FLAG_E0: u8 = 1 << 0;
pub const EVENT_FLAG_NO_TIME: u8 = 1 << 1;
pub const EVENT_KIND_KEY_DOWN: u8 = 1;
pub const EVENT_KIND_KEY_UP: u8 = 2;
pub const EVENT_RECORD_SIZE: usize = 16;
pub const GATE_SYSTEM_BIT: u32 = 1 << 9;
pub const GROUPS_SET_CLEAR: u64 = 1;
pub const GROUPS_SET_REPLACE: u64 = 0;
pub const GROUPS_SET_RESERVED_NONE: u64 = 0;
pub const IDENTITY_SET_RESERVED_NONE: u64 = 0;
pub const MAX_CMDLINE_BYTES: usize = 4096;
pub const MAX_FDS: usize = 1024;
pub const MAX_ENV_COUNT: usize = 64;
pub const MEM_MAP_SHARED: u64 = 1 << 0;
pub const NICE_BIAS: i32 = 20;
pub const NICE_GET: u64 = 0;
pub const NICE_SET: u64 = 1;
pub const PROT_DEFAULT: u64 = PROT_READ | PROT_WRITE;
pub const PROT_EXEC: u64 = 1 << 2;
pub const PROT_READ: u64 = 1 << 0;
pub const PROT_WRITE: u64 = 1 << 1;
pub const SIGALRM: u32 = 14;
pub const SIGBUS: u32 = 7;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGFPE: u32 = 8;
pub const SIGILL: u32 = 4;
pub const SIGINT: u32 = 2;
pub const SIGKILL: u32 = 9;
pub const SIGPIPE: u32 = 13;
pub const SIGSEGV: u32 = 11;
pub const SIGSTOP: u32 = 19;
pub const SIGTERM: u32 = 15;
pub const SIGUSR1: u32 = 10;
pub const SIGUSR2: u32 = 12;
pub const STREAM_READ_NONBLOCK: u64 = 1;
pub const STREAM_READ_PEEK: u64 = 2;
