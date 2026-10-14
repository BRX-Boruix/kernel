//! **自动生成，请勿手改。**
//!
//! 源：tools/abi/constants.json
//! 生成：python tools/abi/generate.py
//! 门禁：python tools/abi/generate.py --check（已登记进 tools/checks/run_all.py）
//!
//! 手改本文件会被门禁发现；要改数值请改 JSON 再重新生成。

// ---------- syscall 号 ----------

pub const SYS_AUDIO_ATTACH: u32 = crate::syscall::domain::AUDIO | 0x01; // 0xA1
pub const SYS_AUDIO_COMMIT: u32 = crate::syscall::domain::AUDIO | 0x04; // 0xA4
pub const SYS_AUDIO_DETACH: u32 = crate::syscall::domain::AUDIO | 0x02; // 0xA2
pub const SYS_AUDIO_FETCH: u32 = crate::syscall::domain::AUDIO | 0x03; // 0xA3
pub const SYS_DEVICE_PROBE: u32 = crate::syscall::domain::DEVICE | 0x08; // 0x58
pub const SYS_DRIVER_CLAIM: u32 = crate::syscall::domain::DEVICE | crate::syscall::op::WRITE; // 0x53
pub const SYS_DRIVER_DMA_ALLOC: u32 = crate::syscall::domain::DEVICE | 0x0A; // 0x5A
pub const SYS_DRIVER_DMA_FREE: u32 = crate::syscall::domain::DEVICE | 0x0B; // 0x5B
pub const SYS_DRIVER_DMA_PHYS: u32 = crate::syscall::domain::DEVICE | 0x0C; // 0x5C
pub const SYS_DRIVER_EVENT_NEXT: u32 = crate::syscall::domain::DEVICE | crate::syscall::op::EVENT; // 0x57
pub const SYS_DRIVER_IRQ_WAIT: u32 = crate::syscall::domain::DEVICE | 0x09; // 0x59
pub const SYS_DRIVER_QUERY: u32 = crate::syscall::domain::DEVICE | crate::syscall::op::READ; // 0x52
pub const SYS_DRIVER_REGISTER: u32 = crate::syscall::domain::DEVICE | crate::syscall::op::CREATE; // 0x51
pub const SYS_DRIVER_UNREGISTER: u32 = crate::syscall::domain::DEVICE | crate::syscall::op::DELETE; // 0x54
pub const SYS_ENTRY_CHDIR: u32 = crate::syscall::domain::VFS | 0x05; // 0x45
pub const SYS_ENTRY_CREATE: u32 = crate::syscall::domain::VFS | crate::syscall::op::CREATE; // 0x41
pub const SYS_ENTRY_DELETE: u32 = crate::syscall::domain::VFS | crate::syscall::op::DELETE; // 0x44
pub const SYS_ENTRY_GETCWD: u32 = crate::syscall::domain::VFS | 0x06; // 0x46
pub const SYS_ENTRY_LINK: u32 = crate::syscall::domain::VFS | 0x09; // 0x49
pub const SYS_ENTRY_READ: u32 = crate::syscall::domain::VFS | crate::syscall::op::READ; // 0x42
pub const SYS_ENTRY_READLINK: u32 = crate::syscall::domain::VFS | 0x08; // 0x48
pub const SYS_ENTRY_SYMLINK: u32 = crate::syscall::domain::VFS | 0x07; // 0x47
pub const SYS_ENTRY_UPDATE: u32 = crate::syscall::domain::VFS | crate::syscall::op::WRITE; // 0x43
pub const SYS_MEMORY_GROW: u32 = crate::syscall::domain::MEMORY | crate::syscall::op::WRITE; // 0x23
pub const SYS_MEMORY_MAP: u32 = crate::syscall::domain::MEMORY | crate::syscall::op::CREATE; // 0x21
pub const SYS_MEMORY_PROTECT: u32 = crate::syscall::domain::MEMORY | 0x05; // 0x25
pub const SYS_MEMORY_QUERY: u32 = crate::syscall::domain::MEMORY | crate::syscall::op::READ; // 0x22
pub const SYS_MEMORY_UNMAP: u32 = crate::syscall::domain::MEMORY | crate::syscall::op::DELETE; // 0x24
pub const SYS_POWER_OFF: u32 = crate::syscall::domain::POWER | 0x01; // 0x91
pub const SYS_POWER_REBOOT: u32 = crate::syscall::domain::POWER | 0x02; // 0x92
pub const SYS_SIGNAL_ACTION: u32 = crate::syscall::domain::SIGNAL | crate::syscall::op::WRITE; // 0x83
pub const SYS_SIGNAL_ALARM: u32 = crate::syscall::domain::SIGNAL | 0x07; // 0x87
pub const SYS_SIGNAL_ALTSTACK: u32 = crate::syscall::domain::SIGNAL | 0x08; // 0x88
pub const SYS_SIGNAL_MASK: u32 = crate::syscall::domain::SIGNAL | crate::syscall::op::READ; // 0x82
pub const SYS_SIGNAL_PENDING: u32 = crate::syscall::domain::SIGNAL | 0x05; // 0x85
pub const SYS_SIGNAL_RETURN: u32 = crate::syscall::domain::SIGNAL | crate::syscall::op::DELETE; // 0x84
pub const SYS_SIGNAL_SUSPEND: u32 = crate::syscall::domain::SIGNAL | 0x06; // 0x86
pub const SYS_STREAM_CLOSE: u32 = crate::syscall::domain::STREAM | crate::syscall::op::DELETE; // 0x14
pub const SYS_STREAM_CREATE: u32 = crate::syscall::domain::STREAM | crate::syscall::op::CREATE; // 0x11
pub const SYS_STREAM_DUP: u32 = crate::syscall::domain::STREAM | 0x05; // 0x15
pub const SYS_STREAM_FCHMOD: u32 = crate::syscall::domain::STREAM | 0x0B; // 0x1B
pub const SYS_STREAM_FCHOWN: u32 = crate::syscall::domain::STREAM | 0x0C; // 0x1C
pub const SYS_STREAM_FOCUS_SET: u32 = crate::syscall::domain::STREAM | 0x08; // 0x18
pub const SYS_STREAM_FSTAT: u32 = crate::syscall::domain::STREAM | 0x07; // 0x17
pub const SYS_STREAM_FSYNC: u32 = crate::syscall::domain::STREAM | 0x0A; // 0x1A
pub const SYS_STREAM_FTRUNCATE: u32 = crate::syscall::domain::STREAM | 0x09; // 0x19
pub const SYS_STREAM_LOCK: u32 = crate::syscall::domain::STREAM | 0x06; // 0x16
pub const SYS_STREAM_READ: u32 = crate::syscall::domain::STREAM | crate::syscall::op::READ; // 0x12
pub const SYS_STREAM_WRITE: u32 = crate::syscall::domain::STREAM | crate::syscall::op::WRITE; // 0x13
pub const SYS_SYNC_CREATE: u32 = crate::syscall::domain::SYNC | crate::syscall::op::CREATE; // 0x71
pub const SYS_SYNC_DELETE: u32 = crate::syscall::domain::SYNC | crate::syscall::op::DELETE; // 0x74
pub const SYS_SYNC_WAIT: u32 = crate::syscall::domain::SYNC | crate::syscall::op::READ; // 0x72
pub const SYS_SYNC_WAKE: u32 = crate::syscall::domain::SYNC | crate::syscall::op::WRITE; // 0x73
pub const SYS_TASK_DERIVE: u32 = crate::syscall::domain::TASK | 0x0A; // 0x3A
pub const SYS_TASK_EXIT: u32 = crate::syscall::domain::TASK | crate::syscall::op::DELETE; // 0x34
pub const SYS_TASK_GETPID: u32 = crate::syscall::domain::TASK | 0x09; // 0x39
pub const SYS_TASK_GETTID: u32 = crate::syscall::domain::TASK | 0x08; // 0x38
pub const SYS_TASK_GROUPS_GET: u32 = crate::syscall::domain::TASK | 0x0E; // 0x3E
pub const SYS_TASK_GROUPS_SET: u32 = crate::syscall::domain::TASK | 0x0D; // 0x3D
pub const SYS_TASK_IDENTITY_QUERY: u32 = crate::syscall::domain::TASK | 0x0B; // 0x3B
pub const SYS_TASK_IDENTITY_SET: u32 = crate::syscall::domain::TASK | 0x0C; // 0x3C
pub const SYS_TASK_NICE: u32 = crate::syscall::domain::TASK | 0x0F; // 0x3F
pub const SYS_TASK_SET_FS_BASE: u32 = crate::syscall::domain::TASK | 0x07; // 0x37
pub const SYS_TASK_SIGNAL: u32 = crate::syscall::domain::TASK | crate::syscall::op::WRITE; // 0x33
pub const SYS_TASK_SPAWN: u32 = crate::syscall::domain::TASK | crate::syscall::op::CREATE; // 0x31
pub const SYS_TASK_THREAD_JOIN: u32 = crate::syscall::domain::TASK | 0x06; // 0x36
pub const SYS_TASK_THREAD_SPAWN: u32 = crate::syscall::domain::TASK | 0x05; // 0x35
pub const SYS_TASK_WAIT: u32 = crate::syscall::domain::TASK | crate::syscall::op::READ; // 0x32
pub const SYS_VOLUME_FORMAT: u32 = crate::syscall::domain::VOLUME | crate::syscall::op::FORMAT; // 0x65
pub const SYS_VOLUME_LIST: u32 = crate::syscall::domain::VOLUME | crate::syscall::op::READ; // 0x62
pub const SYS_VOLUME_MOUNT: u32 = crate::syscall::domain::VOLUME | crate::syscall::op::CREATE; // 0x61
pub const SYS_VOLUME_UNMOUNT: u32 = crate::syscall::domain::VOLUME | crate::syscall::op::UNMOUNT; // 0x66
pub const SYS_VOLUME_UPDATE: u32 = crate::syscall::domain::VOLUME | crate::syscall::op::WRITE; // 0x63
