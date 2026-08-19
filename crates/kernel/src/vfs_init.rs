//! VFS 全局实例与系统骨架初始化。

use alloc::sync::Arc;
use spin::Once;
use vfs::inode::Permissions;
use vfs::mount::MountTable;
use vfs::ramfs::RamFS;

static VFS_ROOT: Once<Arc<MountTable>> = Once::new();

/// 获取全局 VFS 挂载表。
pub fn root() -> &'static Arc<MountTable> {
    VFS_ROOT.get().expect("VFS not initialized")
}

/// 初始化根文件系统并构建默认 RESTful 目录骨架（ADR-005 / ADR-011 / ADR-012）。
pub fn init() {
    let ramfs = Arc::new(RamFS::new());
    let mount_table = Arc::new(MountTable::new(ramfs));

    // 构建默认顶层骨架（全称 RESTful 集合）
    mount_table.mkdir("/binaries", Permissions::all()).expect("mkdir /binaries");
    mount_table.mkdir("/config", Permissions::all()).expect("mkdir /config");
    mount_table.mkdir("/system", Permissions::all()).expect("mkdir /system");
    mount_table.mkdir("/users", Permissions::all()).expect("mkdir /users");
    mount_table.mkdir("/temporary", Permissions::all()).expect("mkdir /temporary");
    mount_table.mkdir("/volumes", Permissions::all()).expect("mkdir /volumes");

    VFS_ROOT.call_once(|| mount_table);
    klib::info!("[vfs] root RamFS mounted, RESTful directories initialized");
}
