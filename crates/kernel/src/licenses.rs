//! `/system/licenses/` 许可证全文播种（法律披露，S15 单点定义）。
//!
//! 【为何是真实文件而非虚视图】ADR-012 §3 #3：`/system` 是真实可写域目录，
//! 只读虚视图一律挂 `/system/info/`。披露文本是随内核构建固定的常量，不是
//! 运行期派生状态，故按真实文件播种（与 `/config/users.json` 同族），不得做成
//! sysfs 动态节点。
//!
//! 【收录判据】分两类，都登记在同一张组件表里：
//!
//! 1. **本分发主体**（`kernel.txt`）：本仓自身的许可。MIT 要求版权与许可声明
//!    随软件的所有副本分发，故它和第三方一样必须随二进制披露——收录理由不是
//!    "代码进了二进制"（它当然进了），而是"它就是被分发的主体作品"。
//! 2. **第三方组件**：判据是**它的代码真的被链接进内核二进制**。该判据可机械
//!    复核，有两条互相独立的证据链：
//!    - `cargo metadata --filter-platform x86_64-unknown-none`，从 `kernel` 出发
//!      只沿**普通依赖**边遍历（排除 dev / build 专属边）；**过程宏及其宿主端
//!      依赖子树不计**——它们在编译期运行于宿主，代码不进目标二进制；
//!    - 在内核自带符号表 `symbols_generated.rs` 里搜该 crate 名的符号——符号带
//!      真实地址，是"确实进了二进制"的硬证据（如 `buddy_system_allocator::Heap`）。
//!
//!    "在 `vendor/` 下"或"在 `Cargo.toml` 里出现过"都**不是**判据：前者会漏掉
//!    未 vendor 的 registry 依赖，后者会把仅构建期使用的 crate 也算进来。
//!
//!    registry 依赖已由 `cargo vendor` 把源码与许可证一并入库到
//!    `vendor/registry/`（源替换配置见 `.cargo/config.toml`），因此它们的许可证
//!    文本落在**仓库内相对路径**上，可用 `include_str!` 内嵌——不再有"只存在于
//!    本机 cargo 缓存、无法内嵌"的缺口。**更新依赖后必须重跑 `cargo vendor`**，
//!    并用 `tools/checks/regression/license_audit.py` 复核（未披露即 exit 1）。
//!
//! 【披露文本格式】统一为：
//!
//! ```text
//! <组件名> <版本> - <许可结论>
//! <来源 / 经何引入，1-2 行>
//! ==============================================================================
//!
//! <许可证全文，逐字节取自组件自带文件>
//! ```
//!
//! 单许可证组件用 `disclosure!` 宏生成（格式单点定义）；多许可证组件
//! （flanterm_rust 的 MIT + BSD-2-Clause）显式写 `concat!`。
//!
//! 【文本语言】正文为许可证原文（英文，法律效力以原文为准）；外层说明亦用
//! 英文——该文件可能在 BORUIX 控制台被 cat 出来，而控制台字体是 CP437 位图，
//! 无 CJK 字形，中文会渲染成缺字（S40 呈现服从可用性）。
//!
//! 【失败模式（S20）】编译期：许可证文件缺失即编译失败（宁可报错，S09）；
//! 运行期：创建/解析/截断/短写任一失败即 panic——与 `vfs_init::build_skeleton`
//! 中 mkdir 与种子文件的既有口径一致；披露残缺不允许静默通过。

use alloc::sync::Arc;

/// 披露目录（单点定义，S15）。
pub const DIR: &str = "/system/licenses";

/// 一个需要随内核二进制披露的组件。
pub struct Component {
    /// `DIR` 下的文件名。规则：**包名 + `.txt`**，与 `Cargo.toml` 的
    /// `package.name` 逐字一致，便于机械追溯（`spin` → `spin.txt`）。
    pub file_name: &'static str,
    /// 完整披露文本（头部 + 许可证全文），编译期内嵌。
    pub text: &'static str,
}

/// 组件表：**唯一登记点**——新增需披露的组件只在这里加一行。
pub const COMPONENTS: &[Component] = &[
    Component {
        file_name: "kernel.txt",
        text: KERNEL_TXT,
    },
    Component {
        file_name: "flanterm_rust.txt",
        text: FLANTERM_RUST_TXT,
    },
    Component {
        file_name: "brxlimine-rs.txt",
        text: BRXLIMINE_RS_TXT,
    },
    Component {
        file_name: "spin.txt",
        text: SPIN_TXT,
    },
    Component {
        file_name: "lock_api.txt",
        text: LOCK_API_TXT,
    },
    Component {
        file_name: "scopeguard.txt",
        text: SCOPEGUARD_TXT,
    },
    Component {
        file_name: "buddy_system_allocator.txt",
        text: BUDDY_SYSTEM_ALLOCATOR_TXT,
    },
];

/// 生成**单许可证**组件的披露文本（头部格式单点定义，见模块文档）。
///
/// `$file` 是相对本文件的路径，直接交给 `include_str!`——许可证全文逐字节入库，
/// 不存在"手抄一份、与上游各自漂移"的可能（S15/S28）。
macro_rules! disclosure {
    ($title:literal, $license:literal, $origin:literal, $file:literal) => {
        concat!(
            $title, " - ", $license, "\n",
            $origin,
            "==============================================================================\n",
            "\n",
            include_str!($file),
        )
    };
}

/// 本分发主体：BORUIX 内核自身的 MIT 许可（第一方，非第三方组件）。
const KERNEL_TXT: &str = disclosure!(
    "kernel (BORUIX kernel)",
    "MIT",
    "Source    : kernel/LICENSE (repository root of the kernel crate)\n",
    "../../../LICENSE"
);

/// `spin`：内核多处自旋锁。
const SPIN_TXT: &str = disclosure!(
    "spin 0.9.9",
    "MIT",
    "Linked via: arch, arch-x86_64, driver, fs, kernel, mm, vfs\nSource    : vendor/registry/spin/ (vendored by cargo vendor)\n",
    "../../../vendor/registry/spin/LICENSE"
);

/// `lock_api`：`spin` 的依赖。上游双许可 MIT OR Apache-2.0，本分发取 MIT 臂。
const LOCK_API_TXT: &str = disclosure!(
    "lock_api 0.4.14",
    "MIT (upstream dual-licenses as MIT OR Apache-2.0; this distribution relies on the MIT arm)",
    "Linked via: spin\nSource    : vendor/registry/lock_api/ (vendored by cargo vendor)\n",
    "../../../vendor/registry/lock_api/LICENSE-MIT"
);

/// `scopeguard`：`lock_api` 的依赖。上游双许可 MIT OR Apache-2.0，本分发取 MIT 臂。
const SCOPEGUARD_TXT: &str = disclosure!(
    "scopeguard 1.2.0",
    "MIT (upstream dual-licenses as MIT OR Apache-2.0; this distribution relies on the MIT arm)",
    "Linked via: lock_api\nSource    : vendor/registry/scopeguard/ (vendored by cargo vendor)\n",
    "../../../vendor/registry/scopeguard/LICENSE-MIT"
);

/// `buddy_system_allocator`：klib 的内核堆分配器后端。
const BUDDY_SYSTEM_ALLOCATOR_TXT: &str = disclosure!(
    "buddy_system_allocator 0.9.1",
    "MIT",
    "Linked via: klib (kernel heap allocator)\nSource    : vendor/registry/buddy_system_allocator/ (vendored by cargo vendor)\n",
    "../../../vendor/registry/buddy_system_allocator/LICENSE"
);

/// `flanterm_rust`：MIT（新增/改写的 Rust 代码）+ BSD-2-Clause（派生自上游 C 版）。
///
/// 两份全文分别逐字节取自 `vendor/flanterm_rust/LICENSE-MIT` 与 `LICENSE-BSD-2`
/// （版权行在文本内，头部不重复，避免双份漂移）。这是唯一的**多许可证**组件，
/// 故不走 `disclosure!` 宏，显式写 `concat!`。
const FLANTERM_RUST_TXT: &str = concat!(
    "flanterm_rust - MIT (new / rewritten Rust code) AND BSD-2-Clause (portions derived from upstream flanterm (C))\n",
    "Linked via: crates/term\n",
    "Source    : vendor/flanterm_rust/ (see README.md there for provenance)\n",
    "==============================================================================\n",
    "\n",
    "------------------------------------------------------------------------------\n",
    "MIT License - applies to new / rewritten Rust code\n",
    "------------------------------------------------------------------------------\n",
    "\n",
    include_str!("../../../vendor/flanterm_rust/LICENSE-MIT"),
    "\n",
    "------------------------------------------------------------------------------\n",
    "BSD-2-Clause - applies to portions derived from upstream flanterm (C)\n",
    "------------------------------------------------------------------------------\n",
    "\n",
    include_str!("../../../vendor/flanterm_rust/LICENSE-BSD-2"),
);

/// `brxlimine-rs`：BORUIX fork 的 limine-rs。上游双许可 MIT OR Apache-2.0，取 MIT 臂。
const BRXLIMINE_RS_TXT: &str = disclosure!(
    "brxlimine-rs 0.1.12 (lib name: limine)",
    "MIT (upstream dual-licenses as MIT OR Apache-2.0; this distribution relies on the MIT arm)",
    "Linked via: crates/kernel, crates/mm, crates/arch/arch-x86_64\nSource    : vendor/brxlimine-rs/ (BORUIX fork; see README.md there for provenance)\n",
    "../../../vendor/brxlimine-rs/LICENSE-MIT"
);

/// 把 [`COMPONENTS`] 中每个组件以**权威重写**语义播种到 [`DIR`] 下。
///
/// 组件级语义（权限、重写理由、软链接策略、失败模式）见 [`seed_one`]。
pub fn seed_all(mount_table: &Arc<vfs::mount::MountTable>) {
    for component in COMPONENTS {
        seed_one(mount_table, component);
    }
}

/// 播种单个组件：创建 `0644`/`(0,0)` 的真实文件，内容为组件披露文本。
///
/// 【权限只在创建时烙印，重写不改】与 `/config/users.json` 种子同口径：
/// 已存在时不 re-chmod，避免把管理员手工收紧的权限改宽。管理员若把披露文件
/// 设为不可读，那是其显式选择，内核不在每次启动时与之对抗。
///
/// 【为何重写而非"存在即跳过"】带盘启动时 `/system` 位于持久 EXT2 分区，
/// 上一轮内核写入的旧文本跨重启保留。披露文本以**当前运行的内核**为权威：
/// 内嵌文本已变（修订/升级/新增组件）而盘上残留旧文本时，披露即失真。故每次
/// 启动先 `truncate(0)` 再写满。截断必须先于写入——`write_at` 只覆盖写入
/// 区间，新文本短于旧文本时若不截断，旧尾巴会残留（对抗验证见
/// `tests::test_licenses_vfs` 第 3 项）。
///
/// # Panics
///
/// 创建/解析/截断/短写任一失败即 panic。静默留下一份残缺或过期的披露文件，
/// 比启动失败更糟（S09 宁可报错，绝不返回伪数据）。
fn seed_one(mount_table: &Arc<vfs::mount::MountTable>, component: &Component) {
    const MODE: u32 = 0o644;
    const OWNER: (u32, u32) = (0, 0);

    let path = alloc::format!("{}/{}", DIR, component.file_name);

    let node = match mount_table.create_file(path.as_str(), MODE, OWNER) {
        Ok(n) => n,
        // 已存在：带盘启动的第二轮（文件已持久化）走这里，取回节点后重写。
        //
        // `follow_symlink = false`：本路径是**权威写入**，绝不跟随软链接。
        // 持久盘上若该名字被替换成指向他处的软链接，跟随就会静默改写链接
        // 目标（把启动期的系统写权当成任意文件写原语）。不跟随时拿到的是
        // 软链接节点，`truncate` 会如实失败并 panic——宁可报错（S09/S20），
        // 也不静默改写一个我们没打算写的文件。
        Err(klib::error::Error::AlreadyExists) => mount_table
            .resolve(path.as_str(), false)
            .unwrap_or_else(|e| panic!("licenses: resolve {}: {:?}", path, e)),
        Err(e) => panic!("licenses: create {}: {:?}", path, e),
    };

    node.truncate(0)
        .unwrap_or_else(|e| panic!("licenses: truncate {}: {:?}", path, e));

    let bytes = component.text.as_bytes();
    match node.write_at(0, bytes) {
        Ok(n) if n == bytes.len() => {}
        other => panic!(
            "licenses: write {} ({} bytes): {:?}",
            path,
            bytes.len(),
            other
        ),
    }
}

