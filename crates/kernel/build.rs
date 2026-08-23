use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let target = std::env::var("TARGET").expect("TARGET not set");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // 根据目标架构选择链接脚本
    let linker_script = match target.as_str() {
        "x86_64-unknown-none" => "linker.ld",
        other => panic!("Unsupported target for kernel: {other}"),
    };

    let script = PathBuf::from(&manifest_dir).join(linker_script);
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-nostdlib");

    // 注入版本横幅所需的构建元数据（BORUIX KERNEL v.x.y.z / Git Commit / Build Timestamp）
    emit_git_commit();
    emit_build_timestamp();
    emit_symbols_epoch();
}

/// KM13：注入符号纪元（SDK 构建路径为本次构建的唯一标识；直连 cargo build
/// 无此环境变量时注入 0）。内核运行时将其与嵌入符号表自带的 SYMBOLS_EPOCH
/// 比对——不一致即快照陈旧，启动横幅如实告警（见 symbols.rs）。
fn emit_symbols_epoch() {
    // 声明环境输入：否则 build 脚本输出被缓存，SDK 第二遍编译不会因该
    // 环境变量出现而重跑，纪元永远停留在首次值。
    println!("cargo:rerun-if-env-changed=BORUIX_SYMBOLS_EPOCH");
    let epoch = std::env::var("BORUIX_SYMBOLS_EPOCH").unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=BORUIX_SYMBOLS_BUILD_EPOCH={epoch}");
}

/// 注入 git 当前 HEAD 提交 hash（非 git 仓库或命令失败时注入 "Not Found"）。
///
/// 同时跟踪 git 状态：HEAD 与当前分支 ref 变化（提交/切分支/checkout 旧提交）
/// 都会强制重跑本 build.rs，保证每次构建拿到最新提交。
fn emit_git_commit() {
    let commit = git_commit_hash().unwrap_or_else(|| "Not Found".to_string());
    println!("cargo:rustc-env=BORUIX_GIT_COMMIT={commit}");

    if let Some(git_dir) = git_dir() {
        let head = git_dir.join("HEAD");
        println!("cargo:rerun-if-changed={}", head.display());
        if let Ok(content) = std::fs::read_to_string(&head) {
            // HEAD 内容形如 "ref: refs/heads/main"，跟踪对应 ref 文件。
            if let Some(ref_path) = content.strip_prefix("ref: ").map(|s| s.trim()) {
                let p = git_dir.join(ref_path);
                if p.exists() {
                    println!("cargo:rerun-if-changed={}", p.display());
                }
            }
        }
    }
}

/// 注入构建时间戳（毫秒级 Unix 时间，编译时刻）。
fn emit_build_timestamp() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=BORUIX_BUILD_TIMESTAMP={ts}");
}

/// 获取 git 当前 HEAD 提交 hash（失败返回 None）。
fn git_commit_hash() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// 获取 git 目录绝对路径（支持普通仓库与 worktree；非 git 仓库返回 None）。
fn git_dir() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let p = PathBuf::from(s.trim());
    if p.as_os_str().is_empty() {
        None
    } else {
        Some(p)
    }
}
