//! vfs 构建期配置注入（ADR-048 扩展 E1，owner 指令 2026-09-27）。
//!
//! `BORUIX_CONSOLES_N`：console 实例总数（devfs 挂载几个 `/devices/consoles/N`）。
//! 默认 4；钳位 1..=256（上限 = 每实例 4KB 环 ×256 ≈ 1MB 内核堆，启动即付的
//! 合理上界；超过 256 的「无限制」在本内核无 cmdline 的现实下无配置入口，
//! 如实定为编译期上界而非伪运行期可变，S09）。为什么是构建期而非运行期：
//! devfs 挂载发生在内核启动极早期（vfs_init），彼时无用户态、无配置文件、
//! 无 cmdline——「运行期改实例数」在启动序列上是伪需求；构建期注入与
//! init 的 BORUIX_INIT_ARGS 同款先例（S13 同一手法的第二次使用）。

fn main() {
    println!("cargo:rerun-if-env-changed=BORUIX_CONSOLES_N");
    let n: u32 = std::env::var("BORUIX_CONSOLES_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let n = n.clamp(1, 256);
    println!("cargo:rustc-env=BORUIX_CONSOLES_N={}", n);
}
