use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").expect("TARGET not set");
    println!("cargo:rerun-if-changed=build.rs");

    // 根据目标架构选择链接脚本
    let linker_script = match target.as_str() {
        "x86_64-unknown-none" => "src/arch/x86_64/linker.ld",
        other => panic!("Unsupported target for kernel: {other}"),
    };

    println!("cargo:rerun-if-changed={linker_script}");

    // 链接脚本路径
    let script = PathBuf::from(linker_script);
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-nostdlib");
}
