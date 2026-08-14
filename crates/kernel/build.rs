use std::path::PathBuf;

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
}
