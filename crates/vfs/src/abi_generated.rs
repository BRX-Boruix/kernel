//! **自动生成，请勿手改。**
//!
//! 源：tools/abi/constants.json
//! 生成：python tools/abi/generate.py
//! 门禁：python tools/abi/generate.py --check（已登记进 tools/checks/run_all.py）
//!
//! 手改本文件会被门禁发现；要改数值请改 JSON 再重新生成。


// ---------- 跨 crate 数值（同一数值只在这里写一次） ----------

pub const PAGE_SIZE: usize = 4096;
pub const NAME_MAX: usize = 255;

// ---------- devfs 段名（由完整路径派生，勿手改） ----------

pub const CONSOLE_NODE_NAME: &str = "console";
pub const CONSOLES_DIR_NAME: &str = "consoles";
