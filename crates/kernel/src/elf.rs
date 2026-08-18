//! 静态 ELF64 加载器（M4.3）。
//!
//! 解析 ELF64 可执行文件（ET_EXEC、x86-64、小端），把各 `PT_LOAD` 段
//! 加载到用户地址空间：分配物理帧 → 拷贝 file 内容 → 清零 bss → 按段
//! 权限映射（W^X），并设置用户栈（栈顶放 argc/argv 雏形）。
//!
//! 依赖 `mm::user_space::UserAddressSpace` 提供独立用户页表与映射能力。
//! 与 `scheduler`/`process` 一致，M4 阶段先用 `X86PageTable` 具体类型
//! （ADR-007 抽象层之上），生产化再泛型化。
#![allow(dead_code)]

use alloc::vec::Vec;

use arch::{PageFlags, PageSize, VirtAddr};
use arch_x86_64::paging::X86PageTable;
use klib::error::Error;
use mm::user_space::{UserAddressSpace, USER_STACK_TOP};

// ---------- ELF 常量 ----------

/// ELF magic：`\x7fELF`（`e_ident[0..4]`）。
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// 64 位（`e_ident[EI_CLASS]`）。
const ELFCLASS64: u8 = 2;
/// 小端（`e_ident[EI_DATA]`）。
const ELFDATA2LSB: u8 = 1;
/// 可执行文件（`e_type`）。
const ET_EXEC: u16 = 2;
/// x86-64 机器（`e_machine`）。
const EM_X86_64: u16 = 0x3E;

/// 可加载段（`p_type`）。
const PT_LOAD: u32 = 1;
/// 段标志：可执行 / 可写 / 可读。
const PF_X: u32 = 1;
const PF_W: u32 = 2;
#[allow(dead_code)]
const PF_R: u32 = 4;

/// ELF header 大小（64 字节）。
const EHDR_SIZE: usize = 64;
/// Program header 大小（56 字节）。
const PHDR_SIZE: usize = 56;

/// 用户栈大小（立即映射，8 页 = 32KB；雏形足够 write/exit）。
const USER_STACK_PAGES: usize = 8;

// ---------- 小端读取辅助 ----------

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

#[inline]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

// ---------- 加载结果 ----------

/// ELF 加载结果：进程可据此 `spawn`。
pub struct LoadedElf {
    /// 用户态入口 RIP（`e_entry`）。
    pub entry: u64,
    /// 用户栈顶（初始 `rsp`，指向栈顶 argc 处）。
    pub user_stack_top: u64,
}

// ---------- 加载器 ----------

/// 把 ELF 镜像加载到 `addr_space`，返回入口与用户栈顶。
///
/// `cmd` 为可选命令行（`exec` 系统调用传入的参数字节串，如 `echo hi`）；
/// 非空时在新进程用户栈上布置 `argc=1 / argv[0]=cmd`，使新进程以"一次性
/// 命令模式"启动（见 `setup_user_stack`）；为空则按 `argc=0` 正常启动。
///
/// 流程：
/// 1. 校验 ELF header（magic / 64 位 / 小端 / ET_EXEC / x86-64）；
/// 2. 遍历 program headers，逐段加载所有 `PT_LOAD`（分配物理帧 + 拷贝
///    file 内容 + 清零 bss + 按段权限映射，W^X）；
/// 3. 设置用户栈（立即映射 8 页），栈顶放 argc/argv 雏形或命令行。
pub fn load(
    elf: &[u8],
    addr_space: &mut UserAddressSpace<X86PageTable>,
    cmd: &[u8],
) -> Result<LoadedElf, Error> {
    // 1. 解析并校验 header。
    let (entry, phoff, phentsize, phnum) = parse_header(elf)?;

    // 2. 加载所有 PT_LOAD 段。
    let mut loaded = 0usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if rd_u32(elf, ph) != PT_LOAD {
            continue;
        }
        load_segment(elf, ph, addr_space)?;
        loaded += 1;
    }
    if loaded == 0 {
        return Err(Error::InvalidParam);
    }

    // 3. 设置用户栈 + argc/argv 雏形（或命令行）。
    let stack_top = setup_user_stack(addr_space, cmd)?;

    klib::info!(
        "[elf] loaded {} segments, entry={:#x}, stack_top={:#x}",
        loaded,
        entry,
        stack_top
    );

    Ok(LoadedElf {
        entry,
        user_stack_top: stack_top,
    })
}

/// 解析并校验 ELF header，返回 `(entry, phoff, phentsize, phnum)`。
fn parse_header(elf: &[u8]) -> Result<(u64, usize, usize, usize), Error> {
    if elf.len() < EHDR_SIZE {
        return Err(Error::InvalidParam);
    }
    if elf[0..4] != ELF_MAGIC {
        return Err(Error::InvalidParam);
    }
    if elf[4] != ELFCLASS64 {
        return Err(Error::NotSupported);
    }
    if elf[5] != ELFDATA2LSB {
        return Err(Error::NotSupported);
    }
    let e_type = rd_u16(elf, 16);
    if e_type != ET_EXEC {
        return Err(Error::NotSupported);
    }
    let e_machine = rd_u16(elf, 18);
    if e_machine != EM_X86_64 {
        return Err(Error::NotSupported);
    }
    let entry = rd_u64(elf, 24);
    let phoff = rd_u64(elf, 32) as usize;
    let phentsize = rd_u16(elf, 54) as usize;
    let phnum = rd_u16(elf, 56) as usize;
    if phentsize != PHDR_SIZE {
        return Err(Error::NotSupported);
    }
    Ok((entry, phoff, phentsize, phnum))
}

/// 加载单个 `PT_LOAD` 段：分配物理帧、拷贝 file、清零 bss、映射。
fn load_segment(
    elf: &[u8],
    ph: usize,
    addr_space: &mut UserAddressSpace<X86PageTable>,
) -> Result<(), Error> {
    let p_flags = rd_u32(elf, ph + 4);
    let p_offset = rd_u64(elf, ph + 8);
    let p_vaddr = rd_u64(elf, ph + 16);
    let p_filesz = rd_u64(elf, ph + 32);
    let p_memsz = rd_u64(elf, ph + 40);

    // 雏形：要求段虚拟地址页对齐（静态链接 ELF 的标准情况）。
    if p_vaddr & 0xFFF != 0 {
        return Err(Error::NotSupported);
    }
    if p_memsz < p_filesz {
        return Err(Error::InvalidParam);
    }
    if p_memsz == 0 {
        // 空段：无需映射。
        return Ok(());
    }

    let page_start = p_vaddr;
    let page_end = align_up(p_vaddr + p_memsz, 0x1000);
    let npages = ((page_end - page_start) / 0x1000) as usize;

    // 分配物理帧（逐帧分配，物理地址可能不连续，逐页拷贝）。
    let mut frames = Vec::with_capacity(npages);
    for _ in 0..npages {
        let f = mm::allocate_frame().ok_or(Error::OutOfMemory)?;
        frames.push(f.start_paddr());
    }

    // 逐页拷贝 file 内容 + 清零 bss（经 HHDM）。
    let off = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    for i in 0..npages {
        let dst = (frames[i] + off) as *mut u8;
        let page_lo = (i * 0x1000) as u64;
        let page_hi = ((i as u64) + 1) * 0x1000;
        // 拷贝 file 内容（页与 [0, filesz) 的交集）。
        let copy_hi = page_hi.min(p_filesz);
        if copy_hi > page_lo {
            let n = (copy_hi - page_lo) as usize;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    elf.as_ptr().add((p_offset + page_lo) as usize),
                    dst,
                    n,
                );
            }
        }
        // 清零 bss（页与 [filesz, memsz) 的交集）。
        let zero_lo = page_lo.max(p_filesz);
        let zero_hi = page_hi.min(p_memsz);
        if zero_hi > zero_lo {
            let start = (zero_lo - page_lo) as usize;
            let n = (zero_hi - zero_lo) as usize;
            unsafe {
                core::ptr::write_bytes(dst.add(start), 0, n);
            }
        }
    }

    // 段权限 → 页标志（map_user 会强制 user 位；W^X：可写段不给执行位）。
    let mut flags = PageFlags::empty();
    if p_flags & PF_W != 0 {
        flags = flags.writable();
    }
    if p_flags & PF_X != 0 {
        flags = flags.executable();
    }
    if p_flags & PF_W != 0 && p_flags & PF_X != 0 {
        klib::warn!(
            "[elf] segment {:#x} is both writable and executable (W^X)",
            p_vaddr
        );
    }

    addr_space.map_user(
        VirtAddr::new(page_start),
        VirtAddr::new(page_end),
        PageSize::Size4K,
        flags,
        &frames,
    )?;

    Ok(())
}

/// 设置用户栈：立即映射 8 页，栈顶放 argc/argv 雏形或命令行。
///
/// 无命令行（正常启动，如 init 拉起 shell）时栈顶布局（Linux `_start` 约定）：
/// ```text
///   [stack_top - 16] = argc = 0
///   [stack_top - 8]  = argv[0] = NULL（argv 结束）
/// 初始 rsp = stack_top - 16，故 [rsp]=argc、[rsp+8]=argv[0]
/// ```
///
/// 有命令行（`cmd` 非空，如 `exec(shell, b"echo hi")` 的后台作业模式）时，
/// 在栈顶页内布置字符串与 argv 数组，使新进程以 `argc=1 / argv[0]=cmd` 启动：
/// ```text
///   str_user  = stack_top - 0x200 : "cmd\0"
///   argv_user = stack_top - 0x210 : [str_user (u64), 0 (u64)]
///   rsp_user  = stack_top - 0x220 : [argc=1 (u64), argv_user (u64)]
/// ```
/// 写入位置用 HHDM 内核虚拟地址（`top - off`），但写入的**值**用新进程用户
/// 虚拟地址（`USER_STACK_TOP - off`），二者独立、互不混淆。
fn setup_user_stack(
    addr_space: &mut UserAddressSpace<X86PageTable>,
    cmd: &[u8],
) -> Result<u64, Error> {
    let stack_size = (USER_STACK_PAGES * 0x1000) as u64;
    let stack_top = USER_STACK_TOP;
    let stack_bottom = stack_top - stack_size;

    // 分配物理帧并立即映射（可写）。
    let mut frames = Vec::with_capacity(USER_STACK_PAGES);
    for _ in 0..USER_STACK_PAGES {
        let f = mm::allocate_frame().ok_or(Error::OutOfMemory)?;
        frames.push(f.start_paddr());
    }
    addr_space.map_user(
        VirtAddr::new(stack_bottom),
        VirtAddr::new(stack_top),
        PageSize::Size4K,
        PageFlags::empty().writable(),
        &frames,
    )?;

    // 写 argc/argv 雏形到栈顶页（经 HHDM；栈顶页 = 最后一个帧）。
    let off = arch::PHYS_OFFSET.get().copied().unwrap_or(0);
    unsafe {
        let top = (frames[USER_STACK_PAGES - 1] + off + 0x1000) as *mut u8;

        if !cmd.is_empty() {
            // 栈内偏移（字节，从 stack_top 向下）。
            // 命令字符串放在 0x200 处；argc/argv 按 Linux `_start` 约定直接放在
            // 0x220 起的连续槽位（无独立指针数组间接层）。
            const STR_OFF: usize = 0x200;
            const RSP_OFF: usize = 0x220;
            let str_user = stack_top - STR_OFF as u64;
            let rsp_user = stack_top - RSP_OFF as u64;

            // 命令字符串（含 NUL），最长 STR_OFF-1 字节，超出截断。
            let sp = top.sub(STR_OFF);
            let n = cmd.len().min(STR_OFF - 1);
            for i in 0..n {
                *sp.add(i) = cmd[i];
            }
            *sp.add(n) = 0;

            // 按 Linux `_start` 约定直接布置 argv 数组（连续槽位）：
            //   [rsp]      = argc = 1
            //   [rsp + 8]  = argv[0] = str_user（字符串指针本身）
            //   [rsp + 16] = 0          （argv[1] = NULL 结束符）
            // 注意：`_start` 取 `rsi = [rsp+8]` 当作 `argv[0]`，故此处必须直接
            // 放字符串指针，而非"指向 argv 数组的指针"——后者会让 `user_main`
            // 把指针值当字符串读，首字节即 0 导致命令被丢弃（后台作业瞬间退出）。
            let rp = top.sub(RSP_OFF) as *mut u64;
            *rp = 1; // argc
            *rp.add(1) = str_user; // argv[0]
            *rp.add(2) = 0; // argv[1] = NULL

            return Ok(rsp_user);
        }

        // 无命令行：argc=0, argv=NULL（原行为）。
        let top64 = top as *mut u64;
        *top64.sub(2) = 0; // argc
        *top64.sub(1) = 0; // argv[0]=NULL
    }

    Ok(stack_top - 16)
}
