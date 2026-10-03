//! 静态 ELF64 加载器与二进制镜像装载（独立 Crate）。
//!
//! 解析 ELF64 可执行文件（ET_EXEC、x86-64、小端），把各 `PT_LOAD` 段
//! 加载到用户地址空间：分配物理帧 → 拷贝 file 内容 → 清零 bss → 按段
//! 权限映射（W^X），并设置用户栈（栈顶放 argc/argv 雏形）。
//!
//! 对抗输入纪律（loader1）：ELF 头与段表的全部字段都是用户可控字节，
//! 一切「表偏移 × 计数」「地址 + 长度」算术全程 checked；任何越界、
//! 溢出、越半区一律显式报错——宁可拒绝镜像，绝不让内核 panic 或把
//! 内核堆内存拷进用户页。
//!
//! 分层（LA4 测试化结构）：
//! - [`raw`] **纯逻辑层**：ELF 头解析与段装载规划的全部校验数学，只依赖
//!   `core`/`alloc`/`klib::error`，host 单测直接覆盖（`cargo test -p loader`）；
//! - **后端层**（`user-space` feature，内核启用）：帧分配、HHDM 访问
//!   与页表映射的执行面。裸机依赖不进 host 构建图。

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

/// 纯逻辑层：ELF 解析 + 段规划。仅在「有测试」或「有后端消费方」时编译，
/// 不产生任何死代码构建面。
#[cfg(any(test, feature = "user-space"))]
pub(crate) mod raw {
    use klib::error::Error;

    // ---------- ELF 格式常量（parse_header 的消费面） ----------
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ET_EXEC: u16 = 2;
    const EM_X86_64: u16 = 0x3E;

    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;

    /// 从 `b[off..]` 读小端 u16。
    ///
    /// 契约：调用方必须已保证 `off + 2 <= b.len()`——程序头表的整体边界在
    /// [`parse_header`] 单点校验（L1），此后所有按表项偏移的读取都在已证
    /// 安全的区间内。
    #[inline]
    pub(crate) fn rd_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }

    /// 从 `b[off..]` 读小端 u32。边界契约同 [`rd_u16`]。
    #[inline]
    pub(crate) fn rd_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    /// 从 `b[off..]` 读小端 u64。边界契约同 [`rd_u16`]。
    #[inline]
    pub(crate) fn rd_u64(b: &[u8], off: usize) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[off..off + 8]);
        u64::from_le_bytes(a)
    }

    /// 向上对齐到 `align`（必须是 2 的幂）。
    ///
    /// S19：`v` 可能是攻击者可控的 u64，裸算术 `v + align - 1` 在 release
    /// 下静默回绕、debug 下 overflow panic；这里全程 checked，溢出返回
    /// `None`，由调用方统一翻译为 `Error::InvalidParam`。
    #[inline]
    pub(crate) fn align_up_checked(v: u64, align: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two());
        Some(v.checked_add(align - 1)? & !(align - 1))
    }

    /// ELF 头解析结果（LD1：命名字段取代匿名四元组）。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ElfHeader {
        /// 入口 RIP（合法性在段规划后由后端统一校验，LM3）。
        pub entry: u64,
        /// 程序头表文件内偏移。已验证 ≥ EHDR_SIZE 且整张表完整落在镜像内（L1）。
        pub phoff: usize,
        pub phentsize: usize,
        pub phnum: usize,
    }

    /// 解析并校验 ELF 头。
    ///
    /// L1：程序头表必须不与 ELF 头重叠、且完整落在镜像内。全部算术
    /// checked——phnum 与 phoff 都是攻击者可控值，回绕后的「合法小值」
    /// 正是越界读 panic 的入口（红阶段实测：len=136、index=4232）。
    pub(crate) fn parse_header(elf: &[u8]) -> Result<ElfHeader, Error> {
        if elf.len() < EHDR_SIZE {
            // LD3：连 ELF 头都装不下 —— 同样属于「这不是 ELF」（ENOEXEC），
            // 而非「是 ELF 但某字段非法」。空文件、被截断的文件、随便一个
            // 短文本文件都会走到这里，它们与"内核不支持这个 ELF"无关。
            return Err(Error::ExecFormat);
        }
        if elf[0..4] != ELF_MAGIC {
            // LD3：**不是 ELF** 与「ELF 头里某字段非法」是两类不同的失败。
            // 前者是「这不是一份可执行镜像」（ENOEXEC），后者是
            // 「是 ELF 但这处参数不合法」（EINVAL）。
            //
            // 此前两者都报 InvalidParam，用户态无法区分「文件坏了」与
            // 「内核不支持」。`Error::ExecFormat` 的文档已写明它表达
            // 「这份镜像本身不合法」，但代码里从未在 magic 处使用，
            // 使该变体在 sys_exec 路径装载上形同虚设。
            // 实测（QEMU）：执行纯文本文件得到 errno=22 而非 8，正是该缺陷。
            return Err(Error::ExecFormat);
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
        let phoff = usize::try_from(rd_u64(elf, 32)).map_err(|_| Error::InvalidParam)?;
        let phentsize = rd_u16(elf, 54) as usize;
        let phnum = rd_u16(elf, 56) as usize;
        if phentsize != PHDR_SIZE {
            return Err(Error::NotSupported);
        }

        if phoff < EHDR_SIZE {
            return Err(Error::InvalidParam);
        }
        let table_bytes = phnum.checked_mul(PHDR_SIZE).ok_or(Error::InvalidParam)?;
        let table_end = phoff
            .checked_add(table_bytes)
            .ok_or(Error::InvalidParam)?;
        if table_end > elf.len() {
            return Err(Error::InvalidParam);
        }

        Ok(ElfHeader {
            entry,
            phoff,
            phentsize,
            phnum,
        })
    }

    /// 程序头中与装载相关的四个字段（S15：单点打包，避免长参数列）。
    #[derive(Clone, Copy)]
    pub(crate) struct SegmentSpec {
        pub p_offset: u64,
        pub p_vaddr: u64,
        pub p_filesz: u64,
        pub p_memsz: u64,
    }

    /// 单个 PT_LOAD 段的装载规划：校验通过后的页几何。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SegmentPlan {
        /// 段虚拟区间起点（= p_vaddr，已验证页对齐）。
        pub vaddr_start: u64,
        /// 页对齐区间终点（= align_up(p_vaddr + p_memsz)，含尾页垫零区）。
        pub vaddr_end: u64,
        /// 覆盖页数。
        pub npages: usize,
    }

    /// 校验单个 PT_LOAD 段并推导其页几何（纯函数：无内存副作用）。
    ///
    /// 汇集 loader1 全部段级对抗校验：
    /// - LM1：p_vaddr 必须按 `page_size` 对齐（本加载器整页映射的限制声明；
    ///   ELF 规范允许非对齐 vaddr 配文件内偏移修正，解除需段内页偏移映射，
    ///   随 PIE/动态链接里程碑立项）；
    /// - L2：段声称的文件内容必须完全落在镜像内——缺失此检查时超出部分会把
    ///   镜像之后相邻的内核堆内存拷进用户页（机密性泄露）；
    /// - L3：地址算术全程 checked（release 裸算术回绕会推导荒谬映射）；
    ///   映射目标必须整体位于用户半区（`user_top`，双层防线之 loader 层，
    ///   提前拒绝避免先分帧再失败）。
    ///
    /// `page_size` / `user_top` 由后端从 arch/mm 单源传入；memsz == 0 的段
    /// 返回空规划（npages == 0），不参与文件边界检查（无内容可读）。
    pub(crate) fn plan_segment(
        elf_len: usize,
        page_size: u64,
        user_top: u64,
        spec: SegmentSpec,
    ) -> Result<SegmentPlan, Error> {
        debug_assert!(page_size.is_power_of_two());

        if spec.p_vaddr % page_size != 0 {
            return Err(Error::NotSupported);
        }
        // S31/S20：不得映射 NULL 页。p_vaddr == 0 会把段落到地址 0——空指针
        // 解引用将不触发故障（掩盖指针 bug）。必须显式拒绝。
        if spec.p_vaddr == 0 {
            return Err(Error::InvalidParam);
        }
        if spec.p_memsz < spec.p_filesz {
            return Err(Error::InvalidParam);
        }
        if spec.p_memsz == 0 {
            return Ok(SegmentPlan {
                vaddr_start: spec.p_vaddr,
                vaddr_end: spec.p_vaddr,
                npages: 0,
            });
        }

        let file_end = spec
            .p_offset
            .checked_add(spec.p_filesz)
            .ok_or(Error::InvalidParam)?;
        if file_end > elf_len as u64 {
            return Err(Error::InvalidParam);
        }

        let vaddr_end = spec
            .p_vaddr
            .checked_add(spec.p_memsz)
            .ok_or(Error::InvalidParam)?;
        let page_start = spec.p_vaddr;
        let page_end = align_up_checked(vaddr_end, page_size).ok_or(Error::InvalidParam)?;

        if page_end > user_top {
            return Err(Error::OutOfRange);
        }
        // page_start 已验证页对齐，故 page_end >= page_start，下方减法不回绕。
        let npages =
            usize::try_from((page_end - page_start) / page_size).map_err(|_| Error::InvalidParam)?;

        Ok(SegmentPlan {
            vaddr_start: page_start,
            vaddr_end: page_end,
            npages,
        })
    }

    // ---------- 入口栈参数块 mini-ABI（docs/abi/syscall-abi.md §4） ----------

    /// 命令行字符串长度上限（字节，**不含** NUL 终止符）——**全系统单点定义**。
    ///
    /// 3P4-2（ABI v2）：此前内核侧拷贝缓冲（4096）与 loader 侧字符串区（511）是**两个**
    /// 门限——512..=4096 的命令行被内核放行、随后在 loader 被 E2BIG 拒绝。同一语义两处
    /// 判断必然漂移，故内核直接引用本常量（`loader::MAX_CMDLINE_BYTES`），门限收敛为一处。
    ///
    /// 取值依据：GCC/tcc 调用 `cc1` 的参数长度必撞旧的 511 上限（3P4-2 依据）；4096 与
    /// 内核单次拷贝缓冲同量级，且远小于用户栈预算（字符串区 + 参数块 < 0x2000）。
    pub const MAX_CMDLINE_BYTES: usize = 4096;

    /// 环境块容量上限（字节：所有 env 串长度 + 各自 NUL 之和）——**单点定义**。
    ///
    /// 3P4-2（ABI v2）：envp 按 §4 预留规则追加（argv 之后、NULL 终结前插入，envp 再其后）。
    pub const MAX_ENV_BYTES: usize = 4096;

    /// 环境变量条数上限（envp 槽位数）——单点定义。
    pub const MAX_ENV_COUNT: usize = 64;

    /// 程序名（`AT_EXECFN` 槽的值来源）长度上限（字节，**不含** NUL）——单点定义。
    ///
    /// 程序名不是 `argv[0]`（后者是整条命令行，语义**不得改变**）：它经 auxv 型的
    /// `AT_EXECFN` 槽单独提供（3P4-2，§4 追加纪律）。
    pub const MAX_PROG_NAME_BYTES: usize = 256;

    /// auxv 槽类型：可执行文件名（与 Linux 的 `AT_EXECFN` 同值 31）。
    pub const AT_EXECFN: u64 = 31;

    /// auxv 终结槽类型（值恒 0）。
    pub const AT_NULL: u64 = 0;

    /// 字符串区偏移：字符串区起于 `stack_top - STR_OFF`，承载**命令行、程序名与环境串**。
    ///
    /// 预算 = 命令行（`MAX_CMDLINE_BYTES` + NUL）+ 程序名（`MAX_PROG_NAME_BYTES` + NUL）
    /// + 环境（`MAX_ENV_BYTES`），向上对齐到 16 字节边界。
    /// **禁止散落魔数**：全部由上述常量派生。
    pub const STR_OFF: usize =
        (MAX_CMDLINE_BYTES + 1 + MAX_PROG_NAME_BYTES + 1 + MAX_ENV_BYTES + 15) & !15;

    /// 入口 `rsp` 相对栈顶的**最小**偏移（空命令行 + 空环境时的字数组下界）。
    ///
    /// ABI v2 起字数组长度随 envp 条数变化，故 `rsp` 由 `entry_block` **动态**算出；
    /// 本常量只用于容量与下溢校验（初始实映射页数亦由算出的 `rsp` 反推）。
    pub const RSP_OFF_MIN: usize = STR_OFF + 0x20;

    /// 入口栈参数块的纯布局结果（mini-ABI）。
    ///
    /// **不是 POSIX argv**：内核不拆词——命令行是**一条字符串**，`argv[0]` 指向它，
    /// `argc` 恒为 1（有命令行时），`argv[1]` 为 NULL。经 shell 派生时该字符串
    /// **不含程序名**（shell 已剥首词）。切分由用户程序完成。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct EntryBlock {
        /// `[rsp + 0x00]`：参数计数（有命令行 = 1，无 = 0）。
        pub argc: u64,
        /// `[rsp + 0x08]`：指向整条命令行字符串（NUL 结尾）；无命令行时为 0。
        pub argv0: u64,
        /// envp 槽位值（逐项指向环境串），位于 `argv[argc]` 的 NULL 终结槽之后。
        ///
        /// 布局（ABI v2）：`argc, argv[0..argc), NULL, envp[0..envc), NULL`——
        /// 消费端可据 `argv + (argc + 1) * 8` 直接定位 envp，无需新 ABI 槽。
        pub envp: alloc::vec::Vec<u64>,
        /// 每个环境串在**字符串区内的字节偏移**（相对 `stack_top - STR_OFF`），与 `envp` 同序。
        pub env_offsets: alloc::vec::Vec<u64>,
        /// `AT_EXECFN` 槽的**值**：指向字符串区内程序名的指针；无程序名时为 `None`。
        ///
        /// 程序名**不是** `argv[0]`（后者是整条命令行）——这正是本槽存在的理由。
        pub prog_name: Option<u64>,
        /// 程序名在字符串区内的字节偏移（写入方据此落串）。
        pub prog_name_offset: Option<u64>,
        /// 入口 `rsp`（字数组首址，16 字节对齐）。
        pub rsp: u64,
    }

    /// 计算入口栈参数块布局——mini-ABI 在代码中的**单点定义**。
    ///
    /// 生产端（`backend::setup_user_stack`）与消费端（`libsys::start`）都以
    /// `docs/abi/syscall-abi.md` §4 为准；本函数是该契约的唯一实现，
    /// host 单测 `tests::entry_block_*` 直接锚定它，文档漂移或实现回退在此先红。
    ///
    /// 错误：
    /// - `cmd_len > MAX_CMDLINE_BYTES` → `ArgListTooLong`（E2BIG）。**绝不截断**：静默裁剪
    ///   会把不完整的命令行伪装成完整交付（LA3/KM5）。
    /// - 环境超 `MAX_ENV_COUNT` 条或超 `MAX_ENV_BYTES` 字节 → 同样显式 `ArgListTooLong`
    ///   （**绝不丢弃**任何一条：静默丢环境与截断命令行同性质）。
    /// - 栈顶不足以容纳字符串区/字数组（算术下溢）→ `OutOfRange`。本函数是纯函数，
    ///   单测会喂任意 `stack_top`，下溢必须显式报错而非回绕出巨地址。
    pub(crate) fn entry_block(
        stack_top: u64,
        cmd_len: usize,
        prog_name: Option<&[u8]>,
        env: &[&[u8]],
    ) -> Result<EntryBlock, Error> {
        if cmd_len > MAX_CMDLINE_BYTES {
            return Err(Error::ArgListTooLong);
        }
        if prog_name.map(|p| p.len()).unwrap_or(0) > MAX_PROG_NAME_BYTES {
            return Err(Error::ArgListTooLong);
        }
        if env.len() > MAX_ENV_COUNT {
            return Err(Error::ArgListTooLong);
        }
        let env_bytes = env
            .iter()
            .try_fold(0usize, |acc, e| acc.checked_add(e.len() + 1))
            .ok_or(Error::OutOfRange)?;
        if env_bytes > MAX_ENV_BYTES {
            return Err(Error::ArgListTooLong);
        }

        let argc: usize = if cmd_len == 0 { 0 } else { 1 };
        // auxv 对：有程序名时 (AT_EXECFN, ptr) + (AT_NULL, 0)，否则仅 (AT_NULL, 0)。
        let auxv_pairs = if prog_name.is_some() { 2 } else { 1 };
        // 字数组：argc + argv[0..argc) + NULL + envp[0..envc) + NULL + auxv 对。
        let words = 1 + argc + 1 + env.len() + 1 + auxv_pairs * 2;
        let str_base = stack_top
            .checked_sub(STR_OFF as u64)
            .ok_or(Error::OutOfRange)?;
        // 字数组紧贴字符串区**之下**，rsp 向下取整到 16 字节对齐（System V 入口要求）。
        let raw_rsp = str_base
            .checked_sub((words * 8) as u64)
            .ok_or(Error::OutOfRange)?;
        let rsp = raw_rsp & !15u64;

        // 字符串区排布：命令行（含 NUL）→ 程序名（含 NUL）→ 环境串（各自含 NUL）。
        let mut off = (cmd_len + if cmd_len == 0 { 0 } else { 1 }) as u64;
        let prog_name_offset = match prog_name {
            Some(p) => {
                let o = off;
                off += (p.len() + 1) as u64;
                Some(o)
            }
            None => None,
        };
        let mut env_offsets = alloc::vec::Vec::new();
        env_offsets.try_reserve(env.len()).map_err(|_| Error::OutOfMemory)?;
        for e in env.iter() {
            env_offsets.push(off);
            off += (e.len() + 1) as u64;
        }
        // envp 槽位地址：字数组内 argv 终结槽之后。
        let envp_first = rsp + ((1 + argc + 1) * 8) as u64;
        let mut envp = alloc::vec::Vec::new();
        envp.try_reserve(env.len()).map_err(|_| Error::OutOfMemory)?;
        for (i, _) in env.iter().enumerate() {
            envp.push(str_base + env_offsets[i]);
        }
        let _ = envp_first;
        Ok(EntryBlock {
            argc: argc as u64,
            argv0: if cmd_len == 0 { 0 } else { str_base },
            envp,
            env_offsets,
            prog_name: prog_name_offset.map(|o| str_base + o),
            prog_name_offset,
            rsp,
        })
    }

    // ---------- 程序头类型的装载处置 ----------

    /// 程序头类型的装载处置（纯函数，host 单测覆盖）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum PhdrClass {
        /// 装载该段（PT_LOAD）。
        Load,
        /// 无需装载、跳过安全（PT_NULL / PT_NOTE / PT_PHDR / PT_GNU_* 等）。
        Skip,
        /// PT_TLS：镜像声明了线程局部存储段——**解析为模板**（不装载、不映射）。
        ///
        /// 此前该段被静默跳过（程序装载成功却在首次 fs: 访问处取指 fault），
        /// 3P0-4 起改为显式拒绝。3P4-1 落地用户态 TLS 后，本类改为「记录模板」：
        /// 每线程的 TLS 块由内核按该模板分配、初始化，并把 FS base 指向块尾 TCB。
        /// 模板的 .tdata 内容仍在某个 PT_LOAD 段内（本类不负责映射）。
        TlsTemplate,
        /// 明确拒绝：PT_INTERP——镜像要求动态链接器，而本加载器只接受静态
        /// ET_EXEC（ET_DYN 已在 parse_header 处拒绝）。
        RejectInterp,
        /// 明确拒绝：PT_DYNAMIC——镜像带动态链接元数据（需要重定位），而本
        /// 加载器不做任何重定位。
        RejectDynamic,
    }

    /// 判定单个程序头类型的处置。
    ///
    /// **拒绝面**只覆盖「要求本加载器不具备的能力」的三类（TLS / 动态链接器 /
    /// 重定位），其余类型一律 Skip。该分界的经验依据：实测现有 33 个用户态程序
    /// （32 个内置 + 第三方样例）只出现 PT_LOAD / PT_GNU_RELRO / PT_GNU_STACK，
    /// 故 Skip 面对它们是空操作、拒绝面为零影响。
    pub(crate) fn classify_phdr(p_type: u32) -> PhdrClass {
        const PT_LOAD: u32 = 1;
        const PT_DYNAMIC: u32 = 2;
        const PT_INTERP: u32 = 3;
        const PT_TLS: u32 = 7;
        match p_type {
            PT_LOAD => PhdrClass::Load,
            PT_TLS => PhdrClass::TlsTemplate,
            PT_INTERP => PhdrClass::RejectInterp,
            PT_DYNAMIC => PhdrClass::RejectDynamic,
            _ => PhdrClass::Skip,
        }
    }

    // ---------- PT_TLS 模板（用户态 TLS，docs/TODO/3p.md 3P4-1） ----------

    /// ELF PT_TLS 描述的用户态 TLS 模板。
    ///
    /// **模板不是映射**：[offset, offset+filesz) 是 .tdata 在镜像文件中的初值，
    /// 其虚拟地址 vaddr 落在某个 PT_LOAD 段内（因此装载后也可从用户地址空间读到）。
    /// 每个线程需要自己的一份副本：内核按 memsz/align 分配块，把 filesz 字节初值
    /// 拷进去、其余补零，然后令 FS base = 块尾 TCB。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct TlsTemplate {
        /// .tdata 初值在文件中的偏移。
        pub offset: u64,
        /// .tdata 初值的目标虚拟地址（仅用于范围校验；块是另分配的）。
        pub vaddr: u64,
        /// 已初始化部分大小（.tdata）。
        pub filesz: u64,
        /// TLS 块大小（.tdata + .tbss）。
        pub memsz: u64,
        /// 块对齐（ELF 要求 0 或 2 的幂）。
        pub align: u64,
    }

    /// 解析并校验一个 PT_TLS 程序头（纯函数，host 单测覆盖）。
    ///
    /// 校验（loader1 的对抗输入纪律）：
    /// - filesz <= memsz（否则声明了超出块大小的初值）；
    /// - align 为 0/1 或 2 的幂（ELF 规范要求）；
    /// - offset + filesz 落在镜像内（L2：越界会把镜像外内存当初值拷进用户页）；
    /// - vaddr + filesz 不回绕（checked）。
    ///
    /// 「模板虚拟地址必须落在某个已加载段内」由 backend 结合段区间集合校验——
    /// 本函数不持有段信息。
    pub(crate) fn parse_tls_template(elf: &[u8], ph: usize) -> Result<TlsTemplate, Error> {
        let offset = rd_u64(elf, ph + 8);
        let vaddr = rd_u64(elf, ph + 16);
        let filesz = rd_u64(elf, ph + 32);
        let memsz = rd_u64(elf, ph + 40);
        let align = rd_u64(elf, ph + 48);
        if filesz > memsz {
            return Err(Error::InvalidParam);
        }
        if align != 0 && align != 1 && !align.is_power_of_two() {
            return Err(Error::InvalidParam);
        }
        let file_end = offset.checked_add(filesz).ok_or(Error::OutOfRange)?;
        if file_end > elf.len() as u64 {
            return Err(Error::InvalidParam);
        }
        vaddr.checked_add(filesz).ok_or(Error::OutOfRange)?;
        Ok(TlsTemplate {
            offset,
            vaddr,
            filesz,
            memsz,
            align,
        })
    }

    // ---------- host 单测（`cargo test -p loader`） ----------
    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;

        /// 与 mm::user_space::USER_TOP 一致的用户半区上界（host 构建无 mm
        /// 依赖的镜像常量；mm 侧变更时由集成测试暴露分歧）。
        const TEST_USER_TOP: u64 = 0x0000_8000_0000_0000;
        const PAGE: u64 = 0x1000;

        // ---- rd_* 小端读取 ----

        #[test]
        fn little_endian_reads() {
            let b = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
            assert_eq!(rd_u16(&b, 0), 0x0201);
            assert_eq!(rd_u32(&b, 0), 0x0403_0201);
            assert_eq!(rd_u64(&b, 0), u64::from_le_bytes(b));
        }

        // ---- align_up_checked ----

        #[test]
        fn align_up_basics_and_overflow() {
            assert_eq!(align_up_checked(0, PAGE), Some(0));
            assert_eq!(align_up_checked(1, PAGE), Some(PAGE));
            assert_eq!(align_up_checked(PAGE, PAGE), Some(PAGE));
            assert_eq!(align_up_checked(PAGE + 1, PAGE), Some(2 * PAGE));
            // 已对齐的最大可能值：不溢出，原样返回
            assert_eq!(
                align_up_checked(u64::MAX - PAGE + 1, PAGE),
                Some(u64::MAX - PAGE + 1)
            );
            // 距对齐界差一：对齐上溢必须被拦截
            assert_eq!(align_up_checked(u64::MAX - PAGE + 2, PAGE), None);
            assert_eq!(align_up_checked(u64::MAX, PAGE), None);
        }

        // ---- parse_header ----

        /// 组装最小合法 ET_EXEC 骨架；`entry/phoff/phentsize/phnum` 可覆写
        /// 产生对抗变体，文件体保持合法形状——只有被测字段是变量。
        fn build_elf(entry: u64, phoff: u64, phentsize: u16, phnum: u16) -> alloc::vec::Vec<u8> {
            let mut e = alloc::vec::Vec::new();
            let w16 = |v: &mut alloc::vec::Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
            let w32 = |v: &mut alloc::vec::Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
            let w64 = |v: &mut alloc::vec::Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
            e.extend_from_slice(&ELF_MAGIC);
            e.push(ELFCLASS64);
            e.push(ELFDATA2LSB);
            e.push(1); // EI_VERSION
            e.extend_from_slice(&[0u8; 9]);
            w16(&mut e, ET_EXEC);
            w16(&mut e, EM_X86_64);
            w32(&mut e, 1); // e_version
            w64(&mut e, entry);
            w64(&mut e, phoff);
            w64(&mut e, 0); // e_shoff
            w32(&mut e, 0); // e_flags
            w16(&mut e, 64); // e_ehsize
            w16(&mut e, phentsize);
            w16(&mut e, phnum);
            w16(&mut e, 0); // e_shentsize
            w16(&mut e, 0); // e_shnum
            w16(&mut e, 0); // e_shstrndx
            e.resize(EHDR_SIZE, 0);
            // 一个真实表项（内容仅作占位，长度恰好 PHDR_SIZE）
            e.extend_from_slice(&[0xA5u8; PHDR_SIZE]);
            e
        }

        #[test]
        fn parse_rejects_structural_garbage() {

            // LD3：magic 不对 = **不是 ELF**，必须是 ExecFormat（ENOEXEC），
            // 不能与「ELF 头字段非法」（InvalidParam/EINVAL）混为一谈。
            let mut magic = build_elf(0, 64, 56, 1);
            magic[0] = 0;
            assert_eq!(parse_header(&magic), Err(Error::ExecFormat));
            // 同一条纪律：空文件 / 短于 ELF 头同样是「不是 ELF」。
            assert_eq!(parse_header(&[]), Err(Error::ExecFormat));
            assert_eq!(parse_header(&[0x7f]), Err(Error::ExecFormat));
            // 纯文本文件（长度足够但 magic 不对）—— 这正是用户在 shell 里
            // 敲一个非 ELF 文件时走的路径，实测曾错误地得到 EINVAL(22)。
            assert_eq!(
                parse_header(b"this is plain text, not an ELF image\n"),
                Err(Error::ExecFormat)
            );

            let mut class = build_elf(0, 64, 56, 1);
            class[4] = 1; // ELFCLASS32
            assert_eq!(parse_header(&class), Err(Error::NotSupported));

            let mut data = build_elf(0, 64, 56, 1);
            data[5] = 2; // ELFDATA2MSB
            assert_eq!(parse_header(&data), Err(Error::NotSupported));

            let mut etype = build_elf(0, 64, 56, 1);
            etype[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
            assert_eq!(parse_header(&etype), Err(Error::NotSupported));

            let mut machine = build_elf(0, 64, 56, 1);
            machine[18..20].copy_from_slice(&0x03u16.to_le_bytes()); // EM_386
            assert_eq!(parse_header(&machine), Err(Error::NotSupported));

            let entsize = build_elf(0, 64, 32, 1);
            assert_eq!(parse_header(&entsize), Err(Error::NotSupported));
        }

        #[test]
        fn parse_rejects_out_of_bounds_table() {
            // 表起点越过镜像末端
            let beyond = build_elf(0, 64 + 56 + 0x1000, 56, 1);
            assert_eq!(parse_header(&beyond), Err(Error::InvalidParam));
            // 表落进 ELF 头区内
            let inside = build_elf(0, 8, 56, 1);
            assert_eq!(parse_header(&inside), Err(Error::InvalidParam));
            // phoff + phnum*phentsize 算术回绕
            let overflow = build_elf(0, u64::MAX - 7, 56, 1);
            assert_eq!(parse_header(&overflow), Err(Error::InvalidParam));
            // 表声明计数超出文件实际容量（文件只有 1 个表项的空间）
            let overrun = build_elf(0, 64, 56, 2);
            assert_eq!(parse_header(&overrun), Err(Error::InvalidParam));
            // 边界恰合：表终点 == 镜像终点，必须放行且字段保真
            let exact = build_elf(0x40_0000, 64, 56, 1);
            let hdr = parse_header(&exact).expect("boundary-exact table must pass");
            assert_eq!(hdr.entry, 0x40_0000);
            assert_eq!(hdr.phoff, 64);
            assert_eq!(hdr.phnum, 1);
        }

        // ---- plan_segment ----

        const BASE_SPEC: SegmentSpec = SegmentSpec {
            p_offset: 120,
            p_vaddr: 0x40_0000,
            p_filesz: 0x10,
            p_memsz: 0x1008, // 跨页：bss 尾 + 末页垫零区
        };

        fn plan(elf_len: usize, spec: SegmentSpec) -> Result<SegmentPlan, Error> {
            plan_segment(elf_len, PAGE, TEST_USER_TOP, spec)
        }

        #[test]
        fn plan_rejects_unaligned_vaddr() {
            let spec = SegmentSpec {
                p_vaddr: 0x40_0800,
                ..BASE_SPEC
            };
            assert_eq!(plan(136, spec), Err(Error::NotSupported));
        }

        #[test]
        fn plan_rejects_memsz_below_filesz() {
            let spec = SegmentSpec {
                p_memsz: BASE_SPEC.p_filesz - 1,
                ..BASE_SPEC
            };
            assert_eq!(plan(136, spec), Err(Error::InvalidParam));
        }

        #[test]
        fn plan_empty_for_zero_memsz() {
            let spec = SegmentSpec {
                p_filesz: 0,
                p_memsz: 0,
                ..BASE_SPEC
            };
            let got = plan(136, spec).expect("empty segment must pass");
            assert_eq!(got.npages, 0);
            assert_eq!(got.vaddr_start, got.vaddr_end);
        }

        #[test]
        fn plan_rejects_file_overrun() {
            // 文件内容声称 0x10000 字节而镜像只有 136 —— 内核堆泄露面（L2）
            let spec = SegmentSpec {
                p_filesz: 0x1_0000,
                p_memsz: 0x1_0000,
                ..BASE_SPEC
            };
            assert_eq!(plan(136, spec), Err(Error::InvalidParam));
            // 边界恰合：file_end == elf_len 放行
            let exact = SegmentSpec {
                p_offset: 120,
                p_vaddr: 0x40_0000,
                p_filesz: 16,
                p_memsz: PAGE,
            };
            assert!(plan(136, exact).is_ok());
        }

        #[test]
        fn plan_rejects_arithmetic_overflow() {
            // p_vaddr + p_memsz 直接回绕（checked_add 拦截）
            let add = SegmentSpec {
                p_vaddr: 0xFFFF_FFFF_FFFF_F000,
                p_offset: 120,
                p_filesz: 0,
                p_memsz: 0x2000,
            };
            assert_eq!(plan(136, add), Err(Error::InvalidParam));
            // 加法不溢出但对齐上溢（align_up_checked 拦截）
            let aln = SegmentSpec {
                p_vaddr: 0xFFFF_FFFF_FFFF_F000,
                p_offset: 120,
                p_filesz: 0,
                p_memsz: 0x0FFF,
            };
            assert_eq!(plan(136, aln), Err(Error::InvalidParam));
        }

        #[test]
        fn plan_rejects_beyond_user_half() {
            let spec = SegmentSpec {
                p_vaddr: PAGE,
                p_memsz: TEST_USER_TOP + PAGE, // page_end 必然越半区
                ..BASE_SPEC
            };
            assert_eq!(plan(usize::MAX, spec), Err(Error::OutOfRange));
            // 边界恰合：page_end == user_top 放行
            let ok_spec = SegmentSpec {
                p_vaddr: TEST_USER_TOP - PAGE,
                p_offset: 120,
                p_filesz: 16,
                p_memsz: PAGE,
            };
            let got = plan(136, ok_spec).expect("page_end == user_top must pass");
            assert_eq!(got.vaddr_end, TEST_USER_TOP);
        }

        /// S31/S20 回归：`p_vaddr == 0` 会把段映射到 NULL 页——空指针解引用
        /// 将不触发故障（掩盖指针 bug）。必须拒绝，不得映射地址 0。
        #[test]
        fn plan_rejects_null_page_vaddr() {
            let spec = SegmentSpec {
                p_vaddr: 0,
                p_offset: 120,
                p_filesz: 16,
                p_memsz: PAGE,
            };
            assert_eq!(
                plan(136, spec),
                Err(Error::InvalidParam),
                "mapping the NULL page must be rejected"
            );
        }

        #[test]
        fn plan_page_math_and_boundaries() {            // 跨页 bss：npages = 2，终点对齐到下一页界
            let got = plan(136, BASE_SPEC).expect("base spec must pass");
            assert_eq!(
                got,
                SegmentPlan {
                    vaddr_start: 0x40_0000,
                    vaddr_end: 0x40_2000,
                    npages: 2,
                }
            );
            // memsz 恰为整页倍数：不产生多余页
            let whole = SegmentSpec {
                p_memsz: 2 * PAGE,
                ..BASE_SPEC
            };
            assert_eq!(plan(136, whole).expect("whole pages").npages, 2);
            // filesz == memsz 的纯文件段同样成立
            let plain = SegmentSpec {
                p_memsz: PAGE,
                ..BASE_SPEC
            };
            assert_eq!(plan(136, plain).expect("plain").npages, 1);
        }

        // ---- entry_block：入口栈参数块 mini-ABI（docs/abi/syscall-abi.md §4） ----
        //
        // 这些断言是 §4 的**行为锚点**：文档若漂移、实现若回退，此处先红。
        // 语义要点（与 POSIX argv 的差异，勿按 POSIX 直觉修改）：
        //   - argc 恒为 1（有命令行时），**内核不拆词**；
        //   - argv[0] 指向**整条命令行字符串**（shell 派生时不含程序名）；
        //   - argv[1] = NULL；拆词是用户程序的职责。

        /// 与 mm::user_space::USER_STACK_TOP 同形的 16 字节对齐栈顶（host 侧样本值）。
        const TEST_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

        #[test]
        fn entry_block_points_argv0_at_whole_cmdline() {
            let b = entry_block(TEST_STACK_TOP, 5, None, &[]).expect("5 字节命令行应被接受");
            assert_eq!(b.argc, 1, "有命令行时 argc 恒为 1（不拆词）");
            assert_eq!(
                b.argv0,
                TEST_STACK_TOP - STR_OFF as u64,
                "argv[0] 指向整条命令行字符串区首址，不是程序名"
            );
            assert!(b.envp.is_empty(), "空环境：envp 无槽位");
            // 字数组（argc + argv[0] + NULL + envp NULL = 32 字节，空环境）整体位于
            // 字符串区**之下**，且与 System V 的 16 字节入口对齐要求相容。
            assert!(b.rsp + 32 <= b.argv0, "字数组不得与字符串区重叠");
            assert_eq!(b.rsp % 16, 0, "entry 处 rsp 须 16 字节对齐");
        }

        #[test]
        fn entry_block_without_cmdline_has_zero_argc() {
            let b = entry_block(TEST_STACK_TOP, 0, None, &[]).expect("空命令行合法");
            assert_eq!(b.argc, 0, "无命令行时 argc 槽为 0");
            assert_eq!(b.argv0, 0, "无命令行时 argv[0] 槽为 0");
            // ABI v2 起布局**统一**（不再有"第三字越出栈顶页"的特例）：空命令行下字数组
            // 仍是 argc + argv NULL + envp NULL，故 envp 定位规则对两种 argc 一致。
            let str_base = TEST_STACK_TOP - STR_OFF as u64;
            assert!((str_base - b.rsp) / 8 >= 3, "空命令行下字数组至少 3 字");
            assert_eq!(b.rsp % 16, 0);
        }

        #[test]
        fn entry_block_accepts_capacity_limit_and_rejects_beyond() {
            // MAX_CMDLINE_BYTES 是命令行长度上限（不含 NUL 终止符）：恰满可交付。
            assert!(entry_block(TEST_STACK_TOP, MAX_CMDLINE_BYTES, None, &[]).is_ok());
            // 超一字节即显式拒绝——绝不截断后把裁剪过的命令行伪装成完整交付（LA3/KM5）。
            assert_eq!(
                entry_block(TEST_STACK_TOP, MAX_CMDLINE_BYTES + 1, None, &[]),
                Err(Error::ArgListTooLong)
            );
            // 3P4-2 行为锚点：**旧上限（511）必须已解除**——512..=MAX 之间一律可交付。
            // 若只改了常量而没改契约，本断言先红（文档漂移/实现回退在此暴露）。
            assert!(
                entry_block(TEST_STACK_TOP, 0x1FF + 1, None, &[]).is_ok(),
                "511 字节旧上限必须已解除（3P4-2）"
            );
            assert!(entry_block(TEST_STACK_TOP, 4096, None, &[]).is_ok());
        }

        #[test]
        fn entry_block_rejects_stack_top_underflow() {
            // 栈顶小到放不下参数块/字符串区时必须显式报错，不得回绕出巨地址。
            assert!(entry_block(0, 1, None, &[]).is_err());
            assert!(entry_block(RSP_OFF_MIN as u64 - 1, 1, None, &[]).is_err());
        }

        #[test]
        fn entry_block_lays_out_envp_after_argv() {
            let env: [&[u8]; 2] = [b"PATH=/programs", b"HOME=/"];
            let b = entry_block(TEST_STACK_TOP, 5, None, &env).expect("带环境应被接受");
            assert_eq!(b.argc, 1);
            assert_eq!(b.envp.len(), 2, "envp 槽位数 = 环境条数");
            let str_base = TEST_STACK_TOP - STR_OFF as u64;
            // envp 指向字符串区内的环境串，且区内偏移紧凑排布（各自含 NUL）。
            assert_eq!(b.envp[0], str_base + b.env_offsets[0]);
            assert_eq!(b.envp[1], str_base + b.env_offsets[1]);
            assert!(b.env_offsets[0] >= 6, "环境串排在命令行（5 + NUL）之后");
            assert_eq!(
                b.env_offsets[1] - b.env_offsets[0],
                env[0].len() as u64 + 1,
                "环境串在区内紧凑排布（各自含 NUL）"
            );
            // 字数组：[argc][argv0][NULL][envp0][envp1][NULL]（6 字 = 48 字节）。
            assert!(b.rsp + 48 <= str_base, "字数组必须整体在字符串区之下");
            assert_eq!(b.rsp % 16, 0, "entry 处 rsp 须 16 字节对齐");
            // 消费端定位规则（ABI §4）：envp = argv + (argc + 1) * 8，
            // 其中 argv 即 argv[0] 槽地址（rsp + 8）。
            let argv_slot = b.rsp + 8;
            assert_eq!(
                argv_slot + (b.argc + 1) * 8,
                b.rsp + 24,
                "envp 首槽紧跟 argv 的 NULL 终结槽"
            );
        }

        #[test]
        fn entry_block_lays_out_execfn_auxv_after_envp() {
            let env: [&[u8]; 1] = [b"PATH=/programs"];
            let b = entry_block(TEST_STACK_TOP, 5, Some(b"tlsdemo"), &env).expect("带程序名应被接受");
            let str_base = TEST_STACK_TOP - STR_OFF as u64;
            let execfn = b.prog_name.expect("有程序名时 AT_EXECFN 值必须存在");
            assert_eq!(execfn, str_base + b.prog_name_offset.unwrap());
            // 字符串区排布：命令行（5 + NUL）→ 程序名（7 + NUL）→ 环境串。
            assert_eq!(b.prog_name_offset, Some(6), "程序名紧随命令行（含其 NUL）");
            assert_eq!(b.env_offsets[0], 6 + 8, "环境串排在程序名（含 NUL）之后");
            // 字数组：argc, argv0, NULL, envp0, NULL, AT_EXECFN, ptr, AT_NULL, 0 = 9 字。
            assert!(b.rsp + 72 <= str_base, "字数组（9 字）必须整体在字符串区之下");
            assert_eq!(b.rsp % 16, 0, "entry 处 rsp 须 16 字节对齐");
            // **语义锚点**：程序名指针不得等于 argv[0]——后者指向整条命令行，含义不得改变。
            assert_ne!(execfn, b.argv0, "AT_EXECFN 与 argv[0] 必须是不同的串");
        }

        #[test]
        fn entry_block_rejects_prog_name_over_limit() {
            let big = alloc::vec![b'n'; MAX_PROG_NAME_BYTES + 1];
            assert_eq!(
                entry_block(TEST_STACK_TOP, 0, Some(&big), &[]),
                Err(Error::ArgListTooLong)
            );
            let exact = alloc::vec![b'n'; MAX_PROG_NAME_BYTES];
            assert!(entry_block(TEST_STACK_TOP, 0, Some(&exact), &[]).is_ok());
        }

        #[test]
        fn entry_block_rejects_env_over_limits() {
            // 条数超限 → 显式拒绝（**绝不静默丢弃**环境变量，与命令行不截断同政策）。
            let many: alloc::vec::Vec<&[u8]> = alloc::vec![&b"K=V"[..]; MAX_ENV_COUNT + 1];
            assert_eq!(
                entry_block(TEST_STACK_TOP, 0, None, &many),
                Err(Error::ArgListTooLong)
            );
            // 字节数超限 → 同样显式拒绝。
            let big = alloc::vec![b'x'; MAX_ENV_BYTES];
            let over: [&[u8]; 1] = [&big];
            assert_eq!(
                entry_block(TEST_STACK_TOP, 0, None, &over),
                Err(Error::ArgListTooLong)
            );
            // 边界内侧（恰满字节预算）可交付。
            let exact = alloc::vec![b'y'; MAX_ENV_BYTES - 1];
            let ok: [&[u8]; 1] = [&exact];
            assert!(entry_block(TEST_STACK_TOP, 0, None, &ok).is_ok());
        }

        // ---- classify_phdr：程序头类型的装载处置 ----
        //
        // 这一组锚定「哪些 p_type 必须被拒绝」：静默跳过要求未实现能力的段，
        // 会让镜像「装载成功」而在运行期崩（伪支持，S09）。

        #[test]
        fn classify_phdr_loads_only_pt_load() {
            assert_eq!(classify_phdr(1), PhdrClass::Load); // PT_LOAD
        }

        #[test]
        fn classify_phdr_rejects_unimplemented_capabilities() {
            // PT_TLS(7)：3P4-1 起改为**解析模板**（不再是拒绝）。
            assert_eq!(classify_phdr(7), PhdrClass::TlsTemplate);
            // PT_INTERP(3)：需要动态链接器；本加载器只接受静态 ET_EXEC。
            assert_eq!(classify_phdr(3), PhdrClass::RejectInterp);
            // PT_DYNAMIC(2)：动态链接元数据；本加载器不做任何重定位。
            assert_eq!(classify_phdr(2), PhdrClass::RejectDynamic);
        }

        #[test]
        fn classify_phdr_skips_types_present_in_real_programs() {
            // 实测：现有 33 个用户态程序（32 内置 + 第三方样例）只含
            // PT_LOAD / PT_GNU_RELRO / PT_GNU_STACK。这三类之外的良性类型
            // 必须继续可跳过，否则会把今天能跑的程序拒之门外。
            assert_eq!(classify_phdr(0x6474_e551), PhdrClass::Skip); // PT_GNU_STACK
            assert_eq!(classify_phdr(0x6474_e552), PhdrClass::Skip); // PT_GNU_RELRO
            assert_eq!(classify_phdr(0), PhdrClass::Skip); // PT_NULL
            assert_eq!(classify_phdr(4), PhdrClass::Skip); // PT_NOTE
            assert_eq!(classify_phdr(6), PhdrClass::Skip); // PT_PHDR
        }

        // ---- parse_tls_template：PT_TLS 模板解析与校验 ----

        /// 覆写 build_elf 留下的占位程序头（位于偏移 64，长度 56）。
        fn write_phdr_fields(e: &mut alloc::vec::Vec<u8>, p_offset: u64, p_vaddr: u64, filesz: u64, memsz: u64, align: u64) {
            let ph = EHDR_SIZE;
            e[ph..ph + 4].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
            e[ph + 4..ph + 8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
            e[ph + 8..ph + 16].copy_from_slice(&p_offset.to_le_bytes());
            e[ph + 16..ph + 24].copy_from_slice(&p_vaddr.to_le_bytes());
            e[ph + 24..ph + 32].copy_from_slice(&0u64.to_le_bytes()); // p_paddr
            e[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
            e[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
            e[ph + 48..ph + 56].copy_from_slice(&align.to_le_bytes());
        }

        /// 组装「头 + 1 个 PT_TLS 程序头 + 16 字节模板内容」的最小镜像。
        fn build_tls_elf(p_offset: u64, p_vaddr: u64, filesz: u64, memsz: u64, align: u64) -> alloc::vec::Vec<u8> {
            let mut e = build_elf(0x40_0000, EHDR_SIZE as u64, 56, 1);
            write_phdr_fields(&mut e, p_offset, p_vaddr, filesz, memsz, align);
            e.extend_from_slice(&[0xA5; 16]);
            e
        }

        #[test]
        fn tls_template_reads_fields() {
            let elf = build_tls_elf(120, 0x40_2000, 4, 8, 4);
            let t = parse_tls_template(&elf, 64).expect("合法 PT_TLS");
            assert_eq!(t.offset, 120);
            assert_eq!(t.vaddr, 0x40_2000);
            assert_eq!(t.filesz, 4);
            assert_eq!(t.memsz, 8);
            assert_eq!(t.align, 4);
        }

        #[test]
        fn tls_template_rejects_filesz_above_memsz() {
            let elf = build_tls_elf(120, 0x40_2000, 16, 8, 4);
            assert_eq!(parse_tls_template(&elf, 64), Err(Error::InvalidParam));
        }

        #[test]
        fn tls_template_rejects_non_power_of_two_align() {
            let elf = build_tls_elf(120, 0x40_2000, 4, 4, 3);
            assert_eq!(parse_tls_template(&elf, 64), Err(Error::InvalidParam));
        }

        #[test]
        fn tls_template_rejects_vaddr_overflow() {
            let elf = build_tls_elf(120, u64::MAX - 3, 8, 8, 4);
            assert_eq!(parse_tls_template(&elf, 64), Err(Error::OutOfRange));
        }

        #[test]
        fn tls_template_accepts_align_zero_and_one() {
            assert!(parse_tls_template(&build_tls_elf(120, 0x40_2000, 4, 4, 0), 64).is_ok());
            assert!(parse_tls_template(&build_tls_elf(120, 0x40_2000, 4, 4, 1), 64).is_ok());
        }
    }
}

// ---------- 后端层：用户地址空间装载（kernel 经 user-space feature 启用） ----------
#[cfg(feature = "user-space")]
mod backend {
    use super::raw::{
        AT_EXECFN, AT_NULL, MAX_CMDLINE_BYTES, MAX_ENV_BYTES, MAX_ENV_COUNT, MAX_PROG_NAME_BYTES,
        PhdrClass, RSP_OFF_MIN, STR_OFF, SegmentSpec, TlsTemplate, align_up_checked, classify_phdr,
        entry_block, parse_header, parse_tls_template, plan_segment, rd_u32, rd_u64,
    };
    use alloc::vec::Vec;
    use arch::{PageFlags, PageSize, VirtAddr};
    use arch_x86_64::paging::X86PageTable;
    use klib::error::Error;
    use mm::user_space::{DEFAULT_STACK_SIZE, TlsParams, USER_STACK_TOP, USER_TOP, UserAddressSpace};

    // PT_LOAD 的判定已上收至 raw::classify_phdr（单点），此处不再保留本地常量。
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    /// 段标志：可读。x86-64 PTE 没有「禁止读」位——present 页恒可读，因此
    /// PF_R 在权限映射中结构性成立、无需参与 flags 计算（LM6）。常量保留
    /// 以对照 ELF 规范，`dead_code` 豁免即此语义说明。
    #[allow(dead_code)]
    const PF_R: u32 = 4;

    /// S28/S17：栈尺寸单一来源取自 `mm::user_space::DEFAULT_STACK_SIZE`。
    /// 此前本文件硬编码 `USER_STACK_PAGES=8`（32KiB），无视 mm 已单点定义
    /// 的 4MiB 规范栈——重复声明小 128 倍且无理由，深递归用户栈极易溢出。
    /// 改为按规范常量推导页数（4MiB / 4KiB = 1024 页）。
    const USER_STACK_PAGES: usize =
        (DEFAULT_STACK_SIZE as usize) / (PageSize::Size4K.bytes() as usize);

    /// 本加载器的映射页粒度（LM5：单一来源取自 arch 抽象层，编译期取值）。
    const PAGE_SIZE: u64 = PageSize::Size4K.bytes();

    /// 帧收集 Vec 的增量扩容粒度。
    ///
    /// 扩容必须走 [`Vec::try_reserve`]：常规 push 触发的堆再分配在物理帧
    /// 耗尽场景下可能连带需要新帧（动态堆增长源），失败即全局 alloc error
    /// panic——耗尽分支的优雅性由此保证（LA4 资源耗尽轴的结构加固）。
    const FRAME_LIST_CHUNK: usize = 64;

    /// HHDM（高半区直接映射）偏移。
    ///
    /// LA1：初始化缺失时不得以 0 兜底——那会把物理地址当虚拟指针直接读写
    /// 内存，比显式失败危险得多。语义上是「必需的启动状态不存在」；Error
    /// 表尚无 Internal 类变体（LD2 的 ExecFormat 已按其自身语义落地，与此
    /// 不同族），暂取 `NotFound` 表达；动态上下文经日志输出（ADR-010：
    /// 错误码保持零分配、可比较）。
    fn hhdm_offset() -> Result<u64, Error> {
        arch::PHYS_OFFSET.get().copied().ok_or(Error::NotFound)
    }

    /// ELF 加载结果：进程可据此 `spawn`。
    pub struct LoadedElf {
        /// 用户态入口 RIP（`e_entry`）。
        pub entry: u64,
        /// 用户栈顶（初始 `rsp`，指向栈顶 argc 处）。
        pub user_stack_top: u64,
        /// 主线程的 TLS 段基址（`IA32_FS_BASE` 初值）。镜像无 PT_TLS 时为 None，
        /// 此时该单元 `fs_base = 0`（与 3P4-1 之前的行为一致）。
        pub tls_fs_base: Option<u64>,
    }

    /// 把 ELF 镜像加载到 `addr_space`，返回入口与用户栈顶。
    ///
    /// 失败时的资源纪律分两层：
    /// - loader 自身收集的物理帧在**任何**错误路径当场全额退还帧池
    ///   （[`collect_frames`] 收集段 + [`refund_frames`] 映射拒绝段，
    ///   audit-r2 F1）；
    /// - `addr_space` 内已成功入账的映射由其 `Drop`（destroy 台账语义）
    ///   回收。台账外的中间状态——mm 侧 `pt.map` 中途失败的已映射页不入
    ///   areas 台账——不在本承诺范围内，见 docs/degradation.md D10；当前
    ///   exec 错误路径 CR3 从未切向该空间、表随 Drop 消亡，无实际可达缺口。
    pub fn load(
        elf: &[u8],
        addr_space: &mut UserAddressSpace<X86PageTable>,
        cmd: &[u8],
        prog_name: Option<&[u8]>,
        env: &[&[u8]],
    ) -> Result<LoadedElf, Error> {
        let hdr = parse_header(elf)?;

        let mut loaded = 0usize;
        // 已成功加载段的用户虚拟区间集合，供入口校验（LM3）。
        // S18/S20：seg_ranges 随段数 push 无界增长（上限仅受 phnum=u16
        // 的 65535 约束，最多 ~1MB），堆耗尽会 OOM abort。用 try_reserve
        // 按 phnum 预分配，失败则**如实报错**而非中止内核。
        let mut seg_ranges: Vec<(u64, u64)> = Vec::new();
        if seg_ranges.try_reserve(hdr.phnum).is_err() {
            return Err(Error::OutOfMemory);
        }
        // PT_TLS 模板（0 或 1 份）：不装载，仅记录，供每线程 TLS 块装配（3P4-1）。
        let mut tls: Option<TlsTemplate> = None;
        for i in 0..hdr.phnum {
            // 表完整性由 parse_header 单点保证：phoff + phnum*PHDR_SIZE
            // <= elf.len()，故按表项偏移的读取不会越界。
            let ph = hdr.phoff + i * hdr.phentsize;
            match classify_phdr(rd_u32(elf, ph)) {
                PhdrClass::Load => {
                    let range = load_segment(elf, ph, addr_space)?;
                    seg_ranges.push(range);
                    loaded += 1;
                }
                PhdrClass::Skip => continue,
                // 拒绝面：显式报错并**点名**原因，绝不做伪支持（S09）。
                // 这三类都要求本加载器不具备的能力，静默跳过的后果是
                // 镜像「装载成功」而程序在运行期以难以定位的方式崩。
                PhdrClass::TlsTemplate => {
                    let t = parse_tls_template(elf, ph)?;
                    // 模板初值必须落在某个已加载段内：否则「拷贝初值」的源地址不在该
                    // 地址空间里（或指向内核半区）——按 L2 纪律显式拒绝。
                    //
                    // **但仅在 filesz > 0 时才有内容要拷**：只有 .tbss（零初始化）的
                    // TLS 段 filesz=0，其 vaddr 天然落在 NOBITS 区、不被任何 PT_LOAD
                    // 覆盖——那是 ELF 的正常形态，不是畸形。此时块内容全为 0，无源可拷，
                    // 故不做区间校验（实测：写后读的探针只产生 .tbss，vaddr 在段外）。
                    if t.filesz > 0 {
                        let tpl_end = t.vaddr.checked_add(t.filesz).ok_or(Error::OutOfRange)?;
                        if !seg_ranges
                            .iter()
                            .any(|&(s, e)| t.vaddr >= s && tpl_end <= e)
                        {
                            return Err(Error::InvalidParam);
                        }
                    }
                    // 单模块静态 TLS：多份 PT_TLS 不支持（本加载器不做多模块 TLS 布局）。
                    if tls.is_some() {
                        return Err(Error::NotSupported);
                    }
                    // 模板随地址空间携带：派生线程据此建**各自独立**的块（3P4-1）。
                    addr_space.set_tls_params(TlsParams {
                        vaddr: t.vaddr,
                        filesz: t.filesz,
                        memsz: t.memsz,
                        align: t.align,
                    });
                    tls = Some(t);
                }
                PhdrClass::RejectInterp => {
                    klib::warn!("[loader] 拒绝镜像：含 PT_INTERP，本加载器不做动态链接");
                    return Err(Error::NotSupported);
                }
                PhdrClass::RejectDynamic => {
                    klib::warn!("[loader] 拒绝镜像：含 PT_DYNAMIC，本加载器不做重定位");
                    return Err(Error::NotSupported);
                }
            }
        }
        if loaded == 0 {
            // LD2（已闭环）：格式可解析但没有任何可装载内容——ENOEXEC 语义，
            // 与 NotSupported（能力未实现，如 PIE 里程碑）处置含义不同。
            return Err(Error::ExecFormat);
        }

        // LM3：入口必须落在某个已加载 PT_LOAD 的页对齐扩展区间
        // [vaddr_start, vaddr_end) 内——vaddr_end = align_up(p_vaddr +
        // p_memsz)（见 SegmentPlan，与 loader1.md LM3 记录同口径；落在尾垫
        // 的入口能过此校验但执行即取指 fault，收紧到精确 memsz 终点随 PIE
        // 里程碑评估）。内核半区 / 非规范地址天然被排除——段范围本身已受
        // 用户半区校验；这比依赖 iretq RPL3 触发 #GP 异常兜底更早、更显式。
        if !seg_ranges
            .iter()
            .any(|&(s, e)| hdr.entry >= s && hdr.entry < e)
        {
            return Err(Error::InvalidParam);
        }

        let stack_top = setup_user_stack(addr_space, cmd, prog_name, env)?;
        // **安全闸（3P4-1 未完，勿删）**：装配路径已实现，且 TLS 块本身经实测验证
        // 正确（用户态 memory_query 报 PRESENT|USER|WRITABLE、裸指针读到正确初值、
        // rdfsbase 读回 FS base），但 **FS 相对访问**仍失败，且该失败会让用户程序
        // 触发内核态取指异常（安全洞）。故在根因定位前**显式拒绝**：解析与校验仍
        // 执行（契约受检、代码可达），只是不交付给用户程序。
        // 证据与下一步见本次提交信息与 docs/TODO/3p.md 的 3P4-1 条目。
        let tls_fs_base = match tls {
            Some(t) => Some(addr_space.alloc_tls_block(&TlsParams {
                vaddr: t.vaddr,
                filesz: t.filesz,
                memsz: t.memsz,
                align: t.align,
            })?),
            None => None,
        };

        klib::debug!(
            "[elf] loaded {} segments, entry={:#x}, stack_top={:#x}, tls_fs_base={:?}",
            loaded,
            hdr.entry,
            stack_top,
            tls_fs_base
        );

        Ok(LoadedElf {
            entry: hdr.entry,
            user_stack_top: stack_top,
            tls_fs_base,
        })
    }

    /// 把一批已收集的物理帧全额归还帧池（全部错误路径退款的**单点实现**）。
    ///
    /// 背景（loader1 §八 8.5）：`PhysFrame` 非 RAII——`allocate_frame` 取得
    /// 后必须显式 `deallocate_frame`，地址清单一旦丢失即永久泄漏。消费方：
    /// [`collect_frames`] 收集中途失败，以及两处 `map_user` 拒绝
    /// （load_segment / setup_user_stack，audit-r2 F1）。
    fn refund_frames(frames: &[u64]) {
        for paddr in frames.iter() {
            mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*paddr));
        }
    }

    /// 逐帧收集 `npages` 个物理帧。
    ///
    /// 任一失败（帧池耗尽 / 堆扩容失败）时先把**已取得的帧全额归还帧池**
    /// 再上抛——错误路径零资源缺口。背景（LA4 耗尽实测暴露的真实缺陷）：
    /// 此前收集循环失败时仅丢弃地址 Vec，而 `PhysFrame` 非 RAII、必须显式
    /// `deallocate_frame`，导致每次中途失败永久漏掉全部已取帧，直至后续
    /// 分配方连锁 OutOfMemory。
    ///
    /// 扩容必须走 [`Vec::try_reserve`]：常规 push 触发的堆再分配在物理帧
    /// 耗尽场景下可能连带需要新帧（动态堆增长源），失败即全局 alloc error
    /// panic。增量倍增粒度自 [`FRAME_LIST_CHUNK`] 起。
    fn collect_frames(npages: usize) -> Result<Vec<u64>, Error> {
        let mut frames: Vec<u64> = Vec::new();
        let outcome = (0..npages).try_for_each(|_| -> Result<(), Error> {
            if frames.len() == frames.capacity() {
                let grow = FRAME_LIST_CHUNK.max(frames.capacity());
                frames.try_reserve(grow).map_err(|_| Error::OutOfMemory)?;
            }
            match mm::allocate_frame() {
                Some(f) => {
                    frames.push(f.start_paddr());
                    Ok(())
                }
                None => Err(Error::OutOfMemory),
            }
        });
        if let Err(e) = outcome {
            refund_frames(&frames);
            return Err(e);
        }
        Ok(frames)
    }

    /// 加载单个 `PT_LOAD` 段，返回它占用的用户虚拟区间
    /// `[vaddr_start, vaddr_end)`（LM3 入口校验的消费方）。
    fn load_segment(
        elf: &[u8],
        ph: usize,
        addr_space: &mut UserAddressSpace<X86PageTable>,
    ) -> Result<(u64, u64), Error> {
        let p_flags = rd_u32(elf, ph + 4);
        let spec = SegmentSpec {
            p_offset: rd_u64(elf, ph + 8),
            p_vaddr: rd_u64(elf, ph + 16),
            p_filesz: rd_u64(elf, ph + 32),
            p_memsz: rd_u64(elf, ph + 40),
        };

        // 全部段级校验与页数学单点在纯逻辑层完成（host 可测，LA4）。
        let plan = plan_segment(elf.len(), PAGE_SIZE, USER_TOP, spec)?;
        if plan.npages == 0 {
            return Ok((plan.vaddr_start, plan.vaddr_end));
        }

        // S20 失败模式优先：可能失败的前置条件（HHDM 偏移）必须在资源获取
        // **之前**取得——若落在 collect_frames 之后，其 Err 会成为与 F1 同族
        // 的整批帧泄漏窗口（audit-r2 四步自查补漏）。
        let off = hhdm_offset()?;

        // S31 确定性轴：超配额段必须在**分配物理帧**之前以 NoSpace 确定性
        // 拒绝。历史缺陷：配额校验只在 map_user 内、位于 collect_frames
        // 之后——超大段先抽帧、后撞配额，拒绝码随物理内存多寡漂移
        // （-m 小 → 池耗尽 OutOfMemory，-m 大 → 配额 NoSpace），同一请求
        // 结果不确定。此处前置校验使拒绝与 RAM 无关。与 map_user 内
        // check_area_quota(e-s) 用同一字节口径，故结果一致。
        addr_space.check_area_quota(plan.vaddr_end - plan.vaddr_start)?;

        let frames = collect_frames(plan.npages)?;

        for i in 0..plan.npages {
            let dst = (frames[i] + off) as *mut u8;
            let page_lo = (i as u64) * PAGE_SIZE;
            let page_hi = page_lo + PAGE_SIZE;
            let copy_hi = page_hi.min(spec.p_filesz);
            if copy_hi > page_lo {
                let n = (copy_hi - page_lo) as usize;
                // 不变量（plan_segment 的 L2 校验已证）：page_lo < p_filesz
                // 且 p_offset + p_filesz <= elf.len()
                //   ⇒ 源区间 [p_offset+page_lo, p_offset+copy_hi) 完全落在
                // 镜像内，此处转换不截断、拷贝不越界。
                let src = (spec.p_offset + page_lo) as usize;
                unsafe {
                    core::ptr::copy_nonoverlapping(elf.as_ptr().add(src), dst, n);
                }
            }
            // LM2：从 file 内容终点一直清零到页终点。[p_filesz, p_memsz) 是
            // bss（语义要求为零），[p_memsz, vaddr_end) 是末页页内垫零——
            // 后者若不清零，分配器残留内容会被映射给用户进程（脏数据交付面）。
            let zero_lo = page_lo.max(spec.p_filesz);
            if page_hi > zero_lo {
                let start = (zero_lo - page_lo) as usize;
                let n = (page_hi - zero_lo) as usize;
                unsafe {
                    core::ptr::write_bytes(dst.add(start), 0, n);
                }
            }
        }

        let mut flags = PageFlags::empty();
        if p_flags & PF_W != 0 {
            flags = flags.writable();
        }
        if p_flags & PF_X != 0 {
            flags = flags.executable();
        }
        // LM4 政策决定（成文）：W^X 冲突段**告警放行、不拒绝**。理由：
        // (a) 本项目尚无进程身份/权限模型（vfs1 A1 的前置组件缺失），单点
        //     强制拒绝只是安全剧场；
        // (b) 部分真实工具链会产出 RWX 段，立即拒绝会破坏兼容性。
        // 权限模型落地后重新评估为拒绝策略（届时升级为正式 ADR）。
        // 登记于 docs/degradation.md D9（测试义务由 [test-loader] 闭环）。
        if p_flags & PF_W != 0 && p_flags & PF_X != 0 {
            klib::warn!(
                "[elf] segment {:#x} is both writable and executable (W^X)",
                spec.p_vaddr
            );
        }

        // audit-r2 F1：map_user 失败（用户区配额 NoSpace / 映射错误）时，
        // `frames` 仍处于「已取得、未入账」状态——Vec Drop 只丢地址清单，
        // PhysFrame 非 RAII，不显式归还即永久泄漏整段帧直至连锁 OOM。与
        // collect_frames 的收集段同一退款纪律（单点 [`refund_frames`]）。
        // 注：失败段可能已有部分页写入页表但未入 areas 台账，该中间态的
        // 回收属 mm 台账语义边界（docs/degradation.md D10）；CR3 从未切向
        // 该空间且表随 Drop 消亡，不构成本函数的资源缺口。
        if let Err(e) = addr_space.map_user(
            VirtAddr::new(plan.vaddr_start),
            VirtAddr::new(plan.vaddr_end),
            PageSize::Size4K,
            flags,
            &frames,
        ) {
            refund_frames(&frames);
            return Err(e);
        }

        Ok((plan.vaddr_start, plan.vaddr_end))
    }

    /// TCB 尺寸（TLS 块尾）：与 libc 的 TCB 契约对齐（T2-1：errno 槽在 FS:0）。
    const TCB_SIZE: u64 = 64;

    fn setup_user_stack(
        addr_space: &mut UserAddressSpace<X86PageTable>,
        cmd: &[u8],
        prog_name: Option<&[u8]>,
        env: &[&[u8]],
    ) -> Result<u64, Error> {
        // 栈顶参数块 mini-ABI：布局的**单点定义**在 `raw::entry_block`（host 单测锚定
        // 其契约），语义、取值理由与变更纪律见 docs/abi/syscall-abi.md §4（LA2）。
        // 消费端 `libsys::start` 按同一契约取 argc/argv，并按 `argv + (argc + 1) * 8`
        // 定位 envp（ABI v2，3P4-2）——**无需新 ABI 槽**。
        //
        // LA3/KM5：命令行与环境都必须能完整放进字符串区，超容即显式 ArgListTooLong
        // ——静默截断或丢弃会把不完整交付伪装成完整（伪数据）。校验在 `entry_block` 内，
        // 且先于任何资源获取：失败路径不产生待回收资源。
        let stack_size = USER_STACK_PAGES as u64 * PAGE_SIZE;
        let stack_top = USER_STACK_TOP;
        let block = entry_block(stack_top, cmd.len(), prog_name, env)?;
        let stack_bottom = stack_top - stack_size;

        // S20：同 load_segment，HHDM 前置先于任何资源获取。
        let off = hhdm_offset()?;

        // 按需分页（M17）：预留整个 4MiB 栈区，初始只实映射承载
        // **字符串区 + 字数组**的那些页；其余页由用户态 #PF 逐页补帧。
        addr_space
            .reserve_user(
                VirtAddr::new(stack_bottom),
                VirtAddr::new(stack_top),
                PageSize::Size4K,
                PageFlags::empty().writable(),
            )
            .map_err(|e| Error::from(e))?;

        // 初始实映射**必须覆盖 [block.rsp, stack_top)**（字符串区 + 字数组）。
        // 页数由**算出的 rsp** 反推——ABI v2 起字数组随 envp 条数变化，固定偏移不再适用。
        //
        // 3P4-2 教训：命令行上限提升后参数块跨出栈顶一页；若仍只映射 1 页，字数组会被
        // 经 HHDM 写进**相邻物理帧**——静默内存损坏（实测症状：运行停滞、命令行永不到达）。
        let need_bytes = stack_top - block.rsp;
        let init_pages = ((need_bytes + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let init_bytes = init_pages as u64 * PAGE_SIZE;
        // 与段帧同一退款纪律（audit-r2 F1）：map_user 拒绝时当场全额归还。
        let frames = collect_frames(init_pages)?;
        let init_bottom_va = stack_top - init_bytes;
        if let Err(e) = addr_space.map_user(
            VirtAddr::new(init_bottom_va),
            VirtAddr::new(stack_top),
            PageSize::Size4K,
            PageFlags::empty().writable(),
            &frames,
        ) {
            refund_frames(&frames);
            return Err(e);
        }

        unsafe {
            // VA → 帧内地址：**禁止用 `top.sub(N)`**。多页映射的帧是**任意物理帧**，
            // 虚拟连续 ≠ 物理连续——`top.sub(STR_OFF)` 在 STR_OFF > 页大小时会写到最高帧
            // **之前**的相邻物理帧，静默踩坏内核内存（3P4-2 首版实测即如此）。
            // 故一律按页索引换算：页 i 覆盖 VA [init_bottom_va + i*PAGE, +PAGE)。
            let page_ptr = |va: u64| -> *mut u8 {
                let idx = ((va - init_bottom_va) / PAGE_SIZE) as usize;
                let po = (va - init_bottom_va) % PAGE_SIZE;
                (frames[idx] + off + po) as *mut u8
            };

            let str_base = stack_top - STR_OFF as u64;
            // 命令行（容量已在 `entry_block` 验证；NUL 必须落地）。
            let n = cmd.len();
            for i in 0..n {
                *page_ptr(str_base + i as u64) = cmd[i];
            }
            if n > 0 {
                *page_ptr(str_base + n as u64) = 0;
            }
            // 程序名（`AT_EXECFN` 槽的值指向它）。**不是 argv[0]**：argv[0] 是整条命令行，
            // 本槽只为"进程从哪里被 exec 起来"提供单点答案（3P4-2）。
            if let (Some(p), Some(o)) = (prog_name, block.prog_name_offset) {
                let base = str_base + o;
                for (k, b) in p.iter().enumerate() {
                    *page_ptr(base + k as u64) = *b;
                }
                *page_ptr(base + p.len() as u64) = 0;
            }
            // 环境串（逐条 NUL 结尾；区内偏移由 `entry_block` 单点给出）。
            for (i, e) in env.iter().enumerate() {
                let base = str_base + block.env_offsets[i];
                for (k, b) in e.iter().enumerate() {
                    *page_ptr(base + k as u64) = *b;
                }
                *page_ptr(base + e.len() as u64) = 0;
            }
            // 字数组：[argc] ++ argv[0..argc) ++ [NULL] ++ envp[0..envc) ++ [NULL] ++ auxv 对。
            let mut words: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
            words
                .try_reserve(6 + block.envp.len())
                .map_err(|_| Error::OutOfMemory)?;
            // **argc = 0 时不得写 argv[0] 槽**：该槽即 argv 的 NULL 终结槽，
            // 多写一字会让 envp 位置与消费端规则 argv + (argc + 1) * 8 不一致。
            words.push(block.argc);
            if block.argc == 1 {
                words.push(block.argv0);
            }
            words.push(0);
            words.extend_from_slice(&block.envp);
            words.push(0);
            // auxv 对：`(AT_EXECFN, 程序名指针)`（有则给）+ `(AT_NULL, 0)` 终结。
            // 消费端从 envp 的 NULL 之后按"类型 + 值"成对走到 AT_NULL 为止。
            if let Some(p) = block.prog_name {
                words.push(AT_EXECFN);
                words.push(p);
            }
            words.push(AT_NULL);
            words.push(0);
            for (i, w) in words.iter().enumerate() {
                *(page_ptr(block.rsp + (i * 8) as u64) as *mut u64) = *w;
            }
        }

        Ok(block.rsp)
    }
}

#[cfg(feature = "user-space")]
pub use backend::{load, LoadedElf};

/// 命令行长度上限的公开再导出（单点定义在 `raw`，供内核 syscall 层引用）。
///
/// 门控与 `raw` 模块一致：本常量只在纯逻辑层编译面存在（有测试或有后端消费方），
/// 否则那个构建面里连模块都没有（cargo 会以"无 test、无 user-space"再编一次库）。
#[cfg(any(test, feature = "user-space"))]
pub use crate::raw::{
    AT_EXECFN, AT_NULL, MAX_CMDLINE_BYTES, MAX_ENV_BYTES, MAX_ENV_COUNT, MAX_PROG_NAME_BYTES,
    RSP_OFF_MIN, STR_OFF,
};
