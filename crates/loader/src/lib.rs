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
    fn align_up_checked(v: u64, align: u64) -> Option<u64> {
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
            assert_eq!(parse_header(&[]), Err(Error::InvalidParam));
            assert_eq!(parse_header(&[0x7f]), Err(Error::InvalidParam));

            let mut magic = build_elf(0, 64, 56, 1);
            magic[0] = 0;
            assert_eq!(parse_header(&magic), Err(Error::InvalidParam));

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
    }
}

// ---------- 后端层：用户地址空间装载（kernel 经 user-space feature 启用） ----------
#[cfg(feature = "user-space")]
mod backend {
    use super::raw::{parse_header, plan_segment, rd_u32, rd_u64, SegmentSpec};
    use alloc::vec::Vec;
    use arch::{PageFlags, PageSize, VirtAddr};
    use arch_x86_64::paging::X86PageTable;
    use klib::error::Error;
    use mm::user_space::{USER_STACK_TOP, USER_TOP, UserAddressSpace};

    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    /// 段标志：可读。x86-64 PTE 没有「禁止读」位——present 页恒可读，因此
    /// PF_R 在权限映射中结构性成立、无需参与 flags 计算（LM6）。常量保留
    /// 以对照 ELF 规范，`dead_code` 豁免即此语义说明。
    #[allow(dead_code)]
    const PF_R: u32 = 4;

    const USER_STACK_PAGES: usize = 8;

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
        for i in 0..hdr.phnum {
            // 表完整性由 parse_header 单点保证：phoff + phnum*PHDR_SIZE
            // <= elf.len()，故按表项偏移的读取不会越界。
            let ph = hdr.phoff + i * hdr.phentsize;
            if rd_u32(elf, ph) != PT_LOAD {
                continue;
            }
            let range = load_segment(elf, ph, addr_space)?;
            seg_ranges.push(range);
            loaded += 1;
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

        let stack_top = setup_user_stack(addr_space, cmd)?;

        klib::info!(
            "[elf] loaded {} segments, entry={:#x}, stack_top={:#x}",
            loaded,
            hdr.entry,
            stack_top
        );

        Ok(LoadedElf {
            entry: hdr.entry,
            user_stack_top: stack_top,
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

    fn setup_user_stack(
        addr_space: &mut UserAddressSpace<X86PageTable>,
        cmd: &[u8],
    ) -> Result<u64, Error> {
        // 栈顶参数块 mini-ABI：布局、STR_OFF/RSP_OFF 取值理由与变更纪律见
        // docs/abi/syscall-abi.md §4（LA2）。
        const STR_OFF: usize = 0x200;
        const RSP_OFF: usize = 0x220;

        // LA3/KM5：命令行 + NUL 终止符必须能完整放进栈顶字符串区。超容即
        // 显式 ArgListTooLong（与 syscall 层 CMD_BUF_BYTES 上限同一政策）——
        // 静默截断会把被裁剪过的命令行伪装成完整交付（伪数据）。校验放在
        // 分配之前：失败路径不产生任何待回收资源。
        if cmd.len() > STR_OFF - 1 {
            return Err(Error::ArgListTooLong);
        }

        let stack_size = USER_STACK_PAGES as u64 * PAGE_SIZE;
        let stack_top = USER_STACK_TOP;
        let stack_bottom = stack_top - stack_size;

        // S20：同 load_segment，HHDM 前置先于任何资源获取。
        let off = hhdm_offset()?;

        // 与段帧同一退款纪律（audit-r2 F1）：映射拒绝时当场全额归还，
        // 见 load_segment 内同名注释。
        let frames = collect_frames(USER_STACK_PAGES)?;
        if let Err(e) = addr_space.map_user(
            VirtAddr::new(stack_bottom),
            VirtAddr::new(stack_top),
            PageSize::Size4K,
            PageFlags::empty().writable(),
            &frames,
        ) {
            refund_frames(&frames);
            return Err(e);
        }

        unsafe {
            let top = (frames[USER_STACK_PAGES - 1] + off + PAGE_SIZE) as *mut u8;

            if !cmd.is_empty() {
                let str_user = stack_top - STR_OFF as u64;
                let rsp_user = stack_top - RSP_OFF as u64;

                let sp = top.sub(STR_OFF);
                // 容量已在函数入口验证（cmd.len() <= STR_OFF - 1），
                // 写入 cmd 后必然还剩至少 1 字节给 NUL，无需截断。
                let n = cmd.len();
                for i in 0..n {
                    *sp.add(i) = cmd[i];
                }
                *sp.add(n) = 0;

                let rp = top.sub(RSP_OFF) as *mut u64;
                *rp = 1;
                *rp.add(1) = str_user;
                *rp.add(2) = 0;

                return Ok(rsp_user);
            }

            let top64 = top as *mut u64;
            *top64.sub(2) = 0;
            *top64.sub(1) = 0;
        }

        Ok(stack_top - 16)
    }
}

#[cfg(feature = "user-space")]
pub use backend::{load, LoadedElf};
