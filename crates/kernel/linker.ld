OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text    PT_LOAD;
    rodata  PT_LOAD;
    data    PT_LOAD;
    dynamic PT_DYNAMIC;
}

SECTIONS
{
    . = 0xffffffff80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
        /* KD6：唯一存活的 Limine 请求段。limine-proc-0.1 的 limine_tag 宏把
           请求指针写入 `.limine_reqs`（NULL 结尾指针数组，bootloader 据此取
           请求，不再逐节扫描）；KEEP 防止"无程序引用"被 gc-sections 删除。
           （曾并存一个 `.requests` 输出段——已核实本 crate 版本从不产生该
           输入段，属误导性冗余，删除；Cargo feature 名 requests-section 仅
           是 limine_tag 宏的启用开关，与段名无关。） */
        KEEP(*(.limine_reqs))
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* KA3：内核主栈 + 向下守护页（NOLOAD = SHT_NOBITS，不占 ELF/ISO 体积，
       仅计入段 memsz，Limine 会为其分配并零填充物理页）。
       - 守护页紧贴栈底（__kstack_guard_top == __kstack_base）：运行期由 kmain
         在页表就绪后显式解映射——内核主栈向下溢出必然命中该无映射页产生 #PF，
         经注册的内核故障检查器识别为"KERNEL STACK OVERFLOW"显式停机；此前
         溢出会静默踩踏相邻 .bss 数据（审计原发现）。
       - 符号四元组是栈边界的唯一事实来源；Rust 侧不再持有任何栈数组静态。
       - 解映射发生在 snapshot_kernel_root 之后：此后派生的所有进程页表继承
         该空洞，守护对所有执行流生效。 */
    .kernel_main_stack (NOLOAD) : ALIGN(CONSTANT(MAXPAGESIZE)) {
        __kstack_guard_base = .;
        . += CONSTANT(MAXPAGESIZE);
        __kstack_guard_top = .;
        __kstack_base = .;
        /* 1MiB 内核主栈（与历史 KMAIN_STACK_SIZE 一致；注释成文防漂移）。 */
        . += 0x100000;
        __kstack_top = .;
    } :data

    .dynamic : {
        *(.dynamic)
    } :data :dynamic

    /* 镜像**物理跨度**的链接期真值（ADR-050 兜底用）：mm 以
       "max(常量下界, __kernel_image_end − 链接基址)" 计算帧分配器要保留的区间，
       使"保留量估小 → 内核代码被当空闲帧发出去"这一灾难性失败结构上不可能发生
       （常量只是下界；真实镜像更大时以真实值为准）。 */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __kernel_image_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
