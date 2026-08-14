/* aarch64 内核链接脚本（已归档，当前不参与构建） */
OUTPUT_FORMAT(elf64-littleaarch64)
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

    .dynamic : {
        *(.dynamic)
    } :data :dynamic

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
