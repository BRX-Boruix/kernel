# kernel

BORUIX's kernel: an x86_64 operating system kernel written from scratch in Rust.

[简体中文](README.md)

After boot the kernel initialises memory management, interrupts, the scheduler and the virtual file
system, loads user-space drivers and hands control to the init process. Most device drivers run in
user space; the kernel keeps address spaces, processes, system calls, the file system and the granting
of device access.

## Features

- Physical and virtual memory management, including a kernel heap allocator
- Interrupt and exception handling, local APIC and SMP multi-core boot
- A preemptive scheduler with a process and thread model
- System call entry with argument validation
- A virtual file system with devfs, ramfs, procfs, sysfs and mount-point management
- Page cache and block cache
- ISO9660 and EXT2 file systems
- An ELF loader and user-space program startup
- Shared memory and pipes
- Device tree and device claiming for user-space drivers to attach to
- A framebuffer terminal based on Flanterm
- AHCI, ATAPI CD-ROM, ATA PIO disk, PCI bus and PS/2 keyboard drivers

## Known limitations

- Verified only on QEMU and x86_64; never run on real hardware
- Requires a nightly toolchain: some crates use unstable features
- No swap and no memory overcommit; running out of physical memory fails
- Single user, with no account isolation beyond the permission model

## Building

Requires a Rust nightly toolchain (with the `rust-src` and `llvm-tools` components) and QEMU.

```bash
# run unit tests
cargo test

# build the kernel for the bare-metal target
cargo build --target x86_64-unknown-none
```

The artifact needs a bootloader to run in a virtual machine. The full image assembly flow lives in
[`tools`](https://github.com/BRX-Boruix/tools).

### One-step build (planned)

[`brxos`](https://github.com/BRX-Boruix/brxos) is planned to provide an entry point that fetches every
repository and builds in one step; it is not implemented yet. The script will collect the repositories
into one workspace and assemble a runnable image with `tools`.

## Repository layout

```
kernel/
├── Cargo.toml          # workspace configuration
├── NOTICE.md           # third-party component notices
├── crates/
│   ├── kernel/         # core: entry, syscalls, ELF loading, VFS init
│   ├── arch/
│   │   ├── arch/       # hardware architecture abstraction
│   │   └── arch-x86_64/# the x86_64 platform implementation
│   ├── klib/           # base library: allocator, logging, sync, time
│   ├── mm/             # physical and virtual memory management
│   ├── task/           # processes, threads and the scheduler
│   ├── ipc/            # inter-process communication: shared memory and pipes
│   ├── vfs/            # the virtual file system
│   ├── fs/             # file system implementations such as ISO9660
│   ├── driver/         # device drivers
│   ├── loader/         # ELF and executable image loading
│   └── term/           # the framebuffer terminal
└── vendor/             # third-party components, see NOTICE.md
```

## Related projects

- [`tools`](https://github.com/BRX-Boruix/tools) — kernel build, image assembly and VM acceptance
- [`libsys`](https://github.com/BRX-Boruix/libsys) — user-space syscall wrappers
- [`init`](https://github.com/BRX-Boruix/init) — the first user-space process the kernel loads

## License

MIT License, copyright Yang Borui. See [LICENSE](LICENSE).
Third-party components bundled here carry their own licenses; see [NOTICE.md](NOTICE.md).
