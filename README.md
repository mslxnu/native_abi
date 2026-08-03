# mSL/NABI

[![C/C++ CI](https://github.com/somestupidgirl/mSL-NABI/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/somestupidgirl/mSL-NABI/actions/workflows/c-cpp.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)](#requirements)
[![Architecture](https://img.shields.io/badge/Architecture-arm64-blue)](#status)

**macOS Subsystem for Linux / Native ABI** — Linux binaries running as ordinary
macOS processes.

One module of **mSL/XNU**, a modular macOS Subsystem for Linux.

## The larger project

mSL/XNU — *macOS Subsystem for Linux / X is Now UNIX* — aims at **native, seamless
execution of Linux ELF binaries on macOS**: not in a container and not in a virtual
machine, but as ordinary processes on the running system.

Reaching that needs several independent pieces, which is why the project is modular
rather than one monolith. Each is useful on its own, and each can be installed,
replaced or omitted:

| Piece | What it does | Where |
|-------|--------------|-------|
| **Syscall translation** | Linux system calls onto Darwin's, over `Hypervisor.framework` | **this repository** |
| **Filesystem Hierarchy Standard** | The Linux filesystem layout, natively | [mSL/FHS](https://github.com/somestupidgirl/mSL-FHS) |
| **procfs** | `/proc`, as a real filesystem | [mSL/ProcFS](https://github.com/somestupidgirl/mSL-ProcFS) |
| **sysfs** | `/sys`, likewise | [mSL/SysFS](https://github.com/somestupidgirl/mSL-SysFS) |
| **devfs** | `/dev` — already part of macOS | XNU |

**This repository is the ABI piece.** The rest of this document describes it.

## What is mSL/NABI?

A Linux program is a file of AArch64 instructions that expects a Linux kernel
underneath it. On an Apple Silicon Mac the instructions are already native — it is
the same CPU — and the kernel is not. NABI supplies the missing kernel interface
and nothing else.

It runs the guest's own instructions on the real CPU inside
`Hypervisor.framework`, catches each `svc` where a Linux kernel would have been,
and answers it from Darwin. There is no instruction emulation, no second kernel,
and no disk image. A guest process is one host process; its files are host files;
its memory is host memory mapped into the guest's address space.

That shape is what distinguishes it. NABI is not a virtual machine that happens to
be small, and not a container: it is a **system-call translator that borrows the
hypervisor purely as a privilege boundary**, so that `svc` has somewhere to land.

**NABI is experimental.** It is a fork of [Noah](https://github.com/linux-noah/noah),
which is unmaintained and last targeted macOS Sierra on Intel; the AArch64 port,
the mSL integration and everything below are new work. For the original design, see
the [academic paper](https://dl.acm.org/doi/abs/10.1145/3381052.3381327).

Tested on:

    - macOS 26.5.2 (Tahoe), Darwin 25.5.0, Apple Silicon (arm64) — primary target

## Design

### Where a syscall goes

The guest runs at EL0 with the host's stage-2 translation underneath it. A guest
`svc` enters a small EL1 trampoline NABI maps into the guest, which immediately
issues `hvc #1` — trapping to the VMM, which reads the guest's registers, decides
what the call meant, and performs it against Darwin.

`hvc #1` rather than `hvc #0`, for a reason worth knowing: an `hvc #0` whose `x0`
falls in the SMCCC range is answered by firmware and never reaches the VMM at all.
That produced a guest which worked for most syscalls and silently failed across a
16-million-value band of arguments.

Two-stage translation means two page tables to keep in step — the guest's own
(4KiB granule) and the host's (`hv_vm_map`, fixed 16KiB). Every protection change
has to touch both: stage 1 cannot grant what stage 2 withholds, and an `mprotect`
that updated only stage 1 left the guest faulting forever on memory that both of
NABI's tables described as writable.

### `fork` is `fork` plus `exec`

`Hypervisor.framework` will not let a forked child create a vCPU once the parent
has ever had one — it crashes inside the framework rather than returning an error.
Measured standalone, that is not something NABI can work around in place.

So a guest `fork` is a host `fork` followed immediately by an `exec` of NABI
itself, with the parent's state handed over through a checkpoint: memory regions,
descriptor table, credentials, signal dispositions, the vCPU snapshot. The child
rebuilds and resumes where the guest expects to be.

This is invisible to the guest and has one consequence worth stating, because it
shapes every investigation here: **a forked child is a fresh process**, so anything
not written into the checkpoint does not travel. Credentials, the supplementary
group list and the debug sinks each had to be added after a bug showed they were
missing.

### The rootfs must be case-sensitive

macOS formats the boot volume case-insensitively. No Linux distribution can be
unpacked there: Debian ships `_exit.2.gz` beside `_Exit.2.gz`, and `xt_connmark.h`
beside `xt_CONNMARK.h`. One such pair is enough.

The failure does not resemble its cause. `dpkg` clears a stale `.dpkg-new` before
each unpack, which for the second name deletes the *first* name's freshly written
file; the second is a symlink, so it is created in the gap, pointing at a name that
does not exist yet; and the deferred `fsync` pass then reports `ENOENT` against the
file that unpacked correctly.

Holding both names would mean mangling them in the VFS and unmangling in `readdir`,
in `readlink`, and in every path handed back — and any host tool looking at the tree
would see the mangled form. So NABI detects the filesystem and says so, and `msl`
keeps the trees on a case-sensitive sparse image it creates on demand. That needs no
administrator rights, and the image is sparse, so its size is a ceiling rather than
an allocation.

### Credentials are emulated, not delegated

The host account NABI runs as is what the guest sees as `root`. `setuid` and friends
move a `struct cred` inside NABI and never touch the host process, so a guest can be
root, drop to an unprivileged user, and use `sudo`, while the host process remains
the ordinary account that started it.

That is the honest boundary: **the guest's root is a fiction, and the host account is
the real limit.** Nothing a guest does with its own credentials widens what the host
process may touch.

## How it compares

| | Approach | Guest processes | Filesystem | Kernel |
|---|---|---|---|---|
| **mSL/NABI** | Syscall translation; hypervisor as a privilege boundary | Host processes, one to one | Host files, directly | Darwin |
| hylyx | Full VM (`Virtualization.framework`) | Inside the guest | Guest disk image | Linux |
| Docker Desktop / OrbStack / Lima | Full VM, containers inside it | Inside the guest | Guest disk image, shared over virtiofs | Linux |
| QEMU user-mode | Instruction emulation + syscall translation | Host processes | Host files | Host |
| WSL 1 | Syscall translation in the NT kernel | Host processes | Host files, via a driver | NT |
| WSL 2 | Full VM | Inside the guest | Guest disk image | Linux |

The closest comparison is **WSL 1**, and the ambition is the same: Linux programs as
first-class citizens of the host rather than guests behind a boundary. WSL 1 had the
advantage of doing it inside the NT kernel; NABI does it from userspace, which is why
`Hypervisor.framework` appears at all — it is the cheapest way to get a trap on `svc`
without a kernel extension.

Against a VM manager such as **hylyx**, the difference is not size or speed but *where
things live*. A VM gives you a complete, correct Linux — a real kernel, so everything
works — reached over SSH, with its own disk, its own memory and its own process table.
NABI gives you no kernel at all, and therefore an incomplete Linux, but the processes
are yours: they appear in `ps`, they exit into your shell's exit status, they read and
write your files with no sharing layer in between, and `kill` from the host works on
them. Both are reasonable. They answer different questions — if you want to *run
Linux*, run a VM; NABI is for wanting to run **a Linux program**.

Against **QEMU user-mode**, architecturally the nearest thing: QEMU interprets or JITs
the guest's instructions, because it exists to cross architectures. Running AArch64
Linux binaries on Apple Silicon there is nothing to cross, so NABI executes them
directly and spends nothing on translation.

What NABI gives up for that is real, and it is what WSL 1 gave up too: every kernel
interface has to be implemented by hand, and the ones that are not are simply absent.
A VM never has that problem.

## Requirements

- Apple Silicon Mac, macOS 15 or later
- Xcode Command Line Tools
- A case-sensitive volume for the rootfs — `msl` makes one for you
- No kernel extension, no Reduced Security, no SIP changes

## Installing

```sh
make                # build into out/
sudo make install   # /usr/local/bin/msl, and the helpers under libexec
```

## Quick start

```console
$ msl install debian        # or ubuntu
$ msl login debian
```

`msl install` downloads the base system from the distribution's own archive,
verifies every package against the checksums in the signed index, unpacks it, and
then finishes the job **inside NABI** by running `dpkg --configure -a` — the same
second stage `debootstrap` performs. That is why the maintainer scripts run, and why
the tree comes out with `/etc/shadow`, an `ld.so` cache and working
`update-alternatives`. It also creates an account named after you, with `sudo`.

`msl` on its own shows what is installed and what to type next; `msl help` lists
everything.

```console
sunneva@host:~$ sudo apt install gcc
sunneva@host:~$ gcc -O2 -o hello hello.c && ./hello
```

## Status

**Apple Silicon (arm64) is the primary target and is working.** A Debian 13 or
Ubuntu 24.04 rootfs installs, configures, updates over the network with OpenPGP
signature verification, and installs and runs a C toolchain.

| Area | Status |
|------|--------|
| ELF loading, static and dynamic | **Working** |
| Syscall translation | **Working** for what a base system exercises |
| Memory: `mmap`, `mprotect`, `mremap`, `brk` | **Working**, including two-stage protection changes |
| `fork` / `clone` / `execve` | **Working**, via checkpointed fork-plus-exec |
| Threads, futexes | **Working** |
| Signals | **Working**, including `tgkill`/`tkill` |
| Terminals | **Working** — `/dev/ptmx` and the `/dev/pts` translation |
| Filesystem | **Working** — host-backed, with passthrough prefixes |
| `/proc/self/{maps,cmdline,comm,exe,fd}` | **Working** — served by NABI |
| Credentials, `su`, `sudo` | **Working** — emulated in software |
| apt, dpkg, pacman, gcc | **Working** |
| Sibling modules (`/proc`, `/sys`) | **Detected**, optional; NABI runs without them |
| Debian, Ubuntu | **Working** — resolved from the archive, apt works inside |
| Arch | **Working** — from the published tarball; pacman installs, signatures and all |
| Fedora | **Rootfs works**, from the published container image; dnf does not run yet |
| x86-64 | **Builds, unverified** — see below |

The x86-64 backend is the original Noah VT-x code. It compiles, and is kept as the
reference implementation of what each syscall path is meant to do — the arm64 code
was written by reading it — but it cannot be executed on Apple Silicon
(`hv_vm_create` returns `HV_UNSUPPORTED` under Rosetta). It is **a compile baseline
and a specification, not a runnable test.**

[PORTING-arm64.md](PORTING-arm64.md) is the working record of the port: the design,
and every bug worth remembering, with what the symptom looked like and why it did
not resemble the cause. [INTEGRATION.md](INTEGRATION.md) covers how NABI fits with
the other modules, and [HACKING.md](HACKING.md) is the developer guide.

## Testing

```sh
make check          # unit tests: instruction decode, page tables, checkpoint
make check-smoke    # freestanding guest binaries, run under NABI
```

The smoke suite is the interesting half. Each test is a small static AArch64 Linux
binary that exercises one thing NABI got wrong at some point, and each is verified
to **fail without its fix** — a test that passes either way is not evidence. They
cover pty allocation, `O_*` flag values, `AT_EMPTY_PATH`, futex timeouts and
wakeups, stage-2 protection, signal delivery, and the process-entry stack alignment.

One lesson is built into them: a test that shares a constant with the code under test
cannot catch that constant being wrong. `ptytest` passed for some time while every
real guest failed to allocate a pty, because the test and NABI used the same
incorrect ioctl number. The tests now spell ABI constants out from the kernel headers.

## Repository layout

| Path | What |
|------|------|
| `src/` | The VMM, syscall translation, memory, process and filesystem code |
| `include/linux/` | The Linux ABI as NABI understands it — structures and constants |
| `lib/` | `Hypervisor.framework` glue |
| `util/` | `msl` and its helpers: rootfs builder, volume maker, shell launcher |
| `test/` | Unit tests and the freestanding smoke suite |
| `spike/` | Standalone experiments that settled design questions |

## Credits

NABI is a fork of [Noah](https://github.com/linux-noah/noah) by Yuichi Nishiwaki and
contributors. The Homebrew and MacPorts packages install the original `noah`, not
this fork, and are not updated for it.

## License

MIT — see [LICENSE](LICENSE). Files carrying their own notice keep it; the inherited
Noah sources are dual MIT/GPL.
