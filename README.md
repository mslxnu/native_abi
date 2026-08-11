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
| hyper-linux | The same: syscall translation, `Hypervisor.framework`, EL1 shim | Host processes, one to one | Host files, directly | Darwin |
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

The nearest peer by *approach* is **hyper-linux**, which does the same thing the
same way: a per-process VM under `Hypervisor.framework`, an EL1 shim trapping `svc`,
and Linux syscalls translated to Darwin's. Where the two differ is coverage. It
reports 172 syscalls translated against NABI's 228, and states that it lacks
namespaces and cgroups, treats `MAP_SHARED` as `MAP_PRIVATE`, and has no `clone3` or
robust futexes. NABI has all eight namespaces, a cgroup hierarchy, real shared file
mappings, System V IPC, `mount(2)` with bind mounts and propagation, inotify and
fanotify. It has `clone3` and robust futexes no more than hyper-linux does.

Where hyper-linux is ahead: it runs **x86-64 Linux binaries on Apple Silicon** through
Rosetta, which NABI does not — NABI's x86 backend is a separate build for Intel Macs,
and is compile-tested rather than run (see PORTING-arm64.md). It also describes
demand-paged memory over a 1TB address space, where NABI maps eagerly.

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
| Credentials, `su`, `sudo` | **Working** — emulated in software, with per-file owner and mode |
| apt, dpkg, pacman, gcc | **Working** |
| Sibling modules (`/proc`, `/sys`) | **Detected**, optional; NABI runs without them |
| Debian, Ubuntu | **Working** — resolved from the archive, apt works inside |
| Arch | **Working** — from the published tarball; pacman installs, signatures and all |
| Fedora | **Working** — from the published container image; dnf installs and its rpm triggers run |
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

## Syscalls

<!-- GENERATED by util/gen_syscall_doc.py - do not edit by hand. -->

**229 of 396 implemented.**

| | |
|---|---|
| ✅ | implemented |
| ⊘ | answered deliberately, and the answer is `ENOSYS` (13 calls) — most are ones Linux does not implement either; `rseq` is the one that could have been and is not, for the reason in `src/proc/rseq.c` |
| · | no handler; the unknown-syscall path, which is also `ENOSYS` |

A dash in a number column means that architecture has no such call.

<details>
<summary>The full table (396 calls)</summary>

| Syscall | aarch64 | x86-64 | NABI |
|---|---:|---:|:---:|
| `_sysctl` | — | 156 | · |
| `accept` | 202 | 43 | ✅ |
| `accept4` | 242 | 288 | · |
| `access` | — | 21 | ✅ |
| `acct` | 89 | 163 | · |
| `add_key` | 217 | 248 | · |
| `adjtimex` | 171 | 159 | · |
| `afs_syscall` | — | 183 | ⊘ |
| `alarm` | — | 37 | ✅ |
| `arch_prctl` | — | 158 | ✅ |
| `bind` | 200 | 49 | ✅ |
| `bpf` | 280 | 321 | · |
| `brk` | 214 | 12 | ✅ |
| `cachestat` | 451 | 451 | · |
| `capget` | 90 | 125 | ✅ |
| `capset` | 91 | 126 | · |
| `chdir` | 49 | 80 | ✅ |
| `chmod` | — | 90 | ✅ |
| `chown` | — | 92 | ✅ |
| `chroot` | 51 | 161 | ✅ |
| `clock_adjtime` | 266 | 305 | · |
| `clock_adjtime64` | 405 | — | · |
| `clock_getres` | 114 | 229 | ✅ |
| `clock_getres_time64` | 406 | — | · |
| `clock_gettime` | 113 | 228 | ✅ |
| `clock_gettime64` | 403 | — | · |
| `clock_nanosleep` | 115 | 230 | ✅ |
| `clock_nanosleep_time64` | 407 | — | · |
| `clock_settime` | 112 | 227 | · |
| `clock_settime64` | 404 | — | · |
| `clone` | 220 | 56 | ✅ |
| `clone3` | 435 | 435 | ✅ |
| `close` | 57 | 3 | ✅ |
| `close_range` | 436 | 436 | · |
| `connect` | 203 | 42 | ✅ |
| `copy_file_range` | 285 | 326 | · |
| `creat` | — | 85 | ✅ |
| `create_module` | — | 174 | · |
| `delete_module` | 106 | 176 | · |
| `dup` | 23 | 32 | ✅ |
| `dup2` | — | 33 | ✅ |
| `dup3` | 24 | 292 | ✅ |
| `epoll_create` | — | 213 | · |
| `epoll_create1` | 20 | 291 | ✅ |
| `epoll_ctl` | 21 | 233 | ✅ |
| `epoll_ctl_old` | — | 214 | ⊘ |
| `epoll_pwait` | 22 | 281 | ✅ |
| `epoll_pwait2` | 441 | 441 | · |
| `epoll_wait` | — | 232 | · |
| `epoll_wait_old` | — | 215 | ⊘ |
| `eventfd` | — | 284 | · |
| `eventfd2` | 19 | 290 | ✅ |
| `execve` | 221 | 59 | ✅ |
| `execveat` | 281 | 322 | · |
| `exit` | 93 | 60 | ✅ |
| `exit_group` | 94 | 231 | ✅ |
| `faccessat` | 48 | 269 | ✅ |
| `faccessat2` | 439 | 439 | ✅ |
| `fadvise64` | — | 221 | ✅ |
| `fallocate` | 47 | 285 | ✅ |
| `fanotify_init` | 262 | 300 | ✅ |
| `fanotify_mark` | 263 | 301 | ✅ |
| `fchdir` | 50 | 81 | ✅ |
| `fchmod` | 52 | 91 | ✅ |
| `fchmodat` | 53 | 268 | ✅ |
| `fchmodat2` | 452 | 452 | · |
| `fchown` | 55 | 93 | ✅ |
| `fchownat` | 54 | 260 | ✅ |
| `fcntl` | — | 72 | ✅ |
| `fdatasync` | 83 | 75 | ✅ |
| `fgetxattr` | 10 | 193 | ✅ |
| `finit_module` | 273 | 313 | · |
| `flistxattr` | 13 | 196 | ✅ |
| `flock` | 32 | 73 | ✅ |
| `fork` | — | 57 | ✅ |
| `fremovexattr` | 16 | 199 | ✅ |
| `fsconfig` | 431 | 431 | · |
| `fsetxattr` | 7 | 190 | ✅ |
| `fsmount` | 432 | 432 | · |
| `fsopen` | 430 | 430 | · |
| `fspick` | 433 | 433 | · |
| `fstat` | — | 5 | ✅ |
| `fstatfs` | — | 138 | ✅ |
| `fsync` | 82 | 74 | ✅ |
| `ftruncate` | — | 77 | ✅ |
| `futex` | 98 | 202 | ✅ |
| `futex_requeue` | 456 | 456 | ✅ |
| `futex_time64` | 422 | — | · |
| `futex_wait` | 455 | 455 | ✅ |
| `futex_waitv` | 449 | 449 | ✅ |
| `futex_wake` | 454 | 454 | ✅ |
| `futimesat` | — | 261 | · |
| `get_kernel_syms` | — | 177 | · |
| `get_mempolicy` | 236 | 239 | ✅ |
| `get_robust_list` | 100 | 274 | ✅ |
| `get_thread_area` | — | 211 | ⊘ |
| `getcpu` | 168 | 309 | · |
| `getcwd` | 17 | 79 | ✅ |
| `getdents` | — | 78 | ✅ |
| `getdents64` | 61 | 217 | ✅ |
| `getegid` | 177 | 108 | ✅ |
| `geteuid` | 175 | 107 | ✅ |
| `getgid` | 176 | 104 | ✅ |
| `getgroups` | 158 | 115 | ✅ |
| `getitimer` | 102 | 36 | ✅ |
| `getpeername` | 205 | 52 | ✅ |
| `getpgid` | 155 | 121 | ✅ |
| `getpgrp` | — | 111 | ✅ |
| `getpid` | 172 | 39 | ✅ |
| `getpmsg` | — | 181 | ⊘ |
| `getppid` | 173 | 110 | ✅ |
| `getpriority` | 141 | 140 | ✅ |
| `getrandom` | 278 | 318 | ✅ |
| `getresgid` | 150 | 120 | ✅ |
| `getresuid` | 148 | 118 | ✅ |
| `getrlimit` | 163 | 97 | ✅ |
| `getrusage` | 165 | 98 | ✅ |
| `getsid` | 156 | 124 | ✅ |
| `getsockname` | 204 | 51 | ✅ |
| `getsockopt` | 209 | 55 | ✅ |
| `gettid` | 178 | 186 | ✅ |
| `gettimeofday` | 169 | 96 | ✅ |
| `getuid` | 174 | 102 | ✅ |
| `getxattr` | 8 | 191 | ✅ |
| `init_module` | 105 | 175 | · |
| `inotify_add_watch` | 27 | 254 | ✅ |
| `inotify_init` | — | 253 | ✅ |
| `inotify_init1` | 26 | 294 | ✅ |
| `inotify_rm_watch` | 28 | 255 | ✅ |
| `io_cancel` | 3 | 210 | · |
| `io_destroy` | 1 | 207 | · |
| `io_getevents` | 4 | 208 | · |
| `io_pgetevents` | 292 | 333 | · |
| `io_pgetevents_time64` | 416 | — | · |
| `io_setup` | 0 | 206 | · |
| `io_submit` | 2 | 209 | · |
| `io_uring_enter` | 426 | 426 | · |
| `io_uring_register` | 427 | 427 | · |
| `io_uring_setup` | 425 | 425 | · |
| `ioctl` | 29 | 16 | ✅ |
| `ioperm` | — | 173 | · |
| `iopl` | — | 172 | · |
| `ioprio_get` | 31 | 252 | · |
| `ioprio_set` | 30 | 251 | · |
| `kcmp` | 272 | 312 | · |
| `kexec_file_load` | 294 | 320 | · |
| `kexec_load` | 104 | 246 | · |
| `keyctl` | 219 | 250 | · |
| `kill` | 129 | 62 | ✅ |
| `landlock_add_rule` | 445 | 445 | · |
| `landlock_create_ruleset` | 444 | 444 | · |
| `landlock_restrict_self` | 446 | 446 | · |
| `lchown` | — | 94 | ✅ |
| `lgetxattr` | 9 | 192 | ✅ |
| `link` | — | 86 | ✅ |
| `linkat` | 37 | 265 | ✅ |
| `listen` | 201 | 50 | ✅ |
| `listmount` | 458 | 458 | · |
| `listxattr` | 11 | 194 | ✅ |
| `llistxattr` | 12 | 195 | ✅ |
| `lookup_dcookie` | 18 | 212 | · |
| `lremovexattr` | 15 | 198 | ✅ |
| `lseek` | — | 8 | ✅ |
| `lsetxattr` | 6 | 189 | ✅ |
| `lsm_get_self_attr` | 459 | 459 | · |
| `lsm_list_modules` | 461 | 461 | · |
| `lsm_set_self_attr` | 460 | 460 | · |
| `lstat` | — | 6 | ✅ |
| `madvise` | 233 | 28 | ✅ |
| `map_shadow_stack` | 453 | 453 | · |
| `mbind` | 235 | 237 | · |
| `membarrier` | 283 | 324 | · |
| `memfd_create` | 279 | 319 | · |
| `memfd_secret` | 447 | 447 | · |
| `migrate_pages` | 238 | 256 | · |
| `mincore` | 232 | 27 | · |
| `mkdir` | — | 83 | ✅ |
| `mkdirat` | 34 | 258 | ✅ |
| `mknod` | — | 133 | ✅ |
| `mknodat` | 33 | 259 | ✅ |
| `mlock` | 228 | 149 | ✅ |
| `mlock2` | 284 | 325 | · |
| `mlockall` | 230 | 151 | · |
| `mmap` | — | 9 | ✅ |
| `modify_ldt` | — | 154 | · |
| `mount` | 40 | 165 | ✅ |
| `mount_setattr` | 442 | 442 | · |
| `move_mount` | 429 | 429 | · |
| `move_pages` | 239 | 279 | · |
| `mprotect` | 226 | 10 | ✅ |
| `mq_getsetattr` | 185 | 245 | · |
| `mq_notify` | 184 | 244 | · |
| `mq_open` | 180 | 240 | · |
| `mq_timedreceive` | 183 | 243 | · |
| `mq_timedreceive_time64` | 419 | — | · |
| `mq_timedsend` | 182 | 242 | · |
| `mq_timedsend_time64` | 418 | — | · |
| `mq_unlink` | 181 | 241 | · |
| `mremap` | 216 | 25 | ✅ |
| `mseal` | 462 | 462 | · |
| `msgctl` | 187 | 71 | ✅ |
| `msgget` | 186 | 68 | ✅ |
| `msgrcv` | 188 | 70 | ✅ |
| `msgsnd` | 189 | 69 | ✅ |
| `msync` | 227 | 26 | ✅ |
| `munlock` | 229 | 150 | ✅ |
| `munlockall` | 231 | 152 | · |
| `munmap` | 215 | 11 | ✅ |
| `name_to_handle_at` | 264 | 303 | ✅ |
| `nanosleep` | 101 | 35 | ✅ |
| `newfstatat` | — | 262 | ✅ |
| `nfsservctl` | 42 | 180 | ⊘ |
| `open` | — | 2 | ✅ |
| `open_by_handle_at` | 265 | 304 | ✅ |
| `open_tree` | 428 | 428 | · |
| `openat` | 56 | 257 | ✅ |
| `openat2` | 437 | 437 | · |
| `pause` | — | 34 | · |
| `perf_event_open` | 241 | 298 | · |
| `personality` | 92 | 135 | · |
| `pidfd_getfd` | 438 | 438 | · |
| `pidfd_open` | 434 | 434 | · |
| `pidfd_send_signal` | 424 | 424 | · |
| `pipe` | — | 22 | ✅ |
| `pipe2` | 59 | 293 | ✅ |
| `pivot_root` | 41 | 155 | · |
| `pkey_alloc` | 289 | 330 | · |
| `pkey_free` | 290 | 331 | · |
| `pkey_mprotect` | 288 | 329 | · |
| `poll` | — | 7 | ✅ |
| `ppoll` | 73 | 271 | ✅ |
| `ppoll_time64` | 414 | — | · |
| `prctl` | 167 | 157 | ✅ |
| `pread64` | 67 | 17 | ✅ |
| `preadv` | 69 | 295 | · |
| `preadv2` | 286 | 327 | · |
| `prlimit64` | 261 | 302 | ✅ |
| `process_madvise` | 440 | 440 | · |
| `process_mrelease` | 448 | 448 | · |
| `process_vm_readv` | 270 | 310 | · |
| `process_vm_writev` | 271 | 311 | · |
| `pselect6` | 72 | 270 | ✅ |
| `pselect6_time64` | 413 | — | · |
| `ptrace` | 117 | 101 | ✅ |
| `putpmsg` | — | 182 | ⊘ |
| `pwrite64` | 68 | 18 | ✅ |
| `pwritev` | 70 | 296 | · |
| `pwritev2` | 287 | 328 | · |
| `query_module` | — | 178 | · |
| `quotactl` | 60 | 179 | · |
| `quotactl_fd` | 443 | 443 | · |
| `read` | 63 | 0 | ✅ |
| `readahead` | 213 | 187 | · |
| `readlink` | — | 89 | ✅ |
| `readlinkat` | 78 | 267 | ✅ |
| `readv` | 65 | 19 | ✅ |
| `reboot` | 142 | 169 | · |
| `recvfrom` | 207 | 45 | ✅ |
| `recvmmsg` | 243 | 299 | · |
| `recvmmsg_time64` | 417 | — | · |
| `recvmsg` | 212 | 47 | ✅ |
| `remap_file_pages` | 234 | 216 | · |
| `removexattr` | 14 | 197 | ✅ |
| `rename` | — | 82 | ✅ |
| `renameat` | 38 | 264 | ✅ |
| `renameat2` | 276 | 316 | · |
| `request_key` | 218 | 249 | · |
| `restart_syscall` | 128 | 219 | · |
| `rmdir` | — | 84 | ✅ |
| `rseq` | 293 | 334 | ⊘ |
| `rt_sigaction` | 134 | 13 | ✅ |
| `rt_sigpending` | 136 | 127 | ✅ |
| `rt_sigprocmask` | 135 | 14 | ✅ |
| `rt_sigqueueinfo` | 138 | 129 | · |
| `rt_sigreturn` | 139 | 15 | ✅ |
| `rt_sigsuspend` | 133 | 130 | ✅ |
| `rt_sigtimedwait` | 137 | 128 | · |
| `rt_sigtimedwait_time64` | 421 | — | · |
| `rt_tgsigqueueinfo` | 240 | 297 | · |
| `sched_get_priority_max` | 125 | 146 | ✅ |
| `sched_get_priority_min` | 126 | 147 | ✅ |
| `sched_getaffinity` | 123 | 204 | ✅ |
| `sched_getattr` | 275 | 315 | · |
| `sched_getparam` | 121 | 143 | ✅ |
| `sched_getscheduler` | 120 | 145 | ✅ |
| `sched_rr_get_interval` | 127 | 148 | ✅ |
| `sched_rr_get_interval_time64` | 423 | — | · |
| `sched_setaffinity` | 122 | 203 | ✅ |
| `sched_setattr` | 274 | 314 | · |
| `sched_setparam` | 118 | 142 | ✅ |
| `sched_setscheduler` | 119 | 144 | ✅ |
| `sched_yield` | 124 | 24 | ✅ |
| `seccomp` | 277 | 317 | · |
| `security` | — | 185 | ⊘ |
| `select` | — | 23 | ✅ |
| `semctl` | 191 | 66 | ✅ |
| `semget` | 190 | 64 | ✅ |
| `semop` | 193 | 65 | ✅ |
| `semtimedop` | 192 | 220 | ✅ |
| `semtimedop_time64` | 420 | — | · |
| `sendfile` | — | 40 | · |
| `sendmmsg` | 269 | 307 | ✅ |
| `sendmsg` | 211 | 46 | ✅ |
| `sendto` | 206 | 44 | ✅ |
| `set_mempolicy` | 237 | 238 | · |
| `set_mempolicy_home_node` | 450 | 450 | · |
| `set_robust_list` | 99 | 273 | ✅ |
| `set_thread_area` | — | 205 | ⊘ |
| `set_tid_address` | 96 | 218 | ✅ |
| `setdomainname` | 162 | 171 | ✅ |
| `setfsgid` | 152 | 123 | · |
| `setfsuid` | 151 | 122 | · |
| `setgid` | 144 | 106 | ✅ |
| `setgroups` | 159 | 116 | ✅ |
| `sethostname` | 161 | 170 | ✅ |
| `setitimer` | 103 | 38 | ✅ |
| `setns` | 268 | 308 | ✅ |
| `setpgid` | 154 | 109 | ✅ |
| `setpriority` | 140 | 141 | ✅ |
| `setregid` | 143 | 114 | · |
| `setresgid` | 149 | 119 | ✅ |
| `setresuid` | 147 | 117 | ✅ |
| `setreuid` | 145 | 113 | · |
| `setrlimit` | 164 | 160 | ✅ |
| `setsid` | 157 | 112 | ✅ |
| `setsockopt` | 208 | 54 | ✅ |
| `settimeofday` | 170 | 164 | · |
| `setuid` | 146 | 105 | ✅ |
| `setxattr` | 5 | 188 | ✅ |
| `shmat` | 196 | 30 | ✅ |
| `shmctl` | 195 | 31 | ✅ |
| `shmdt` | 197 | 67 | ✅ |
| `shmget` | 194 | 29 | ✅ |
| `shutdown` | 210 | 48 | ✅ |
| `sigaltstack` | 132 | 131 | ✅ |
| `signalfd` | — | 282 | · |
| `signalfd4` | 74 | 289 | · |
| `socket` | 198 | 41 | ✅ |
| `socketpair` | 199 | 53 | ✅ |
| `splice` | 76 | 275 | · |
| `stat` | — | 4 | ✅ |
| `statfs` | — | 137 | ✅ |
| `statmount` | 457 | 457 | · |
| `statx` | 291 | 332 | ✅ |
| `swapoff` | 225 | 168 | · |
| `swapon` | 224 | 167 | · |
| `symlink` | — | 88 | ✅ |
| `symlinkat` | 36 | 266 | ✅ |
| `sync` | 81 | 162 | ✅ |
| `sync_file_range` | 84 | 277 | ✅ |
| `sync_file_range2` | 84 | — | · |
| `syncfs` | 267 | 306 | ✅ |
| `sysfs` | — | 139 | ✅ |
| `sysinfo` | 179 | 99 | ✅ |
| `syslog` | 116 | 103 | ✅ |
| `tee` | 77 | 276 | ✅ |
| `tgkill` | 131 | 234 | ✅ |
| `time` | — | 201 | ✅ |
| `timer_create` | 107 | 222 | ✅ |
| `timer_delete` | 111 | 226 | ✅ |
| `timer_getoverrun` | 109 | 225 | ✅ |
| `timer_gettime` | 108 | 224 | ✅ |
| `timer_gettime64` | 408 | — | · |
| `timer_settime` | 110 | 223 | ✅ |
| `timer_settime64` | 409 | — | · |
| `timerfd_create` | 85 | 283 | ✅ |
| `timerfd_gettime` | 87 | 287 | ✅ |
| `timerfd_gettime64` | 410 | — | · |
| `timerfd_settime` | 86 | 286 | ✅ |
| `timerfd_settime64` | 411 | — | · |
| `times` | 153 | 100 | · |
| `tkill` | 130 | 200 | ✅ |
| `truncate` | — | 76 | · |
| `tuxcall` | — | 184 | ⊘ |
| `umask` | 166 | 95 | ✅ |
| `umount2` | 39 | 166 | ✅ |
| `uname` | 160 | 63 | ✅ |
| `unlink` | — | 87 | ✅ |
| `unlinkat` | 35 | 263 | ✅ |
| `unshare` | 97 | 272 | ✅ |
| `uretprobe` | — | 335 | · |
| `uselib` | — | 134 | ⊘ |
| `userfaultfd` | 282 | 323 | · |
| `ustat` | — | 136 | · |
| `utime` | — | 132 | ✅ |
| `utimensat` | 88 | 280 | ✅ |
| `utimensat_time64` | 412 | — | · |
| `utimes` | — | 235 | ✅ |
| `vfork` | — | 58 | ✅ |
| `vhangup` | 58 | 153 | · |
| `vmsplice` | 75 | 278 | · |
| `vserver` | — | 236 | ⊘ |
| `wait4` | 260 | 61 | ✅ |
| `waitid` | 95 | 247 | · |
| `write` | 64 | 1 | ✅ |
| `writev` | 66 | 20 | ✅ |

</details>

Regenerate with:

```
make syscalls UNISTD=/usr/include/asm-generic/unistd.h \
              UNISTD_X86=/usr/include/x86_64-linux-gnu/asm/unistd_64.h
```

That regenerates both dispatch tables from the same headers and writes this
table out beside them, so the three cannot disagree.

The numbers and names come from the kernel's own headers and the status from
NABI's dispatch tables, so this says what is true of the tree it was generated
against rather than what someone remembered to update.


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
