# arm64 end-to-end smoke test

The smallest real aarch64 Linux binaries, run under a natively-built `nabi` to
exercise the whole pipeline at once: ELF load, stage-1/stage-2 translation, the
EL1 trampoline, syscall dispatch through the generated aarch64 table, and the
guest-code cache sync.

- `exit42` — `exit(42)`; checks exit-code propagation.
- `hello`  — `write(1, "hello arm64!\n", 14); exit(0)`; checks a syscall with
  guest memory arguments and stdout.
- `mmaptest` — mmap a page, write() from it, munmap it, exit(0); exercises the
  mmap/munmap syscall path and vmm_munmap in the real runtime.
- `sigtest` — install a SIGUSR1 handler, `kill()` self, verify the handler ran
  and the interrupted code resumed; exercises signal-frame setup, the sigreturn
  trampoline and rt_sigreturn.
- `stattest` — `fstat` a file and confirm the aarch64 `struct stat` layout:
  `st_mode` reads back as a regular file. Guards `struct l_newstat` against
  regressing to the x86-64 field order.
- `sxtest` — `statx` a file (regular file, nonzero size) and `prlimit64`-query
  `RLIMIT_NOFILE`; covers two syscalls modern glibc/musl need at startup.
- `pptest` — `ppoll` over a self-pipe: the timeout path (nothing ready) and the
  data-ready path (POLLIN). `ppoll` is aarch64's primary poll.
- `forktest` — `fork`, the child exits with a known code, the parent `wait4`s it
  and checks the status; exercises the whole vCPU-snapshot / VM-teardown / host
  fork / reentry cycle.
- `clonetid` — `clone` with `CHILD_SETTID` in aarch64 argument order (as glibc's
  `fork` issues it); the child's tid must land in the `child_tid` pointer.
- `atomic` — load/store-exclusive and an LSE atomic on normal memory. Guards
  `SCTLR_EL1.C`/`.I` being enabled: exclusives are unsupported on Non-cacheable
  memory, and every real libc locks, so this gates running any glibc binary.
- `exectest` — `execve`s `/hello` and lets the new image print. Guards the guest
  PC being set through `ELR_EL1` rather than the EL1 trampoline's `HV_REG_PC`,
  without which `execve` returns to the old image and the guest wanders off
  silently. Runs `hello`, so the two are paired.
- `threadtest` — a guest thread (a second live vCPU in the same VM), `CLONE_SETTLS`
  reaching `TPIDR_EL0`, thread exit with `CHILD_CLEARTID`, futex `WAIT`/`WAKE`,
  and `fork` from a process that has had threads: the primitives a threading libc
  is built out of.
- `clocktest` — the clocks an interactive shell asks for (including
  `CLOCK_REALTIME_COARSE`) and `fcntl(F_GETFL)`; both used to kill the guest
  rather than answer it, and an unknown clock must give EINVAL, not die.
- `sharedmaptest` — a `MAP_SHARED` write reaches the file and a `MAP_PRIVATE`
  one does not. Other file mappings are copied into guest memory, which cannot
  give `MAP_SHARED` its meaning.
- `splitmunmaptest` — unmap part of a mapping so live pages remain inside the
  16KiB stage-2 blocks it partly emptied; survivors keep their contents and the
  unmapped pages fault. This case used to panic as needing "evacuation".
- `epolltest` — `epoll` over a self-pipe (translated to kqueue): the timeout
  path, a readable descriptor, the guest's opaque 64-bit data returned verbatim,
  and that `EPOLL_CTL_DEL` really unregisters.
- `pathtest` — a guest path merely starting with a host-passthrough name
  (`/tmpmark` vs `/tmp`) must resolve in the rootfs, not on the host.
- `protecttest` — `mprotect` a page read-only and write to it; the write must trap.
  Covers both halves: the stage-1 descriptors carrying the new permission, and
  the stage-2 block being re-established so the translation notices.
- `mtexectest` — `execve` from a multi-threaded process, with the spare thread in
  a syscall-free loop so it must be kicked out of `hv_vcpu_run` to be stopped.
- `bigmaptest` — the dynamic linker's over-align-then-trim load, at library size:
  reserve `maplength+p_align` anonymously, map the file at the aligned address
  inside it, munmap the slack at each end, `PROT_NONE` the inter-segment hole,
  then read what survives. The byte immediately after the hole is the point:
  `mprotect` used to apply the new permission to the whole remainder of the
  region rather than the requested range, which made a library load and then
  fault on its own data. Needs `/bigmapfile`, which `run.sh` creates shorter than
  the mapping so the tail also checks that past-EOF pages read as zero.

- `identtest` — `/proc/self/{cmdline,comm,exe}` name the guest rather than the
  `nabi`, across a fork that has to carry them in the checkpoint.
- `mapstest` — `/proc/self/maps` describes the guest rather than the `nabi`
  running it, before and after a fork. Looks for a mapping the test made itself.
- `procfstest` — a mounted pseudo-filesystem is visible and stays visible across
  a fork. Skips when nothing is mounted at `/proc`, since it is about NABI
  passing one through rather than about mSL/ProcFS.
- `permtest` — the guest's credentials decide what it may open, create and
  remove, including through a directory it may not search. Drops from root to an
  ordinary uid partway through, which is the transition that matters, and checks
  that a recorded `chown` survives a `stat`.
- `aligntest` — the stack is 16-byte aligned at process entry, checked across
  sixteen environment lengths because one would only catch a misalignment half
  the time. An 8-byte-off stack does not fault; it corrupts a heap much later.
- `signaltest` — `tgkill`/`tkill` actually kill. Checked from a parent with
  `wait4`, because the point is not that the call returns 0 but that the process
  goes away; a stub turns every `abort()` into a hang.
- `futextest` — `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` errno, timeout units and the
  compare-and-block. Times the wait rather than only checking that it returned,
  since "did not sleep at all" also returns.
- `emptypathtest` — `statx`/`fstatat` with `AT_EMPTY_PATH`, the form Rust's
  standard library uses for every file it opens. Compared against `fstat` on
  the same descriptor, since a stat of the wrong object also returns 0.
- `oflagtest` — `O_DIRECTORY` and `O_NOFOLLOW` refuse what they are supposed
  to refuse. arm64 permutes these four flag values relative to asm-generic, and
  a flag read as one NABI ignores is granted rather than rejected.
- `ptytest` — `/dev/ptmx`, `TIOCSPTLCK`, `TIOCGPTN` and the `/dev/pts/<n>`
  path, which Darwin spells differently at every step. apt runs dpkg under a
  pty, so all four have to work or nothing installs. Also the `termios2` forms
  (`TCGETS2` and its setters), which are what glibc 2.42 sends instead of
  `TCGETS`: without them `isatty()` says nothing is a terminal, so bash starts
  non-interactive with an empty prompt and a login looks like a hang.
- `growtest` — a large `PROT_NONE` reservation with a piece `mprotect`ed
  writable, and large regions grown by `mremap`, reached from the parent and
  from a child. Stage 2 has to be re-permissioned, not merely reflushed.
- `hvctest` — sweeps every top byte through x0 and checks each syscall still
  reaches the host. The EL1 trampoline clobbers no register, so the guest's x0
  is live at its `hvc`, and an `hvc #0` whose x0 looks like an SMCCC function ID
  the hypervisor owns is answered in firmware instead of exiting to us.
- `bigmaptest` — the dynamic linker's over-align-then-trim sequence at
  libcrypto's size: reserve, map the file at an aligned address inside it, trim
  both ends, and `PROT_NONE` the inter-segment hole. Needs `bigmapfile` in the
  root.

- `synctest` — `fsync`, `fdatasync` and `syncfs` on a file, then reading the
  bytes back. `syncfs` was not implemented, and coreutils' `sync(1)` reports the
  resulting ENOSYS as "Function not implemented" - which is what stopped
  `apt-get install linux-image-arm64`, since the kernel postinst syncs the
  initrd it just built and treats a failure as fatal.

- `eventfdtest` — `eventfd2`: that it counts rather than queues, that it polls
  readable only when it should, and that the descriptor it returns is a
  descriptor. The last is the point: the syscall once returned `register_fd`'s
  status instead, so every eventfd came back as fd 0, which behaves plausibly
  right up until the guest closes it and thereby closes its own stdin. Also
  checks `openat(-1, "/", ...)`, since an absolute path makes the directory
  descriptor irrelevant and Linux does not look at it - rpm opens the root that
  way before unpacking anything.

- `brktest` — `brk(0)` answers with the break as it stands, agrees with the
  value the preceding move returned, and follows it back down. It answered
  `start_brk` instead, which is the same number only until something has grown
  the heap - and static glibc grows it during startup, taking its TLS block with
  `sbrk`. The next allocation was then handed the same bytes again.

- `suidtest` (with `suidhelper`) — a file at mode `4111`, which is how every
  distribution ships sudo: executable by all, readable by none, set-user-ID
  root. Checks that the guest still *sees* `4111`, that the file can be executed
  anyway, and that the bit elevates. NABI performs every access as the host
  account, so a mode with no owner read is one it cannot open at all - Fedora's
  sudo installed correctly and then answered "Permission denied".

- `priotest` — `getpriority` returns `20 - nice`, not `nice`. Linux encodes it
  so the result can never look like a negative errno; Darwin's returns the value
  itself, and passing that through made a guest read an ordinary nice of 0 as
  20. pam_limits applied what it read, which really did drop the process to nice
  20, and putting it back was then a privileged operation - so sudo stopped at
  "pam_open_session: Permission denied" over a nice value.

- `roottest` — `/..` is `/`, by path and through a descriptor the guest opened
  itself, and `getcwd` answers in the guest's namespace. The host resolved `..`
  at the rootfs boundary, so every host file was one `..` away; and systemd,
  which decides whether a descriptor is the root by asking where `..` leads,
  concluded `/` was not the root and failed every rpm `%sysusers` scriptlet.

The ELF binaries are committed prebuilt (as the x86 guest tests under
`test/*/build/` are), so the check needs no cross-toolchain. The `.s` sources
are here for reference; rebuild with an aarch64-linux clang + ld.lld:

    clang -target aarch64-linux-gnu -c exit42.s -o exit42.o
    ld.lld -static -e _start exit42.o -o exit42

Run via `make check-smoke` (Apple Silicon only; needs a natively-built nabi).
