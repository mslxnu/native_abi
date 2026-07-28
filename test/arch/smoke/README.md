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

- `mapstest` — `/proc/self/maps` describes the guest rather than the `nabi`
  running it, before and after a fork. Looks for a mapping the test made itself.
- `procfstest` — a mounted pseudo-filesystem is visible and stays visible across
  a fork. Skips when nothing is mounted at `/proc`, since it is about NABI
  passing one through rather than about mSL/ProcFS.
- `hvctest` — sweeps every top byte through x0 and checks each syscall still
  reaches the host. The EL1 trampoline clobbers no register, so the guest's x0
  is live at its `hvc`, and an `hvc #0` whose x0 looks like an SMCCC function ID
  the hypervisor owns is answered in firmware instead of exiting to us.
- `bigmaptest` — the dynamic linker's over-align-then-trim sequence at
  libcrypto's size: reserve, map the file at an aligned address inside it, trim
  both ends, and `PROT_NONE` the inter-segment hole. Needs `bigmapfile` in the
  root.

The ELF binaries are committed prebuilt (as the x86 guest tests under
`test/*/build/` are), so the check needs no cross-toolchain. The `.s` sources
are here for reference; rebuild with an aarch64-linux clang + ld.lld:

    clang -target aarch64-linux-gnu -c exit42.s -o exit42.o
    ld.lld -static -e _start exit42.o -o exit42

Run via `make check-smoke` (Apple Silicon only; needs a natively-built nabi).
