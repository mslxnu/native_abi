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

The ELF binaries are committed prebuilt (as the x86 guest tests under
`test/*/build/` are), so the check needs no cross-toolchain. The `.s` sources
are here for reference; rebuild with an aarch64-linux clang + ld.lld:

    clang -target aarch64-linux-gnu -c exit42.s -o exit42.o
    ld.lld -static -e _start exit42.o -o exit42

Run via `make check-smoke` (Apple Silicon only; needs a natively-built nabi).
