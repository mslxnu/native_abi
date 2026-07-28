#!/bin/sh
#
# arm64 end-to-end smoke test: run the committed aarch64 binaries under a
# natively-built nabi and check exit codes and output. See README.md.
#
# Usage: test/arch/smoke/run.sh <path-to-nabi>
set -u

NABI="${1:?usage: run.sh <path-to-nabi>}"
here=$(cd "$(dirname "$0")" && pwd)

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
cp "$here/exit42" "$here/hello" "$root/"
chmod +x "$root/exit42" "$root/hello"

fail=0

# exit(42): the guest's exit code must propagate.
"$NABI" -m "$root" /exit42
rc=$?
if [ "$rc" -eq 42 ]; then
    echo "  ok  exit42 -> 42"
else
    echo "  FAIL exit42 -> $rc, want 42"
    fail=1
fi

# hello: write(1, "hello arm64!\n") then exit(0).
out=$("$NABI" -m "$root" /hello)
rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "hello arm64!" ]; then
    echo "  ok  hello -> \"$out\", exit 0"
else
    echo "  FAIL hello -> \"$out\", exit $rc"
    fail=1
fi

# mmaptest: mmap a page, write() from it, munmap it, exit(0). Exercises the
# mmap/munmap syscall path and vmm_munmap in the real runtime.
cp "$here/mmaptest" "$root/"; chmod +x "$root/mmaptest"
out=$("$NABI" -m "$root" /mmaptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mmap+munmap ok" ]; then
    echo "  ok  mmaptest -> \"$out\", exit 0"
else
    echo "  FAIL mmaptest -> \"$out\", exit $rc"
    fail=1
fi

# sigtest: install a SIGUSR1 handler, kill() self, and verify the handler ran
# and the interrupted code resumed. Exercises signal frame setup, the sigreturn
# trampoline and rt_sigreturn in the real runtime.
cp "$here/sigtest" "$root/"; chmod +x "$root/sigtest"
out=$("$NABI" -m "$root" /sigtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "signal ok" ]; then
    echo "  ok  sigtest -> \"$out\", exit 0"
else
    echo "  FAIL sigtest -> \"$out\", exit $rc"
    fail=1
fi

# stattest: fstat a file and confirm the aarch64 struct stat layout (st_mode
# reads as a regular file). Guards struct l_newstat against the x86-64 order.
cp "$here/stattest" "$root/"; chmod +x "$root/stattest"
out=$("$NABI" -m "$root" /stattest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "stat ok" ]; then
    echo "  ok  stattest -> \"$out\", exit 0"
else
    echo "  FAIL stattest -> \"$out\", exit $rc"
    fail=1
fi

# sxtest: statx a file and prlimit64-query RLIMIT_NOFILE. Exercises two aarch64
# syscalls (291, 261) that modern glibc/musl use at startup and for stat().
cp "$here/sxtest" "$root/"; chmod +x "$root/sxtest"
out=$("$NABI" -m "$root" /sxtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "statx ok
prlimit64 ok" ]; then
    echo "  ok  sxtest -> statx + prlimit64, exit 0"
else
    echo "  FAIL sxtest -> \"$out\", exit $rc"
    fail=1
fi

# pptest: ppoll over a self-pipe - the timeout path and the data-ready path.
cp "$here/pptest" "$root/"; chmod +x "$root/pptest"
out=$("$NABI" -m "$root" /pptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "ppoll timeout ok
ppoll ready ok" ]; then
    echo "  ok  pptest -> ppoll timeout + ready, exit 0"
else
    echo "  FAIL pptest -> \"$out\", exit $rc"
    fail=1
fi

# forktest: fork, the child exits with a known code, the parent wait4()s it.
# Exercises the whole snapshot / hv_vm_destroy / host fork / reentry cycle.
cp "$here/forktest" "$root/"; chmod +x "$root/forktest"
out=$("$NABI" -m "$root" /forktest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "child
parent" ]; then
    echo "  ok  forktest -> child + parent, exit 0"
else
    echo "  FAIL forktest -> \"$out\", exit $rc"
    fail=1
fi

# clonetid: clone with CHILD_SETTID in aarch64 arg order (as glibc fork does);
# the child's tid must land in the child_tid pointer.
cp "$here/clonetid" "$root/"; chmod +x "$root/clonetid"
out=$("$NABI" -m "$root" /clonetid); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "settid ok" ]; then
    echo "  ok  clonetid -> settid ok, exit 0"
else
    echo "  FAIL clonetid -> \"$out\", exit $rc"
    fail=1
fi

# atomic: load/store-exclusive and an LSE atomic. Guards the caches being on
# (SCTLR_EL1.C/.I) - exclusives are unsupported on Non-cacheable memory.
cp "$here/atomic" "$root/"; chmod +x "$root/atomic"
out=$("$NABI" -m "$root" /atomic); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "atomics ok" ]; then
    echo "  ok  atomic -> \"$out\", exit 0"
else
    echo "  FAIL atomic -> \"$out\", exit $rc"
    fail=1
fi

# exectest: execve /hello and let the new image produce the output. Guards the
# guest PC being set through ELR_EL1 rather than the trampoline's HV_REG_PC.
cp "$here/exectest" "$root/"; chmod +x "$root/exectest"
out=$("$NABI" -m "$root" /exectest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "hello arm64!" ]; then
    echo "  ok  exectest -> execve ran /hello, exit 0"
else
    echo "  FAIL exectest -> \"$out\", exit $rc"
    fail=1
fi

# threadtest: a guest thread (a second live vCPU), CLONE_SETTLS reaching
# TPIDR_EL0, thread exit with CHILD_CLEARTID, futex WAIT/WAKE, and fork from a
# process that has had threads - the primitives a threading libc is built from.
cp "$here/threadtest" "$root/"; chmod +x "$root/threadtest"
out=$("$NABI" -m "$root" /threadtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "threads ok" ]; then
    echo "  ok  threadtest -> \"$out\", exit 0"
else
    echo "  FAIL threadtest -> \"$out\", exit $rc"
    fail=1
fi

# mtexectest: execve from a multi-threaded process, where the spare thread is in
# a syscall-free loop and so must be kicked out of hv_vcpu_run to be stopped.
cp "$here/mtexectest" "$root/"; chmod +x "$root/mtexectest"
out=$("$NABI" -m "$root" /mtexectest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "hello arm64!" ]; then
    echo "  ok  mtexectest -> execve from a thread, exit 0"
else
    echo "  FAIL mtexectest -> \"$out\", exit $rc"
    fail=1
fi

# protecttest: mprotect a page read-only and write to it. The write must trap,
# which needs both the stage-1 descriptors rewritten and the stage-2 block
# re-established so the translation notices.
cp "$here/protecttest" "$root/"; chmod +x "$root/protecttest"
out=$("$NABI" -m "$root" /protecttest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mprotect ok" ]; then
    echo "  ok  protecttest -> \"$out\", exit 0"
else
    echo "  FAIL protecttest -> \"$out\", exit $rc"
    fail=1
fi

# bigmaptest: the dynamic linker's over-align-then-trim sequence at library
# size - reserve, map the file inside it, trim both ends, PROT_NONE the
# inter-segment hole - and then read what survives. Catches an mprotect that
# applies the new permission to the whole remainder of a region instead of only
# the requested range: the bytes just past the hole must still be readable.
cp "$here/bigmaptest" "$root/"; chmod +x "$root/bigmaptest"
# shorter than the mapping on purpose, so the tail reads as zero
dd if=/dev/zero of="$root/bigmapfile" bs=1024 count=6100 2>/dev/null
out=$("$NABI" -m "$root" /bigmaptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "OK" ]; then
    echo "  ok  bigmaptest -> library-sized reserve/trim/protect, exit 0"
else
    echo "  FAIL bigmaptest -> \"$out\", exit $rc"
    fail=1
fi

# mapstest: /proc/self/maps describes the guest, not the nabi running it.
# Looks for a mapping the test made itself, so it cannot pass against the
# host's map by accident.
cp "$here/mapstest" "$root/"; chmod +x "$root/mapstest"
out=$("$NABI" -m "$root" /mapstest); rc=$?
if [ "$rc" -eq 0 ] && { [ "$out" = "maps ok" ] || [ "$out" = "maps skipped" ]; }; then
    echo "  ok  mapstest -> \"$out\""
else
    echo "  FAIL mapstest -> \"$out\", exit $rc"
    fail=1
fi

# procfstest: a mounted pseudo-filesystem is passed through, and survives a
# fork - which on arm64 is fork + exec, so the child has to re-probe the host
# for itself. Skips when nothing is mounted at /proc.
cp "$here/procfstest" "$root/"; chmod +x "$root/procfstest"
out=$("$NABI" -m "$root" /procfstest); rc=$?
if [ "$rc" -eq 0 ] && { [ "$out" = "procfs ok" ] || [ "$out" = "procfs skipped" ]; }; then
    echo "  ok  procfstest -> \"$out\""
else
    echo "  FAIL procfstest -> \"$out\", exit $rc"
    fail=1
fi

# hvctest: no value in x0 may stop a syscall from reaching the host. The EL1
# trampoline preserves the guest's registers, so x0 is live when its `hvc`
# runs, and Apple's hypervisor answers SMCCC-shaped function IDs itself unless
# the immediate is non-zero. Sweeps the whole top byte.
cp "$here/hvctest" "$root/"; chmod +x "$root/hvctest"
out=$("$NABI" -m "$root" /hvctest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "hvc ok" ]; then
    echo "  ok  hvctest -> \"$out\", exit 0"
else
    echo "  FAIL hvctest -> \"$out\", exit $rc"
    fail=1
fi

# pathtest: a guest path starting with a host-passthrough name (/tmpmark) must
# resolve in the rootfs, not on the host. Needs the marker file to exist here.
cp "$here/pathtest" "$root/"; chmod +x "$root/pathtest"; echo marker > "$root/tmpmark"
out=$("$NABI" -m "$root" /pathtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "path ok" ]; then
    echo "  ok  pathtest -> \"$out\", exit 0"
else
    echo "  FAIL pathtest -> \"$out\", exit $rc"
    fail=1
fi

# epolltest: epoll over a self-pipe, translated to kqueue - the timeout path, a
# readable descriptor, the guest's opaque data returned verbatim, and DEL.
cp "$here/epolltest" "$root/"; chmod +x "$root/epolltest"
out=$("$NABI" -m "$root" /epolltest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "epoll ok" ]; then
    echo "  ok  epolltest -> \"$out\", exit 0"
else
    echo "  FAIL epolltest -> \"$out\", exit $rc"
    fail=1
fi

# splitmunmaptest: unmap part of a mapping so live pages remain inside the
# 16KiB stage-2 blocks it partly emptied. Survivors must keep their contents and
# the unmapped pages must fault - this used to panic as needing "evacuation".
cp "$here/splitmunmaptest" "$root/"; chmod +x "$root/splitmunmaptest"
out=$("$NABI" -m "$root" /splitmunmaptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "split munmap ok" ]; then
    echo "  ok  splitmunmaptest -> \"$out\", exit 0"
else
    echo "  FAIL splitmunmaptest -> \"$out\", exit $rc"
    fail=1
fi

# sharedmaptest: a MAP_SHARED write must reach the file (and a MAP_PRIVATE one
# must not). Everything else file-backed is copied into guest memory, which
# cannot give MAP_SHARED its meaning.
cp "$here/sharedmaptest" "$root/"; chmod +x "$root/sharedmaptest"
out=$("$NABI" -m "$root" /sharedmaptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "shared map ok" ]; then
    echo "  ok  sharedmaptest -> \"$out\", exit 0"
else
    echo "  FAIL sharedmaptest -> \"$out\", exit $rc"
    fail=1
fi

# clocktest: the clocks and descriptor flags an interactive shell asks for -
# CLOCK_REALTIME_COARSE and fcntl(F_GETFL) both used to kill the guest.
cp "$here/clocktest" "$root/"; chmod +x "$root/clocktest"
out=$("$NABI" -m "$root" /clocktest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "clocks ok" ]; then
    echo "  ok  clocktest -> \"$out\", exit 0"
else
    echo "  FAIL clocktest -> \"$out\", exit $rc"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "smoke: PASS"
else
    echo "smoke: FAIL"
fi
exit $fail
