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

# identtest: /proc/self/{cmdline,comm,exe} describe the guest, not the nabi -
# before and after a fork, which is where the checkpoint has to carry them.
cp "$here/identtest" "$root/"; chmod +x "$root/identtest"
out=$("$NABI" -m "$root" /identtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "ident ok" ]; then
    echo "  ok  identtest -> \"$out\""
else
    echo "  FAIL identtest -> \"$out\", exit $rc"
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

# The same three again with the sibling modules pretended absent. NABI has to
# work without mSL/FHS and mSL/ProcFS, and on a machine that has them that is
# otherwise a claim with nothing exercising it. What must hold: the passthrough
# goes away, and the files NABI answers from its own state do not.
for t in procfstest mapstest identtest; do
    out=$(NABI_IGNORE_HOST_FS=1 "$NABI" -m "$root" /$t); rc=$?
    case "$t:$out" in
        procfstest:"procfs skipped") ok=yes ;;
        mapstest:"maps ok")          ok=yes ;;
        identtest:"ident ok")        ok=yes ;;
        *)                           ok=no  ;;
    esac
    if [ "$rc" -eq 0 ] && [ "$ok" = yes ]; then
        echo "  ok  $t (no host fs) -> \"$out\""
    else
        echo "  FAIL $t (no host fs) -> \"$out\", exit $rc"
        fail=1
    fi
done

# permtest: the guest's own credentials decide what it may touch - which needs
# ownership to be real first, since the host cannot represent it.
cp "$here/permtest" "$root/"; chmod +x "$root/permtest"
out=$("$NABI" -m "$root" /permtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "perm ok" ]; then
    echo "  ok  permtest -> \"$out\""
else
    echo "  FAIL permtest -> \"$out\", exit $rc"
    fail=1
fi

# aligntest: the stack is 16-byte aligned at process entry. Re-execs itself
# sixteen times with a growing environment, since one length would only catch a
# misalignment half the time.
cp "$here/aligntest" "$root/"; chmod +x "$root/aligntest"
out=$("$NABI" -m "$root" /aligntest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "align ok" ]; then
    echo "  ok  aligntest -> \"$out\""
else
    echo "  FAIL aligntest -> \"$out\", exit $rc"
    fail=1
fi

# signaltest: a process that asks to die, dies. tgkill is how abort() delivers
# SIGABRT to itself, and a stub turns every abort into a hang.
cp "$here/signaltest" "$root/"; chmod +x "$root/signaltest"
out=$("$NABI" -m "$root" /signaltest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "signal ok" ]; then
    echo "  ok  signaltest -> \"$out\""
else
    echo "  FAIL signaltest -> \"$out\", exit $rc"
    fail=1
fi

# futextest: the futex operations glibc's locking primitives rely on. A
# relative timeout read as absolute makes a sleeping guest spin; a missing
# compare makes a woken one sleep forever.
cp "$here/futextest" "$root/"; chmod +x "$root/futextest"
out=$("$NABI" -m "$root" /futextest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "futex ok" ]; then
    echo "  ok  futextest -> \"$out\""
else
    echo "  FAIL futextest -> \"$out\", exit $rc"
    fail=1
fi

# emptypathtest: AT_EMPTY_PATH, on the calls that read a file and on the ones
# that change it. statx and fstatat are how Rust's standard library stats every
# file it opens; fchmodat2 and fchownat are how systemd sets the mode and owner
# of a temporary file by descriptor, which is what every %sysusers scriptlet in
# a Fedora dnf transaction does - and which used to answer EINVAL. The mode and
# owner are checked for actually changing, not for the call returning 0.
cp "$here/emptypathtest" "$root/"; chmod +x "$root/emptypathtest"
out=$("$NABI" -m "$root" /emptypathtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "emptypath ok" ]; then
    echo "  ok  emptypathtest -> \"$out\""
else
    echo "  FAIL emptypathtest -> \"$out\", exit $rc"
    fail=1
fi

# oflagtest: O_DIRECTORY and O_NOFOLLOW must refuse. arm64 permutes these four
# flag values relative to asm-generic, and a flag read as one NABI ignores is
# silently granted - the worst outcome for a flag whose job is to fail.
cp "$here/oflagtest" "$root/"; chmod +x "$root/oflagtest"
out=$("$NABI" -m "$root" /oflagtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "oflag ok" ]; then
    echo "  ok  oflagtest -> \"$out\""
else
    echo "  FAIL oflagtest -> \"$out\", exit $rc"
    fail=1
fi

# ptytest: a guest allocates a pty and talks through it. Linux and Darwin
# agree on /dev/ptmx and on nothing after it.
cp "$here/ptytest" "$root/"; chmod +x "$root/ptytest"
out=$("$NABI" -m "$root" /ptytest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pty ok" ]; then
    echo "  ok  ptytest -> \"$out\""
else
    echo "  FAIL ptytest -> \"$out\", exit $rc"
    fail=1
fi

# growtest: a large PROT_NONE reservation with a piece mprotected writable -
# how malloc builds an arena - and large regions grown by mremap, touched in
# the parent and again from a child.
cp "$here/growtest" "$root/"; chmod +x "$root/growtest"
out=$("$NABI" -m "$root" /growtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "grow ok" ]; then
    echo "  ok  growtest -> \"$out\""
else
    echo "  FAIL growtest -> \"$out\", exit $rc"
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

# mremapfixedtest: mremap with MREMAP_FIXED|MREMAP_MAYMOVE onto a pinned,
# 4KiB-but-not-16KiB-aligned interior page of a reservation - the CFI
# shadow-rewrite move. The answer must be the destination, the bytes must arrive
# with the move, and the moved page must be mprotected writable and written
# through afterwards. The source was isolated by an mprotect, so the 16KiB block
# it shares with the tail it left behind must survive the move - this used to
# panic in hv_vm_map when the source's host memory was freed first.
cp "$here/mremapfixedtest" "$root/"; chmod +x "$root/mremapfixedtest"
out=$("$NABI" -m "$root" /mremapfixedtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mremapfixed ok" ]; then
    echo "  ok  mremapfixedtest -> \"$out\", exit 0"
else
    echo "  FAIL mremapfixedtest -> \"$out\", exit $rc"
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

# synctest: fsync, fdatasync and syncfs. syncfs was missing entirely, and an
# ENOSYS there is what left a freshly unpacked kernel package unconfigured.
cp "$here/synctest" "$root/"; chmod +x "$root/synctest"
out=$("$NABI" -m "$root" /synctest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "sync ok" ]; then
    echo "  ok  synctest -> \"$out\", exit 0"
else
    echo "  FAIL synctest -> \"$out\", exit $rc"
    fail=1
fi

# eventfdtest: eventfd's counter and pollability, the descriptor number it is
# handed out as, and openat with an absolute path against a bogus dirfd.
cp "$here/eventfdtest" "$root/"; chmod +x "$root/eventfdtest"
out=$("$NABI" -m "$root" /eventfdtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "eventfd ok" ]; then
    echo "  ok  eventfdtest -> \"$out\", exit 0"
else
    echo "  FAIL eventfdtest -> \"$out\", exit $rc"
    fail=1
fi

# brktest: brk(0) must answer with the break as it stands, not where it began.
cp "$here/brktest" "$root/"; chmod +x "$root/brktest"
out=$("$NABI" -m "$root" /brktest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "brk ok" ]; then
    echo "  ok  brktest -> \"$out\", exit 0"
else
    echo "  FAIL brktest -> \"$out\", exit $rc"
    fail=1
fi

# suidtest: a mode that denies its own owner, and the setuid bit on it. The
# helper's mode is set from here rather than by the test, so this also covers a
# file that was already on disk with nothing recorded about it.
cp "$here/suidtest" "$here/suidhelper" "$root/"
chmod +x "$root/suidtest"; chmod 4111 "$root/suidhelper"
out=$("$NABI" -m "$root" /suidtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "suid ok" ]; then
    echo "  ok  suidtest -> \"$out\", exit 0"
else
    echo "  FAIL suidtest -> \"$out\", exit $rc"
    fail=1
fi

# priotest: getpriority's 20 - nice encoding, which is not what Darwin returns.
cp "$here/priotest" "$root/"; chmod +x "$root/priotest"
out=$("$NABI" -m "$root" /priotest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "prio ok" ]; then
    echo "  ok  priotest -> \"$out\", exit 0"
else
    echo "  FAIL priotest -> \"$out\", exit $rc"
    fail=1
fi

# roottest: the guest's root has no parent, by path and through a descriptor,
# and the working directory is named the way the guest names things.
cp "$here/roottest" "$root/"; chmod +x "$root/roottest"
out=$("$NABI" -m "$root" /roottest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "root ok" ]; then
    echo "  ok  roottest -> \"$out\", exit 0"
else
    echo "  FAIL roottest -> \"$out\", exit $rc"
    fail=1
fi

# randtest: /proc/sys/kernel/random/uuid is a generator (never twice the same)
# and boot_id is not (never different).
cp "$here/randtest" "$root/"; chmod +x "$root/randtest"
out=$("$NABI" -m "$root" /randtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "rand ok" ]; then
    echo "  ok  randtest -> \"$out\", exit 0"
else
    echo "  FAIL randtest -> \"$out\", exit $rc"
    fail=1
fi

# schedtest: the sched_* family, and that its answers agree with each other -
# what getscheduler reports must be what setscheduler accepted.
cp "$here/schedtest" "$root/"; chmod +x "$root/schedtest"
out=$("$NABI" -m "$root" /schedtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "sched ok" ]; then
    echo "  ok  schedtest -> \"$out\", exit 0"
else
    echo "  FAIL schedtest -> \"$out\", exit $rc"
    fail=1
fi

# nstest: namespaces - uts works, the rest refuse rather than pretend, and the
# identity survives a fork (which on arm64 rebuilds it from a checkpoint).
cp "$here/nstest" "$root/"; chmod +x "$root/nstest"
out=$("$NABI" -m "$root" /nstest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "ns ok" ]; then
    echo "  ok  nstest -> \"$out\", exit 0"
else
    echo "  FAIL nstest -> \"$out\", exit $rc"
    fail=1
fi

# ipctest: System V IPC on its own tables, and the namespace that scopes them.
# The segment attached across a fork is the case that used to panic the child
# in checkpoint_restore, a Darwin attachment being neither arena- nor
# file-backed.
cp "$here/ipctest" "$root/"; chmod +x "$root/ipctest"
out=$("$NABI" -m "$root" /ipctest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "ipc ok" ]; then
    echo "  ok  ipctest -> \"$out\", exit 0"
else
    echo "  FAIL ipctest -> \"$out\", exit $rc"
    fail=1
fi

# inotest: inotify over kqueue. The names on the events are the point - kqueue
# says a directory changed and not what changed in it - and so is the refusal
# of a mask that could never fire, which is the difference between a caller
# that fails and one that waits forever.
cp "$here/inotest" "$root/"; chmod +x "$root/inotest"
rm -rf "$root/ino-dir"
out=$("$NABI" -m "$root" /inotest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "ino ok" ]; then
    echo "  ok  inotest -> \"$out\", exit 0"
else
    echo "  FAIL inotest -> \"$out\", exit $rc"
    fail=1
fi

# fantest: fanotify, which unlike inotify exists to watch *other* processes -
# so the file is touched by a forked child, and a listener that could only see
# its own process would fail here rather than pass by accident. Needs guest
# root, as fanotify needs CAP_SYS_ADMIN.
cp "$here/fantest" "$root/"; chmod +x "$root/fantest"
rm -rf "$root/fan-dir"
out=$(MSL_ROOT=1 "$NABI" -m "$root" /fantest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "fan ok" ]; then
    echo "  ok  fantest -> \"$out\", exit 0"
else
    echo "  FAIL fantest -> \"$out\", exit $rc"
    fail=1
fi

# xattrtest: extended attributes round-tripping, and nabi's own bookkeeping
# attribute staying invisible, unwritable and unremovable while the ownership it
# records keeps working. Needs guest root for the chown.
cp "$here/xattrtest" "$root/"; chmod +x "$root/xattrtest"
out=$(MSL_ROOT=1 "$NABI" -m "$root" /xattrtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "xattr ok" ]; then
    echo "  ok  xattrtest -> \"$out\", exit 0"
else
    echo "  FAIL xattrtest -> \"$out\", exit $rc"
    fail=1
fi

# futextest: the rest of the futex family - requeue moving waiters without
# waking them, TRYLOCK_PI, and the futex2 syscalls. futex_waitv is the one that
# needs a test of its own: it must report *which* of several futexes woke, so an
# implementation that queued only the first would satisfy a weaker check.
cp "$here/futextest" "$root/"; chmod +x "$root/futextest"
out=$("$NABI" -m "$root" /futextest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "futex ok" ]; then
    echo "  ok  futextest -> \"$out\", exit 0"
else
    echo "  FAIL futextest -> \"$out\", exit $rc"
    fail=1
fi

# timertest: timerfd and POSIX timers, neither of which Darwin has at all. The
# check that matters is ppoll seeing the timerfd - one that only worked through
# read() would pass a simpler test and be useless in an event loop, which is
# where timerfds are used.
cp "$here/timertest" "$root/"; chmod +x "$root/timertest"
out=$("$NABI" -m "$root" /timertest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "timer ok" ]; then
    echo "  ok  timertest -> \"$out\", exit 0"
else
    echo "  FAIL timertest -> \"$out\", exit $rc"
    fail=1
fi

# teetest: tee(2), which needs a peek into a pipe that Darwin does not have.
# The check that matters is the partial tee with a writer behind it - copying is
# the easy half, and every scheme that reads and puts back passes a single-shot
# test and returns the stream reordered as soon as anything else writes.
cp "$here/teetest" "$root/"; chmod +x "$root/teetest"
out=$("$NABI" -m "$root" /teetest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "tee ok" ]; then
    echo "  ok  teetest -> \"$out\", exit 0"
else
    echo "  FAIL teetest -> \"$out\", exit $rc"
    fail=1
fi

# splicetest: splice and vmsplice. These consume what they move, so they avoid
# tee's ordering trap - except when splicing a pipe tee is holding bytes for,
# which is the case checked here and the one that fails without the pushback
# lookup (2 bytes instead of 4). The offset pair is the other half: an offset
# splice must advance the caller's offset and leave the file's own alone.
cp "$here/splicetest" "$root/"; chmod +x "$root/splicetest"
out=$("$NABI" -m "$root" /splicetest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "splice ok" ]; then
    echo "  ok  splicetest -> \"$out\", exit 0"
else
    echo "  FAIL splicetest -> \"$out\", exit $rc"
    fail=1
fi

# copytest: sendfile and copy_file_range. The copying is the easy part; the
# check that matters sends a 200K file into a non-blocking pipe that cannot take
# it all and then looks at the source's position, which must equal what the call
# said it moved. An implementation that reads with read(2) and discovers the
# short write afterwards leaves the file 64K further on than it delivered - a
# silent hole that only appears when the destination is slow.
cp "$here/copytest" "$root/"; chmod +x "$root/copytest"
out=$("$NABI" -m "$root" /copytest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "copy ok" ]; then
    echo "  ok  copytest -> \"$out\", exit 0"
else
    echo "  FAIL copytest -> \"$out\", exit $rc"
    fail=1
fi

# aiotest: the io_setup family. Reading is the easy half; the checks that matter
# are that a read's data is in the *guest's* buffer by the time the event is
# reaped (NABI's worker never touches guest memory, so the copy happens at reap
# time), that each event carries its own iocb's data and address - crossed wires
# are invisible with one request in flight - and that an eventfd named by
# IOCB_FLAG_RESFD is poked, without which the test hangs rather than fails.
cp "$here/aiotest" "$root/"; chmod +x "$root/aiotest"
out=$("$NABI" -m "$root" /aiotest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "aio ok" ]; then
    echo "  ok  aiotest -> \"$out\", exit 0"
else
    echo "  FAIL aiotest -> \"$out\", exit $rc"
    fail=1
fi

# uringtest: io_uring, driven by hand rather than through liburing, because the
# thing being tested is the layout NABI reports - the offsets come out of
# io_uring_params and are used as a real caller would use them. The first check
# is the one that matters: NABI writes ring_entries before the guest ever maps
# the page, so reading it back proves the two are looking at the same memory.
# That check is what caught the ring descriptor being returned wrong.
cp "$here/uringtest" "$root/"; chmod +x "$root/uringtest"
out=$("$NABI" -m "$root" /uringtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "uring ok" ]; then
    echo "  ok  uringtest -> \"$out\", exit 0"
else
    echo "  FAIL uringtest -> \"$out\", exit $rc"
    fail=1
fi

# mqtest: POSIX message queues, which Darwin does not have at all, and the io
# priority pair. The checks that matter are the ones a pipe-shaped implementation
# would fail: a later message with a higher priority comes out first, equal
# priorities come out oldest-first, a receive buffer smaller than the queue's
# message size is refused without consuming anything, and mq_unlink removes the
# name while a still-open descriptor keeps working.
cp "$here/mqtest" "$root/"; chmod +x "$root/mqtest"
out=$("$NABI" -m "$root" /mqtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mq ok" ]; then
    echo "  ok  mqtest -> \"$out\", exit 0"
else
    echo "  FAIL mqtest -> \"$out\", exit $rc"
    fail=1
fi

# mounttest: mount_setattr, listmount and mbind, plus the two kexec refusals.
# The check that matters is that mount_setattr *takes effect* rather than being
# recorded - a bind made read-only through it has to start refusing writes, and
# an implementation that stored the attribute instead reports 4 where -EROFS was
# wanted. mbind has one node to work with, so what is tested is that a nodemask
# naming a node this machine does not have is refused rather than ignored.
cp "$here/mounttest" "$root/"; chmod +x "$root/mounttest"
out=$("$NABI" -m "$root" /mounttest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mount ok" ]; then
    echo "  ok  mounttest -> \"$out\", exit 0"
else
    echo "  FAIL mounttest -> \"$out\", exit $rc"
    fail=1
fi

# lxctest: the LXC /dev setup in one pass - mknod placeholders whose stat
# reports S_IFCHR with the right rdev and whose open answers ENXIO, a devtmpfs
# mount that reaches the host's /dev, binderfs and devpts mount types, and a
# cgroup2 mount whose cgroup.subtree_control refuses writes (the file's whole
# contract is that no controller can be enabled). It unmounts what it mounted,
# leaving the mount namespace as it found it.
cp "$here/lxctest" "$root/"; chmod +x "$root/lxctest"
out=$("$NABI" -m "$root" /lxctest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "lxctest start
lxctest ok" ]; then
    echo "  ok  lxctest -> \"$out\", exit 0"
else
    echo "  FAIL lxctest -> \"$out\", exit $rc"
    fail=1
fi

# auxvtest: the auxiliary vector, walked off the process's own stack rather than
# through getauxval - so it checks what NABI put there with no libc in between.
# AT_SECURE is why it exists: getauxval sets errno for an entry that is absent,
# and GLib's g_check_setuid turns that into g_error, which aborts. Without it
# dconf's RPM scriptlet trapped during a Fedora install, and with it every other
# GLib program.
cp "$here/auxvtest" "$root/"; chmod +x "$root/auxvtest"
out=$("$NABI" -m "$root" /auxvtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "auxv ok" ]; then
    echo "  ok  auxvtest -> \"$out\", exit 0"
else
    echo "  FAIL auxvtest -> \"$out\", exit $rc"
    fail=1
fi

# AT_RANDOM, which only two runs can judge. glibc builds the stack canary and
# the pointer guard out of those sixteen bytes, and no single run can tell
# random bytes from bytes that are simply the same every time - which is what
# they were when the array was left uninitialised: the upper eight identical on
# every run and the lower eight a host pointer with a few bits of ASLR in it.
a=$("$NABI" -m "$root" /auxvtest --random)
b=$("$NABI" -m "$root" /auxvtest --random)
if [ -n "$a" ] && [ "$a" != "$b" ]; then
    echo "  ok  auxvtest AT_RANDOM differs between runs"
else
    echo "  FAIL auxvtest AT_RANDOM -> \"$a\" then \"$b\""
    fail=1
fi

# pvmtest: process_vm_readv and process_vm_writev. Only the same-process form
# can work here - a guest process is a host process with its own guest memory -
# so the cross-process form is refused, and both halves are checked. What is
# easy to get wrong in the half that works is the vector walk: the two sides are
# gathered and scattered independently, and the shapes here deliberately do not
# match, so an implementation that pairs entry with entry reports 8 of 10.
cp "$here/pvmtest" "$root/"; chmod +x "$root/pvmtest"
out=$("$NABI" -m "$root" /pvmtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pvm ok" ]; then
    echo "  ok  pvmtest -> \"$out\", exit 0"
else
    echo "  FAIL pvmtest -> \"$out\", exit $rc"
    fail=1
fi

# pidfdtest: pidfd_open, process_madvise and process_mrelease. The two that were
# asked for take a pidfd and there was no way to obtain one, so pidfd_open came
# with them. The trap it walks into is that a pidfd is a file here, and poll and
# select call a file readable always - so a live process would look exited. Both
# halves are checked: a running process must not be readable, and a child that
# has exited must be, through poll, select and epoll alike.
cp "$here/pidfdtest" "$root/"; chmod +x "$root/pidfdtest"
out=$("$NABI" -m "$root" /pidfdtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pidfd ok" ]; then
    echo "  ok  pidfdtest -> \"$out\", exit 0"
else
    echo "  FAIL pidfdtest -> \"$out\", exit $rc"
    fail=1
fi

# staletest: a recorded guest mode the host mode contradicts.
#
# NABI writes the mode attribute and the host mode together, and the host mode is
# always `record | 0600`, so a pair that disagrees is one NABI cannot have
# written. A Fedora tree carried records of 0200 against files the host held at
# 0644 - 0200 denies read to everyone, so Python could not import `encodings` and
# every GLib program that touched one died. The two files here are that case and
# its opposite: /etc/shadow's shape, 0000 recorded against a host 0600, which is
# consistent, correct, and must go on being obeyed.
printf 'hello-stale\n' > "$root/stale"; chmod 644 "$root/stale"
xattr -w -x msl.nabi.mode '80 00 00 00' "$root/stale"
printf 'secret\n' > "$root/shadowlike"; chmod 600 "$root/shadowlike"
xattr -w -x msl.nabi.mode '00 00 00 00' "$root/shadowlike"
cp "$here/staletest" "$root/"; chmod +x "$root/staletest"
out=$("$NABI" -m "$root" /staletest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "stale ok" ]; then
    echo "  ok  staletest -> \"$out\", exit 0"
else
    echo "  FAIL staletest -> \"$out\", exit $rc"
    fail=1
fi

# miscsystest: close_range, epoll_pwait2, execveat, fchmodat2, adjtimex and the
# four that answer ENOSYS. Each is checked on what distinguishes it from the call
# it resembles - CLOSE_RANGE_CLOEXEC marks rather than closes so the descriptor
# stays usable, epoll_pwait2's sub-millisecond timeout must not round down to no
# wait, fchmodat2's AT_SYMLINK_NOFOLLOW must land on the link and leave the
# target alone, and adjtimex reads but refuses to write a clock the whole machine
# shares. It ends by exec'ing /miscdone through a descriptor, so the "misc ok"
# below is printed by the program execveat ran.
cp "$here/miscsystest" "$here/miscdone" "$root/"
chmod +x "$root/miscsystest" "$root/miscdone"
out=$("$NABI" -m "$root" /miscsystest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "misc ok" ]; then
    echo "  ok  miscsystest -> \"$out\", exit 0"
else
    echo "  FAIL miscsystest -> \"$out\", exit $rc"
    fail=1
fi

# acc4test: accept4, kcmp and keyctl. The listening socket is put into
# non-blocking mode first, because macOS passes that down to the accepted socket
# and Linux does not - so a plain accept4(..., 0) producing a *blocking*
# descriptor is the thing being checked, not that the flags can be turned on.
# kcmp is checked on the distinction it exists for: a dup compares equal to its
# original and the two ends of one pipe do not, which is the pair that stat
# cannot tell apart, and two opens of one directory are refused rather than
# guessed at.
cp "$here/acc4test" "$root/"; chmod +x "$root/acc4test"
out=$("$NABI" -m "$root" /acc4test); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "acc4 ok" ]; then
    echo "  ok  acc4test -> \"$out\", exit 0"
else
    echo "  FAIL acc4test -> \"$out\", exit $rc"
    fail=1
fi

# captest: cachestat, capget/capset, getcpu and the LSM three. cachestat is
# checked against a *sparse* file, because a file that is entirely cached cannot
# tell an implementation that measures residency from one that just counts the
# range - which is exactly how the first version of this test passed while
# measuring nothing. capget is checked by poisoning the buffer first, since the
# fault it replaces was a capget that returned success and wrote nothing at all.
# getcpu is checked against the affinity mask, which offers one CPU: the host's
# real core number is outside it.
cp "$here/captest" "$root/"; chmod +x "$root/captest"
out=$("$NABI" -m "$root" /captest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "cap ok" ]; then
    echo "  ok  captest -> \"$out\", exit 0"
else
    echo "  FAIL captest -> \"$out\", exit $rc"
    fail=1
fi

# memtest: memfd_create, the mlock family, migrate_pages, membarrier and the six
# that answer ENOSYS. The memfd is checked by round-tripping its contents and by
# writing through a shared mapping and reading it back off the descriptor, so a
# merely-open descriptor cannot pass. mlock is checked on its *failures* - a
# guest cannot observe a successful lock, and the stub this replaces returned 0
# for every address in the machine, including ones that are not mapped.
cp "$here/memtest" "$root/"; chmod +x "$root/memtest"
out=$("$NABI" -m "$root" /memtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "mem ok" ]; then
    echo "  ok  memtest -> \"$out\", exit 0"
else
    echo "  FAIL memtest -> \"$out\", exit $rc"
    fail=1
fi

# sealtest: mseal, mincore, move_pages, the preadv/pwritev family, personality
# and pkey_mprotect. mseal is checked by trying every gate against a sealed page
# - munmap, mprotect, mremap, MAP_FIXED mmap and pkey_mprotect - and by checking
# that the pages either side of it are still ordinary, so neither an
# unenforced seal nor an over-broad one passes. It also forks: a fork here is a
# fork plus an exec, so a seal that is not carried in the checkpoint comes back
# cleared, and the child reports through its exit code.
cp "$here/sealtest" "$root/"; chmod +x "$root/sealtest"
out=$("$NABI" -m "$root" /sealtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "seal ok" ]; then
    echo "  ok  sealtest -> \"$out\", exit 0"
else
    echo "  FAIL sealtest -> \"$out\", exit $rc"
    fail=1
fi

# scmtest: passing a descriptor over a unix socket with SCM_RIGHTS, which is
# what Wayland is built out of - a client sends the compositor a memfd for every
# buffer. Checked by writing through the sent descriptor and reading it back
# through the received one, so a number in a buffer cannot pass for a
# descriptor, and by closing the received one, which only works if nabi
# registered it.
cp "$here/scmtest" "$root/"; chmod +x "$root/scmtest"
out=$("$NABI" -m "$root" /scmtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "scm ok" ]; then
    echo "  ok  scmtest -> \"$out\", exit 0"
else
    echo "  FAIL scmtest -> \"$out\", exit $rc"
    fail=1
fi

# sockcredtest: who a bound unix socket belongs to, and who SO_PEERCRED says a
# peer is. Run with --user, and it refuses to run as root: both answers are
# produced by mapping the host account, which the guest sees as root, so as root
# the wrong answer and the right one are the same number.
cp "$here/sockcredtest" "$root/"; chmod +x "$root/sockcredtest"
chmod 777 "$root"
out=$("$NABI" --user 1000:1000 -m "$root" /sockcredtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "sockcred ok" ]; then
    echo "  ok  sockcredtest -> \"$out\", exit 0"
else
    echo "  FAIL sockcredtest -> \"$out\", exit $rc"
    fail=1
fi

# rtsigtest: real-time signals, and the two prctl options beside them. Darwin's
# signals stop at 31, so there is no host signal to carry one - they were not
# carried at all, and the sender was told they had been. Checks a handler being
# installed, delivery to this process and from another one, that blocking holds
# one, and that the number arrives intact. Queueing is not implemented and not
# checked; see the note in the source.
cp "$here/rtsigtest" "$root/"; chmod +x "$root/rtsigtest"
out=$("$NABI" -m "$root" /rtsigtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "rtsig ok" ]; then
    echo "  ok  rtsigtest -> \"$out\", exit 0"
else
    echo "  FAIL rtsigtest -> \"$out\", exit $rc"
    fail=1
fi

# looptest: loop devices, which is how anything actually mounts an image -
# util-linux's mount sets one up in userspace and never calls mount(2) on a
# regular file at all. Checks the control device, the block-device stat, that a
# bound device *reads as its backing file* (the ext4 magic, which is what a
# filesystem probe looks for), mounting through it, and that unbinding gives
# the number back.
cp "$here/looptest" "$here/tiny.ext4" "$root/"; chmod +x "$root/looptest"
out=$("$NABI" -m "$root" /looptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "loop ok" ]; then
    echo "  ok  looptest -> \"$out\", exit 0"
else
    echo "  FAIL looptest -> \"$out\", exit $rc"
    fail=1
fi

# imagemounttest: mount(2) on a filesystem image, which the host is asked to
# perform - nabi has no block layer to do it with. tiny.ext4 beside it is 1MiB
# of ext4 with two known files in it. Checks that the files are readable through
# the guest's mountpoint (a mount returning 0 over an empty directory is the
# likely failure), that a writable mount is refused rather than downgraded, and
# that a file which is not an image is refused before anything is attached.
cp "$here/imagemounttest" "$here/tiny.ext4" "$root/"
chmod +x "$root/imagemounttest"
out=$("$NABI" -m "$root" /imagemounttest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "imagemount ok" ]; then
    echo "  ok  imagemounttest -> \"$out\", exit 0"
else
    echo "  FAIL imagemounttest -> \"$out\", exit $rc"
    fail=1
fi

# waitidtest: waitid, and WNOWAIT in particular - reporting a child without
# consuming it, which wait4 cannot express and lxc-start relies on. An
# implementation that quietly reaped would return the same siginfo and differ
# only in what happens next, so the check is that the child is still reapable.
cp "$here/waitidtest" "$root/"; chmod +x "$root/waitidtest"
out=$("$NABI" -m "$root" /waitidtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "waitid ok" ]; then
    echo "  ok  waitidtest -> \"$out\", exit 0"
else
    echo "  FAIL waitidtest -> \"$out\", exit $rc"
    fail=1
fi

# renametest: renameat2's flags. NOREPLACE must refuse and leave both names
# alone; EXCHANGE must swap both ways at once - checked on the file contents,
# because a NOREPLACE that quietly replaced and an EXCHANGE that renamed one way
# both return 0 and are what the flags exist to prevent.
cp "$here/renametest" "$root/"; chmod +x "$root/renametest"
out=$("$NABI" -m "$root" /renametest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "rename ok" ]; then
    echo "  ok  renametest -> \"$out\", exit 0"
else
    echo "  FAIL renametest -> \"$out\", exit $rc"
    fail=1
fi

# pdeathtest: PR_SET_PDEATHSIG, and the signal actually arriving. Darwin has no
# parent-death signal, so nabi watches for one with kqueue. Checked on a
# grandchild that asks to be killed when its parent goes and is orphaned: a
# prctl that stored the number and delivered nothing would round-trip perfectly
# and leave the process running, which is what LXC uses it to prevent.
cp "$here/pdeathtest" "$root/"; chmod +x "$root/pdeathtest"
out=$("$NABI" -m "$root" /pdeathtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pdeath ok" ]; then
    echo "  ok  pdeathtest -> \"$out\", exit 0"
else
    echo "  FAIL pdeathtest -> \"$out\", exit $rc"
    fail=1
fi

# clonenstest: clone with a namespace flag, which had never worked - the
# namespaces were created and then do_clone refused the flags that asked for
# them. Checks the clone succeeds, the child is in its own uts namespace, and
# the *parent* is put back: the namespace is made in the parent because a child
# here is rebuilt from a checkpoint, so a clone that forgot to restore would
# leave the parent somewhere it never asked to be.
cp "$here/clonenstest" "$root/"; chmod +x "$root/clonenstest"
out=$("$NABI" -m "$root" /clonenstest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "clonens ok" ]; then
    echo "  ok  clonenstest -> \"$out\", exit 0"
else
    echo "  FAIL clonenstest -> \"$out\", exit $rc"
    fail=1
fi

# abstracttest: the abstract unix socket namespace, which Darwin does not have
# and which was not translated at all - the leading NUL was kept and the host
# was asked to create a file with an empty name. Checks bind, connect and data,
# that the name is unique and released on close, that an unbound name refuses
# with ECONNREFUSED rather than ENOENT (which is what lxc-info reads to decide
# a container is stopped), and that it has no filesystem entry.
cp "$here/abstracttest" "$root/"; chmod +x "$root/abstracttest"
out=$("$NABI" -m "$root" /abstracttest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "abstract ok" ]; then
    echo "  ok  abstracttest -> \"$out\", exit 0"
else
    echo "  FAIL abstracttest -> \"$out\", exit $rc"
    fail=1
fi

# seqpackettest: AF_UNIX SOCK_SEQPACKET, which Darwin has no such thing as and
# answers EPROTONOSUPPORT for - so Android's second-stage init died making its
# channel to property_service. Built out of a connected datagram pair instead.
# Checks the pair is created, that message boundaries survive, that an oversize
# message truncates rather than leaving a remainder, and that a peer that goes
# away reads as end-of-file and keeps reading that way.
cp "$here/seqpackettest" "$root/"; chmod +x "$root/seqpackettest"
out=$("$NABI" -m "$root" /seqpackettest 2>&1 | tail -1); rc=$?
if [ "$out" = "seqpackettest: ok" ]; then
    echo "  ok  seqpackettest -> \"$out\""
else
    echo "  FAIL seqpackettest -> \"$out\", exit $rc"
    fail=1
fi

# opathsocktest: O_PATH on a socket, which Darwin will not open by any flag -
# so nabi invents the descriptor and answers from the name. Android's init
# reopens its bound property_service socket this way to set the mode. Checks
# the open, fchmod and fstat through it, that it names the socket itself, that
# a read is EBADF, and that O_PATH on an ordinary file is unaffected.
cp "$here/opathsocktest" "$root/"; chmod +x "$root/opathsocktest"
out=$("$NABI" -m "$root" /opathsocktest 2>&1 | tail -1); rc=$?
if [ "$out" = "opathsock ok" ]; then
    echo "  ok  opathsocktest -> \"$out\""
else
    echo "  FAIL opathsocktest -> \"$out\", exit $rc"
    fail=1
fi

# sigchldfdtest: a signalfd for a signal the guest never handles, which is the
# ordinary use of signalfd and the one nabi did not cover - the arrival was
# only ever recorded for signals that had a guest handler, so the descriptor
# stayed unreadable, and the wait that would have seen it returned EINTR.
# Android's init blocks SIGCHLD, handles it nowhere, and learns of a service
# exiting from a signalfd inside epoll. Checks both waits and both sources.
cp "$here/sigchldfdtest" "$root/"; chmod +x "$root/sigchldfdtest"
out=$("$NABI" -m "$root" /sigchldfdtest 2>&1 | tail -1); rc=$?
if [ "$out" = "sigchldfd ok" ]; then
    echo "  ok  sigchldfdtest -> \"$out\""
else
    echo "  FAIL sigchldfdtest -> \"$out\", exit $rc"
    fail=1
fi

# reboottest: reboot(2), which has no firmware to hand control back to, so the
# halting commands end the guest instead. Checks the magic numbers that are the
# whole of what stops a stray call from stopping the machine, that CAD_ON/OFF
# succeed, and that kexec and software suspend are ENOSYS rather than EPERM.
cp "$here/reboottest" "$root/"; chmod +x "$root/reboottest"
out=$("$NABI" -m "$root" /reboottest 2>&1 | tail -1); rc=$?
if [ "$out" = "reboot ok" ]; then
    echo "  ok  reboottest -> \"$out\""
else
    echo "  FAIL reboottest -> \"$out\", exit $rc"
    fail=1
fi

# rebootoff: the half reboottest cannot check, since a test that verified it
# would have nothing left to report with. It calls reboot(POWER_OFF) and prints
# "not reached" afterwards, so an empty output and exit 0 is the guest having
# stopped where it was told to.
cp "$here/rebootoff" "$root/"; chmod +x "$root/rebootoff"
out=$("$NABI" -m "$root" /rebootoff 2>&1); rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
    echo "  ok  rebootoff -> ended the guest, exit 0"
else
    echo "  FAIL rebootoff -> \"$out\", exit $rc"
    fail=1
fi

# mntkeytest: a mount table belongs to one image, not to one boot. The initial
# mount namespace has the same inode number in every guest, so two guests of
# different images shared a table - mounting a tmpfs on /dev for an Android
# image put it, and everything else Android mounted, into an unrelated Fedora
# guest whose login shell then could not write /dev/null. Both halves are
# checked: a second run of the same image must see the first one's mount, and a
# different image must see nothing.
cp "$here/mntkeytest" "$root/"; chmod +x "$root/mntkeytest"
root2=$(mktemp -d)
cp "$here/mntkeytest" "$root2/"; chmod +x "$root2/mntkeytest"
a1=$("$NABI" -m "$root" /mntkeytest 2>&1 | head -1)
a2=$("$NABI" -m "$root" /mntkeytest 2>&1 | head -1)
b1=$("$NABI" -m "$root2" /mntkeytest 2>&1 | head -1)
rm -rf "$root2"
if [ "$a1" = "mntkey: /mnt absent" ] && [ "$a2" = "mntkey: /mnt present" ] &&
   [ "$b1" = "mntkey: /mnt absent" ]; then
    echo "  ok  mntkeytest -> same image shares, different image does not"
else
    echo "  FAIL mntkeytest -> first=\"$a1\" second=\"$a2\" other-image=\"$b1\""
    fail=1
fi

# splitblocktest: unmapping part of a stage-2 block. Guest mappings are 4KiB
# and the blocks under them are 16KiB, so a guest unmapping one page splits a
# block: the survivors must keep working and the hole must fault, and the block
# must not be released until the last page in it has gone. Checks the survivors
# keep their contents and stay writable, that the unmapped page faults, and
# that the space is reusable and reads back as zero afterwards.
cp "$here/splitblocktest" "$root/"; chmod +x "$root/splitblocktest"
out=$("$NABI" -m "$root" /splitblocktest 2>&1 | tail -1); rc=$?
if [ "$out" = "splitblock ok" ]; then
    echo "  ok  splitblocktest -> \"$out\""
else
    echo "  FAIL splitblocktest -> \"$out\", exit $rc"
    fail=1
fi

# procchmodtest: chmod on a passed-through /proc, which the host module serving
# it refuses - and Android's first-stage init treats a failed chmod of
# /proc/cmdline as fatal. Checks that it succeeds by path and by dirfd, that a
# missing file is still ENOENT, and that chmod of an ordinary file still takes.
cp "$here/procchmodtest" "$root/"; chmod +x "$root/procchmodtest"
out=$("$NABI" -m "$root" /procchmodtest 2>&1 | tail -1); rc=$?
if [ "$out" = "procchmod ok" ]; then
    echo "  ok  procchmodtest -> \"$out\""
else
    echo "  FAIL procchmodtest -> \"$out\", exit $rc"
    fail=1
fi

# netlinktest: AF_NETLINK, which nabi had no address family for at all - so
# `ip` and glibc's getifaddrs both stopped at socket(). Checks the socket, its
# own sockaddr_nl name, the MSG_PEEK|MSG_TRUNC sizing every netlink reader
# does, a link dump that actually names interfaces, and that creating a link is
# refused as an NLMSG_ERROR rather than by a broken socket.
cp "$here/netlinktest" "$root/"; chmod +x "$root/netlinktest"
out=$("$NABI" -m "$root" /netlinktest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "netlink ok" ]; then
    echo "  ok  netlinktest -> \"$out\", exit 0"
else
    echo "  FAIL netlinktest -> \"$out\", exit $rc"
    fail=1
fi

# privdroptest: prctl's shape, PR_SET_KEEPCAPS, and dropping capabilities
# without holding any - the sequence libcap performs for a daemon giving up
# privilege. Under --user: captest covers the same calls as root, and the point
# here is what a process that is *not* root may do.
cp "$here/privdroptest" "$root/"; chmod +x "$root/privdroptest"
out=$("$NABI" --user 1000:1000 -m "$root" /privdroptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "privdrop ok" ]; then
    echo "  ok  privdroptest -> \"$out\", exit 0"
else
    echo "  FAIL privdroptest -> \"$out\", exit $rc"
    fail=1
fi

# clearsigtest: CLONE_CLEAR_SIGHAND, which glibc's posix_spawn asks for because
# the child shares the parent's address space until the exec and an inherited
# handler would run there. Checked on the child seeing SIG_DFL where the parent
# installed a handler, on a SIG_IGN disposition surviving as Linux leaves it,
# and on the parent's own table being unchanged.
cp "$here/clearsigtest" "$root/"; chmod +x "$root/clearsigtest"
out=$("$NABI" -m "$root" /clearsigtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "clearsig ok" ]; then
    echo "  ok  clearsigtest -> \"$out\", exit 0"
else
    echo "  FAIL clearsigtest -> \"$out\", exit $rc"
    fail=1
fi

# seccomptest: seccomp, the setre*/setfs* credential calls and set_mempolicy.
# seccomp is checked on syscalls actually being stopped, on a later filter being
# unable to loosen an earlier one, and on the chain surviving a fork - which on
# arm64 means surviving the checkpoint, the one failure of the feature that
# nothing inside the guest could detect.
cp "$here/seccomptest" "$root/"; chmod +x "$root/seccomptest"
out=$("$NABI" -m "$root" /seccomptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "seccomp ok" ]; then
    echo "  ok  seccomptest -> \"$out\", exit 0"
else
    echo "  FAIL seccomptest -> \"$out\", exit $rc"
    fail=1
fi

# pivottest: chroot and pivot_root. The check that matters is that the old root
# is still reachable at put_old afterwards - a pivot that swapped the root and
# left put_old an empty directory would pass everything else and lose the
# filesystem the guest came from, with the failure surfacing later at the
# unmount. It also asks the ".." question through a descriptor the guest opened
# itself, before and after the root changes, which is the only path that
# consults nabi's root-identity cache: a stale one lets a handle on "/" climb
# out of the root the guest was just confined to.
cp "$here/pivottest" "$root/"; chmod +x "$root/pivottest"
out=$("$NABI" -m "$root" /pivottest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pivot ok" ]; then
    echo "  ok  pivottest -> \"$out\", exit 0"
else
    echo "  FAIL pivottest -> \"$out\", exit $rc"
    fail=1
fi

# binderprobe: the binder ioctl passthrough, spoken in a guest against a live
# mSL/DevFS load. The guest opens /dev/binder through a symlink to the host's
# node (a real device node needs root to mknod, and the guest root is a plain
# directory); the numbers and argument pointers then travel through nabi to
# the driver exactly as on the host. The epoll stage of the same binary is
# where the read filter needs its NOTE_LOWAT of one. Skips (77) when the
# driver is not loaded.
if [ -e /dev/binder ]; then
    mkdir -p "$root/dev"
    ln -s /dev/binder "$root/dev/binder"
    cp "$here/binderprobe" "$root/"; chmod +x "$root/binderprobe"
    out=$("$NABI" -m "$root" /binderprobe); rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "binderprobe ok" ]; then
        echo "  ok  binderprobe -> \"$out\", exit 0"
    elif [ "$rc" -eq 77 ]; then
        echo "  ok  binderprobe -> skipped (no /dev/binder in the guest)"
    else
        echo "  FAIL binderprobe -> \"$out\", exit $rc"
        fail=1
    fi
else
    echo "  ok  binderprobe -> skipped (no /dev/binder on the host)"
fi

# signalfdtest: signalfd4 - the record it answers a read with, that the read
# consumes the signal (blocked in the guest and handled, it must neither stay
# pending nor reach a handler), and that the descriptor polls readable only
# while a wanted signal is pending. The socketpair byte is the last half, since
# signalfd exists for event loops and one that only worked through read() would
# be useless there.
cp "$here/signalfdtest" "$root/"; chmod +x "$root/signalfdtest"
out=$("$NABI" -m "$root" /signalfdtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "signalfd ok" ]; then
    echo "  ok  signalfdtest -> \"$out\", exit 0"
else
    echo "  FAIL signalfdtest -> \"$out\", exit $rc"
    fail=1
fi

# tagtest: AArch64 pointer tags. The top byte of a user pointer is not part of
# the address - TCR_EL1.TBI0 tells the MMU, and nabi's own guest_to_host has to
# be told separately, because a syscall argument is resolved in software and
# never reaches the MMU. Android tags every heap pointer, so both halves are
# load-bearing there; each is checked on its own, since either alone looks like
# it works until the other is needed.
cp "$here/tagtest" "$root/"; chmod +x "$root/tagtest"
out=$("$NABI" -m "$root" /tagtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "tagged-write-ok
tag ok" ]; then
    echo "  ok  tagtest -> \"tag ok\", exit 0"
else
    echo "  FAIL tagtest -> \"$out\", exit $rc"
    fail=1
fi

# xattrdevtest: extended attributes on a filesystem that has none. macOS devfs
# answers EPERM for listxattr on every device node; Linux devtmpfs answers with
# an empty list, so passing the EPERM through made `ls -l /dev/binder` print
# "Operation not permitted" about a node it then listed correctly. Checked in
# both directions - a device node lists empty, and a path that does not exist is
# still ENOENT rather than being swallowed into "no such attribute".
cp "$here/xattrdevtest" "$root/"; chmod +x "$root/xattrdevtest"
out=$("$NABI" -m "$root" /xattrdevtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "xattrdev ok" ]; then
    echo "  ok  xattrdevtest -> \"$out\", exit 0"
else
    echo "  FAIL xattrdevtest -> \"$out\", exit $rc"
    fail=1
fi

# binderpolltest: registering a binder descriptor with epoll. macOS refuses a
# plain EVFILT_READ knote on a third-party character device and accepts only the
# NOTE_LOWAT form, which is also the predicate the driver's selwakeup fires - so
# readiness is exact and a looper neither spins nor sleeps through a pending
# transaction. Android's looper is built on epoll, so getting this wrong reads
# as "binder is broken" from inside the guest. Skips cleanly when the kext is
# not loaded; the pipe checks either side tell a device-specific failure apart
# from epoll being broken outright.
cp "$here/binderpolltest" "$root/"; chmod +x "$root/binderpolltest"
out=$("$NABI" -m "$root" /binderpolltest); rc=$?
if [ "$rc" -eq 0 ] && { [ "$out" = "binderpoll ok" ] || [ "$out" = "binderpoll skipped (no /dev/binder)" ]; }; then
    echo "  ok  binderpolltest -> \"$out\", exit 0"
else
    echo "  FAIL binderpolltest -> \"$out\", exit $rc"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "smoke: PASS"
else
    echo "smoke: FAIL"
fi
exit $fail
