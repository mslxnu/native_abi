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

# forkmemtest: what a fork owes a child, and what it owes a grandchild.
# fork here is fork-plus-exec - the parent flushes guest memory to a file the
# child maps privately - so "the child sees the parent's memory" is arranged
# rather than automatic. The check that matters is the second generation and the
# kernel's view: a resumed process maps the arena a piece at a time, two regions
# can be 4KiB slices of one 16KiB block, and mapping that block twice gives two
# copy-on-write copies of it. Both start identical, so nothing shows until
# something writes - after which the guest reaches one copy through stage 2 and
# NABI reaches the other through the region, and neither sees the other's
# stores. A shell hits it constantly: `x=$(y=$(cmd))` died in glibc's allocator
# with "malloc_consolidate(): unaligned fastbin chunk detected", in a process
# that had done nothing but be forked.
cp "$here/forkmemtest" "$root/"; chmod +x "$root/forkmemtest"
out=$("$NABI" -m "$root" /forkmemtest 2>&1 | tail -1); rc=$?
if [ "$out" = "forkmem ok" ]; then
    echo "  ok  forkmemtest -> \"$out\""
else
    echo "  FAIL forkmemtest -> \"$out\""
    fail=1
fi

# pagesztest: AT_PAGESZ has to be the granule the guest's own mappings use, not
# the stage-2 block size. A guest computes with the number it is given: glibc
# serves anything past its mmap threshold with a mapping of its own and, freeing
# one, checks that the address and the length are page-aligned by that number.
# Told 16KiB while mmap handed out 4KiB-aligned addresses, every large free
# aborted with "munmap_chunk(): invalid pointer" - a heap corruption message for
# an arithmetic disagreement - and `apt install` and `dnf install` both died.
# The check is that mmap's addresses are aligned to what the auxv advertised,
# over several awkward sizes, since a mapping that lands on a coarser boundary
# by luck proves nothing.
cp "$here/pagesztest" "$root/"; chmod +x "$root/pagesztest"
out=$("$NABI" -m "$root" /pagesztest 2>&1); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "pagesz ok" ]; then
    echo "  ok  pagesztest -> \"$out\", exit 0"
else
    echo "  FAIL pagesztest -> \"$out\", exit $rc"
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

# nofollowtest: O_NOFOLLOW is about the file, not the path to it. nabi refused
# every symlink in a name rather than only the last component, so a path that
# plainly exists returned ENOENT - but only for callers passing the flag, which
# is why nothing else noticed. Android ships /etc as a symlink and
# libprocessgroup opens /etc/cgroups.json with O_NOFOLLOW|O_CLOEXEC.
nfroot=$(mktemp -d)
mkdir -p "$nfroot/dir"; echo hi > "$nfroot/dir/file"
ln -s /dir "$nfroot/link_to_dir"; ln -s /dir/file "$nfroot/link_to_file"
cp "$here/nofollowtest" "$nfroot/"; chmod +x "$nfroot/nofollowtest"
out=$("$NABI" -m "$nfroot" /nofollowtest 2>&1 | tail -1); rc=$?
rm -rf "$nfroot"
if [ "$out" = "nofollow ok" ]; then
    echo "  ok  nofollowtest -> \"$out\""
else
    echo "  FAIL nofollowtest -> \"$out\", exit $rc"
    fail=1
fi

# shmapdtest: a read-only descriptor on a writable file still maps MAP_SHARED.
# A descriptor that cannot write is not a file that cannot be written, and
# Android's property area is a 0644 file that init writes while every other
# process opens it O_RDONLY and maps it shared - so a private copy froze every
# property at the moment it was mapped. Checks visibility through another
# descriptor and across a fork, and that a genuinely read-only file still maps.
cp "$here/shmapdtest" "$root/"; chmod +x "$root/shmapdtest"
out=$("$NABI" -m "$root" /shmapdtest 2>&1 | tail -1); rc=$?
if [ "$out" = "shmapd ok" ]; then
    echo "  ok  shmapdtest -> \"$out\""
else
    echo "  FAIL shmapdtest -> \"$out\", exit $rc"
    fail=1
fi

# binderprobe, against nabi's own binder rather than the kext's. The same
# conformance probe is the oracle for both, which is the point of having the
# emulation selectable: NABI_BINDER=emulated forces it even where /dev/binder
# exists, so the emulation is held to what the driver does rather than to a
# description of it. Held to the whole probe now, not to how far it gets:
# version, arena, manager, oneway, epoll, cross-process delivery, descriptor
# transfer, scatter-gather with a file-descriptor array, and the
# security-context form of a transaction.
cp "$here/binderprobe" "$root/"; chmod +x "$root/binderprobe"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderprobe 2>&1)
rc=$?
last=$(printf '%s\n' "$out" | tail -1)
if [ "$rc" -eq 0 ] && [ "$last" = "binderprobe ok" ]; then
    echo "  ok  binderprobe (emulated) -> \"$last\", exit 0"
else
    echo "  FAIL binderprobe (emulated) -> \"$last\", exit $rc"
    printf '%s\n' "$out" | tail -3 | sed 's/^/       /'
    fail=1
fi

# sockpathtest: a unix socket reports the name the guest bound, not the host
# path bind translated it into. bionic's android_get_control_socket compares the
# two, so every Android service that takes a socket from init depends on it.
cp "$here/sockpathtest" "$root/"; chmod +x "$root/sockpathtest"
out=$("$NABI" -m "$root" /sockpathtest 2>&1 | tail -1); rc=$?
if [ "$out" = "sockpath ok" ]; then
    echo "  ok  sockpathtest -> \"$out\""
else
    echo "  FAIL sockpathtest -> \"$out\", exit $rc"
    fail=1
fi

# execfmttest: execve of a file nothing here can run must be an error the caller
# survives, not a segmentation fault. The format is checked before the address
# space is torn down, which is where Linux puts the point of no return.
cp "$here/execfmttest" "$root/"; chmod +x "$root/execfmttest"
out=$("$NABI" -m "$root" /execfmttest 2>&1 | tail -1); rc=$?
if [ "$out" = "execfmt ok" ]; then
    echo "  ok  execfmttest -> \"$out\""
else
    echo "  FAIL execfmttest -> \"$out\", exit $rc"
    fail=1
fi

# exelinktest: /proc/self/exe, which names the guest's program and not nabi.
# Both halves - readlink, and a stat that follows - because they are served by
# different code and only one of them used to work.
cp "$here/exelinktest" "$root/"; chmod +x "$root/exelinktest"
out=$("$NABI" -m "$root" /exelinktest 2>&1 | tail -1); rc=$?
if [ "$out" = "exelink ok" ]; then
    echo "  ok  exelinktest -> \"$out\""
else
    echo "  FAIL exelinktest -> \"$out\", exit $rc"
    fail=1
fi

# cgmovetest: putting another process in a cgroup, which is what a process
# manager does with cgroup.procs and what nabi used to refuse.
cp "$here/cgmovetest" "$root/"; chmod +x "$root/cgmovetest"
out=$("$NABI" -m "$root" /cgmovetest 2>&1 | tail -1); rc=$?
if [ "$out" = "cgmove ok" ]; then
    echo "  ok  cgmovetest -> \"$out\""
else
    echo "  FAIL cgmovetest -> \"$out\", exit $rc"
    fail=1
fi

# sigchldfd2test: a signalfd for a signal the guest also has a handler for,
# which is Android init's shape and not the one sigchldfdtest covers. Two of
# nabi's decisions lean on each other here - signalfd_arm bows out when the
# guest has its own handler, and rt_sigprocmask leaves a handled signal
# unblocked on the host - and each is only right while the other holds.
cp "$here/sigchldfd2test" "$root/"; chmod +x "$root/sigchldfd2test"
out=$("$NABI" -m "$root" /sigchldfd2test 2>&1 | tail -1); rc=$?
if [ "$out" = "sigchldfd2 ok" ]; then
    echo "  ok  sigchldfd2test -> \"$out\""
else
    echo "  FAIL sigchldfd2test -> \"$out\", exit $rc"
    fail=1
fi

# pid1test: --pid1, which starts the guest as pid 1 of a pid namespace of its
# own. Run both ways, because the option has to do something and has to be the
# only thing that does it: without it the guest keeps an ordinary pid, and a
# default that quietly made everything init would be worse than not having it.
cp "$here/pid1test" "$root/"; chmod +x "$root/pid1test"
out=$("$NABI" -m "$root" /pid1test 2>&1 | tail -1)
one=$("$NABI" --pid1 -m "$root" /pid1test 2>&1 | tail -1)
case "$out" in
    "pid1 ok self=1 "*) echo "  FAIL pid1test -> pid 1 without --pid1: \"$out\""; fail=1 ;;
    "pid1 ok self="*)   ok_plain=1 ;;
    *)                  echo "  FAIL pid1test -> \"$out\""; fail=1 ;;
esac
if [ "$one" = "pid1 ok self=1 ppid=0" ] && [ "${ok_plain:-0}" = 1 ]; then
    echo "  ok  pid1test -> an ordinary pid by default, \"$one\" with --pid1"
elif [ "${ok_plain:-0}" = 1 ]; then
    echo "  FAIL pid1test --pid1 -> \"$one\""
    fail=1
fi

# sysfscgtest: /sys/fs/cgroup is there without anything having mounted it, as
# it is on Linux. libprocessgroup gives up before it tries to mount when the
# directory cannot be made, and /sys is read-only whichever side it comes from.
cp "$here/sysfscgtest" "$root/"; chmod +x "$root/sysfscgtest"
out=$("$NABI" -m "$root" /sysfscgtest 2>&1 | tail -1); rc=$?
if [ "$out" = "sysfscg ok" ]; then
    echo "  ok  sysfscgtest -> \"$out\""
else
    echo "  FAIL sysfscgtest -> \"$out\", exit $rc"
    fail=1
fi

# seqcredtest: the AF_UNIX features Android asks for that Darwin has not got -
# a SOCK_SEQPACKET socket that can be listened on, and SO_PASSCRED actually
# delivering SCM_CREDENTIALS. init needs the first for lmkd's socket and the
# second to create it at all.
cp "$here/seqcredtest" "$root/"; chmod +x "$root/seqcredtest"
out=$("$NABI" -m "$root" /seqcredtest 2>&1 | tail -1); rc=$?
if [ "$out" = "seqcred ok" ]; then
    echo "  ok  seqcredtest -> \"$out\""
else
    echo "  FAIL seqcredtest -> \"$out\", exit $rc"
    fail=1
fi

# nicetest: setpriority answered with the guest's credentials. Raising a
# priority needs CAP_SYS_NICE, which the guest may hold while the account nabi
# runs as does not - and init sets the zygote's priority before exec'ing it and
# treats the refusal as fatal.
cp "$here/nicetest" "$root/"; chmod +x "$root/nicetest"
out=$("$NABI" -m "$root" /nicetest 2>&1 | tail -1); rc=$?
if [ "$out" = "nice ok" ]; then
    echo "  ok  nicetest -> \"$out\""
else
    echo "  FAIL nicetest -> \"$out\", exit $rc"
    fail=1
fi

# capambtest: the ambient capability set, and that an execve carries it. It is
# the only way to hand capabilities to a program that is not setuid and has
# none of its own, and Android's init uses nothing else. Needs its helper,
# which reports what arrived on the far side of the exec.
cp "$here/capambtest" "$here/capambhelper" "$root/"
chmod +x "$root/capambtest" "$root/capambhelper"
out=$("$NABI" -m "$root" /capambtest 2>&1 | tail -1); rc=$?
if [ "$out" = "capamb ok" ]; then
    echo "  ok  capambtest -> \"$out\""
else
    echo "  FAIL capambtest -> \"$out\", exit $rc"
    fail=1
fi

# capuidtest: what a change of user does to the capabilities - the securebits,
# the bounding set, and whether a permitted set survives becoming another user.
# Android's init sets the bits, changes user, and only then installs the
# capabilities a service is to run with.
cp "$here/capuidtest" "$root/"; chmod +x "$root/capuidtest"
out=$("$NABI" -m "$root" /capuidtest 2>&1 | tail -1); rc=$?
if [ "$out" = "capuid ok" ]; then
    echo "  ok  capuidtest -> \"$out\""
else
    echo "  FAIL capuidtest -> \"$out\", exit $rc"
    fail=1
fi

# binderarenatest: the receiver's arena is reusable. It was a bump allocator
# whose mark never came down, so an endpoint stopped receiving for good after
# its arena's worth of traffic - an intermittent failure by construction, since
# whether a call gets through depends on what went before it.
cp "$here/binderarenatest" "$root/"; chmod +x "$root/binderarenatest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderarenatest 2>&1 | tail -1); rc=$?
if [ "$out" = "binderarena ok" ]; then
    echo "  ok  binderarenatest -> \"$out\""
else
    echo "  FAIL binderarenatest -> \"$out\", exit $rc"
    fail=1
fi

# binderbusytest: a sender waits for a receiver that is behind rather than
# being refused. Linux's queue is a list bounded by the receiver's buffer; this
# one has a count, and reaching it used to fail the transaction outright -
# which Android's boot did about a hundred times, taking vold's registration
# with it in roughly one run in four.
cp "$here/binderbusytest" "$root/"; chmod +x "$root/binderbusytest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderbusytest 2>&1 | tail -1); rc=$?
if [ "$out" = "binderbusy ok" ]; then
    echo "  ok  binderbusytest -> \"$out\""
else
    echo "  FAIL binderbusytest -> \"$out\", exit $rc"
    fail=1
fi

# binderhandletest: an object passed by reference, and called through it. The
# emulated driver knew one handle - zero, the context manager - which is enough
# to reach servicemanager and nothing else, while Android is built the other way
# round: a service registers *with* the manager, is handed out to whoever asks,
# and every call after that goes to a handle the driver invented. So a client
# could look a service up, be given a reference, and transact into nothing -
# `vdc checkpoint markBootAttempt` found vold, called it, and waited until init
# gave up on post-fs, which is why post-fs-data never ran. Checked: an object
# its owner sends arrives as a handle rather than as a pointer into another
# address space, that handle reaches the process owning the object, and the
# same handle sent back to its owner becomes the owner's pointer again.
cp "$here/binderhandletest" "$root/"; chmod +x "$root/binderhandletest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderhandletest 2>&1 | tail -1)
if [ "$out" = "binderhandle ok" ]; then
    echo "  ok  binderhandletest -> \"$out\""
else
    echo "  FAIL binderhandletest -> \"$out\""
    fail=1
fi

# binderreplytest: a reply that crosses a process boundary. BC_REPLY names no
# target - the driver is expected to know which call the replying thread is
# inside - so without a record of that, a process could only answer itself and
# every real call hung. Android's boot is made of these.
cp "$here/binderreplytest" "$root/"; chmod +x "$root/binderreplytest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderreplytest 2>&1 | tail -1); rc=$?
if [ "$out" = "binderreply ok" ]; then
    echo "  ok  binderreplytest -> \"$out\""
else
    echo "  FAIL binderreplytest -> \"$out\", exit $rc"
    fail=1
fi

# bindersibtest: two sibling processes must find the same binder registry when
# their parent never opened the device. A fork hides this - the parent has
# already named the registry - which is why binderprobe's twoproc stage never
# caught it, and why every Android service ended up in a registry of its own.
cp "$here/bindersibtest" "$root/"; chmod +x "$root/bindersibtest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /bindersibtest 2>&1 | tail -1); rc=$?
if [ "$out" = "bindersib ok" ]; then
    echo "  ok  bindersibtest -> \"$out\""
else
    echo "  FAIL bindersibtest -> \"$out\", exit $rc"
    fail=1
fi

# bindermmaptest: mmap of the binder device, which is how a real client asks for
# its arena - and what every process in Android does. Emulated only: the kext's
# driver answers mmap with ENODEV, so the shared probe cannot ask for it.
cp "$here/bindermmaptest" "$root/"; chmod +x "$root/bindermmaptest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /bindermmaptest 2>&1 | tail -1); rc=$?
if [ "$out" = "bindermmap ok" ]; then
    echo "  ok  bindermmaptest -> \"$out\""
else
    echo "  FAIL bindermmaptest -> \"$out\", exit $rc"
    fail=1
fi

# binderfstest: the filesystem that makes binders, served by nabi rather than by
# the kext. Forced to the emulation, because that is the side that has to work
# without one - and because the two do not answer alike: the kext's binderfs is
# the host's, whose control node is root-only, so the same test against it
# would be measuring the host's permissions.
cp "$here/binderfstest" "$root/"; chmod +x "$root/binderfstest"
out=$(NABI_BINDER=emulated "$NABI" -m "$root" /binderfstest 2>&1); rc=$?
last=$(printf '%s\n' "$out" | tail -1)
if [ "$rc" -eq 0 ] && [ "$last" = "binderfs ok" ]; then
    echo "  ok  binderfstest -> \"$last\""
else
    echo "  FAIL binderfstest -> \"$last\", exit $rc"
    printf '%s\n' "$out" | grep FAIL | head -4 | sed 's/^/       /'
    fail=1
fi

# kmsgtest: /dev/kmsg, served by nabi because there is no kernel here to keep a
# log. It was mapped onto /dev/null, so a guest's own account of its boot was
# destroyed as it was written - Android's init says everything it has to say
# there and nowhere else. Checks the record format Linux gives readers, one
# read per record, EAGAIN at the end rather than EOF, EINVAL for a record that
# will not fit, and that what one process writes another can read.
cp "$here/kmsgtest" "$root/"; chmod +x "$root/kmsgtest"
out=$("$NABI" -m "$root" /kmsgtest 2>&1 | tail -1); rc=$?
if [ "$out" = "kmsg ok" ]; then
    echo "  ok  kmsgtest -> \"$out\""
else
    echo "  FAIL kmsgtest -> \"$out\", exit $rc"
    fail=1
fi

# devnodetest: the devices nabi answers for once the guest owns /dev. A node
# made with mknod is a placeholder, and Linux names devices two ways: by number
# for the ones whose major/minor it fixes, and by name for the ones it assigns
# dynamically. Binder is the second kind, so it answered ENXIO the moment a
# guest mounted its own /dev - which Android always does - while /dev/null went
# on working. Also checks that a name is a device only inside /dev.
cp "$here/devnodetest" "$root/"; chmod +x "$root/devnodetest"
out=$("$NABI" -m "$root" /devnodetest 2>&1)
rc=$?
binder=$(printf '%s\n' "$out" | sed -n 's/^binder-open=//p')
last=$(printf '%s\n' "$out" | tail -1)
# Whether this host provides binder at all depends on mSL/DevFS being loaded,
# so the strict check is made only where the device exists to be reached.
if [ -e /dev/binder ]; then want_binder=1; else want_binder=-6; fi
if [ "$last" = "devnode ok" ] && [ "$binder" = "$want_binder" ]; then
    echo "  ok  devnodetest -> \"$last\", binder=$binder"
else
    echo "  FAIL devnodetest -> \"$last\", binder=$binder (wanted $want_binder), exit $rc"
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

# sigqtest: rt_sigqueueinfo and rt_sigtimedwait. rt_sigqueueinfo sends a
# real-time signal with a siginfo payload; the si_code must be validated (only
# SI_QUEUE and friends are legal, not SI_USER, SI_KERNEL, SI_TKILL or
# positive). rt_sigtimedwait suspends until one of a chosen set of signals is
# pending or a timeout expires: it must return -EAGAIN on timeout, return the
# signal number when one arrives, fill the uinfo with signo and SI_USER, and
# refuse a wrong sigsetsize. The real-time signals have no Darwin counterpart,
# so the whole path runs through nabi's own infrastructure.
cp "$here/sigqtest" "$root/"; chmod +x "$root/sigqtest"
out=$("$NABI" -m "$root" /sigqtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "sigq ok" ]; then
    echo "  ok  sigqtest -> \"$out\", exit 0"
else
    echo "  FAIL sigqtest -> \"$out\", exit $rc"
    fail=1
fi

# sattrtest: sched_setattr and sched_getattr — the modern scheduling interface
# that replaces sched_setscheduler/sched_setparam and adds SCHED_DEADLINE.
# Checks: the size field versions the struct (too small is EINVAL, too large is
# accepted), normal policies succeed silently, real-time policies are refused
# with EPERM, DEADLINE is refused with EINVAL, priority range is checked before
# privilege, SCHED_FLAG_RESET_ON_FORK is accepted, and getattr always reports
# SCHED_OTHER with priority 0 — consistent with every other scheduler call.
cp "$here/sattrtest" "$root/"; chmod +x "$root/sattrtest"
out=$("$NABI" -m "$root" /sattrtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "sattr ok" ]; then
    echo "  ok  sattrtest -> \"$out\", exit 0"
else
    echo "  FAIL sattrtest -> \"$out\", exit $rc"
    fail=1
fi

# timestest: times(2) — process CPU time counters and wall clock since boot
cp "$here/timestest" "$root/"; chmod +x "$root/timestest"
out=$("$NABI" -m "$root" /timestest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "times ok" ]; then
    echo "  ok  timestest -> \"$out\", exit 0"
else
    echo "  FAIL timestest -> \"$out\", exit $rc"
    fail=1
fi

# quotatest: quotactl(2) and quotactl_fd(2) — disk quota control returns ENOSYS
cp "$here/quotatest" "$root/"; chmod +x "$root/quotatest"
out=$("$NABI" -m "$root" /quotatest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "quota ok" ]; then
    echo "  ok  quotatest -> \"$out\", exit 0"
else
    echo "  FAIL quotatest -> \"$out\", exit $rc"
    fail=1
fi

# rahtest: readahead(2) — prefetch hint on valid/bogus fd
cp "$here/rahtest" "$root/"; chmod +x "$root/rahtest"
out=$("$NABI" -m "$root" /rahtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "rahtest ok" ]; then
    echo "  ok  rahtest -> \"$out\", exit 0"
else
    echo "  FAIL rahtest -> \"$out\", exit $rc"
    fail=1
fi

# uffdtest: userfaultfd(2) — on-demand page resolution lifecycle
cp "$here/uffdtest" "$root/"; chmod +x "$root/uffdtest"
out=$("$NABI" -m "$root" /uffdtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "uffdtest ok (15 checks)" ]; then
    echo "  ok  uffdtest -> \"$out\", exit 0"
else
    echo "  FAIL uffdtest -> \"$out\", exit $rc"
    fail=1
fi

# rfptest: remap_file_pages(2) — deprecated no-op, always returns 0
cp "$here/rfptest" "$root/"; chmod +x "$root/rfptest"
out=$("$NABI" -m "$root" /rfptest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "rfptest ok (5 checks)" ]; then
    echo "  ok  rfptest -> \"$out\", exit 0"
else
    echo "  FAIL rfptest -> \"$out\", exit $rc"
    fail=1
fi

# rmmtest: recvmmsg(2) — receive multiple datagrams on a socketpair, vlen=0,
# timeout expiry, and MSG_DONTWAIT on an empty socket.
cp "$here/rmmtest" "$root/"; chmod +x "$root/rmmtest"
out=$("$NABI" -m "$root" /rmmtest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "recvmmsg ok" ]; then
    echo "  ok  rmmtest -> \"$out\", exit 0"
else
    echo "  FAIL rmmtest -> \"$out\", exit $rc"
    fail=1
fi

# truntest: truncate(2) — shrink, expand, error on ENOENT, and no-op.
cp "$here/truntest" "$root/"; chmod +x "$root/truntest"
out=$("$NABI" -m "$root" /truntest); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "truntest ok" ]; then
    echo "  ok  truntest -> \"$out\", exit 0"
else
    echo "  FAIL truntest -> \"$out\", exit $rc"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "smoke: PASS"
else
    echo "smoke: FAIL"
fi
exit $fail
