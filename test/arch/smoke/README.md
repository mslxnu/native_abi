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
- `binderprobe` — the mSL/DevFS binder driver's ioctls spoken in a guest (needs
  a live `/dev/binder`; skips 77 otherwise). Its epoll stage registers the
  binder fd for `EPOLLIN` and checks the filter is exact both ways: silent
  before work arrives, woken by it, and silent again once drained - the
  NOTE_LOWAT-of-one registration NABI has to use for a device kqueue would
  otherwise refuse. Its twoproc stage sends a oneway transaction across a fork,
  so the client is its own process with its own binder fd, arena and acquire,
  and the manager receives the payload in its own arena. Its fd stage sends a
  `BINDER_TYPE_FD` object in a transaction: NABI's broker moves the descriptor
  over `SCM_RIGHTS` (the manager registered with `FLAT_BINDER_FLAG_ACCEPTS_FDS`
  and receives a real, usable fd back, keyed by the sender's pid in the cookie).
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

- `randtest` — `/proc/sys/kernel/random/uuid` and `boot_id`, which are
  opposites: the first must give a different value on every read, the second the
  same one for as long as the host has been up. mSL/FHS mirrors Darwin's sysctl
  tree under `/proc/sys`, so `random/` is empty there and Arch's shell startup
  opened a login with three "No such file or directory" complaints.

- `schedtest` — the `sched_*` family. A guest thread is an ordinary host thread
  and stays one: Darwin's real-time scheduling is Mach's, needing a privilege
  NABI has not got, so `SCHED_FIFO` is refused with EPERM exactly as Linux
  refuses it to an unprivileged caller. What the test is really for is
  agreement - `getscheduler` reporting what `setscheduler` accepted, `getparam`
  agreeing with both, and `setaffinity` accepting the mask `getaffinity` just
  handed out. A setter that quietly succeeded while the getter said otherwise
  would be worse than either answer alone.

- `nstest` — namespaces, all eight of them. All ten links Linux has under
  `/proc/<pid>/ns` exist, and a call that fails leaves every namespace where it
  was. Per namespace:

  - **uts** — `unshare` changes the identity, and a hostname set inside it
    survives a fork, which on arm64 means surviving a rebuild from a checkpoint.
  - **mnt** — a bind mount reads through to its source; a read-only remount
    refuses `openat` for write and `mkdir` with EROFS while still reading;
    `MS_MOVE` carries a mount to a new path and uncovers the old one, refusing a
    source that is not a mount point and a destination inside the mount's own
    subtree; `umount2` empties the target, and unmounting a non-mount is EINVAL.
    Propagation is checked where it can only be checked - between namespaces: a
    child that unshares and mounts under a **shared** mount has that mount
    arrive in the parent, and under a **private** one it does not. A plain fork
    shares the table, so the child must unshare first or the test would pass by
    proving nothing was isolated.
  - **ipc** — covered by `ipctest` below.
  - **pid** — `unshare(CLONE_NEWPID)` must *not* renumber the caller, only
    `pid_for_children`; the first child is pid 1 with a reported parent of 0,
    its parent being outside; `wait4` returns the number `clone` did; a pid
    outside the namespace cannot be signalled.
  - **net** — a socket can still be made but has nowhere to go: `connect` is
    ENETUNREACH and `bind` EADDRNOTAVAIL, while `socketpair(AF_UNIX)` goes on
    working, pathname sockets being the mount namespace's business.
  - **user** — the map is the only thing that gives an id meaning. Before one is
    written every id reads as nobody; after `100 <self> 1` the process is 100
    and a file it owns reads as 100 while one owned by an unmapped id still
    reads as nobody; chowning to an unmapped id is EINVAL; a second write to
    `uid_map` is EPERM.
  - **cgroup** — a hierarchy mounted with `cgroup2` reports empty
    `cgroup.controllers`, because nothing here may claim to control anything;
    writing a pid to `cgroup.procs` moves the process and `/proc/self/cgroup`
    says so; `unshare(CLONE_NEWCGROUP)` rebases that path to `/` while the
    process has not moved.
  - **time** — the one that is unlike the others: `unshare(CLONE_NEWTIME)` must
    not move the caller, only `time_for_children`; `clone(CLONE_NEWTIME)` is
    EINVAL; and a child of a namespace with offsets written through
    `/proc/self/timens_offsets` sees `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`
    shifted by exactly them while `CLOCK_REALTIME` is untouched.

- `inotest` — inotify, which macOS has no equivalent of. The descriptor is the
  read end of a pipe a kqueue watcher feeds, so `read` and `poll` work by
  construction; what the test is for is the events themselves carrying the right
  *names*, since kqueue reports that a directory changed and not what changed in
  it. Also `IN_CLOSE_WRITE`, which no host notification can produce and which is
  taken from the guest's own `close` - the test creates and closes the file in
  the same process, which is the only case where that works - and a watch asking
  only for events that cannot arrive from anywhere being refused rather than
  left to wait.

- `fantest` — fanotify, which unlike inotify exists to watch *other* processes.
  The file is opened, written and closed by a forked child, so an implementation
  that could only see its own process fails here rather than passing by
  accident. Permission events are covered too: a listener denies an open made by
  another process and that open has to actually fail, since a guard that
  reported the open after allowing it would pass a notification test and be
  worthless. The last case is the one the feature rests on - a listener that
  dies *without* answering must release whoever is waiting, or a guest that ran
  a guard once could never open a file again. `FAN_REPORT_FID` is covered by
  taking the handle out of an event and handing it straight to
  `open_by_handle_at`, then checking the *content* that comes back - a handle
  that opened the wrong file would pass any check of the return value alone.

- `xattrtest` — extended attributes round-tripping, which they did not: `setxattr`
  used to warn and return 0, so everything a guest stored was stored nowhere and
  reported as stored. The rest is containment — nabi keeps a file's guest
  ownership in `msl.nabi.owner`, and a guest that could read it could also copy
  it, since `cp -a` and `tar --xattrs` read every attribute from one file and
  write them onto another. It has to be absent from listings and refused by
  name, with the ownership it records still working afterwards.

- `futextest` — the rest of the futex family: `REQUEUE` and `CMP_REQUEUE`, which
  move waiters without waking them and are what a broadcast is built on;
  `TRYLOCK_PI`; `get_robust_list` round-tripping what was registered; and the
  futex2 syscalls. `futex_waitv` is the one needing its own check — it waits on
  several futexes and must report *which* woke, so an implementation that
  queued only the first, or woke correctly but reported the wrong index, would
  satisfy a test that merely saw the call return.

- `timertest` — timerfd and POSIX timers, neither of which Darwin has at all.
  The check that matters is `ppoll` seeing the timerfd: one that worked only
  through `read()` would pass a simpler test and be useless in an event loop,
  which is the only place timerfds are used. Then that `read()` answers with the
  *count of expirations* and resets it, that an interval timer accumulates while
  nobody reads, that disarming stops it, and — for POSIX timers — that a
  realtime signal is refused at creation rather than becoming a timer that never
  fires.

- `signalfdtest` — `signalfd4`, which replaces the 3-arg `signalfd` and so is
  checked in its aarch64 argument order (fd, mask, sizemask, flags). What can go
  wrong in an emulation is distinct from the kernel's own story: a signal
  blocked in the guest and handled must still reach the host's handler, or the
  descriptor would never learn it arrived; a signal already pending when the
  descriptor is created must be readable without the poke its arrival would have
  sent; and the read must *consume* the signal, or it would also reach a
  handler. Readability is a byte held in a socketpair, so `poll` answers
  without knowing any of this — and the test drives the readiness through
  `ppoll` rather than `read`, since that is what an event loop does and it is
  the difference between a descriptor and a file. The record also names the
  sender, which is where an emulation lies most easily: a self-`kill` must read
  back as the guest's own `getpid()`/`getuid()`, not as the host pid of the
  `nabi` process and the account it runs under — an all-zero identity would
  defeat every waitpid-style matcher built on `ssi_pid`.

- `ipctest` — System V IPC: a segment created, attached, shared across a fork,
  detached and removed; keys resolving to ids; semaphore values through
  `SETVAL`/`GETALL`/`semop`; and `unshare(CLONE_NEWIPC)` making the same key
  name a different object. The fork case is the one that mattered: a Darwin
  `shmat` region is neither arena-backed nor file-backed, so the child panicked
  in `checkpoint_restore` rather than inheriting the segment.

- `teetest` — `tee(2)`: what it copied is still there, unchanged and in order.
  The check that matters is the partial tee with a writer behind it — four bytes
  of `"ABCDEF"` copied, `"GH"` written while those four are still out, and the
  source reading back `"ABCDEFGH"`. Copying is the easy half and every wrong
  implementation passes it: one that appends what it read gives `"EFABCD"`, and
  one that drains and restores under a lock gives `"GHABCDEF"` as soon as the
  writer wins the race. `ppoll` and `select` are checked for the same reason a
  timerfd's `poll` is — bytes only `read` can see are invisible to an event loop,
  and a guest that polls first would wait forever on data it already has.

- `splicetest` — `splice(2)` and `vmsplice(2)` in both directions, between a
  pipe and a file and between two pipes. Because these consume what they move
  they avoid the ordering trap `tee` posed, with one exception: splicing a pipe
  that `tee` is holding bytes for must see those first, and without that lookup
  the test gets 2 bytes where it wanted 4. The offset arguments are the other
  half — an offset splice must advance the caller's offset and leave the file's
  own position where it was, a pair that is easy to get half right.

- `copytest` — `sendfile(2)` and `copy_file_range(2)`. The copying is the easy
  part and the bookkeeping is not: the test sends a 200K file into a
  *non-blocking pipe* that cannot take it all, then checks the source's position
  against what the call reported moving. An implementation that reads with
  `read(2)` and finds out about the short write afterwards leaves the file 64K
  past what it delivered — bytes consumed, undelivered and unreported, and only
  when the destination is slow, which no small test makes it. Offsets are
  checked as `splice`'s are, and `copy_file_range` is checked to refuse
  overlapping ranges of one file across *two separate opens* of it.

- `aiotest` — Linux asynchronous I/O, the `io_setup` family. That a read reads is
  the easy half. The checks that matter: a read's data must be in the *guest's*
  buffer by the time the event is reaped (NABI's worker thread never touches
  guest memory, so the copy happens at reap time — remove it and the buffer comes
  back empty); each event must carry its own iocb's `aio_data` **and address**,
  which is how a caller matches a completion to its request and which is
  invisibly correct with only one in flight; `io_getevents(min_nr)` must wait for
  `min_nr` rather than return what happens to be ready; and an eventfd named by
  `IOCB_FLAG_RESFD` must be poked on completion — without that the test hangs
  rather than fails, which is what a guest folding aio into a poll loop would do.

- `uringtest` — `io_uring`, driven by hand rather than through liburing, because
  what is being checked is the layout NABI *reports*: the offsets come out of
  `io_uring_params` and are used exactly as a real caller would use them, so a
  wrong one shows up here rather than as a mystery inside somebody's library. The
  first assertion is the load-bearing one — NABI writes `ring_entries` before the
  guest ever maps the page, so reading it back proves the two are looking at the
  same memory, and that check is what caught the ring descriptor being returned
  wrong. Then a nop, a write and a read through the ring, two submissions in one
  call (each completion must carry its own `user_data`; with one in flight a
  mix-up is invisible), a vectored read, an unknown opcode failing per entry
  rather than per batch, and a registered eventfd counting one per completion.
  The poll and timeout cases are the ones that pin down the asynchrony: a poll is
  armed on an *empty* pipe and the submitting call must return having posted
  nothing, the pipe is fed only afterwards, and the completion is asked for
  then — an implementation that answered the poll at submit time reports a
  completion that should not exist yet and fails there. A timeout ended by its
  clock reports `-ETIME`; one ended by its completion count reports 0, which is
  how a caller tells the two apart. `TIMEOUT_REMOVE` is checked in both of its
  modes, and the update mode is **timed** — a ten-second timeout is shortened to
  40ms and the wait must finish well inside two seconds. That is the only way to
  catch a deadline that was updated without waking the poller: the completion
  still arrives with the right result, ten seconds late. The test sleeps briefly
  before updating so the poller has actually settled onto the old deadline,
  without which the update races ahead of it and the timing proves nothing.
  `ASYNC_CANCEL` is checked cancelling a poll *and* a timeout through the one
  opcode — a typed implementation answers `ENOENT` for one of them — and then
  clearing two polls off a descriptor with `CANCEL_FD | CANCEL_ALL`. Both flags
  are load-bearing: without `CANCEL_FD` the descriptor number is matched against
  user_data and nothing is found, and without `CANCEL_ALL` one of the two polls
  is cancelled and success reported while the other stays armed. `STATX`,
  `MKDIRAT` and `UNLINKAT` are the same operations as the syscalls of those
  names and share their code, so what is checked is that the *entry* is read
  correctly — the arguments sit in different fields here than in a syscall
  frame. The statx result is read out of the buffer rather than trusted from
  `res`, because a buffer pointer taken from the wrong field still reports
  success and simply writes somewhere else. `SEND` and `RECV` go over a
  socketpair. `OPENAT` and `OPENAT2` are checked by **reading from the
  descriptor they hand back** — an open that produced a raw host descriptor
  without entering it in the guest's table looks entirely successful until first
  use, which is exactly the bug that check found. `OPENAT2` is also checked to
  refuse a mode with nothing to create and to refuse a resolve restriction it
  cannot enforce. Registered files are checked so that an *index* and a
  *descriptor* are told apart: slot 0 holds the real file, so a submission naming
  0 without `IOSQE_FIXED_FILE` means descriptor 0 — stdin — and an
  implementation that ignored the flag reads nothing and reports 0 where 5 was
  wanted. Registered buffers are checked on their bound, which is the one
  guarantee registration carries here: a read that runs off the end of its
  registration is refused even though the memory either side of it is perfectly
  valid. Last, the ring is closed **through itself** — a `CLOSE` submitted
  against the ring's own descriptor — which exercises the ring surviving being
  freed underneath the call still running it, and catches a `CLOSE` that reaches
  the descriptor table directly instead of going through `user_close` (the ring
  is never detached, and entering it afterwards succeeds where it should say
  `EOPNOTSUPP`). Note the suite does **not** cover the ring lock being released
  around a blocking operation: showing that needs a second guest thread to be
  held up, and these tests are single-threaded.

- `mqtest` — POSIX message queues, which macOS does not have in any form, plus
  `ioprio_get`/`ioprio_set`. The checks are the ones an implementation shaped
  like a pipe would fail: a message sent *later* with a higher priority comes out
  first, equal priorities come out oldest-first, a receive buffer smaller than
  the queue's message size is refused **without consuming the message**, and
  `mq_unlink` removes the name while a descriptor still open keeps working. The
  refusals are checked too — a name with no leading slash, a name with a path in
  it, and a notification asking for a realtime signal NABI cannot deliver.

- `mounttest` — `mount_setattr`, `listmount`, `mbind`, and the two `kexec` calls
  answering `ENOSYS`. The load-bearing check is that `mount_setattr` **takes
  effect** rather than being recorded: a bind made read-only through it has to
  start refusing writes, and an implementation that stored the attribute instead
  reports a successful create where `-EROFS` was wanted. Clearing is checked as
  precisely as setting, since saying which attributes to change rather than
  handing over a whole flag word is the reason the call exists. `mbind` has one
  node to work with, so what is tested is the validation — a nodemask naming a
  node this machine does not have is refused rather than accepted and ignored.
  It also drives the new mount API end to end — `fsopen`, `fsconfig`,
  `fsmount`, `move_mount` — and proves the result is a mount by putting a
  marker in the mount point first and requiring it to be *hidden*: writing
  under `/newapi` would succeed whether or not anything was mounted, since it
  is a real directory either way, but only a mount shadows what was there.
  `open_tree` is checked the same way, by reading a file that exists only
  through the clone. `statmount` is read at the offsets it reports rather
  than at assumed ones.

- `auxvtest` — the auxiliary vector a process starts with, walked off its own
  stack rather than through `getauxval`, so it checks what NABI actually put
  there with no libc in between to paper over a gap. `AT_SECURE` is why it
  exists: `getauxval` sets `errno` to `ENOENT` for an entry that is absent, and
  not every caller treats that as "no answer" — GLib's `g_check_setuid()` asks
  for `AT_SECURE` and calls `g_error()` if `errno` is set, which aborts. A
  missing entry is not a feature a program does without, it is a program that
  dies, and without this one `dconf`'s RPM scriptlet trapped during a Fedora
  install and took every other GLib program with it. `AT_EXECFN` and
  `AT_PLATFORM` are pointers, so being present is only half of it — a pointer
  into memory the guest cannot read, or at a string that was never written,
  passes a presence check and fails everything after it. Both are followed and
  read. `AT_RANDOM` is judged across **two** runs rather than within one,
  because no single run can tell random bytes from bytes that are simply the
  same every time — which is what they were when the array was left
  uninitialised.

- `pvmtest` — `process_vm_readv` and `process_vm_writev`. Only the same-process
  form can work here, so the cross-process form is checked to be *refused* and
  told apart from a process that does not exist. The part that is easy to get
  wrong in the half that works is the vector walk: the local and remote sides are
  gathered and scattered **independently**, need not have the same number of
  entries or the same lengths, and the transfer stops when either runs out. The
  shapes in the test deliberately do not match — three remote pieces into two
  local ones — so an implementation that pairs them entry by entry reports 8
  where 10 were asked for.

- `pidfdtest` — `pidfd_open`, `process_madvise` and `process_mrelease`. The trap
  is that a pidfd is a *file* here, and `poll` and `select` call a file readable
  always — so a live process would look exited, and a readiness hook that only
  *added* readability could not fix it. Both halves are checked: a running
  process must **not** be readable, and a child that has exited must be, through
  `poll`, `select` and `epoll` alike. The `epoll` half needed its own work in the
  opposite direction, since kqueue raises no read event for a regular file at
  all, so an event loop would otherwise wait on a pidfd forever. It then
  exercises the family end to end: a child forked with `CLONE_PIDFD`, killed
  through the descriptor the *parent* was handed at the moment the child
  appeared, and a second signal to the same descriptor answering `ESRCH`
  rather than reaching whoever holds that number now — which is the whole
  reason the family exists. `pidfd_getfd`'s copy is *used* rather than
  counted: a pipe is written and read back through it.

- `staletest` — a recorded guest mode that the host mode contradicts. NABI writes
  the mode attribute and the host mode together, and the host mode is always
  `record | 0600`, so a pair that disagrees is one NABI cannot have written. A
  Fedora tree carried records of `0200` against files the host held at `0644`;
  `0200` denies read to *everyone*, so Python could not import `encodings` and
  every GLib program that reached one died with a bare `PermissionError`. The
  test runs as an ordinary user, because root short-circuits the permission check
  and would never have seen it. Its other half matters as much: a file recorded
  `0000` against a host `0600` — `/etc/shadow`'s exact shape — is *consistent*,
  and must still be refused. "Restrictive" is not the test; disagreement is.

- `miscsystest` — `close_range`, `epoll_pwait2`, `execveat`, `fchmodat2`,
  `adjtimex`, and the four that answer `ENOSYS`. Each is checked on what
  distinguishes it from the call it resembles, which is where these go wrong:
  `CLOSE_RANGE_CLOEXEC` **marks** rather than closes, so the descriptor must
  still be readable afterwards; `epoll_pwait2`'s sub-millisecond timeout must
  round *up*, since rounding down turns a short sleep into a busy loop;
  `fchmodat2`'s `AT_SYMLINK_NOFOLLOW` must land on the link and leave the target
  alone — the thing `fchmodat` never could do, and which this got wrong until the
  lookup was told not to follow. It ends by exec'ing `/miscdone` through a
  descriptor with `AT_EMPTY_PATH`, so the `misc ok` it prints comes from the
  program `execveat` ran.

The ELF binaries are committed prebuilt (as the x86 guest tests under
`test/*/build/` are), so the check needs no cross-toolchain. The `.s` sources
are here for reference; rebuild with an aarch64-linux clang + ld.lld:

    clang -target aarch64-linux-gnu -c exit42.s -o exit42.o
    ld.lld -static -e _start exit42.o -o exit42

Run via `make check-smoke` (Apple Silicon only; needs a natively-built nabi).
