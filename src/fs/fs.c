/*-
 * Copyright (c) 2016 Yuichi Nishiwaki and Takaya Saeki
 * Copyright (c) 1994-1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "mount.h"
#include "cgroup.h"
#include "checkpoint.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/fanotify.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "linux/termios.h"
#include "linux/socket.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/syslimits.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/file.h>

#include <mach-o/dyld.h>

struct file {
  struct file_operations *ops;
  int fd;
  /* Live directory stream, opened on the first getdents and kept until close.
   * NULL for anything that is not being read as a directory. */
  DIR *dirp;
};

struct file_operations {
  int (*readv)(struct file *f, struct iovec *iov, size_t iovcnt);
  int (*writev)(struct file *f, const struct iovec *iov, size_t iovcnt);
  int (*close)(struct file *f);
  int (*ioctl)(struct file *f, int cmd, uint64_t val0);
  int (*lseek)(struct file *f, l_off_t offset, int whence);
  int (*getdents)(struct file *f, char *buf, uint count, bool is64);
  int (*fcntl)(struct file *f, unsigned int cmd, unsigned long arg);
  int (*fsync)(struct file *f);
  /* inode operations */
  int (*fstat)(struct file *f, struct l_newstat *stat);
  int (*fstatfs)(struct file *f, struct l_statfs *buf);
  int (*fchown)(struct file *f, l_uid_t uid, l_gid_t gid);
  int (*fchmod)(struct file *f, l_mode_t mode);
};

static inline bool in_userfd(int fd);
static const int user_fdtable_initsize = 64;
static const int vkern_fdtable_maxsize = 64;
static const int fdtable_alloc_unit = 64; // must be a multiple of 64

static inline void set_fdbit(struct fdtable *table, uint64_t *fdbits, int fd);
static inline void clear_fdbit(struct fdtable *table, uint64_t *fdbits, int fd);

static inline int div_ceil(int x, int y) { return (x + y - 1) / y; }

int
alloc_fdtable(struct fdtable *fdtable, int newsize)
{
  newsize = div_ceil(newsize, fdtable_alloc_unit) * fdtable_alloc_unit;
  int oldsize = fdtable->size;
  if (newsize <= oldsize)
    return 0;

  int newunit = newsize / fdtable_alloc_unit;
  int oldunit = oldsize / fdtable_alloc_unit;
  fdtable->files = realloc(fdtable->files, sizeof(struct file *) * newunit);
  if (fdtable->files == NULL)
    return -LINUX_ENOMEM;
  for (int i = oldunit; i < newunit; i++) {
    fdtable->files[i] = calloc(fdtable_alloc_unit, sizeof(struct file));
    if (fdtable->files[i] == NULL)
      return -LINUX_ENOMEM;
  }

  int newfdslen = newsize / 8;
  fdtable->open_fds = realloc(fdtable->open_fds, newfdslen);
  if (fdtable->open_fds == NULL)
      return -LINUX_ENOMEM;
  fdtable->cloexec_fds = realloc(fdtable->cloexec_fds, newfdslen);
  if (fdtable->cloexec_fds == NULL)
      return -LINUX_ENOMEM;

  int offset = oldsize / 8;
  int size = newfdslen - offset;

  bzero(fdtable->open_fds + oldunit, size);
  bzero(fdtable->cloexec_fds + oldunit, size);

  fdtable->size = newsize;
  return 0;
}

/* Set by init_fileinfo, reported once the debug sinks exist. */
static bool rootfs_case_insensitive;

void
report_rootfs_case(void)
{
  if (!rootfs_case_insensitive)
    return;
  /* Loud, and on stderr, because the alternative is finding out three hundred
   * files into an install. A case-insensitive filesystem cannot hold both
   * halves of a pair like _exit.2.gz and _Exit.2.gz, and Debian ships several:
   * manpages-dev has two, linux-libc-dev has the netfilter headers. dpkg does
   * not fail where the collision is. It clears a stale .dpkg-new for the
   * second name, which deletes the first name's freshly unpacked file, writes
   * a symlink over it, and only reports anything later when its fsync pass
   * cannot reopen what it just extracted - as ENOENT, on the file that was
   * fine. Nothing in that chain names the real problem. */
  warnk("rootfs is on a case-insensitive filesystem\n");
  fprintf(stderr,
          "nabi: warning: the rootfs is on a case-insensitive filesystem.\n"
          "  Linux distributions ship files whose names differ only in case,\n"
          "  and this filesystem cannot hold both. Installing packages will\n"
          "  fail in ways that do not mention case at all.\n"
          "  Put the rootfs on a case-sensitive volume:\n"
          "    util/msl-mkvolume.sh ~/.msl/disk.sparseimage /Volumes/msl\n");
}

void
init_fileinfo(int rootfd)
{
  init_host_passthrough();

  /* pathconf answers this without touching the tree, which matters: probing by
   * creating two files would write to a rootfs that may be read-only, and
   * would race a second guest doing the same. A filesystem that declines to
   * answer is left alone rather than guessed at.
   *
   * Only worth saying for a rootfs that holds a distribution. The colliding
   * names all arrive with packages, so a hand-assembled tree of a few binaries
   * - the smoke tests, anything run with -m against a scratch directory - has
   * nothing to collide and does not need telling. Crying wolf there would
   * teach the warning to be ignored where it matters. */
  errno = 0;
  long cs = fpathconf(rootfd, _PC_CASE_SENSITIVE);
  rootfs_case_insensitive =
    cs == 0 && errno == 0 &&
    (faccessat(rootfd, "etc/os-release", F_OK, 0) == 0 ||
     faccessat(rootfd, "var/lib/dpkg", F_OK, 0) == 0);

  struct rlimit limit;
  struct fileinfo *fileinfo = &proc.fileinfo;

  getrlimit(RLIMIT_NOFILE, &limit);
  fileinfo->vkern_fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fileinfo->vkern_fdtable.start = limit.rlim_cur - vkern_fdtable_maxsize;
  alloc_fdtable(&fileinfo->vkern_fdtable, vkern_fdtable_maxsize);
  fileinfo->fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  alloc_fdtable(&fileinfo->fdtable, user_fdtable_initsize);

  for (int i = 0; i < (int) limit.rlim_cur; i++) {
    if (i == rootfd) {
      continue;
    }
    int flag = fcntl(i, F_GETFD);
    if (flag < 0) {
      continue;
    }
    if (in_userfd(i)) {
      register_fd(i, flag & FD_CLOEXEC);
    } else {
      warnk("closing a file whose fd overlaps with vkern_fdtable, fd: %d\n", i);
      fprintf(stderr, "NABI uses high file descriptor numbers as the system file descriptors. fd[%d] is closed because it overlaps with the system area.\n", i);
      close(i);
    }
  }
  fileinfo->rootfd = vkern_dup_fd(rootfd, false);
}

/*
 * RLIMIT_NOFILE, in both directions.
 *
 * NABI keeps its own descriptors in the top vkern_fdtable_maxsize slots of the
 * host's table, so the guest is told a limit that excludes them. The inverse
 * has to exist, and did not: a guest that reads its limits and writes them back
 * - which is exactly what su, login and PAM all do - had the reduced number
 * applied to the host verbatim, dropping the host's limit onto the reserved
 * range. Every dup2 into the vkern table then failed with EBADF, and since
 * vkern_dup_fd did not check dup2 the caller got a slot with nothing behind it.
 * The first thing to notice was execve: it fstats the descriptor it just
 * opened, got EBADF, decided the file was not regular, and returned EACCES -
 * "su: failed to execute /bin/bash: Permission denied", about a file that is
 * plainly executable.
 *
 * Both fields are shifted, not just rlim_max, so the round trip is exact.
 */
void
darwin_to_linux_rlimit_nofile(struct rlimit *darwin_rlimit, struct l_rlimit *linux_rlimit)
{
  linux_rlimit->rlim_cur = darwin_rlimit->rlim_cur == RLIM_INFINITY
                             ? LINUX_RLIM_INFINITY
                             : darwin_rlimit->rlim_cur - vkern_fdtable_maxsize;
  linux_rlimit->rlim_max = darwin_rlimit->rlim_max == RLIM_INFINITY
                             ? LINUX_RLIM_INFINITY
                             : darwin_rlimit->rlim_max - vkern_fdtable_maxsize;
}

void
linux_to_darwin_rlimit_nofile(struct l_rlimit *linux_rlimit, struct rlimit *darwin_rlimit)
{
  darwin_rlimit->rlim_cur = linux_rlimit->rlim_cur == LINUX_RLIM_INFINITY
                              ? RLIM_INFINITY
                              : linux_rlimit->rlim_cur + vkern_fdtable_maxsize;
  darwin_rlimit->rlim_max = linux_rlimit->rlim_max == LINUX_RLIM_INFINITY
                              ? RLIM_INFINITY
                              : linux_rlimit->rlim_max + vkern_fdtable_maxsize;
}

/* The lowest host limit that still leaves NABI's own descriptors addressable. */
int
vkern_fd_floor(void)
{
  return proc.fileinfo.vkern_fdtable.start + vkern_fdtable_maxsize;
}


/* ------------------------------------------------------------- eventfd */

/*
 * eventfd, on a system that has none.
 *
 * An eventfd is a counter you can poll: write adds to it, read returns the
 * total and zeroes it, and it is readable exactly while the total is nonzero.
 * Darwin has no equivalent, and nothing here had implemented syscall 19 at all,
 * so it returned ENOSYS - which is what stopped every download in the guest.
 * libcurl's multi interface creates one for curl_multi_wakeup and treats the
 * failure as fatal, so curl_multi_init returned NULL and the tool reported
 * "curl: (27) Out of memory" - about a machine with 32GiB free. pacman 7 and
 * dnf both drive libcurl that way, which is why neither could fetch anything.
 *
 * The pollable part is what needs a real descriptor, so it is a socketpair: the
 * guest is given one end, NABI keeps the other, and a single byte is held in
 * flight whenever the counter is nonzero. That byte is what makes poll, select
 * and epoll answer correctly without any of them knowing this is emulated. The
 * counter itself lives here, because a socketpair queues bytes where an eventfd
 * accumulates a total, and a guest that writes 1 five times must read back 5
 * rather than 1 with four bytes still pending.
 *
 * What does not survive: arm64's fork is fork-plus-exec, and this table is
 * process memory rather than checkpoint state, so a forked child inherits the
 * descriptor without the counter behind it. libcurl creates its eventfd after
 * forking, so no guest yet has needed it to travel; a guest that did would see
 * a socketpair with eventfd's arithmetic missing rather than a broken fd.
 */
struct eventfd_state {
  int      notify_fd;   /* the end NABI keeps; the guest never sees it */
  uint64_t count;
  bool     semaphore;
};

KHASH_MAP_INIT_INT(evfd, struct eventfd_state)
static khash_t(evfd) *eventfds;

/* NULL unless `fd` is one of ours, which is also the "is this an eventfd" test
 * every hook below uses. */
static struct eventfd_state *
eventfd_lookup(int fd)
{
  if (eventfds == NULL)
    return NULL;
  khiter_t k = kh_get(evfd, eventfds, fd);
  return k == kh_end(eventfds) ? NULL : &kh_value(eventfds, k);
}

/* Exactly one byte is outstanding whenever the counter is nonzero, so the
 * descriptor's readability and the counter never disagree. */
static void
eventfd_poke(struct eventfd_state *ev)
{
  char one = 1;
  (void) write(ev->notify_fd, &one, 1);
}

static void
eventfd_drain(int fd)
{
  char one;
  (void) recv(fd, &one, 1, MSG_DONTWAIT);
}

static int
eventfd_do_read(struct file *file, struct eventfd_state *ev,
                struct iovec *iov, size_t iovcnt)
{
  if (iovcnt < 1 || iov[0].iov_len < sizeof(uint64_t))
    return -LINUX_EINVAL;

  while (ev->count == 0) {
    int fl = fcntl(file->fd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK))
      return -LINUX_EAGAIN;
    /* Block where the guest asked to block: the byte arrives when somebody
     * writes, and the counter it belongs to is then nonzero. */
    char one;
    ssize_t r = read(file->fd, &one, 1);
    if (r < 0)
      return -darwin_to_linux_errno(errno);
    if (r == 0)
      return -LINUX_EBADF;
    if (ev->count == 0)
      continue;              /* somebody else drained it first */
    goto have_it;
  }
  eventfd_drain(file->fd);

have_it:;
  uint64_t out;
  if (ev->semaphore) {
    out = 1;
    ev->count--;
  } else {
    out = ev->count;
    ev->count = 0;
  }
  /* Still owed something, so it must stay readable. */
  if (ev->count > 0)
    eventfd_poke(ev);

  memcpy(iov[0].iov_base, &out, sizeof out);
  return (int) sizeof out;
}

static int
eventfd_do_write(struct eventfd_state *ev, const struct iovec *iov, size_t iovcnt)
{
  if (iovcnt < 1 || iov[0].iov_len < sizeof(uint64_t))
    return -LINUX_EINVAL;

  uint64_t add;
  memcpy(&add, iov[0].iov_base, sizeof add);
  /* UINT64_MAX is reserved: it is the value that could never be read back,
   * since the counter saturates one below it. */
  if (add == UINT64_MAX)
    return -LINUX_EINVAL;
  if (add == 0)
    return (int) sizeof add;
  if (ev->count > UINT64_MAX - 1 - add)
    return -LINUX_EAGAIN;    /* a blocking writer would wait for a reader */

  bool was_empty = ev->count == 0;
  ev->count += add;
  if (was_empty)
    eventfd_poke(ev);

  return (int) sizeof add;
}

static void
eventfd_forget(int fd)
{
  if (eventfds == NULL)
    return;
  khiter_t k = kh_get(evfd, eventfds, fd);
  if (k == kh_end(eventfds))
    return;
  close(kh_value(eventfds, k).notify_fd);
  kh_del(evfd, eventfds, k);
}

#define LINUX_EFD_SEMAPHORE 1

DEFINE_SYSCALL(eventfd2, unsigned int, initval, int, flags)
{
  if (flags & ~(LINUX_EFD_SEMAPHORE | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC))
    return -LINUX_EINVAL;

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return -darwin_to_linux_errno(errno);

  /* Only the guest's end takes the guest's flags. The end NABI keeps must stay
   * blocking and must not leak across exec... except that on arm64 exec is how
   * fork works, so it is deliberately left inheritable and simply closed with
   * the descriptor it belongs to. */
  if ((flags & LINUX_O_NONBLOCK) && fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0)
    goto fail;
  if ((flags & LINUX_O_CLOEXEC) && fcntl(sv[0], F_SETFD, FD_CLOEXEC) < 0)
    goto fail;

  /* register_fd reports success or -errno; the descriptor the guest gets is the
   * host one it was handed, because nabi does not renumber. Returning what
   * register_fd returned instead handed every eventfd out as fd 0 - so dnf
   * created one, was told 0, later closed it, and thereby closed the guest's
   * real stdin. The next open took the free slot, librepo asserted
   * `dtarget->fd > 0` on a destination file that had legitimately been given
   * descriptor zero, and aborted. */
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(sv[0], (flags & LINUX_O_CLOEXEC) != 0);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(sv[0]);
    close(sv[1]);
    return err;
  }

  if (eventfds == NULL)
    eventfds = kh_init(evfd);
  int ret;
  khiter_t k = kh_put(evfd, eventfds, sv[0], &ret);
  kh_value(eventfds, k) = (struct eventfd_state){
    .notify_fd = sv[1],
    .count = initval,
    .semaphore = (flags & LINUX_EFD_SEMAPHORE) != 0,
  };
  if (initval > 0)
    eventfd_poke(&kh_value(eventfds, k));

  return sv[0];

fail:;
  int e = errno;
  close(sv[0]);
  close(sv[1]);
  return -darwin_to_linux_errno(e);
}

/*
 * Retry a blocking transfer the host gave up on because a signal arrived.
 *
 * Linux restarts a call interrupted by a handler carrying SA_RESTART; the guest
 * is never told. NABI's host handler only records the signal for delivery
 * later, so an EINTR arriving here is an artefact of how it was noticed rather
 * than something the guest asked to hear about - and sigrestart_wanted() is
 * what distinguishes that from a signal whose handler is entitled to break the
 * call.
 *
 * Reads and writes only. They are the two that block with nothing else to
 * report, and they are where it was found: dnf's children exit while it waits
 * at "Is this ok [y/N]:", and it takes the failed read as a refusal.
 */
#define RETRY_ON_RESTARTABLE_EINTR(expr) ({                                   \
      int _r;                                                                 \
      for (;;) {                                                              \
        _r = syswrap(expr);                                                   \
        if (_r != -LINUX_EINTR || !sigrestart_wanted())                       \
          break;                                                              \
      }                                                                       \
      _r;                                                                     \
    })

int
darwinfs_writev(struct file *file, const struct iovec *iov, size_t iovcnt)
{
  struct eventfd_state *ev = eventfd_lookup(file->fd);
  if (ev != NULL)
    return eventfd_do_write(ev, iov, iovcnt);
  return RETRY_ON_RESTARTABLE_EINTR(writev(file->fd, iov, iovcnt));
}

int
darwinfs_readv(struct file *file, struct iovec *iov, size_t iovcnt)
{
  struct eventfd_state *ev = eventfd_lookup(file->fd);
  if (ev != NULL)
    return eventfd_do_read(file, ev, iov, iovcnt);
  return RETRY_ON_RESTARTABLE_EINTR(readv(file->fd, iov, iovcnt));
}

int
darwinfs_close(struct file *file)
{
  eventfd_forget(file->fd);
  procfs_close_fd(file->fd);
  if (file->dirp != NULL) {
    closedir(file->dirp);       /* takes the dup with it */
    file->dirp = NULL;
  }
  return syswrap(close(file->fd));
}

/*
 * The devpts <-> Darwin naming translation, in both directions.
 *
 * Linux names a pty slave /dev/pts/<n>, where <n> is what TIOCGPTN reports;
 * Darwin names it /dev/ttys<n> zero-padded to three digits, and has no number
 * to ask for - only the name. So the number the guest is told is parsed out of
 * the host's name, and the path the guest then opens is turned back into that
 * name. The round trip holds as long as the host's format does, which is why
 * a name that does not parse is reported rather than guessed at.
 */
static bool
devpts_number_of(const char *hostname, unsigned int *out)
{
  const char *p = hostname;
  if (strncmp(p, "/dev/ttys", 9) != 0)
    return false;
  p += 9;
  if (*p < '0' || *p > '9')
    return false;              /* /dev/ttyse and the other pre-ptmx nodes */
  unsigned int n = 0;
  for (; *p >= '0' && *p <= '9'; p++)
    n = n * 10 + (unsigned int) (*p - '0');
  if (*p != '\0')
    return false;
  *out = n;
  return true;
}

static bool
devpts_to_host(const char *name, char *buf, size_t len)
{
  if (strncmp(name, "/dev/pts/", 9) != 0)
    return false;
  const char *p = name + 9;
  if (*p < '0' || *p > '9')
    return false;              /* /dev/pts itself, and /dev/pts/ptmx */
  unsigned int n = 0;
  for (; *p >= '0' && *p <= '9'; p++)
    n = n * 10 + (unsigned int) (*p - '0');
  if (*p != '\0')
    return false;
  snprintf(buf, len, "/dev/ttys%03u", n);
  return true;
}

int
darwinfs_ioctl(struct file *file, int cmd, uint64_t val0)
{
  uint64_t sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
  int fd = file->fd;
  int r;

  switch (cmd) {
  case LINUX_TCGETS: {
    struct termios dios;
    struct linux_termios lios;

    if ((r = RETRY_ON_RESTARTABLE_EINTR(tcgetattr(fd, &dios))) < 0) {
      return r;
    }
    darwin_to_linux_termios(&dios, &lios);
    if (copy_to_user(val0, &lios, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  /*
   * The terminal calls retry an EINTR that was never the guest's.
   *
   * nabi's own machinery takes signals - a child it reaped, a timer - and a
   * host EINTR raised by one of those describes an interruption the guest
   * cannot see and did not ask about. read and write already hid it; these did
   * not, so apt restoring the terminal after dpkg reported "Setting in Stop via
   * TCSAFLUSH for stdin failed! - tcsetattr (4: Interrupted system call)" about
   * a call that had simply been interrupted by nabi.
   *
   * sigrestart_wanted is what makes this safe rather than a blanket retry: an
   * EINTR raised while the guest genuinely has a signal pending is still its
   * own, and is still reported.
   */
  case LINUX_TCSETS: {
    struct termios dios;
    struct linux_termios lios;
    if (copy_from_user(&lios, val0, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_termios(&lios, &dios);
    return RETRY_ON_RESTARTABLE_EINTR(tcsetattr(fd, TCSANOW, &dios));
  }
  case LINUX_TCSETSW: {
    struct termios dios;
    struct linux_termios lios;
    if (copy_from_user(&lios, val0, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_termios(&lios, &dios);
    return RETRY_ON_RESTARTABLE_EINTR(tcsetattr(fd, TCSADRAIN, &dios));
  }
  /* The third of the three, and it was missing - so tcsetattr(TCSAFLUSH) fell
   * through to the default arm and came back EPERM. apt uses it on stdin when
   * it sets up a terminal for dpkg, and reported "Setting in Start via
   * TCSAFLUSH for stdin failed! - Operation not permitted" about something that
   * needed no permission. */
  case LINUX_TCSETSF: {
    struct termios dios;
    struct linux_termios lios;
    if (copy_from_user(&lios, val0, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_termios(&lios, &dios);
    return RETRY_ON_RESTARTABLE_EINTR(tcsetattr(fd, TCSAFLUSH, &dios));
  }
  /*
   * The termios2 family. A guest running glibc 2.42 or newer sends these and
   * never the four above - tcgetattr(3) compiles to TCGETS2 now - so without
   * them every terminal query from a current distribution came back EPERM from
   * the default arm. isatty() concluded nothing was a terminal, bash started
   * non-interactive with an empty PS1, and `msl login fedora` showed a blank
   * screen: alive, echoing, answering commands, and with no prompt, which is
   * indistinguishable from a hang.
   *
   * The extra content over the older form is the pair of baud rates, which
   * Darwin's termios carries too, so nothing has to be invented. The
   * conversion of everything else is shared - a termios2 *is* a termios with
   * two fields appended, and treating it as a separate thing would be two
   * copies of the flag mapping to keep in step.
   */
  case LINUX_TCGETS2: {
    struct termios dios;
    struct linux_termios2 lios2;
    struct linux_termios lios;

    if ((r = RETRY_ON_RESTARTABLE_EINTR(tcgetattr(fd, &dios))) < 0) {
      return r;
    }
    darwin_to_linux_termios(&dios, &lios);
    memcpy(&lios2, &lios, sizeof lios);
    lios2.c_ispeed = (unsigned int) cfgetispeed(&dios);
    lios2.c_ospeed = (unsigned int) cfgetospeed(&dios);
    if (copy_to_user(val0, &lios2, sizeof lios2)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TCSETS2:
  case LINUX_TCSETSW2:
  case LINUX_TCSETSF2: {
    struct termios dios;
    struct linux_termios2 lios2;
    struct linux_termios lios;
    if (copy_from_user(&lios2, val0, sizeof lios2)) {
      return -LINUX_EFAULT;
    }
    memcpy(&lios, &lios2, sizeof lios);
    linux_to_darwin_termios(&lios, &dios);
    /* Only if the guest asked for something. A zero here means "leave it", and
     * cfsetspeed(0) would be B0 - which hangs up the line. */
    if (lios2.c_ispeed)
      cfsetispeed(&dios, (speed_t) lios2.c_ispeed);
    if (lios2.c_ospeed)
      cfsetospeed(&dios, (speed_t) lios2.c_ospeed);
    int when = cmd == LINUX_TCSETS2  ? TCSANOW
             : cmd == LINUX_TCSETSW2 ? TCSADRAIN
             :                         TCSAFLUSH;
    return RETRY_ON_RESTARTABLE_EINTR(tcsetattr(fd, when, &dios));
  }
  case LINUX_TIOCGPGRP: {
    l_pid_t pgrp;
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCGPGRP, &pgrp))) < 0) {
      return r;
    }
    if (copy_to_user(val0, &pgrp, sizeof pgrp)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TIOCSPGRP: {
    l_pid_t pgrp;
    if (copy_from_user(&pgrp, val0, sizeof pgrp)) {
      return -LINUX_EFAULT;
    }
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCSPGRP, &pgrp))) < 0) {
      return r;
    }
    return 0;
  }
  case LINUX_TIOCGWINSZ: {
    struct winsize ws;
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCGWINSZ, &ws))) < 0) {
      return r;
    }
    struct linux_winsize lws;
    darwin_to_linux_winsize(&ws, &lws);
    if (copy_to_user(val0, &lws, sizeof lws)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TIOCSWINSZ: {
    struct linux_winsize lws;
    struct winsize ws;
    if (copy_from_user(&lws, val0, sizeof lws)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_winsize(&ws, &lws);
    return RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCSWINSZ, &ws));
  }
  case LINUX_TCXONC: {
    int sel;
    switch(val0) {
    case LINUX_TCOOFF: sel = TCOOFF; break;
    case LINUX_TCOON: sel = TCOON; break;
    case LINUX_TCIOFF: sel = TCIOFF; break;
    case LINUX_TCION: sel = TCION; break;
    default:
      return -LINUX_EINVAL;
    }
    return syswrap(tcflow(fd, sel));
  }
  case LINUX_TCFLSH: {
    int sel;
    switch (val0) {
    case LINUX_TCIFLUSH: sel = TCIFLUSH; break;
    case LINUX_TCOFLUSH: sel = TCOFLUSH; break;
    case LINUX_TCIOFLUSH: sel = TCIOFLUSH; break;
    default:
      return -LINUX_EINVAL;
    }
    return syswrap(tcflush(fd, sel));
  }
  /*
   * The three calls behind Linux's pty allocation, which Darwin spells
   * differently at every step.
   *
   *   posix_openpt   open("/dev/ptmx")           - passthrough, works already
   *   unlockpt       ioctl(TIOCSPTLCK, &0)       TIOCPTYGRANT + TIOCPTYUNLK
   *   ptsname        ioctl(TIOCGPTN, &n)         TIOCPTYGNAME -> "/dev/ttysNNN"
   *                  then "/dev/pts/n"           then that path back to ttysNNN
   *
   * Unhandled, TIOCSPTLCK fell through to the default arm and came back EPERM,
   * which is how a guest that only wants a terminal to run dpkg under ends up
   * reporting "Unlocking the slave of master fd 27 failed".
   */
  case LINUX_TIOCSPTLCK: {
    int lock;
    if (copy_from_user(&lock, val0, sizeof lock)) {
      return -LINUX_EFAULT;
    }
    if (lock) {
      /* Darwin can unlock a slave but not lock one again, and nothing does:
       * the kernel hands every master out locked and glibc only ever clears
       * it. Reporting that rather than returning a success we did not deliver.
       */
      return -LINUX_EINVAL;
    }
    /* grantpt's work, done here rather than where the guest calls grantpt.
     * On Linux with devpts the slave node already exists with the right
     * owner, so glibc's grantpt does nothing and NABI never sees it; on
     * Darwin the slave is unusable until it has been granted. unlockpt is the
     * call that means "I am about to use this", so it is the one place both
     * halves can be done. */
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCPTYGRANT))) < 0) {
      return r;
    }
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCPTYUNLK))) < 0) {
      return r;
    }
    /*
     * Open the slave once and let it go again.
     *
     * On Linux a pty is a pair from the moment the master exists, and the
     * termios and window size live on the pair - so a program may set them on
     * the master before anything has opened the slave, and everything does:
     * apt sizes the terminal it is about to run dpkg under before it forks.
     *
     * Darwin attaches no line discipline until the slave has been opened at
     * least once. Until then TCGETS, TCSETS and TIOCSWINSZ on the master all
     * return ENOTTY - which is how "Setting TIOCSWINSZ for master fd 76 failed"
     * came about, for a descriptor that was a perfectly good master.
     *
     * Opening it here and closing it immediately is enough: the state persists
     * after the descriptor goes, and the transient open costs nothing the guest
     * can observe. Holding it open instead would be wrong - the master's read
     * returns EOF when the last slave closes, and a slave NABI never released
     * would mean that EOF never arrives and the reader waits forever.
     */
    {
      char slave[PATH_MAX];
      if (ioctl(fd, TIOCPTYGNAME, slave) == 0) {
        int probe = open(slave, O_RDWR | O_NOCTTY);
        if (probe >= 0)
          close(probe);
      }
    }
    return 0;
  }
  case LINUX_TIOCGPTN: {
    char name[PATH_MAX];
    unsigned int n;
    if ((r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCPTYGNAME, name))) < 0) {
      return r;
    }
    if (!devpts_number_of(name, &n)) {
      warnk("TIOCGPTN: host slave \"%s\" is not a ttysNNN\n", name);
      return -LINUX_EINVAL;
    }
    if (copy_to_user(val0, &n, sizeof n)) {
      return -LINUX_EFAULT;
    }
    return 0;
  }
  /* Both take no argument on either side; only the numbers differ. */
  case LINUX_TIOCSCTTY:
    return RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCSCTTY));
  case LINUX_TIOCNOTTY:
    return RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, TIOCNOTTY));
  case LINUX_FIONREAD: {
    int val;
    int r = RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, FIONREAD, &val));
    if (r < 0) {
      return r;
    }
    if (copy_to_user(val0, &val, sizeof val)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_FIONBIO: {
    int val;
    if (copy_from_user(&val, val0, sizeof val)) {
      return -LINUX_EFAULT;
    }
    return RETRY_ON_RESTARTABLE_EINTR(ioctl(fd, FIONBIO, &val));
  }
  case LINUX_FIOCLEX: {
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    int r = sys_fcntl(fd, LINUX_F_SETFD, 1);
    if (r >= 0) {
      set_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, fd);
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  }
  default:
    warnk("unhandled darwinfs ioctl (fd = %08x, cmd = 0x%08x)\n", fd, cmd);
    return -LINUX_EPERM;
  }
}

int
darwinfs_lseek(struct file *file, l_off_t offset, int whence)
{
  /* A directory being read has its position in the stream rather than on the
   * descriptor, so a seek has to move the stream or it moves nothing that
   * getdents will notice. rewinddir is the case that occurs - it is what
   * glibc's rewinddir(3) compiles to, and what anything re-reading a directory
   * after changing it does. */
  if (file->dirp != NULL && offset == 0 && whence == SEEK_SET) {
    /* If this is /proc/self/fd, the answer has to be recomputed rather than
     * replayed - the guest is rewinding precisely because it expects the list
     * to have changed since it last looked. */
    procfs_refresh_fddir(file->fd);
    rewinddir(file->dirp);
    return 0;
  }
  return syswrap(lseek(file->fd, offset, whence));
}

ssize_t
darwin_to_linux_dent(struct dirent *d_dent, void *l_dent, size_t buflen, int is64)
{
  /*
   * The name has to be counted in both cases. Without the parentheses the
   * "+ d_namlen + 2" bound to the else branch alone, so a 64-bit record was a
   * fixed roundup(offsetof(d_name), 8) = 24 bytes however long the name was -
   * room for five characters. Longer names ran past the record and the next
   * entry's d_ino overwrote their tail, so a directory listing came back with
   * some names silently mangled ("lost+found" -> "lost+@�C") and others
   * intact, depending on whether the clobbering inode happened to start with a
   * zero byte. The +2 covers the NUL and, for the 32-bit layout, the d_type
   * byte stored at reclen-1; one spare byte in the 64-bit case is free after
   * the 8-byte roundup.
   */
  unsigned reclen = roundup((is64 ? offsetof(struct l_dirent64, d_name)
                                  : offsetof(struct l_dirent, d_name))
                            + d_dent->d_namlen + 2, 8);
  if (reclen > buflen) {
    return -1;
  }
  /* fill dirent buffer */
  if (is64) {
    struct l_dirent64 *dp = (struct l_dirent64 *) l_dent;
    dp->d_reclen = reclen;
    dp->d_ino = d_dent->d_ino;
    dp->d_off = d_dent->d_seekoff;
    dp->d_type = d_dent->d_type;
    memcpy(dp->d_name, d_dent->d_name, d_dent->d_namlen + 1);
  } else {
    struct l_dirent *dp = (struct l_dirent *) l_dent;
    dp->d_reclen = reclen;
    dp->d_ino = d_dent->d_ino;
    dp->d_off = d_dent->d_seekoff;
    memcpy(dp->d_name, d_dent->d_name, d_dent->d_namlen + 1);
    ((char *) dp)[reclen - 1] = d_dent->d_type;
  }
  return reclen;
}

/*
 * getdents, over a directory stream that stays open between calls.
 *
 * A guest reads a directory in whatever size buffer it chose, so any directory
 * too big for one call has to continue exactly where the last one stopped.
 *
 * This used to open a fresh DIR over a dup of the descriptor every call and
 * close it again, keeping its place with telldir/seekdir. Neither half of that
 * works. A telldir cookie belongs to one DIR instance and does not outlive it,
 * and what seekdir leaves on the descriptor is the start of the block it
 * re-read rather than the entry that was asked for - so a directory that did
 * not fit resumed in the wrong place. Reading a 4000-entry directory returned
 * 3792 of them, with no error anywhere: a guest simply did not see some of its
 * own files. d_seekoff is no way out either; APFS reports it as zero, and
 * seeking there restarts the directory from the top forever.
 *
 * Keeping the stream open makes the question go away, because the position
 * lives in the stream rather than having to be reconstructed. seekdir is then
 * used only within one instance, where its cookies do mean something, to push
 * back the entry that did not fit.
 */
int
darwinfs_getdents(struct file *file, char *direntp, unsigned count, bool is64)
{
  if (file->dirp == NULL) {
    int fd = dup(file->fd);
    if (fd < 0)
      return -darwin_to_linux_errno(errno);
    if ((file->dirp = fdopendir(fd)) == NULL) {
      int e = errno;
      close(fd);
      return -darwin_to_linux_errno(e);
    }
  }

  DIR *dir = file->dirp;
  struct dirent *dent;
  size_t pos = 0;
  bool full = false;
  long loc = telldir(dir);

  errno = 0;
  while ((dent = readdir(dir)) != NULL) {
    ssize_t reclen = darwin_to_linux_dent(dent, direntp + pos, count - pos, is64);
    if (reclen < 0) {
      seekdir(dir, loc);        /* this one goes to the next call */
      full = true;
      break;
    }
    pos += reclen;
    loc = telldir(dir);
  }
  if (dent == NULL && !full && errno)
    return -darwin_to_linux_errno(errno);

  /* Not one entry fitted. Linux calls that EINVAL rather than end-of-directory,
   * and the difference matters: a guest told 0 stops reading and concludes the
   * directory is empty. */
  if (pos == 0 && full)
    return -LINUX_EINVAL;

  return pos;
}

void linux_to_darwin_flock(struct l_flock *linux_flock, struct flock *darwin_flock);

void darwin_to_linux_flock(struct flock *darwin_flock, struct l_flock *linux_flock);

int
darwinfs_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
  int r;
  struct l_flock lflock;
  struct flock dflock;

  switch (cmd) {
  case LINUX_F_DUPFD:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_DUPFD, arg)); /* FIXME */
    if (r >= 0) {
      procfs_dup_fd(file->fd, r);
      int err = register_fd(r, false);
      if (err < 0) {
        close(r);
        r = err;
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  case LINUX_F_DUPFD_CLOEXEC:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_DUPFD_CLOEXEC, arg));
    if (r >= 0) {
      procfs_dup_fd(file->fd, r);
      int err = register_fd(r, true);
      if (err < 0) {
        close(r);
        r = err;
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
    /* no translation required for fd flags (i.e. CLOEXEC==1 */
  case LINUX_F_GETFD:
    return syswrap(fcntl(file->fd, F_GETFD));
  case LINUX_F_SETFD:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_SETFD, arg));
    if (r >= 0) {
      if (arg & FD_CLOEXEC) {
        set_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, file->fd);
      } else {
        clear_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, file->fd);
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  case LINUX_F_GETFL:
    r = syswrap(fcntl(file->fd, F_GETFL));
    if (r < 0)
      return r;
    return darwin_to_linux_o_flags(r);
  case LINUX_F_SETFL:
    return syswrap(fcntl(file->fd, F_SETFL, linux_to_darwin_o_flags(arg)));
  case LINUX_F_GETLK:
    if (copy_from_user(&lflock, arg, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_flock(&lflock, &dflock);
    r = syswrap(fcntl(file->fd, F_GETLK, &dflock));
    if (r < 0) {
      return r;
    }
    darwin_to_linux_flock(&dflock, &lflock);
    if (copy_to_user(arg, &lflock, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    return 0;
  case LINUX_F_SETLK: case LINUX_F_SETLKW:
    if (copy_from_user(&lflock, arg, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_flock(&lflock, &dflock);
    return syswrap(fcntl(file->fd, (cmd == LINUX_F_SETLK) ? F_SETLK : F_SETLKW, &dflock));
  /*
   * Open file description locks, served with flock().
   *
   * Darwin has no F_OFD_*, but it has BSD flock(), and for a whole-file lock
   * the two describe the same thing: ownership by the open file description
   * rather than by the process, so an unrelated close does not drop the lock
   * and two descriptions in one process contend with each other. That is the
   * property callers reach for OFD locks to get, and the property POSIX record
   * locks famously do not have.
   *
   * Only whole-file. flock() cannot express a byte range, so a ranged request
   * is refused rather than widened - a lock quietly covering more of the file
   * than was asked for is a deadlock waiting to be blamed on something else.
   * Nothing yet seen asks for one: systemd takes the /etc/passwd lock whole,
   * which is what turned every sysusers run into "Failed to take /etc/passwd
   * lock: Invalid argument" and stopped systemd, udev and cron configuring.
   */
  case LINUX_F_OFD_SETLK: case LINUX_F_OFD_SETLKW: {
    if (copy_from_user(&lflock, arg, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    /* SEEK_SET is 0 on both sides; a whole-file lock is the only shape
     * flock() can express, and any other whence makes the range depend on the
     * file position, which cannot be whole-file either. */
    if (lflock.l_whence != SEEK_SET || lflock.l_start != 0 ||
        lflock.l_len != 0) {
      warnk("F_OFD_SETLK%s over a byte range (start %lld len %lld); "
            "flock() can only take the whole file\n",
            cmd == LINUX_F_OFD_SETLKW ? "W" : "",
            (long long) lflock.l_start, (long long) lflock.l_len);
      return -LINUX_EINVAL;
    }
    int op;
    switch (lflock.l_type) {
    case LINUX_F_RDLCK: op = LOCK_SH; break;
    case LINUX_F_WRLCK: op = LOCK_EX; break;
    case LINUX_F_UNLCK: op = LOCK_UN; break;
    default:            return -LINUX_EINVAL;
    }
    /* The non-waiting form is the one that must not block; SETLKW may. */
    if (cmd == LINUX_F_OFD_SETLK && op != LOCK_UN)
      op |= LOCK_NB;
    r = syswrap(flock(file->fd, op));
    /* flock says EWOULDBLOCK where fcntl says EAGAIN. They are the same errno
     * on Linux, but syswrap has already mapped it, so only the name differs. */
    return r;
  }
  case LINUX_F_OFD_GETLK:
    /* flock() cannot be asked who holds a lock, and inventing an answer would
     * be worse than saying so: a caller told "unlocked" would proceed. */
    warnk("F_OFD_GETLK: flock() cannot report the holder of a lock\n");
    return -LINUX_EINVAL;
  default:
    warnk("unknown fcntl cmd: %d\n", cmd);
    return -LINUX_EINVAL;
  }
}

int
darwinfs_fsync(struct file *file)
{
  return syswrap(fsync(file->fd));
}

/* ---------------------------------------------------------------------------
 * Guest ownership
 *
 * The host cannot represent it. Every file in a rootfs belongs to the single
 * account nabi runs as; chown to anybody else needs privileges nabi does not
 * have; and host_uid_to_guest maps that one account onto guest root. So a file
 * created by the guest's own user came back owned by root, useradd's chown of a
 * home directory did nothing, and `ls -ln ~` on a fresh account read
 * "drwx------ 0 0". Enforcing permissions on top of that would have locked
 * every user out of their own home on the first check.
 *
 * The guest's idea of who owns a file is therefore kept beside the file, in an
 * extended attribute. It travels with the file, survives a copy within the
 * volume, can be read from the host with `xattr -p`, and - unlike anything held
 * in nabi's memory - is shared by every process, which matters here because a
 * fork is a fork plus an exec and sibling guests are separate host processes.
 *
 * Absent, the owner is the host account, which the guest already reads as root.
 * That is both the sensible default and the common case: everything a
 * distribution unpacks is installed by root and carries no attribute at all, so
 * the ordinary path costs one failed lookup and no storage.
 * ------------------------------------------------------------------------ */

/* Defined with the passthrough table further down; needed here to tell a host
 * object, which cannot carry an attribute, from one in the rootfs, which can. */
static bool is_host_passthrough(const char *name);

#define GUEST_OWNER_XATTR "msl.nabi.owner"

struct guest_owner {
  uint32_t uid;
  uint32_t gid;
};

/*
 * An absolute host path for a (dirfd, relative path) pair.
 *
 * macOS has no getxattrat, so the attribute calls need a name rather than a
 * descriptor. The directory's own path comes from F_GETPATH, cached for one
 * descriptor because path resolution asks about the same one over and over -
 * nearly always the rootfs.
 */
static bool
abs_path_at(int dirfd, const char *rel, char *out, size_t len)
{
  static int cached_fd = -1;
  static char cached_path[PATH_MAX];

  if (rel[0] == '/')
    return (size_t) snprintf(out, len, "%s", rel) < len;

  if (dirfd == AT_FDCWD) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof cwd) == NULL)
      return false;
    return (size_t) snprintf(out, len, "%s/%s", cwd, rel) < len;
  }

  if (dirfd != cached_fd) {
    if (fcntl(dirfd, F_GETPATH, cached_path) < 0) {
      cached_fd = -1;
      return false;
    }
    cached_fd = dirfd;
  }
  return (size_t) snprintf(out, len, "%s/%s", cached_path, rel) < len;
}

static bool
guest_owner_read(const char *abs, bool nofollow, struct guest_owner *out)
{
  ssize_t n = getxattr(abs, GUEST_OWNER_XATTR, out, sizeof *out, 0,
                       nofollow ? XATTR_NOFOLLOW : 0);
  return n == (ssize_t) sizeof *out;
}

static int
guest_owner_write(const char *abs, bool nofollow, const struct guest_owner *o)
{
  return setxattr(abs, GUEST_OWNER_XATTR, o, sizeof *o, 0,
                  nofollow ? XATTR_NOFOLLOW : 0);
}

/* Overlay the recorded owner onto a stat already converted for the guest. */
static void
guest_owner_overlay(int dirfd, const char *path, bool nofollow,
                    struct l_newstat *l_st)
{
  char abs[PATH_MAX];
  struct guest_owner o;
  if (!abs_path_at(dirfd, path, abs, sizeof abs))
    return;
  if (guest_owner_read(abs, nofollow, &o)) {
    l_st->st_uid = userns_uid_inward(o.uid);
    l_st->st_gid = userns_gid_inward(o.gid);
  }
}

static void
guest_owner_overlay_fd(int fd, struct l_newstat *l_st)
{
  struct guest_owner o;
  if (fgetxattr(fd, GUEST_OWNER_XATTR, &o, sizeof o, 0, 0) == (ssize_t) sizeof o) {
    l_st->st_uid = userns_uid_inward(o.uid);
    l_st->st_gid = userns_gid_inward(o.gid);
  }
}

/*
 * Record an owner. -1 for either means "leave as it is", as chown does.
 *
 * Root - the host account - is written out rather than left implicit, so that
 * chowning something back to root removes an attribute that said otherwise
 * rather than being ignored.
 */
static int
guest_owner_record(int dirfd, const char *path, bool nofollow,
                   l_uid_t uid, l_gid_t gid)
{
  char abs[PATH_MAX];
  struct guest_owner o = { 0, 0 };
  if (!abs_path_at(dirfd, path, abs, sizeof abs))
    return -LINUX_ENOENT;
  guest_owner_read(abs, nofollow, &o);          /* keep whatever is not changing */
  if (uid != (l_uid_t) -1) o.uid = uid;
  if (gid != (l_gid_t) -1) o.gid = gid;
  if (o.uid == 0 && o.gid == 0) {
    removexattr(abs, GUEST_OWNER_XATTR, nofollow ? XATTR_NOFOLLOW : 0);
    return 0;
  }
  if (guest_owner_write(abs, nofollow, &o) == 0)
    return 0;

  /*
   * Nowhere to record it, on something that was never ours to record.
   *
   * A passthrough path is a host object - devfs, procfs, the host's /tmp - and
   * carries no extended attributes at all: setxattr on a pty slave is EPERM,
   * and so is chown, because nabi is not root on the host and devfs would not
   * store either if it were. Reporting that back says "you may not do this" to
   * a guest that on Linux plainly may.
   *
   * grantpt() is the case that matters. It chowns the slave to the caller and
   * to group tty, which on Linux devpts the kernel has already done and which
   * nothing afterwards reads. sudo takes the failure as fatal, so `sudo id`
   * from a terminal answered "unable to allocate pty: Operation not permitted"
   * - about a pty it had successfully opened a line earlier.
   *
   * So a passthrough is told yes. Inside the rootfs a failure here is real and
   * is still returned: that is where ownership means something.
   */
  if (abs[0] == '/' && is_host_passthrough(abs) &&
      (errno == EPERM || errno == ENOTSUP))
    return 0;

  return -darwin_to_linux_errno(errno);
}

/* ---------------------------------------------------------------------------
 * Guest mode
 *
 * The same problem as ownership, arriving from the other side. A mode that
 * denies its own owner cannot be worked around by being the owner: nabi is the
 * host account, so `---s--x--x` - which is what every distribution ships sudo
 * as - means nabi cannot *read* the file, and reading it is exactly what
 * loading an ELF requires. Fedora's sudo installed correctly and then could not
 * run, reporting "Permission denied" about a file the guest was perfectly
 * entitled to execute.
 *
 * It cannot be fixed by relaxing the mode outright, because the mode is also
 * what the guest sees and what nabi's own permission checks are made of;
 * turning sudo into 0755 would hand it to everybody. So the guest's mode is
 * recorded beside the file, exactly as its owner is, and the host keeps a mode
 * that lets nabi do its job.
 *
 * What the host is left with is the guest's mode plus owner access, and without
 * the setuid bits - those are honoured by nabi against the recorded mode, and
 * leaving them on a host file owned by an ordinary account only invites
 * confusion. Granting the owner what it already had is not a concession: nabi
 * owns the tree and can chmod anything in it whenever it likes, so this changes
 * what other host tools see and nothing about what the guest can reach.
 *
 * Absent, the mode is the host's, which is the common case and costs one failed
 * lookup: everything a distribution unpacks with ordinary permissions needs no
 * attribute at all.
 * ------------------------------------------------------------------------ */

#define GUEST_MODE_XATTR "msl.nabi.mode"

/* Permission and setuid bits; the file-type bits are the host's to state. */
#define GUEST_MODE_BITS 07777

static bool
guest_mode_read(const char *abs, bool nofollow, uint32_t *out)
{
  ssize_t n = getxattr(abs, GUEST_MODE_XATTR, out, sizeof *out, 0,
                       nofollow ? XATTR_NOFOLLOW : 0);
  return n == (ssize_t) sizeof *out;
}

/* What the host should carry so that nabi can still read, write and traverse.
 * Directories need search as well, or nothing beneath them can be reached. */
static mode_t
host_mode_for(uint32_t guest_mode, bool is_dir)
{
  mode_t m = (mode_t) (guest_mode & 0777);
  return m | (is_dir ? 0700 : 0600);
}

/* Overlay the recorded mode onto a stat already converted for the guest. */
static void
guest_mode_overlay(int dirfd, const char *path, bool nofollow,
                   struct l_newstat *l_st)
{
  char abs[PATH_MAX];
  uint32_t m;
  if (!abs_path_at(dirfd, path, abs, sizeof abs))
    return;
  if (guest_mode_read(abs, nofollow, &m))
    l_st->st_mode = (l_st->st_mode & ~(uint32_t) GUEST_MODE_BITS)
                  | (m & GUEST_MODE_BITS);
}

static void
guest_mode_overlay_fd(int fd, struct l_newstat *l_st)
{
  uint32_t m;
  if (fgetxattr(fd, GUEST_MODE_XATTR, &m, sizeof m, 0, 0) == (ssize_t) sizeof m)
    l_st->st_mode = (l_st->st_mode & ~(uint32_t) GUEST_MODE_BITS)
                  | (m & GUEST_MODE_BITS);
}

/*
 * Record a mode and put a workable one on the host.
 *
 * A mode the host can carry as it stands is left alone and any old attribute
 * dropped, so the ordinary case stores nothing and the attribute's presence
 * always means "the host's mode is not the answer".
 */
static int
guest_mode_record(int dirfd, const char *path, bool nofollow, uint32_t mode)
{
  char abs[PATH_MAX];
  if (!abs_path_at(dirfd, path, abs, sizeof abs))
    return -LINUX_ENOENT;

  struct stat dst;
  if (fstatat(dirfd, path, &dst, nofollow ? AT_SYMLINK_NOFOLLOW : 0) < 0)
    return -darwin_to_linux_errno(errno);
  bool is_dir = S_ISDIR(dst.st_mode);

  /* The host mode goes on first, and that ordering is not cosmetic: writing an
   * extended attribute needs write permission on the file, and the mode being
   * recorded is precisely one that does not grant it. Recording first fails
   * with EACCES on exactly the files this exists for. */
  mode_t host = host_mode_for(mode, is_dir);
  int r = syswrap(fchmodat(dirfd, path, host, nofollow ? AT_SYMLINK_NOFOLLOW : 0));
  if (r < 0)
    return r;

  if ((mode & GUEST_MODE_BITS) == (uint32_t) host) {
    removexattr(abs, GUEST_MODE_XATTR, nofollow ? XATTR_NOFOLLOW : 0);
    return 0;
  }
  uint32_t m = mode & GUEST_MODE_BITS;
  if (setxattr(abs, GUEST_MODE_XATTR, &m, sizeof m, 0,
               nofollow ? XATTR_NOFOLLOW : 0) < 0)
    return -darwin_to_linux_errno(errno);
  return 0;
}

/*
 * Adopt a mode that was already on disk when nabi could not use it.
 *
 * Trees built before any of this exists, and anything a package manager laid
 * down through a path that is not chmod, carry a restrictive mode and no
 * attribute - so the first open fails and there is nothing recorded to explain
 * why. Rather than require the tree to be swept, the failure repairs itself:
 * the mode that is there becomes the mode the guest sees, and the host gets one
 * that works.
 *
 * Only for a file nabi owns, and only when the mode really is the problem.
 * Anything else is a genuine refusal and is left to stand.
 */
static bool
guest_mode_adopt(int dirfd, const char *path)
{
  char abs[PATH_MAX];
  struct stat dst;
  uint32_t existing;

  if (!abs_path_at(dirfd, path, abs, sizeof abs))
    return false;
  if (guest_mode_read(abs, false, &existing))
    return false;                 /* already recorded; EACCES meant something else */
  if (fstatat(dirfd, path, &dst, 0) < 0 || dst.st_uid != geteuid())
    return false;

  bool is_dir = S_ISDIR(dst.st_mode);
  mode_t host = host_mode_for(dst.st_mode, is_dir);
  if ((mode_t) (dst.st_mode & 0777) == host)
    return false;                 /* the host mode was never the obstacle */

  /* Mode first, attribute second, for the same reason as guest_mode_record:
   * the file cannot be given an attribute while its mode forbids writing it. */
  uint32_t m = dst.st_mode & GUEST_MODE_BITS;
  if (fchmodat(dirfd, path, host, 0) < 0)
    return false;
  if (setxattr(abs, GUEST_MODE_XATTR, &m, sizeof m, 0, 0) < 0) {
    fchmodat(dirfd, path, dst.st_mode & 07777, 0);      /* put it back */
    return false;
  }
  return true;
}

/*
 * The guest's view of an open file: who owns it and what its mode is, with both
 * recorded attributes applied.
 *
 * exec needs this and cannot assemble it itself. A raw host fstat answers with
 * the account nabi runs as and with the mode the host carries, and since a
 * setuid bit is deliberately not left on the host file, asking the host means
 * never seeing one. Both halves of the answer live here.
 */
void
guest_view_of_fd(int fd, uint32_t *uid, uint32_t *gid, uint32_t *mode)
{
  struct stat dst;
  struct l_newstat st;
  if (fstat(fd, &dst) < 0)
    return;
  stat_darwin_to_linux(&dst, &st);
  guest_owner_overlay_fd(fd, &st);
  guest_mode_overlay_fd(fd, &st);
  if (uid)  *uid  = st.st_uid;
  if (gid)  *gid  = st.st_gid;
  if (mode) *mode = st.st_mode;
}

/*
 * Called after the guest creates something. Only when it is not root: a root
 * guest's files are the host account's, which is what an absent attribute
 * already means.
 */
static void
guest_owner_stamp_new(int dirfd, const char *path)
{
  l_uid_t uid;
  l_gid_t gid;
  pthread_rwlock_rdlock(&proc.cred.lock);
  uid = proc.cred.euid;
  gid = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (uid == 0 && gid == 0)
    return;
  guest_owner_record(dirfd, path, true, uid, gid);
}

int
darwinfs_fstat(struct file *file, struct l_newstat *l_st)
{
  struct stat st;
  int ret = syswrap(fstat(file->fd, &st));
  if (ret < 0) {
    return ret;
  }
  stat_darwin_to_linux(&st, l_st);
  guest_owner_overlay_fd(file->fd, l_st);
  guest_mode_overlay_fd(file->fd, l_st);
  return ret;
}

/*
 * Turn a chown the guest asked for into one the host can perform.
 *
 * Every file the guest can see is really owned by the one account NABI runs as,
 * so there is no ownership to change: the guest's uids are names for a thing
 * the host filesystem does not have. Accepting and doing nothing is the honest
 * end of that - Darwin reserves chown for the superuser, so passing it on fails
 * with EPERM, and both dpkg and apt treat that as a broken unpack rather than a
 * missing capability. dpkg chowns nearly everything to root:root, apt chowns
 * its partial downloads to _apt.
 *
 * What is lost is that ownership does not persist: chown to _apt then stat
 * reads back root. Nothing in a single-account world could make it read back
 * otherwise, and a guest that is root is entitled to be told its chown worked.
 */
static bool
chown_is_noop(l_uid_t uid, l_gid_t gid)
{
  (void) uid; (void) gid;
  return true;
}

int
darwinfs_fchown(struct file *file, l_uid_t uid, l_gid_t gid)
{
  if (chown_is_noop(uid, gid))
    return 0;
  return syswrap(fchown(file->fd, guest_uid_to_host(uid), guest_gid_to_host(gid)));
}

int
darwinfs_fchmod(struct file *file, l_mode_t mode)
{
  /* Same reasoning as fchmodat, reached through a descriptor. F_GETPATH names
   * the file so the attribute can be written by name, since macOS has no
   * fsetxattr-by-mode helper that would keep this to one call. */
  char abs[PATH_MAX];
  if (fcntl(file->fd, F_GETPATH, abs) == 0)
    return guest_mode_record(AT_FDCWD, abs, false, mode);
  return syswrap(fchmod(file->fd, mode));
}

int
darwinfs_fstatfs(struct file *file, struct l_statfs *buf)
{
  struct statfs st;
  int r = syswrap(fstatfs(file->fd, &st));
  if (r < 0)
    return r;
  statfs_darwin_to_linux(&st, buf);
  return r;
}

static inline bool
in_userfd(int fd)
{
  return (fd >= 0 && fd < proc.fileinfo.vkern_fdtable.start);
}

static inline void
set_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  fdbits[idx_table] |= (1ULL << (idx_bit));
}

static inline void
clear_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  fdbits[idx_table] &= ~(1ULL << (idx_bit));
}

static inline bool
test_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  return fdbits[idx_table] & (1ULL << (idx_bit));
}

static void
alloc_file(struct fdtable *table, int fd)
{
  static struct file_operations ops = {
    darwinfs_readv,
    darwinfs_writev,
    darwinfs_close,
    darwinfs_ioctl,
    darwinfs_lseek,
    darwinfs_getdents,
    darwinfs_fcntl,
    darwinfs_fsync,
    darwinfs_fstat,
    darwinfs_fstatfs,
    darwinfs_fchown,
    darwinfs_fchmod,
  };

  int offset = fd - table->start;
  struct file *file = &table->files[offset / fdtable_alloc_unit][offset % fdtable_alloc_unit];
  file->ops = &ops;
  file->fd = fd;
  /* A recycled slot must not inherit the previous descriptor's stream. */
  file->dirp = NULL;
}

/*
 * The caller of register_fd and vkern_dup_fd must acquire the lock properly if necessary
 */

int
register_fd(int fd, bool is_cloexec)
{
  if (fd >= proc.fileinfo.vkern_fdtable.start) {
    // Relocation of vkern_fdtable is not implemented currently
    return -LINUX_EMFILE;
  }
  struct fdtable *fdtable = &proc.fileinfo.fdtable;
  if (proc.fileinfo.fdtable.size <= fd) {
    int err = alloc_fdtable(fdtable, fd + 1);
    if (err < 0)
      return err;
  }
  set_fdbit(fdtable, fdtable->open_fds, fd);
  if (is_cloexec) {
    set_fdbit(fdtable, fdtable->cloexec_fds, fd);
  } else {
    clear_fdbit(fdtable, fdtable->cloexec_fds, fd);
  }
  alloc_file(fdtable, fd);
  return 0;
}

static inline int
find_emptyfd(struct fdtable *table)
{
  for (int i = 0; i < table->size / 64; i++) {
    int ret = ffs(~table->open_fds[i]);
    if (ret > 0) {
      return table->start + ret - 1 + i * 64;
    }
  }
  return -1;
}


/* ---------------------------------------------------------------------------
 * Permission checks
 *
 * Until now the guest's credentials decided nothing: every access was performed
 * by the host account, which owns the whole tree, so an unprivileged guest user
 * could open anything. `apt install` without sudo got as far as dpkg before
 * anything objected, where a real Linux refuses at the lock file.
 *
 * These are Linux's discretionary rules, applied to the ownership recorded
 * above. The host still performs the access - it has to, there is only one
 * account - so this is the only place the guest's own answer is decided.
 *
 * Root costs nothing. A guest running as root, which is the default and most of
 * what happens, short-circuits before any stat: root bypasses read and write,
 * and the one rule it does not bypass - that an executable needs an execute bit
 * somewhere - is checked from a stat the caller already had.
 * ------------------------------------------------------------------------ */

/* Bits shared with access(2): 4 read, 2 write, 1 execute. */
#define WANT_R 4
#define WANT_W 2
#define WANT_X 1

/*
 * `real` asks against the real uid rather than the effective one, which is what
 * access(2) does and faccessat2 does not unless AT_EACCESS is set.
 */
static int
cred_may(const struct l_newstat *st, int want, bool real)
{
  l_uid_t uid;
  l_gid_t gid;
  pthread_rwlock_rdlock(&proc.cred.lock);
  uid = real ? proc.cred.uid : proc.cred.euid;
  gid = real ? proc.cred.gid : proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);

  if (uid == 0) {
    /* The single rule root does not get to ignore: something must be
     * executable by somebody before root may execute it. Directories are
     * always searchable by root. */
    if ((want & WANT_X) && !S_ISDIR(st->st_mode) && (st->st_mode & 0111) == 0)
      return -LINUX_EACCES;
    return 0;
  }

  int shift;
  if (st->st_uid == uid)
    shift = 6;
  else if (st->st_gid == gid || guest_in_group(st->st_gid))
    shift = 3;
  else
    shift = 0;

  return ((st->st_mode >> shift) & want) == (unsigned) want ? 0 : -LINUX_EACCES;
}

/* Whether the guest is root, without a stat - the fast path every check takes
 * when nothing has dropped privileges. */
static bool
cred_is_root(void)
{
  bool r;
  pthread_rwlock_rdlock(&proc.cred.lock);
  r = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  return r;
}

/* Stat one path and rule on it. */
static int
permit_at(int dirfd, const char *path, bool nofollow, int want, bool real)
{
  struct stat dst;
  struct l_newstat st;
  if (fstatat(dirfd, path, &dst, nofollow ? AT_SYMLINK_NOFOLLOW : 0) < 0)
    return -darwin_to_linux_errno(errno);
  stat_darwin_to_linux(&dst, &st);
  guest_owner_overlay(dirfd, path, nofollow, &st);
  guest_mode_overlay(dirfd, path, nofollow, &st);
  return cred_may(&st, want, real);
}

/*
 * Whether the guest may create, remove or rename `entry`: write and search on
 * the directory that holds it.
 *
 * The directory is derived from the entry rather than passed in, because the
 * two are named relative to the same descriptor and getting that wrong is
 * silent - an earlier version asked about "." and so ruled on the rootfs root
 * every time, which denied a user the right to write in their own home.
 *
 * `removing` turns on the sticky-bit rule: in a directory like /tmp, only the
 * owner of an entry - or of the directory, or root - may take it away.
 */
static int
permit_parent(int dirfd, const char *entry, bool removing)
{
  if (cred_is_root())
    return 0;

  char dirpath[LINUX_PATH_MAX];
  const char *slash = strrchr(entry, '/');
  if (slash == NULL) {
    strcpy(dirpath, ".");
  } else {
    size_t n = (size_t) (slash - entry);
    if (n == 0)
      n = 1;                            /* "/x" is held by "/" */
    if (n >= sizeof dirpath)
      n = sizeof dirpath - 1;
    memcpy(dirpath, entry, n);
    dirpath[n] = '\0';
  }

  struct stat dst;
  struct l_newstat dir;
  if (fstatat(dirfd, dirpath, &dst, 0) < 0)
    return -darwin_to_linux_errno(errno);
  stat_darwin_to_linux(&dst, &dir);
  guest_owner_overlay(dirfd, dirpath, false, &dir);
  guest_mode_overlay(dirfd, dirpath, false, &dir);

  int r = cred_may(&dir, WANT_W | WANT_X, false);
  if (r < 0 || !removing || !(dir.st_mode & S_ISVTX))
    return r;

  struct l_newstat v;
  if (fstatat(dirfd, entry, &dst, AT_SYMLINK_NOFOLLOW) < 0)
    return 0;                           /* nothing there to protect */
  stat_darwin_to_linux(&dst, &v);
  guest_owner_overlay(dirfd, entry, true, &v);
  guest_mode_overlay(dirfd, entry, true, &v);

  l_uid_t euid;
  pthread_rwlock_rdlock(&proc.cred.lock);
  euid = proc.cred.euid;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (v.st_uid == euid || dir.st_uid == euid)
    return 0;
  return -LINUX_EACCES;
}

int
vkern_dup_fd(int fd, bool is_cloexec)
{
  int vkern_fd = find_emptyfd(&proc.fileinfo.vkern_fdtable);
  if (vkern_fd == -1) {
    panic("Too many files opened in the kernel space");
  }
  /* Checked, because the failure is otherwise invisible and arrives much later
   * as a descriptor that every syscall rejects. dup2 refuses a target above
   * RLIMIT_NOFILE, which is how a guest lowering its own limit used to poison
   * the whole vkern table. */
  if (dup2(fd, vkern_fd) < 0) {
    warnk("vkern_dup_fd: dup2(%d, %d) failed: %s\n", fd, vkern_fd, strerror(errno));
    return -LINUX_EBADF;
  }
  set_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.open_fds, vkern_fd);
  if (is_cloexec) {
    set_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.cloexec_fds, vkern_fd);
  } else {
    clear_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.cloexec_fds, vkern_fd);
  }
  alloc_file(&proc.fileinfo.vkern_fdtable, vkern_fd);
  return vkern_fd;
}

struct file *
do_get_file(struct fdtable *table, int fd)
{
  if (!test_fdbit(table, table->open_fds, fd)) {
    return NULL;
  }
  int offset = fd - table->start;
  return &table->files[offset / fdtable_alloc_unit][offset % fdtable_alloc_unit];
}

struct file *
get_file(int fd)
{
  struct file *ret = NULL;
  struct fdtable *table = &proc.fileinfo.fdtable;
  pthread_rwlock_rdlock(&proc.fileinfo.fdtable_lock);
  if (fd < 0 || fd >= table->size) {
    goto out;
  }
  ret = do_get_file(table, fd);

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(write, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);
  if (copy_from_user(buf, buf_ptr, size)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  /*
   * /proc/<pid>/timens_offsets is served as a temporary file holding the
   * current text, so a write would land in that copy and be reported as a
   * success while the namespace went unchanged. It is diverted before the
   * descriptor is looked up at all.
   */
  if (procfs_write_timens(fd, buf, size, &r))
    goto out;

  /*
   * Writing a pid to cgroup.procs is what moves a process between control
   * groups. The file is an ordinary one on the host, so a write would land in
   * it and change nothing - the caller would be told it had moved and would
   * not have.
   */
  if (cgroup_write_procs(fd, buf, size, &r))
    goto out;

  struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->writev == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  struct iovec iov = { buf, size };
  r =  file->ops->writev(file, &iov, 1);
  if (r >= 0 && fanotify_watching())
    fanotify_note_fd(file->fd, LINUX_FAN_MODIFY);
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(read, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);

  /*
   * A read of a fanotify descriptor is not a read of a file: the records carry
   * a descriptor, so they have to be built in the process that will use it.
   * Recognised before the descriptor is looked up, since it is not one of the
   * guest's files.
   */
  if (buf != NULL && fanotify_read(fd, buf, size, &r)) {
    if (r > 0 && copy_to_user(buf_ptr, buf, (size_t) r))
      r = -LINUX_EFAULT;
    free(buf);
    return r;
  }

  struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->readv == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  struct iovec iov = { buf, size };
  r = file->ops->readv(file, &iov, 1);
  if (r < 0) {
    goto out;
  }
  if (fanotify_watching())
    fanotify_note_fd(file->fd, LINUX_FAN_ACCESS);
  if (copy_to_user(buf_ptr, buf, r)) {
    r = -LINUX_EFAULT;
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(writev, int, fd, gaddr_t, iov_ptr, int, iovcnt)
{
  struct l_iovec *liov = alloca(sizeof(struct l_iovec) * iovcnt);

  if (copy_from_user(liov, iov_ptr, sizeof(struct l_iovec) * iovcnt))
    return -LINUX_EFAULT;

  struct iovec *iov = alloca(sizeof(struct iovec) * iovcnt);
  for (int i = 0; i < iovcnt; ++i) {
    iov[i].iov_len = liov[i].iov_len;
    iov[i].iov_base = alloca(liov[i].iov_len);
    if (copy_from_user(iov[i].iov_base, liov[i].iov_base, iov[i].iov_len))
      return -LINUX_EFAULT;
  }

  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->writev == NULL) {
    return -LINUX_EBADF;
  }
  return file->ops->writev(file, iov, iovcnt);
}

DEFINE_SYSCALL(readv, int, fd, gaddr_t, iov_ptr, int, iovcnt)
{
  struct l_iovec *liov = alloca(sizeof(struct l_iovec) * iovcnt);

  if (copy_from_user(liov, iov_ptr, sizeof(struct l_iovec) * iovcnt))
    return -LINUX_EFAULT;

  struct iovec *iov = alloca(sizeof(struct iovec) * iovcnt);
  for (int i = 0; i < iovcnt; ++i) {
    iov[i].iov_base = alloca(liov[i].iov_len);
    iov[i].iov_len = liov[i].iov_len;
  }

  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->readv == NULL) {
    return -LINUX_EBADF;
  }
  int r = file->ops->readv(file, iov, iovcnt);
  if (r < 0) {
    return r;
  }
  size_t size = r;
  for (int i = 0; i < iovcnt; ++i) {
    size_t s = MIN(size, iov[i].iov_len);
    if (copy_to_user(liov[i].iov_base, iov[i].iov_base, s)) {
      return -LINUX_EFAULT;
    }
    size -= s;
    if (size == 0)
      break;
  }
  return r;
}

DEFINE_SYSCALL(fstat, int, fd, gaddr_t, st_ptr)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  struct l_newstat st;
  int n = file->ops->fstat(file, &st);
  if (n < 0)
    return n;
  if (copy_to_user(st_ptr, &st, sizeof st)) {
    return -LINUX_EFAULT;
  }
  return n;
}

DEFINE_SYSCALL(fchown, int, fd, l_uid_t, uid, l_gid_t, gid)
{
  uint32_t o;
  if (uid != (l_uid_t) -1) {
    if (!userns_uid_outward(uid, &o))
      return -LINUX_EINVAL;
    uid = (l_uid_t) o;
  }
  if (gid != (l_gid_t) -1) {
    if (!userns_gid_outward(gid, &o))
      return -LINUX_EINVAL;
    gid = (l_gid_t) o;
  }
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fchown(file, uid, gid);
}

DEFINE_SYSCALL(fchmod, int, fd, l_mode_t, mode)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fchmod(file, mode);
}

DEFINE_SYSCALL(ioctl, int, fd, int, cmd, uint64_t, val0)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->ioctl == NULL) {
    return -LINUX_ENOTTY;
  }
  return file->ops->ioctl(file, cmd, val0);
}

DEFINE_SYSCALL(lseek, int, fd, off_t, offset, int, whence)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->lseek(file, offset, whence);
}

DEFINE_SYSCALL(getdents64, unsigned int, fd, gaddr_t, dirent_ptr, unsigned int, count)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  char *buf = malloc(count);
  int r = file->ops->getdents(file, buf, count, true);
  if (r < 0) {
    goto out;
  }
  /* Only the r bytes actually filled: copying the whole buffer would hand the
   * guest whatever was in the uninitialized tail of a host malloc. */
  if (copy_to_user(dirent_ptr, buf, r)) {
    r = -LINUX_EFAULT;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(getdents, unsigned int, fd, gaddr_t, dirent_ptr, unsigned int, count)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  char *buf = malloc(count);
  int r = file->ops->getdents(file, buf, count, false);
  if (r < 0) {
    goto out;
  }
  /* See getdents64: only the bytes actually filled. */
  if (copy_to_user(dirent_ptr, buf, r)) {
    r = -LINUX_EFAULT;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fcntl(file, cmd, arg);
}

DEFINE_SYSCALL(fstatfs, int, fd, gaddr_t, buf_ptr)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  struct l_statfs st;
  int n = file->ops->fstatfs(file, &st);
  if (n < 0)
    return n;
  if (copy_to_user(buf_ptr, &st, sizeof st)) {
    return -LINUX_EFAULT;
  }
  return n;
}

DEFINE_SYSCALL(fsync, int, fd)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fsync(file);
}

struct dir {
  int fd;
};

struct path {
  struct fs *fs;
  struct dir *dir;
  char subpath[LINUX_PATH_MAX];
  /*
   * Whether the mount this path came through was mounted read-only. Carried
   * here because resolution is the only place that knows which mount a name
   * fell in, and the operations that write are the only ones that care - a
   * read-only mount that quietly accepted writes would be worse than not
   * having one, since the entire reason to ask for it is to be certain.
   */
  bool rdonly;
};

struct fs {
  struct fs_operations *ops;
};

struct fs_operations {
  int (*openat)(struct fs *fs, struct dir *dir, const char *path, int flags, int mode); /* TODO: return struct file * instaed of file descripter */
  int (*symlinkat)(struct fs *fs, const char *target, struct dir *dir, const char *name);
  int (*faccessat)(struct fs *fs, struct dir *dir, const char *path, int mode, int flags);
  int (*renameat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to);
  int (*linkat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to, int flags);
  int (*unlinkat)(struct fs *fs, struct dir *dir, const char *path, int flags);
  int (*readlinkat)(struct fs *fs, struct dir *dir, const char *path, char *buf, int bufsize);
  int (*mkdirat)(struct fs *fs, struct dir *dir, const char *path, int mode);
  /* inode operations */
  int (*fstatat)(struct fs *fs, struct dir *dir, const char *path, struct l_newstat *stat, int flags);
  int (*statfs)(struct fs *fs, struct dir *dir, const char *path, struct l_statfs *buf);
  int (*fchownat)(struct fs *fs, struct dir *dir, const char *path, l_uid_t uid, l_gid_t gid, int flags);
  int (*fchmodat)(struct fs *fs, struct dir *dir, const char *path, l_mode_t mode);
};

/*
 * Set while nabi is reading a program image on the guest's behalf.
 *
 * execve(2) requires *execute* permission and then reads the file regardless of
 * whether the caller could have read it - which is the whole point of a mode
 * like `---s--x--x`. Loading an ELF here means an ordinary open, so without
 * this the guest's own read check refuses the very files this is for: sudo, run
 * by a user who may execute it and may not read it, failed at the open with
 * EACCES after passing the execute check a few lines earlier.
 *
 * Only the file's own read check is suppressed. Search permission on the
 * directories leading to it still applies, because Linux enforces that too.
 */
static _Thread_local bool loading_image;

int
darwinfs_openat(struct fs *fs, struct dir *dir, const char *path, int l_flags, int mode)
{
  int flags = linux_to_darwin_o_flags(l_flags);
  /* Whether this open is about to create the file, asked before it does.
   * O_CREAT alone does not say - it succeeds either way - and stamping an
   * ownership attribute onto a file that already existed would quietly hand
   * somebody else's file to whoever opened it. The extra stat is only on the
   * O_CREAT path, which is rare next to plain opens. */
  bool creating = false;
  if (flags & O_CREAT) {
    struct stat probe;
    creating = fstatat(dir->fd, path, &probe, AT_SYMLINK_NOFOLLOW) < 0;
  }

  if (!cred_is_root() && !loading_image) {
    int want = 0;
    switch (flags & O_ACCMODE) {
    case O_RDONLY: want = WANT_R; break;
    case O_WRONLY: want = WANT_W; break;
    case O_RDWR:   want = WANT_R | WANT_W; break;
    }
    if (flags & O_TRUNC)
      want |= WANT_W;
    int r;
    if (creating) {
      /* A new entry needs permission on the directory that will hold it,
       * not on a file that does not exist yet. */
      if ((r = permit_parent(dir->fd, path, false)) < 0)
        return r;
    } else if (want && (r = permit_at(dir->fd, path, false, want, false)) < 0) {
      return r;
    }
  }

  int fd = syswrap(openat(dir->fd, path, flags, mode));

  /*
   * The host refused, and the mode may be why. A file that denies its own owner
   * cannot be opened by nabi at all, and trees built before any of this - or
   * anything a package manager writes without going through chmod - carry
   * exactly that with nothing recorded to explain it. Adopt the mode as the
   * guest's, put a workable one on the host, and try once more.
   */
  if (fd == -LINUX_EACCES && guest_mode_adopt(dir->fd, path))
    fd = syswrap(openat(dir->fd, path, flags, mode));

  if (fd >= 0 && creating) {
    guest_owner_stamp_new(dir->fd, path);
    /* Created with a mode the host cannot carry - `mkstemp` then `fchmod 0600`
     * is common, but O_CREAT with 0400 happens too. */
    if ((mode & 0600) != 0600)
      guest_mode_record(dir->fd, path, false, (uint32_t) mode);
  }
  return fd;
}

int
darwinfs_symlinkat(struct fs *fs, const char *target, struct dir *dir, const char *name)
{
  int r;
  if ((r = permit_parent(dir->fd, name, false)) < 0)
    return r;
  r = syswrap(symlinkat(target, dir->fd, name));
  if (r >= 0)
    guest_owner_stamp_new(dir->fd, name);
  return r;
}

int
darwinfs_faccessat(struct fs *fs, struct dir *dir, const char *path, int mode, int l_flags)
{
  /*
   * Answered against the guest's credentials, not the host's.
   *
   * Handing this to the host was wrong in both directions: the host account
   * owns the whole tree, so it said yes to everything an unprivileged guest
   * asked about, and it knew nothing of the ownership recorded for the guest.
   *
   * access(2) asks with the *real* ids and faccessat2 with the effective ones
   * unless AT_EACCESS says otherwise, which is the whole reason that flag
   * exists.
   */
  if (mode == 0)                                  /* F_OK: existence only */
    return syswrap(faccessat(dir->fd, path, F_OK,
                             linux_to_darwin_at_flags(l_flags)));
  return permit_at(dir->fd, path,
                   (l_flags & LINUX_AT_SYMLINK_NOFOLLOW) != 0,
                   mode & (WANT_R | WANT_W | WANT_X),
                   (l_flags & LINUX_AT_EACCESS) == 0);
}

int
darwinfs_renameat(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to)
{
  int r;
  if ((r = permit_parent(dir1->fd, from, true)) < 0 ||
      (r = permit_parent(dir2->fd, to, true)) < 0)
    return r;
  return syswrap(renameat(dir1->fd, from, dir2->fd, to));
}

int
darwinfs_linkat(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  int r;
  if ((r = permit_parent(dir2->fd, to, false)) < 0)
    return r;
  return syswrap(linkat(dir1->fd, from, dir2->fd, to, flags));
}

int
darwinfs_unlinkat(struct fs *fs, struct dir *dir, const char *path, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  /* You must treat E_ACCESS as E_REMOVEDIR in unlinkat */
  if (flags & AT_EACCESS) {
    flags &= ~AT_EACCESS;
    flags |= AT_REMOVEDIR;
  }
  int r;
  if ((r = permit_parent(dir->fd, path, true)) < 0)
    return r;
  return syswrap(unlinkat(dir->fd, path, flags));
}

int
darwinfs_readlinkat(struct fs *fs, struct dir *dir, const char *path, char *buf, int bufsize)
{
  return syswrap(readlinkat(dir->fd, path, buf, bufsize));
}

int
darwinfs_mkdirat(struct fs *fs, struct dir *dir, const char *path, int mode)
{
  int r;
  if ((r = permit_parent(dir->fd, path, false)) < 0)
    return r;
  r = syswrap(mkdirat(dir->fd, path, mode));
  if (r >= 0)
    guest_owner_stamp_new(dir->fd, path);
  return r;
}

int
darwinfs_fstatat(struct fs *fs, struct dir *dir, const char *path, struct l_newstat *l_st, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  struct stat st;
  int ret = syswrap(fstatat(dir->fd, path, &st, flags));
  if (ret < 0) {
    return ret;
  }
  stat_darwin_to_linux(&st, l_st);
  guest_owner_overlay(dir->fd, path, (flags & AT_SYMLINK_NOFOLLOW) != 0, l_st);
  guest_mode_overlay(dir->fd, path, (flags & AT_SYMLINK_NOFOLLOW) != 0, l_st);
  return ret;
}

int
darwinfs_statfs(struct fs *fs, struct dir *dir, const char *path, struct l_statfs *buf)
{
  char full_path[LINUX_PATH_MAX];
  const char *path_to_statfs;

  if (dir->fd != AT_FDCWD) {
    path_to_statfs = full_path;
    char at_path[PATH_MAX];
    // fd must be a regular directory to which fcntl should succeed
    int r = fcntl(dir->fd, F_GETPATH, at_path);
    if (r != 0) {
      panic("fcntl failed");
    }
    if (snprintf(full_path, PATH_MAX, "%s/%s", at_path, path) >= PATH_MAX) {
      return -LINUX_ENAMETOOLONG;
    }
  } else {
    path_to_statfs = path;
  }

  struct statfs st;
  int r = syswrap(statfs(path_to_statfs, &st));
  if (r < 0)
    return r;
  statfs_darwin_to_linux(&st, buf);
  return r;
}


int
darwinfs_fchownat(struct fs *fs, struct dir *dir, const char *path, l_uid_t uid, l_gid_t gid, int l_flags)
{
  /*
   * Who may. Only root gives a file to another user; an owner may change the
   * group, but only to one they belong to. Anything else is EPERM, which is
   * what chown returns rather than EACCES.
   */
  if (!cred_is_root()) {
    struct stat dst;
    struct l_newstat st;
    bool nf = (l_flags & LINUX_AT_SYMLINK_NOFOLLOW) != 0;
    if (fstatat(dir->fd, path, &dst, nf ? AT_SYMLINK_NOFOLLOW : 0) < 0)
      return -darwin_to_linux_errno(errno);
    stat_darwin_to_linux(&dst, &st);
    guest_owner_overlay(dir->fd, path, nf, &st);
    guest_mode_overlay(dir->fd, path, nf, &st);
    l_uid_t euid;
    pthread_rwlock_rdlock(&proc.cred.lock);
    euid = proc.cred.euid;
    pthread_rwlock_unlock(&proc.cred.lock);
    if (st.st_uid != euid)
      return -LINUX_EPERM;
    if (uid != (l_uid_t) -1 && uid != st.st_uid)
      return -LINUX_EPERM;
    if (gid != (l_gid_t) -1 && !guest_in_group(gid))
      return -LINUX_EPERM;
  }
  /* Recorded rather than performed: the host has one account and no way to
   * hand a file to another, so this is the only place the guest's answer can
   * live. See "Guest ownership" above. */
  return guest_owner_record(dir->fd, path,
                            (l_flags & LINUX_AT_SYMLINK_NOFOLLOW) != 0,
                            uid, gid);
}

int
darwinfs_fchmodat(struct fs *fs, struct dir *dir, const char *path, l_mode_t mode)
{
  /* Only the owner may change a file's mode, and only root may do it to
   * somebody else's. Nothing else in the check is about permission bits, so
   * this one is spelled out rather than routed through cred_may. */
  if (!cred_is_root()) {
    struct stat dst;
    struct l_newstat st;
    if (fstatat(dir->fd, path, &dst, 0) < 0)
      return -darwin_to_linux_errno(errno);
    stat_darwin_to_linux(&dst, &st);
    guest_owner_overlay(dir->fd, path, false, &st);
    guest_mode_overlay(dir->fd, path, false, &st);
    l_uid_t euid;
    pthread_rwlock_rdlock(&proc.cred.lock);
    euid = proc.cred.euid;
    pthread_rwlock_unlock(&proc.cred.lock);
    if (st.st_uid != euid)
      return -LINUX_EPERM;
  }
  /* Recorded, not applied verbatim. A mode that denies its own owner would
   * lock nabi out of a file the guest may still use - `chmod 4111 sudo` is the
   * ordinary case - so the guest's answer is kept beside the file and the host
   * gets one that can be worked with. See "Guest mode" above. */
  return guest_mode_record(dir->fd, path, false, mode);
}

#define LOOKUP_NOFOLLOW   0x0001
#define LOOKUP_DIRECTORY  0x0002
/* #define LOOKUP_CONTINUE   0x0004 */
/* #define LOOKUP_AUTOMOUNT  0x0008 */
/* #define LOOKUP_PARENT     0x0010 */
/* #define LOOKUP_REVAL      0x0020 */

#define LOOP_MAX 20

/*
 * Absolute guest paths that are deliberately the *host's*, not the rootfs's.
 *
 * This is what lets a guest see the Mac's files - much of the point of the thing
 * - and it means `-m <root>` is a filesystem root, not a sandbox. Anything not
 * listed here resolves inside the rootfs.
 *
 * Matched a whole component at a time. A plain prefix test also catches
 * `/tmpmark`, `/devices` or `/private-key`, which are ordinary guest paths that
 * would then be looked up on the host instead: the guest's own file becomes
 * invisible and a host file of that name is exposed in its place.
 */
static const char *const host_passthrough[] = {
  "/Users", "/Volumes", "/dev", "/tmp", "/private",
  /*
   * The Data volume, because a passed-through path may be a host symlink and
   * NABI resolves symlink targets in the *guest's* namespace. /tmp is already
   * such a case - it is a symlink to /private/tmp, which is why /private is
   * above - and mSL/FHS's root entries are all of this shape: /boot points at
   * /System/Volumes/Data/boot, /home at .../home, and so on. Without the
   * target's prefix listed too, following one lands inside the rootfs, where
   * /System does not exist, and the lookup fails.
   */
  "/System/Volumes/Data",
};

/*
 * Host paths that are passed through only when the host actually provides them.
 *
 * These are the directories mSL/FHS puts at the root, and they divide by what
 * kind of thing they are:
 *
 *   /proc, /sys are mount points FHS declares in /etc/synthetic.conf for its
 *     sibling modules to mount on. Their contents are synthesised per-process
 *     by a real filesystem - a directory of files describing the machine's live
 *     state is not something that can be unpacked from a .deb - so when one is
 *     mounted, the host's is the only true answer. Being *mounted* is the test,
 *     because FHS creates these as empty directories at boot whether or not the
 *     module that fills them is installed, and an empty /proc passed through
 *     would mask the rootfs's own while claiming to answer a question we
 *     cannot.
 *
 * What is deliberately not here is the rest of what FHS names - /home, /run,
 * /root, /media, /mnt, /srv. Those are host directories that already have a
 * macOS path, and a rootfs has its own legitimate claim on them; /home in
 * particular must stay the rootfs's own, or the guest's shell reads the host's
 * dotfiles and arrives wearing the host's prompt.
 *
 * /boot used to be here too, on the reasoning that FHS owns the real one and a
 * rootfs cannot know what this machine boots. That was answering a different
 * question from the one a guest asks. A Linux distribution reading /boot wants
 * its own kernel, its own System.map, its own grub.cfg - not the kernel
 * collections macOS boots - and passing the host's through gave a wrong answer
 * to that question while making the right one unreachable:
 *
 *   - Arch Linux ARM ships a kernel, an initramfs and a tree of device trees in
 *     the tarball, and the guest could not see any of it.
 *   - `apt-get install linux-image-arm64` stopped at "unable to create
 *     /boot/System.map-...dpkg-new: Permission denied", because dpkg was
 *     writing into the host's /boot as an ordinary account. A guest package
 *     manager installing a Linux kernel into the Mac's boot directory would
 *     have been worse than the failure.
 *
 * So the guest keeps its own /boot unconditionally. Nothing NABI does boots
 * anything, and the files there are read - by initramfs hooks, by os-prober, by
 * postinsts - rather than executed.
 */
static const struct {
  const char *path;
  bool needs_mount;        /* mounted, vs merely present */
} optional_passthrough[] = {
  { "/proc", true  },
  { "/sys",  true  },
};
#define NR_OPTIONAL (sizeof optional_passthrough / sizeof optional_passthrough[0])
static bool optional_live[NR_OPTIONAL];
static bool passthrough_ignored;

/*
 * Probed rather than inherited, so it has to run on *both* ways into a process:
 * init_fileinfo for a fresh one, and resume_main for a child, since arm64's fork
 * is fork + exec and the child does not go through init_fileinfo at all. Miss
 * the second and the effect is a puzzle - `bash -c 'cat /proc/version'` works
 * because bash execs a lone command directly, while adding a second command
 * makes it fork first and the same read fails.
 *
 * Checked once at startup: mounting procfs later needs a new nabi, which is the
 * honest behaviour for a decision made this early in path resolution.
 */
void
init_host_passthrough(void)
{
  /*
   * NABI_IGNORE_HOST_FS pretends the sibling modules are not installed.
   *
   * Everything here is optional by construction, but on a machine that has FHS
   * and ProcFS there is otherwise no way to exercise the path where it does
   * not - and "degrades gracefully" is a claim worth being able to run rather
   * than assert. The smoke tests use it for exactly that.
   */
  bool ignore = getenv("NABI_IGNORE_HOST_FS") != NULL;

  for (size_t i = 0; i < NR_OPTIONAL; i++) {
    const char *path = optional_passthrough[i].path;
    if (ignore) {
      optional_live[i] = false;
    } else if (optional_passthrough[i].needs_mount) {
      struct statfs sfs;
      /* f_mntonname naming the path itself is what distinguishes a mount point
       * from a directory that merely exists on the parent's filesystem. */
      optional_live[i] = statfs(path, &sfs) == 0 &&
                         strcmp(sfs.f_mntonname, path) == 0;
    } else {
      struct stat st;
      optional_live[i] = stat(path, &st) == 0 && S_ISDIR(st.st_mode);
    }
  }
  passthrough_ignored = ignore;
}

/*
 * Say what the probe decided.
 *
 * Separate from the probe itself because that has to run before any path is
 * resolved, which is before the debug sinks exist - anything it logged would go
 * nowhere. Called once main has opened them. A resumed child does not report:
 * it parses no options, has no sinks, and its answer is the parent's anyway.
 */
void
report_host_passthrough(void)
{
  for (size_t i = 0; i < NR_OPTIONAL; i++)
    warnk("host filesystem: %s %s\n", optional_passthrough[i].path,
          optional_live[i] ? "passed through"
                           : (passthrough_ignored
                                ? "ignored (NABI_IGNORE_HOST_FS)"
                                : "not provided by the host"));
}

static bool
match_component(const char *name, const char *prefix)
{
  size_t n = strlen(prefix);
  return strncmp(name, prefix, n) == 0 && (name[n] == '\0' || name[n] == '/');
}

static bool
is_host_passthrough(const char *name)
{
  for (size_t i = 0; i < sizeof host_passthrough / sizeof host_passthrough[0]; i++) {
    if (match_component(name, host_passthrough[i]))
      return true;
  }
  for (size_t i = 0; i < NR_OPTIONAL; i++) {
    if (optional_live[i] && match_component(name, optional_passthrough[i].path))
      return true;
  }
  return false;
}

/*
 * Whether a descriptor names the guest's root directory.
 *
 * By what it points at, not by its number. A guest that opens "/" for itself
 * gets an ordinary descriptor, and comparing that against the one nabi keeps
 * would say no about the very same directory - which is how systemd, holding
 * its own handle on the root, still walked ".." straight out of the rootfs.
 *
 * The root's identity cannot change while a guest runs, so it is looked up
 * once. Lazily, because a resumed child rebuilds its descriptor table from a
 * checkpoint and this file's statics start empty again.
 */
static bool
dir_is_rootfs(int fd)
{
  static dev_t root_dev;
  static ino_t root_ino;
  static bool known;

  if (fd == proc.fileinfo.rootfd)
    return true;
  if (fd == AT_FDCWD)
    return false;

  if (!known) {
    struct stat rst;
    if (fstat(proc.fileinfo.rootfd, &rst) < 0)
      return false;
    root_dev = rst.st_dev;
    root_ino = rst.st_ino;
    known = true;
  }

  struct stat st;
  if (fstat(fd, &st) < 0)
    return false;
  return st.st_dev == root_dev && st.st_ino == root_ino;
}

int
resolve_path(const struct dir *parent, const char *name, int flags, struct path *path, int loop)
{
  static struct fs_operations ops = {
    darwinfs_openat,
    darwinfs_symlinkat,
    darwinfs_faccessat,
    darwinfs_renameat,
    darwinfs_linkat,
    darwinfs_unlinkat,
    darwinfs_readlinkat,
    darwinfs_mkdirat,
    darwinfs_fstatat,
    darwinfs_statfs,
    darwinfs_fchownat,
    darwinfs_fchmodat,
  };
  static struct fs darwinfs = {
    .ops = &ops,
  };
  struct fs *fs = &darwinfs;

  if (loop > LOOP_MAX)
    return -LINUX_ELOOP;

  path->rdonly = false;
  struct dir dir = *parent;
  /* Both outlive the branch below, since `name` may be made to point at one. */
  char ptsname[32];
  char procpath[PATH_MAX];
  int procfd;

  /* resolve mountpoints */
  char mntpath[PATH_MAX];
  char pidpath[PATH_MAX];       /* separate: mount_resolve reads what this wrote */
  if (*name == '/') {
    if (name[1] == '\0') {
      dir.fd = proc.fileinfo.rootfd;
      strcpy(path->subpath, ".");
      goto out;
    }
    /*
     * A mount comes first, because that is what mounting means: whatever the
     * path would otherwise have reached, the mount is now in front of it. The
     * table gives a host path, so from here it is handled exactly like a
     * passthrough - the machinery for "this absolute name is already a host
     * name" is the same machinery a bind mount needs.
     */
    /* A pid namespace renumbers /proc's per-process directories; a number that
     * names nobody in it is refused rather than passed to the host. */
    bool pid_denied = false;
    if (procfs_pidns_path(name, pidpath, sizeof pidpath, &pid_denied)) {
      if (pid_denied)
        return -LINUX_ENOENT;
      name = pidpath;
    }

    if (mount_resolve(name, mntpath, sizeof mntpath, &path->rdonly)) {
      name = mntpath;
    } else if (!is_host_passthrough(name)) {
      dir.fd = proc.fileinfo.rootfd;
      name++;
    } else if ((procfd = procfs_fd_number(name)) >= 0 &&
               in_userfd(procfd) &&
               fcntl(procfd, F_GETPATH, procpath) == 0) {
      /* /proc/self/fd/<n> naming a file the guest has open. Every operation
       * other than opening it - chmod, chown, stat, rename - has to reach the
       * file itself, and the host's /proc knows nothing of the guest's
       * descriptors. F_GETPATH turns the one into the other. */
      name = procpath;
    } else if (devpts_to_host(name, ptsname, sizeof ptsname)) {
      /* /dev is a passthrough, so a guest that asks for the slave it was just
       * told about would reach the host's /dev/pts/<n>, which does not exist:
       * Darwin has no devpts. The name is rewritten here rather than in
       * openat because stat has to find it too - glibc's ptsname_r stats the
       * path it is about to return, and reports the failure as if TIOCGPTN
       * had failed. */
      name = ptsname;
    }
  }

  /*
   * Whether ".." may be followed out of the top of this walk.
   *
   * It may not, when the walk starts at the guest's root: on Linux "/.." is
   * "/", the kernel pins it, and a guest cannot climb out of its own
   * filesystem. Here the host resolves the component, so it climbed straight
   * out of the rootfs - `stat /..` gave a different inode from `stat /`, and
   * `ls /../..` reached the host's /Volumes.
   *
   * That is a containment hole on its own, and it also broke software that
   * checks the invariant. systemd's chaseat() returns an absolute path when the
   * descriptor it walked from is the root, and decides that by asking whether
   * ".." leads back to the same directory. Told no, it returned a relative path
   * with root "/", which chaseat_prefix_root refuses as impossible - so every
   * rpm %sysusers scriptlet failed with "Failed to prefix '...' with root '/':
   * Invalid argument", and dnf reported a failed transaction for packages that
   * had installed perfectly.
   *
   * Only for a walk rooted at the rootfs. A walk from a descriptor the guest
   * passed to openat starts somewhere below, and how far below is not known
   * here, so those are left to the host as before.
   */
  /* A passthrough path keeps its leading slash, because it is a host path and
   * is meant to stay one; everything else is being built relative to a
   * descriptor and must not acquire one. */
  bool leading_slash = *name == '/';

  /* resolve symlinks */
  char *sp = path->subpath;
  *sp = 0;
  const char *c = name;
  assert(*c);
  while (*c) {
    char *component = sp;
    while (*c && *c != '/') {
      *sp++ = *c++;
    }
    *sp = 0;

    /*
     * "." and ".." are folded here rather than before the walk, because on
     * Linux they apply to what the path has resolved to so far - and a symlink
     * earlier in it has already been expanded by the time we arrive. Folding
     * the whole string up front would take "link/.." to nothing instead of to
     * the parent of the link's target.
     */
    if (sp - component == 1 && component[0] == '.') {
      sp = component;                       /* "." is nothing at all */
      *sp = 0;
    } else if (sp - component == 2 &&
               component[0] == '.' && component[1] == '.') {
      if (component == path->subpath) {
        /* At the top. Linux stays put; the host would leave the rootfs. Asked
         * here rather than once up front because it costs a stat, and a path
         * with ".." on its front is rare. */
        if (dir_is_rootfs(dir.fd)) {
          sp = component;
          *sp = 0;
        }
      } else {
        sp = component;
        if (sp > path->subpath && sp[-1] == '/')
          sp--;                             /* the separator before ".." */
        while (sp > path->subpath && sp[-1] != '/')
          sp--;                             /* and the component before it */
        if (sp > path->subpath && sp[-1] == '/')
          sp--;
        *sp = 0;
      }
    }
    if ((flags & LOOKUP_NOFOLLOW) == 0) {
      char buf[LINUX_PATH_MAX];
      int n;
      if ((n = fs->ops->readlinkat(fs, &dir, path->subpath, buf, sizeof buf)) > 0) {
        strcpy(buf + n, c);
        if (buf[0] == '/') {
          return resolve_path(&dir, buf, flags, path, loop + 1);
        } else {
          /* remove the last component */
          while (sp >= path->subpath && *--sp != '/')
            ;
          *++sp = 0;
          char buf2[LINUX_PATH_MAX];
          strcpy(buf2, path->subpath);
          strcat(buf2, buf);
          return resolve_path(&dir, buf2, flags, path, loop + 1);
        }
      }
    }
    /*
     * Search permission on every directory walked through.
     *
     * Without this the rest of the checks are a formality: a file may be
     * readable by everybody and still sit inside a directory that is not, and
     * on Linux the directory decides. /root is 0700, and whatever is under it
     * is out of reach whatever its own mode says.
     *
     * One stat per component, and only for a guest that is not root - which is
     * the whole reason cred_is_root is asked first rather than inside
     * permit_at.
     */
    /* subpath is empty for the leading slash of an absolute passthrough path,
     * where the first component boundary arrives before any characters have
     * been copied. There is no directory to rule on yet. */
    if (*c == '/' && path->subpath[0] != '\0' && !cred_is_root()) {
      int r = permit_at(dir.fd, path->subpath, false, WANT_X, false);
      if (r < 0)
        return r;
    }
    if (*c) {
      /*
       * Only between components, and only for a path being built relative to
       * the rootfs descriptor. Folding may have emptied that - "/.." is the
       * whole of it - and a separator on the front would turn it back into an
       * absolute path.
       *
       * A passthrough path is the opposite case: it keeps its leading slash,
       * because it is a host path and is meant to be. Suppressing that turned
       * /dev/null into dev/null and the guest lost its /dev.
       */
      if (sp > path->subpath || leading_slash)
        *sp++ = *c;
      c++;
    }
    *sp = 0;
  }

  /* Everything folded away, which is the root itself. openat has no name for
   * that; "." is how it is spelled. */
  if (path->subpath[0] == '\0')
    strcpy(path->subpath, ".");

 out:
  path->fs = fs;
  path->dir = malloc(sizeof(struct dir));
  path->dir->fd = dir.fd;
  return 0;
}

int
vfs_grab_dir(int dirfd, const char *name, int flags, struct path *path)
{
  struct dir dir;

  if (flags & ~(LOOKUP_NOFOLLOW | LOOKUP_DIRECTORY)) {
    return -LINUX_EINVAL;
  }

  if (*name == 0) {
    return -LINUX_ENOENT;
  }

  /*
   * An absolute path makes the directory descriptor irrelevant, and Linux does
   * not look at it at all - not even to check that it is open. Checking it here
   * first is what made `openat(-1, "/", ...)` EBADF, and rpm opens the root
   * exactly that way before unpacking anything: the descriptor it then used for
   * every component came back -1, so `dnf install` reported "failed to open dir
   * usr of /usr/bin/: cpio: open failed - Bad file descriptor" about a
   * directory that was there all along.
   *
   * resolve_path replaces the directory with the rootfs for an absolute name
   * regardless, so nothing downstream depends on what is put here.
   */
  if (dirfd == LINUX_AT_FDCWD || *name == '/') {
    dir.fd = AT_FDCWD;
  } else {
    dir.fd = dirfd;
    if (!in_userfd(dir.fd)) {
      return -LINUX_EBADF;
    }
  }
  return resolve_path(&dir, name, flags, path, 0);
}

void vfs_ungrab_dir(struct path *path);

/*
 * Resolve a name that is about to be written through.
 *
 * The read-only check is here rather than at each caller so that the policy is
 * stated once: every operation that modifies a file or a directory goes through
 * this, and one that forgot would be a read-only mount that was not.
 */
static int
vfs_grab_dir_w(int dirfd, const char *name, int flags, struct path *path)
{
  int r = vfs_grab_dir(dirfd, name, flags, path);
  if (r < 0)
    return r;
  if (path->rdonly) {
    vfs_ungrab_dir(path);
    return -LINUX_EROFS;
  }
  return 0;
}

void
vfs_ungrab_dir(struct path *path)
{
  free(path->dir);
}

static int
do_openat(int dirfd, const char *name, int flags, int mode)
{
  int lkflag = 0;
  if (flags & LINUX_O_NOFOLLOW) {
    lkflag |= LOOKUP_NOFOLLOW;
  }
  if (flags & LINUX_O_DIRECTORY) {
    lkflag |= LOOKUP_DIRECTORY;
  }

  /* Opening for write, creating, or truncating is a write; opening to read is
   * not, and a read-only mount must still be readable. */
  bool writes = (flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY ||
                (flags & (LINUX_O_CREAT | LINUX_O_TRUNC));

  struct path path;
  int r = writes ? vfs_grab_dir_w(dirfd, name, lkflag, &path)
                 : vfs_grab_dir(dirfd, name, lkflag, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->openat(path.fs, path.dir, path.subpath, flags, mode);
  vfs_ungrab_dir(&path);
  return r;
}

int
vkern_openat(int atdirfd, const char *name, int flags, int mode)
{
  int ret;

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd = do_openat(atdirfd, name, flags, mode);
  if (fd < 0) {
    ret = fd;
    goto out;
  }
  ret = vkern_dup_fd(fd, flags & LINUX_O_CLOEXEC);
  close(fd);

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

int
vkern_open(const char *path, int l_flags, int mode)
{
  return vkern_openat(LINUX_AT_FDCWD, path, l_flags, mode);
}

/*
 * A guest path that turns out to be a symlink into /proc.
 *
 * The files under /proc that describe the guest are NABI's to answer, and the
 * check for them is made on the name the guest passed. But /etc/mtab is a
 * symlink to /proc/self/mounts on every distribution now, so the name that
 * arrives is /etc/mtab, the check declines it, and resolution then follows the
 * link inside the rootfs - where /proc/self/mounts is not a file - and the open
 * fails with ENOENT. pacman reads /etc/mtab to find out which filesystem it is
 * unpacking into, and stopped at "could not determine filesystem mount points"
 * having downloaded everything it needed.
 *
 * One hop, deliberately. Distributions ship exactly one link here, and
 * following a chain would be re-implementing resolution rather than finishing
 * it - resolve_path already does that, in the guest's namespace, which is
 * exactly why it cannot see /proc.
 *
 * Writes the target as an absolute guest path with . and .. folded out, or
 * returns false if `name` is not a link or the target does not land in /proc.
 */
static bool
symlink_into_procfs(int dirfd, const char *name, char *out, size_t outsz)
{
  struct path path;
  if (vfs_grab_dir(dirfd, name, LOOKUP_NOFOLLOW, &path) < 0)
    return false;

  char target[LINUX_PATH_MAX];
  int n = path.fs->ops->readlinkat(path.fs, path.dir, path.subpath,
                                   target, sizeof target - 1);
  vfs_ungrab_dir(&path);
  if (n <= 0)
    return false;
  target[n] = '\0';

  /* Relative targets are relative to the link's own directory, so that is what
   * they are joined onto. */
  char joined[LINUX_PATH_MAX * 2];
  if (target[0] == '/') {
    snprintf(joined, sizeof joined, "%s", target);
  } else {
    const char *slash = strrchr(name, '/');
    int dirlen = slash ? (int)(slash - name) : 0;
    snprintf(joined, sizeof joined, "%.*s/%s", dirlen, name, target);
  }

  /* Fold . and .. textually. Every component here came from the guest's own
   * namespace, so there is no host path to leak by doing it this way. */
  char norm[LINUX_PATH_MAX];
  size_t len = 0;
  norm[0] = '\0';
  for (char *p = joined; *p; ) {
    while (*p == '/') p++;
    if (!*p) break;
    char *e = p;
    while (*e && *e != '/') e++;
    size_t clen = (size_t)(e - p);
    if (clen == 1 && p[0] == '.') {
      /* nothing */
    } else if (clen == 2 && p[0] == '.' && p[1] == '.') {
      while (len > 0 && norm[--len] != '/')
        ;
      norm[len] = '\0';
    } else {
      if (len + clen + 2 > sizeof norm)
        return false;
      norm[len++] = '/';
      memcpy(norm + len, p, clen);
      len += clen;
      norm[len] = '\0';
    }
    p = e;
  }
  if (len == 0)
    return false;

  if (strncmp(norm, "/proc/", 6) != 0)
    return false;
  if (strlcpy(out, norm, outsz) >= outsz)
    return false;
  return true;
}

/*
 * Where a guest path lives on the host.
 *
 * Almost nothing needs this: every ordinary file operation is done with an
 * *at() call against the resolved directory, which is both faster and free of
 * the races a rebuilt absolute path invites. AF_UNIX is the exception, because
 * bind(2) and connect(2) take a path inside a sockaddr and there is no
 * bindat(). Passing the guest's path through untranslated is what NABI did, so
 * a guest binding /etc/pacman.d/gnupg/S.gpg-agent asked the *host* for that
 * path, got ENOENT, and gpg-agent reported "error binding socket" - which is
 * why gpg could not start and pacman could not check a signature.
 *
 * F_GETPATH names the directory the resolver landed on, which is what turns a
 * dirfd back into something a sockaddr can carry. A passthrough path is already
 * a host path and is returned as it stands.
 */
int
guest_to_host_path(const char *name, char *out, size_t outsz)
{
  /*
   * A mount comes first, exactly as it does in resolve_path. Without this the
   * passthrough shortcut below answered for a path that had been mounted over -
   * so a cgroup made under /sys/fs/cgroup, which is a mount on top of a
   * passthrough, resolved to the host's /sys and was not recognised as a
   * cgroup at all.
   */
  if (name[0] == '/') {
    char mnt[PATH_MAX];
    if (mount_resolve(name, mnt, sizeof mnt, NULL)) {
      if (strlcpy(out, mnt, outsz) >= outsz)
        return -LINUX_ENAMETOOLONG;
      return 0;
    }
  }

  if (name[0] == '/' && is_host_passthrough(name)) {
    if (strlcpy(out, name, outsz) >= outsz)
      return -LINUX_ENAMETOOLONG;
    return 0;
  }

  struct path path;
  int r = vfs_grab_dir(LINUX_AT_FDCWD, name, LOOKUP_NOFOLLOW, &path);
  if (r < 0)
    return r;

  char dirpath[PATH_MAX];
  if (fcntl(path.dir->fd, F_GETPATH, dirpath) < 0) {
    vfs_ungrab_dir(&path);
    return -LINUX_ENOENT;
  }

  int n;
  if (strcmp(path.subpath, ".") == 0)
    n = snprintf(out, outsz, "%s", dirpath);
  else
    n = snprintf(out, outsz, "%s/%s", dirpath, path.subpath);
  vfs_ungrab_dir(&path);

  /* sun_path is 104 bytes on Darwin against Linux's 108, and the rootfs prefix
   * eats into that, so this is a limit a guest can genuinely reach. Saying so
   * beats a truncated path that binds somewhere unintended. */
  if (n < 0 || (size_t) n >= outsz)
    return -LINUX_ENAMETOOLONG;
  return 0;
}

int
vkern_open_exec(const char *path)
{
  loading_image = true;
  int fd = vkern_open(path, LINUX_O_RDONLY, 0);
  loading_image = false;
  return fd;
}

int
user_openat(int atdirfd, const char *name, int flags, int mode)
{
  int fd;
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  /* A few /proc files describe the guest rather than the nabi running it, and
   * only NABI can answer those. Anything else falls through to the host's. */
  if (procfs_open(name, &fd) < 0) {
    fd = do_openat(atdirfd, name, flags, mode);
    if (fd < 0) {
      char target[LINUX_PATH_MAX];
      if (symlink_into_procfs(atdirfd, name, target, sizeof target))
        procfs_open(target, &fd);
    }
  }
  if (fd < 0) {
    goto out;
  }
  if (inotify_watching() || fanotify_watching()) {
    char opath[PATH_MAX];
    struct stat ost;
    if (fcntl(fd, F_GETPATH, opath) == 0) {
      inotify_note_open(opath, fstat(fd, &ost) == 0 && S_ISDIR(ost.st_mode));
      /* fanotify sees the open itself, which is what it is for - and unlike
       * inotify's, this one is reported wherever the open happened. */
      fanotify_note(opath, LINUX_FAN_OPEN);
    }
  }
  int err = register_fd(fd, flags & LINUX_O_CLOEXEC);
  if (err < 0) {
    fd = err;
    close(fd);
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return fd;
}

int
user_open(const char *path, int l_flags, int mode)
{
  return user_openat(LINUX_AT_FDCWD, path, l_flags, mode);
}

int
do_close(struct fdtable *table, int fd)
{
  if (fd < table->start || fd >= table->start + table->size) {
    return -LINUX_EBADF;
  }
  if (!test_fdbit(table, table->open_fds, fd)) {
    return -LINUX_EBADF;
  }
  struct file *file = do_get_file(table, fd);
  if (file == NULL)
    return -LINUX_EBADF;
  int n = file->ops->close(file);
  clear_fdbit(table, table->open_fds, fd);
  clear_fdbit(table, table->cloexec_fds, fd);
  return n;
}

int
user_close(int fd)
{
  /*
   * IN_CLOSE_WRITE and IN_CLOSE_NOWRITE, which kqueue has no way to report -
   * the host cannot see a descriptor being closed. They are taken here, where
   * nabi already knows, and before the close so the path can still be found.
   * Both questions are asked only when something is watching.
   */
  if (inotify_watching() || fanotify_watching()) {
    char path[PATH_MAX];
    if (fcntl(fd, F_GETPATH, path) == 0) {
      int fl = fcntl(fd, F_GETFL);
      bool wrote = fl >= 0 && ((fl & O_ACCMODE) == O_WRONLY ||
                               (fl & O_ACCMODE) == O_RDWR);
      inotify_note_close(path, wrote);
      fanotify_note(path, wrote ? LINUX_FAN_CLOSE_WRITE
                                : LINUX_FAN_CLOSE_NOWRITE);
    }
  }
  /* And a notification descriptor of the guest's own takes its queue with it. */
  inotify_close(fd);
  fanotify_close(fd);

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = do_close(&proc.fileinfo.fdtable, fd);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

int
vkern_close(int fd)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int n = do_close(&proc.fileinfo.vkern_fdtable, fd);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return n;
}

void
close_cloexec()
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  struct fdtable *fdtable = &proc.fileinfo.fdtable;
  for (int i = 0; i < fdtable->size / 64; i++) {
    for (int j = 0; j < 64; j++) {
      if (fdtable->cloexec_fds[i] == 0) {
        break;
      }
      if ((fdtable->cloexec_fds[i] >> j) & 1) {
        do_close(fdtable, j + i * 64);
      }
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
}

DEFINE_SYSCALL(openat, int, dirfd, gstr_t, path_ptr, int, flags, int, mode)
{
  char path[LINUX_PATH_MAX];
  strncpy_from_user(path, path_ptr, sizeof path);
  return user_openat(dirfd, path, flags, mode);
}

DEFINE_SYSCALL(open, gstr_t, path_ptr, int, flags, int, mode)
{
  return sys_openat(LINUX_AT_FDCWD, path_ptr, flags, mode);
}

DEFINE_SYSCALL(close, int, fd)
{
  return user_close(fd);
}

DEFINE_SYSCALL(creat, gstr_t, path_ptr, int, mode)
{
  return sys_open(path_ptr, LINUX_O_CREAT | LINUX_O_TRUNC | LINUX_O_WRONLY, mode);
}

DEFINE_SYSCALL(symlinkat, gstr_t, path1_ptr, int, dirfd, gstr_t, path2_ptr)
{
  char path1[LINUX_PATH_MAX], path2[LINUX_PATH_MAX];

  strncpy_from_user(path1, path1_ptr, sizeof path1);
  strncpy_from_user(path2, path2_ptr, sizeof path2);

  struct path path;
  int r = vfs_grab_dir_w(dirfd, path2, 0, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->symlinkat(path.fs, path1, path.dir, path.subpath);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(symlink, gstr_t, path1_ptr, gstr_t, path2_ptr)
{
  return sys_symlinkat(path1_ptr, LINUX_AT_FDCWD, path2_ptr);
}

/*
 * The AT_EMPTY_PATH form: an empty pathname naming the descriptor itself.
 *
 * The descriptor may be any kind of file, not just a directory, so it cannot
 * go through vfs_grab_dir - which rejects an empty name with ENOENT, and that
 * is exactly what went wrong. Rust's standard library stats every file it
 * opens as statx(fd, "", AT_EMPTY_PATH), so sqv opened apt's signature file
 * successfully and then reported "Reading /tmp/apt.sig.XXXXXX: No such file or
 * directory" about a descriptor it was already holding. apt read that as the
 * Debian archive being unsigned. The error named the right file and the wrong
 * reason, which is why it survived so long.
 *
 * Returns 0 and fills st, or a negative errno. Callers only reach it once they
 * have decided the flags and path say so.
 */
static int
fstat_by_fd(int dirfd, struct l_newstat *st)
{
  struct file *file = get_file(dirfd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fstat(file, st);
}

static inline bool
is_at_empty_path(const char *path, int flags)
{
  return (flags & LINUX_AT_EMPTY_PATH) != 0 && path[0] == '\0';
}

DEFINE_SYSCALL(newfstatat, int, dirfd, gstr_t, path_ptr, gaddr_t, st_ptr, int, flags)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  if (flags & ~(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH)) {
    return -LINUX_EINVAL;
  }
  struct l_newstat st;
  int r;

  /* A /proc entry nabi serves itself, which the host has no file for. */
  {
    uint32_t mode; uint64_t size, ino;
    if (procfs_stat(pathname, &mode, &size, &ino)) {
      memset(&st, 0, sizeof st);
      st.st_mode = mode;
      st.st_size = (l_off_t) size;
      st.st_ino = ino;
      st.st_nlink = 1;
      st.st_blksize = 4096;
      if (copy_to_user(st_ptr, &st, sizeof st))
        return -LINUX_EFAULT;
      return 0;
    }
  }

  if (is_at_empty_path(pathname, flags) && dirfd != LINUX_AT_FDCWD) {
    r = fstat_by_fd(dirfd, &st);
  } else {
    /* AT_FDCWD with an empty path is the working directory. */
    if (is_at_empty_path(pathname, flags))
      strcpy(pathname, ".");
    int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
    struct path path;
    r = vfs_grab_dir(dirfd, pathname, grab_flags, &path);
    if (r < 0) {
      return r;
    }
    r = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st, flags);
    vfs_ungrab_dir(&path);
  }
  if (0 <= r && copy_to_user(st_ptr, &st, sizeof st))
    return -LINUX_EFAULT;
  return r;
}

/*
 * statx is what modern glibc/musl route stat()/lstat()/fstatat() through. It
 * reuses the same fstatat fs op as newfstatat and then repacks the arch-specific
 * struct l_newstat into the fixed struct l_statx (field-for-field, all names are
 * common to both stat layouts). Only the SYMLINK_NOFOLLOW lookup flag is honored
 * from `flags` besides AT_EMPTY_PATH; the AT_STATX_* sync hints are not, and `mask`
 * is advisory - we always return the STATX_BASIC_STATS set. btime is not filled.
 */
DEFINE_SYSCALL(statx, int, dirfd, gstr_t, path_ptr, int, flags, unsigned int, mask, gaddr_t, stx_ptr)
{
  char pathname[LINUX_PATH_MAX];
  if (strncpy_from_user(pathname, path_ptr, sizeof pathname) < 0)
    return -LINUX_EFAULT;

  struct l_newstat st;
  int r;

  /* Same as newfstatat: an entry nabi serves itself has no host file behind it.
   * Hooked here too because a current coreutils calls statx and never
   * newfstatat, so `ls /proc/self/ns` failed while `stat` through the other
   * path would have worked. */
  bool served = false;
  {
    uint32_t pmode; uint64_t psize, pino;
    if (procfs_stat(pathname, &pmode, &psize, &pino)) {
      memset(&st, 0, sizeof st);
      st.st_mode = pmode;
      st.st_size = (off_t) psize;
      st.st_ino = pino;
      st.st_nlink = 1;
      st.st_blksize = 4096;
      /* Guest-side already, like everything the filesystem path produces -
       * see the assignment of stx_uid below, which no longer converts. */
      st.st_uid = host_uid_to_guest(geteuid());
      st.st_gid = host_gid_to_guest(getegid());
      served = true;
      r = 0;
    }
  }

  if (!served && is_at_empty_path(pathname, flags)) {
    /* AT_FDCWD names the working directory rather than a descriptor. */
    if (dirfd == LINUX_AT_FDCWD)
      strcpy(pathname, ".");
    else
      r = fstat_by_fd(dirfd, &st);
  }
  if (!served && (!is_at_empty_path(pathname, flags) || dirfd == LINUX_AT_FDCWD)) {
    int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
    struct path path;
    r = vfs_grab_dir(dirfd, pathname, grab_flags, &path);
    if (r < 0)
      return r;
    r = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st,
                              flags & LINUX_AT_SYMLINK_NOFOLLOW);
    vfs_ungrab_dir(&path);
  }
  if (r < 0)
    return r;

  struct l_statx stx;
  memset(&stx, 0, sizeof stx);
  /*
   * The mount is reported as well as the basic set, because the alternative is
   * worse than not answering.
   *
   * Software that wants to know whether two paths are on the same mount asks
   * statx for STATX_MNT_ID first and falls back to name_to_handle_at when the
   * answer is missing - which Darwin has nothing to implement, so it is
   * ENOSYS, which is fatal where EOPNOTSUPP would not have been. systemd's
   * sysusers stopped there with "Failed to load user database: Function not
   * implemented", and every rpm %sysusers scriptlet failed with it.
   *
   * st_dev is the identifier to give. It is exactly what a mount id means here
   * - one number per filesystem, equal for two files on the same one - and it
   * agrees with the stx_dev_major/minor pair reported beside it, which is the
   * fallback comparison anything doing this uses anyway.
   */
  stx.stx_mask       = LINUX_STATX_BASIC_STATS | LINUX_STATX_MNT_ID;
  stx.stx_mnt_id     = (uint64_t) st.st_dev;
  stx.stx_blksize    = st.st_blksize;
  stx.stx_nlink      = st.st_nlink;
  /*
   * Taken as they are. `st` is an l_newstat that the filesystem path has
   * already put through host_uid_to_guest, the ownership overlay and the user
   * namespace, so converting again here would be a second translation of an
   * id that had been translated once. That was harmless while the conversion
   * was its own inverse for everything but one account; with a user namespace
   * in the way it stopped being, and every file read back as nobody inside one.
   */
  stx.stx_uid        = st.st_uid;
  stx.stx_gid        = st.st_gid;
  stx.stx_mode       = st.st_mode;
  stx.stx_ino        = st.st_ino;
  stx.stx_size       = st.st_size;
  stx.stx_blocks     = st.st_blocks;
  stx.stx_atime.tv_sec  = st.st_atim.tv_sec;  stx.stx_atime.tv_nsec = st.st_atim.tv_nsec;
  stx.stx_mtime.tv_sec  = st.st_mtim.tv_sec;  stx.stx_mtime.tv_nsec = st.st_mtim.tv_nsec;
  stx.stx_ctime.tv_sec  = st.st_ctim.tv_sec;  stx.stx_ctime.tv_nsec = st.st_ctim.tv_nsec;
  stx.stx_rdev_major = major(st.st_rdev);  stx.stx_rdev_minor = minor(st.st_rdev);
  stx.stx_dev_major  = major(st.st_dev);   stx.stx_dev_minor  = minor(st.st_dev);

  if (copy_to_user(stx_ptr, &stx, sizeof stx))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(stat, gstr_t, path, gaddr_t, st)
{
  return sys_newfstatat(LINUX_AT_FDCWD, path, st, 0);
}

DEFINE_SYSCALL(lstat, gstr_t, path, gaddr_t, st)
{
  return sys_newfstatat(LINUX_AT_FDCWD, path, st, LINUX_AT_SYMLINK_NOFOLLOW);
}

DEFINE_SYSCALL(fchownat, int, dirfd, gstr_t, path_ptr, l_uid_t, user, l_gid_t, group, int, flags)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  if (flags & ~(LINUX_AT_SYMLINK_NOFOLLOW)) {
    return -LINUX_EINVAL;
  }
  /*
   * The ids the guest names are its namespace's, so they come back out to the
   * ones the rest of nabi works in. An id the map does not cover has no outside
   * equivalent at all, and Linux answers that with EINVAL rather than picking
   * something - which is the only safe answer, since the alternative is
   * chowning a file to an id the caller cannot name.
   */
  uint32_t out_uid = (uint32_t) -1, out_gid = (uint32_t) -1;
  if (user != (l_uid_t) -1) {
    if (!userns_uid_outward(user, &out_uid))
      return -LINUX_EINVAL;
    user = (l_uid_t) out_uid;
  }
  if (group != (l_gid_t) -1) {
    if (!userns_gid_outward(group, &out_gid))
      return -LINUX_EINVAL;
    group = (l_gid_t) out_gid;
  }

  int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
  struct path path;
  int r = vfs_grab_dir_w(dirfd, pathname, grab_flags, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->fchownat(path.fs, path.dir, path.subpath, user, group, flags);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(chown, gstr_t, path, int, uid, int, gid)
{
  return sys_fchownat(LINUX_AT_FDCWD, path, uid, gid, 0);
}

DEFINE_SYSCALL(lchown, gstr_t, path, int, uid, int, gid)
{
  return sys_fchownat(LINUX_AT_FDCWD, path, uid, gid, LINUX_AT_SYMLINK_NOFOLLOW);
}

DEFINE_SYSCALL(fchmodat, int, dirfd, gstr_t, path_ptr, l_mode_t, mode)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  struct path path;
  int r = vfs_grab_dir_w(dirfd, pathname, 0, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->fchmodat(path.fs, path.dir, path.subpath, mode);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(chmod, gstr_t, path, int, mode)
{
  return sys_fchmodat(LINUX_AT_FDCWD, path, mode);
}

DEFINE_SYSCALL(statfs, gstr_t, path_ptr, gaddr_t, buf_ptr)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  struct path path;
  int r = vfs_grab_dir(LINUX_AT_FDCWD, pathname, 0, &path);
  if (r < 0) {
    return r;
  }
  struct l_statfs st;
  r = path.fs->ops->statfs(path.fs, path.dir, path.subpath, &st);
  vfs_ungrab_dir(&path);
  if (0 <= r && copy_to_user(buf_ptr, &st, sizeof st))
    return -LINUX_EFAULT;
  return r;
}

int
do_faccessat(int dirfd, const char *name, int mode, int flags)
{
  struct path path;
  int lkflags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
  int r = vfs_grab_dir(dirfd, name, lkflags, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->faccessat(path.fs, path.dir, path.subpath, mode, flags);
  vfs_ungrab_dir(&path);
  return r;
}

int do_access(const char *path, int mode)
{
  return do_faccessat(LINUX_AT_FDCWD, path, mode, 0);
}

DEFINE_SYSCALL(faccessat, int, dirfd, gstr_t, path_ptr, int, mode)
{
  char path[LINUX_PATH_MAX];
  if (strncpy_from_user(path, path_ptr, sizeof path) < 0)
    return -LINUX_EFAULT;
  return do_faccessat(dirfd, path, mode, 0);
}

/*
 * Defined only where the syscall table reaches it. x86-64 numbers faccessat2
 * 439 and this tree's x86 table stops at 332; padding a hundred unimplemented
 * rows into a build that exists as a reference (see PORTING-arm64.md §7) buys
 * nothing. The body is arch-neutral and moves over with the table when it grows.
 */
#if defined(__arm64__) || defined(__aarch64__)
/*
 * faccessat2 is faccessat with the flags the older call could not carry, and
 * glibc reaches for it first for anything that needs AT_EACCESS - "may the
 * *effective* user do this", which is what a program asks when it has changed
 * identity and wants to know what it can still touch.
 *
 * Unimplemented it returned ENOSYS, and glibc's fallback is not a syscall: it
 * works the answer out in userspace from the file's mode and owner against the
 * ids it believes it has. Under NABI those ids are the guest's, so a process
 * that had dropped to an unprivileged account decided it could not write
 * directories it could in fact write. sqv, run by apt as _apt, concluded it had
 * nowhere to put its working files and answered "No good signature" for every
 * repository - while the same binary as root verified them all.
 */
DEFINE_SYSCALL(faccessat2, int, dirfd, gstr_t, path_ptr, int, mode, int, flags)
{
  char path[LINUX_PATH_MAX];
  if (strncpy_from_user(path, path_ptr, sizeof path) < 0)
    return -LINUX_EFAULT;
  if (flags & ~(LINUX_AT_EACCESS | LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH))
    return -LINUX_EINVAL;
  return do_faccessat(dirfd, path, mode, flags);
}
#endif

DEFINE_SYSCALL(access, gstr_t, path_ptr, int, mode)
{
  return sys_faccessat(LINUX_AT_FDCWD, path_ptr, mode);
}

DEFINE_SYSCALL(renameat, int, oldfd, gstr_t, oldpath_ptr, int, newfd, gstr_t, newpath_ptr)
{
  char oldname[LINUX_PATH_MAX], newname[LINUX_PATH_MAX];

  strncpy_from_user(oldname, oldpath_ptr, sizeof oldname);
  strncpy_from_user(newname, newpath_ptr, sizeof newname);

  struct path oldpath, newpath;
  int r;
  if ((r = vfs_grab_dir_w(oldfd, oldname, LOOKUP_NOFOLLOW, &oldpath)) < 0) {
    goto out1;
  }
  if ((r = vfs_grab_dir_w(newfd, newname, LOOKUP_NOFOLLOW, &newpath)) < 0) {
    goto out2;
  }
  if (oldpath.fs != newpath.fs) {
    r = -LINUX_EXDEV;
    goto out2;
  }
  r = newpath.fs->ops->renameat(newpath.fs, oldpath.dir, oldpath.subpath, newpath.dir, newpath.subpath);
  vfs_ungrab_dir(&newpath);
 out2:
  vfs_ungrab_dir(&oldpath);
 out1:
  return r;
}

DEFINE_SYSCALL(rename, gstr_t, oldpath_ptr, gstr_t, newpath_ptr)
{
  return sys_renameat(LINUX_AT_FDCWD, oldpath_ptr, LINUX_AT_FDCWD, newpath_ptr);
}

DEFINE_SYSCALL(unlinkat, int, dirfd, gstr_t, path_ptr, int, flags)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  struct path path;
  int r;
  if ((r = vfs_grab_dir_w(dirfd, name, LOOKUP_NOFOLLOW, &path)) < 0) {
    return r;
  }
  r = path.fs->ops->unlinkat(path.fs, path.dir, path.subpath, flags);
  if (r == -LINUX_EPERM) {
    struct l_newstat st;
    int r2 = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st,
				   LINUX_AT_SYMLINK_NOFOLLOW);
    if (r2 == 0 && S_ISDIR(st.st_mode)) {
      r = -LINUX_EISDIR;
    }
  }
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(unlink, gstr_t, path)
{
  return sys_unlinkat(LINUX_AT_FDCWD, path, 0);
}

DEFINE_SYSCALL(rmdir, gstr_t, path)
{
  return sys_unlinkat(LINUX_AT_FDCWD, path, LINUX_AT_REMOVEDIR);
}

DEFINE_SYSCALL(linkat, int, oldfd, gstr_t, oldpath_ptr, int, newfd, gstr_t, newpath_ptr, int, flags)
{
  char oldname[LINUX_PATH_MAX], newname[LINUX_PATH_MAX];

  strncpy_from_user(oldname, oldpath_ptr, sizeof oldname);
  strncpy_from_user(newname, newpath_ptr, sizeof newname);

  if (flags & ~LINUX_AT_SYMLINK_FOLLOW) {
    return -LINUX_EINVAL;
  }

  int lkflag = flags & LINUX_AT_SYMLINK_FOLLOW ? 0 : LOOKUP_NOFOLLOW;
  struct path oldpath, newpath;
  int r;
  if ((r = vfs_grab_dir_w(oldfd, oldname, lkflag, &oldpath)) < 0) {
    goto out1;
  }
  if ((r = vfs_grab_dir_w(newfd, newname, 0, &newpath)) < 0) {
    goto out2;
  }
  if (oldpath.fs != newpath.fs) {
    r = -LINUX_EXDEV;
    goto out2;
  }
  r = newpath.fs->ops->linkat(newpath.fs, oldpath.dir, oldpath.subpath, newpath.dir, newpath.subpath, flags);
  vfs_ungrab_dir(&newpath);
 out2:
  vfs_ungrab_dir(&oldpath);
 out1:
  return r;
}

DEFINE_SYSCALL(link, gstr_t, oldpath, gstr_t, newpath)
{
  return sys_linkat(LINUX_AT_FDCWD, oldpath, LINUX_AT_FDCWD, newpath, 0);
}

DEFINE_SYSCALL(readlinkat, int, dirfd, gstr_t, path_ptr, gaddr_t, buf_ptr, int, bufsize)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  /* /proc/<pid>/exe names the guest's binary, which only NABI knows - from the
   * host's side this process's executable is the emulator. */
  {
    char own[LINUX_PATH_MAX];
    int n = procfs_readlink(name, own, sizeof own);
    if (n >= 0) {
      if (n > bufsize)
        n = bufsize;
      if (copy_to_user(buf_ptr, own, n))
        return -LINUX_EFAULT;
      return n;
    }
  }

  int r;
  struct path path;
  if ((r = vfs_grab_dir(dirfd, name, LOOKUP_NOFOLLOW, &path)) < 0) {
    return r;
  }
  char *buf = malloc(bufsize);
  if (buf == NULL) {
    r = -LINUX_ENOMEM;
    goto out;
  }
  r = path.fs->ops->readlinkat(path.fs, path.dir, path.subpath, buf, bufsize);
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, bufsize)) {
    r = -LINUX_EFAULT;
    goto out;
  }
 out:
  if (buf) {
    free(buf);
  }
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(readlink, gstr_t, path_ptr, gaddr_t, buf_ptr, int, bufsize)
{
  return sys_readlinkat(LINUX_AT_FDCWD, path_ptr, buf_ptr, bufsize);
}

/* A directory made inside the cgroup hierarchy is a cgroup, and a cgroup has
 * files. The kernel materialises them on a real cgroupfs; here the directory is
 * an ordinary one, so they are written when it appears - otherwise a cgroup
 * just created would have nothing in it to read or to join. */
static void
cgroup_after_mkdir(int dirfd, const char *name)
{
  char host[PATH_MAX];
  if (guest_to_host_path(name, host, sizeof host) < 0)
    return;
  if (cgroup_is_hierarchy_path(host))
    cgroup_populate(host);
  (void) dirfd;
}

DEFINE_SYSCALL(mkdirat, int, dirfd, gstr_t, path_ptr, int, mode)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  struct path path;
  int r;
  if ((r = vfs_grab_dir_w(dirfd, name, 0, &path)) < 0) {
    return r;
  }
  r = path.fs->ops->mkdirat(path.fs, path.dir, path.subpath, mode);
  if (r >= 0)
    cgroup_after_mkdir(dirfd, name);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(mkdir, gstr_t, path_ptr, int, mode)
{
  return sys_mkdirat(LINUX_AT_FDCWD, path_ptr, mode);
}

/*
 * The working directory, named the way the guest names things.
 *
 * The host's answer is a host path, and handing that over says
 * "/Volumes/msltest/fedora/etc" to a guest whose own name for it is "/etc" -
 * or, before the process has chdir'd anywhere, a directory outside the rootfs
 * entirely. bash hides it by tracking PWD itself, so this went unnoticed until
 * something did arithmetic on the real answer: systemd's chaseat_prefix_root
 * calls path_make_absolute_cwd, and every rpm %sysusers scriptlet failed with
 * "Failed to prefix '...' with root '/': Invalid argument".
 *
 * A passthrough directory keeps its name, because that name is the same on both
 * sides - that is what makes it a passthrough.
 */
int
vfs_getcwd(char *buf, size_t size)
{
  char host[PATH_MAX];

  errno = 0;
  if (getcwd(host, sizeof host) == NULL)
    return -darwin_to_linux_errno(errno);

  char root[PATH_MAX];
  const char *guest = NULL;

  if (fcntl(proc.fileinfo.rootfd, F_GETPATH, root) == 0) {
    size_t rlen = strlen(root);
    /* Careful with the boundary: "/a/rootfs-old" starts with "/a/rootfs" and
     * is not inside it. */
    if (strncmp(host, root, rlen) == 0) {
      if (host[rlen] == '\0')
        guest = "/";
      else if (host[rlen] == '/')
        guest = host + rlen;
    }
  }

  if (guest == NULL && host[0] == '/' && is_host_passthrough(host))
    guest = host;

  /* Outside both, so the guest has no name for it. It cannot happen once the
   * process has been started in the rootfs, and answering with the root beats
   * handing over a path that resolves to something else entirely. */
  if (guest == NULL)
    guest = "/";

  if (strlcpy(buf, guest, size) >= size)
    return -LINUX_ERANGE;
  return 0;
}

int
vfs_fchdir(int fd)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  return syswrap(fchdir(fd));
}

int
vfs_umask(int mask)
{
  return syswrap(umask(mask));
}

/*
 * The syscall version of getcwd differs from that provided by glibc!
 * Quoting a part of source code of linux:
 *
 * > NOTE! The user-level library version returns a
 * > character pointer. The kernel system call just
 * > returns the length of the buffer filled (which
 * > includes the ending '\0' character), or a negative
 * > error value. So libc would do something like
 */
DEFINE_SYSCALL(getcwd, gaddr_t, buf_ptr, unsigned long, size)
{
  char *buf = malloc(size);
  if (buf == NULL) {
    return -LINUX_ENOMEM;
  }
  memset(buf, 0, size);
  int r;
  if ((r = vfs_getcwd(buf, size)) < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, size)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  r = strlen(buf) + 1;
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(fchdir, int, fd)
{
  return vfs_fchdir(fd);
}

DEFINE_SYSCALL(chdir, gstr_t, path_ptr)
{
  char path[LINUX_PATH_MAX];
  strncpy_from_user(path, path_ptr, sizeof path);
  int fd = user_openat(LINUX_AT_FDCWD, path, LINUX_O_DIRECTORY, 0);
  if (fd < 0)
    return fd;
  int r = sys_fchdir(fd);
  user_close(fd);
  return r;
}

DEFINE_SYSCALL(umask, int, mask)
{
  return vfs_umask(mask);
}

DEFINE_SYSCALL(mknodat, int, dirfd, gaddr_t, path_ptr, l_mode_t, mode, l_dev_t, dev) {
  char name[LINUX_PATH_MAX];
  if (strncpy_from_user(name, path_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;

  struct path path;
  int r = 0;
  switch(mode & S_IFMT) {
  case S_IFIFO: {
    if ((r = vfs_grab_dir_w(dirfd, name, 0, &path)) < 0) {
      goto out;
    }
    r = syswrap(mkfifo(path.subpath, mode));
    break;
  }
  default:
    warnk("unsupported mknod mode: %d", mode);
    return -LINUX_EINVAL;
  }
 out:
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(mknod, gaddr_t, path_ptr, l_mode_t, mode, l_dev_t, dev) {
  return sys_mknodat(LINUX_AT_FDCWD, path_ptr, mode, dev);
}


/* TODO: functions below are not yet ported to the new vfs archtecture. */


DEFINE_SYSCALL(pipe, gaddr_t, fildes_ptr)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd[2];
  int r = syswrap(pipe(fd));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(fildes_ptr, fd, sizeof fd)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  int err0 = register_fd(fd[0], false);
  int err1 = register_fd(fd[1], false);
  if (err0 < 0 || err1 < 0) {
    r = (err0 < 0) ? err0 : err1;
    close(err0);
    close(err1);
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);

  return r;
}

DEFINE_SYSCALL(pipe2, gaddr_t, fildes_ptr, int, flags)
{
  if (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC | LINUX_O_DIRECT)) {
    return -LINUX_EINVAL;
  }

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fildes[2];

  int ret = pipe(fildes);
  if (ret < 0) {
    goto out;
  }

  int err0, err1;
  if (flags & LINUX_O_CLOEXEC) {
    err0 = syswrap(fcntl(fildes[0], F_SETFD, FD_CLOEXEC));
    err1 = syswrap(fcntl(fildes[1], F_SETFD, FD_CLOEXEC));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }
  if (flags & LINUX_O_NONBLOCK) {
    err0 = syswrap(fcntl(fildes[0], F_SETFL, O_NONBLOCK));
    err1 = syswrap(fcntl(fildes[1], F_SETFL, O_NONBLOCK));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }
  if (flags & LINUX_O_DIRECT) {
    err0 = syswrap(fcntl(fildes[0], F_NOCACHE, 1));
    err1 = syswrap(fcntl(fildes[1], F_NOCACHE, 1));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }

  err0 = register_fd(fildes[0], flags & LINUX_O_CLOEXEC);
  err1 = register_fd(fildes[1], flags & LINUX_O_CLOEXEC);
  if (err0 < 0 || err1 < 0) {
    goto close_by_fail;
  }

  if (copy_to_user(fildes_ptr, fildes, sizeof(fildes))) {
    ret = -LINUX_EFAULT;
  }

  goto out;

close_by_fail:
  close(fildes[0]);
  close(fildes[1]);
  ret = (err0 < 0) ? err0 : err1;

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);

  return ret;
}

DEFINE_SYSCALL(dup, unsigned int, fd)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = sys_fcntl(fd, LINUX_F_DUPFD, 0);
  if (ret >= 0) {
    procfs_dup_fd(fd, ret);
    int err = register_fd(ret, false);
    if (err < 0) {
      close(ret);
      ret = err;
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(dup2, unsigned int, fd1, unsigned int, fd2)
{
  if (!in_userfd(fd1) || !in_userfd(fd2)) {
    return -LINUX_EBADF;
  }
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = syswrap(dup2(fd1, fd2));
  if (ret >= 0) {
    procfs_dup_fd(fd1, ret);
    int err = register_fd(ret, false);
    if (err < 0) {
      close(ret);
      ret = err;
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
  if (flags & ~LINUX_O_CLOEXEC) {
    return -LINUX_EINVAL;
  }
  if (oldfd == newfd) {
    return -LINUX_EINVAL;
  }

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = syswrap(dup2(oldfd, newfd));
  if (ret < 0) {
    goto out;
  }
  procfs_dup_fd(oldfd, ret);
  if (flags & LINUX_O_CLOEXEC) {
    int fcntl_err = syswrap(fcntl(newfd, F_SETFD, FD_CLOEXEC));
    if (fcntl_err < 0) {
      close(ret);
      ret = fcntl_err;
      goto out;
    }
  }
  int err = register_fd(ret, flags & LINUX_O_CLOEXEC);
  if (err < 0) {
    close(ret);
    ret = err;
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(pread64, unsigned int, fd, gstr_t, buf_ptr, size_t, count, off_t, pos)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  char *buf = malloc(count);
  int r = syswrap(pread(fd, buf, count, pos));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, r)) {
    r = -LINUX_EFAULT;
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(pwrite64, unsigned int, fd, gstr_t, buf_ptr, size_t, count, off_t, pos)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  int r;
  char *buf = malloc(count);
  if (copy_from_user(buf, buf_ptr, count)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  r = syswrap(pwrite(fd, buf, count, pos));
  if (r < 0) {
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(getxattr, gstr_t, path_ptr, gstr_t, name_ptr, gaddr_t, value, size_t, size)
{
  warnk("getxattr is unimplemented\n");
  return -LINUX_ENOTSUP;
}

DEFINE_SYSCALL(fgetxattr, int, fd, gaddr_t, name, gaddr_t, value, size_t, size)
{
  warnk("fgetxattr is unimplemented\n");
  return -LINUX_ENOTSUP;
}

DEFINE_SYSCALL(setxattr, gstr_t, pathname, gstr_t, name, gaddr_t, value, size_t, size, int, flags)
{
  warnk("setxattr is unimplemented\n");
  return 0;
}

DEFINE_SYSCALL(fsetxattr, int, fd, gaddr_t, name, gaddr_t, value, size_t, size, int, flags)
{
  warnk("fsetxattr is unimplemented\n");
  return 0;
}

DEFINE_SYSCALL(fadvise64, int, fd, off_t, offset, size_t, len, int, advice)
{
  return 0;
}

DEFINE_SYSCALL(select, int, nfds, gaddr_t, readfds_ptr, gaddr_t, writefds_ptr, gaddr_t, errorfds_ptr, gaddr_t, timeout_ptr)
{
  // TODO: Check if fd is in userspace
  // Darwin's fd_set and timeval is compatible with those of Linux

  struct timeval timeout;
  fd_set readfds, writefds, errorfds;
  struct timeval *to;
  fd_set *rfds, *wfds, *efds;

  if (nfds - 1 >= proc.fileinfo.vkern_fdtable.start) {
    return -LINUX_EBADF;
  }

  if (timeout_ptr == 0) {
    to = NULL;
  } else {
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
      return -LINUX_EFAULT;
    to = &timeout;
  }
  if (readfds_ptr == 0) {
    rfds = NULL;
  } else {
    if (copy_from_user(&readfds, readfds_ptr, sizeof readfds))
      return -LINUX_EFAULT;
    rfds = &readfds;
  }
  if (writefds_ptr == 0) {
    wfds = NULL;
  } else {
    if (copy_from_user(&writefds, writefds_ptr, sizeof writefds))
      return -LINUX_EFAULT;
    wfds = &writefds;
  }
  if (errorfds_ptr == 0) {
    efds = NULL;
  } else {
    if (copy_from_user(&errorfds, errorfds_ptr, sizeof errorfds))
      return -LINUX_EFAULT;
    efds = &errorfds;
  }

  int r = syswrap(select(nfds, rfds, wfds, efds, to));
  if (r < 0)
    return r;

  if (readfds_ptr != 0 && copy_to_user(readfds_ptr, &readfds, sizeof readfds))
    return -LINUX_EFAULT;
  if (writefds_ptr != 0 && copy_to_user(writefds_ptr, &writefds, sizeof writefds))
    return -LINUX_EFAULT;
  if (errorfds_ptr != 0 && copy_to_user(errorfds_ptr, &errorfds, sizeof errorfds))
    return -LINUX_EFAULT;
  return r;
}

DEFINE_SYSCALL(pselect6, int, nfds, gaddr_t, readfds_ptr, gaddr_t, writefds_ptr, gaddr_t, errorfds_ptr, gaddr_t, timeout_ptr, gaddr_t, sigmask_ptr)
{
  // TODO: Check if fd is in userspace
  // Darwin's fd_set and timeval is compatible with those of Linux

  struct timespec timeout;
  fd_set readfds, writefds, errorfds;
  struct timespec *to;
  fd_set *rfds, *wfds, *efds;

  if (nfds - 1 >= proc.fileinfo.vkern_fdtable.start) {
    return -LINUX_EBADF;
  }

  if (timeout_ptr == 0) {
    to = NULL;
  } else {
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
      return -LINUX_EFAULT;
    to = &timeout;
  }
  if (readfds_ptr == 0) {
    rfds = NULL;
  } else {
    if (copy_from_user(&readfds, readfds_ptr, sizeof readfds))
      return -LINUX_EFAULT;
    rfds = &readfds;
  }
  if (writefds_ptr == 0) {
    wfds = NULL;
  } else {
    if (copy_from_user(&writefds, writefds_ptr, sizeof writefds))
      return -LINUX_EFAULT;
    wfds = &writefds;
  }
  if (errorfds_ptr == 0) {
    efds = NULL;
  } else {
    if (copy_from_user(&errorfds, errorfds_ptr, sizeof errorfds))
      return -LINUX_EFAULT;
    efds = &errorfds;
  }

  // FIXME: Ignore sigmask now. Support it after implementing signal handling
  int r = syswrap(pselect(nfds, rfds, wfds, efds, to, NULL));
  if (r < 0)
    return r;

  if (readfds_ptr != 0 && copy_to_user(readfds_ptr, &readfds, sizeof readfds))
    return -LINUX_EFAULT;
  if (writefds_ptr != 0 && copy_to_user(writefds_ptr, &writefds, sizeof writefds))
    return -LINUX_EFAULT;
  if (errorfds_ptr != 0 && copy_to_user(errorfds_ptr, &errorfds, sizeof errorfds))
    return -LINUX_EFAULT;
  return r;
}

/* Shared body of poll and ppoll: marshal the guest pollfd array, poll the host
 * descriptors (kernel-owned fds are masked to -1), and write the results back.
 * timeout is in milliseconds, -1 for no timeout - the same units poll() takes. */
static int
poll_common(gaddr_t fds_ptr, int nfds, int timeout)
{
  /* FIXME! event numbers should be translated */

  struct pollfd *l_fds = malloc(nfds * sizeof(struct pollfd)), *d_fds = malloc(nfds * sizeof(struct pollfd));

  if (l_fds == NULL || d_fds == NULL) {
    if (l_fds) {
      free(l_fds);
    }
    if (d_fds) {
      free(d_fds);
    }
    return -LINUX_ENOMEM;
  }

  int r;
  if (nfds > OPEN_MAX) {
    r = -LINUX_EINVAL;
    goto out;
  }

  if (copy_from_user(l_fds, fds_ptr, nfds * sizeof(struct pollfd))) {
    r = -LINUX_EFAULT;
    goto out;
  }

  for (int i = 0; i < nfds; i++) {
    d_fds[i] = l_fds[i];
    if (!in_userfd(l_fds[i].fd)) {
      d_fds[i].fd = -1;
    }
  }

  r = syswrap(poll(d_fds, nfds, timeout));
  if (r < 0)
    goto out;

  for (int i = 0; i < nfds; i++) {
    if (in_userfd(l_fds[i].fd) || l_fds[i].fd < 0 || l_fds[i].events == 0) {
      l_fds[i].revents = d_fds[i].revents;
    } else {
      l_fds[i].revents = LINUX_POLLNVAL;
      r++;
    }
  }

  if (copy_to_user(fds_ptr, l_fds, nfds * sizeof(struct pollfd))) {
    r = -LINUX_EFAULT;
  }

out:
  free(l_fds);
  free(d_fds);
  return r;
}

DEFINE_SYSCALL(poll, gaddr_t, fds_ptr, int, nfds, int, timeout)
{
  return poll_common(fds_ptr, nfds, timeout);
}

/*
 * ppoll is aarch64's primary poll (there is no plain poll in the syscall set a
 * modern libc uses on this arch). It differs from poll in two ways: the timeout
 * is a relative struct timespec (NULL = block forever) rather than a millisecond
 * int, and it takes an optional signal mask to install for the duration.
 *
 * The mask is applied around the wait rather than atomically inside it - close
 * enough for the common poll-with-a-mask use, though a signal delivered in the
 * gap between installing the mask and entering poll() will not cut the wait
 * short the way a truly atomic ppoll would. Linux leaves *tmo unmodified on
 * return here (unlike select), so it is only read.
 */
DEFINE_SYSCALL(ppoll, gaddr_t, fds_ptr, int, nfds, gaddr_t, tmo_ptr, gaddr_t, sigmask_ptr, size_t, sigsetsize)
{
  int timeout = -1;
  if (tmo_ptr) {
    struct l_timespec ts;
    if (copy_from_user(&ts, tmo_ptr, sizeof ts))
      return -LINUX_EFAULT;
    /* Round a sub-millisecond remainder up so a short wait is not truncated to
     * a busy zero-timeout poll. */
    timeout = ts.tv_sec * 1000 + (ts.tv_nsec + 999999) / 1000000;
  }

  sigset_t saved;
  bool have_mask = false;
  if (sigmask_ptr) {
    if (sigsetsize != sizeof(l_sigset_t))
      return -LINUX_EINVAL;
    l_sigset_t lset;
    if (copy_from_user(&lset, sigmask_ptr, sizeof lset))
      return -LINUX_EFAULT;
    sigset_t dset;
    linux_to_darwin_sigset(&lset, &dset);
    sigprocmask(SIG_SETMASK, &dset, &saved);
    have_mask = true;
  }

  int r = poll_common(fds_ptr, nfds, timeout);

  if (have_mask)
    sigprocmask(SIG_SETMASK, &saved, NULL);

  return r;
}

DEFINE_SYSCALL(chroot, gstr_t, path_ptr)
{
  char path[PATH_MAX];
  int len = strncpy_from_user(path, path_ptr, sizeof path);
  if (len == PATH_MAX) {
    return -LINUX_ENAMETOOLONG;
  }
  if (len < 0) {
    return -LINUX_EFAULT;
  }

  /* We have not impelemented caps, just check if user is root */
  if (getuid() != 0) {
    return -LINUX_EPERM;
  }

  /* for pacman */
  if (! (path[0] == '/' && path[1] == '\0')) {
    return -LINUX_EACCES;
  }
  return 0;
}

DEFINE_SYSCALL(ftruncate, unsigned int, fd, unsigned long, length)
{
  return syswrap(ftruncate(fd, length));
}

DEFINE_SYSCALL(flistxattr, int, fd, gaddr_t, list, size_t, size)
{
  assert(size == 0);
  return 0;
}

DEFINE_SYSCALL(flock, int, fd, int, operation)
{
  // Linux's and Darwin's operation are compatible
  return syswrap(flock(fd, operation));
}

DEFINE_SYSCALL(fallocate, int, fd, int, mode, l_off_t, offset, l_off_t, len)
{
  if (mode != 0) {
    // FreeBSD's Linuxulator also implements only mode zero
    warnk("Unsupported fallocate mode\n");
    return -ENOSYS;
  }
  
  // Emulate posix_fallocate
  assert(offset == 0);
  struct fstore store = {F_ALLOCATEALL, F_PEOFPOSMODE, 0, len, 0};
  return syswrap(fcntl(fd, F_PREALLOCATE, &store));
}

DEFINE_SYSCALL(sync)
{
  sync();
  return 0;
}

/*
 * Flush the filesystem holding one descriptor.
 *
 * Darwin has no syncfs, and the nearest thing - F_FULLFSYNC - is a stronger
 * promise about one file rather than a weaker one about the filesystem. fsync
 * on the descriptor is the honest approximation: every caller that reaches here
 * wants the bytes it just wrote to be durable, and they are.
 *
 * Missing entirely, this returned ENOSYS, which coreutils' sync(1) reports as
 * "error syncing '<file>': Function not implemented". That is what stopped
 * `apt-get install linux-image-arm64`: update-initramfs builds the initrd and
 * syncs it, the kernel postinst treats a failure there as fatal, and the whole
 * package was left unconfigured over a flush.
 */
DEFINE_SYSCALL(syncfs, int, fd)
{
  return syswrap(fsync(fd));
}

/*
 * The descriptor tables, for a handover.
 *
 * Walks both tables' open bits and records which guest number maps to which
 * host descriptor. The host descriptors need no saving of their own - they
 * survive fork and exec, offsets and all - so this table is the entire mapping
 * a resumed process needs to keep the guest's I/O pointing where it was.
 *
 * Returns the number of open descriptors, which may exceed `max`.
 */
/*
 * The guest's open descriptor numbers, for /proc/self/fd.
 *
 * Only the user table: the vkern table is NABI's own bookkeeping and a guest
 * has no business seeing it, which is the whole reason the host's /proc cannot
 * answer this question. Writes up to `max` of them and returns how many there
 * are, so a caller can size a buffer by asking with max 0.
 */
int
fdtable_open_fds(int *out, int max)
{
  struct fdtable *t = &proc.fileinfo.fdtable;
  int n = 0;

  pthread_rwlock_rdlock(&proc.fileinfo.fdtable_lock);
  for (int fd = t->start; fd < t->start + t->size; fd++) {
    int i = (fd - t->start) / 64, b = (fd - t->start) - i * 64;
    if (!(t->open_fds[i] & (1ULL << b)))
      continue;
    if (out != NULL && n < max)
      out[n] = fd;
    n++;
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return n;
}

static size_t
fdtable_snapshot_one(struct fdtable *t, int32_t which,
                     struct checkpoint_fd *out, size_t max, size_t n)
{
  for (int fd = t->start; fd < t->start + t->size; fd++) {
    int i = (fd - t->start) / 64, b = (fd - t->start) - i * 64;
    if (!(t->open_fds[i] & (1ULL << b)))
      continue;
    if (n < max) {
      int off = fd - t->start;
      struct file *f = &t->files[off / fdtable_alloc_unit][off % fdtable_alloc_unit];
      out[n] = (struct checkpoint_fd){
        .table = which,
        .index = fd,
        .host_fd = f->fd,
        .cloexec = (t->cloexec_fds[i] & (1ULL << b)) ? 1 : 0,
      };
    }
    n++;
  }
  return n;
}

size_t
fdtable_snapshot(struct checkpoint_fd *out, size_t max, struct checkpoint_header *hdr)
{
  struct fileinfo *fi = &proc.fileinfo;

  if (hdr) {
    hdr->rootfd      = fi->rootfd;
    hdr->user_start  = fi->fdtable.start;
    hdr->user_size   = fi->fdtable.size;
    hdr->vkern_start = fi->vkern_fdtable.start;
    hdr->vkern_size  = fi->vkern_fdtable.size;
  }

  size_t n = fdtable_snapshot_one(&fi->fdtable, 0, out, max, 0);
  n = fdtable_snapshot_one(&fi->vkern_fdtable, 1, out, max, n);
  return n;
}

/*
 * Rebuild both descriptor tables from a checkpoint.
 *
 * The host descriptors are already open - they came through fork and exec
 * untouched, with their offsets and flags - so nothing here opens anything. It
 * rebuilds the tables that say which of them the guest can see and under which
 * number, and re-attaches the one static ops table every file shares.
 */
void
fdtable_restore(const struct checkpoint_fd *fds, size_t n,
                const struct checkpoint_header *hdr)
{
  struct fileinfo *fi = &proc.fileinfo;

  pthread_rwlock_init(&fi->fdtable_lock, NULL);

  fi->vkern_fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fi->vkern_fdtable.start = hdr->vkern_start;
  alloc_fdtable(&fi->vkern_fdtable, hdr->vkern_size);

  fi->fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fi->fdtable.start = hdr->user_start;
  alloc_fdtable(&fi->fdtable, hdr->user_size);

  fi->rootfd = hdr->rootfd;

  for (size_t i = 0; i < n; i++) {
    struct fdtable *t = fds[i].table ? &fi->vkern_fdtable : &fi->fdtable;
    alloc_file(t, fds[i].index);
    set_fdbit(t, t->open_fds, fds[i].index);
    if (fds[i].cloexec)
      set_fdbit(t, t->cloexec_fds, fds[i].index);
  }
}

/*
 * Clear FD_CLOEXEC on every descriptor the guest has open.
 *
 * For the child of a guest fork, between the host fork and the host exec.
 *
 * The guest asked to fork, and fork does not close close-on-exec descriptors -
 * only exec does. But this fork is implemented as fork+exec (the framework
 * cannot give a forked child a vCPU, see spike/arm64-fork/), so the kernel would
 * apply exec semantics the guest never asked for and close them: a shell
 * pipeline, whose pipe ends are exactly such descriptors, would come up with
 * nothing connected.
 *
 * The flags are not lost, only moved: the checkpoint carries each descriptor's
 * close-on-exec bit, so the resumed process restores the table exactly, and a
 * later *guest* execve still closes the right ones through close_cloexec().
 */
void
fdtable_clear_host_cloexec(void)
{
  struct fileinfo *fi = &proc.fileinfo;
  struct fdtable *tables[] = { &fi->fdtable, &fi->vkern_fdtable };

  for (int t = 0; t < 2; t++) {
    struct fdtable *tab = tables[t];
    for (int fd = tab->start; fd < tab->start + tab->size; fd++) {
      int i = (fd - tab->start) / 64, b = (fd - tab->start) - i * 64;
      if (!(tab->open_fds[i] & (1ULL << b)))
        continue;
      int flags = fcntl(fd, F_GETFD);
      if (flags >= 0 && (flags & FD_CLOEXEC))
        fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
  }
}
