/*
 * pidfd_open: a process referred to by descriptor rather than by number.
 *
 * A pid is a name that can be reused. Between deciding to signal a process and
 * signalling it, that process can exit and its number be handed to another, and
 * the signal goes to a stranger. A pidfd closes that window: it refers to the
 * process itself, so an operation on it either reaches that process or reports
 * that it is gone, and never reaches a different one.
 *
 * This is here because process_madvise and process_mrelease take one, and until
 * now there was no way for a guest to obtain a pidfd at all - clone3 refuses
 * CLONE_PIDFD, and pidfd_getfd does not exist. Implementing those two without
 * this would have been implementing two calls nothing could invoke.
 *
 * The descriptor is an unlinked file with a magic and a pid in it, which is the
 * shape the POSIX message queues and the mount contexts use: the descriptor is
 * the object, so it survives fork and the exec arm64's fork is built on, it
 * goes when the guest closes it, and nothing here tracks which are live.
 *
 * What a pidfd must also do is become *readable* when the process exits, since
 * that is how a program waits for a child without a signal handler. Darwin has
 * no descriptor that does that, so it is answered where every other readiness
 * question here is answered: poll, select and epoll are nabi's own, and they ask
 * whether the process is still there. That is a check at poll time rather than
 * an event, which differs from Linux in one way worth stating - a poll already
 * blocked in the host when the process exits is not woken by it, and returns
 * when its timeout expires. A caller polling with a timeout, which is what
 * every event loop does, sees the exit on its next pass.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/fs.h"

#define PIDFD_MAGIC 0x70696466u   /* "pidf" */

#define LINUX_PIDFD_NONBLOCK 04000

struct pidfd_hdr {
  uint32_t magic;
  int32_t  pid;                 /* the host pid, which is what acts on it */
};

/*
 * How many pidfds this process holds.
 *
 * Read on the way into poll and select, so it has to be answerable without
 * doing anything: a guest with no pidfds pays one comparison to find that out,
 * and only a guest that has one pays for the check itself.
 */
static int pidfd_live;

static int
pidfd_read(int fd, struct pidfd_hdr *h)
{
  if (pread(fd, h, sizeof *h, 0) != (ssize_t) sizeof *h)
    return -LINUX_EBADF;
  if (h->magic != PIDFD_MAGIC)
    return -LINUX_EBADF;        /* a descriptor, but not a pidfd */
  return 0;
}

/* The host pid a pidfd names, or -1 if this is not one. */
int
pidfd_host_pid(int fd)
{
  struct pidfd_hdr h;
  if (pidfd_read(fd, &h) < 0)
    return -1;
  return h.pid;
}

bool
pidfd_any(void)
{
  return pidfd_live > 0;
}

/* Whether this descriptor is a pidfd at all, which is a different question
 * from whether it is readable and has to be asked separately - see below. */
bool
pidfd_is(int fd)
{
  struct pidfd_hdr h;
  return pidfd_live > 0 && pidfd_read(fd, &h) == 0;
}

/*
 * A pidfd is readable exactly when its process has exited - that is the whole
 * of what can be read from one, and Linux reports it the same way.
 *
 * Note what this has to *un*-say. The descriptor is a file, and the host calls
 * a file readable always, so a poll that only added readability would report
 * every pidfd ready the moment it was made. The callers below therefore replace
 * what the host said about a pidfd rather than adding to it, which is the one
 * place a readiness hook here works that way.
 */
bool
pidfd_readable(int fd)
{
  if (pidfd_live <= 0)
    return false;
  struct pidfd_hdr h;
  if (pidfd_read(fd, &h) < 0)
    return false;
  return kill(h.pid, 0) < 0 && errno == ESRCH;
}

/* Called from the close path, so the fast path above stays honest. */
void
pidfd_close(int fd)
{
  if (pidfd_live <= 0)
    return;
  struct pidfd_hdr h;
  if (pidfd_read(fd, &h) == 0)
    pidfd_live--;
}

/*
 * The same replacement for select's bitmaps: a pidfd belongs in the ready set
 * exactly when its process has gone, whatever the host said about the file
 * behind it. Returns the change in the count select should report.
 */
int
pidfd_fix_readset(int nfds, fd_set *out, const fd_set *want)
{
  if (!out || !want || pidfd_live <= 0)
    return 0;
  int delta = 0;
  for (int fd = 0; fd < nfds; fd++) {
    if (!FD_ISSET(fd, want) || !pidfd_is(fd))
      continue;
    bool was = FD_ISSET(fd, out) != 0;
    bool now = pidfd_readable(fd);
    if (was && !now) { FD_CLR(fd, out); delta--; }
    if (!was && now) { FD_SET(fd, out); delta++; }
  }
  return delta;
}

DEFINE_SYSCALL(pidfd_open, int, pid, unsigned int, flags)
{
  if (flags & ~(unsigned) LINUX_PIDFD_NONBLOCK)
    return -LINUX_EINVAL;
  if (pid <= 0)
    return -LINUX_EINVAL;

  int32_t host = pidns_to_host(pid);
  if (host < 0)
    return -LINUX_ESRCH;
  /* The process has to exist now, or the descriptor would name nothing from
   * the moment it was made - which is the race this call exists to close. */
  if (kill(host, 0) < 0 && errno == ESRCH)
    return -LINUX_ESRCH;

  const char *tmp = getenv("TMPDIR");
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/nabi-pidfd-%s-XXXXXX",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag());
  int fd = mkstemp(path);
  if (fd < 0)
    return -darwin_to_linux_errno(errno);
  unlink(path);

  struct pidfd_hdr h = { PIDFD_MAGIC, host };
  if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h) {
    close(fd);
    return -LINUX_EIO;
  }
  if (flags & LINUX_PIDFD_NONBLOCK)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, true);   /* a pidfd is close-on-exec by default */
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(fd);
    return err;
  }
  pidfd_live++;
  return fd;
}
