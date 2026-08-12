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

/*
 * Make a pidfd for a host pid that is known to exist.
 *
 * Split out because clone needs it: a child's descriptor has to be created by
 * the parent at the moment the child appears, which is the only moment at which
 * the pid is certainly still that child's.
 */
int
pidfd_make(int32_t host, bool cloexec)
{
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
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, cloexec);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(fd);
    return err;
  }
  pidfd_live++;
  return fd;
}

/*
 * pidfd_send_signal: the reason a pidfd is worth having.
 *
 * kill(2) names a process by a number that can be reused, so between deciding
 * to signal and signalling, the target can exit and its number pass to someone
 * else - and the signal arrives at a stranger. That window cannot be closed
 * from outside the kernel, which is why this call exists.
 *
 * Here it is closed for the same reason it is on Linux, if by a different
 * mechanism: the descriptor holds the pid it was opened for, and pidfd_open
 * checked the process existed at that moment. A pid recycled afterwards is
 * still a wrong target - nothing on Darwin makes a pid *stop* being reusable -
 * so this is narrower than the kernel's guarantee and the difference is worth
 * stating: what is removed is the window between the caller's decision and the
 * call, which is the one a program can do nothing about. What remains is the
 * window between opening the descriptor and using it, which a program closes by
 * holding the descriptor, exactly as it would on Linux.
 */
DEFINE_SYSCALL(pidfd_send_signal, int, pidfd, int, sig, gaddr_t, info,
               unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;

  struct pidfd_hdr h;
  int r = pidfd_read(pidfd, &h);
  if (r < 0)
    return r;

  /*
   * A siginfo may be supplied, which makes this rt_sigqueueinfo rather than
   * kill - the signal carries a value with it. nabi's signal delivery has no
   * way to attach one, and a receiver that read si_value would get whatever the
   * host put there rather than what the sender sent. Refused, so a caller that
   * needs the value knows it did not travel; a caller that does not need it
   * passes NULL and this is kill.
   */
  if (info != 0)
    return -LINUX_EINVAL;

  /* No liveness check first: send_signal answers ESRCH for a process that has
   * gone, so one here would change nothing a caller could see. */
  return send_signal(h.pid, sig);
}

/*
 * pidfd_getfd: take a copy of a descriptor belonging to another process.
 *
 * That is a debugger's operation - it needs the same access ptrace does - and
 * the cross-process half runs into the wall process_vm_readv describes: a guest
 * process is a host process, and nabi has no way into another one's descriptor
 * table. It answers EPERM there, which is what Linux answers when the ptrace
 * check fails.
 *
 * A process may name itself, and then this is dup with a race removed, so that
 * half is real.
 */
DEFINE_SYSCALL(pidfd_getfd, int, pidfd, int, targetfd, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;

  struct pidfd_hdr h;
  int r = pidfd_read(pidfd, &h);
  if (r < 0)
    return r;
  if (kill(h.pid, 0) < 0 && errno == ESRCH)
    return -LINUX_ESRCH;
  if (h.pid != getpid())
    return -LINUX_EPERM;

  int copy = dup(targetfd);
  if (copy < 0)
    return -darwin_to_linux_errno(errno);
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(copy, true);   /* always close-on-exec, as on Linux */
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(copy);
    return err;
  }
  /* A copy of a pidfd is another pidfd, and the count has to know. */
  if (pidfd_is(copy))
    pidfd_live++;
  return copy;
}
