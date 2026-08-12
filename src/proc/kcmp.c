/*
 * kcmp: are these two processes looking at the same kernel object?
 *
 * The question is one only the kernel can answer, because what it compares are
 * things userspace never sees an address for - the struct file behind a
 * descriptor, the address space, the file table, the signal handlers. Two
 * descriptors that name the same file are not the same open file description,
 * and no amount of stat-ing tells them apart; that distinction is the entire
 * reason the call exists.
 *
 * Here there is no kernel to ask, and the two halves of the question fall out
 * very differently.
 *
 * The process-wide types - VM, FILES, FS, SIGHAND, IO, SYSVSEM - are answerable
 * exactly when both sides are the calling process, because a process shares all
 * of those with itself. That is not a shortcut: it is the true answer, and it is
 * the whole answer for a caller asking about itself. Anything naming another
 * process meets the same wall process_vm_readv documents - a guest process is a
 * host process with its own guest memory, and nabi cannot see into another one -
 * so it is EPERM rather than a guess.
 *
 * KCMP_FILE is the type callers actually use, and it is where this stops short.
 * Darwin will say which *file* a descriptor names, but for most descriptors it
 * will not say which open file description - so two independent opens of one
 * path and one descriptor duplicated are indistinguishable, which is precisely
 * the pair kcmp is asked to tell apart. Pipes and sockets are the exception:
 * proc_pidfdinfo hands back the kernel's own handle for the object, and the only
 * ways to get two descriptors onto one pipe end or one socket - dup, fork,
 * SCM_RIGHTS - all share the description. So those are answered exactly, and
 * everything else is refused.
 *
 * Refused, rather than answered from st_dev and st_ino. A caller comparing two
 * descriptors it opened separately would be told they are the same, and act on
 * it. Being told the question cannot be answered here costs a fallback path;
 * being told the wrong answer costs correctness somewhere further away.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/errno.h"

#include <libproc.h>          /* last: sys/param.h's roundup eats util/misc.h */

#define LINUX_KCMP_FILE       0
#define LINUX_KCMP_VM         1
#define LINUX_KCMP_FILES      2
#define LINUX_KCMP_FS         3
#define LINUX_KCMP_SIGHAND    4
#define LINUX_KCMP_IO         5
#define LINUX_KCMP_SYSVSEM    6
#define LINUX_KCMP_EPOLL_TFD  7
#define LINUX_KCMP_TYPES      8

/* What the guest passes by pointer as idx2 for KCMP_EPOLL_TFD. */
struct l_kcmp_epoll_slot {
  uint32_t efd;
  uint32_t tfd;
  uint32_t toff;
};

/*
 * The kernel's handle for whatever object a descriptor names, when there is one.
 *
 * Non-zero means the object is identified exactly: equal handles are the same
 * open file description and unequal ones are not. Zero means Darwin will not say,
 * and the comparison has to be refused rather than approximated.
 */
static uint64_t
description_handle(int fd)
{
  struct stat st;
  if (fstat(fd, &st) < 0)
    return 0;

  if (S_ISFIFO(st.st_mode)) {
    struct pipe_fdinfo pi;
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDPIPEINFO, &pi, sizeof pi) <= 0)
      return 0;
    /*
     * Each end of a pipe reports its own handle - which is what makes this an
     * identity for the description and not merely for the pipe. tee keys its
     * pushback store on the same pair for the same reason.
     */
    return pi.pipeinfo.pipe_handle;
  }

  if (S_ISSOCK(st.st_mode)) {
    struct socket_fdinfo si;
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &si, sizeof si) <= 0)
      return 0;
    return si.psi.soi_so;
  }

  return 0;             /* a vnode names a file, which is not the question */
}

/*
 * 0 same, 1 or 2 different, or a negative error.
 *
 * The 1/2 split is Linux's: it orders unequal objects so that a caller sorting
 * descriptors gets a consistent result rather than only ever learning "not
 * equal". Ordering by handle here does the same job the kernel's pointer
 * ordering does, and is stable for as long as both descriptions are open, which
 * is as long as the ordering means anything.
 */
static int
compare_fds(int fd1, int fd2)
{
  if (fcntl(fd1, F_GETFD) < 0 || fcntl(fd2, F_GETFD) < 0)
    return -LINUX_EBADF;
  if (fd1 == fd2)
    return 0;

  uint64_t h1 = description_handle(fd1);
  uint64_t h2 = description_handle(fd2);
  if (h1 == 0 || h2 == 0)
    return -LINUX_EOPNOTSUPP;   /* see the top of this file */
  if (h1 == h2)
    return 0;
  return h1 < h2 ? 1 : 2;
}

DEFINE_SYSCALL(kcmp, int, pid1, int, pid2, int, type,
               unsigned long, idx1, unsigned long, idx2)
{
  if (type < 0 || type >= LINUX_KCMP_TYPES)
    return -LINUX_EINVAL;
  if (pid1 <= 0 || pid2 <= 0)
    return -LINUX_ESRCH;

  int32_t h1 = pidns_to_host(pid1);
  int32_t h2 = pidns_to_host(pid2);
  if (h1 < 0 || h2 < 0)
    return -LINUX_ESRCH;

  /*
   * Same existence-before-permission order process_vm_readv uses: "no such
   * process" and "not allowed" are different answers and a caller acts on them
   * differently, so the process is looked for rather than assumed to exist
   * because a number translated.
   */
  int32_t me = getpid();
  if (h1 != me || h2 != me) {
    if ((h1 != me && kill(h1, 0) < 0 && errno == ESRCH) ||
        (h2 != me && kill(h2, 0) < 0 && errno == ESRCH))
      return -LINUX_ESRCH;
    return -LINUX_EPERM;
  }

  switch (type) {
  case LINUX_KCMP_VM:
  case LINUX_KCMP_FILES:
  case LINUX_KCMP_FS:
  case LINUX_KCMP_SIGHAND:
  case LINUX_KCMP_IO:
  case LINUX_KCMP_SYSVSEM:
    /* One process, so it shares every one of these with itself. */
    return 0;

  case LINUX_KCMP_FILE:
    return compare_fds((int) idx1, (int) idx2);

  case LINUX_KCMP_EPOLL_TFD: {
    struct l_kcmp_epoll_slot slot;
    if (copy_from_user(&slot, (gaddr_t) idx2, sizeof slot))
      return -LINUX_EFAULT;
    /*
     * toff picks the nth registration of one file in the set, which only
     * exists on Linux because a set may hold several entries for one struct
     * file reached through different descriptors. nabi's epoll registrations
     * are keyed by descriptor, so there is exactly one, and anything past the
     * first is honestly absent.
     */
    if (slot.toff != 0)
      return -LINUX_ENOENT;

    int regs[256];
    int n = epoll_registered_fds((int) idx1, regs, (int) (sizeof regs / sizeof *regs));
    if (n > (int) (sizeof regs / sizeof *regs))
      n = (int) (sizeof regs / sizeof *regs);

    bool unsure = false;
    for (int i = 0; i < n; i++) {
      int c = compare_fds(regs[i], (int) slot.tfd);
      if (c == 0)
        return 0;                       /* the file is in the set */
      if (c == -LINUX_EOPNOTSUPP)
        unsure = true;
    }
    /*
     * Not saying "absent" when one of the entries could not be compared. The
     * whole of this answer is a negative, and a negative built out of a
     * comparison that failed is a guess.
     */
    return unsure ? -LINUX_EOPNOTSUPP : -LINUX_ENOENT;
  }
  }

  return -LINUX_EINVAL;
}
