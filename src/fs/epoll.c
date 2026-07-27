/*
 * epoll, over kqueue.
 *
 * The two are close enough to translate but not congruent, and the differences
 * are where the work is:
 *
 *   - epoll describes a descriptor with one mask; kqueue uses a separate filter
 *     per direction. So a registration for EPOLLIN|EPOLLOUT is two kevents, and
 *     a wait that reports both has to fold them back into one epoll event, or a
 *     guest that expects one entry per ready descriptor sees two and may act on
 *     the same descriptor twice.
 *
 *   - epoll hands back an opaque 64-bit value the guest chose. kqueue's udata
 *     could carry it, but only what is *registered* comes back, so a MOD would
 *     have to rewrite every filter to change it. Keeping a registration table
 *     instead makes MOD and DEL exact, and is also what lets EPOLLONESHOT and a
 *     level-triggered EPOLLHUP behave.
 *
 *   - kqueue reports end-of-file as a flag on the read filter, where epoll has
 *     EPOLLHUP and EPOLLRDHUP; and an EV_ERROR entry is a per-event error rather
 *     than a failure of the wait.
 *
 * Only the descriptor types kqueue accepts work - sockets, pipes, ttys. A
 * regular file is always ready under epoll and cannot be registered with kqueue
 * at all, so it is answered directly rather than passed down.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "util/khash.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/signal.h"

/*
 * What the guest asked for, per (epoll fd, registered fd).
 *
 * Keyed by both, because one descriptor may sit in several epoll sets with
 * different masks and different data - a thing real event loops do.
 */
struct epoll_reg {
  uint32_t events;      /* the mask as the guest gave it, EPOLLET/ONESHOT and all */
  uint64_t data;        /* the guest's opaque value, returned verbatim */
};

KHASH_MAP_INIT_INT64(epoll, struct epoll_reg)
static khash_t(epoll) *epoll_regs;
static pthread_mutex_t epoll_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t
reg_key(int epfd, int fd)
{
  return ((uint64_t) (uint32_t) epfd << 32) | (uint32_t) fd;
}

static void
epoll_regs_init(void)
{
  if (epoll_regs == NULL)
    epoll_regs = kh_init(epoll);
}

/* Is this a descriptor kqueue will not take? Regular files and directories are
 * always ready as far as epoll is concerned. */
static bool
always_ready(int fd)
{
  struct stat st;
  if (fstat(fd, &st) < 0)
    return false;
  return S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
}

DEFINE_SYSCALL(epoll_create1, int, flags)
{
  if (flags & ~LINUX_EPOLL_CLOEXEC)
    return -LINUX_EINVAL;

  int kq = kqueue();
  if (kq < 0)
    return -darwin_to_linux_errno(errno);

  /* kqueue descriptors are not inherited across fork, which epoll's are; that
   * is a difference we cannot paper over here, but a guest that only uses its
   * epoll set in the process that made it - the overwhelmingly common case - is
   * unaffected. */
  /* register_fd returns 0 on success, not a descriptor: the guest's number for a
   * file is the host's, so the kqueue descriptor is what to hand back. */
  int err = register_fd(kq, (flags & LINUX_EPOLL_CLOEXEC) != 0);
  if (err < 0) {
    close(kq);
    return err;
  }
  return kq;
}

DEFINE_SYSCALL(epoll_ctl, int, epfd, int, op, int, fd, gaddr_t, event_ptr)
{
  struct l_epoll_event ev;
  memset(&ev, 0, sizeof ev);

  if (op != LINUX_EPOLL_CTL_DEL) {
    if (copy_from_user(&ev, event_ptr, sizeof ev))
      return -LINUX_EFAULT;
  }

  pthread_mutex_lock(&epoll_lock);
  epoll_regs_init();

  uint64_t key = reg_key(epfd, fd);
  khiter_t k = kh_get(epoll, epoll_regs, key);
  bool known = (k != kh_end(epoll_regs));

  int ret = 0;
  switch (op) {
  case LINUX_EPOLL_CTL_ADD:
    if (known) { ret = -LINUX_EEXIST; goto out; }
    break;
  case LINUX_EPOLL_CTL_MOD:
    if (!known) { ret = -LINUX_ENOENT; goto out; }
    break;
  case LINUX_EPOLL_CTL_DEL:
    if (!known) { ret = -LINUX_ENOENT; goto out; }
    break;
  default:
    ret = -LINUX_EINVAL;
    goto out;
  }

  /*
   * Apply to the kqueue. Deletes of a filter that was never added return ENOENT,
   * which is expected whenever the mask did not include that direction, so the
   * per-event errors are read back and ignored rather than failing the call.
   */
  if (!always_ready(fd)) {
    bool want_read  = (op != LINUX_EPOLL_CTL_DEL) && (ev.events & (LINUX_EPOLLIN | LINUX_EPOLLPRI | LINUX_EPOLLRDHUP));
    bool want_write = (op != LINUX_EPOLL_CTL_DEL) && (ev.events & LINUX_EPOLLOUT);

    uint16_t extra = 0;
    if (ev.events & LINUX_EPOLLET)      extra |= EV_CLEAR;
    if (ev.events & LINUX_EPOLLONESHOT) extra |= EV_ONESHOT;

    struct timespec zero = { 0, 0 };
    struct kevent kev[2], res[2];

    /*
     * Removals first, and their errors are all ignored: a direction that was
     * never registered - because the old mask did not include it - answers
     * ENOENT, and for one end of a pipe the wrong direction cannot be
     * registered at all. Neither is a failure of this call.
     */
    int n = 0;
    if (!want_read)
      EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (!want_write)
      EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    if (n > 0)
      (void) kevent(epfd, kev, n, res, n, &zero);

    /* Additions, where an error is real. */
    n = 0;
    if (want_read)
      EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE | extra, 0, 0, NULL);
    if (want_write)
      EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | extra, 0, 0, NULL);
    if (n > 0) {
      int nres = kevent(epfd, kev, n, res, n, &zero);
      if (nres < 0) {
        ret = -darwin_to_linux_errno(errno);
        goto out;
      }
      /* Only the entries kevent actually returned are initialized - reading
       * past them would read the stack and reject a registration that worked. */
      for (int i = 0; i < nres; i++) {
        if ((res[i].flags & EV_ERROR) && res[i].data != 0) {
          ret = -darwin_to_linux_errno((int) res[i].data);
          goto out;
        }
      }
    }
  }

  if (op == LINUX_EPOLL_CTL_DEL) {
    if (known)
      kh_del(epoll, epoll_regs, k);
  } else {
    int put;
    k = kh_put(epoll, epoll_regs, key, &put);
    kh_value(epoll_regs, k) = (struct epoll_reg){ ev.events, ev.data };
  }

out:
  pthread_mutex_unlock(&epoll_lock);
  return ret;
}

/*
 * The wait.
 *
 * Results are folded by descriptor: kqueue may report the read and the write
 * filter of one descriptor as two entries, and epoll owes the guest one.
 */
static int
epoll_wait_common(int epfd, gaddr_t events_ptr, int maxevents, int timeout)
{
  if (maxevents <= 0)
    return -LINUX_EINVAL;

  struct kevent *kev = calloc((size_t) maxevents * 2, sizeof *kev);
  struct l_epoll_event *out = calloc((size_t) maxevents, sizeof *out);
  if (!kev || !out) {
    free(kev); free(out);
    return -LINUX_ENOMEM;
  }

  struct timespec ts, *tsp = NULL;
  if (timeout >= 0) {
    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (long)(timeout % 1000) * 1000000L;
    tsp = &ts;
  }

  int n = kevent(epfd, NULL, 0, kev, maxevents * 2, tsp);
  if (n < 0) {
    int e = errno;
    free(kev); free(out);
    return -darwin_to_linux_errno(e);
  }

  pthread_mutex_lock(&epoll_lock);
  epoll_regs_init();

  int nout = 0;
  for (int i = 0; i < n; i++) {
    int fd = (int) kev[i].ident;

    uint32_t mask = 0;
    if (kev[i].filter == EVFILT_READ)  mask |= LINUX_EPOLLIN;
    if (kev[i].filter == EVFILT_WRITE) mask |= LINUX_EPOLLOUT;
    if (kev[i].flags & EV_EOF) {
      /* kqueue's one EOF flag covers both of epoll's hangups. The peer-closed
       * half - EPOLLRDHUP - is only reported if the guest asked for it, since a
       * guest that did not is entitled never to see that bit. */
      mask |= LINUX_EPOLLHUP;
    }
    if (kev[i].flags & EV_ERROR)
      mask |= LINUX_EPOLLERR;

    khiter_t k = kh_get(epoll, epoll_regs, reg_key(epfd, fd));
    if (k == kh_end(epoll_regs))
      continue;                       /* deleted since; not the guest's concern */
    struct epoll_reg reg = kh_value(epoll_regs, k);

    if ((kev[i].flags & EV_EOF) && (reg.events & LINUX_EPOLLRDHUP))
      mask |= LINUX_EPOLLRDHUP;

    /* Fold into an existing entry for this descriptor if there is one. */
    int slot = -1;
    for (int j = 0; j < nout; j++) {
      if (out[j].data == reg.data) { slot = j; break; }
    }
    if (slot < 0) {
      if (nout == maxevents)
        continue;
      slot = nout++;
      out[slot].data = reg.data;
      out[slot].events = 0;
    }
    out[slot].events |= mask;

    /* EPOLLONESHOT: the registration is spent once it has fired. The kqueue
     * side already disarmed itself via EV_ONESHOT. */
    if (reg.events & LINUX_EPOLLONESHOT)
      kh_del(epoll, epoll_regs, k);
  }

  pthread_mutex_unlock(&epoll_lock);

  int ret = nout;
  if (nout > 0 && copy_to_user(events_ptr, out, (size_t) nout * sizeof *out))
    ret = -LINUX_EFAULT;

  free(kev); free(out);
  return ret;
}

DEFINE_SYSCALL(epoll_pwait, int, epfd, gaddr_t, events, int, maxevents, int, timeout,
               gaddr_t, sigmask_ptr, size_t, sigsetsize)
{
  /*
   * The mask is installed around the wait rather than atomically inside it, as
   * in ppoll: a signal arriving between the two is not cut short the way a real
   * epoll_pwait would cut it. See sys_ppoll.
   */
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

  int ret = epoll_wait_common(epfd, events, maxevents, timeout);

  if (have_mask)
    sigprocmask(SIG_SETMASK, &saved, NULL);
  return ret;
}
