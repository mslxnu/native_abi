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
#include <limits.h>
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

/*
 * Everything registered on an epoll instance goes when its descriptor does.
 *
 * Without this the registrations outlive the instance, and a descriptor number
 * is reused: a later epoll_create1 that lands on the same number inherits them,
 * and adding a descriptor that instance has never seen answers EEXIST. That is
 * how this was found - a second epoll instance in one process, which is not an
 * exotic thing for an event loop to do.
 */
void
epoll_close(int epfd)
{
  pthread_mutex_lock(&epoll_lock);
  if (epoll_regs) {
    for (khiter_t k = kh_begin(epoll_regs); k != kh_end(epoll_regs); k++) {
      if (!kh_exist(epoll_regs, k))
        continue;
      if ((int) (kh_key(epoll_regs, k) >> 32) == epfd)
        kh_del(epoll, epoll_regs, k);
    }
  }
  pthread_mutex_unlock(&epoll_lock);
}

/*
 * Which descriptors are registered on an epoll instance, for kcmp.
 *
 * kcmp asks whether a *file* is in the set, not whether a descriptor number is,
 * so the caller has to compare identities rather than numbers - and identity is
 * decided in one place, in kcmp.c, which is why this hands back the list instead
 * of answering the question itself.
 *
 * Returns the number written, or the number that would have been needed if that
 * is more than max, so a caller can tell a full buffer from a complete one.
 */
int
epoll_registered_fds(int epfd, int *out, int max)
{
  int n = 0;
  pthread_mutex_lock(&epoll_lock);
  if (epoll_regs) {
    for (khiter_t k = kh_begin(epoll_regs); k != kh_end(epoll_regs); k++) {
      if (!kh_exist(epoll_regs, k))
        continue;
      if ((int) (kh_key(epoll_regs, k) >> 32) != epfd)
        continue;
      if (n < max)
        out[n] = (int) (uint32_t) kh_key(epoll_regs, k);
      n++;
    }
  }
  pthread_mutex_unlock(&epoll_lock);
  return n;
}

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
    if (want_read) {
      /* A binder device refuses a plain read filter (EINVAL); the NOTE_LOWAT
       * form is the one its selwakeup fires. */
      if (binder_fd(fd))
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE | extra, NOTE_LOWAT, 1, NULL);
      else
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE | extra, 0, 0, NULL);
    }
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

  /*
   * Descriptors that are readable because of pushback rather than because the
   * pipe has anything in it. kqueue cannot know about those, so they are
   * gathered from the registration table - which is keyed by (epfd, fd) and is
   * therefore already the list of what this set is watching.
   *
   * Collected before the wait because finding one means not waiting: an event
   * loop that blocks here is blocking on data the guest was handed by tee.
   */
  struct epoll_reg pb[64];
  int npb = 0;
  if (tee_pending() || pidfd_any()) {
    pthread_mutex_lock(&epoll_lock);
    epoll_regs_init();
    for (khiter_t k = kh_begin(epoll_regs); k != kh_end(epoll_regs); k++) {
      if (!kh_exist(epoll_regs, k))
        continue;
      uint64_t key = kh_key(epoll_regs, k);
      if ((int) (key >> 32) != epfd)
        continue;
      struct epoll_reg reg = kh_value(epoll_regs, k);
      if (!(reg.events & LINUX_EPOLLIN))
        continue;
      int rfd = (int) (uint32_t) key;
      /*
       * Two things kqueue will not report. Bytes tee is holding in front of a
       * pipe, and a pidfd whose process has gone - the latter because kqueue
       * does not raise EVFILT_READ for a regular file at all, which is what a
       * pidfd is here. Without this an event loop waiting on a pidfd would
       * never learn that the process exited.
       */
      if (npb < (int) (sizeof pb / sizeof pb[0]) &&
          (tee_readable(rfd) || pidfd_readable(rfd)))
        pb[npb++] = reg;
    }
    pthread_mutex_unlock(&epoll_lock);
    if (npb > 0) {
      ts.tv_sec = 0;
      ts.tv_nsec = 0;
      tsp = &ts;
    }
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

  /* Fold the pushback ones in, on the same terms: an entry per descriptor, and
   * only if the wait did not already report it. */
  for (int i = 0; i < npb && nout < maxevents; i++) {
    int slot = -1;
    for (int j = 0; j < nout; j++) {
      if (out[j].data == pb[i].data) { slot = j; break; }
    }
    if (slot < 0) {
      slot = nout++;
      out[slot].data = pb[i].data;
      out[slot].events = 0;
    }
    out[slot].events |= LINUX_EPOLLIN;
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

/*
 * The older spellings, which are the same calls with less in them.
 *
 * epoll_create takes a size hint that has meant nothing since 2.6.8 - the
 * kernel sizes the set itself - and Linux keeps it only so that programs
 * compiled against the old header still run. It is required to be positive,
 * which is the one part still worth enforcing: a caller passing 0 has almost
 * certainly confused it with epoll_create1's flags.
 */
DEFINE_SYSCALL(epoll_create, int, size)
{
  if (size <= 0)
    return -LINUX_EINVAL;
  return sys_epoll_create1(0);
}

/* epoll_wait is epoll_pwait without the mask, and passing no mask is exactly
 * what a null sigmask means. */
DEFINE_SYSCALL(epoll_wait, int, epfd, gaddr_t, events, int, maxevents,
               int, timeout)
{
  return sys_epoll_pwait(epfd, events, maxevents, timeout, 0, 0);
}

/*
 * epoll_pwait2 differs from epoll_pwait in one thing: the timeout arrives as a
 * timespec rather than a count of milliseconds, so a caller can ask for less
 * than a millisecond and can tell "no timeout" from "zero" by the pointer
 * rather than by a magic -1.
 *
 * The nanoseconds are rounded *up* to a millisecond, because the wait
 * underneath counts in milliseconds and a sub-millisecond request rounded down
 * becomes a poll that does not wait at all - which is a busy loop where the
 * caller asked for a short sleep.
 */
DEFINE_SYSCALL(epoll_pwait2, int, epfd, gaddr_t, events, int, maxevents,
               gaddr_t, timeout_ptr, gaddr_t, sigmask, size_t, sigsetsize)
{
  int timeout = -1;
  if (timeout_ptr) {
    struct l_timespec ts;
    if (copy_from_user(&ts, timeout_ptr, sizeof ts))
      return -LINUX_EFAULT;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
      return -LINUX_EINVAL;
    int64_t ms = (int64_t) ts.tv_sec * 1000 + (ts.tv_nsec + 999999) / 1000000;
    timeout = ms > INT_MAX ? INT_MAX : (int) ms;
  }
  return sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
}
