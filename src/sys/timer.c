/*
 * POSIX timers and timerfds, on a host that has neither.
 *
 * Darwin does not implement timer_create at all - there is no timer_t in its
 * headers - and it has no timerfd. What it has is threads and a condition
 * variable that can be waited on until a deadline, which is enough to build
 * both, because both are the same object with different ways of telling you it
 * fired: a timerfd makes a descriptor readable, a POSIX timer raises a signal.
 *
 * So there is one engine here and two faces on it. A timer is a deadline, an
 * interval and a thread asleep until the first of them; when it wakes it counts
 * the expiry, computes the next deadline and does whichever of the two things
 * it was made for.
 *
 * The timerfd's descriptor is the read end of a pipe, as inotify's and
 * fanotify's are, so poll, select and epoll work on it without being taught
 * anything - which matters more here than anywhere else, because a timerfd
 * exists to be put in an event loop. What read(2) returns is not what is in the
 * pipe, though: Linux answers with the *number of expirations since the last
 * read*, as a u64, and resets it. The pipe carries readability and the count is
 * kept beside it.
 *
 * What POSIX timers cannot do here is the one thing worth stating plainly.
 * SIGEV_SIGNAL asks for a signal, and nabi's send_signal drops every signal at
 * or above SIGRTMIN - Darwin has no realtime signals to map them onto - so a
 * timer asked to raise one would be a timer that never fired. glibc's
 * SIGEV_THREAD is built on exactly that: it registers SIGEV_THREAD_ID against
 * SIGTIMER, which is SIGRTMIN. Those are refused at timer_create rather than
 * accepted, because a caller told its timer was created and then never woken
 * has no way to find out why, and the failure surfaces a long way from here.
 * SIGEV_NONE - the form that is polled with timer_gettime - and a signal nabi
 * can actually deliver both work.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/misc.h"
#include "linux/time.h"

#include "util/khash.h"

#define NS_PER_SEC 1000000000LL

/* Both faces of the same object. */
enum timer_kind { TIMER_FD, TIMER_POSIX };

struct nabi_timer {
  enum timer_kind kind;
  int             clockid;      /* the guest's LINUX_CLOCK_* */

  pthread_mutex_t lock;
  pthread_cond_t  cv;
  pthread_t       thread;
  bool            running;
  bool            armed;

  int64_t         next_ns;      /* absolute, on this timer's clock */
  int64_t         interval_ns;  /* 0 for one-shot */

  /* TIMER_FD */
  int             rd, wr;
  uint64_t        count;        /* expirations since the last read */

  /* TIMER_POSIX */
  int             signo;        /* 0 for SIGEV_NONE */
  int             overrun;      /* of the most recent delivery */
  int             pending_overrun;
};

KHASH_MAP_INIT_INT(timerfd, struct nabi_timer *)
static khash_t(timerfd) *timerfds;          /* by guest descriptor */
KHASH_MAP_INIT_INT(ptimer, struct nabi_timer *)
static khash_t(ptimer) *ptimers;            /* by timer id */
static int next_timer_id = 1;
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ clock */

static int
host_clock(int l_clockid)
{
  switch (l_clockid) {
  case LINUX_CLOCK_REALTIME:
  case LINUX_CLOCK_REALTIME_COARSE:
    return CLOCK_REALTIME;
  case LINUX_CLOCK_MONOTONIC:
  case LINUX_CLOCK_MONOTONIC_COARSE:
  case LINUX_CLOCK_BOOTTIME:
    return CLOCK_MONOTONIC;
  default:
    return -1;
  }
}

static int64_t
now_ns(int l_clockid)
{
  struct timespec ts;
  clock_gettime(host_clock(l_clockid), &ts);
  return (int64_t) ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static int64_t
l_timespec_ns(const struct l_timespec *t)
{
  return (int64_t) t->tv_sec * NS_PER_SEC + t->tv_nsec;
}

static void
ns_to_l_timespec(int64_t ns, struct l_timespec *out)
{
  if (ns < 0)
    ns = 0;
  out->tv_sec = ns / NS_PER_SEC;
  out->tv_nsec = ns % NS_PER_SEC;
}

/* ----------------------------------------------------------------- engine */

/*
 * One thread per timer, asleep until its deadline.
 *
 * The wait is on a condition variable rather than a plain sleep so that
 * settime can move the deadline - or disarm the timer - without waiting for the
 * old one to pass, which is what a program rearming a timer in its event loop
 * does constantly.
 */
static void *
timer_thread(void *arg)
{
  struct nabi_timer *t = arg;

  pthread_mutex_lock(&t->lock);
  while (t->running) {
    if (!t->armed) {
      pthread_cond_wait(&t->cv, &t->lock);
      continue;
    }

    int64_t now = now_ns(t->clockid);
    if (now < t->next_ns) {
      /* pthread_cond_timedwait measures against the real clock whatever the
       * timer's own clock is, so the interval is what carries over, not the
       * instant. */
      int64_t delta = t->next_ns - now;
      struct timespec until;
      clock_gettime(CLOCK_REALTIME, &until);
      until.tv_sec += delta / NS_PER_SEC;
      until.tv_nsec += delta % NS_PER_SEC;
      if (until.tv_nsec >= NS_PER_SEC) {
        until.tv_nsec -= NS_PER_SEC;
        until.tv_sec++;
      }
      pthread_cond_timedwait(&t->cv, &t->lock, &until);
      continue;                 /* re-read the state; settime may have moved it */
    }

    /*
     * Expired. An interval timer that has fallen behind counts every deadline
     * that passed rather than only the last: that count is what read(2) returns
     * on a timerfd and what timer_getoverrun reports, and it is how a program
     * that was slow finds out it was.
     */
    uint64_t ticks = 1;
    if (t->interval_ns > 0) {
      int64_t late = now - t->next_ns;
      ticks += (uint64_t) (late / t->interval_ns);
      t->next_ns += (int64_t) ticks * t->interval_ns;
    } else {
      t->armed = false;         /* one-shot */
    }

    if (t->kind == TIMER_FD) {
      t->count += ticks;
      /* One byte is enough to make it readable; the count is the answer, and
       * writing per tick would fill the pipe and block this thread. */
      char b = 1;
      (void) !write(t->wr, &b, 1);
    } else {
      t->overrun = (int) ticks - 1;
      if (t->signo != 0) {
        int sig = t->signo;
        pthread_mutex_unlock(&t->lock);
        send_signal(getpid(), sig);
        pthread_mutex_lock(&t->lock);
      }
    }
  }
  pthread_mutex_unlock(&t->lock);
  return NULL;
}

static struct nabi_timer *
timer_new(enum timer_kind kind, int l_clockid)
{
  struct nabi_timer *t = calloc(1, sizeof *t);
  if (!t)
    return NULL;
  t->kind = kind;
  t->clockid = l_clockid;
  t->running = true;
  t->rd = t->wr = -1;
  pthread_mutex_init(&t->lock, NULL);
  pthread_cond_init(&t->cv, NULL);
  return t;
}

static void
timer_destroy(struct nabi_timer *t)
{
  pthread_mutex_lock(&t->lock);
  t->running = false;
  t->armed = false;
  pthread_cond_signal(&t->cv);
  pthread_mutex_unlock(&t->lock);
  pthread_join(t->thread, NULL);

  if (t->wr >= 0)
    close(t->wr);
  pthread_cond_destroy(&t->cv);
  pthread_mutex_destroy(&t->lock);
  free(t);
}

/* Arm or disarm, reporting what the previous setting had been. */
static void
timer_set(struct nabi_timer *t, bool absolute, int64_t value_ns,
          int64_t interval_ns, struct l_itimerspec *old)
{
  pthread_mutex_lock(&t->lock);

  if (old) {
    ns_to_l_timespec(t->interval_ns, &old->it_interval);
    if (t->armed) {
      int64_t left = t->next_ns - now_ns(t->clockid);
      ns_to_l_timespec(left > 0 ? left : 0, &old->it_value);
    } else {
      old->it_value.tv_sec = old->it_value.tv_nsec = 0;
    }
  }

  if (value_ns == 0) {
    t->armed = false;           /* a zero it_value disarms, as on Linux */
    t->interval_ns = interval_ns;
  } else {
    t->interval_ns = interval_ns;
    t->next_ns = absolute ? value_ns : now_ns(t->clockid) + value_ns;
    t->armed = true;
  }
  pthread_cond_signal(&t->cv);
  pthread_mutex_unlock(&t->lock);
}

static void
timer_get(struct nabi_timer *t, struct l_itimerspec *out)
{
  pthread_mutex_lock(&t->lock);
  ns_to_l_timespec(t->interval_ns, &out->it_interval);
  if (t->armed) {
    int64_t left = t->next_ns - now_ns(t->clockid);
    ns_to_l_timespec(left > 0 ? left : 0, &out->it_value);
  } else {
    out->it_value.tv_sec = out->it_value.tv_nsec = 0;
  }
  pthread_mutex_unlock(&t->lock);
}

/* --------------------------------------------------------------- timerfd */

static struct nabi_timer *
timerfd_of(int fd)
{
  if (!timerfds)
    return NULL;
  pthread_mutex_lock(&table_lock);
  khiter_t k = kh_get(timerfd, timerfds, fd);
  struct nabi_timer *t = k == kh_end(timerfds) ? NULL : kh_value(timerfds, k);
  pthread_mutex_unlock(&table_lock);
  return t;
}

DEFINE_SYSCALL(timerfd_create, int, clockid, int, flags)
{
  if (host_clock(clockid) < 0)
    return -LINUX_EINVAL;
  if (flags & ~(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC))
    return -LINUX_EINVAL;

  int p[2];
  if (pipe(p) < 0)
    return -darwin_to_linux_errno(errno);

  struct nabi_timer *t = timer_new(TIMER_FD, clockid);
  if (!t) {
    close(p[0]); close(p[1]);
    return -LINUX_ENOMEM;
  }
  t->rd = p[0];
  t->wr = p[1];
  /* The pipe never blocks this side: a full one already means readable, which
   * is all the descriptor has to be. */
  fcntl(t->wr, F_SETFL, O_NONBLOCK);
  if (flags & LINUX_TFD_NONBLOCK)
    fcntl(t->rd, F_SETFL, O_NONBLOCK);
  if (flags & LINUX_TFD_CLOEXEC)
    fcntl(t->rd, F_SETFD, FD_CLOEXEC);

  if (pthread_create(&t->thread, NULL, timer_thread, t) != 0) {
    close(p[0]); close(p[1]); free(t);
    return -LINUX_ENOMEM;
  }

  int err = register_fd(t->rd, (flags & LINUX_TFD_CLOEXEC) != 0);
  if (err < 0) {
    close(p[0]);
    timer_destroy(t);
    return err;
  }

  pthread_mutex_lock(&table_lock);
  if (!timerfds)
    timerfds = kh_init(timerfd);
  int ret;
  khiter_t k = kh_put(timerfd, timerfds, t->rd, &ret);
  kh_value(timerfds, k) = t;
  pthread_mutex_unlock(&table_lock);
  return t->rd;
}

DEFINE_SYSCALL(timerfd_settime, int, fd, int, flags, gaddr_t, new_ptr,
               gaddr_t, old_ptr)
{
  struct nabi_timer *t = timerfd_of(fd);
  if (!t)
    return -LINUX_EBADF;
  if (flags & ~LINUX_TFD_TIMER_ABSTIME)
    return -LINUX_EINVAL;

  struct l_itimerspec spec, old;
  if (copy_from_user(&spec, new_ptr, sizeof spec))
    return -LINUX_EFAULT;
  if (spec.it_value.tv_nsec < 0 || spec.it_value.tv_nsec >= NS_PER_SEC ||
      spec.it_interval.tv_nsec < 0 || spec.it_interval.tv_nsec >= NS_PER_SEC)
    return -LINUX_EINVAL;

  timer_set(t, (flags & LINUX_TFD_TIMER_ABSTIME) != 0,
            l_timespec_ns(&spec.it_value), l_timespec_ns(&spec.it_interval),
            old_ptr ? &old : NULL);
  if (old_ptr && copy_to_user(old_ptr, &old, sizeof old))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(timerfd_gettime, int, fd, gaddr_t, out_ptr)
{
  struct nabi_timer *t = timerfd_of(fd);
  if (!t)
    return -LINUX_EBADF;
  struct l_itimerspec spec;
  timer_get(t, &spec);
  if (copy_to_user(out_ptr, &spec, sizeof spec))
    return -LINUX_EFAULT;
  return 0;
}

/*
 * Reading a timerfd is not reading the pipe.
 *
 * Linux answers with the number of expirations since the last read and resets
 * the count; the pipe underneath only carries readability, so the byte in it is
 * drained and the number comes from beside it.
 */
bool
timerfd_read(int fd, char *out, size_t size, int *ret)
{
  struct nabi_timer *t = timerfd_of(fd);
  if (!t)
    return false;

  if (size < sizeof(uint64_t)) {
    *ret = -LINUX_EINVAL;
    return true;
  }

  for (;;) {
    pthread_mutex_lock(&t->lock);
    uint64_t n = t->count;
    t->count = 0;
    pthread_mutex_unlock(&t->lock);

    if (n != 0) {
      char drain[64];
      while (read(t->rd, drain, sizeof drain) > 0)
        ;
      memcpy(out, &n, sizeof n);
      *ret = (int) sizeof n;
      return true;
    }

    /* Nothing yet. A non-blocking descriptor says so; a blocking one waits on
     * the pipe, which is what the timer thread makes readable. */
    int fl = fcntl(t->rd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK)) {
      *ret = -LINUX_EAGAIN;
      return true;
    }
    char b;
    ssize_t r = read(t->rd, &b, 1);
    if (r < 0 && errno != EINTR && errno != EAGAIN) {
      *ret = -darwin_to_linux_errno(errno);
      return true;
    }
    if (r < 0 && errno == EINTR && has_sigpending()) {
      *ret = -LINUX_EINTR;
      return true;
    }
  }
}

void
timerfd_close(int fd)
{
  if (!timerfds)
    return;
  pthread_mutex_lock(&table_lock);
  khiter_t k = kh_get(timerfd, timerfds, fd);
  if (k == kh_end(timerfds)) {
    pthread_mutex_unlock(&table_lock);
    return;
  }
  struct nabi_timer *t = kh_value(timerfds, k);
  kh_del(timerfd, timerfds, k);
  pthread_mutex_unlock(&table_lock);
  timer_destroy(t);
}

/* ---------------------------------------------------------- POSIX timers */

static struct nabi_timer *
ptimer_of(int id)
{
  if (!ptimers)
    return NULL;
  pthread_mutex_lock(&table_lock);
  khiter_t k = kh_get(ptimer, ptimers, id);
  struct nabi_timer *t = k == kh_end(ptimers) ? NULL : kh_value(ptimers, k);
  pthread_mutex_unlock(&table_lock);
  return t;
}

DEFINE_SYSCALL(timer_create, int, clockid, gaddr_t, sevp_ptr, gaddr_t, id_ptr)
{
  if (host_clock(clockid) < 0)
    return -LINUX_EINVAL;

  int signo = 0;
  if (sevp_ptr != 0) {
    struct l_sigevent sev;
    if (copy_from_user(&sev, sevp_ptr, sizeof sev))
      return -LINUX_EFAULT;

    switch (sev.sigev_notify) {
    case LINUX_SIGEV_NONE:
      signo = 0;
      break;
    case LINUX_SIGEV_SIGNAL:
    case LINUX_SIGEV_THREAD_ID:
      if (sev.sigev_signo < 1 || sev.sigev_signo > LINUX_NSIG)
        return -LINUX_EINVAL;
      /*
       * A signal nabi cannot deliver would make this a timer that never fires,
       * and a caller told its timer was created has no way to find that out.
       * send_signal drops everything at or above SIGRTMIN, because Darwin has
       * no realtime signals to carry them - so those are refused here, where
       * the caller is still in a position to see it. glibc's SIGEV_THREAD is
       * built on exactly this (SIGEV_THREAD_ID against SIGTIMER = SIGRTMIN), so
       * that form is refused too rather than silently never arriving.
       */
      if (sev.sigev_signo >= LINUX_SIGRTMIN)
        return -LINUX_EINVAL;
      signo = sev.sigev_signo;
      break;
    default:
      return -LINUX_EINVAL;     /* SIGEV_THREAD is glibc's, never the kernel's */
    }
  } else {
    signo = LINUX_SIGALRM;      /* what Linux defaults to */
  }

  struct nabi_timer *t = timer_new(TIMER_POSIX, clockid);
  if (!t)
    return -LINUX_ENOMEM;
  t->signo = signo;
  if (pthread_create(&t->thread, NULL, timer_thread, t) != 0) {
    free(t);
    return -LINUX_ENOMEM;
  }

  pthread_mutex_lock(&table_lock);
  if (!ptimers)
    ptimers = kh_init(ptimer);
  int id = next_timer_id++;
  int ret;
  khiter_t k = kh_put(ptimer, ptimers, id, &ret);
  kh_value(ptimers, k) = t;
  pthread_mutex_unlock(&table_lock);

  if (copy_to_user(id_ptr, &id, sizeof id)) {
    /* The guest never learned the id, so nothing can ever refer to it: take it
     * back out rather than leaving a thread running for a timer nobody has. */
    pthread_mutex_lock(&table_lock);
    khiter_t dead = kh_get(ptimer, ptimers, id);
    if (dead != kh_end(ptimers))
      kh_del(ptimer, ptimers, dead);
    pthread_mutex_unlock(&table_lock);
    timer_destroy(t);
    return -LINUX_EFAULT;
  }
  return 0;
}

DEFINE_SYSCALL(timer_settime, int, id, int, flags, gaddr_t, new_ptr,
               gaddr_t, old_ptr)
{
  struct nabi_timer *t = ptimer_of(id);
  if (!t)
    return -LINUX_EINVAL;
  if (flags & ~LINUX_TIMER_ABSTIME)
    return -LINUX_EINVAL;

  struct l_itimerspec spec, old;
  if (copy_from_user(&spec, new_ptr, sizeof spec))
    return -LINUX_EFAULT;
  if (spec.it_value.tv_nsec < 0 || spec.it_value.tv_nsec >= NS_PER_SEC ||
      spec.it_interval.tv_nsec < 0 || spec.it_interval.tv_nsec >= NS_PER_SEC)
    return -LINUX_EINVAL;

  timer_set(t, (flags & LINUX_TIMER_ABSTIME) != 0,
            l_timespec_ns(&spec.it_value), l_timespec_ns(&spec.it_interval),
            old_ptr ? &old : NULL);
  if (old_ptr && copy_to_user(old_ptr, &old, sizeof old))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(timer_gettime, int, id, gaddr_t, out_ptr)
{
  struct nabi_timer *t = ptimer_of(id);
  if (!t)
    return -LINUX_EINVAL;
  struct l_itimerspec spec;
  timer_get(t, &spec);
  if (copy_to_user(out_ptr, &spec, sizeof spec))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(timer_getoverrun, int, id)
{
  struct nabi_timer *t = ptimer_of(id);
  if (!t)
    return -LINUX_EINVAL;
  pthread_mutex_lock(&t->lock);
  int n = t->overrun;
  pthread_mutex_unlock(&t->lock);
  return n;
}

DEFINE_SYSCALL(timer_delete, int, id)
{
  if (!ptimers)
    return -LINUX_EINVAL;
  pthread_mutex_lock(&table_lock);
  khiter_t k = kh_get(ptimer, ptimers, id);
  if (k == kh_end(ptimers)) {
    pthread_mutex_unlock(&table_lock);
    return -LINUX_EINVAL;
  }
  struct nabi_timer *t = kh_value(ptimers, k);
  kh_del(ptimer, ptimers, k);
  pthread_mutex_unlock(&table_lock);
  timer_destroy(t);
  return 0;
}
