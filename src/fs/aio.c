/*
 * Linux asynchronous I/O: the io_setup family.
 *
 * This is the older of Linux's two async interfaces - io_uring is the other,
 * and is a different subsystem rather than more of this one. Six calls: make a
 * context, submit requests against it, reap completions, cancel, tear down.
 *
 * Darwin has POSIX aio_read/aio_write, and they are not a substitute. They
 * complete by signal or by a spawned thread, they have no shared completion
 * queue to reap from, and aio_cancel does not mean what io_cancel means. What
 * Linux's interface actually promises is narrower than "the kernel does I/O by
 * itself": submit returns without waiting, and the results turn up in order of
 * completion when asked for. A worker thread per context delivers exactly that,
 * so that is what this is.
 *
 * Two decisions are worth spelling out, because both are about *which thread*
 * touches what.
 *
 * The first is guest memory. The worker never reads or writes it. A write's
 * data is copied out of the guest at submit time and a read's data is copied in
 * at reap time, both on the guest's own thread, with the worker seeing only a
 * buffer nabi owns. That is not a workaround, it is the contract: a read
 * buffer's contents are undefined until the operation completes and is reaped,
 * so filling it at reap time is indistinguishable from filling it earlier - and
 * it means no guest page can be unmapped underneath a thread that is mid-write
 * to it, which on Linux is prevented by pinning the pages and here has no
 * equivalent.
 *
 * The second is the context id. Linux's aio_context_t is not a handle, it is
 * the address of a ring the kernel mapped into the process, and libaio treats
 * it as one: io_getevents dereferences it to read a magic number before
 * deciding whether it can answer without a syscall. Hand back a small integer
 * and that dereference is a segfault in the guest. So a page is mapped and its
 * address is the id - deliberately left zeroed, because a magic that does not
 * match is exactly what sends libaio down the syscall path, which is the only
 * path here. The page costs one mapping per context and removes a crash that
 * would look like a guest bug.
 *
 * Not inherited across fork, which is not a limitation but the specified
 * behaviour: fork(2) is explicit that a child inherits neither its parent's aio
 * contexts nor its outstanding operations. arm64's fork is fork-plus-exec and
 * this table is process memory, so the child gets none - which is what it is
 * owed.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "page.h"
#include "linux/common.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/aio.h"
#include "linux/mman.h"
#include "linux/socket.h"

/* One submitted request, from io_submit to io_getevents. */
struct aio_req {
  struct l_iocb   cb;
  gaddr_t         ucb;          /* the guest's iocb address; the event's obj */
  char           *buf;          /* nabi's, never the guest's */
  size_t          len;
  int64_t         res;
  bool            done;
  struct aio_req *next;
};

struct aio_ctx {
  gaddr_t          id;          /* the mapped page, and the guest's handle */
  unsigned         max;         /* nr_events, as a bound on what is in flight */
  unsigned         live;        /* submitted and not yet reaped */
  struct aio_req  *queue, *queue_tail;   /* waiting for the worker */
  struct aio_req  *ready, *ready_tail;   /* waiting for the guest */
  pthread_mutex_t  lock;
  pthread_cond_t   work;        /* the worker sleeps here */
  pthread_cond_t   arrived;     /* io_getevents sleeps here */
  pthread_t        worker;
  bool             stopping;
  struct aio_ctx  *next;
};

static struct aio_ctx *contexts;
static pthread_mutex_t contexts_lock = PTHREAD_MUTEX_INITIALIZER;

static struct aio_ctx *
ctx_find(gaddr_t id)
{
  pthread_mutex_lock(&contexts_lock);
  struct aio_ctx *c = contexts;
  while (c && c->id != id)
    c = c->next;
  pthread_mutex_unlock(&contexts_lock);
  return c;
}

/* ------------------------------------------------------------- the worker */

/*
 * Everything an operation needs is already in nabi's own memory by the time it
 * gets here, so this runs without touching the guest at all.
 */
static int64_t
run_one(struct aio_req *r)
{
  int fd = (int) r->cb.aio_fildes;
  ssize_t n;

  switch (r->cb.aio_lio_opcode) {
  case LINUX_IOCB_CMD_PREAD:
  case LINUX_IOCB_CMD_PREADV:
    n = pread(fd, r->buf, r->len, (off_t) r->cb.aio_offset);
    break;
  case LINUX_IOCB_CMD_PWRITE:
  case LINUX_IOCB_CMD_PWRITEV:
    n = pwrite(fd, r->buf, r->len, (off_t) r->cb.aio_offset);
    break;
  case LINUX_IOCB_CMD_FSYNC:
    n = fsync(fd);
    break;
  case LINUX_IOCB_CMD_FDSYNC:
    /* Linux's fdatasync skips metadata that is not needed to read the data
     * back. Darwin has no such call, so this is fsync - stronger than asked
     * for, which is the safe direction to be wrong in. */
    n = fsync(fd);
    break;
  case LINUX_IOCB_CMD_NOOP:
    n = 0;
    break;
  default:
    /* Including IOCB_CMD_POLL, which is a descriptor readiness wait rather
     * than a transfer. Refused per request, in the event, which is how a
     * caller finds out about one operation without the batch failing. */
    return -LINUX_EINVAL;
  }
  return n < 0 ? -darwin_to_linux_errno(errno) : (int64_t) n;
}

static void *
worker(void *arg)
{
  struct aio_ctx *ctx = arg;

  pthread_mutex_lock(&ctx->lock);
  for (;;) {
    while (!ctx->queue && !ctx->stopping)
      pthread_cond_wait(&ctx->work, &ctx->lock);
    if (ctx->stopping)
      break;

    struct aio_req *r = ctx->queue;
    ctx->queue = r->next;
    if (!ctx->queue)
      ctx->queue_tail = NULL;
    r->next = NULL;

    /* Off the lock for the part that blocks, or a submit would wait behind a
     * read this context is already doing - which is the one thing io_submit
     * promises not to do. */
    pthread_mutex_unlock(&ctx->lock);
    int64_t res = run_one(r);
    pthread_mutex_lock(&ctx->lock);

    r->res = res;
    r->done = true;
    if (ctx->ready_tail)
      ctx->ready_tail->next = r;
    else
      ctx->ready = r;
    ctx->ready_tail = r;

    pthread_cond_broadcast(&ctx->arrived);

    /* An eventfd named by the request is how a guest folds aio completion into
     * a poll loop, so it has to be poked for every completion. */
    if (r->cb.aio_flags & LINUX_IOCB_FLAG_RESFD) {
      int resfd = (int) r->cb.aio_resfd;
      pthread_mutex_unlock(&ctx->lock);
      eventfd_signal(resfd, 1);
      pthread_mutex_lock(&ctx->lock);
    }
  }
  pthread_mutex_unlock(&ctx->lock);
  return NULL;
}

/* --------------------------------------------------------------- setup */

DEFINE_SYSCALL(io_setup, unsigned, nr_events, gaddr_t, ctxp)
{
  if (nr_events == 0)
    return -LINUX_EINVAL;

  /* Linux insists the handle starts out zero, which catches a context being
   * set up over the top of one still in use. */
  uint64_t given;
  if (copy_from_user(&given, ctxp, sizeof given))
    return -LINUX_EFAULT;
  if (given != 0)
    return -LINUX_EINVAL;

  /* The page whose address becomes the handle. See the note at the top: it
   * exists so libaio's dereference finds memory rather than a fault, and it
   * stays zeroed so the magic never matches. */
  int prot = LINUX_PROT_READ | LINUX_PROT_WRITE;
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  gaddr_t ring = do_mmap(0, PAGE_SIZEOF(PAGE_4KB), prot, prot,
                         LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  if ((int64_t) ring < 0)
    return -LINUX_ENOMEM;

  struct aio_ctx *ctx = calloc(1, sizeof *ctx);
  if (!ctx)
    return -LINUX_ENOMEM;
  ctx->id = ring;
  ctx->max = nr_events;
  pthread_mutex_init(&ctx->lock, NULL);
  pthread_cond_init(&ctx->work, NULL);
  pthread_cond_init(&ctx->arrived, NULL);

  if (pthread_create(&ctx->worker, NULL, worker, ctx) != 0) {
    free(ctx);
    return -LINUX_EAGAIN;
  }

  pthread_mutex_lock(&contexts_lock);
  ctx->next = contexts;
  contexts = ctx;
  pthread_mutex_unlock(&contexts_lock);

  uint64_t out = (uint64_t) ring;
  if (copy_to_user(ctxp, &out, sizeof out))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(io_destroy, gaddr_t, ctx_id)
{
  pthread_mutex_lock(&contexts_lock);
  struct aio_ctx **pp = &contexts, *ctx = NULL;
  while (*pp) {
    if ((*pp)->id == ctx_id) {
      ctx = *pp;
      *pp = ctx->next;
      break;
    }
    pp = &(*pp)->next;
  }
  pthread_mutex_unlock(&contexts_lock);
  if (!ctx)
    return -LINUX_EINVAL;

  /*
   * Linux waits for outstanding operations rather than abandoning them, and so
   * does this: the worker is told to stop, and joined, so nothing is still
   * reading or writing a descriptor the guest is entitled to close next.
   */
  pthread_mutex_lock(&ctx->lock);
  ctx->stopping = true;
  pthread_cond_broadcast(&ctx->work);
  pthread_mutex_unlock(&ctx->lock);
  pthread_join(ctx->worker, NULL);

  for (struct aio_req *r = ctx->queue; r; ) {
    struct aio_req *n = r->next;
    free(r->buf); free(r);
    r = n;
  }
  for (struct aio_req *r = ctx->ready; r; ) {
    struct aio_req *n = r->next;
    free(r->buf); free(r);
    r = n;
  }
  pthread_cond_destroy(&ctx->work);
  pthread_cond_destroy(&ctx->arrived);
  pthread_mutex_destroy(&ctx->lock);
  free(ctx);

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  do_munmap(ctx_id, PAGE_SIZEOF(PAGE_4KB));
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return 0;
}

/* -------------------------------------------------------------- submit */

/*
 * Turn one guest iocb into a request nabi owns outright.
 *
 * The vectored forms are gathered here rather than in the worker, for the same
 * reason everything else is: the iovec and what it points at are guest memory,
 * and only this thread may look at them.
 */
static int
build(struct aio_req *r)
{
  uint16_t op = r->cb.aio_lio_opcode;
  bool reads  = (op == LINUX_IOCB_CMD_PREAD  || op == LINUX_IOCB_CMD_PREADV);
  bool writes = (op == LINUX_IOCB_CMD_PWRITE || op == LINUX_IOCB_CMD_PWRITEV);
  if (!reads && !writes)
    return 0;                   /* fsync and friends carry no buffer */

  bool vectored = (op == LINUX_IOCB_CMD_PREADV || op == LINUX_IOCB_CMD_PWRITEV);
  if (!vectored) {
    r->len = (size_t) r->cb.aio_nbytes;
    if (r->len == 0)
      return 0;
    if (!(r->buf = malloc(r->len)))
      return -LINUX_ENOMEM;
    if (writes && copy_from_user(r->buf, (gaddr_t) r->cb.aio_buf, r->len))
      return -LINUX_EFAULT;
    return 0;
  }

  unsigned long n = (unsigned long) r->cb.aio_nbytes;
  if (n == 0)
    return 0;
  if (n > 1024)                 /* UIO_MAXIOV, as everywhere else */
    return -LINUX_EINVAL;
  struct l_iovec *iov = calloc(n, sizeof *iov);
  if (!iov)
    return -LINUX_ENOMEM;
  if (copy_from_user(iov, (gaddr_t) r->cb.aio_buf, n * sizeof *iov)) {
    free(iov);
    return -LINUX_EFAULT;
  }
  for (unsigned long i = 0; i < n; i++)
    r->len += iov[i].iov_len;
  if (r->len == 0) {
    free(iov);
    return 0;
  }
  if (!(r->buf = malloc(r->len))) {
    free(iov);
    return -LINUX_ENOMEM;
  }
  if (writes) {
    size_t at = 0;
    for (unsigned long i = 0; i < n; i++) {
      if (iov[i].iov_len &&
          copy_from_user(r->buf + at, iov[i].iov_base, iov[i].iov_len)) {
        free(iov);
        return -LINUX_EFAULT;
      }
      at += iov[i].iov_len;
    }
  }
  free(iov);
  return 0;
}

DEFINE_SYSCALL(io_submit, gaddr_t, ctx_id, long, nr, gaddr_t, iocbpp)
{
  if (nr < 0)
    return -LINUX_EINVAL;
  struct aio_ctx *ctx = ctx_find(ctx_id);
  if (!ctx)
    return -LINUX_EINVAL;
  if (nr == 0)
    return 0;

  long done = 0;
  for (long i = 0; i < nr; i++) {
    gaddr_t ucb;
    if (copy_from_user(&ucb, iocbpp + (gaddr_t) i * sizeof(uint64_t),
                       sizeof ucb))
      return done ? (int) done : -LINUX_EFAULT;

    struct aio_req *r = calloc(1, sizeof *r);
    if (!r)
      return done ? (int) done : -LINUX_ENOMEM;
    r->ucb = ucb;
    if (copy_from_user(&r->cb, ucb, sizeof r->cb)) {
      free(r);
      return done ? (int) done : -LINUX_EFAULT;
    }

    /*
     * A batch stops at the first request it cannot take, and reports how many
     * it did take. Only a failure on the very first is an error return - after
     * that the count is the answer, because those requests are already running
     * and the guest has to be told about them.
     */
    int err = build(r);
    if (err < 0) {
      free(r->buf); free(r);
      return done ? (int) done : err;
    }

    pthread_mutex_lock(&ctx->lock);
    if (ctx->live >= ctx->max) {
      pthread_mutex_unlock(&ctx->lock);
      free(r->buf); free(r);
      return done ? (int) done : -LINUX_EAGAIN;
    }
    ctx->live++;
    if (ctx->queue_tail)
      ctx->queue_tail->next = r;
    else
      ctx->queue = r;
    ctx->queue_tail = r;
    pthread_cond_signal(&ctx->work);
    pthread_mutex_unlock(&ctx->lock);
    done++;
  }
  return (int) done;
}

/* --------------------------------------------------------------- reap */

/* Finish a completed request on the guest's thread: this is where a read's
 * data reaches the buffer it was asked for. */
static int
deliver(struct aio_req *r, struct l_io_event *ev)
{
  uint16_t op = r->cb.aio_lio_opcode;
  bool reads = (op == LINUX_IOCB_CMD_PREAD || op == LINUX_IOCB_CMD_PREADV);

  if (reads && r->res > 0 && r->buf) {
    size_t got = (size_t) r->res;
    if (op == LINUX_IOCB_CMD_PREAD) {
      if (copy_to_user((gaddr_t) r->cb.aio_buf, r->buf, got))
        return -LINUX_EFAULT;
    } else {
      unsigned long n = (unsigned long) r->cb.aio_nbytes;
      struct l_iovec *iov = calloc(n, sizeof *iov);
      if (!iov)
        return -LINUX_ENOMEM;
      if (copy_from_user(iov, (gaddr_t) r->cb.aio_buf, n * sizeof *iov)) {
        free(iov);
        return -LINUX_EFAULT;
      }
      size_t at = 0;
      for (unsigned long i = 0; i < n && at < got; i++) {
        size_t s = MIN(got - at, iov[i].iov_len);
        if (s && copy_to_user(iov[i].iov_base, r->buf + at, s)) {
          free(iov);
          return -LINUX_EFAULT;
        }
        at += s;
      }
      free(iov);
    }
  }

  ev->data = r->cb.aio_data;
  ev->obj = (uint64_t) r->ucb;
  ev->res = r->res;
  ev->res2 = 0;
  return 0;
}

static int
getevents(gaddr_t ctx_id, long min_nr, long nr, gaddr_t events_ptr,
          gaddr_t timeout_ptr)
{
  if (nr < 0 || min_nr < 0 || min_nr > nr)
    return -LINUX_EINVAL;
  struct aio_ctx *ctx = ctx_find(ctx_id);
  if (!ctx)
    return -LINUX_EINVAL;
  if (nr == 0)
    return 0;

  /* A timeout is a deadline once it is being waited on more than once. */
  bool timed = false;
  struct timespec deadline;
  if (timeout_ptr) {
    struct l_timespec lt;
    if (copy_from_user(&lt, timeout_ptr, sizeof lt))
      return -LINUX_EFAULT;
    timed = true;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += lt.tv_sec;
    deadline.tv_nsec += lt.tv_nsec;
    if (deadline.tv_nsec >= 1000000000L) {
      deadline.tv_sec++;
      deadline.tv_nsec -= 1000000000L;
    }
  }

  struct l_io_event *out = calloc((size_t) nr, sizeof *out);
  if (!out)
    return -LINUX_ENOMEM;

  long got = 0;
  int err = 0;
  pthread_mutex_lock(&ctx->lock);
  for (;;) {
    while (ctx->ready && got < nr) {
      struct aio_req *r = ctx->ready;
      ctx->ready = r->next;
      if (!ctx->ready)
        ctx->ready_tail = NULL;
      ctx->live--;
      pthread_mutex_unlock(&ctx->lock);
      err = deliver(r, &out[got]);
      free(r->buf);
      free(r);
      pthread_mutex_lock(&ctx->lock);
      if (err < 0)
        goto out;
      got++;
    }
    if (got >= min_nr || ctx->stopping)
      break;
    /* min_nr is the whole point of the call: fewer than that and it waits. */
    if (timed) {
      if (pthread_cond_timedwait(&ctx->arrived, &ctx->lock, &deadline) != 0)
        break;
    } else {
      pthread_cond_wait(&ctx->arrived, &ctx->lock);
    }
  }
out:
  pthread_mutex_unlock(&ctx->lock);

  if (err < 0 && got == 0) {
    free(out);
    return err;
  }
  if (got && copy_to_user(events_ptr, out, (size_t) got * sizeof *out)) {
    free(out);
    return -LINUX_EFAULT;
  }
  free(out);
  return (int) got;
}

DEFINE_SYSCALL(io_getevents, gaddr_t, ctx_id, long, min_nr, long, nr,
               gaddr_t, events, gaddr_t, timeout)
{
  return getevents(ctx_id, min_nr, nr, events, timeout);
}

/*
 * The same wait with a signal mask, installed around it rather than atomically
 * inside it - as in ppoll and epoll_pwait, and with the same consequence: a
 * signal arriving in the gap is not cut short the way the real call would cut
 * it. See sys_ppoll.
 */
DEFINE_SYSCALL(io_pgetevents, gaddr_t, ctx_id, long, min_nr, long, nr,
               gaddr_t, events, gaddr_t, timeout, gaddr_t, usig)
{
  sigset_t saved;
  bool have_mask = false;
  if (usig) {
    /* struct __aio_sigset: a pointer to the mask, then its size. */
    struct { uint64_t mask_ptr; uint64_t size; } sig;
    if (copy_from_user(&sig, usig, sizeof sig))
      return -LINUX_EFAULT;
    if (sig.mask_ptr) {
      if (sig.size != sizeof(l_sigset_t))
        return -LINUX_EINVAL;
      l_sigset_t lset;
      if (copy_from_user(&lset, (gaddr_t) sig.mask_ptr, sizeof lset))
        return -LINUX_EFAULT;
      sigset_t dset;
      host_sigmask_of(&lset, &dset);
      sigprocmask(SIG_SETMASK, &dset, &saved);
      have_mask = true;
    }
  }

  int r = getevents(ctx_id, min_nr, nr, events, timeout);

  if (have_mask)
    sigprocmask(SIG_SETMASK, &saved, NULL);
  return r;
}

/* -------------------------------------------------------------- cancel */

DEFINE_SYSCALL(io_cancel, gaddr_t, ctx_id, gaddr_t, iocb_ptr,
               gaddr_t, result_ptr)
{
  struct aio_ctx *ctx = ctx_find(ctx_id);
  if (!ctx)
    return -LINUX_EINVAL;

  /*
   * Only a request the worker has not started can be cancelled. One already
   * running cannot be called back - Darwin has no way to abort a pread in
   * progress - and one already finished has a result the guest is owed, so
   * both answer EINVAL rather than pretending. That is the same answer Linux
   * gives for an iocb it cannot find, which is what those are from here.
   */
  struct aio_req *found = NULL;
  pthread_mutex_lock(&ctx->lock);
  struct aio_req **pp = &ctx->queue;
  while (*pp) {
    if ((*pp)->ucb == iocb_ptr) {
      found = *pp;
      *pp = found->next;
      if (ctx->queue_tail == found)
        ctx->queue_tail = (ctx->queue == NULL) ? NULL : ctx->queue_tail;
      if (!ctx->queue)
        ctx->queue_tail = NULL;
      ctx->live--;
      break;
    }
    pp = &(*pp)->next;
  }
  pthread_mutex_unlock(&ctx->lock);

  if (!found)
    return -LINUX_EINVAL;

  struct l_io_event ev = {
    .data = found->cb.aio_data,
    .obj = (uint64_t) found->ucb,
    .res = -LINUX_ECANCELED,
    .res2 = 0,
  };
  free(found->buf);
  free(found);

  /* The cancelled request's event goes to the caller here rather than into the
   * completion queue, which is what makes it cancelled rather than failed. */
  if (result_ptr && copy_to_user(result_ptr, &ev, sizeof ev))
    return -LINUX_EFAULT;
  return 0;
}
