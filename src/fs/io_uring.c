/*
 * io_uring.
 *
 * The three syscalls are the small part. io_uring's interface is a *memory
 * layout*: the guest asks for a ring, maps three regions of the descriptor it
 * gets back, and from then on submits work by writing 64-byte entries into
 * shared memory and bumping a counter. Nothing arrives as syscall arguments.
 *
 * Which is why the first question was whether this was possible here at all.
 * The regions have to be memory the guest and nabi both see, and nabi cannot
 * hand the guest a pointer into its own heap - guest memory is a separate
 * address space established through stage-2. The way in is that nabi already
 * maps a *shared file* into the guest when a guest asks it to (see do_mmap):
 * the host mapping and the guest mapping are then the same pages. So the ring
 * is a file - created, sized, and immediately unlinked, so it is a name nothing
 * else can reach and it goes when the descriptor does - and the guest's own
 * mmap of the ring descriptor is an ordinary mmap that needs no special case.
 *
 * The file is sparse and enormous on paper. IORING_OFF_CQ_RING is 128MiB and
 * IORING_OFF_SQES is 256MiB, and those are the offsets a caller passes to mmap;
 * they are magic numbers rather than real offsets, but the cheapest way to make
 * them work is to let them be real, so the file is sized past the largest and
 * the regions are placed where the constants say. No blocks are allocated for
 * the gap. The alternative - intercepting mmap to translate the offsets - would
 * put an io_uring special case into the middle of the memory manager.
 *
 * The file operations are executed during io_uring_enter, on the thread that
 * called it. A real io_uring hands anything that would block to a worker pool;
 * here a guest that submits a blocking read and expects to work meanwhile will
 * wait instead. That is a performance property rather than a correctness one -
 * completions carry the right user_data, the counters advance, a caller reading
 * the completion ring finds its entries - and it is what makes it legal to touch
 * guest memory in the handler at all, which is the difficulty src/fs/aio.c had
 * to design around.
 *
 * Poll and timeout cannot work that way, and they are why there is a thread
 * here. A poll that is not ready yet has nothing to report, and a five-second
 * timeout has nothing to report for five seconds; running either to completion
 * inside io_uring_enter would make a submission block, which is the one thing
 * the interface promises it does not do. So they are recorded as pending and a
 * per-ring thread waits on them.
 *
 * That thread is safe for exactly these operations, and the reason is worth
 * stating because it does not generalise. A completion for a poll carries a
 * readiness mask and a completion for a timeout carries an error - neither reads
 * or writes a guest buffer - and the completion ring itself is *nabi's own
 * mapping* of the ring file rather than guest memory reached through the page
 * tables. So posting one touches nothing the guest could unmap underneath it.
 * A read or a write has a buffer, and would not be safe here; that is why those
 * stay on the submitting thread.
 *
 * SQPOLL and IOPOLL are refused rather than ignored. Both are promises about
 * *how* the ring is serviced - a kernel thread polling submissions, and busy
 * polling for completions - and a guest that asks for either and is told yes
 * would then stop calling io_uring_enter, which is the only thing that makes
 * this ring go.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/socket.h"
#include "linux/io_uring.h"

/*
 * The layout inside each region.
 *
 * A caller is required to read these out of io_uring_params rather than assume
 * them, which is what makes a simple arrangement safe: head and tail first, the
 * fixed fields after, and the variable-length part at the end.
 */
#define SQ_OFF_HEAD      0
#define SQ_OFF_TAIL      4
#define SQ_OFF_MASK      8
#define SQ_OFF_ENTRIES  12
#define SQ_OFF_FLAGS    16
#define SQ_OFF_DROPPED  20
#define SQ_OFF_ARRAY    32      /* uint32_t[sq_entries] */

#define CQ_OFF_HEAD      0
#define CQ_OFF_TAIL      4
#define CQ_OFF_MASK      8
#define CQ_OFF_ENTRIES  12
#define CQ_OFF_OVERFLOW 16
#define CQ_OFF_FLAGS    20
#define CQ_OFF_CQES     32      /* struct cqe[cq_entries], 8-aligned */

#define URING_MAX_ENTRIES 4096

/*
 * A submission that cannot answer yet: a poll waiting for its descriptor, or a
 * timeout waiting for its deadline.
 */
struct pending {
  uint8_t          op;
  uint64_t         user_data;
  int              fd;          /* poll */
  short            events;      /* poll */
  struct timespec  deadline;    /* timeout */
  uint64_t         target;      /* timeout: the completion count it waits for */
  bool             counted;     /* timeout: whether it waits on a count at all */
  struct pending  *next;
};

struct uring {
  int       fd;                 /* the guest's ring descriptor, and ours */
  uint32_t  sq_entries, cq_entries;
  char     *sq;                 /* nabi's view of the same pages the guest maps */
  char     *cq;
  char     *sqes;
  size_t    sq_len, cq_len, sqes_len;
  int       eventfd;            /* poked per completion, or -1 */

  pthread_mutex_t  lock;        /* between the submitting thread and the poller */
  pthread_cond_t   posted;      /* a completion has been added */
  struct pending  *pending;
  uint64_t         completions; /* posted since setup; what a counted timeout waits on */
  /*
   * Registered files and buffers. On Linux these are pre-attached so that a
   * submission can name one by index instead of by descriptor or address, and
   * the kernel can hold a reference and pin the pages once rather than resolve
   * them per operation. Here there is nothing to pin and no descriptor lookup
   * worth saving, so what is left is the naming - and the naming is the part a
   * guest can observe, so it is the part that has to be right.
   */
  int             *files;
  uint32_t         nfiles;
  struct l_iovec  *bufs;
  uint32_t         nbufs;

  pthread_t        poller;
  bool             polling;     /* the thread exists */
  bool             stopping;
  int              wake[2];     /* the poller's way of being interrupted */

  struct uring *next;
};

static struct uring *rings;

static struct uring *
ring_of(int fd)
{
  for (struct uring *r = rings; r; r = r->next)
    if (r->fd == fd)
      return r;
  return NULL;
}

static uint32_t
ld(const char *base, size_t off)
{
  uint32_t v;
  memcpy(&v, base + off, sizeof v);
  return v;
}

static void
st(char *base, size_t off, uint32_t v)
{
  memcpy(base + off, &v, sizeof v);
}

/* -------------------------------------------------------- completions */

/*
 * Add one completion to the ring. Called from the submitting thread and from
 * the poller, so it is the one place the completion tail is written.
 *
 * The tail is published after the entry it accounts for, because a guest reads
 * the tail first and then the entry: the reverse order would let it read an
 * entry that had not been written yet.
 */
static void
post_cqe(struct uring *r, uint64_t user_data, int32_t res)
{
  uint32_t tail = ld(r->cq, CQ_OFF_TAIL);
  struct l_io_uring_cqe c = { .user_data = user_data, .res = res, .flags = 0 };
  memcpy(r->cq + CQ_OFF_CQES +
         (size_t) (tail & (r->cq_entries - 1)) * sizeof c, &c, sizeof c);
  __sync_synchronize();
  st(r->cq, CQ_OFF_TAIL, tail + 1);

  r->completions++;
  if (r->eventfd >= 0)
    eventfd_signal(r->eventfd, 1);
  pthread_cond_broadcast(&r->posted);
}

/* Detach one pending operation by user_data. */
static struct pending *
pending_take(struct uring *r, uint64_t user_data, uint8_t op)
{
  struct pending **pp = &r->pending;
  while (*pp) {
    if ((*pp)->user_data == user_data && (*pp)->op == op) {
      struct pending *p = *pp;
      *pp = p->next;
      return p;
    }
    pp = &(*pp)->next;
  }
  return NULL;
}

/* The same lookup without detaching, for the operations that change a pending
 * entry rather than end it. */
static struct pending *
pending_find(struct uring *r, uint64_t user_data, uint8_t op)
{
  for (struct pending *p = r->pending; p; p = p->next)
    if (p->user_data == user_data && p->op == op)
      return p;
  return NULL;
}

static void
wake_poller(struct uring *r)
{
  char one = 1;
  (void) !write(r->wake[1], &one, 1);
}

/*
 * What a cancellation is looking for.
 *
 * The three cancelling opcodes differ only in this. POLL_REMOVE and
 * TIMEOUT_REMOVE name one kind of pending work and match a user_data within it;
 * ASYNC_CANCEL matches across kinds, and its flags let it match on a descriptor
 * or on nothing at all. Keeping the difference in a predicate means the part
 * that actually cancels is written once.
 */
#define CANCEL_ANY_OP 0xff      /* not an opcode; "whatever kind" */

struct cancel_match {
  uint8_t  op;                  /* CANCEL_ANY_OP to ignore the kind */
  bool     any;                 /* match everything pending */
  bool     by_fd;               /* key is a descriptor, not a user_data */
  uint64_t key;
};

static bool
matches(const struct pending *p, const struct cancel_match *m)
{
  if (m->op != CANCEL_ANY_OP && p->op != m->op)
    return false;
  if (m->any)
    return true;
  if (m->by_fd)
    /* Only work that waits on a descriptor can be matched by one; a timeout
     * has none, and would otherwise match every fd number of zero. */
    return p->op == LINUX_IORING_OP_POLL_ADD && p->fd == (int) m->key;
  return p->user_data == m->key;
}

/*
 * Cancel pending work, answering each cancelled request on its *own* user_data
 * before the cancelling request answers on its. Without that a caller waiting on
 * the request it just cancelled waits for something that will never arrive.
 *
 * Returns how many were cancelled. Nothing here can be half-done - a pending
 * entry is either still waiting or already completed and off the list - so
 * EALREADY, which the kernel uses for work that has started and cannot be
 * called back, has no case to arise from.
 */
static int
cancel_matching(struct uring *r, const struct cancel_match *m, bool all)
{
  int n = 0;
  for (;;) {
    struct pending **pp = &r->pending, *hit = NULL;
    while (*pp) {
      if (matches(*pp, m)) {
        hit = *pp;
        *pp = hit->next;
        break;
      }
      pp = &(*pp)->next;
    }
    if (!hit)
      break;
    post_cqe(r, hit->user_data, -LINUX_ECANCELED);
    free(hit);
    n++;
    if (!all)
      break;
  }
  if (n)
    wake_poller(r);             /* the set it is waiting on has changed */
  return n;
}

/*
 * A counted timeout completes when enough *other* completions have been posted,
 * whichever comes first with its deadline. Checked after every batch rather than
 * inside post_cqe, so that a timeout cannot be completed by the very completion
 * that is still being posted.
 */
static void
check_counted_timeouts(struct uring *r)
{
  for (;;) {
    struct pending **pp = &r->pending, *hit = NULL;
    while (*pp) {
      if ((*pp)->op == LINUX_IORING_OP_TIMEOUT && (*pp)->counted &&
          r->completions >= (*pp)->target) {
        hit = *pp;
        *pp = hit->next;
        break;
      }
      pp = &(*pp)->next;
    }
    if (!hit)
      return;
    post_cqe(r, hit->user_data, 0);   /* 0: the count was reached, not the clock */
    free(hit);
  }
}

/*
 * Work out when a timeout should fire, and record it against the clock the
 * poller measures with.
 *
 * A relative timeout is simply added to now. An absolute one is named against
 * the realtime clock, which is not the clock the poller reads - so it is
 * converted to a monotonic deadline here rather than compared later across two
 * different origins. A deadline already in the past becomes now, which fires on
 * the next pass instead of never.
 */
static void
set_deadline(struct pending *p, const struct l_timespec *ts, bool absolute)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  if (absolute) {
    struct timespec real;
    clock_gettime(CLOCK_REALTIME, &real);
    int64_t delta = (int64_t) (ts->tv_sec - real.tv_sec) * 1000000000LL +
                    (ts->tv_nsec - real.tv_nsec);
    if (delta < 0)
      delta = 0;
    p->deadline.tv_sec = now.tv_sec + delta / 1000000000LL;
    p->deadline.tv_nsec = now.tv_nsec + delta % 1000000000LL;
  } else {
    p->deadline.tv_sec = now.tv_sec + ts->tv_sec;
    p->deadline.tv_nsec = now.tv_nsec + ts->tv_nsec;
  }
  if (p->deadline.tv_nsec >= 1000000000L) {
    p->deadline.tv_sec++;
    p->deadline.tv_nsec -= 1000000000L;
  }
}

static bool
expired(const struct timespec *deadline, const struct timespec *now)
{
  return now->tv_sec > deadline->tv_sec ||
         (now->tv_sec == deadline->tv_sec && now->tv_nsec >= deadline->tv_nsec);
}

/*
 * The poller. One per ring, started the first time a ring is given something
 * that has to wait, and running until the ring is destroyed.
 */
static void *
poller(void *arg)
{
  struct uring *r = arg;
  struct pollfd *fds = NULL;
  struct pending **owner = NULL;
  size_t cap = 0;

  pthread_mutex_lock(&r->lock);
  while (!r->stopping) {
    /* Everything waiting on a descriptor, plus the pipe that says the set has
     * changed - without which a poll armed during the wait would not be seen
     * until the current one happened to return. */
    size_t n = 1;
    for (struct pending *p = r->pending; p; p = p->next)
      if (p->op == LINUX_IORING_OP_POLL_ADD)
        n++;
    if (n > cap) {
      struct pollfd *nf = realloc(fds, n * sizeof *nf);
      struct pending **no = realloc(owner, n * sizeof *no);
      if (!nf || !no) {
        free(nf ? nf : fds); free(no ? no : owner);
        fds = NULL; owner = NULL; cap = 0;
        break;
      }
      fds = nf; owner = no; cap = n;
    }
    fds[0].fd = r->wake[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    owner[0] = NULL;
    size_t i = 1;
    for (struct pending *p = r->pending; p; p = p->next) {
      if (p->op != LINUX_IORING_OP_POLL_ADD)
        continue;
      fds[i].fd = p->fd;
      fds[i].events = p->events;
      fds[i].revents = 0;
      owner[i] = p;
      i++;
    }

    /* The nearest deadline decides how long to wait; nothing pending at all
     * means wait for the pipe alone. */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int timeout = -1;
    for (struct pending *p = r->pending; p; p = p->next) {
      if (p->op != LINUX_IORING_OP_TIMEOUT)
        continue;
      long ms = (long) (p->deadline.tv_sec - now.tv_sec) * 1000 +
                (p->deadline.tv_nsec - now.tv_nsec) / 1000000;
      if (ms < 0)
        ms = 0;
      if (timeout < 0 || ms < timeout)
        timeout = (int) ms;
    }

    pthread_mutex_unlock(&r->lock);
    int ready = poll(fds, (nfds_t) i, timeout);
    pthread_mutex_lock(&r->lock);
    if (r->stopping)
      break;

    if (ready > 0 && (fds[0].revents & POLLIN)) {
      char drain[64];
      (void) !read(r->wake[0], drain, sizeof drain);
    }

    /* Ready descriptors: one-shot, so the registration goes with the answer. */
    for (size_t j = 1; j < i && ready > 0; j++) {
      if (fds[j].revents == 0)
        continue;
      struct pending *p = pending_take(r, owner[j]->user_data,
                                       LINUX_IORING_OP_POLL_ADD);
      if (!p)
        continue;               /* removed while the poll was in flight */
      post_cqe(r, p->user_data, (int32_t) (uint32_t) fds[j].revents);
      free(p);
    }

    /* Expired deadlines. */
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (;;) {
      struct pending **pp = &r->pending, *hit = NULL;
      while (*pp) {
        if ((*pp)->op == LINUX_IORING_OP_TIMEOUT &&
            expired(&(*pp)->deadline, &now)) {
          hit = *pp;
          *pp = hit->next;
          break;
        }
        pp = &(*pp)->next;
      }
      if (!hit)
        break;
      /* ETIME, which is how a caller tells "the clock ran out" from "the thing
       * I was counting happened". */
      post_cqe(r, hit->user_data, -LINUX_ETIME);
      free(hit);
    }
  }
  pthread_mutex_unlock(&r->lock);
  free(fds);
  free(owner);
  return NULL;
}

/* Started on demand: a ring that only ever does file I/O never gets a thread. */
static int
poller_start(struct uring *r)
{
  if (r->polling)
    return 0;
  if (pipe(r->wake) < 0)
    return -darwin_to_linux_errno(errno);
  fcntl(r->wake[0], F_SETFL, O_NONBLOCK);
  if (pthread_create(&r->poller, NULL, poller, r) != 0) {
    close(r->wake[0]); close(r->wake[1]);
    r->wake[0] = r->wake[1] = -1;
    return -LINUX_EAGAIN;
  }
  r->polling = true;
  return 0;
}

/* ------------------------------------------------------------------ setup */

DEFINE_SYSCALL(io_uring_setup, uint32_t, entries, gaddr_t, params_ptr)
{
  if (entries == 0 || entries > URING_MAX_ENTRIES)
    return -LINUX_EINVAL;

  struct l_io_uring_params p;
  if (copy_from_user(&p, params_ptr, sizeof p))
    return -LINUX_EFAULT;
  for (int i = 0; i < 3; i++)
    if (p.resv[i] != 0)
      return -LINUX_EINVAL;

  /* Refused rather than ignored: see the note at the top. A guest granted
   * SQPOLL stops calling io_uring_enter, and nothing would ever run. */
  if (p.flags & (LINUX_IORING_SETUP_SQPOLL | LINUX_IORING_SETUP_IOPOLL |
                 LINUX_IORING_SETUP_SQ_AFF | LINUX_IORING_SETUP_ATTACH_WQ))
    return -LINUX_EINVAL;

  /* Round up to a power of two, as the kernel does - the masks depend on it. */
  uint32_t sq_entries = 1;
  while (sq_entries < entries)
    sq_entries <<= 1;
  uint32_t cq_entries = sq_entries * 2;
  if (p.flags & LINUX_IORING_SETUP_CQSIZE) {
    if (p.cq_entries < sq_entries || p.cq_entries > URING_MAX_ENTRIES * 2)
      return -LINUX_EINVAL;
    cq_entries = 1;
    while (cq_entries < p.cq_entries)
      cq_entries <<= 1;
  }

  size_t sq_len   = SQ_OFF_ARRAY + (size_t) sq_entries * sizeof(uint32_t);
  size_t cq_len   = CQ_OFF_CQES + (size_t) cq_entries * sizeof(struct l_io_uring_cqe);
  size_t sqes_len = (size_t) sq_entries * sizeof(struct l_io_uring_sqe);

  /*
   * The backing file. Created under TMPDIR and unlinked at once: from here on
   * the only way to it is this descriptor, which is exactly the lifetime the
   * ring should have.
   */
  const char *tmp = getenv("TMPDIR");
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/nabi-uring-%s-%d-XXXXXX",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(), getpid());
  int fd = mkstemp(path);
  if (fd < 0)
    return -darwin_to_linux_errno(errno);
  unlink(path);

  /* Sized past the highest of the three magic offsets, so the offsets a caller
   * passes to mmap are real ones. Sparse: the gap costs nothing. */
  off_t need = (off_t) LINUX_IORING_OFF_SQES + (off_t) sqes_len;
  if (ftruncate(fd, need) < 0) {
    int e = errno;
    close(fd);
    return -darwin_to_linux_errno(e);
  }

  struct uring *r = calloc(1, sizeof *r);
  if (!r) {
    close(fd);
    return -LINUX_ENOMEM;
  }
  r->sq_len = sq_len; r->cq_len = cq_len; r->sqes_len = sqes_len;
  r->eventfd = -1;
  r->wake[0] = r->wake[1] = -1;
  pthread_mutex_init(&r->lock, NULL);
  pthread_cond_init(&r->posted, NULL);
  r->sq_entries = sq_entries; r->cq_entries = cq_entries;

  r->sq = mmap(NULL, sq_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
               (off_t) LINUX_IORING_OFF_SQ_RING);
  r->cq = mmap(NULL, cq_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
               (off_t) LINUX_IORING_OFF_CQ_RING);
  r->sqes = mmap(NULL, sqes_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                 (off_t) LINUX_IORING_OFF_SQES);
  if (r->sq == MAP_FAILED || r->cq == MAP_FAILED || r->sqes == MAP_FAILED) {
    if (r->sq != MAP_FAILED) munmap(r->sq, sq_len);
    if (r->cq != MAP_FAILED) munmap(r->cq, cq_len);
    if (r->sqes != MAP_FAILED) munmap(r->sqes, sqes_len);
    free(r);
    close(fd);
    return -LINUX_ENOMEM;
  }

  st(r->sq, SQ_OFF_HEAD, 0);
  st(r->sq, SQ_OFF_TAIL, 0);
  st(r->sq, SQ_OFF_MASK, sq_entries - 1);
  st(r->sq, SQ_OFF_ENTRIES, sq_entries);
  st(r->sq, SQ_OFF_FLAGS, 0);
  st(r->sq, SQ_OFF_DROPPED, 0);
  st(r->cq, CQ_OFF_HEAD, 0);
  st(r->cq, CQ_OFF_TAIL, 0);
  st(r->cq, CQ_OFF_MASK, cq_entries - 1);
  st(r->cq, CQ_OFF_ENTRIES, cq_entries);
  st(r->cq, CQ_OFF_OVERFLOW, 0);
  st(r->cq, CQ_OFF_FLAGS, 0);

  /* register_fd reports success or an error; the descriptor the guest gets is
   * the host one, as everywhere else that hands a real fd over. */
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, false);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    munmap(r->sq, sq_len); munmap(r->cq, cq_len); munmap(r->sqes, sqes_len);
    free(r);
    close(fd);
    return err;
  }
  r->fd = fd;
  r->next = rings;
  rings = r;

  p.sq_entries = sq_entries;
  p.cq_entries = cq_entries;
  /*
   * Both of these are true here rather than aspirational. NODROP: a completion
   * is never dropped, because the completion ring is at least as large as the
   * submission ring and no more than a ringful is ever in flight. SUBMIT_STABLE:
   * an entry may be reused as soon as submit returns, because it has been read
   * in full by then - which follows from executing it there.
   */
  p.features = LINUX_IORING_FEAT_NODROP | LINUX_IORING_FEAT_SUBMIT_STABLE;
  p.sq_off = (struct l_io_sqring_offsets){
    .head = SQ_OFF_HEAD, .tail = SQ_OFF_TAIL, .ring_mask = SQ_OFF_MASK,
    .ring_entries = SQ_OFF_ENTRIES, .flags = SQ_OFF_FLAGS,
    .dropped = SQ_OFF_DROPPED, .array = SQ_OFF_ARRAY,
  };
  p.cq_off = (struct l_io_cqring_offsets){
    .head = CQ_OFF_HEAD, .tail = CQ_OFF_TAIL, .ring_mask = CQ_OFF_MASK,
    .ring_entries = CQ_OFF_ENTRIES, .overflow = CQ_OFF_OVERFLOW,
    .cqes = CQ_OFF_CQES, .flags = CQ_OFF_FLAGS,
  };
  if (copy_to_user(params_ptr, &p, sizeof p))
    return -LINUX_EFAULT;
  return fd;
}

/*
 * A ring's descriptor has been closed, so its mappings go with it. Called from
 * the close path, because a ring outliving its descriptor would keep a mapping
 * of a file nothing can reach.
 */
void
uring_close(int fd)
{
  struct uring **pp = &rings;
  while (*pp) {
    if ((*pp)->fd == fd) {
      struct uring *r = *pp;
      *pp = r->next;

      /* The poller is stopped and joined before anything it looks at is freed;
       * abandoning it would leave a thread polling a descriptor that is about
       * to be closed and writing into a mapping about to go. */
      if (r->polling) {
        pthread_mutex_lock(&r->lock);
        r->stopping = true;
        pthread_mutex_unlock(&r->lock);
        wake_poller(r);
        pthread_join(r->poller, NULL);
        close(r->wake[0]);
        close(r->wake[1]);
      }
      for (struct pending *p = r->pending; p; ) {
        struct pending *n = p->next;
        free(p);
        p = n;
      }
      free(r->files);
      free(r->bufs);
      pthread_cond_destroy(&r->posted);
      pthread_mutex_destroy(&r->lock);

      munmap(r->sq, r->sq_len);
      munmap(r->cq, r->cq_len);
      munmap(r->sqes, r->sqes_len);
      free(r);
      return;
    }
    pp = &(*pp)->next;
  }
}

/* ------------------------------------------------------------- one entry */

/*
 * Executed on the thread that called io_uring_enter, which is what makes it
 * legal to touch guest memory here at all - and is also why a blocking
 * operation blocks the caller. See the note at the top.
 */
static int32_t
run_sqe(struct uring *r, const struct l_io_uring_sqe *s)
{
  ssize_t n;

  switch (s->opcode) {
  case LINUX_IORING_OP_NOP:
    return 0;

  case LINUX_IORING_OP_READ:
  case LINUX_IORING_OP_WRITE: {
    if (s->len == 0)
      return 0;
    char *buf = malloc(s->len);
    if (!buf)
      return -LINUX_ENOMEM;
    bool writing = (s->opcode == LINUX_IORING_OP_WRITE);
    if (writing && copy_from_user(buf, (gaddr_t) s->addr, s->len)) {
      free(buf);
      return -LINUX_EFAULT;
    }
    /* An offset of -1 means "use the file's own position", which is how the
     * non-vectored forms stand in for read(2) and write(2). */
    bool at_off = (s->off != (uint64_t) -1);
    if (writing)
      n = at_off ? pwrite(s->fd, buf, s->len, (off_t) s->off)
                 : write(s->fd, buf, s->len);
    else
      n = at_off ? pread(s->fd, buf, s->len, (off_t) s->off)
                 : read(s->fd, buf, s->len);
    int e = errno;
    if (!writing && n > 0 && copy_to_user((gaddr_t) s->addr, buf, (size_t) n)) {
      free(buf);
      return -LINUX_EFAULT;
    }
    free(buf);
    return n < 0 ? -darwin_to_linux_errno(e) : (int32_t) n;
  }

  case LINUX_IORING_OP_READ_FIXED:
  case LINUX_IORING_OP_WRITE_FIXED: {
    /*
     * The same transfer as READ and WRITE, except the memory was named ahead of
     * time: buf_index picks a registered buffer and addr points somewhere inside
     * it. The range is checked against that buffer, which is the one guarantee
     * registration actually carries here - the kernel checks it because it has
     * pinned those pages and will touch nothing else, and a caller that relies
     * on the check should get it whether or not there is pinning behind it.
     */
    if (!r->bufs || s->buf_index >= r->nbufs)
      return -LINUX_EFAULT;
    const struct l_iovec *b = &r->bufs[s->buf_index];
    uint64_t base = (uint64_t) b->iov_base;
    if (s->addr < base || s->addr - base > b->iov_len ||
        s->len > b->iov_len - (s->addr - base))
      return -LINUX_EFAULT;
    if (s->len == 0)
      return 0;

    char *buf = malloc(s->len);
    if (!buf)
      return -LINUX_ENOMEM;
    bool writing = (s->opcode == LINUX_IORING_OP_WRITE_FIXED);
    if (writing && copy_from_user(buf, (gaddr_t) s->addr, s->len)) {
      free(buf);
      return -LINUX_EFAULT;
    }
    bool at_off = (s->off != (uint64_t) -1);
    if (writing)
      n = at_off ? pwrite(s->fd, buf, s->len, (off_t) s->off)
                 : write(s->fd, buf, s->len);
    else
      n = at_off ? pread(s->fd, buf, s->len, (off_t) s->off)
                 : read(s->fd, buf, s->len);
    int e = errno;
    if (!writing && n > 0 && copy_to_user((gaddr_t) s->addr, buf, (size_t) n)) {
      free(buf);
      return -LINUX_EFAULT;
    }
    free(buf);
    return n < 0 ? -darwin_to_linux_errno(e) : (int32_t) n;
  }

  case LINUX_IORING_OP_READV:
  case LINUX_IORING_OP_WRITEV: {
    uint32_t nr = s->len;
    if (nr == 0)
      return 0;
    if (nr > 1024)
      return -LINUX_EINVAL;
    struct l_iovec *iov = calloc(nr, sizeof *iov);
    if (!iov)
      return -LINUX_ENOMEM;
    if (copy_from_user(iov, (gaddr_t) s->addr, nr * sizeof *iov)) {
      free(iov);
      return -LINUX_EFAULT;
    }
    size_t total = 0;
    for (uint32_t i = 0; i < nr; i++)
      total += iov[i].iov_len;
    char *buf = total ? malloc(total) : NULL;
    if (total && !buf) {
      free(iov);
      return -LINUX_ENOMEM;
    }
    bool writing = (s->opcode == LINUX_IORING_OP_WRITEV);
    if (writing) {
      size_t at = 0;
      for (uint32_t i = 0; i < nr; i++) {
        if (iov[i].iov_len &&
            copy_from_user(buf + at, iov[i].iov_base, iov[i].iov_len)) {
          free(buf); free(iov);
          return -LINUX_EFAULT;
        }
        at += iov[i].iov_len;
      }
    }
    bool at_off = (s->off != (uint64_t) -1);
    if (writing)
      n = at_off ? pwrite(s->fd, buf, total, (off_t) s->off)
                 : write(s->fd, buf, total);
    else
      n = at_off ? pread(s->fd, buf, total, (off_t) s->off)
                 : read(s->fd, buf, total);
    int e = errno;
    if (!writing && n > 0) {
      size_t left = (size_t) n, at = 0;
      for (uint32_t i = 0; i < nr && left; i++) {
        size_t part = MIN(left, iov[i].iov_len);
        if (part && copy_to_user(iov[i].iov_base, buf + at, part)) {
          free(buf); free(iov);
          return -LINUX_EFAULT;
        }
        at += part;
        left -= part;
      }
    }
    free(buf);
    free(iov);
    return n < 0 ? -darwin_to_linux_errno(e) : (int32_t) n;
  }

  case LINUX_IORING_OP_FSYNC:
    /* IORING_FSYNC_DATASYNC asks for fdatasync, which Darwin does not have.
     * fsync is stronger than requested, which is the safe way to be wrong. */
    return fsync(s->fd) < 0 ? -darwin_to_linux_errno(errno) : 0;

  case LINUX_IORING_OP_CLOSE: {
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    int ret = do_close(&proc.fileinfo.fdtable, s->fd);
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return ret;
  }

  case LINUX_IORING_OP_OPENAT: {
    char guestpath[LINUX_PATH_MAX];
    if (strncpy_from_user(guestpath, (gaddr_t) s->addr, sizeof guestpath) < 0)
      return -LINUX_EFAULT;
    /*
     * user_openat rather than do_openat: the latter opens a file and hands back
     * a host descriptor, and everything that makes it the *guest's* - the entry
     * in the guest's descriptor table, the /proc redirect, the fanotify open
     * permission - happens above it. An opcode that skipped all that returned a
     * number that looked like a descriptor and was EBADF on first use.
     */
    return user_openat(s->fd, guestpath, (int) s->rw_flags, (int) s->len);
  }

  case LINUX_IORING_OP_SEND:
    /*
     * send(2) on a connected socket, and sendto(2) when the entry carries a
     * destination - which lives in addr2, with its length in the low half of
     * the slot splice_fd_in occupies. A zero there is the connected case, and
     * sendto with a null address is send.
     */
    return (int32_t) sys_sendto(s->fd, (gaddr_t) s->addr, (int) s->len,
                                (int) s->rw_flags, (gaddr_t) s->off,
                                (unsigned int) (uint16_t) s->splice_fd_in);

  case LINUX_IORING_OP_RECV:
    /* The plain form, which does not report where the data came from - that is
     * RECVMSG's job, and it is a different opcode. */
    return (int32_t) sys_recvfrom(s->fd, (gaddr_t) s->addr, (int) s->len,
                                  (int) s->rw_flags, 0, 0);

  case LINUX_IORING_OP_OPENAT2:
    /* how is at addr2 and its size is in len, which is the one place len is
     * neither a length of data nor a mode. */
    return (int32_t) sys_openat2(s->fd, (gstr_t) s->addr, (gaddr_t) s->off,
                                 s->len);

  case LINUX_IORING_OP_STATX:
    /*
     * The same operation as the syscall of that name, answered by the same
     * function - a second implementation here would be one more thing to keep
     * in step with the first. The arguments are spread across the entry
     * differently: the mask is in len and the buffer is in addr2, which shares
     * its slot with off.
     */
    return (int32_t) sys_statx(s->fd, (gstr_t) s->addr, (int) s->rw_flags,
                               s->len, (gaddr_t) s->off);

  case LINUX_IORING_OP_UNLINKAT:
    /* rw_flags is unlink_flags here, and carries AT_REMOVEDIR - which is the
     * difference between removing a file and removing a directory, so it is
     * passed through rather than dropped. */
    return (int32_t) sys_unlinkat(s->fd, (gstr_t) s->addr, (int) s->rw_flags);

  case LINUX_IORING_OP_MKDIRAT:
    /* len is the mode, not a length. */
    return (int32_t) sys_mkdirat(s->fd, (gstr_t) s->addr, (int) s->len);

  default:
    /* Every other opcode, including the ones this could grow into. An
     * unimplemented opcode is EINVAL per entry, exactly as the kernel answers
     * one it does not know - so a caller learns which submission it was without
     * the batch failing. */
    return -LINUX_EINVAL;
  }
}

/*
 * IOSQE_FIXED_FILE: the fd field is an index into the ring's registered table
 * rather than a descriptor.
 *
 * Done once here rather than in each operation, so that every opcode taking a
 * descriptor gets it and there is a single place for it to be wrong. An index
 * with nothing behind it is EBADF - the same answer a bad descriptor would get,
 * which is what the caller is really holding.
 */
static int
resolve_fixed_file(struct uring *r, struct l_io_uring_sqe *s)
{
  if (!(s->flags & LINUX_IOSQE_FIXED_FILE))
    return 0;
  uint32_t i = (uint32_t) s->fd;
  if (!r->files || i >= r->nfiles || r->files[i] < 0)
    return -LINUX_EBADF;
  s->fd = r->files[i];
  return 0;
}

/*
 * The three operations that cannot answer during the submitting call.
 *
 * Returns true if the entry was dealt with here - whether that meant putting it
 * on the pending list to be answered later or posting a completion outright -
 * and false if it is an ordinary operation for run_sqe. Posting is done here
 * rather than reported back through an argument because these three do not
 * agree on how many completions they produce: a poll makes none yet, a removal
 * makes two, and a failure to arm makes one.
 */
static bool
arm_async(struct uring *r, const struct l_io_uring_sqe *s)
{
  switch (s->opcode) {
  case LINUX_IORING_OP_POLL_ADD: {
    struct pending *p = calloc(1, sizeof *p);
    if (!p) { post_cqe(r, s->user_data, -LINUX_ENOMEM); return true; }
    p->op = LINUX_IORING_OP_POLL_ADD;
    p->user_data = s->user_data;
    p->fd = s->fd;
    /*
     * The events live in the same word as rw_flags; a caller may have written
     * the 16-bit poll_events or the 32-bit poll32_events, and on a
     * little-endian machine the low half is the mask either way.
     */
    p->events = (short) (s->rw_flags & 0xffff);
    if (poller_start(r) < 0) {
      free(p);
      post_cqe(r, s->user_data, -LINUX_EAGAIN);
      return true;
    }
    p->next = r->pending;
    r->pending = p;
    wake_poller(r);
    return true;                /* nothing to report until it is ready */
  }

  case LINUX_IORING_OP_POLL_REMOVE: {
    /* addr names the poll to cancel, by the user_data it was submitted with. */
    struct cancel_match m = { .op = LINUX_IORING_OP_POLL_ADD, .key = s->addr };
    int n = cancel_matching(r, &m, false);
    post_cqe(r, s->user_data, n ? 0 : -LINUX_ENOENT);
    return true;
  }

  case LINUX_IORING_OP_TIMEOUT_REMOVE: {
    /*
     * One opcode, two operations, told apart by a flag. Without UPDATE this
     * cancels the timeout named by addr; with it, the timeout stays and its
     * deadline is replaced by the one at addr2.
     *
     * The flag has to be looked at rather than ignored. Ignoring it would turn
     * a request to *extend* a timeout into a cancellation - the caller is told
     * its update succeeded and the timeout it was relying on never fires, which
     * is a wrong answer dressed as a right one.
     */
    if (s->rw_flags & LINUX_IORING_TIMEOUT_UPDATE) {
      struct pending *p = pending_find(r, s->addr, LINUX_IORING_OP_TIMEOUT);
      if (!p) {
        post_cqe(r, s->user_data, -LINUX_ENOENT);
        return true;
      }
      /* The replacement deadline is at addr2, which shares its slot with off -
       * so this is the one timeout operation where off is not a count. */
      struct l_timespec ts;
      if (copy_from_user(&ts, (gaddr_t) s->off, sizeof ts)) {
        post_cqe(r, s->user_data, -LINUX_EFAULT);
        return true;
      }
      set_deadline(p, &ts, (s->rw_flags & LINUX_IORING_TIMEOUT_ABS) != 0);
      /* The poller is sleeping on the old deadline, so it has to recompute -
       * otherwise a shortened timeout still fires at its original time. */
      wake_poller(r);
      post_cqe(r, s->user_data, 0);
      return true;
    }

    struct cancel_match m = { .op = LINUX_IORING_OP_TIMEOUT, .key = s->addr };
    int n = cancel_matching(r, &m, false);
    post_cqe(r, s->user_data, n ? 0 : -LINUX_ENOENT);
    return true;
  }

  case LINUX_IORING_OP_ASYNC_CANCEL: {
    /*
     * The general form of the two removes above: it does not care what kind of
     * work it is cancelling, and its flags decide what "matching" means.
     *
     * Ignoring those flags would cancel the wrong thing. CANCEL_FD says addr is
     * a descriptor rather than a user_data, so matching on user_data would
     * compare a descriptor against a cookie; CANCEL_ALL says cancel every match
     * rather than the first, so a caller clearing out an fd would be left with
     * all but one still armed and told it had succeeded.
     */
    uint32_t cf = s->rw_flags;
    if (cf & LINUX_IORING_ASYNC_CANCEL_FD_FIXED) {
      /* Names a registered descriptor, and registration is refused here - so
       * the index would mean nothing. Refused rather than guessed at. */
      post_cqe(r, s->user_data, -LINUX_EINVAL);
      return true;
    }
    if (cf & ~(uint32_t) (LINUX_IORING_ASYNC_CANCEL_ALL |
                          LINUX_IORING_ASYNC_CANCEL_FD |
                          LINUX_IORING_ASYNC_CANCEL_ANY)) {
      post_cqe(r, s->user_data, -LINUX_EINVAL);
      return true;
    }

    struct cancel_match m = {
      .op = CANCEL_ANY_OP,
      .any = (cf & LINUX_IORING_ASYNC_CANCEL_ANY) != 0,
      .by_fd = (cf & LINUX_IORING_ASYNC_CANCEL_FD) != 0,
      .key = s->addr,
    };
    bool all = (cf & LINUX_IORING_ASYNC_CANCEL_ALL) != 0;
    int n = cancel_matching(r, &m, all);
    /* Cancelling several reports how many; cancelling one reports that it did.
     * Nothing found is ENOENT either way. */
    post_cqe(r, s->user_data, n == 0 ? -LINUX_ENOENT : (all ? n : 0));
    return true;
  }

  case LINUX_IORING_OP_TIMEOUT: {
    if (s->len != 1) { post_cqe(r, s->user_data, -LINUX_EINVAL); return true; }
    struct l_timespec ts;
    if (copy_from_user(&ts, (gaddr_t) s->addr, sizeof ts)) {
      post_cqe(r, s->user_data, -LINUX_EFAULT);
      return true;
    }
    struct pending *p = calloc(1, sizeof *p);
    if (!p) { post_cqe(r, s->user_data, -LINUX_ENOMEM); return true; }
    p->op = LINUX_IORING_OP_TIMEOUT;
    p->user_data = s->user_data;

    set_deadline(p, &ts, (s->rw_flags & LINUX_IORING_TIMEOUT_ABS) != 0);

    /* off is a number of completions to wait for; zero means the clock alone. */
    if (s->off > 0) {
      p->counted = true;
      p->target = r->completions + s->off;
    }
    if (poller_start(r) < 0) {
      free(p);
      post_cqe(r, s->user_data, -LINUX_EAGAIN);
      return true;
    }
    p->next = r->pending;
    r->pending = p;
    wake_poller(r);
    return true;
  }

  default:
    return false;
  }
}

/* ------------------------------------------------------------------ enter */

DEFINE_SYSCALL(io_uring_enter, int, fd, uint32_t, to_submit,
               uint32_t, min_complete, uint32_t, flags, gaddr_t, sig,
               size_t, sigsz)
{
  struct uring *r = ring_of(fd);
  if (!r)
    return -LINUX_EOPNOTSUPP;   /* not a ring; what the kernel answers here */
  if (flags & ~(LINUX_IORING_ENTER_GETEVENTS | LINUX_IORING_ENTER_SQ_WAKEUP))
    return -LINUX_EINVAL;

  pthread_mutex_lock(&r->lock);

  /*
   * The guest wrote entries and advanced the tail; nabi consumes from the head.
   * Both live in the shared pages, so this is the whole handshake.
   */
  uint32_t sq_head = ld(r->sq, SQ_OFF_HEAD);
  uint32_t sq_tail = ld(r->sq, SQ_OFF_TAIL);
  uint32_t mask    = r->sq_entries - 1;
  uint32_t avail   = sq_tail - sq_head;   /* wraps correctly; both are counters */
  if (to_submit > avail)
    to_submit = avail;

  uint32_t dropped = ld(r->sq, SQ_OFF_DROPPED);

  uint32_t done = 0;
  for (uint32_t i = 0; i < to_submit; i++) {
    uint32_t slot;
    memcpy(&slot, r->sq + SQ_OFF_ARRAY +
                  (size_t) ((sq_head + i) & mask) * sizeof(uint32_t),
           sizeof slot);
    if (slot >= r->sq_entries) {
      /* The index the guest put in the array does not name an entry. The
       * kernel counts these in `dropped` and carries on rather than failing
       * the call, since the other submissions are perfectly good. */
      dropped++;
      done++;
      continue;
    }

    struct l_io_uring_sqe s;
    memcpy(&s, r->sqes + (size_t) slot * sizeof s, sizeof s);
    done++;

    int fixed = resolve_fixed_file(r, &s);
    if (fixed < 0) {
      post_cqe(r, s.user_data, fixed);
      continue;
    }

    if (arm_async(r, &s))
      continue;
    post_cqe(r, s.user_data, run_sqe(r, &s));
  }

  st(r->sq, SQ_OFF_DROPPED, dropped);
  st(r->sq, SQ_OFF_HEAD, sq_head + done);
  check_counted_timeouts(r);

  /*
   * IORING_ENTER_GETEVENTS asks to wait for min_complete. Everything submitted
   * has already completed by the time control reaches here, so the wait is
   * always already satisfied - which is the one place this design shows through,
   * and it shows through as the call returning promptly rather than as a
   * different answer.
   */
  /*
   * IORING_ENTER_GETEVENTS asks to wait until min_complete completions are
   * available. Everything run on this thread is already posted by now, so this
   * only ever waits on the poller - which is exactly what a caller doing
   * "submit a poll, then wait for it" needs, and is the path liburing takes
   * when the completion ring is empty.
   */
  int err = 0;
  if ((flags & LINUX_IORING_ENTER_GETEVENTS) && min_complete > 0) {
    sigset_t saved;
    bool have_mask = false;
    if (sig) {
      if (sigsz != sizeof(l_sigset_t)) {
        pthread_mutex_unlock(&r->lock);
        return -LINUX_EINVAL;
      }
      l_sigset_t lset;
      if (copy_from_user(&lset, sig, sizeof lset)) {
        pthread_mutex_unlock(&r->lock);
        return -LINUX_EFAULT;
      }
      sigset_t dset;
      linux_to_darwin_sigset(&lset, &dset);
      sigprocmask(SIG_SETMASK, &dset, &saved);
      have_mask = true;
    }

    while (!r->stopping) {
      uint32_t head = ld(r->cq, CQ_OFF_HEAD);
      uint32_t tail = ld(r->cq, CQ_OFF_TAIL);
      if (tail - head >= min_complete)
        break;
      /* Nothing pending and nothing ready is a wait that cannot end, so it is
       * refused rather than entered - the guest asked for completions that
       * nothing has been asked to produce. */
      if (!r->pending) {
        err = -LINUX_EAGAIN;
        break;
      }
      pthread_cond_wait(&r->posted, &r->lock);
    }

    if (have_mask)
      sigprocmask(SIG_SETMASK, &saved, NULL);
  }

  pthread_mutex_unlock(&r->lock);
  if (err < 0 && done == 0)
    return err;
  return (int) done;
}

static int
uring_register(struct uring *r, uint32_t opcode, gaddr_t arg, uint32_t nr_args)
{
  switch (opcode) {
  case LINUX_IORING_REGISTER_EVENTFD: {
    /* The one registration that is worth having here and costs nothing to
     * provide: an eventfd the ring pokes as completions are posted. */
    if (nr_args != 1)
      return -LINUX_EINVAL;
    int efd;
    if (copy_from_user(&efd, arg, sizeof efd))
      return -LINUX_EFAULT;
    if (r->eventfd >= 0)
      return -LINUX_EBUSY;      /* one at a time, as the kernel has it */
    r->eventfd = efd;
    return 0;
  }
  case LINUX_IORING_UNREGISTER_EVENTFD:
    if (r->eventfd < 0)
      return -LINUX_ENXIO;
    r->eventfd = -1;
    return 0;

  case LINUX_IORING_REGISTER_FILES: {
    if (r->files)
      return -LINUX_EBUSY;      /* replacing is an update, or unregister first */
    if (nr_args == 0 || nr_args > 4096)
      return -LINUX_EINVAL;
    int *t = calloc(nr_args, sizeof *t);
    if (!t)
      return -LINUX_ENOMEM;
    if (copy_from_user(t, arg, (size_t) nr_args * sizeof *t)) {
      free(t);
      return -LINUX_EFAULT;
    }
    r->files = t;
    r->nfiles = nr_args;
    return 0;
  }

  case LINUX_IORING_UNREGISTER_FILES:
    if (!r->files)
      return -LINUX_ENXIO;
    free(r->files);
    r->files = NULL;
    r->nfiles = 0;
    return 0;

  case LINUX_IORING_REGISTER_FILES_UPDATE: {
    if (!r->files)
      return -LINUX_ENXIO;
    struct l_io_uring_rsrc_update up;
    if (copy_from_user(&up, arg, sizeof up))
      return -LINUX_EFAULT;
    /* The replacement has to fit inside the table that is already there;
     * growing it would move slots a caller has already been handed. */
    if (nr_args == 0 || up.offset > r->nfiles ||
        nr_args > r->nfiles - up.offset)
      return -LINUX_EINVAL;
    if (copy_from_user(r->files + up.offset, (gaddr_t) up.data,
                       (size_t) nr_args * sizeof *r->files))
      return -LINUX_EFAULT;
    return (int) nr_args;
  }

  case LINUX_IORING_REGISTER_BUFFERS: {
    if (r->bufs)
      return -LINUX_EBUSY;
    if (nr_args == 0 || nr_args > 1024)
      return -LINUX_EINVAL;
    struct l_iovec *t = calloc(nr_args, sizeof *t);
    if (!t)
      return -LINUX_ENOMEM;
    if (copy_from_user(t, arg, (size_t) nr_args * sizeof *t)) {
      free(t);
      return -LINUX_EFAULT;
    }
    r->bufs = t;
    r->nbufs = nr_args;
    return 0;
  }

  case LINUX_IORING_UNREGISTER_BUFFERS:
    if (!r->bufs)
      return -LINUX_ENXIO;
    free(r->bufs);
    r->bufs = NULL;
    r->nbufs = 0;
    return 0;

  default:
    /*
     * What is left - probing, personalities, restricting a ring - is refused on
     * the same terms as before: a guest told a thing was registered and then
     * submitting against it would be submitting against nothing.
     */
    return -LINUX_EINVAL;
  }
}

DEFINE_SYSCALL(io_uring_register, int, fd, uint32_t, opcode, gaddr_t, arg,
               uint32_t, nr_args)
{
  struct uring *r = ring_of(fd);
  if (!r)
    return -LINUX_EOPNOTSUPP;

  pthread_mutex_lock(&r->lock);
  int ret = uring_register(r, opcode, arg, nr_args);
  pthread_mutex_unlock(&r->lock);
  return ret;
}
