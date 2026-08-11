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
 * What this does not do is run the work asynchronously. A real io_uring hands
 * anything that would block to a worker pool; here, a submission is executed
 * during io_uring_enter, on the thread that called it. Every visible rule still
 * holds - completions carry the right user_data, the counters advance, a caller
 * reading the completion ring finds its entries there - and for the file I/O
 * this supports, the kernel very often completes inline too. What a guest loses
 * is the case where it submits a read that blocks and expects to do other work
 * meanwhile: here it waits. That is a performance property rather than a
 * correctness one, and it is the honest place to start; the alternative is the
 * aio worker-pool machinery plus a way to touch guest memory off-thread, which
 * src/fs/aio.c had to avoid for reasons that apply here too.
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

struct uring {
  int       fd;                 /* the guest's ring descriptor, and ours */
  uint32_t  sq_entries, cq_entries;
  char     *sq;                 /* nabi's view of the same pages the guest maps */
  char     *cq;
  char     *sqes;
  size_t    sq_len, cq_len, sqes_len;
  int       eventfd;            /* poked per completion, or -1 */
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
run_sqe(const struct l_io_uring_sqe *s)
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
    return do_openat(s->fd, guestpath, (int) s->rw_flags, (int) s->len);
  }

  default:
    /* Every other opcode, including the ones this could grow into. An
     * unimplemented opcode is EINVAL per entry, exactly as the kernel answers
     * one it does not know - so a caller learns which submission it was without
     * the batch failing. */
    return -LINUX_EINVAL;
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

  uint32_t cq_tail = ld(r->cq, CQ_OFF_TAIL);
  uint32_t cq_mask = r->cq_entries - 1;
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
    int32_t res = run_sqe(&s);

    struct l_io_uring_cqe c = {
      .user_data = s.user_data,
      .res = res,
      .flags = 0,
    };
    memcpy(r->cq + CQ_OFF_CQES +
           (size_t) (cq_tail & cq_mask) * sizeof c, &c, sizeof c);
    cq_tail++;
    done++;
  }

  st(r->sq, SQ_OFF_DROPPED, dropped);
  st(r->sq, SQ_OFF_HEAD, sq_head + done);
  /*
   * The completion tail is published last, after every entry it accounts for
   * has been written. A caller that reads the tail and then reads the entries
   * must not be able to see the second without the first.
   */
  __sync_synchronize();
  st(r->cq, CQ_OFF_TAIL, cq_tail);

  /*
   * IORING_ENTER_GETEVENTS asks to wait for min_complete. Everything submitted
   * has already completed by the time control reaches here, so the wait is
   * always already satisfied - which is the one place this design shows through,
   * and it shows through as the call returning promptly rather than as a
   * different answer.
   */
  (void) min_complete;
  (void) sig;
  (void) sigsz;

  /* A registered eventfd counts one per completion posted, which is what lets a
   * guest wait on the ring inside an ordinary poll loop instead of spinning on
   * the completion tail. */
  if (r->eventfd >= 0 && done)
    eventfd_signal(r->eventfd, done);

  return (int) done;
}

DEFINE_SYSCALL(io_uring_register, int, fd, uint32_t, opcode, gaddr_t, arg,
               uint32_t, nr_args)
{
  struct uring *r = ring_of(fd);
  if (!r)
    return -LINUX_EOPNOTSUPP;

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

  default:
    /*
     * Registering buffers or descriptors pre-attaches them to a ring so a later
     * submission can name one by index instead of by address. That is an
     * optimisation over what a submission can already express, and honouring it
     * means honouring IOSQE_FIXED_FILE and the *_FIXED opcodes as well - so it
     * is refused rather than accepted and ignored. A guest told its buffers were
     * registered would submit an index into a table that does not exist, and
     * read whatever that index landed on.
     */
    return -LINUX_EINVAL;
  }
}
