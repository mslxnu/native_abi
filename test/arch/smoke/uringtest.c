/* freestanding: io_uring.
 *
 * The interface is not the three syscalls, it is shared memory. The guest maps
 * three regions of the ring descriptor, writes 64-byte submission entries into
 * one of them, bumps a counter, and reads completions back out of another. So
 * the thing being tested here is really whether NABI and the guest are looking
 * at the same pages at all - everything else follows from that.
 *
 * This drives the ring by hand rather than through liburing, because the point
 * is to check the layout NABI reports: the offsets come out of io_uring_params
 * and are used exactly as a real caller would use them, so a wrong offset shows
 * up here as a wrong answer rather than as a mystery in someone's library.
 *
 * The ordering check at the end is the one worth having. Two entries submitted
 * in one call must produce two completions, each carrying its own user_data -
 * with a single request in flight, an implementation that mixed them up would
 * look perfect.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_unlinkat           35
#define SYS_openat             56
#define SYS_close              57
#define SYS_lseek              62
#define SYS_read               63
#define SYS_write              64
#define SYS_mmap              222
#define SYS_eventfd2           19
#define SYS_pipe2              59
#define SYS_clock_gettime     113
#define SYS_nanosleep         101
#define SYS_exit               93
#define SYS_io_uring_setup    425
#define SYS_io_uring_enter    426
#define SYS_io_uring_register 427

#define AT_FDCWD  -100
#define O_RDWR     2
#define O_CREAT    0100
#define O_TRUNC    01000
#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_POPULATE 0x8000
#define EINVAL    22
#define EOPNOTSUPP 95
#define ENXIO      6
#define ENOENT     2
#define ETIME     62
#define ECANCELED 125
#define POLLIN     1
#define REGISTER_EVENTFD   4
#define UNREGISTER_EVENTFD 5

#define IORING_OFF_SQ_RING 0x0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES    0x10000000ULL
#define IORING_ENTER_GETEVENTS 1
#define IORING_SETUP_SQPOLL    2

#define OP_NOP    0
#define OP_READV  1
#define OP_WRITEV 2
#define OP_FSYNC  3
#define OP_READ  22
#define OP_WRITE 23
#define OP_POLL_ADD     6
#define OP_POLL_REMOVE  7
#define OP_TIMEOUT     11
#define OP_TIMEOUT_REMOVE 12
#define OP_ASYNC_CANCEL   14
#define OP_STATX          21
#define OP_UNLINKAT       36
#define OP_MKDIRAT        37
#define OP_OPENAT         18
#define OP_SEND           26
#define OP_RECV           27
#define OP_OPENAT2        28
#define SYS_socketpair    199
#define AF_UNIX            1
#define SOCK_STREAM        1
#define E2BIG              7
#define AT_REMOVEDIR   0x200
#define STATX_BASIC_STATS 0x7ff
#define CANCEL_ALL        1
#define CANCEL_FD         2
#define CANCEL_ANY        4
#define CANCEL_FD_FIXED   8
#define TIMEOUT_UPDATE  2

struct sqe {
  unsigned char opcode, flags; unsigned short ioprio; int fd;
  unsigned long long off, addr; unsigned int len, rw_flags;
  unsigned long long user_data;
  unsigned short buf_index, personality; int splice_fd_in;
  unsigned long long addr3, pad2;
};
struct cqe { unsigned long long user_data; int res; unsigned int flags; };
struct sqring_off { unsigned head, tail, ring_mask, ring_entries, flags, dropped, array, resv1; unsigned long long resv2; };
struct cqring_off { unsigned head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1; unsigned long long resv2; };
struct params {
  unsigned sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle,
           features, wq_fd, resv[3];
  struct sqring_off sq_off; struct cqring_off cq_off;
};
struct iov { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("uring FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("uring FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

/* The ring, as the guest sees it once mapped. */
static char *sqbase, *cqbase;
static struct sqe *sqes;
static struct params p;

static unsigned *sq(unsigned off){ return (unsigned *)(sqbase + off); }
static unsigned *cq(unsigned off){ return (unsigned *)(cqbase + off); }

/* Put one entry in the submission ring; return its slot. */
static struct sqe *
push(void)
{
  unsigned tail = *sq(p.sq_off.tail);
  unsigned mask = *sq(p.sq_off.ring_mask);
  unsigned slot = tail & mask;
  ((unsigned *)(sqbase + p.sq_off.array))[slot] = slot;
  clr((char *) &sqes[slot], sizeof sqes[slot]);
  *sq(p.sq_off.tail) = tail + 1;
  return &sqes[slot];
}

/* Take one completion, or fail. */
static struct cqe
pop(const char *what)
{
  unsigned head = *cq(p.cq_off.head);
  unsigned tail = *cq(p.cq_off.tail);
  if (head == tail)
    fail(what, 0, 1);
  unsigned mask = *cq(p.cq_off.ring_mask);
  struct cqe c = ((struct cqe *)(cqbase + p.cq_off.cqes))[head & mask];
  *cq(p.cq_off.head) = head + 1;
  return c;
}

void _start(void)
{
  long r;

  /* SQPOLL is refused rather than quietly ignored: a guest granted it would
   * stop calling io_uring_enter and nothing would ever run. */
  { struct params sp; clr((char *) &sp, sizeof sp);
    sp.flags = IORING_SETUP_SQPOLL;
    if ((r = sys6(SYS_io_uring_setup, 8, (long) &sp, 0, 0, 0, 0)) != -EINVAL)
      fail("io_uring_setup with SQPOLL", r, -EINVAL); }

  clr((char *) &p, sizeof p);
  long fd = sys6(SYS_io_uring_setup, 8, (long) &p, 0, 0, 0, 0);
  if (fd < 0)
    fail("io_uring_setup", fd, 0);
  if (p.sq_entries != 8)
    fail("sq_entries", p.sq_entries, 8);
  if (p.cq_entries < p.sq_entries)
    fail("cq_entries; it must be at least sq_entries", p.cq_entries,
         p.sq_entries);

  /*
   * The three mappings. This is the part that decides whether io_uring is
   * possible here at all: these pages must be the same ones NABI is reading.
   */
  unsigned long sqsz = p.sq_off.array + p.sq_entries * 4;
  unsigned long cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
  unsigned long sqesz = p.sq_entries * sizeof(struct sqe);

  sqbase = (char *) sys6(SYS_mmap, 0, sqsz, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
  if ((long) sqbase < 0)
    fail("mmap of the submission ring", (long) sqbase, 0);
  cqbase = (char *) sys6(SYS_mmap, 0, cqsz, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
  if ((long) cqbase < 0)
    fail("mmap of the completion ring", (long) cqbase, 0);
  sqes = (struct sqe *) sys6(SYS_mmap, 0, sqesz, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
  if ((long) sqes < 0)
    fail("mmap of the submission entries", (long) sqes, 0);

  /* NABI wrote these before the guest ever mapped the page. Reading them back
   * is the proof that the two are looking at the same memory. */
  if (*sq(p.sq_off.ring_entries) != p.sq_entries)
    fail("ring_entries as seen through the mapping",
         *sq(p.sq_off.ring_entries), p.sq_entries);
  if (*sq(p.sq_off.ring_mask) != p.sq_entries - 1)
    fail("ring_mask as seen through the mapping",
         *sq(p.sq_off.ring_mask), p.sq_entries - 1);

  long f = sys6(SYS_openat, AT_FDCWD, (long) "/uringfile",
                O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
  if (f < 0)
    fail("creating a file", f, 0);

  /* ---- a nop, which tests the ring and nothing else ---- */
  { struct sqe *s = push();
    s->opcode = OP_NOP;
    s->user_data = 0x1234;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a nop", r, 1);
    struct cqe c = pop("a completion for the nop");
    if (c.user_data != 0x1234)
      fail("the nop's user_data", (long) c.user_data, 0x1234);
    if (c.res != 0)
      fail("the nop's result", c.res, 0); }

  /* ---- a write, then a read of what it wrote ---- */
  { struct sqe *s = push();
    s->opcode = OP_WRITE;
    s->fd = f;
    s->addr = (unsigned long long) (long) "hello ring";
    s->len = 10;
    s->off = 0;
    s->user_data = 0x2222;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a write", r, 1);
    struct cqe c = pop("a completion for the write");
    if (c.res != 10)
      fail("what the write reported", c.res, 10);
    if (c.user_data != 0x2222)
      fail("the write's user_data", (long) c.user_data, 0x2222); }

  { char buf[32]; clr(buf, sizeof buf);
    struct sqe *s = push();
    s->opcode = OP_READ;
    s->fd = f;
    s->addr = (unsigned long long) (long) buf;
    s->len = 10;
    s->off = 0;
    s->user_data = 0x3333;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a read", r, 1);
    struct cqe c = pop("a completion for the read");
    if (c.res != 10)
      fail("what the read reported", c.res, 10);
    if (!eq(buf, "hello ring"))
      fails("what the read delivered", buf, "hello ring"); }

  /* ---- two in one call: each completion must carry its own user_data ---- */
  { char b1[16], b2[16]; clr(b1, 16); clr(b2, 16);
    struct sqe *s1 = push();
    s1->opcode = OP_READ; s1->fd = f;
    s1->addr = (unsigned long long) (long) b1; s1->len = 5; s1->off = 0;
    s1->user_data = 0xAAAA;
    struct sqe *s2 = push();
    s2->opcode = OP_READ; s2->fd = f;
    s2->addr = (unsigned long long) (long) b2; s2->len = 4; s2->off = 6;
    s2->user_data = 0xBBBB;

    if ((r = sys6(SYS_io_uring_enter, fd, 2, 2, IORING_ENTER_GETEVENTS, 0, 0)) != 2)
      fail("io_uring_enter for two", r, 2);

    struct cqe c1 = pop("the first of two completions");
    struct cqe c2 = pop("the second of two completions");
    if (c1.user_data != 0xAAAA)
      fail("the first completion's user_data", (long) c1.user_data, 0xAAAA);
    if (c2.user_data != 0xBBBB)
      fail("the second completion's user_data", (long) c2.user_data, 0xBBBB);
    if (c1.res != 5)
      fail("the first completion's result", c1.res, 5);
    if (c2.res != 4)
      fail("the second completion's result", c2.res, 4);
    if (!eq(b1, "hello"))
      fails("the first read's buffer", b1, "hello");
    if (!eq(b2, "ring"))
      fails("the second read's buffer", b2, "ring"); }

  /* ---- a vectored read scatters ---- */
  { char one[5], two[8]; clr(one, 5); clr(two, 8);
    struct iov v[2] = { { one, 5 }, { two, 5 } };
    struct sqe *s = push();
    s->opcode = OP_READV; s->fd = f;
    s->addr = (unsigned long long) (long) v;
    s->len = 2;                 /* a count of segments */
    s->off = 0;
    s->user_data = 0x4444;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a vectored read", r, 1);
    struct cqe c = pop("a completion for the vectored read");
    if (c.res != 10)
      fail("what the vectored read reported", c.res, 10);
    if (!eq(one, "hello"))
      fails("the first segment", one, "hello");
    if (two[0] != ' ' || two[1] != 'r' || two[2] != 'i' || two[3] != 'n' ||
        two[4] != 'g')
      fails("the second segment", two, " ring"); }

  /* ---- fsync ---- */
  { struct sqe *s = push();
    s->opcode = OP_FSYNC; s->fd = f; s->user_data = 0x5555;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an fsync", r, 1);
    struct cqe c = pop("a completion for the fsync");
    if (c.res != 0)
      fail("what the fsync reported", c.res, 0); }

  /* ---- an opcode this does not implement fails per entry, not per batch ---- */
  { struct sqe *s1 = push();
    s1->opcode = 200;           /* nothing */
    s1->user_data = 0x6666;
    struct sqe *s2 = push();
    s2->opcode = OP_NOP;
    s2->user_data = 0x7777;
    if ((r = sys6(SYS_io_uring_enter, fd, 2, 2, IORING_ENTER_GETEVENTS, 0, 0)) != 2)
      fail("a batch containing an unknown opcode", r, 2);
    struct cqe c1 = pop("the unknown opcode's completion");
    struct cqe c2 = pop("the good entry's completion");
    if (c1.res != -EINVAL)
      fail("what an unknown opcode reported", c1.res, -EINVAL);
    if (c2.user_data != 0x7777 || c2.res != 0)
      fail("the good entry beside it", (long) c2.user_data, 0x7777); }

  /* ---- a registered eventfd counts completions ---- */
  { long efd = sys6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (efd < 0)
      fail("eventfd2", efd, 0);
    int arg = (int) efd;
    if ((r = sys6(SYS_io_uring_register, fd, REGISTER_EVENTFD, (long) &arg, 1, 0, 0)) != 0)
      fail("registering an eventfd", r, 0);

    struct sqe *s1 = push(); s1->opcode = OP_NOP; s1->user_data = 0x8888;
    struct sqe *s2 = push(); s2->opcode = OP_NOP; s2->user_data = 0x9999;
    if ((r = sys6(SYS_io_uring_enter, fd, 2, 2, IORING_ENTER_GETEVENTS, 0, 0)) != 2)
      fail("io_uring_enter with an eventfd registered", r, 2);

    /* One count per completion posted, which is what makes a poll loop over
     * the ring possible. */
    unsigned long long got = 0;
    if ((r = sys6(SYS_read, efd, (long) &got, 8, 0, 0, 0)) != 8)
      fail("reading the ring's eventfd", r, 8);
    if (got != 2)
      fail("what the ring's eventfd counted", (long) got, 2);
    pop("the first completion beside the eventfd");
    pop("the second completion beside the eventfd");

    if ((r = sys6(SYS_io_uring_register, fd, UNREGISTER_EVENTFD, 0, 0, 0, 0)) != 0)
      fail("unregistering the eventfd", r, 0);
    if ((r = sys6(SYS_io_uring_register, fd, UNREGISTER_EVENTFD, 0, 0, 0, 0)) != -ENXIO)
      fail("unregistering it twice", r, -ENXIO);
    sys6(SYS_close, efd, 0, 0, 0, 0, 0); }

  /* ---- a timeout completes with ETIME when its clock runs out ---- */
  { struct { long long sec, nsec; } ts = { 0, 40 * 1000 * 1000 };
    struct sqe *s = push();
    s->opcode = OP_TIMEOUT;
    s->addr = (unsigned long long) (long) &ts;
    s->len = 1;                 /* one timespec */
    s->off = 0;                 /* no completion count; the clock alone */
    s->user_data = 0x7001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a timeout", r, 1);
    struct cqe c = pop("a completion for the timeout");
    if (c.user_data != 0x7001)
      fail("the timeout's user_data", (long) c.user_data, 0x7001);
    if (c.res != -ETIME)
      fail("what an expired timeout reported", c.res, -ETIME); }

  /*
   * ---- a poll that is not ready when it is submitted ----
   *
   * This is the case the whole thread exists for. The poll is armed and the
   * submitting call returns *without waiting* - there is nothing to report yet.
   * The pipe is fed afterwards, and only then is the completion asked for. An
   * implementation that ran the poll to completion inside the submitting call
   * would block right here with nothing able to write.
   */
  { int pfd[2];
    if (sys6(SYS_pipe2, (long) pfd, 0, 0, 0, 0, 0) != 0)
      fail("pipe2", -1, 0);

    struct sqe *s = push();
    s->opcode = OP_POLL_ADD;
    s->fd = pfd[0];
    s->rw_flags = POLLIN;
    s->user_data = 0x9001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a poll that cannot be ready yet", r, 1);

    /* Nothing should have been posted: the pipe is empty. */
    if (*cq(p.cq_off.head) != *cq(p.cq_off.tail))
      fail("a completion for a poll that is not ready", 1, 0);

    sys6(SYS_write, pfd[1], (long) "!", 1, 0, 0, 0);

    if ((r = sys6(SYS_io_uring_enter, fd, 0, 1, IORING_ENTER_GETEVENTS, 0, 0)) < 0)
      fail("waiting for the poll", r, 0);
    struct cqe c = pop("a completion for the poll");
    if (c.user_data != 0x9001)
      fail("the poll's user_data", (long) c.user_data, 0x9001);
    if (!(c.res & POLLIN))
      fail("what the poll reported", c.res, POLLIN);

    /* ---- and one that is removed before it can fire ---- */
    char drain[8];
    sys6(SYS_read, pfd[0], (long) drain, 1, 0, 0, 0);

    struct sqe *s2 = push();
    s2->opcode = OP_POLL_ADD;
    s2->fd = pfd[0];
    s2->rw_flags = POLLIN;
    s2->user_data = 0x9002;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a poll to remove", r, 1);

    struct sqe *s3 = push();
    s3->opcode = OP_POLL_REMOVE;
    s3->addr = 0x9002;            /* the user_data of the poll to cancel */
    s3->user_data = 0x9003;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a poll removal", r, 1);

    /* The cancelled poll is answered too, so a caller waiting on its user_data
     * is not left waiting for something that will never come. */
    struct cqe c1 = pop("a completion for the cancelled poll");
    struct cqe c2 = pop("a completion for the removal itself");
    if (c1.user_data != 0x9002 || c1.res != -ECANCELED)
      fail("what the cancelled poll reported", c1.res, -ECANCELED);
    if (c2.user_data != 0x9003 || c2.res != 0)
      fail("what the removal reported", c2.res, 0);

    /* Removing something that is not there. */
    struct sqe *s4 = push();
    s4->opcode = OP_POLL_REMOVE;
    s4->addr = 0xDEAD;
    s4->user_data = 0x9004;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a removal of nothing", r, 1);
    struct cqe c3 = pop("a completion for the removal of nothing");
    if (c3.res != -ENOENT)
      fail("removing a poll that was never armed", c3.res, -ENOENT);

    sys6(SYS_close, pfd[0], 0, 0, 0, 0, 0);
    sys6(SYS_close, pfd[1], 0, 0, 0, 0, 0); }

  /*
   * ---- a timeout that is waiting on a count, not on its clock ----
   *
   * off is a number of completions to wait for. Ten seconds is long enough that
   * the clock cannot be what ends this, so a res of 0 rather than -ETIME is the
   * proof that the count is what did.
   */
  { struct { long long sec, nsec; } ts = { 10, 0 };
    struct sqe *s1 = push();
    s1->opcode = OP_TIMEOUT;
    s1->addr = (unsigned long long) (long) &ts;
    s1->len = 1;
    s1->off = 1;                /* complete once one other completion lands */
    s1->user_data = 0x7002;
    struct sqe *s2 = push();
    s2->opcode = OP_NOP;
    s2->user_data = 0x7003;
    if ((r = sys6(SYS_io_uring_enter, fd, 2, 2, IORING_ENTER_GETEVENTS, 0, 0)) != 2)
      fail("a counted timeout beside a nop", r, 2);
    struct cqe c1 = pop("the nop's completion");
    struct cqe c2 = pop("the counted timeout's completion");
    if (c1.user_data != 0x7003)
      fail("the nop came first", (long) c1.user_data, 0x7003);
    if (c2.user_data != 0x7002)
      fail("the counted timeout's user_data", (long) c2.user_data, 0x7002);
    if (c2.res != 0)
      fail("a timeout ended by its count reports 0, not ETIME", c2.res, 0); }

  /*
   * ---- a timeout cancelled before its clock runs out ----
   *
   * Ten seconds, removed at once. That the test finishes at all is half the
   * assertion: a removal that waited for the timeout it was cancelling would
   * sit here.
   */
  { struct { long long sec, nsec; } ts = { 10, 0 };
    struct sqe *s1 = push();
    s1->opcode = OP_TIMEOUT;
    s1->addr = (unsigned long long) (long) &ts;
    s1->len = 1; s1->off = 0;
    s1->user_data = 0x7011;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a timeout to remove", r, 1);

    struct sqe *s2 = push();
    s2->opcode = OP_TIMEOUT_REMOVE;
    s2->addr = 0x7011;          /* the user_data of the timeout to cancel */
    s2->user_data = 0x7012;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a timeout removal", r, 1);

    struct cqe c1 = pop("a completion for the cancelled timeout");
    struct cqe c2 = pop("a completion for the removal itself");
    if (c1.user_data != 0x7011 || c1.res != -ECANCELED)
      fail("what the cancelled timeout reported", c1.res, -ECANCELED);
    if (c2.user_data != 0x7012 || c2.res != 0)
      fail("what the timeout removal reported", c2.res, 0);

    struct sqe *s3 = push();
    s3->opcode = OP_TIMEOUT_REMOVE;
    s3->addr = 0xDEAD;
    s3->user_data = 0x7013;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a removal of nothing", r, 1);
    struct cqe c3 = pop("a completion for the removal of nothing");
    if (c3.res != -ENOENT)
      fail("removing a timeout that was never armed", c3.res, -ENOENT); }

  /*
   * ---- the same opcode, updating instead of cancelling ----
   *
   * This is the case that separates the two. A ten-second timeout is updated
   * down to 40ms and then waited for. It must come back -ETIME rather than
   * -ECANCELED, which is what ignoring the UPDATE flag would produce.
   *
   * The wait is timed, and that is deliberate. Accepting the update but not
   * waking the poller leaves it asleep on the original deadline, so the
   * completion still arrives with the right result - ten seconds later. Only
   * the clock can tell that apart from a working update.
   */
  { struct { long long sec, nsec; } slow = { 10, 0 };
    struct { long long sec, nsec; } soon = { 0, 40 * 1000 * 1000 };
    struct sqe *s1 = push();
    s1->opcode = OP_TIMEOUT;
    s1->addr = (unsigned long long) (long) &slow;
    s1->len = 1; s1->off = 0;
    s1->user_data = 0x7021;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a timeout to update", r, 1);

    /*
     * Let the poller settle onto the ten-second deadline before changing it.
     * Without this the update can land while the poller has not yet gone back
     * to sleep, and it picks up the new deadline whether or not anything woke
     * it - which would make the timing check below prove nothing.
     */
    { struct { long long sec, nsec; } nap = { 0, 100 * 1000 * 1000 };
      sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0); }

    struct sqe *s2 = push();
    s2->opcode = OP_TIMEOUT_REMOVE;
    s2->rw_flags = TIMEOUT_UPDATE;
    s2->addr = 0x7021;          /* which timeout */
    s2->off = (unsigned long long) (long) &soon;   /* addr2: its new deadline */
    s2->user_data = 0x7022;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a timeout update", r, 1);

    struct cqe c1 = pop("a completion for the update itself");
    if (c1.user_data != 0x7022 || c1.res != 0)
      fail("what the timeout update reported", c1.res, 0);

    struct { long long sec, nsec; } t0, t1;
    sys6(SYS_clock_gettime, 1 /* MONOTONIC */, (long) &t0, 0, 0, 0, 0);
    if ((r = sys6(SYS_io_uring_enter, fd, 0, 1, IORING_ENTER_GETEVENTS, 0, 0)) < 0)
      fail("waiting for the updated timeout", r, 0);
    sys6(SYS_clock_gettime, 1, (long) &t1, 0, 0, 0, 0);

    struct cqe c2 = pop("a completion for the updated timeout");
    if (c2.user_data != 0x7021)
      fail("the updated timeout's user_data", (long) c2.user_data, 0x7021);
    if (c2.res != -ETIME)
      fail("an updated timeout must still expire, not be cancelled", c2.res,
           -ETIME);
    /* Two seconds is far above the 40ms asked for and far below the ten
     * seconds the timeout was originally armed with, so it separates the two
     * without depending on how fast this machine is. */
    if (t1.sec - t0.sec >= 2)
      fail("the update did not shorten the wait; seconds elapsed",
           (long) (t1.sec - t0.sec), 0); }

  /*
   * ---- async cancel, which does not care what it is cancelling ----
   *
   * The two removes above each know one kind of pending work. This one matches
   * across kinds, so the check that matters is that the *same* opcode cancels a
   * poll and a timeout - a typed implementation would answer ENOENT for one of
   * them.
   */
  { int pfd[2];
    if (sys6(SYS_pipe2, (long) pfd, 0, 0, 0, 0, 0) != 0)
      fail("pipe2", -1, 0);

    /* a poll */
    struct sqe *s1 = push();
    s1->opcode = OP_POLL_ADD; s1->fd = pfd[0]; s1->rw_flags = POLLIN;
    s1->user_data = 0xC001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a poll to cancel", r, 1);
    struct sqe *s2 = push();
    s2->opcode = OP_ASYNC_CANCEL; s2->addr = 0xC001; s2->user_data = 0xC002;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("cancelling a poll", r, 1);
    struct cqe c1 = pop("the cancelled poll's completion");
    struct cqe c2 = pop("the cancellation's completion");
    if (c1.user_data != 0xC001 || c1.res != -ECANCELED)
      fail("what the cancelled poll reported", c1.res, -ECANCELED);
    if (c2.res != 0)
      fail("what cancelling a poll reported", c2.res, 0);

    /* a timeout, through the same opcode */
    struct { long long sec, nsec; } ts = { 10, 0 };
    struct sqe *s3 = push();
    s3->opcode = OP_TIMEOUT; s3->addr = (unsigned long long) (long) &ts;
    s3->len = 1; s3->off = 0; s3->user_data = 0xC003;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("submitting a timeout to cancel", r, 1);
    struct sqe *s4 = push();
    s4->opcode = OP_ASYNC_CANCEL; s4->addr = 0xC003; s4->user_data = 0xC004;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("cancelling a timeout", r, 1);
    struct cqe c3 = pop("the cancelled timeout's completion");
    struct cqe c4 = pop("the cancellation's completion");
    if (c3.user_data != 0xC003 || c3.res != -ECANCELED)
      fail("what the cancelled timeout reported", c3.res, -ECANCELED);
    if (c4.res != 0)
      fail("what cancelling a timeout reported", c4.res, 0);

    /* nothing to cancel */
    struct sqe *s5 = push();
    s5->opcode = OP_ASYNC_CANCEL; s5->addr = 0xDEAD; s5->user_data = 0xC005;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("cancelling nothing", r, 1);
    struct cqe c5 = pop("the completion for cancelling nothing");
    if (c5.res != -ENOENT)
      fail("cancelling something that was never armed", c5.res, -ENOENT);

    /*
     * ---- by descriptor, and all of them ----
     *
     * Two polls on one pipe, each with its own user_data, cleared out by naming
     * the descriptor. Ignoring CANCEL_FD would match a descriptor number
     * against a user_data and find nothing; ignoring CANCEL_ALL would cancel
     * one of the two and report success, leaving the other armed.
     */
    struct sqe *s6 = push();
    s6->opcode = OP_POLL_ADD; s6->fd = pfd[0]; s6->rw_flags = POLLIN;
    s6->user_data = 0xC101;
    struct sqe *s7 = push();
    s7->opcode = OP_POLL_ADD; s7->fd = pfd[0]; s7->rw_flags = POLLIN;
    s7->user_data = 0xC102;
    if ((r = sys6(SYS_io_uring_enter, fd, 2, 0, 0, 0, 0)) != 2)
      fail("submitting two polls on one descriptor", r, 2);

    struct sqe *s8 = push();
    s8->opcode = OP_ASYNC_CANCEL;
    s8->rw_flags = CANCEL_FD | CANCEL_ALL;
    s8->addr = pfd[0];          /* a descriptor, not a user_data */
    s8->user_data = 0xC103;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("cancelling everything on a descriptor", r, 1);

    struct cqe d1 = pop("the first cancelled poll");
    struct cqe d2 = pop("the second cancelled poll");
    struct cqe d3 = pop("the cancellation's own completion");
    if (d1.res != -ECANCELED || d2.res != -ECANCELED)
      fail("what the polls cancelled by descriptor reported", d1.res,
           -ECANCELED);
    if ((d1.user_data == d2.user_data) ||
        (d1.user_data != 0xC101 && d1.user_data != 0xC102) ||
        (d2.user_data != 0xC101 && d2.user_data != 0xC102))
      fail("the two cancellations must name the two polls",
           (long) d1.user_data, 0xC101);
    /* Cancelling several reports how many, which is how a caller knows the
     * descriptor is now clear. */
    if (d3.res != 2)
      fail("how many CANCEL_ALL reported", d3.res, 2);

    /* A registered-descriptor cancel names a table that does not exist here. */
    struct sqe *s9 = push();
    s9->opcode = OP_ASYNC_CANCEL; s9->rw_flags = CANCEL_FD_FIXED;
    s9->addr = 0; s9->user_data = 0xC104;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 0, 0, 0, 0)) != 1)
      fail("cancelling by registered descriptor", r, 1);
    struct cqe d4 = pop("the completion for a fixed-descriptor cancel");
    if (d4.res != -EINVAL)
      fail("cancelling by a descriptor that was never registered", d4.res,
           -EINVAL);

    sys6(SYS_close, pfd[0], 0, 0, 0, 0, 0);
    sys6(SYS_close, pfd[1], 0, 0, 0, 0, 0); }

  /*
   * ---- statx, mkdirat and unlinkat through the ring ----
   *
   * These are the same operations as the syscalls of those names and are
   * answered by the same code, so what is worth checking is that the entry is
   * read correctly: the arguments sit in different fields here than they do in
   * a syscall frame, and a mask read out of the wrong one is a plausible bug
   * that still returns success.
   */
  /* A previous run that failed part-way could have left this behind, and a
   * test that cannot be run twice is a test that stops being run. */
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/uringdir", AT_REMOVEDIR, 0, 0, 0);

  { struct sqe *s = push();
    s->opcode = OP_MKDIRAT;
    s->fd = AT_FDCWD;
    s->addr = (unsigned long long) (long) "/uringdir";
    s->len = 0755;              /* the mode lives in len */
    s->user_data = 0xF001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a mkdirat", r, 1);
    struct cqe c = pop("a completion for the mkdirat");
    if (c.res != 0)
      fail("what mkdirat through the ring reported", c.res, 0); }

  /* statx of what mkdirat just made; the buffer is in addr2, the mask in len. */
  { char stx[256]; clr(stx, sizeof stx);
    struct sqe *s = push();
    s->opcode = OP_STATX;
    s->fd = AT_FDCWD;
    s->addr = (unsigned long long) (long) "/uringdir";
    s->len = STATX_BASIC_STATS; /* the mask lives in len */
    s->off = (unsigned long long) (long) stx;   /* addr2: the buffer */
    s->rw_flags = 0;
    s->user_data = 0xF002;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a statx", r, 1);
    struct cqe c = pop("a completion for the statx");
    if (c.res != 0)
      fail("what statx through the ring reported", c.res, 0);
    /* stx_mode is a u16 at offset 28 of struct statx; S_IFDIR is 040000. An
     * answer written into the wrong buffer, or not written at all, leaves this
     * zero - which is the point of reading it rather than trusting res. */
    unsigned short mode = *(unsigned short *)(stx + 28);
    if ((mode & 0170000) != 0040000)
      fail("what statx said the mode was", mode, 0040000); }

  /* unlinkat needs AT_REMOVEDIR for a directory: without it the flag has been
   * dropped somewhere and this comes back an error. */
  { struct sqe *s = push();
    s->opcode = OP_UNLINKAT;
    s->fd = AT_FDCWD;
    s->addr = (unsigned long long) (long) "/uringdir";
    s->rw_flags = AT_REMOVEDIR;
    s->user_data = 0xF003;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an unlinkat", r, 1);
    struct cqe c = pop("a completion for the unlinkat");
    if (c.res != 0)
      fail("removing a directory needs AT_REMOVEDIR carried through", c.res, 0);

    /* And it is really gone. */
    struct sqe *s2 = push();
    char stx[256];
    s2->opcode = OP_STATX;
    s2->fd = AT_FDCWD;
    s2->addr = (unsigned long long) (long) "/uringdir";
    s2->len = STATX_BASIC_STATS;
    s2->off = (unsigned long long) (long) stx;
    s2->user_data = 0xF004;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for the statx after removal", r, 1);
    struct cqe c2 = pop("a completion for the statx after removal");
    if (c2.res == 0)
      fail("the directory should be gone", c2.res, -1); }

  /*
   * ---- openat through the ring, and the descriptor it hands back ----
   *
   * The completion carries a descriptor, and the only way to know it is a
   * descriptor the *guest* can use is to use it: an open that produced a raw
   * host descriptor without entering it in the guest's table looks perfectly
   * successful right up until the first read.
   */
  { struct sqe *s = push();
    s->opcode = OP_OPENAT;
    s->fd = AT_FDCWD;
    s->addr = (unsigned long long) (long) "/uringfile";
    s->rw_flags = O_RDWR;       /* open_flags */
    s->len = 0;                 /* mode */
    s->user_data = 0xE001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an openat", r, 1);
    struct cqe c = pop("a completion for the openat");
    if (c.res < 0)
      fail("what openat through the ring reported", c.res, 0);

    char buf[16]; clr(buf, sizeof buf);
    long got = sys6(SYS_read, c.res, (long) buf, 5, 0, 0, 0);
    if (got != 5)
      fail("reading the descriptor openat handed back", got, 5);
    if (!eq(buf, "hello"))
      fails("what that descriptor read", buf, "hello");
    sys6(SYS_close, c.res, 0, 0, 0, 0, 0); }

  /* ---- send and recv over a socketpair ---- */
  { int sv[2];
    if (sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0, 0) != 0)
      fail("socketpair", -1, 0);

    struct sqe *s1 = push();
    s1->opcode = OP_SEND;
    s1->fd = sv[0];
    s1->addr = (unsigned long long) (long) "ring send";
    s1->len = 9;
    s1->rw_flags = 0;           /* msg_flags */
    s1->off = 0;                /* no destination: a connected socket */
    s1->user_data = 0xD001;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a send", r, 1);
    struct cqe c1 = pop("a completion for the send");
    if (c1.res != 9)
      fail("what send through the ring reported", c1.res, 9);

    char buf[32]; clr(buf, sizeof buf);
    struct sqe *s2 = push();
    s2->opcode = OP_RECV;
    s2->fd = sv[1];
    s2->addr = (unsigned long long) (long) buf;
    s2->len = sizeof buf;
    s2->rw_flags = 0;
    s2->user_data = 0xD002;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for a recv", r, 1);
    struct cqe c2 = pop("a completion for the recv");
    if (c2.res != 9)
      fail("what recv through the ring reported", c2.res, 9);
    if (!eq(buf, "ring send"))
      fails("what recv delivered", buf, "ring send");

    sys6(SYS_close, sv[0], 0, 0, 0, 0, 0);
    sys6(SYS_close, sv[1], 0, 0, 0, 0, 0); }

  /*
   * ---- openat2, whose point is that it checks ----
   *
   * The struct is the visible difference and the validation is the real one.
   * openat ignores a mode that cannot apply and bits it does not know; openat2
   * refuses both, which is how a caller finds out it did not get what it asked
   * for instead of quietly not getting it.
   */
  { struct { unsigned long long flags, mode, resolve; } how;

    how.flags = O_RDWR; how.mode = 0; how.resolve = 0;
    struct sqe *s = push();
    s->opcode = OP_OPENAT2;
    s->fd = AT_FDCWD;
    s->addr = (unsigned long long) (long) "/uringfile";
    s->off = (unsigned long long) (long) &how;   /* addr2 */
    s->len = sizeof how;                         /* its size, not a length */
    s->user_data = 0xD101;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an openat2", r, 1);
    struct cqe c = pop("a completion for the openat2");
    if (c.res < 0)
      fail("what openat2 through the ring reported", c.res, 0);
    /* Again: a descriptor is only a descriptor if the guest can use it. */
    char buf[16]; clr(buf, sizeof buf);
    if (sys6(SYS_read, c.res, (long) buf, 5, 0, 0, 0) != 5)
      fail("reading the descriptor openat2 handed back", -1, 5);
    if (!eq(buf, "hello"))
      fails("what that descriptor read", buf, "hello");
    sys6(SYS_close, c.res, 0, 0, 0, 0, 0);

    /* A mode with nothing to create is refused, where openat would ignore it. */
    how.flags = O_RDWR; how.mode = 0644; how.resolve = 0;
    struct sqe *s2 = push();
    s2->opcode = OP_OPENAT2;
    s2->fd = AT_FDCWD;
    s2->addr = (unsigned long long) (long) "/uringfile";
    s2->off = (unsigned long long) (long) &how;
    s2->len = sizeof how;
    s2->user_data = 0xD102;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an openat2 with a stray mode", r, 1);
    struct cqe c2 = pop("a completion for that openat2");
    if (c2.res != -EINVAL)
      fail("a mode with no O_CREAT must be refused, not ignored", c2.res,
           -EINVAL);

    /* A resolve restriction that cannot be enforced is refused rather than
     * accepted, because a caller sets one because it is relying on it. */
    how.flags = O_RDWR; how.mode = 0; how.resolve = 0x08;  /* RESOLVE_BENEATH */
    struct sqe *s3 = push();
    s3->opcode = OP_OPENAT2;
    s3->fd = AT_FDCWD;
    s3->addr = (unsigned long long) (long) "/uringfile";
    s3->off = (unsigned long long) (long) &how;
    s3->len = sizeof how;
    s3->user_data = 0xD103;
    if ((r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0)) != 1)
      fail("io_uring_enter for an openat2 with RESOLVE_BENEATH", r, 1);
    struct cqe c3 = pop("a completion for that openat2");
    if (c3.res != -EINVAL)
      fail("an unenforceable resolve flag must be refused", c3.res, -EINVAL); }

  /* ---- what these refuse ---- */
  if ((r = sys6(SYS_io_uring_enter, f, 0, 0, 0, 0, 0)) != -EOPNOTSUPP)
    fail("io_uring_enter on a descriptor that is not a ring", r, -EOPNOTSUPP);
  /* Registering buffers would mean honouring the fixed-buffer opcodes too, so
   * it is refused rather than accepted and ignored. */
  if ((r = sys6(SYS_io_uring_register, fd, 0, 0, 0, 0, 0)) != -EINVAL)
    fail("registering buffers, which is not implemented", r, -EINVAL);

  sys6(SYS_close, f, 0, 0, 0, 0, 0);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/uringfile", 0, 0, 0, 0);

  put("uring ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
