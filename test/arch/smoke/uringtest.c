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
