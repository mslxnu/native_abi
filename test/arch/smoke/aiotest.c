/* freestanding: Linux asynchronous I/O, the io_setup family.
 *
 * The easy half is that a read reads. The parts worth testing are the ones an
 * implementation can get wrong while still looking like it works:
 *
 *   - io_submit must not wait. A batch of reads returns a count immediately and
 *     the results turn up later, which is the entire reason the interface
 *     exists.
 *   - A read's data must be in the guest's own buffer by the time the event is
 *     reaped, not in some buffer NABI keeps.
 *   - io_getevents(min_nr) must actually wait for min_nr, rather than returning
 *     whatever happens to be ready.
 *   - Each event must carry back the iocb's aio_data and the iocb's *address*,
 *     which is how a caller matches a completion to the request it made. Getting
 *     these crossed is invisible with one request in flight and wrong with two.
 *   - An eventfd named by IOCB_FLAG_RESFD must become readable, which is how aio
 *     joins a poll loop.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_io_setup      0
#define SYS_io_destroy    1
#define SYS_io_submit     2
#define SYS_io_cancel     3
#define SYS_io_getevents  4
#define SYS_unlinkat     35
#define SYS_openat       56
#define SYS_close        57
#define SYS_lseek        62
#define SYS_read         63
#define SYS_write        64
#define SYS_eventfd2     19
#define SYS_exit         93

#define AT_FDCWD  -100
#define O_RDONLY   0
#define O_RDWR     2
#define O_CREAT    0100
#define O_TRUNC    01000
#define SEEK_SET   0
#define EINVAL    22

#define IOCB_CMD_PREAD   0
#define IOCB_CMD_PWRITE  1
#define IOCB_CMD_FSYNC   2
#define IOCB_CMD_NOOP    6
#define IOCB_CMD_PREADV  7
#define IOCB_FLAG_RESFD  1

struct iocb {
  unsigned long long aio_data;
  unsigned int aio_key, aio_rw_flags;
  unsigned short aio_lio_opcode;
  short aio_reqprio;
  unsigned int aio_fildes;
  unsigned long long aio_buf, aio_nbytes;
  long long aio_offset;
  unsigned long long aio_reserved2;
  unsigned int aio_flags, aio_resfd;
};
struct io_event { unsigned long long data, obj; long long res, res2; };
struct iov { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("aio FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("aio FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

void _start(void)
{
  long r;
  unsigned long long ctx = 0;

  /* A handle that is not zero on the way in is refused. */
  { unsigned long long dirty = 1;
    if ((r = sys6(SYS_io_setup, 8, (long) &dirty, 0, 0, 0, 0)) != -EINVAL)
      fail("io_setup over a handle that is not zero", r, -EINVAL); }

  if ((r = sys6(SYS_io_setup, 8, (long) &ctx, 0, 0, 0, 0)) != 0)
    fail("io_setup", r, 0);
  if (ctx == 0)
    fail("the context handle", (long) ctx, 1);

  long f = sys6(SYS_openat, AT_FDCWD, (long) "/aiofile",
                O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
  if (f < 0)
    fail("creating a file", f, 0);

  /* ---- a write, submitted and reaped ---- */
  { struct iocb cb; clr((char *) &cb, sizeof cb);
    cb.aio_data = 0x1111;
    cb.aio_lio_opcode = IOCB_CMD_PWRITE;
    cb.aio_fildes = f;
    cb.aio_buf = (unsigned long long) (long) "hello aio";
    cb.aio_nbytes = 9;
    cb.aio_offset = 0;
    struct iocb *v[1] = { &cb };
    if ((r = sys6(SYS_io_submit, (long) ctx, 1, (long) v, 0, 0, 0)) != 1)
      fail("io_submit of one write", r, 1);

    struct io_event ev; clr((char *) &ev, sizeof ev);
    if ((r = sys6(SYS_io_getevents, (long) ctx, 1, 1, (long) &ev, 0, 0)) != 1)
      fail("io_getevents for the write", r, 1);
    if (ev.res != 9)
      fail("what the write reported", (long) ev.res, 9);
    if (ev.data != 0x1111)
      fail("the event's data", (long) ev.data, 0x1111);
    if (ev.obj != (unsigned long long) (long) &cb)
      fail("the event's obj; it must be the iocb's address", (long) ev.obj,
           (long) &cb); }

  /* ---- a read, whose data must land in the guest's own buffer ---- */
  { char buf[32]; clr(buf, sizeof buf);
    struct iocb cb; clr((char *) &cb, sizeof cb);
    cb.aio_data = 0x2222;
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_fildes = f;
    cb.aio_buf = (unsigned long long) (long) buf;
    cb.aio_nbytes = 9;
    cb.aio_offset = 0;
    struct iocb *v[1] = { &cb };
    if ((r = sys6(SYS_io_submit, (long) ctx, 1, (long) v, 0, 0, 0)) != 1)
      fail("io_submit of one read", r, 1);

    struct io_event ev; clr((char *) &ev, sizeof ev);
    if ((r = sys6(SYS_io_getevents, (long) ctx, 1, 1, (long) &ev, 0, 0)) != 1)
      fail("io_getevents for the read", r, 1);
    if (ev.res != 9)
      fail("what the read reported", (long) ev.res, 9);
    if (!eq(buf, "hello aio"))
      fails("where the read's data ended up", buf, "hello aio"); }

  /*
   * ---- two at once ----
   *
   * min_nr is the part that must wait. Both come back, and each event has to
   * carry its own request's data and address - crossed wires are invisible with
   * one in flight.
   */
  { char b1[16], b2[16]; clr(b1, 16); clr(b2, 16);
    struct iocb c1, c2; clr((char *) &c1, sizeof c1); clr((char *) &c2, sizeof c2);
    c1.aio_data = 0xAAAA; c1.aio_lio_opcode = IOCB_CMD_PREAD;
    c1.aio_fildes = f; c1.aio_buf = (unsigned long long) (long) b1;
    c1.aio_nbytes = 5; c1.aio_offset = 0;
    c2.aio_data = 0xBBBB; c2.aio_lio_opcode = IOCB_CMD_PREAD;
    c2.aio_fildes = f; c2.aio_buf = (unsigned long long) (long) b2;
    c2.aio_nbytes = 3; c2.aio_offset = 6;
    struct iocb *v[2] = { &c1, &c2 };
    if ((r = sys6(SYS_io_submit, (long) ctx, 2, (long) v, 0, 0, 0)) != 2)
      fail("io_submit of two", r, 2);

    struct io_event ev[2]; clr((char *) ev, sizeof ev);
    if ((r = sys6(SYS_io_getevents, (long) ctx, 2, 2, (long) ev, 0, 0)) != 2)
      fail("io_getevents waiting for both", r, 2);

    for (int i = 0; i < 2; i++) {
      if (ev[i].data == 0xAAAA) {
        if (ev[i].obj != (unsigned long long) (long) &c1)
          fail("the first request's obj", (long) ev[i].obj, (long) &c1);
        if (ev[i].res != 5)
          fail("the first request's result", (long) ev[i].res, 5);
      } else if (ev[i].data == 0xBBBB) {
        if (ev[i].obj != (unsigned long long) (long) &c2)
          fail("the second request's obj", (long) ev[i].obj, (long) &c2);
        if (ev[i].res != 3)
          fail("the second request's result", (long) ev[i].res, 3);
      } else {
        fail("an event belonging to neither request", (long) ev[i].data, 0xAAAA);
      }
    }
    if (!eq(b1, "hello"))
      fails("the first read's buffer", b1, "hello");
    if (!eq(b2, "aio"))
      fails("the second read's buffer", b2, "aio"); }

  /* ---- a timeout with nothing outstanding returns nothing, not an error ---- */
  { struct io_event ev;
    struct { long sec, nsec; } to = { 0, 20 * 1000 * 1000 };
    if ((r = sys6(SYS_io_getevents, (long) ctx, 1, 1, (long) &ev, (long) &to, 0)) != 0)
      fail("io_getevents with nothing outstanding", r, 0); }

  /* ---- a vectored read scatters ---- */
  { char one[5], two[8]; clr(one, 5); clr(two, 8);
    struct iov v[2] = { { one, 5 }, { two, 4 } };
    struct iocb cb; clr((char *) &cb, sizeof cb);
    cb.aio_data = 0x3333;
    cb.aio_lio_opcode = IOCB_CMD_PREADV;
    cb.aio_fildes = f;
    cb.aio_buf = (unsigned long long) (long) v;
    cb.aio_nbytes = 2;          /* a count of segments, not of bytes */
    cb.aio_offset = 0;
    struct iocb *p[1] = { &cb };
    if ((r = sys6(SYS_io_submit, (long) ctx, 1, (long) p, 0, 0, 0)) != 1)
      fail("io_submit of a vectored read", r, 1);
    struct io_event ev; clr((char *) &ev, sizeof ev);
    if ((r = sys6(SYS_io_getevents, (long) ctx, 1, 1, (long) &ev, 0, 0)) != 1)
      fail("io_getevents for the vectored read", r, 1);
    if (ev.res != 9)
      fail("what the vectored read reported", (long) ev.res, 9);
    if (!eq(one, "hello"))
      fails("the first segment", one, "hello");
    if (two[0] != ' ' || two[1] != 'a' || two[2] != 'i' || two[3] != 'o')
      fails("the second segment", two, " aio"); }

  /* ---- an eventfd is signalled on completion ---- */
  { long efd = sys6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (efd < 0)
      fail("eventfd2", efd, 0);
    char buf[16]; clr(buf, sizeof buf);
    struct iocb cb; clr((char *) &cb, sizeof cb);
    cb.aio_data = 0x4444;
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_fildes = f;
    cb.aio_buf = (unsigned long long) (long) buf;
    cb.aio_nbytes = 5;
    cb.aio_offset = 0;
    cb.aio_flags = IOCB_FLAG_RESFD;
    cb.aio_resfd = efd;
    struct iocb *v[1] = { &cb };
    if ((r = sys6(SYS_io_submit, (long) ctx, 1, (long) v, 0, 0, 0)) != 1)
      fail("io_submit with an eventfd", r, 1);

    /* The read blocks here until the completion pokes it, which is the whole
     * point of naming one. */
    unsigned long long got = 0;
    if ((r = sys6(SYS_read, efd, (long) &got, 8, 0, 0, 0)) != 8)
      fail("reading the eventfd a completion should have poked", r, 8);
    if (got != 1)
      fail("what the eventfd counted", (long) got, 1);

    struct io_event ev;
    if ((r = sys6(SYS_io_getevents, (long) ctx, 1, 1, (long) &ev, 0, 0)) != 1)
      fail("io_getevents after the eventfd fired", r, 1);
    sys6(SYS_close, efd, 0, 0, 0, 0, 0); }

  /* ---- fsync and noop are operations too ---- */
  { struct iocb c1, c2; clr((char *) &c1, sizeof c1); clr((char *) &c2, sizeof c2);
    c1.aio_data = 0x5555; c1.aio_lio_opcode = IOCB_CMD_FSYNC; c1.aio_fildes = f;
    c2.aio_data = 0x6666; c2.aio_lio_opcode = IOCB_CMD_NOOP;  c2.aio_fildes = f;
    struct iocb *v[2] = { &c1, &c2 };
    if ((r = sys6(SYS_io_submit, (long) ctx, 2, (long) v, 0, 0, 0)) != 2)
      fail("io_submit of fsync and noop", r, 2);
    struct io_event ev[2];
    if ((r = sys6(SYS_io_getevents, (long) ctx, 2, 2, (long) ev, 0, 0)) != 2)
      fail("io_getevents for fsync and noop", r, 2);
    if (ev[0].res != 0 || ev[1].res != 0)
      fail("what fsync and noop reported", (long) ev[0].res, 0); }

  /* ---- what these refuse ---- */
  if ((r = sys6(SYS_io_submit, 0x1234, 1, 0, 0, 0, 0)) != -EINVAL)
    fail("io_submit against a context that does not exist", r, -EINVAL);
  if ((r = sys6(SYS_io_destroy, 0x1234, 0, 0, 0, 0, 0)) != -EINVAL)
    fail("io_destroy of a context that does not exist", r, -EINVAL);
  { struct iocb cb; clr((char *) &cb, sizeof cb);
    struct io_event ev;
    if ((r = sys6(SYS_io_cancel, (long) ctx, (long) &cb, (long) &ev, 0, 0, 0)) != -EINVAL)
      fail("io_cancel of a request that was never submitted", r, -EINVAL); }

  if ((r = sys6(SYS_io_destroy, (long) ctx, 0, 0, 0, 0, 0)) != 0)
    fail("io_destroy", r, 0);
  if ((r = sys6(SYS_io_submit, (long) ctx, 1, 0, 0, 0, 0)) != -EINVAL)
    fail("io_submit against a destroyed context", r, -EINVAL);

  sys6(SYS_close, f, 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/aiofile", 0, 0, 0, 0);

  put("aio ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
