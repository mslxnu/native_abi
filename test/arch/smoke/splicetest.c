/* freestanding: splice(2) and vmsplice(2).
 *
 * These consume what they move, so the ordering trap that made tee hard does
 * not apply - except in one place, and that is the case worth testing. A pipe
 * that tee has taken bytes out of is holding them in front of the pipe, and a
 * splice from that pipe has to see those first. An implementation that reads
 * the pipe directly gets a stream with a hole in the middle of it, and gets it
 * only after a tee, which is exactly the combination nobody tries by hand.
 *
 * The offset arguments are the other half. An offset means the file's own
 * position must not move, and the caller's offset must - a pair that is easy to
 * get half right, and half right means a second splice reads the same bytes
 * again or skips some.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_unlinkat  35
#define SYS_openat    56
#define SYS_close     57
#define SYS_pipe2     59
#define SYS_lseek     62
#define SYS_read      63
#define SYS_write     64
#define SYS_vmsplice  75
#define SYS_splice    76
#define SYS_tee       77
#define SYS_exit      93

#define AT_FDCWD   -100
#define O_RDONLY    0
#define O_RDWR      2
#define O_CREAT     0100
#define O_TRUNC     01000
#define EBADF       9
#define EINVAL     22
#define ESPIPE     29

struct iov { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("splice FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("splice FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

void _start(void)
{
  long r;
  int p[2], q[2];
  char buf[64];

  if (sys6(SYS_pipe2, (long) p, 0, 0, 0, 0, 0) != 0 ||
      sys6(SYS_pipe2, (long) q, 0, 0, 0, 0, 0) != 0)
    fail("pipe2", -1, 0);

  long f = sys6(SYS_openat, AT_FDCWD, (long) "/splicefile",
                O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
  if (f < 0)
    fail("creating a file to splice through", f, 0);

  /* ---- pipe -> file ---- */
  sys6(SYS_write, p[1], (long) "hello world", 11, 0, 0, 0);
  if ((r = sys6(SYS_splice, p[0], 0, f, 0, 11, 0)) != 11)
    fail("splice from a pipe to a file", r, 11);

  sys6(SYS_lseek, f, 0, 0, 0, 0, 0);            /* SEEK_SET */
  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, f, (long) buf, sizeof buf, 0, 0, 0)) != 11)
    fail("what reached the file", r, 11);
  if (!eq(buf, "hello world"))
    fails("what the file holds", buf, "hello world");

  /* ---- file -> pipe, through a caller's offset ---- */
  { long long off = 6;
    if ((r = sys6(SYS_splice, f, (long) &off, q[1], 0, 5, 0)) != 5)
      fail("splice from a file to a pipe", r, 5);
    if (off != 11)
      fail("the caller's offset after a splice", (long) off, 11);

    clr(buf, sizeof buf);
    if ((r = sys6(SYS_read, q[0], (long) buf, sizeof buf, 0, 0, 0)) != 5)
      fail("what reached the pipe", r, 5);
    if (!eq(buf, "world"))
      fails("splicing from an offset", buf, "world");

    /* The file's own position must not have moved - that is what passing an
     * offset means, and a splice that moved it would make the next read of
     * this descriptor start in the wrong place. */
    if ((r = sys6(SYS_lseek, f, 0, 1, 0, 0, 0)) != 11)   /* SEEK_CUR */
      fail("the file position after an offset splice", r, 11); }

  /* ---- pipe -> pipe ---- */
  sys6(SYS_write, p[1], (long) "abcdef", 6, 0, 0, 0);
  if ((r = sys6(SYS_splice, p[0], 0, q[1], 0, 6, 0)) != 6)
    fail("splice between two pipes", r, 6);
  clr(buf, sizeof buf);
  sys6(SYS_read, q[0], (long) buf, 6, 0, 0, 0);
  if (!eq(buf, "abcdef"))
    fails("what crossed between two pipes", buf, "abcdef");

  /* ---- the case that needed care: splicing a pipe tee is holding ---- */
  sys6(SYS_write, p[1], (long) "ABCDEF", 6, 0, 0, 0);
  if ((r = sys6(SYS_tee, p[0], q[1], 4, 0, 0, 0)) != 4)
    fail("tee before the splice", r, 4);
  sys6(SYS_read, q[0], (long) buf, 4, 0, 0, 0);         /* drain the copy */

  if ((r = sys6(SYS_splice, p[0], 0, q[1], 0, 64, 0)) != 4)
    fail("splice sees the held bytes first", r, 4);
  clr(buf, sizeof buf);
  sys6(SYS_read, q[0], (long) buf, 4, 0, 0, 0);
  if (!eq(buf, "ABCD"))
    fails("the held bytes, through a splice", buf, "ABCD");

  if ((r = sys6(SYS_splice, p[0], 0, q[1], 0, 64, 0)) != 2)
    fail("then the rest of the pipe", r, 2);
  clr(buf, sizeof buf);
  sys6(SYS_read, q[0], (long) buf, 2, 0, 0, 0);
  if (!eq(buf, "EF"))
    fails("the rest, through a splice", buf, "EF");

  /* ---- vmsplice both ways ---- */
  { struct iov v[2] = { { (void *) "12", 2 }, { (void *) "345", 3 } };
    if ((r = sys6(SYS_vmsplice, p[1], (long) v, 2, 0, 0, 0)) != 5)
      fail("vmsplice into a pipe", r, 5);
    clr(buf, sizeof buf);
    sys6(SYS_read, p[0], (long) buf, 5, 0, 0, 0);
    if (!eq(buf, "12345"))
      fails("what vmsplice put in the pipe", buf, "12345"); }

  { char one[2], two[8];
    clr(one, 2); clr(two, 8);
    struct iov v[2] = { { one, 2 }, { two, 8 } };
    sys6(SYS_write, p[1], (long) "wxyz", 4, 0, 0, 0);
    if ((r = sys6(SYS_vmsplice, p[0], (long) v, 2, 0, 0, 0)) != 4)
      fail("vmsplice out of a pipe", r, 4);
    if (one[0] != 'w' || one[1] != 'x' || two[0] != 'y' || two[1] != 'z')
      fails("how vmsplice scattered them", two, "yz"); }

  /* ---- what Linux refuses ---- */
  { long g = sys6(SYS_openat, AT_FDCWD, (long) "/splicefile", O_RDONLY, 0, 0, 0);
    if (g < 0)
      fail("reopening the file", g, 0);
    if ((r = sys6(SYS_splice, g, 0, f, 0, 4, 0)) != -EINVAL)
      fail("splice with a pipe on neither end", r, -EINVAL);
    sys6(SYS_close, g, 0, 0, 0, 0, 0); }

  { long long off = 0;
    if ((r = sys6(SYS_splice, p[0], (long) &off, f, 0, 4, 0)) != -ESPIPE)
      fail("an offset for the pipe end", r, -ESPIPE); }

  { struct iov v = { buf, 4 };
    if ((r = sys6(SYS_vmsplice, f, (long) &v, 1, 0, 0, 0)) != -EBADF)
      fail("vmsplice of something that is not a pipe", r, -EBADF); }

  sys6(SYS_close, f, 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/splicefile", 0, 0, 0, 0);
  sys6(SYS_close, p[0], 0, 0, 0, 0, 0);
  sys6(SYS_close, p[1], 0, 0, 0, 0, 0);
  sys6(SYS_close, q[0], 0, 0, 0, 0, 0);
  sys6(SYS_close, q[1], 0, 0, 0, 0, 0);

  put("splice ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
