/* freestanding: tee(2), on a host with no way to look into a pipe.
 *
 * That tee copies is the easy half, and a wrong implementation passes it. The
 * half worth testing is that the source is *unchanged* - in content and in
 * order - including while a writer keeps writing, which is the situation tee is
 * used in and the one every read-and-restore scheme gets wrong.
 *
 * So the partial tee below is the real test. Four bytes of "ABCDEF" are copied,
 * "GH" is written while those four are still out, and the source must read back
 * "ABCDEFGH". An implementation that appends what it read gives "EFABCD..."; one
 * that restores under a lock gives "GHABCDEF" as soon as the writer wins the
 * race.
 *
 * poll and select are checked for the same reason a timerfd's poll is: bytes
 * that only read() can see are invisible to every event loop, and a guest that
 * polls before reading would wait forever on data it already has.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_close     57
#define SYS_pselect6  72
#define SYS_ppoll     73
#define SYS_read      63
#define SYS_readv     65
#define SYS_write     64
#define SYS_exit      93
#define SYS_openat    56
#define SYS_pipe2     59
#define SYS_tee       77

#define POLLIN 1
#define EINVAL 22

struct tspec { long tv_sec, tv_nsec; };
struct pfd   { int fd; short events, revents; };
struct iov   { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("tee FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("tee FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }

static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

void _start(void)
{
  long r;
  int a[2], b[2];
  char buf[64];

  if (sys6(SYS_pipe2, (long) a, 0, 0, 0, 0, 0) != 0 ||
      sys6(SYS_pipe2, (long) b, 0, 0, 0, 0, 0) != 0)
    fail("pipe2", -1, 0);

  /* ---- what tee copied is still there ---- */
  sys6(SYS_write, a[1], (long) "ABCDEF", 6, 0, 0, 0);
  if ((r = sys6(SYS_tee, a[0], b[1], 6, 0, 0, 0)) != 6)
    fail("tee of six bytes", r, 6);

  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, b[0], (long) buf, 6, 0, 0, 0)) != 6)
    fail("reading the copy", r, 6);
  if (!eq(buf, "ABCDEF"))
    fails("what the copy holds", buf, "ABCDEF");

  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, a[0], (long) buf, sizeof buf, 0, 0, 0)) != 6)
    fail("the source still has its six bytes", r, 6);
  if (!eq(buf, "ABCDEF"))
    fails("what the source holds after a tee", buf, "ABCDEF");

  /* ---- a partial tee, and a writer while it is out ---- */
  sys6(SYS_write, a[1], (long) "ABCDEF", 6, 0, 0, 0);
  if ((r = sys6(SYS_tee, a[0], b[1], 4, 0, 0, 0)) != 4)
    fail("tee of four of six", r, 4);
  sys6(SYS_write, a[1], (long) "GH", 2, 0, 0, 0);   /* the hazard */

  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, a[0], (long) buf, sizeof buf, 0, 0, 0)) != 4)
    fail("the held bytes come back first", r, 4);
  if (!eq(buf, "ABCD"))
    fails("the held bytes, in order", buf, "ABCD");

  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, a[0], (long) buf, sizeof buf, 0, 0, 0)) != 4)
    fail("then the rest of the stream", r, 4);
  if (!eq(buf, "EFGH"))
    fails("the rest, with the late write behind it", buf, "EFGH");

  clr(buf, sizeof buf);
  sys6(SYS_read, b[0], (long) buf, 4, 0, 0, 0);     /* drain the copy */

  /* ---- held bytes make the descriptor readable ---- */
  sys6(SYS_write, a[1], (long) "XY", 2, 0, 0, 0);
  if ((r = sys6(SYS_tee, a[0], b[1], 2, 0, 0, 0)) != 2)
    fail("tee before the readiness checks", r, 2);
  sys6(SYS_read, b[0], (long) buf, 2, 0, 0, 0);

  { struct pfd p = { a[0], POLLIN, 0 };
    struct tspec to = { 0, 0 };
    r = sys6(SYS_ppoll, (long) &p, 1, (long) &to, 0, 0, 0);
    if (r != 1 || !(p.revents & POLLIN))
      fail("poll on a pipe whose bytes tee is holding", r, 1); }

  { unsigned long set = 1UL << a[0];
    struct tspec to = { 0, 0 };
    r = sys6(SYS_pselect6, a[0] + 1, (long) &set, 0, 0, (long) &to, 0);
    if (r != 1 || !(set & (1UL << a[0])))
      fail("select on a pipe whose bytes tee is holding", r, 1); }

  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, a[0], (long) buf, sizeof buf, 0, 0, 0)) != 2)
    fail("reading what poll promised", r, 2);
  if (!eq(buf, "XY"))
    fails("what poll promised", buf, "XY");

  /* ---- readv must see the same stream as read ---- */
  sys6(SYS_write, a[1], (long) "12345", 5, 0, 0, 0);
  if ((r = sys6(SYS_tee, a[0], b[1], 5, 0, 0, 0)) != 5)
    fail("tee before readv", r, 5);
  sys6(SYS_read, b[0], (long) buf, 5, 0, 0, 0);

  { char one[2], two[8];
    clr(one, 2); clr(two, 8);
    struct iov v[2] = { { one, 2 }, { two, 8 } };
    if ((r = sys6(SYS_readv, a[0], (long) v, 2, 0, 0, 0)) != 5)
      fail("readv of held bytes", r, 5);
    if (one[0] != '1' || one[1] != '2' ||
        two[0] != '3' || two[1] != '4' || two[2] != '5')
      fails("how readv scattered them", two, "345"); }

  /* ---- what Linux refuses ---- */
  /* A regular file, not fd 1: whether stdout is a pipe depends on how the
   * test was run, and a write-only pipe end answers EBADF rather than EINVAL. */
  { long f = sys6(SYS_openat, -100, (long) "/teetest", 0, 0, 0, 0);
    if (f < 0)
      fail("opening a regular file", f, 0);
    if ((r = sys6(SYS_tee, f, b[1], 4, 0, 0, 0)) != -EINVAL)
      fail("tee from something that is not a pipe", r, -EINVAL);
    sys6(SYS_close, f, 0, 0, 0, 0, 0); }
  if ((r = sys6(SYS_tee, a[0], a[1], 4, 0, 0, 0)) != -EINVAL)
    fail("tee from a pipe to itself", r, -EINVAL);
  if ((r = sys6(SYS_tee, a[0], b[1], 0, 0, 0, 0)) != 0)
    fail("tee of nothing", r, 0);

  sys6(SYS_close, a[0], 0, 0, 0, 0, 0);
  sys6(SYS_close, a[1], 0, 0, 0, 0, 0);
  sys6(SYS_close, b[0], 0, 0, 0, 0, 0);
  sys6(SYS_close, b[1], 0, 0, 0, 0, 0);

  put("tee ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
