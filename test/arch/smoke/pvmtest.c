/* freestanding: process_vm_readv and process_vm_writev.
 *
 * These copy between two address spaces, and here only one of them is reachable
 * - a guest process is a host process with its own guest memory, and nothing
 * gives NABI a way into another one (see the note in src/mm/mmap.c). So the
 * same-process form is implemented and the cross-process form is refused, and
 * both halves of that are worth pinning down.
 *
 * What is easy to get wrong in the half that works is the vector walk. The two
 * sides are gathered and scattered *independently*: the local and remote
 * vectors need not have the same number of entries or the same lengths, and the
 * transfer stops when either runs out. An implementation that paired them entry
 * by entry passes every test where the two happen to match and fails the moment
 * they do not, so the shapes here deliberately do not match.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getpid              172
#define SYS_write                64
#define SYS_exit                 93
#define SYS_process_vm_readv    270
#define SYS_process_vm_writev   271

#define EINVAL 22
#define EPERM   1
#define ESRCH   3

struct iov { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("pvm FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("pvm FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

void _start(void)
{
  long r;
  long me = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);

  /*
   * ---- a read whose two sides have different shapes ----
   *
   * Three remote pieces of 4, 4 and 2 bytes; two local pieces of 5 and 5. Same
   * ten bytes in total, arranged differently on each side - so anything that
   * pairs entry with entry gets it wrong.
   */
  { char r1[4] = { 'a','b','c','d' };
    char r2[4] = { 'e','f','g','h' };
    char r3[2] = { 'i','j' };
    char l1[6], l2[6];
    clr(l1, 6); clr(l2, 6);

    struct iov rv[3] = { { r1, 4 }, { r2, 4 }, { r3, 2 } };
    struct iov lv[2] = { { l1, 5 }, { l2, 5 } };

    r = sys6(SYS_process_vm_readv, me, (long) lv, 2, (long) rv, 3, 0);
    if (r != 10)
      fail("a read across three remote pieces into two local ones", r, 10);
    if (!eq(l1, "abcde"))
      fails("the first local piece", l1, "abcde");
    if (!eq(l2, "fghij"))
      fails("the second local piece", l2, "fghij"); }

  /* ---- the transfer stops when either side runs out ---- */
  { char src[8] = { '1','2','3','4','5','6','7','8' };
    char dst[4];
    clr(dst, 4);
    struct iov rv[1] = { { src, 8 } };
    struct iov lv[1] = { { dst, 3 } };   /* room for three of the eight */
    r = sys6(SYS_process_vm_readv, me, (long) lv, 1, (long) rv, 1, 0);
    if (r != 3)
      fail("a read into less room than there is to read", r, 3);
    if (!eq(dst, "123"))
      fails("what a short read delivered", dst, "123"); }

  { char src[2] = { 'x','y' };
    char dst[8];
    clr(dst, 8);
    struct iov rv[1] = { { src, 2 } };
    struct iov lv[1] = { { dst, 8 } };   /* more room than there is to read */
    r = sys6(SYS_process_vm_readv, me, (long) lv, 1, (long) rv, 1, 0);
    if (r != 2)
      fail("a read of less than there is room for", r, 2);
    if (!eq(dst, "xy"))
      fails("what that read delivered", dst, "xy"); }

  /* ---- writev goes the other way ---- */
  { char src[6] = { 'h','e','l','l','o','!' };
    char d1[4], d2[4];
    clr(d1, 4); clr(d2, 4);
    struct iov lv[1] = { { src, 6 } };
    struct iov rv[2] = { { d1, 3 }, { d2, 3 } };
    r = sys6(SYS_process_vm_writev, me, (long) lv, 1, (long) rv, 2, 0);
    if (r != 6)
      fail("a write scattered across two remote pieces", r, 6);
    if (!eq(d1, "hel"))
      fails("the first piece written", d1, "hel");
    if (!eq(d2, "lo!"))
      fails("the second piece written", d2, "lo!"); }

  /* ---- what these refuse ---- */
  { char b[4]; struct iov v[1] = { { b, 4 } };
    if ((r = sys6(SYS_process_vm_readv, me, (long) v, 1, (long) v, 1, 1)) != -EINVAL)
      fail("a flag, of which there are none", r, -EINVAL);
    if ((r = sys6(SYS_process_vm_readv, me, (long) v, 2000, (long) v, 1, 0)) != -EINVAL)
      fail("more iovec entries than UIO_MAXIOV", r, -EINVAL);

    /* Nothing to copy is not an error. */
    if ((r = sys6(SYS_process_vm_readv, me, (long) v, 0, (long) v, 1, 0)) != 0)
      fail("a read with no local pieces", r, 0);

    /*
     * Another process is refused rather than answered wrongly. EPERM is what
     * Linux says when the ptrace check fails, and callers have a path for it -
     * where a made-up success would hand back a buffer of nothing.
     */
    if ((r = sys6(SYS_process_vm_readv, 1, (long) v, 1, (long) v, 1, 0)) != -EPERM)
      fail("reading another process", r, -EPERM);
    if ((r = sys6(SYS_process_vm_writev, 1, (long) v, 1, (long) v, 1, 0)) != -EPERM)
      fail("writing another process", r, -EPERM);

    /* And one that does not exist is told apart from one that does. */
    if ((r = sys6(SYS_process_vm_readv, 0x7ffffff, (long) v, 1, (long) v, 1, 0)) != -ESRCH)
      fail("reading a process that does not exist", r, -ESRCH); }

  put("pvm ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
