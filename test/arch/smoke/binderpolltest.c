/* freestanding: registering a binder descriptor with epoll.
 *
 * macOS will not attach a plain EVFILT_READ knote to a third-party character
 * device - the driver would have to have called cdevsw_setkqueueok(), which is
 * private KPI - and refuses it with EINVAL. The one form it accepts carries
 * NOTE_LOWAT with a low-water mark of 1, and that is the predicate the driver's
 * selwakeup fires on, so readiness is exact rather than approximate.
 *
 * That matters because Android's looper is built on epoll: every binder client
 * registers the fd for readability at startup. If epoll_ctl(EPOLL_CTL_ADD)
 * fails there, the guest concludes binder is broken and stops - and the report
 * points at the driver rather than at the shim that never set the flag.
 *
 * poll() cannot be made to work on these nodes from outside the kernel at all;
 * it answers POLLNVAL. select() needs nothing special. So epoll is the one that
 * has to be got right, and this checks it end to end rather than trusting that
 * the branch exists.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_epoll_create1  20
#define SYS_epoll_ctl      21
#define SYS_epoll_pwait    22
#define SYS_openat         56
#define SYS_close          57
#define SYS_write          64
#define SYS_exit           93
#define SYS_pipe2          59

#define AT_FDCWD (-100)
#define O_RDWR    2
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2   /* ADD=1, DEL=2, MOD=3 */
#define EPOLLIN   1

struct epev { unsigned events; unsigned pad; unsigned long long data; } __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("binderpoll FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

void _start(void)
{
  long r;
  long ep = sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
  if (ep < 0) fail("epoll_create1", ep, 0);

  /* An ordinary descriptor first, so a total failure of epoll is told apart
   * from one specific to the device. The DEL is checked, and the descriptors
   * are closed afterwards - which is where a stale registration would show,
   * since the next open reuses the number. */
  { int p[2];
    if ((r = sys6(SYS_pipe2, (long) p, 0, 0,0,0,0)) != 0) fail("pipe2", r, 0);
    struct epev ev = { EPOLLIN, 0, 1 };
    if ((r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, p[0], (long) &ev, 0,0)) != 0)
      fail("epoll_ctl on a pipe", r, 0);
    if ((r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, p[0], 0, 0,0)) != 0)
      fail("epoll_ctl(DEL) on a pipe", r, 0);
    sys6(SYS_close, p[0], 0,0,0,0,0); sys6(SYS_close, p[1], 0,0,0,0,0);
    /* A fresh descriptor landing on the same number must be addable. */
    int q[2];
    if ((r = sys6(SYS_pipe2, (long) q, 0, 0,0,0,0)) != 0) fail("pipe2 again", r, 0);
    if ((r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, q[0], (long) &ev, 0,0)) != 0)
      fail("epoll_ctl on a reused descriptor number", r, 0);
    sys6(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, q[0], 0, 0,0);
    sys6(SYS_close, q[0], 0,0,0,0,0); sys6(SYS_close, q[1], 0,0,0,0,0); }

  /* The binder node. Absent is not a failure of this test - the kext may not
   * be loaded - but present-and-unregisterable is. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder", O_RDWR, 0, 0, 0);
  if (fd < 0) { put("binderpoll skipped (no /dev/binder)\n"); sys6(SYS_exit,0,0,0,0,0,0); }

  struct epev ev = { EPOLLIN, 0, 0x1234 };
  r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, fd, (long) &ev, 0, 0);
  if (r != 0)
    fail("epoll_ctl(ADD) on /dev/binder", r, 0);

  /* Idle, so nothing should be ready - a filter that reported readable with no
   * transaction pending would spin a looper flat out. */
  struct epev got[4];
  r = sys6(SYS_epoll_pwait, ep, (long) got, 4, 0, 0, 0);
  if (r != 0)
    fail("epoll_pwait on an idle binder fd", r, 0);

  if ((r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, fd, 0, 0, 0)) != 0)
    fail("epoll_ctl(DEL) on /dev/binder", r, 0);

  /* And re-adding works, which is what a looper does across its lifetime. */
  if ((r = sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, fd, (long) &ev, 0, 0)) != 0)
    fail("epoll_ctl(ADD) again after DEL", r, 0);

  sys6(SYS_close, fd, 0,0,0,0,0);
  sys6(SYS_close, ep, 0,0,0,0,0);
  put("binderpoll ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
