/* freestanding: a signalfd for a signal nothing handles.
 *
 * The point of signalfd is to stop needing a handler: block the signal, put it
 * on a descriptor, and read it where it suits you. So the ordinary use is a
 * signal whose disposition is still SIG_DFL - which is the case nabi did not
 * cover. __host_signal_handler is the one place nabi learns a signal arrived,
 * and it was installed only for signals the guest had a real handler for; a
 * blocked, unhandled signal kept its host disposition, arrived nowhere, and
 * the descriptor watching it stayed unreadable for good.
 *
 * signalfdtest does not reach this: it installs handlers for the two signals
 * it uses, deliberately, so that nothing can default-terminate the test behind
 * a failure. The gap only shows with no handler at all.
 *
 * Android's init sits exactly here. It blocks SIGCHLD, never handles it, and
 * waits on a signalfd inside epoll to learn that a service has exited - so
 * every service it started was reported as "Exec service is hung? Waited
 * 10.0023 with no response" while the child had already run and exited.
 *
 * SIGCHLD is the signal used here for the same reason init uses it and the
 * reason it is safe to test with: its default action is to be ignored, so a
 * failure of this test cannot take the test process with it.
 *
 * What is checked:
 *
 *   - a signal raised at ourselves with no handler installed makes the
 *     descriptor readable, and reads back as that signal.
 *   - it is still pollable, since that is how anything actually waits on one -
 *     init has it inside an epoll and never reads it speculatively.
 *   - a real child exiting produces it too. That is the case that matters and
 *     it is not the same path: the signal comes from the host reaping a
 *     process rather than from the guest raising one at itself.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write         64
#define SYS_read          63
#define SYS_exit          93
#define SYS_close         57
#define SYS_ppoll         73
#define SYS_signalfd4     74
#define SYS_rt_sigprocmask 135
#define SYS_getpid       172
#define SYS_kill         129
#define SYS_clone        220
#define SYS_wait4        260
#define SYS_epoll_create1 20
#define SYS_epoll_ctl     21
#define SYS_epoll_pwait   22

#define SIGCHLD          17
#define SIGCHLD_BIT      (1UL << (SIGCHLD - 1))
#define SIG_BLOCK        0
#define SFD_CLOEXEC      0x80000
#define SI_SIZE          128
#define POLLIN           1
#define EPOLL_CTL_ADD    1
#define EPOLLIN          1

struct pollfd { int fd; short events, revents; };
struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}

static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) { put("  ok  "); put(what); put("\n"); return; }
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  /* Blocked, and deliberately never handled: no rt_sigaction anywhere here. */
  unsigned long mask = SIGCHLD_BIT;
  want("block SIGCHLD",
       sys6(SYS_rt_sigprocmask, SIG_BLOCK, (long)&mask, 0, 8, 0, 0), 0);

  long sfd = sys6(SYS_signalfd4, -1, (long)&mask, 8, SFD_CLOEXEC, 0, 0);
  want("signalfd4 on SIGCHLD", sfd >= 0, 1);
  if (sfd < 0) { put("sigchldfd FAILED\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  /* Raised at ourselves, with nothing to catch it. */
  long me = sys6(SYS_getpid, 0,0,0,0,0,0);
  want("kill(self, SIGCHLD)", sys6(SYS_kill, me, SIGCHLD, 0,0,0,0), 0);

  struct pollfd p = { (int) sfd, POLLIN, 0 };
  struct { long sec, nsec; } ts = { 5, 0 };
  long r = sys6(SYS_ppoll, (long)&p, 1, (long)&ts, 0, 0, 0);
  want("the descriptor becomes readable", r, 1);

  char buf[SI_SIZE];
  r = sys6(SYS_read, sfd, (long)buf, sizeof buf, 0, 0, 0);
  want("a record is read", r, SI_SIZE);
  want("and it is SIGCHLD", *(unsigned int *)buf, SIGCHLD);

  /* And the case init actually depends on: a child that exits. */
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0)
    sys6(SYS_exit, 0, 0,0,0,0,0);
  want("fork", kid > 0, 1);
  if (kid > 0) {
    p.revents = 0;
    ts.sec = 10;
    r = sys6(SYS_ppoll, (long)&p, 1, (long)&ts, 0, 0, 0);
    want("a child exiting is reported", r, 1);
    if (r == 1) {
      r = sys6(SYS_read, sfd, (long)buf, sizeof buf, 0, 0, 0);
      want("its record reads back", r, SI_SIZE);
      want("as SIGCHLD", *(unsigned int *)buf, SIGCHLD);
    }
    sys6(SYS_wait4, kid, 0, 0, 0, 0, 0);
  }

  /* And again through epoll, which is how init waits on it. */
  long ep = sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
  want("epoll_create1", ep >= 0, 1);
  if (ep >= 0) {
    struct epoll_event ev = { EPOLLIN, 0 };
    want("epoll_ctl(ADD, signalfd)",
         sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, sfd, (long)&ev, 0, 0), 0);
    long kid2 = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (kid2 == 0)
      sys6(SYS_exit, 0, 0,0,0,0,0);
    want("second fork", kid2 > 0, 1);
    if (kid2 > 0) {
      struct epoll_event got;
      long n = sys6(SYS_epoll_pwait, ep, (long)&got, 1, 10000, 0, 0);
      want("epoll reports the child's exit", n, 1);
      if (n == 1) {
        long rr = sys6(SYS_read, sfd, (long)buf, sizeof buf, 0, 0, 0);
        want("and the record is SIGCHLD",
             rr == SI_SIZE && *(unsigned int *)buf == SIGCHLD, 1);
      }
      sys6(SYS_wait4, kid2, 0, 0, 0, 0, 0);
    }
    sys6(SYS_close, ep, 0,0,0,0,0);
  }

  sys6(SYS_close, sfd, 0,0,0,0,0);
  put(fails ? "sigchldfd FAILED\n" : "sigchldfd ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
