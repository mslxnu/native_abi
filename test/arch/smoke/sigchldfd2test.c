/* freestanding: a signalfd for a signal the guest *also* has a handler for.
 *
 * sigchldfdtest covers the textbook shape - block the signal, never handle it,
 * read it off a descriptor. Android's init does something else, and the
 * difference is the whole of this test: it installs a real SIGCHLD handler
 * first, *then* blocks the signal, *then* opens the signalfd, and waits on the
 * descriptor inside an epoll. Every one of those steps changes what nabi has
 * to do about the host's own disposition and mask, and they interact:
 * signalfd_arm bows out when the guest has a handler of its own, on the
 * grounds that the handler already brought a host handler with it, and
 * rt_sigprocmask leaves a handled signal unblocked on the host for the same
 * reason. Both are true only if the other holds.
 *
 * What is checked:
 *
 *   - with a handler installed and the signal blocked, a child exiting still
 *     makes the descriptor readable through epoll. This is the case init lives
 *     or dies by: it is how it learns a service it started has finished, and
 *     when it does not hear, it declares the service hung after ten seconds
 *     and reboots the machine.
 *   - the handler does not run, because the signal is blocked - the arrival
 *     has to be recorded without being delivered.
 *   - and a second child works the same way, so the first is not a one-off
 *     left over from something armed at creation.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_close 57
#define SYS_signalfd4 74
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_epoll_create1 20
#define SYS_epoll_ctl 21
#define SYS_epoll_pwait 22
#define SYS_read 63
#define SYS_getpid 172

#define SIGCHLD 17
#define SIGCHLD_BIT (1UL << (SIGCHLD - 1))
#define SIG_BLOCK 0
#define SFD_CLOEXEC 02000000
#define EPOLL_CTL_ADD 1
#define EPOLLIN 1
#define SI_SIZE 128

struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

static volatile int handler_ran;
static void handler(int s) { (void) s; handler_ran = 1; }

/* A child that does a little work before exiting, so the exit does not land in
 * the same instant as the fork - init's services all run for a while. */
static long spawn(void)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    for (volatile int i = 0; i < 200000; i++)
      ;
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }
  return kid;
}

void _start(void)
{
  char buf[SI_SIZE];
  unsigned long mask = SIGCHLD_BIT;

  /* init's order, and the order is the point. */
  long act[4] = { (long) handler, 0, 0, 0 };
  want("rt_sigaction(SIGCHLD)",
       sys6(SYS_rt_sigaction, SIGCHLD, (long)act, 0, 8, 0, 0), 0);
  want("block SIGCHLD",
       sys6(SYS_rt_sigprocmask, SIG_BLOCK, (long)&mask, 0, 8, 0, 0), 0);

  long sfd = sys6(SYS_signalfd4, -1, (long)&mask, 8, SFD_CLOEXEC, 0, 0);
  want("signalfd4 on SIGCHLD", sfd >= 0, 1);
  long ep = sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
  want("epoll_create1", ep >= 0, 1);
  if (sfd < 0 || ep < 0) { put("sigchldfd2 FAILED\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  struct epoll_event ev = { EPOLLIN, 0 };
  want("epoll_ctl(ADD, signalfd)",
       sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, (int) sfd, (long)&ev, 0, 0), 0);

  for (int round = 0; round < 2; round++) {
    long kid = spawn();
    want("fork", kid > 0, 1);
    if (kid <= 0)
      break;

    struct epoll_event got;
    long n = sys6(SYS_epoll_pwait, ep, (long)&got, 1, 10000, 0, 0);
    want("epoll reports the child's exit", n, 1);
    if (n == 1) {
      long rr = sys6(SYS_read, sfd, (long)buf, sizeof buf, 0, 0, 0);
      want("the record reads back as SIGCHLD",
           rr == SI_SIZE && *(unsigned int *)buf == SIGCHLD, 1);
    }
    sys6(SYS_wait4, kid, 0, 0, 0, 0, 0);
  }

  want("the handler did not run for a blocked signal", handler_ran, 0);

  sys6(SYS_close, sfd, 0,0,0,0,0);
  sys6(SYS_close, ep, 0,0,0,0,0);
  put(fails == 0 ? "sigchldfd2 ok\n" : "sigchldfd2 failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
