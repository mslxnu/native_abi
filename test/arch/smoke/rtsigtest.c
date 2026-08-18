/* freestanding: real-time signals, and the two prctl options beside them.
 *
 * Darwin's signals stop at 31 and Linux's real-time ones start at 32, so there
 * is no host signal to carry one. They were not carried: send_signal warned and
 * returned success, so a process that raised SIGRTMIN was told it had and
 * nothing was ever delivered. Two further things would have stopped it even if
 * it had been - rt_sigaction refused to install a handler for a signal with no
 * host counterpart, and the scan of the pending set used ffs on an int, so the
 * top half of a sixty-four bit mask was invisible.
 *
 * What is checked:
 *
 *   - a handler can be installed for SIGRTMIN at all.
 *   - a signal sent to *this* process runs it. That needs no host signal and is
 *     the case the pending-set scan had to be widened for.
 *   - one sent to another process runs it there, which is the case that needs
 *     the doorbell.
 *   - blocking one holds it, and unblocking delivers it - so it is really going
 *     through the pending set rather than being handled at the point of the
 *     kill.
 *   - the number arrives intact. A signal delivered as the wrong number would
 *     satisfy any check that only counted handler calls, and truncation is the
 *     failure this is most likely to have.
 *
 * What is NOT checked, because it is not implemented: queueing. Linux queues
 * real-time signals and delivers each instance; this coalesces them into a
 * pending bit, so two sent before either is handled arrive once.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_kill        129
#define SYS_getpid      172
#define SYS_clone       220
#define SYS_wait4       260
#define SYS_nanosleep   101
#define SYS_prctl       167
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135

#define SIGRTMIN     32
#define SIGCHLD      17
#define SIG_DFL       0
#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SA_RESTORER 0x04000000

#define PR_GET_DUMPABLE     3
#define PR_SET_DUMPABLE     4
#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42
#define EINVAL 22

struct lsigaction { unsigned long handler, flags, restorer, mask; };
struct ts { long sec, nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("rtsig FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static volatile int caught;
static volatile int caught_sig;

static void handler(int s) { caught++; caught_sig = s; }

static void
install(int sig)
{
  struct lsigaction sa;
  sa.handler = (unsigned long) handler;
  sa.flags = SA_RESTORER;
  sa.restorer = (unsigned long) handler;
  sa.mask = 0;
  long r = sys6(SYS_rt_sigaction, sig, (long) &sa, 0, 8, 0, 0);
  if (r != 0)
    fail("installing a handler for a real-time signal", r, 0);
}

/* Give the signal a moment to be noticed, without spinning for ever. */
static void
settle(void)
{
  struct ts t = { 0, 50 * 1000 * 1000 };
  sys6(SYS_nanosleep, (long) &t, 0, 0, 0, 0, 0);
}

void _start(void)
{
  long r;

  /* The prctl options first: they are independent and quick. */
  if ((r = sys6(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0, 0)) != 1)
    fail("PR_GET_DUMPABLE before anything sets it", r, 1);
  if ((r = sys6(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0, 0)) != 0)
    fail("PR_SET_DUMPABLE to 0", r, 0);
  if ((r = sys6(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0, 0)) != 0)
    fail("PR_GET_DUMPABLE after clearing it", r, 0);
  if ((r = sys6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0)) != 0)
    fail("PR_SET_DUMPABLE back to 1", r, 0);
  if ((r = sys6(SYS_prctl, PR_SET_DUMPABLE, 3, 0, 0, 0, 0)) != -EINVAL)
    fail("PR_SET_DUMPABLE with a value out of range", r, -EINVAL);

  if ((r = sys6(SYS_prctl, PR_GET_THP_DISABLE, 0, 0, 0, 0, 0)) != 0)
    fail("PR_GET_THP_DISABLE before anything sets it", r, 0);
  if ((r = sys6(SYS_prctl, PR_SET_THP_DISABLE, 1, 0, 0, 0, 0)) != 0)
    fail("PR_SET_THP_DISABLE", r, 0);
  if ((r = sys6(SYS_prctl, PR_GET_THP_DISABLE, 0, 0, 0, 0, 0)) != 1)
    fail("PR_GET_THP_DISABLE after setting it", r, 1);
  if ((r = sys6(SYS_prctl, PR_SET_THP_DISABLE, 1, 1, 0, 0, 0)) != -EINVAL)
    fail("PR_SET_THP_DISABLE with a nonzero second argument", r, -EINVAL);

  /* Now the signals. */
  install(SIGRTMIN);
  install(SIGRTMIN + 3);

  long me = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);

  /* To ourselves. */
  caught = 0; caught_sig = 0;
  if ((r = sys6(SYS_kill, me, SIGRTMIN, 0, 0, 0, 0)) != 0)
    fail("kill of ourselves with SIGRTMIN", r, 0);
  settle();
  if (caught != 1) fail("the handler after signalling ourselves", caught, 1);
  if (caught_sig != SIGRTMIN)
    fail("the number the handler was given", caught_sig, SIGRTMIN);

  /* A different number, to catch one being delivered as another. */
  caught = 0; caught_sig = 0;
  if ((r = sys6(SYS_kill, me, SIGRTMIN + 3, 0, 0, 0, 0)) != 0)
    fail("kill with SIGRTMIN+3", r, 0);
  settle();
  if (caught_sig != SIGRTMIN + 3)
    fail("the number for SIGRTMIN+3", caught_sig, SIGRTMIN + 3);

  /* Blocked, it waits; unblocked, it arrives. */
  { unsigned long mask = 1UL << (SIGRTMIN - 1);
    if ((r = sys6(SYS_rt_sigprocmask, SIG_BLOCK, (long) &mask, 0, 8, 0, 0)) != 0)
      fail("blocking SIGRTMIN", r, 0);
    caught = 0; caught_sig = 0;
    sys6(SYS_kill, me, SIGRTMIN, 0, 0, 0, 0);
    settle();
    if (caught != 0)
      fail("a blocked real-time signal was delivered anyway", caught, 0);
    if ((r = sys6(SYS_rt_sigprocmask, SIG_UNBLOCK, (long) &mask, 0, 8, 0, 0)) != 0)
      fail("unblocking SIGRTMIN", r, 0);
    settle();
    if (caught != 1)
      fail("the signal held while it was blocked", caught, 1); }

  /*
   * And across processes, which is the case that needs the doorbell: the child
   * signals the parent, and the parent has to notice.
   */
  caught = 0; caught_sig = 0;
  long child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (child < 0) fail("clone", child, 0);
  if (child == 0) {
    sys6(SYS_kill, me, SIGRTMIN, 0, 0, 0, 0);
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
  }
  int st = 0;
  sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0);
  for (int i = 0; i < 40 && caught == 0; i++)
    settle();
  if (caught == 0)
    fail("a real-time signal sent from another process", caught, 1);
  if (caught_sig != SIGRTMIN)
    fail("the number it arrived as", caught_sig, SIGRTMIN);

  put("rtsig ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
