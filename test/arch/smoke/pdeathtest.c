/* freestanding: PR_SET_PDEATHSIG, and the death actually arriving.
 *
 * Darwin has no parent-death signal, so nabi watches for one: kqueue reports a
 * process exiting, and a thread waiting on that raises the signal here.
 *
 * The reason this is worth a real test rather than a round-trip of the value is
 * what asks for it. LXC sets SIGKILL on a container's first process so that a
 * container cannot outlive the lxc-start that owns it. A prctl that stored the
 * number and delivered nothing would satisfy PR_GET_PDEATHSIG perfectly and
 * leave an orphaned container running - the exact thing the flag exists to
 * prevent, and invisible from the process that set it.
 *
 * So the check is a grandchild: it asks for a signal on its parent's death, its
 * parent exits, and the grandchild has to die of it. The test waits for that
 * and reports what actually happened to it.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write       64
#define SYS_exit        93
#define SYS_clone      220
#define SYS_wait4      260
#define SYS_prctl      167
#define SYS_nanosleep  101
#define SYS_getppid    173
#define SYS_openat      56
#define SYS_close       57
#define SYS_unlinkat    35

#define O_WRONLY   1
#define O_CREAT   64
#define AT_FDCWD (-100)
#define MARK "/pdeath-survived" 

#define SIGCHLD    17
#define SIGUSR1    10
#define EINVAL     22
#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2

struct ts { long sec, nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("pdeath FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static void nap(long ms)
{ struct ts t = { ms / 1000, (ms % 1000) * 1000000 };
  sys6(SYS_nanosleep, (long) &t, 0, 0, 0, 0, 0); }

void _start(void)
{
  long r;

  /* The value round-trips, and a nonsense one is refused. */
  if ((r = sys6(SYS_prctl, PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0, 0)) != 0)
    fail("PR_SET_PDEATHSIG", r, 0);
  { int got = -1;
    if ((r = sys6(SYS_prctl, PR_GET_PDEATHSIG, (long) &got, 0, 0, 0, 0)) != 0)
      fail("PR_GET_PDEATHSIG", r, 0);
    if (got != SIGUSR1)
      fail("the signal it reports back", got, SIGUSR1); }
  if ((r = sys6(SYS_prctl, PR_SET_PDEATHSIG, 999, 0, 0, 0, 0)) != -EINVAL)
    fail("PR_SET_PDEATHSIG with a signal that does not exist", r, -EINVAL);
  /* Clearing it is setting it to zero. */
  if ((r = sys6(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0, 0)) != 0)
    fail("clearing PR_SET_PDEATHSIG", r, 0);

  /*
   * The part that matters: a grandchild asking to be killed when its parent
   * goes, and its parent going.
   */
  sys6(SYS_unlinkat, AT_FDCWD, (long) MARK, 0, 0, 0, 0);

  long child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (child < 0) fail("clone", child, 0);

  if (child == 0) {
    long grand = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (grand == 0) {
      /*
       * The grandchild. It asks to be killed when its parent goes, then waits
       * and leaves a mark. Reaching the mark is the "stored but never
       * delivered" outcome, and it is what the test looks for - the grandchild
       * is orphaned by then, so nobody can wait for it and its exit status is
       * not available to anyone.
       */
      sys6(SYS_prctl, PR_SET_PDEATHSIG, 9 /* SIGKILL */, 0, 0, 0, 0);
      nap(2500);
      long f = sys6(SYS_openat, AT_FDCWD, (long) MARK, O_WRONLY | O_CREAT, 0644, 0, 0);
      if (f >= 0) { sys6(SYS_write, f, (long) "x", 1, 0, 0, 0);
                    sys6(SYS_close, f, 0, 0, 0, 0, 0); }
      sys6(SYS_exit, 31, 0, 0, 0, 0, 0);
    }
    /*
     * Long enough for the grandchild to have asked, and no longer. Setting the
     * flag after the parent has already gone is a race Linux loses too - the
     * kernel checks it when the parent exits, so an exit that already happened
     * delivers nothing - and every caller that relies on this sets it as its
     * first act. LXC does exactly that.
     */
    nap(800);
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
  }

  int st = 0;
  if ((r = sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0)) != child)
    fail("wait4 of the middle process", r, child);

  /*
   * Long enough that a grandchild which was *not* killed has certainly woken
   * and left its mark. If the mark is there, the signal never arrived.
   */
  nap(5000);

  { long f = sys6(SYS_openat, AT_FDCWD, (long) MARK, 0, 0, 0, 0);
    if (f >= 0) {
      sys6(SYS_close, f, 0, 0, 0, 0, 0);
      sys6(SYS_unlinkat, AT_FDCWD, (long) MARK, 0, 0, 0, 0);
      fail("the grandchild outlived its parent", 1, 0);
    } }

  put("pdeath ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
