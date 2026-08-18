/* freestanding: waitid, and the looking-without-reaping that is its point.
 *
 * wait4 puts the outcome in a status word the caller picks apart with macros;
 * waitid states it in a siginfo, and can report a child *without* consuming it.
 * That last part has no expression in wait4 at all, which is why this is served
 * by the host's waitid rather than built out of the one already here - and it is
 * what lxc-start uses.
 *
 * The check that matters is that WNOWAIT leaves the child reapable: an
 * implementation that quietly reaped would return exactly the same siginfo and
 * differ only in what happens next, which is the whole difference.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_clone  220
#define SYS_wait4  260
#define SYS_waitid  95

#define SIGCHLD     17
#define P_ALL        0
#define P_PID        1
#define WNOHANG      1
#define WEXITED      4
#define WNOWAIT   0x01000000
#define CLD_EXITED   1
#define ECHILD      10
#define EINVAL      22

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("waitid FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

/* aarch64 siginfo: signo, errno, code at 0/4/8; pid, uid, status at 16/20/24. */
static int si[32];

void _start(void)
{
  long r;

  long child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (child < 0) fail("clone", child, 0);
  if (child == 0)
    sys6(SYS_exit, 7, 0, 0, 0, 0, 0);

  /* Look, without taking. */
  for (int i = 0; i < 32; i++) si[i] = 0;
  r = sys6(SYS_waitid, P_PID, child, (long) si, WEXITED | WNOWAIT, 0, 0);
  if (r != 0) fail("waitid with WNOWAIT", r, 0);
  if (si[0] != SIGCHLD)  fail("si_signo", si[0], SIGCHLD);
  if (si[2] != CLD_EXITED) fail("si_code", si[2], CLD_EXITED);
  if (si[4] != (int) child) fail("si_pid", si[4], child);
  if (si[6] != 7) fail("si_status", si[6], 7);

  /* And it is still there to be taken, which is what WNOWAIT means. */
  int st = 0;
  r = sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0);
  if (r != child) fail("the child after WNOWAIT - it was reaped", r, child);
  if (((st >> 8) & 0xff) != 7) fail("its exit status", (st >> 8) & 0xff, 7);

  /* Nothing left to wait for. */
  r = sys6(SYS_waitid, P_ALL, 0, (long) si, WEXITED | WNOHANG, 0, 0);
  if (r != -ECHILD) fail("waitid with no children", r, -ECHILD);

  /* A caller has to say which states it wants to hear about. */
  r = sys6(SYS_waitid, P_ALL, 0, (long) si, WNOHANG, 0, 0);
  if (r != -EINVAL) fail("waitid naming no state", r, -EINVAL);

  put("waitid ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
