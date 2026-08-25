/* freestanding: setpriority answered with the guest's credentials.
 *
 * Raising a process's priority - a negative nice - needs CAP_SYS_NICE on
 * Linux. The guest that asks may well have it: Android's init is root and
 * holds it. The account nabi runs as does not, so the host refuses a request
 * the guest was entitled to make, and the refusal is about nabi rather than
 * about the guest.
 *
 * init sets the zygote's priority before exec'ing it and treats the refusal as
 * fatal - "cannot set attribute for zygote: setpriority failed: Permission
 * denied" - so the whole framework never started over a nice value.
 *
 * The value is remembered rather than applied, and that gap is the point of
 * this comment: the guest's scheduling request has no effect here, and only
 * the answer to "what did I ask for" is truthful. Nothing nabi can do would
 * honour it, and failing is worse without being more honest.
 *
 * What is checked:
 *
 *   - a privileged guest may raise its priority, and reads back what it set.
 *   - lowering it still goes to the host, which takes it - so the ordinary
 *     path is not replaced by the remembered one.
 *   - a guest with neither root nor CAP_SYS_NICE is refused, which is the half
 *     that must not be given away: the answer is the guest's credentials, not
 *     a blanket yes.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_setpriority 140
#define SYS_getpriority 141
#define SYS_setuid 146
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define SIGCHLD 17
#define PRIO_PROCESS 0
#define EPERM 1

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static long setnice(int n){ return sys6(SYS_setpriority, PRIO_PROCESS, 0, n, 0,0,0); }
/* Linux returns 20 - nice, so that the result can never look like an error. */
static long getnice(void){ return 20 - sys6(SYS_getpriority, PRIO_PROCESS, 0, 0,0,0,0); }

void _start(void)
{
  /* Root may raise it, and reads back what it asked for. */
  want("raise the priority as root", setnice(-10), 0);
  want("and it reads back", getnice(), -10);

  /* Lowering is something the host will take, so the ordinary path still runs
   * and the answer still agrees. */
  want("lower it again", setnice(5), 0);
  want("and that reads back too", getnice(), 5);

  /* Somebody with neither root nor CAP_SYS_NICE is refused. */
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    if (sys6(SYS_setuid, 1000, 0, 0, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 2, 0,0,0,0,0);
    /* -20 is a raise from anywhere, so the host refuses it and so must we. */
    sys6(SYS_exit_group, setnice(-20) == -EPERM ? 0 : 3, 0,0,0,0,0);
  }
  want("fork", kid > 0, 1);
  if (kid > 0) {
    long status = 0;
    sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
    want("an unprivileged guest is still refused", (status >> 8) & 0xff, 0);
  }

  put(fails == 0 ? "nice ok\n" : "nice failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
