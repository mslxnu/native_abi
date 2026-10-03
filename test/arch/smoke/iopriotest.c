/* freestanding: ioprio_set for a process that is not the caller.
 *
 * Android's init lowers the disk priority of each service it starts, and the
 * service is not init - so every one of those was refused: "init: failed to set
 * pid 23 ioprio=2,2: Operation not permitted", 91 times a boot.
 *
 * Darwin has no way to name another process here; setiopolicy_np adjusts the caller
 * and takes no pid. So the request is accepted and applied to nothing, with the
 * checks Linux makes still made - which is what this covers: the pid has to exist,
 * what was asked for has to be a class and a level that exist, and the caller needs
 * the privilege Linux asks for. The order matters as much as the answers: a caller
 * probing the range must not have EPERM hide an EINVAL.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_kill 129
#define SYS_ioprio_set 30
#define SYS_ioprio_get 31
#define SYS_setuid 146
#define SYS_nanosleep 101
#define SYS_exit_group 94
#define SIGCHLD 17
#define SIGKILL 9
#define EPERM 1
#define ESRCH 3
#define EINVAL 22
#define CLASS_RT   1
#define CLASS_BE   2
#define CLASS_IDLE 3
#define SHIFT 13
#define PRIO(c,l) (((c) << SHIFT) | (l))

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++; put("  FAIL "); put(what); put(": got "); putd(got);
  put(", want "); putd(expect); put("\n"); }

struct ts { long s, ns; };
static void nap(long ms){ struct ts t = { ms/1000, (ms%1000)*1000000 };
  sys6(SYS_nanosleep, (long)&t, 0, 0,0,0,0); }

void _start(void)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { for (;;) nap(200); }
  if (kid < 0) { put("clone FAIL\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }
  nap(200);

  /* The caller is root here, which is what init is. */
  want("set a child's io priority", sys6(SYS_ioprio_set, 1, kid, PRIO(CLASS_BE,2), 0,0,0), 0);
  want("every class is accepted",   sys6(SYS_ioprio_set, 1, kid, PRIO(CLASS_IDLE,0), 0,0,0), 0);
  want("and the realtime one",      sys6(SYS_ioprio_set, 1, kid, PRIO(CLASS_RT,4), 0,0,0), 0);
  /* Our own still goes to the host, which really can set it. */
  want("our own still works",       sys6(SYS_ioprio_set, 1, 0, PRIO(CLASS_BE,4), 0,0,0), 0);

  /* A pid that names nothing is ESRCH, not a policy set on somebody. */
  want("a pid that does not exist", sys6(SYS_ioprio_set, 1, 999999, PRIO(CLASS_BE,2), 0,0,0), -ESRCH);

  /*
   * And what was asked for is checked before who asked, so these stay EINVAL for
   * an unprivileged caller too - the case that found the ordering.
   */
  want("a class that does not exist", sys6(SYS_ioprio_set, 1, kid, PRIO(9,2), 0,0,0), -EINVAL);
  want("a level that does not exist", sys6(SYS_ioprio_set, 1, kid, PRIO(CLASS_BE,9), 0,0,0), -EINVAL);
  want("a `which` that does not exist", sys6(SYS_ioprio_set, 9, kid, PRIO(CLASS_BE,2), 0,0,0), -EINVAL);

  /* Asking about another process is still declined rather than answered with an
   * invented number: nabi records nothing about somebody else's io priority. */
  want("ioprio_get on another process", sys6(SYS_ioprio_get, 1, kid, 0,0,0,0), -EPERM);
  if (sys6(SYS_ioprio_get, 1, 0, 0,0,0,0) < 0)
    want("ioprio_get on ourselves", -1, 0);

  /*
   * Unprivileged, the same requests are refused as Linux refuses them - and the
   * malformed ones still say so rather than being hidden behind the refusal.
   */
  if (sys6(SYS_setuid, 1000, 0,0,0,0,0) == 0) {
    want("unprivileged, a child is refused",
         sys6(SYS_ioprio_set, 1, kid, PRIO(CLASS_BE,2), 0,0,0), -EPERM);
    want("unprivileged, a bad class is still EINVAL",
         sys6(SYS_ioprio_set, 1, kid, PRIO(9,2), 0,0,0), -EINVAL);
    want("unprivileged, our own is still ours",
         sys6(SYS_ioprio_set, 1, 0, PRIO(CLASS_BE,4), 0,0,0), 0);
  }

  sys6(SYS_kill, kid, SIGKILL, 0,0,0,0);
  long st = 0;
  sys6(SYS_wait4, kid, (long) &st, 0, 0, 0, 0);

  put(fails == 0 ? "ioprio ok\n" : "ioprio failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
