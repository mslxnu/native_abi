/* freestanding: the sched_* family, and that its answers agree with each other.
 *
 * A guest thread is an ordinary host thread and stays one. Darwin has real-time
 * scheduling only through Mach's thread_policy_set, which needs a port and a
 * privilege nabi has not got, so there is no honest way to put a guest on
 * SCHED_FIFO. What matters is that saying so is *consistent*: getscheduler has
 * to agree with what setscheduler accepted, and getparam with both. A set that
 * quietly succeeded and a get that reported something else would be worse than
 * either answer alone, because nothing would ever notice.
 *
 * The priority ranges are the exception and are checked against Linux's real
 * numbers. Asking what a policy's range is is a question about the interface,
 * not a request to be scheduled under it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_setparam         118
#define SYS_sched_setscheduler     119
#define SYS_sched_getscheduler     120
#define SYS_sched_getparam         121
#define SYS_sched_setaffinity      122
#define SYS_sched_getaffinity      123
#define SYS_sched_yield            124
#define SYS_sched_get_priority_max 125
#define SYS_sched_get_priority_min 126
#define SYS_sched_rr_get_interval  127

#define SCHED_OTHER 0
#define SCHED_FIFO  1
#define SCHED_RR    2
#define SCHED_BATCH 3
#define SCHED_IDLE  5
#define SCHED_RESET_ON_FORK 0x40000000

#define EPERM  1
#define ESRCH  3
#define EINVAL 22

struct sched_param { int sched_priority; };
struct timespec { long tv_sec, tv_nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int n=v<0;if(n)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(n)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{
  put("sched FAIL: "); put(what); put(" -> "); putd(got);
  put(", wanted "); putd(want); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}
static void want(const char *what, long got, long expect)
{ if (got != expect) fail(what, got, expect); }

void _start(void)
{
  struct sched_param p;
  long r;

  /* The ranges, which are Linux's regardless of what this host can schedule. */
  want("get_priority_max(FIFO)",  sys6(SYS_sched_get_priority_max, SCHED_FIFO,0,0,0,0,0), 99);
  want("get_priority_min(FIFO)",  sys6(SYS_sched_get_priority_min, SCHED_FIFO,0,0,0,0,0), 1);
  want("get_priority_max(RR)",    sys6(SYS_sched_get_priority_max, SCHED_RR,0,0,0,0,0), 99);
  want("get_priority_max(OTHER)", sys6(SYS_sched_get_priority_max, SCHED_OTHER,0,0,0,0,0), 0);
  want("get_priority_min(OTHER)", sys6(SYS_sched_get_priority_min, SCHED_OTHER,0,0,0,0,0), 0);
  want("get_priority_max(IDLE)",  sys6(SYS_sched_get_priority_max, SCHED_IDLE,0,0,0,0,0), 0);
  want("get_priority_max(nonsense)",
       sys6(SYS_sched_get_priority_max, 99,0,0,0,0,0), -EINVAL);

  /* What the guest is, and it is the same before and after being asked. */
  want("getscheduler(self)", sys6(SYS_sched_getscheduler, 0,0,0,0,0,0), SCHED_OTHER);

  p.sched_priority = 123;
  if ((r = sys6(SYS_sched_getparam, 0, (long) &p, 0,0,0,0)) < 0)
    fail("getparam", r, 0);
  want("getparam priority", p.sched_priority, 0);

  /* SCHED_OTHER has one priority and it is zero; anything else is EINVAL
   * rather than a silent success. */
  p.sched_priority = 0;
  want("setparam(0)", sys6(SYS_sched_setparam, 0, (long) &p, 0,0,0,0), 0);
  p.sched_priority = 5;
  want("setparam(5)", sys6(SYS_sched_setparam, 0, (long) &p, 0,0,0,0), -EINVAL);

  /* Asking for the policy it already has is granted. */
  p.sched_priority = 0;
  want("setscheduler(OTHER,0)",
       sys6(SYS_sched_setscheduler, 0, SCHED_OTHER, (long) &p, 0,0,0), 0);
  want("setscheduler(OTHER|RESET_ON_FORK,0)",
       sys6(SYS_sched_setscheduler, 0, SCHED_OTHER|SCHED_RESET_ON_FORK,
            (long) &p, 0,0,0), 0);
  want("setscheduler(BATCH,0)",
       sys6(SYS_sched_setscheduler, 0, SCHED_BATCH, (long) &p, 0,0,0), 0);

  /* Real time is refused, and refused the way Linux refuses it to somebody
   * without the privilege - which every caller already handles. */
  p.sched_priority = 50;
  want("setscheduler(FIFO,50)",
       sys6(SYS_sched_setscheduler, 0, SCHED_FIFO, (long) &p, 0,0,0), -EPERM);
  want("setscheduler(RR,50)",
       sys6(SYS_sched_setscheduler, 0, SCHED_RR, (long) &p, 0,0,0), -EPERM);

  /* An out-of-range priority is EINVAL before privilege is considered, so a
   * caller probing the range is not told the wrong thing. */
  p.sched_priority = 4000;
  want("setscheduler(FIFO,4000)",
       sys6(SYS_sched_setscheduler, 0, SCHED_FIFO, (long) &p, 0,0,0), -EINVAL);
  p.sched_priority = 0;
  want("setscheduler(nonsense)",
       sys6(SYS_sched_setscheduler, 0, 99, (long) &p, 0,0,0), -EINVAL);

  /* And after all that, unchanged. */
  want("getscheduler after the refusals",
       sys6(SYS_sched_getscheduler, 0,0,0,0,0,0), SCHED_OTHER);

  /* A pid that cannot exist. */
  want("getscheduler(bogus pid)",
       sys6(SYS_sched_getscheduler, 0x7ffffff,0,0,0,0,0), -ESRCH);

  /* Affinity: what getaffinity reports must be something setaffinity accepts,
   * or the pair contradict each other. */
  unsigned char mask[128] = {0};
  long n = sys6(SYS_sched_getaffinity, 0, sizeof mask, (long) mask, 0,0,0);
  if (n < 0)
    fail("getaffinity", n, 0);
  if (!(mask[0] & 1))
    fail("getaffinity named no cpu 0; first byte", mask[0], 1);
  want("setaffinity(what getaffinity said)",
       sys6(SYS_sched_setaffinity, 0, (long) n, (long) mask, 0,0,0), 0);

  unsigned char empty[128] = {0};
  want("setaffinity(empty mask)",
       sys6(SYS_sched_setaffinity, 0, sizeof empty, (long) empty, 0,0,0), -EINVAL);

  /* Not on SCHED_RR, so the quantum is zero - which is what Linux reports for
   * exactly that reason. */
  struct timespec ts = { 42, 42 };
  want("rr_get_interval", sys6(SYS_sched_rr_get_interval, 0, (long) &ts, 0,0,0,0), 0);
  want("rr_get_interval seconds", ts.tv_sec, 0);
  want("rr_get_interval nanoseconds", ts.tv_nsec, 0);

  want("sched_yield", sys6(SYS_sched_yield, 0,0,0,0,0,0), 0);

  put("sched ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
