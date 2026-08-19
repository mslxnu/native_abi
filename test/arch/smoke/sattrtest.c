/* freestanding: sched_getattr and sched_setattr.
 *
 * sched_setattr is the modern interface for changing scheduling policy: it
 * replaces the older sched_setscheduler / sched_setparam pair and adds
 * SCHED_DEADLINE, whose three timing parameters have no older call.  What
 * matters in emulation:
 *
 *   - the size field versions the structure: too small is EINVAL, too large
 *     is accepted (the caller is newer);
 *   - normal policies (OTHER, BATCH, IDLE) are accepted silently — the
 *     thread is already SCHED_OTHER and stays there;
 *   - real-time policies (FIFO, RR) are refused with EPERM, the same way
 *     Linux refuses an unprivileged caller;
 *   - DEADLINE is refused with EINVAL because it needs kernel support;
 *   - priority range is checked before privilege, so probing the range does
 *     not have EPERM hide an EINVAL;
 *   - SCHED_FLAG_RESET_ON_FORK is accepted.
 *
 * sched_getattr reports the task's scheduling attributes.  The answer is
 * always the same: SCHED_OTHER, no flags, nice 0, priority 0, and zero
 * timing parameters — consistent with every other scheduler call.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write            64
#define SYS_exit             93
#define SYS_sched_setattr    274
#define SYS_sched_getattr    275

#define SCHED_OTHER  0
#define SCHED_FIFO   1
#define SCHED_RR     2
#define SCHED_BATCH  3
#define SCHED_IDLE   5
#define SCHED_DEADLINE 6
#define SCHED_RESET_ON_FORK 0x40000000
#define SCHED_FLAG_RESET_ON_FORK 0x01

#define EPERM  1
#define ESRCH  3
#define EINVAL 22

/* The sched_attr layout: 56 bytes for v1. */
struct sched_attr {
  unsigned int  size;
  unsigned int  sched_policy;
  unsigned long sched_flags;
  int           sched_nice;
  unsigned int  sched_priority;
  unsigned long sched_runtime;
  unsigned long sched_deadline;
  unsigned long sched_period;
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("sattr FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void want(const char *w, long got, long expect)
{ if (got != expect) fail(w, got, expect); }

static void attr_init(struct sched_attr *a)
{
  a->size           = sizeof(struct sched_attr);
  a->sched_policy   = 0;
  a->sched_flags    = 0;
  a->sched_nice     = 0;
  a->sched_priority = 0;
  a->sched_runtime  = 0;
  a->sched_deadline = 0;
  a->sched_period   = 0;
}

void _start(void)
{
  struct sched_attr a;
  long r;

  /* ------------------------------------------------------------------ */
  /* sched_getattr: the baseline answer.                                */
  /* ------------------------------------------------------------------ */

  /* (1) Default: SCHED_OTHER, priority 0, nice 0, no flags, no timing. */
  attr_init(&a);
  r = sys6(SYS_sched_getattr, 0, (long) &a, 0, 0, 0, 0);
  if (r != sizeof(struct sched_attr))
    fail("getattr return size", r, (long) sizeof(struct sched_attr));
  if (a.sched_policy != SCHED_OTHER)
    fail("getattr policy", a.sched_policy, SCHED_OTHER);
  if (a.sched_priority != 0)
    fail("getattr priority", a.sched_priority, 0);
  if (a.sched_nice != 0)
    fail("getattr nice", a.sched_nice, 0);
  if (a.sched_flags != 0)
    fail("getattr flags", (long) a.sched_flags, 0);

  /* (2) NULL attr pointer: EINVAL. */
  r = sys6(SYS_sched_getattr, 0, 0, 0, 0, 0, 0);
  if (r != -EINVAL)
    fail("getattr NULL", r, -EINVAL);

  /* (3) Bogus pid: ESRCH. */
  attr_init(&a);
  r = sys6(SYS_sched_getattr, 0x7ffffff, (long) &a, 0, 0, 0, 0);
  if (r != -ESRCH)
    fail("getattr bogus pid", r, -ESRCH);

  /* ------------------------------------------------------------------ */
  /* sched_setattr: normal policies.                                    */
  /* ------------------------------------------------------------------ */

  /* (4) SCHED_OTHER with priority 0: always succeeds. */
  attr_init(&a);
  a.sched_policy = SCHED_OTHER;
  want("setattr OTHER", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), 0);

  /* (5) SCHED_BATCH with priority 0: succeeds. */
  attr_init(&a);
  a.sched_policy = SCHED_BATCH;
  want("setattr BATCH", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), 0);

  /* (6) SCHED_IDLE with priority 0: succeeds. */
  attr_init(&a);
  a.sched_policy = SCHED_IDLE;
  want("setattr IDLE", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), 0);

  /* (7) SCHED_OTHER with priority 5: EINVAL (OTHER only has priority 0). */
  attr_init(&a);
  a.sched_policy   = SCHED_OTHER;
  a.sched_priority = 5;
  want("setattr OTHER prio 5", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* ------------------------------------------------------------------ */
  /* sched_setattr: real-time policies — EPERM.                         */
  /* ------------------------------------------------------------------ */

  /* (8) SCHED_FIFO: priority in range, but no privilege. */
  attr_init(&a);
  a.sched_policy   = SCHED_FIFO;
  a.sched_priority = 50;
  want("setattr FIFO", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EPERM);

  /* (9) SCHED_RR: same refusal. */
  attr_init(&a);
  a.sched_policy   = SCHED_RR;
  a.sched_priority = 50;
  want("setattr RR", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EPERM);

  /* (10) FIFO with out-of-range priority: EINVAL (checked before privilege). */
  attr_init(&a);
  a.sched_policy   = SCHED_FIFO;
  a.sched_priority = 4000;
  want("setattr FIFO prio 4000", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* (11) FIFO with priority 0: EINVAL (below RT_PRIO_MIN). */
  attr_init(&a);
  a.sched_policy   = SCHED_FIFO;
  a.sched_priority = 0;
  want("setattr FIFO prio 0", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* ------------------------------------------------------------------ */
  /* sched_setattr: DEADLINE and unknown policies.                      */
  /* ------------------------------------------------------------------ */

  /* (12) SCHED_DEADLINE: not supported, EINVAL. */
  attr_init(&a);
  a.sched_policy = SCHED_DEADLINE;
  want("setattr DEADLINE", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* (13) Unknown policy: EINVAL. */
  attr_init(&a);
  a.sched_policy = 99;
  want("setattr unknown", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* ------------------------------------------------------------------ */
  /* sched_setattr: size validation.                                    */
  /* ------------------------------------------------------------------ */

  /* (14) Size too small (36 bytes < minimum 40): EINVAL. */
  attr_init(&a);
  a.size = 36;
  a.sched_policy = SCHED_OTHER;
  want("setattr size 36", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), -EINVAL);

  /* (15) Size exactly at the minimum (40 bytes = through sched_priority):
   * succeeds for SCHED_OTHER. The struct is on the stack and already has
   * the right layout, so we just set the size field. */
  attr_init(&a);
  a.size = 40;
  a.sched_policy = SCHED_OTHER;
  want("setattr size 40", sys6(SYS_sched_setattr, 0, (long) &a, 0, 0, 0, 0), 0);

  /* (16) NULL attr pointer: EINVAL. */
  r = sys6(SYS_sched_setattr, 0, 0, 0, 0, 0, 0);
  if (r != -EINVAL)
    fail("setattr NULL", r, -EINVAL);

  /* ------------------------------------------------------------------ */
  /* sched_setattr: SCHED_FLAG_RESET_ON_FORK.                          */
  /* ------------------------------------------------------------------ */

  /* (17) SCHED_OTHER with RESET_ON_FORK flag: succeeds. */
  attr_init(&a);
  a.sched_policy = SCHED_OTHER;
  want("setattr OTHER|RESET_ON_FORK",
       sys6(SYS_sched_setattr, 0, (long) &a, SCHED_FLAG_RESET_ON_FORK, 0, 0, 0), 0);

  /* (18) SCHED_FIFO with RESET_ON_FORK flag: still EPERM. */
  attr_init(&a);
  a.sched_policy   = SCHED_FIFO;
  a.sched_priority = 50;
  want("setattr FIFO|RESET_ON_FORK",
       sys6(SYS_sched_setattr, 0, (long) &a, SCHED_FLAG_RESET_ON_FORK, 0, 0, 0), -EPERM);

  /* ------------------------------------------------------------------ */
  /* Consistency: set then get, the answer is unchanged.                 */
  /* ------------------------------------------------------------------ */

  /* (19) After all the refusals, still SCHED_OTHER. */
  attr_init(&a);
  r = sys6(SYS_sched_getattr, 0, (long) &a, 0, 0, 0, 0);
  if (r != sizeof(struct sched_attr))
    fail("getattr return after refusals", r, (long) sizeof(struct sched_attr));
  if (a.sched_policy != SCHED_OTHER)
    fail("policy after refusals", a.sched_policy, SCHED_OTHER);

  /* (20) Bogus pid on setattr: ESRCH. */
  attr_init(&a);
  a.sched_policy = SCHED_OTHER;
  r = sys6(SYS_sched_setattr, 0x7ffffff, (long) &a, 0, 0, 0, 0);
  if (r != -ESRCH)
    fail("setattr bogus pid", r, -ESRCH);

  put("sattr ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
