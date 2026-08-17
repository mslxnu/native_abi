/* freestanding: CLONE_CLEAR_SIGHAND.
 *
 * glibc's posix_spawn clones with CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND,
 * because between the clone and the exec the child runs in the parent's
 * address space: a handler inherited there would run on the parent's stack
 * against half-torn state. nabi refused the flag, so posix_spawn fell back to
 * a slower path and warned on every use.
 *
 * What is worth checking:
 *
 *   - a handler the parent installed is SIG_DFL in the child. Accepting the
 *     flag and doing nothing is the failure that looks identical from the
 *     parent, and it is what "implemented" would otherwise mean here.
 *   - SIG_IGN survives, because a parent that deliberately ignored a signal is
 *     saying something the child should keep - Linux resets handlers, not
 *     dispositions.
 *   - and the parent's own table is untouched, which is what separates a reset
 *     in the child from a reset full stop.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_clone       220
#define SYS_wait4       260
#define SYS_rt_sigaction 134
#define SYS_clone3      435

#define SIGCHLD 17
#define SIGUSR1 10
#define SIGUSR2 12
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#define CLONE_SIGHAND 0x00000800
#define CLONE_VM      0x00000100
#define CLONE_FS      0x00000200
#define CLONE_FILES   0x00000400
#define CLONE_SYSVSEM 0x00040000
#define CLONE_THREAD  0x00010000
#define EINVAL 22
#define SIG_DFL 0
#define SIG_IGN 1

struct lsigaction { unsigned long handler; unsigned long flags;
                    unsigned long restorer; unsigned long mask; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("clearsig FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

struct l_clone_args {
  unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal;
  unsigned long long stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

static void handler(int s) { (void) s; }

static unsigned long get_handler(int sig)
{
  struct lsigaction old;
  old.handler = 0xdead;
  if (sys6(SYS_rt_sigaction, sig, 0, (long) &old, 8, 0, 0) != 0)
    fail("rt_sigaction query", sig, 0);
  return old.handler;
}

void _start(void)
{
  long r;
  struct lsigaction sa;

  /* A real handler on SIGUSR1, and SIG_IGN on SIGUSR2. */
  sa.handler = (unsigned long) handler; sa.flags = 0x04000000 /* SA_RESTORER-ish */;
  sa.restorer = (unsigned long) handler; sa.mask = 0;
  if ((r = sys6(SYS_rt_sigaction, SIGUSR1, (long) &sa, 0, 8, 0, 0)) != 0)
    fail("installing a SIGUSR1 handler", r, 0);
  sa.handler = SIG_IGN;
  if ((r = sys6(SYS_rt_sigaction, SIGUSR2, (long) &sa, 0, 8, 0, 0)) != 0)
    fail("ignoring SIGUSR2", r, 0);

  if (get_handler(SIGUSR1) != (unsigned long) handler)
    fail("the parent's handler did not take", (long) get_handler(SIGUSR1), 1);

  long child = sys6(SYS_clone, SIGCHLD | CLONE_CLEAR_SIGHAND, 0, 0, 0, 0, 0);
  if (child < 0)
    fail("clone with CLONE_CLEAR_SIGHAND", child, 0);
  if (child == 0) {
    /* 21: handler reset. 22: it survived, which is the flag being ignored.
     * 23: SIG_IGN was reset, which Linux does not do. */
    if (get_handler(SIGUSR1) != SIG_DFL) sys6(SYS_exit, 22, 0,0,0,0,0);
    if (get_handler(SIGUSR2) != SIG_IGN) sys6(SYS_exit, 23, 0,0,0,0,0);
    sys6(SYS_exit, 21, 0,0,0,0,0);
  }

  int st = 0, code;
  if ((r = sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0)) != child)
    fail("wait4", r, child);
  code = (st >> 8) & 0xff;
  if (code == 22) fail("the child kept the parent's handler", 22, 21);
  if (code == 23) fail("the child reset a SIG_IGN disposition", 23, 21);
  if (code != 21) fail("the child", code, 21);

  /* The parent's own table is untouched. */
  if (get_handler(SIGUSR1) != (unsigned long) handler)
    fail("the parent's handler was reset too", (long) get_handler(SIGUSR1), 1);

  /* And again through clone3, which is how glibc actually asks: posix_spawn
   * uses clone3 with CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND. The flag is bit
   * 32, so a clone3 that narrowed flags to 32 bits would drop it silently and
   * legacy clone alone would not notice. */
  struct l_clone_args ca;
  for (unsigned i = 0; i < sizeof ca; i++) ((char *) &ca)[i] = 0;
  ca.flags = CLONE_CLEAR_SIGHAND;
  ca.exit_signal = SIGCHLD;
  child = sys6(SYS_clone3, (long) &ca, sizeof ca, 0, 0, 0, 0);
  if (child < 0)
    fail("clone3 with CLONE_CLEAR_SIGHAND", child, 0);
  if (child == 0) {
    if (get_handler(SIGUSR1) != SIG_DFL) sys6(SYS_exit, 22, 0,0,0,0,0);
    if (get_handler(SIGUSR2) != SIG_IGN) sys6(SYS_exit, 23, 0,0,0,0,0);
    sys6(SYS_exit, 21, 0,0,0,0,0);
  }
  st = 0;
  if ((r = sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0)) != child)
    fail("wait4 after clone3", r, child);
  code = (st >> 8) & 0xff;
  if (code == 22) fail("the clone3 child kept the parent's handler", 22, 21);
  if (code == 23) fail("the clone3 child reset a SIG_IGN disposition", 23, 21);
  if (code != 21) fail("the clone3 child", code, 21);

  /* The two flags contradict each other - one says share the table, the other
   * says reset the copy - and Linux refuses the pair rather than picking. */
  for (unsigned i = 0; i < sizeof ca; i++) ((char *) &ca)[i] = 0;
  /* CLONE_SIGHAND is only accepted here alongside the rest of the thread set,
   * so the thread set is what has to be asked for - otherwise the refusal
   * under test is indistinguishable from the generic one for a flag nabi does
   * not implement, and the check would pass whether or not it exists. */
  ca.flags = CLONE_CLEAR_SIGHAND | CLONE_THREAD | CLONE_VM | CLONE_FS |
             CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM;
  r = sys6(SYS_clone3, (long) &ca, sizeof ca, 0, 0, 0, 0);
  if (r == 0) sys6(SYS_exit, 24, 0,0,0,0,0);   /* a child got made: worse than wrong */
  if (r != -EINVAL)
    fail("CLONE_CLEAR_SIGHAND with CLONE_SIGHAND", r, -EINVAL);

  put("clearsig ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
