/* freestanding: a process that asks to die, dies.
 *
 * tgkill was a stub returning ENOSYS, and that is much worse than a missing
 * feature: it is how glibc's abort() delivers SIGABRT to itself. A process that
 * decides to stop and cannot then does not stop - it carries on with the signal
 * never raised, holding whatever its parent is waiting on.
 *
 * That is what deadlocked apt. Its download method aborted, could not, and
 * never closed its end of the pipe; apt sat in pselect6 waiting for a greeting
 * or an EOF that were both never coming, and `apt-get update` printed nothing
 * at all and never returned. A syscall that cannot fail visibly is a syscall
 * whose absence turns an error into a hang.
 *
 * Checked from a parent, because the interesting part is not that tgkill
 * returns 0 - it is that the process actually goes away, and only wait4 can say
 * so.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_getpid 172
#define SYS_gettid 178
#define SYS_tgkill 131
#define SYS_tkill 130
#define SIGCHLD 17
#define SIGKILL 9

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("signal FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

/* Run `which` (0 = tgkill, 1 = tkill) in a child and report its wait status. */
static int died_by_signal(int which, int *sig_out)
{
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) {
    long p = sys6(SYS_getpid, 0,0,0,0,0,0);
    long t = sys6(SYS_gettid, 0,0,0,0,0,0);
    if (which == 0)
      sys6(SYS_tgkill, p, t, SIGKILL, 0, 0, 0);
    else
      sys6(SYS_tkill, t, SIGKILL, 0, 0, 0, 0);
    /* Reached only if the signal was not delivered, which is the bug. */
    sys6(SYS_exit, 42, 0,0,0,0,0);
  }
  if (pid < 0)
    fail("clone", pid);

  int status = 0;
  long r = sys6(SYS_wait4, pid, (long) &status, 0, 0, 0, 0);
  if (r < 0)
    fail("wait4", r);
  *sig_out = status & 0x7f;
  /* Exited normally rather than by signal: the low 7 bits are zero and the
   * exit code is in the next byte. 42 is this test's "the signal never
   * arrived" marker. */
  return (status & 0x7f) != 0;
}

void _start(void)
{
  int sig = 0;

  if (!died_by_signal(0, &sig))
    fail("tgkill(SIGKILL) did not kill the child; it exited with", 42);
  if (sig != SIGKILL)
    fail("tgkill killed the child with the wrong signal", sig);

  if (!died_by_signal(1, &sig))
    fail("tkill(SIGKILL) did not kill the child; it exited with", 42);
  if (sig != SIGKILL)
    fail("tkill killed the child with the wrong signal", sig);

  /* A nonsense target must be refused rather than silently swallowed. */
  long r = sys6(SYS_tgkill, 0, 0, SIGKILL, 0, 0, 0);
  if (r >= 0)
    fail("tgkill accepted a zero thread group", r);

  put("signal ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
