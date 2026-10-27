/* freestanding: asking about your own priority is not ESRCH.
 *
 * The neighbour priotest.c covers getpriority's 20 - nice encoding; this one is
 * about which process `who` names.
 *
 * getpriority's `who` was handed to Darwin untranslated, so a guest inside a
 * pid namespace - which is every Android guest - asking about itself asked
 * about a host process that does not exist. getpriority(PRIO_PROCESS, 59)
 * answered ESRCH to the process whose own pid is 59. ART asks four times during
 * zygote's startup.
 *
 * Three spellings of "me" have to agree: 0, getpid(), and gettid() for the
 * leader - and on Linux PRIO_PROCESS takes a thread id, so a real thread of
 * this process counts too. The namespace is what makes this worth testing, so
 * the suite runs it under one as well.
 *
 * WHICH ASSERTION DOES THE WORK: not the ESRCH one. Under --pid1 the guest's
 * pid is 1, and the host has a pid 1 - launchd - so an untranslated
 * getpriority(PRIO_PROCESS, 1) succeeds with somebody else's nice value rather
 * than failing, and every "is it ESRCH" check passes while nothing is right.
 * The zygote case had pid 59, which happened not to exist on the host. What
 * catches the bug here is the setpriority round trip at the end: the self case
 * was recognised only by the host pid, so a guest naming its own namespace pid
 * never matched it and the value it asked for was remembered for nobody. That
 * assertion fails on the unfixed build; the ESRCH ones do not.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_gettid 178
#define SYS_getpriority 141
#define SYS_setpriority 140
#define PRIO_PROCESS 0
#define ESRCH 3

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static void puthex(unsigned long v)
{
  char b[19]; b[0]='0'; b[1]='x';
  for (int i = 0; i < 16; i++) {
    unsigned d = (v >> ((15 - i) * 4)) & 0xf;
    b[2+i] = d < 10 ? '0'+d : 'a'+d-10;
  }
  b[18] = 0;
  put(b);
}

static void fail(const char *what, unsigned long v)
{
  put("FAIL "); put(what); put(" "); puthex(v); put("\n");
  sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

/* Linux returns 20 - nice, so 1..40 and never an error value. */
static long prio_of(long who)
{
  return sys6(SYS_getpriority, PRIO_PROCESS, who, 0, 0, 0, 0);
}

void _start(void)
{
  long pid = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  long tid = sys6(SYS_gettid, 0, 0, 0, 0, 0, 0);

  long by_zero = prio_of(0);
  if (by_zero < 1 || by_zero > 40)
    fail("getpriority(0) is not a 20-nice value", (unsigned long) by_zero);

  long by_pid = prio_of(pid);
  if (by_pid == -ESRCH)
    fail("getpriority on our own pid said ESRCH, pid", (unsigned long) pid);
  if (by_pid != by_zero) {
    put("by 0 "); puthex((unsigned long) by_zero);
    put(" by pid "); puthex((unsigned long) by_pid); put("\n");
    fail("getpriority(0) and getpriority(getpid()) disagree", (unsigned long) pid);
  }

  /* The leader's tid is its pid, but ask by the number gettid gave anyway -
   * that is the spelling a threaded runtime uses. */
  long by_tid = prio_of(tid);
  if (by_tid != by_zero)
    fail("getpriority(gettid()) disagrees", (unsigned long) by_tid);

  /* A pid that is certainly not in this namespace is still ESRCH, so the
   * translation has not become "everything is me". */
  long bogus = prio_of(0x3fffffff);
  if (bogus != -ESRCH)
    fail("a pid in no namespace was not ESRCH", (unsigned long) bogus);

  /*
   * And setpriority on ourselves, by pid, is reported back by getpriority. The
   * self case used to be recognised only by the host pid, so a guest naming
   * its own namespace pid never matched it and the value it asked for was
   * remembered for nobody.
   */
  long r = sys6(SYS_setpriority, PRIO_PROCESS, pid, 5, 0, 0, 0);
  if (r != 0)
    fail("setpriority on our own pid", (unsigned long) r);
  long after = prio_of(pid);
  if (after != 20 - 5)
    fail("the nice we set did not come back", (unsigned long) after);
  if (prio_of(0) != after)
    fail("getpriority(0) disagrees after the set", (unsigned long) prio_of(0));

  put("ok prioself\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
