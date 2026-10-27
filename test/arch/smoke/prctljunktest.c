/* freestanding: prctl's unused arguments are register junk, not a request.
 *
 * prctl is variadic, so prctl(PR_SET_DUMPABLE, 1) passes two arguments and
 * leaves x2 to x5 holding whatever was in them. nabi refused the call when any
 * of them was non-zero, which refuses a correct program: Linux's
 * PR_GET_DUMPABLE validates nothing and its PR_SET_DUMPABLE validates only the
 * value. bionic's crash handler calls both, and the trailing register held the
 * tail of a log tag, so both came back EINVAL inside the path that is supposed
 * to produce a tombstone.
 *
 * Deliberate junk is passed in every argument the option does not use. The
 * THP pair is checked too, in the other direction: Linux really does validate
 * its trailing arguments, so those must still be refused - the fix must not
 * become "nabi never checks".
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_prctl 167
#define PR_SET_PDEATHSIG 1
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42
#define EINVAL 22

/* The value bionic's crash handler happened to leave behind: the tail of a log
 * tag, which is why this was found in a tombstone that never got written. */
#define JUNK 0x2f1f64636e621f2bL
#define JUNK2 0xffffffffffffffL

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

void _start(void)
{
  /* Set, with junk in every argument after the value. */
  long r = sys6(SYS_prctl, PR_SET_DUMPABLE, 1, JUNK, JUNK2, JUNK, 0);
  if (r != 0)
    fail("PR_SET_DUMPABLE(1) with junk args", (unsigned long) r);

  /* Get, which uses no arguments at all, so all of them are junk. */
  r = sys6(SYS_prctl, PR_GET_DUMPABLE, JUNK2, JUNK, JUNK2, JUNK, 0);
  if (r != 1)
    fail("PR_GET_DUMPABLE after setting 1", (unsigned long) r);

  /* And it is really the stored value coming back, not a constant. */
  r = sys6(SYS_prctl, PR_SET_DUMPABLE, 0, JUNK, 0, JUNK, 0);
  if (r != 0)
    fail("PR_SET_DUMPABLE(0) with junk args", (unsigned long) r);
  r = sys6(SYS_prctl, PR_GET_DUMPABLE, JUNK, 0, 0, JUNK2, 0);
  if (r != 0)
    fail("PR_GET_DUMPABLE after setting 0", (unsigned long) r);

  /* The value is still validated: 2 is Linux's sysctl-only setting. */
  r = sys6(SYS_prctl, PR_SET_DUMPABLE, 2, 0, 0, 0, 0);
  if (r != -EINVAL)
    fail("PR_SET_DUMPABLE(2) was not refused", (unsigned long) r);

  /* Restore, so nothing after this runs undumpable. */
  sys6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0);

  /*
   * The other direction. Linux checks the trailing arguments of the THP pair,
   * so they must still be refused here - a fix for the options Linux does not
   * check must not turn into never checking.
   */
  r = sys6(SYS_prctl, PR_GET_THP_DISABLE, JUNK, 0, 0, 0, 0);
  if (r != -EINVAL)
    fail("PR_GET_THP_DISABLE stopped checking its arguments", (unsigned long) r);
  r = sys6(SYS_prctl, PR_SET_THP_DISABLE, 1, JUNK, 0, 0, 0);
  if (r != -EINVAL)
    fail("PR_SET_THP_DISABLE stopped checking its arguments", (unsigned long) r);

  /* And an option that validates its value still does. */
  r = sys6(SYS_prctl, PR_SET_PDEATHSIG, 1 << 20, 0, 0, 0, 0);
  if (r != -EINVAL)
    fail("PR_SET_PDEATHSIG took an impossible signal", (unsigned long) r);

  put("ok prctljunk\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
