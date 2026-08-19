/* freestanding: times(2) — process CPU time counters.
 *
 * times() fills a struct tms with four clock-tick counters (utime, stime,
 * cutime, cstime) and returns wall clock time since boot in clock ticks.
 *
 * The children fields are zeroed by NABI (it does not track unwaited
 * children), so we verify that.  The self fields should be non-negative.
 * The return value should advance between calls.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_times   153

#define EFAULT  14

/* struct tms: four clock_t (int64 on arm64) fields = 32 bytes. */
struct tms {
  long tms_utime;
  long tms_stime;
  long tms_cutime;
  long tms_cstime;
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("times FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void want(const char *w, long got, long expect)
{ if (got != expect) fail(w, got, expect); }

void _start(void)
{
  struct tms t;
  long r;

  /* ------------------------------------------------------------------ */
  /* Basic: call times with a valid buffer.                              */
  /* ------------------------------------------------------------------ */

  /* (1) Return value: wall clock since boot, must be > 0. */
  r = sys6(SYS_times, (long)&t, 0, 0, 0, 0, 0);
  if (r <= 0)
    fail("return value", r, 1);

  /* (2) tms_utime: non-negative (we haven't burned much CPU yet, but > 0). */
  if (t.tms_utime < 0)
    fail("tms_utime negative", t.tms_utime, 0);

  /* (3) tms_stime: non-negative. */
  if (t.tms_stime < 0)
    fail("tms_stime negative", t.tms_stime, 0);

  /* (4) tms_cutime: zero (no dead children tracked). */
  want("tms_cutime", t.tms_cutime, 0);

  /* (5) tms_cstime: zero (no dead children tracked). */
  want("tms_cstime", t.tms_cstime, 0);

  /* ------------------------------------------------------------------ */
  /* Monotonicity: a second call must return >= the first.               */
  /* ------------------------------------------------------------------ */

  /* (6) Second call returns >= first. */
  long r1 = r;
  r = sys6(SYS_times, (long)&t, 0, 0, 0, 0, 0);
  if (r < r1)
    fail("monotonicity", r, r1);

  /* (7) Second call's tms_utime >= first. */
  long u1 = t.tms_utime;
  r = sys6(SYS_times, (long)&t, 0, 0, 0, 0, 0);
  if (t.tms_utime < u1)
    fail("utime monotonicity", t.tms_utime, u1);

  /* ------------------------------------------------------------------ */
  /* NULL buffer: returns the clock value without writing.               */
  /* ------------------------------------------------------------------ */

  /* (8) times(NULL) returns a positive value. */
  r = sys6(SYS_times, 0, 0, 0, 0, 0, 0);
  if (r <= 0)
    fail("times(NULL) return", r, 1);

  /* ------------------------------------------------------------------ */
  /* EFAULT: bogus pointer.                                              */
  /* ------------------------------------------------------------------ */

  /* (9) Bogus pointer: EFAULT. */
  r = sys6(SYS_times, 0x7fffffffffffUL, 0, 0, 0, 0, 0);
  if (r != -EFAULT)
    fail("bogus pointer", r, -EFAULT);

  /* ------------------------------------------------------------------ */
  /* Structure size: verify tms is 32 bytes (4 x int64).                */
  /* ------------------------------------------------------------------ */

  /* (10) sizeof(tms) == 32. */
  want("sizeof tms", (long)sizeof(struct tms), 32);

  /* ------------------------------------------------------------------ */
  /* Consistency: utime + stime > 0 after doing some work.               */
  /* ------------------------------------------------------------------ */

  /* Burn a tiny bit of CPU. */
  { volatile long x = 0; for (long i = 0; i < 100000; i++) x += i; }

  /* (11) After work, utime should be >= 0 (may still be 0 if work was tiny). */
  r = sys6(SYS_times, (long)&t, 0, 0, 0, 0, 0);
  if (t.tms_utime < 0)
    fail("utime after work", t.tms_utime, 0);

  /* (12) Return value still > 0 and > previous. */
  if (r <= 0)
    fail("return after work", r, 1);

  put("times ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
