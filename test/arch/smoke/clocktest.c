/* freestanding: the clocks and descriptor flags an interactive shell asks for.
 *
 * Both of these used to kill the guest rather than answer it. clock_gettime
 * panicked on any clock not in a short list - and bash asks for
 * CLOCK_REALTIME_COARSE, which is an ordinary clock that simply was not listed -
 * while fcntl(F_GETFL) asserted that every Darwin flag had a Linux counterpart,
 * which is a fact about the host, not about the guest.
 *
 * The coarse clocks are the same clocks read more cheaply, so they must return
 * plausible times rather than merely not crash. An unknown clock must be
 * refused with EINVAL, not fatally. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit  93
#define SYS_fcntl 25
#define SYS_clock_gettime 113
#define F_GETFL 3
struct ts { long sec; long nsec; };
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int ok = 1;

static void check_clock(int id, const char *name)
{
  struct ts t = { 0, 0 };
  long r = sys6(SYS_clock_gettime, id, (long)&t, 0,0,0,0);
  if (r < 0 || t.sec <= 0) { put("clock FAIL: "); put(name); put("\n"); ok = 0; }
}

void _start(void){
  check_clock(0, "REALTIME");
  check_clock(1, "MONOTONIC");
  check_clock(4, "MONOTONIC_RAW");
  check_clock(5, "REALTIME_COARSE");   /* what bash asks for */
  check_clock(6, "MONOTONIC_COARSE");
  check_clock(7, "BOOTTIME");

  /* an unknown clock is refused, not fatal */
  struct ts t;
  if (sys6(SYS_clock_gettime, 99, (long)&t, 0,0,0,0) >= 0) {
    put("bogus clock accepted\n"); ok = 0;
  }

  /* F_GETFL on stdin must answer rather than assert */
  if (sys6(SYS_fcntl, 0, F_GETFL, 0, 0,0,0) < 0) { put("F_GETFL FAIL\n"); ok = 0; }

  if (ok) put("clocks ok\n");
  sys6(SYS_exit, ok ? 0 : 1, 0,0,0,0,0);
}
