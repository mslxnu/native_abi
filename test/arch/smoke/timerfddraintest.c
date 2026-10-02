/* freestanding: reading a *blocking* timerfd returns, it does not wedge.
 *
 * timerfd_read drains the pipe after taking the expiry count, because the count
 * is the answer and the bytes only carry readability. The drain read has to be
 * non-blocking: a timerfd created without TFD_NONBLOCK is a blocking
 * descriptor, and then the read after the last byte waits for ever - inside a
 * loop that never gets back to handing the caller its count.
 *
 * Nothing recovers from that. Every later expiry only feeds the stuck read, so
 * the timer goes on firing and the count goes on climbing while read(2) never
 * returns. Android's servicemanager arms a five second interval and reads it
 * blocking, so it hung there for the rest of the boot with every service that
 * wanted it hanging behind it - which spent a long time looking like binder
 * losing a wakeup.
 *
 * The first read that finds an expiry is enough to catch it: the blocking wait
 * takes the byte, and then the drain finds the pipe already empty.
 *
 * SIGALRM bounds the whole thing, because a test that hangs takes the suite
 * with it rather than reporting anything.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_setitimer 103
#define SYS_timerfd_create 85
#define SYS_timerfd_settime 86
#define SYS_exit_group 94
#define CLOCK_MONOTONIC 1
#define ITIMER_REAL 0

struct ts { long sec, nsec; };
struct its { struct ts interval, value; };   /* interval first, as Linux has it */
struct tv { long sec, usec; };
struct itv { struct tv interval, value; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  /* If the drain wedges, this kills us instead of hanging the suite. */
  struct itv guard = { { 0, 0 }, { 4, 0 } };
  sys6(SYS_setitimer, ITIMER_REAL, (long)&guard, 0, 0, 0, 0);

  /* flags 0: a BLOCKING timerfd, which is the whole point. */
  long fd = sys6(SYS_timerfd_create, CLOCK_MONOTONIC, 0, 0, 0, 0, 0);
  want("timerfd_create", fd >= 0, 1);
  if (fd < 0) { put("timerfddrain failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  /* 50ms, repeating - short enough that the read waits briefly, long enough
   * that the pipe is empty again by the time the drain runs. */
  struct its spec = { { 0, 50000000 }, { 0, 50000000 } };
  want("timerfd_settime", sys6(SYS_timerfd_settime, fd, 0, (long)&spec, 0, 0, 0), 0);

  /*
   * Each read must come back with a count. Before the fix the first one never
   * returned at all: the loop took the byte, found the pipe empty, and stayed
   * in the drain while the timer kept firing behind it.
   */
  for (int i = 0; i < 3; i++) {
    unsigned long long exp = 0;
    long r = sys6(SYS_read, fd, (long)&exp, sizeof exp, 0, 0, 0);
    want("read returns 8 bytes", r, (long) sizeof exp);
    want("at least one expiry", exp >= 1, 1);
    if (r != (long) sizeof exp) break;
  }

  sys6(SYS_close, fd, 0,0,0,0,0);
  put(fails == 0 ? "timerfddrain ok\n" : "timerfddrain failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
