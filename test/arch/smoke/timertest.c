/* freestanding: timerfd and POSIX timers, neither of which Darwin has.
 *
 * A timerfd exists to go in an event loop, so the check that matters is that
 * poll(2) sees it - an implementation that made read() work but left the
 * descriptor永 unreadable would satisfy a simpler test and be useless in the
 * place these are actually used. What read() returns is the second: Linux
 * answers with the *number of expirations since the last read*, not with
 * whatever made the descriptor readable, and resets the count.
 *
 * The POSIX timer half is checked through SIGEV_NONE, which is the form that is
 * polled rather than delivered - timer_gettime counting down is the whole of
 * it. A signal-delivering timer is refused for realtime signals, since nabi
 * cannot deliver those and a timer that never fires is worse than one that
 * failed to be created; that refusal is checked too.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_close            57
#define SYS_read             63
#define SYS_write            64
#define SYS_exit             93
#define SYS_nanosleep       101
#define SYS_clock_gettime   113
#define SYS_ppoll            73
#define SYS_timerfd_create   85
#define SYS_timerfd_settime  86
#define SYS_timerfd_gettime  87
#define SYS_timer_create    107
#define SYS_timer_gettime   108
#define SYS_timer_getoverrun 109
#define SYS_timer_settime   110
#define SYS_timer_delete    111

#define CLOCK_MONOTONIC 1
#define TFD_NONBLOCK 04000
#define POLLIN 1
#define SIGEV_SIGNAL 0
#define SIGEV_NONE   1
#define EAGAIN 11
#define EINVAL 22

struct tspec  { long tv_sec, tv_nsec; };
struct itspec { struct tspec it_interval, it_value; };
struct pfd    { int fd; short events, revents; };
struct sigev  { int val, padv, signo, notify, tid, pad[11]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("timer FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

void _start(void)
{
  long r;

  /* ---- timerfd ---- */
  long fd = sys6(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_NONBLOCK, 0, 0, 0, 0);
  if (fd < 0)
    fail("timerfd_create", fd, 0);

  /* Nothing has expired, so a non-blocking read says so rather than lying. */
  { unsigned long long v;
    if ((r = sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0)) != -EAGAIN)
      fail("reading a timerfd that has not fired", r, -EAGAIN); }

  /* 60ms one-shot. */
  { struct itspec s = { {0,0}, {0, 60*1000*1000} };
    if ((r = sys6(SYS_timerfd_settime, fd, 0, (long) &s, 0, 0, 0)) != 0)
      fail("timerfd_settime", r, 0); }

  /* It counts down. */
  { struct itspec g;
    if ((r = sys6(SYS_timerfd_gettime, fd, (long) &g, 0, 0, 0, 0)) != 0)
      fail("timerfd_gettime", r, 0);
    if (g.it_value.tv_sec != 0 || g.it_value.tv_nsec <= 0 ||
        g.it_value.tv_nsec > 60*1000*1000)
      fail("the time left on an armed timerfd, ns", g.it_value.tv_nsec, 60000000); }

  /*
   * poll must see it. This is the half that makes a timerfd worth having, and
   * the half a read-only implementation would fail.
   */
  { struct pfd p = { (int) fd, POLLIN, 0 };
    struct tspec to = { 5, 0 };
    r = sys6(SYS_ppoll, (long) &p, 1, (long) &to, 0, 0, 0);
    if (r != 1)
      fail("ppoll on a timerfd", r, 1);
    if (!(p.revents & POLLIN))
      fail("ppoll reported no readability", p.revents, POLLIN); }

  /* And read answers with the count, then resets it. */
  { unsigned long long v = 0;
    if ((r = sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0)) != 8)
      fail("read of an expired timerfd", r, 8);
    if (v != 1)
      fail("the number of expirations", (long) v, 1);
    if ((r = sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0)) != -EAGAIN)
      fail("the count was not reset by the read", r, -EAGAIN); }

  /* An interval timer accumulates while nobody is reading. */
  { struct itspec s = { {0, 20*1000*1000}, {0, 20*1000*1000} };
    if ((r = sys6(SYS_timerfd_settime, fd, 0, (long) &s, 0, 0, 0)) != 0)
      fail("timerfd_settime (interval)", r, 0);
    struct tspec nap = { 0, 150*1000*1000 };
    sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0);
    unsigned long long v = 0;
    if ((r = sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0)) != 8)
      fail("read of a repeating timerfd", r, 8);
    if (v < 2)
      fail("expirations counted over 150ms of a 20ms timer", (long) v, 2); }

  /* Disarming is a zero it_value, and it stops. */
  { struct itspec s = { {0,0}, {0,0} };
    if ((r = sys6(SYS_timerfd_settime, fd, 0, (long) &s, 0, 0, 0)) != 0)
      fail("disarming a timerfd", r, 0);
    unsigned long long v;
    sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0);   /* drain what had piled up */
    struct tspec nap = { 0, 80*1000*1000 };
    sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0);
    if ((r = sys6(SYS_read, fd, (long) &v, sizeof v, 0, 0, 0)) != -EAGAIN)
      fail("a disarmed timerfd fired anyway", r, -EAGAIN); }

  sys6(SYS_close, fd, 0, 0, 0, 0, 0);

  /* ---- POSIX timers ---- */

  /* A realtime signal is one nabi cannot deliver, so the timer is refused
   * rather than created and never heard from. */
  { struct sigev se; for (unsigned i=0;i<sizeof se/4;i++) ((int*)&se)[i]=0;
    se.notify = SIGEV_SIGNAL; se.signo = 34;   /* SIGRTMIN + 2 */
    int id = 0;
    if ((r = sys6(SYS_timer_create, CLOCK_MONOTONIC, (long) &se, (long) &id, 0, 0, 0)) != -EINVAL)
      fail("timer_create asking for a realtime signal", r, -EINVAL); }

  /* SIGEV_NONE is the polled form and works. */
  int id = -1;
  { struct sigev se; for (unsigned i=0;i<sizeof se/4;i++) ((int*)&se)[i]=0;
    se.notify = SIGEV_NONE;
    if ((r = sys6(SYS_timer_create, CLOCK_MONOTONIC, (long) &se, (long) &id, 0, 0, 0)) != 0)
      fail("timer_create(SIGEV_NONE)", r, 0); }

  { struct itspec s = { {0,0}, {1, 0} };
    if ((r = sys6(SYS_timer_settime, id, 0, (long) &s, 0, 0, 0)) != 0)
      fail("timer_settime", r, 0); }

  { struct itspec g;
    if ((r = sys6(SYS_timer_gettime, id, (long) &g, 0, 0, 0, 0)) != 0)
      fail("timer_gettime", r, 0);
    if (g.it_value.tv_sec != 0 || g.it_value.tv_nsec <= 0)
      fail("the time left on a one-second timer, sec", g.it_value.tv_sec, 0);
    struct tspec nap = { 0, 100*1000*1000 };
    sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0);
    struct itspec g2;
    sys6(SYS_timer_gettime, id, (long) &g2, 0, 0, 0, 0);
    if (g2.it_value.tv_nsec >= g.it_value.tv_nsec)
      fail("the timer did not count down; ns", g2.it_value.tv_nsec,
           g.it_value.tv_nsec); }

  if ((r = sys6(SYS_timer_getoverrun, id, 0, 0, 0, 0, 0)) < 0)
    fail("timer_getoverrun", r, 0);
  if ((r = sys6(SYS_timer_delete, id, 0, 0, 0, 0, 0)) != 0)
    fail("timer_delete", r, 0);
  if ((r = sys6(SYS_timer_gettime, id, (long) &id, 0, 0, 0, 0)) != -EINVAL)
    fail("using a deleted timer", r, -EINVAL);

  put("timer ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
