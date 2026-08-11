/* freestanding: the rest of the futex family.
 *
 * futex() was WAIT, WAKE, the bitset pair, WAKE_OP and the PI operations. What
 * was missing is the part that moves waiters without waking them - REQUEUE and
 * CMP_REQUEUE, which is what a broadcast is built on - the non-blocking half of
 * LOCK_PI, and the futex2 syscalls a program written today reaches for.
 *
 * futex_waitv is the one worth a test of its own. It waits on several futexes
 * and returns *which* one woke, so an implementation that queued only the first,
 * or that woke correctly but reported the wrong index, would satisfy anything
 * that merely checked the call returned.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_futex            98
#define SYS_set_robust_list  99
#define SYS_get_robust_list 100
#define SYS_write            64
#define SYS_exit             93
#define SYS_exit_group       94
#define SYS_nanosleep       101
#define SYS_clock_gettime   113
#define SYS_clone           220
#define SYS_mmap            222
#define SYS_futex_waitv     449
#define SYS_futex_wake      454
#define SYS_futex_wait      455
#define SYS_futex_requeue   456

#define FUTEX_WAIT          0
#define FUTEX_WAKE          1
#define FUTEX_REQUEUE       3
#define FUTEX_CMP_REQUEUE   4
#define FUTEX_TRYLOCK_PI    8
#define FUTEX_PRIVATE     128

#define FUTEX2_SIZE_U32     0x02
#define CLOCK_MONOTONIC     1

#define CLONE_VM      0x00000100
#define CLONE_THREAD  0x00010000
#define CLONE_SIGHAND 0x00000800

#define EAGAIN 11
#define EINVAL 22

struct waitv { unsigned long long val, uaddr; unsigned flags, reserved; };
struct tspec { long tv_sec, tv_nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("futex FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit_group, 1, 0, 0, 0, 0, 0); }

/* futex2 deadlines are absolute, unlike FUTEX_WAIT's relative one - a struct
 * holding {30,0} is thirty seconds after boot, which is long gone. */
static void deadline_in(long secs, struct tspec *out)
{
  sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long) out, 0,0,0,0);
  out->tv_sec += secs;
}

static void nap(long ms)
{ struct tspec t = { 0, ms * 1000000 }; sys6(SYS_nanosleep, (long)&t, 0, 0, 0, 0, 0); }

/* Two futex words and a little state, shared with the helper thread. */
static volatile int fa, fb;
static volatile int helper_done;
static char helper_stack[65536] __attribute__((aligned(16)));

/* What the helper is asked to do next. */
static volatile int job;
#define JOB_WAKE_B_FUTEX2 1
#define JOB_WAKE_A_PLAIN  2

static void
helper(void)
{
  for (;;) {
    if (job == JOB_WAKE_B_FUTEX2) {
      nap(60);
      sys6(SYS_futex_wake, (long) &fb, ~0ULL, 1, FUTEX2_SIZE_U32, 0, 0);
      job = 0;
    } else if (job == JOB_WAKE_A_PLAIN) {
      nap(60);
      sys6(SYS_futex, (long) &fa, FUTEX_WAKE | FUTEX_PRIVATE, 1, 0, 0, 0);
      job = 0;
    } else if (helper_done) {
      sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
    }
    nap(5);
  }
}

void _start(void)
{
  long r;

  /* set/get_robust_list round-trips what was registered. */
  {
    static char head[24];
    if ((r = sys6(SYS_set_robust_list, (long) head, 24, 0, 0, 0, 0)) != 0)
      fail("set_robust_list", r, 0);
    unsigned long got = 0, len = 0;
    if ((r = sys6(SYS_get_robust_list, 0, (long) &got, (long) &len, 0, 0, 0)) != 0)
      fail("get_robust_list", r, 0);
    if (got != (unsigned long) head)
      fail("the robust list pointer that came back", (long) got, (long) head);
    if (len != 24)
      fail("the robust list length", (long) len, 24);
  }

  /* TRYLOCK_PI takes a free lock and refuses a held one, without blocking. */
  fa = 0;
  if ((r = sys6(SYS_futex, (long) &fa, FUTEX_TRYLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0)) != 0)
    fail("FUTEX_TRYLOCK_PI on a free lock", r, 0);
  if (fa == 0)
    fail("TRYLOCK_PI did not take the lock; word", fa, 1);
  if ((r = sys6(SYS_futex, (long) &fa, FUTEX_TRYLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0)) != -EAGAIN)
    fail("FUTEX_TRYLOCK_PI on a held lock", r, -EAGAIN);

  /* CMP_REQUEUE checks the word before it moves anything. */
  fa = 7;
  if ((r = sys6(SYS_futex, (long) &fa, FUTEX_CMP_REQUEUE | FUTEX_PRIVATE, 0, 1, (long) &fb, 9)) != -EAGAIN)
    fail("CMP_REQUEUE with a stale compare", r, -EAGAIN);
  if ((r = sys6(SYS_futex, (long) &fa, FUTEX_CMP_REQUEUE | FUTEX_PRIVATE, 0, 1, (long) &fb, 7)) != 0)
    fail("CMP_REQUEUE with nobody waiting", r, 0);
  /* REQUEUE has no compare, so it does not care what the word says. */
  if ((r = sys6(SYS_futex, (long) &fa, FUTEX_REQUEUE | FUTEX_PRIVATE, 0, 1, (long) &fb, 0)) != 0)
    fail("REQUEUE with nobody waiting", r, 0);

  /* The futex2 flags are checked rather than assumed. */
  if ((r = sys6(SYS_futex_wake, (long) &fa, ~0ULL, 1, 0 /* size u8 */, 0, 0)) != -EINVAL)
    fail("futex_wake with a width that is not served", r, -EINVAL);

  /* A helper thread, so there is somebody to do the waking. */
  {
    long tid = sys6(SYS_clone, CLONE_VM | CLONE_THREAD | CLONE_SIGHAND, (long) (helper_stack + sizeof helper_stack), 0, 0, 0, 0);
    if (tid < 0)
      fail("clone for the helper", tid, 0);
    if (tid == 0)
      helper();
  }

  /* futex_wait and futex_wake, the pair a program written today uses. */
  fb = 1;
  job = JOB_WAKE_B_FUTEX2;
  {
    struct tspec deadline; deadline_in(30, &deadline);
    r = sys6(SYS_futex_wait, (long) &fb, 1, ~0ULL, FUTEX2_SIZE_U32, (long) &deadline, CLOCK_MONOTONIC);
    if (r != 0)
      fail("futex_wait was not woken by futex_wake", r, 0);
  }

  /*
   * futex_waitv over two futexes, woken on the second. The index it returns is
   * the point: 1 here, and an implementation that watched only the first would
   * never return at all.
   */
  fa = 1; fb = 1;
  job = JOB_WAKE_B_FUTEX2;
  {
    struct waitv w[2];
    w[0].val = 1; w[0].uaddr = (unsigned long long) (long) &fa;
    w[0].flags = FUTEX2_SIZE_U32; w[0].reserved = 0;
    w[1].val = 1; w[1].uaddr = (unsigned long long) (long) &fb;
    w[1].flags = FUTEX2_SIZE_U32; w[1].reserved = 0;
    struct tspec deadline; deadline_in(30, &deadline);
    r = sys6(SYS_futex_waitv, (long) w, 2, 0, (long) &deadline, CLOCK_MONOTONIC, 0);
    if (r != 1)
      fail("futex_waitv reported the wrong futex", r, 1);
  }

  /* A word that already differs is not something to wait for. */
  {
    struct waitv w[1];
    fa = 5;
    w[0].val = 1; w[0].uaddr = (unsigned long long) (long) &fa;
    w[0].flags = FUTEX2_SIZE_U32; w[0].reserved = 0;
    r = sys6(SYS_futex_waitv, (long) w, 1, 0, 0, CLOCK_MONOTONIC, 0);
    if (r != -EAGAIN)
      fail("futex_waitv on a word that already changed", r, -EAGAIN);
  }

  helper_done = 1;
  nap(60);
  put("futex ok\n");
  sys6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
}
