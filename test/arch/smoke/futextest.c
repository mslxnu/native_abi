/* freestanding: the futex operations glibc's locking primitives rely on.
 *
 * Four separate bugs lived here, all silent, and between them they produced a
 * guest that would occasionally hang forever partway through a package install
 * - one thread spinning at a full core, another asleep on a wake that had
 * already been sent.
 *
 *   - FUTEX_WAIT's timeout is relative, but it was copied into the deadline as
 *     though it were absolute. A wait "until three seconds after the epoch"
 *     returns immediately, so a guest that meant to sleep spun instead.
 *   - FUTEX_WAIT returned Darwin's EWOULDBLOCK (35) where the guest expects
 *     Linux's EAGAIN (11), which on Linux is EDEADLK - not a value any caller
 *     handles.
 *   - FUTEX_WAIT_BITSET did not compare the word at all. It is the operation
 *     glibc actually uses for pthread_cond_wait and sem_wait, and without the
 *     compare a wake arriving between the guest's read and the syscall is lost.
 *   - A timed-out waiter was freed while still linked into the wait list, so
 *     the next wake walked freed memory.
 *
 * Timing is checked rather than assumed: "the wait returned" is true both when
 * it slept correctly and when it did not sleep at all, and the second is the
 * bug. Elapsed time is read with clock_gettime around the call.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_futex 98
#define SYS_clock_gettime 113
#define CLOCK_MONOTONIC 1

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_BITSET_ANY 0xffffffffu
#define EAGAIN 11

struct ts { long sec, nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("futex FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static long now_ms(void)
{
  struct ts t;
  sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long) &t, 0, 0, 0, 0);
  return t.sec * 1000 + t.nsec / 1000000;
}

void _start(void)
{
  static volatile int word __attribute__((aligned(4))) = 1;
  struct ts t;
  long r, ms;

  /* A mismatched value must not block, and must say EAGAIN. Anything else and
   * the caller's retry loop does not recognise the answer. */
  r = sys6(SYS_futex, (long) &word, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 999, 0, 0, 0);
  if (r != -EAGAIN) fail("FUTEX_WAIT on a stale value should be -EAGAIN", r);

  /* Same for the bitset form, which had no compare at all. */
  r = sys6(SYS_futex, (long) &word, FUTEX_WAIT_BITSET|FUTEX_PRIVATE_FLAG, 999, 0, 0,
           FUTEX_BITSET_ANY);
  if (r != -EAGAIN) fail("FUTEX_WAIT_BITSET on a stale value should be -EAGAIN", r);

  /* A matching value with a relative timeout must actually sleep for about
   * that long. Returning promptly is the spin that burned a core. */
  t.sec = 0; t.nsec = 300000000;        /* 300ms */
  ms = now_ms();
  r = sys6(SYS_futex, (long) &word, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 1, (long) &t, 0, 0);
  ms = now_ms() - ms;
  if (ms < 200) {
    put("futex FAIL: a 300ms FUTEX_WAIT returned after "); putd(ms);
    put("ms - the timeout is being read as absolute\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }
  if (ms > 3000) fail("a 300ms FUTEX_WAIT slept far too long (ms)", ms);

  /* Waking an address nobody waits on is zero woken, not an error - and after
   * the timeout above, the wait list must not still be holding the entry that
   * was freed when it timed out. This is where a use-after-free showed up. */
  for (int i = 0; i < 64; i++) {
    t.sec = 0; t.nsec = 1000000;        /* 1ms, so it times out promptly */
    sys6(SYS_futex, (long) &word, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 1, (long) &t, 0, 0);
    r = sys6(SYS_futex, (long) &word, FUTEX_WAKE|FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
    if (r != 0) fail("FUTEX_WAKE found a waiter that had already timed out", r);
  }

  put("futex ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
