/* freestanding: a futex without FUTEX_PRIVATE_FLAG is not therefore shared.
 *
 * The flag's absence was taken for the presence of sharing: every call that
 * did not pass it was treated as a futex in shared memory, whatever the memory
 * actually was. That path is bounded on purpose - nabi cannot be woken across
 * processes, so it sleeps a little and reports a wake so the caller re-reads
 * the word - and it was being applied to ordinary private memory.
 *
 * Everything libc does passes the flag, which is why this went unseen. What
 * does not is code written against the raw syscall: bionic's crash handler
 * waits on a word in its own memory for its dump thread to finish, was told it
 * had been woken twenty milliseconds later, and re-raised the fatal signal
 * while the dump thread was still forking. No tombstone, from a futex nobody
 * shared.
 *
 * So: on private memory a wait with nobody to wake it must time out and not
 * report a wake, and a real wake must still arrive. On shared memory the
 * bounded wait is deliberate and must stay - what is checked there is only that
 * it returns rather than hangs, because a cross-process wake has to become a
 * delay rather than a dead guest.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_exit_group 94
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_futex 98
#define SYS_sched_yield 124
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define CLONE_VM 0x100
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128
#define ETIMEDOUT 110
#define STACK 65536

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static void putd(const char *t, long v)
{
  char b[40]; int i = 0; put(t); put("=");
  if (v < 0) { put("-"); v = -v; }
  char q[24]; int j = 0; if (!v) q[j++] = '0';
  while (v) { q[j++] = '0' + (char)(v % 10); v /= 10; }
  while (j) b[i++] = q[--j]; b[i++] = '\n'; b[i] = 0; put(b);
}

static void fail(const char *what, long v) { putd(what, v); put("FAIL\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }

struct ts { long sec, nsec; };
static volatile int privword = 7;
static volatile int wakeword = 0;
static volatile int waiter_ret = -999;
static volatile int waiter_in = 0;

void _start(void)
{
  struct ts one = { 1, 0 };

  /*
   * Private memory, no flag, nobody waking: must be ETIMEDOUT every time.
   * Several rounds, because the bug reported a wake after a fixed interval and
   * one round could be mistaken for a real one.
   */
  for (int i = 0; i < 4; i++) {
    long r = sys6(SYS_futex, (long)&privword, FUTEX_WAIT, 7, (long)&one, 0, 0);
    if (r == 0)
      fail("round reported a wake with nobody to wake it", i);
    if (r != -ETIMEDOUT)
      fail("round returned something other than ETIMEDOUT", r);
  }

  /* The same with the flag, which always took the other path. */
  long r = sys6(SYS_futex, (long)&privword, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7,
                (long)&one, 0, 0);
  if (r != -ETIMEDOUT)
    fail("FUTEX_WAIT_PRIVATE did not time out", r);

  /* And a real wake still arrives - the fix must not have made waiting deaf. */
  long st = sys6(SYS_mmap, 0, STACK, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  if (st <= 0)
    fail("mmap thread stack", st);
  long t = sys6(SYS_clone, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, st + STACK - 512, 0, 0, 0, 0);
  if (t < 0)
    fail("clone", t);
  if (t == 0) {
    struct ts ten = { 10, 0 };
    waiter_in = 1;
    waiter_ret = (int) sys6(SYS_futex, (long)&wakeword, FUTEX_WAIT, 0,
                            (long)&ten, 0, 0);
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  for (long i = 0; i < 200000 && !waiter_in; i++)
    sys6(SYS_sched_yield, 0,0,0,0,0,0);
  /* Give it time to be properly asleep, now that it really sleeps. */
  for (long i = 0; i < 20000; i++)
    sys6(SYS_sched_yield, 0,0,0,0,0,0);
  long woke = sys6(SYS_futex, (long)&wakeword, FUTEX_WAKE, 1, 0, 0, 0);
  if (woke < 1)
    fail("FUTEX_WAKE woke nobody", woke);
  for (long i = 0; i < 400000 && waiter_ret == -999; i++)
    sys6(SYS_sched_yield, 0,0,0,0,0,0);
  if (waiter_ret != 0)
    fail("the woken waiter did not report a wake", waiter_ret);

  /*
   * Shared memory keeps the bounded wait. Only that it returns is checked: the
   * interval is nabi's own and not a promise, and a hang here is the failure
   * that path exists to prevent.
   */
  long sh = sys6(SYS_mmap, 0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
  if (sh <= 0)
    fail("mmap shared", sh);
  *(volatile int *)sh = 3;
  r = sys6(SYS_futex, sh, FUTEX_WAIT, 3, (long)&one, 0, 0);
  if (r != 0 && r != -ETIMEDOUT)
    fail("a shared futex wait neither returned nor timed out", r);

  put("ok futexpriv\n");
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}
