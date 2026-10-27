/* freestanding: CLONE_CHILD_SETTID on a thread, read by the parent, in a pid namespace.
 *
 * clonetid next door covers the same flag on a fork, checked from inside the
 * child and with no namespace. This is the other shape, and it is the one
 * bionic's crash handler uses: clone a thread with CHILD_SETTID and
 * CHILD_CLEARTID, then wait in the *parent* for the word to be cleared, which
 * is how it knows the dump has finished.
 *
 * The word the child wrote has to be the tid the guest would see, and above all
 * it must not be zero - zero is what a cleared word means, so a zero here tells
 * the parent the thread it just created has already exited. That is precisely
 * what happened to debuggerd: it skipped waiting, never got a tombstone, and
 * re-raised the fatal signal while its dump thread was still closing
 * descriptors.
 *
 * In a pid namespace, because without one the translation is the identity and
 * nothing here can go wrong.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_gettid 178
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_sched_yield 124
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define CLONE_VM 0x00000100
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD 0x00010000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID 0x01000000
#define STACK 65536
/* Bounded so a failure cannot hang the suite, and small because every turn of
 * these loops is a real syscall. */
#define SPIN 200000

static volatile int tidword = -1;
static volatile long child_saw_tid = 0;
static volatile int child_may_go = 0;

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
  long st = sys6(SYS_mmap, 0, STACK, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANON, -1, 0);
  if (st <= 0)
    fail("mmap stack", (unsigned long) st);
  /* Headroom below the top: the child's first frame is written below the stack
   * pointer it is handed. */
  long sp = st + STACK - 512;

  long flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD |
               CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
  /* aarch64 order: flags, stack, parent_tid, tls, child_tid. */
  long t = sys6(SYS_clone, flags, sp, 0, 0, (long) &tidword, 0);
  if (t < 0)
    fail("clone", (unsigned long) t);

  if (t == 0) {
    /* The child. Report the tid it is given, then wait to be released. */
    child_saw_tid = sys6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    for (long i = 0; i < SPIN && !child_may_go; i++)
      sys6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);     /* this thread only */
  }

  /*
   * The number clone handed back must be the number the child calls itself.
   * They are two spellings of one tid and a caller cannot tell them apart - it
   * waits on the word using the value clone returned, so if clone answers in
   * host numbers while the word is written in namespace numbers, the wait never
   * matches and the caller cannot tell "not yet" from "already gone".
   */
  long i;
  for (i = 0; i < SPIN && child_saw_tid == 0; i++)
    sys6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
  if (child_saw_tid != 0 && t != child_saw_tid) {
    put("clone returned "); puthex((unsigned long) t);
    put(" child gettid "); puthex((unsigned long) child_saw_tid); put("\n");
    fail("clone's tid and the child's own tid disagree", (unsigned long) t);
  }

  /* Wait for the child to have run at all. */
  for (i = 0; i < SPIN && child_saw_tid == 0; i++)
    sys6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
  if (child_saw_tid == 0)
    fail("the cloned thread never ran", 0);

  /*
   * The word must be set, and set to the tid the child itself reports. Zero is
   * the failure that matters: it is indistinguishable from "already exited".
   */
  for (i = 0; i < SPIN && tidword == -1; i++)
    sys6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
  if (tidword == -1)
    fail("CHILD_SETTID never wrote the word", 0);
  if (tidword == 0)
    fail("CHILD_SETTID wrote zero, which reads as 'already exited'", 0);
  if (tidword != (int) child_saw_tid) {
    put("word "); puthex((unsigned long) tidword);
    put(" child gettid "); puthex((unsigned long) child_saw_tid); put("\n");
    fail("CHILD_SETTID wrote a different tid than the child sees", 0);
  }

  /* And CHILD_CLEARTID on exit, which is what the parent actually waits for. */
  child_may_go = 1;
  for (i = 0; i < SPIN && tidword != 0; i++)
    sys6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
  if (tidword != 0)
    fail("CHILD_CLEARTID never cleared the word on exit",
         (unsigned long) tidword);

  put("ok clonethreadtid\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
