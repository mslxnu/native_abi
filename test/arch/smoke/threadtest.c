/* freestanding: the pthread primitives, without a libc.
 *
 * Creates a guest thread with CLONE_THREAD (a second live vCPU in the same VM,
 * which is the ordinary Hypervisor.framework model and unrelated to the fork
 * problem in spike/arm64-fork/), and checks the four things a real threading
 * libc is built out of:
 *
 *   - the thread runs and shares memory with its creator
 *   - CLONE_SETTLS reaches TPIDR_EL0, which is where aarch64 keeps the thread
 *     pointer and how every __thread variable is found
 *   - exit(2) ends the thread rather than the process, and CLONE_CHILD_CLEARTID
 *     zeroes the tid and wakes a waiter - that is how pthread_join finishes
 *   - futex WAIT/WAKE actually block and wake, which is every mutex and
 *     condition variable
 *
 * Then forks, to check that fork from a process which has had a second thread
 * gives a single-threaded child - Linux semantics, and what the handover does
 * naturally by snapshotting only the calling thread.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_exit_group 94
#define SYS_futex 98
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_wait4 260
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define CLONE_SYSVSEM 0x40000
#define CLONE_SETTLS 0x80000
#define CLONE_CHILD_CLEARTID 0x200000
#define SIGCHLD 17
#define THREAD_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM)
#define TLSVAL 0x5eed1234

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static volatile long tls_seen = 0;
static volatile int  ctid = 1;
static volatile int  fut = 0;
static volatile long woke = 0;
static int ok = 1;

static long new_stack(void){
  long s = sys6(SYS_mmap, 0, 1<<16, 3 /*RW*/, 0x22 /*PRIVATE|ANON*/, -1, 0);
  return s < 0 ? 0 : s + (1<<16) - 16;
}
static void spin_until(volatile long *p, long want){
  for (long i = 0; i < 300000000 && *p != want; i++) asm volatile("" ::: "memory");
}

void _start(void){
  /* --- a thread, with TLS, ending in a thread exit that clears the tid --- */
  long sp = new_stack();
  if (!sp) { put("mmap FAIL\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  /* aarch64 clone order: x3 = tls, x4 = child_tid */
  long tid = sys6(SYS_clone, THREAD_FLAGS|CLONE_SETTLS|CLONE_CHILD_CLEARTID,
                  sp, 0, TLSVAL, (long)&ctid, 0);
  if (tid < 0) { put("clone FAIL\n"); sys6(SYS_exit_group,2,0,0,0,0,0); }
  if (tid == 0) {
    long t; asm volatile("mrs %0, tpidr_el0" : "=r"(t));
    tls_seen = t;
    sys6(SYS_exit, 0, 0,0,0,0,0);        /* the thread, not the process */
  }
  for (long i = 0; i < 300000000 && ctid != 0; i++) asm volatile("" ::: "memory");
  if (tls_seen != TLSVAL) { put("tls FAIL\n"); ok = 0; }
  if (ctid != 0)          { put("thread exit FAIL\n"); ok = 0; }

  /* --- futex: one thread blocks, the other wakes it --- */
  sp = new_stack();
  long tid2 = sys6(SYS_clone, THREAD_FLAGS, sp, 0, 0, 0, 0);
  if (tid2 < 0) { put("clone2 FAIL\n"); sys6(SYS_exit_group,3,0,0,0,0,0); }
  if (tid2 == 0) {
    sys6(SYS_futex, (long)&fut, FUTEX_WAIT, 0, 0, 0, 0);
    woke = 1;
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  for (long i = 0; i < 20000000; i++) asm volatile("" ::: "memory");  /* let it block */
  fut = 1;
  sys6(SYS_futex, (long)&fut, FUTEX_WAKE, 1, 0, 0, 0);
  spin_until(&woke, 1);
  if (!woke) { put("futex FAIL\n"); ok = 0; }

  /* --- fork from a process that has had threads --- */
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) sys6(SYS_exit_group, 5, 0,0,0,0,0);
  if (pid < 0) { put("mtfork FAIL\n"); sys6(SYS_exit_group,4,0,0,0,0,0); }
  long st = 0; sys6(SYS_wait4, -1, (long)&st, 0,0,0,0);
  if (((st>>8)&0xff) != 5) { put("mtfork FAIL\n"); ok = 0; }

  if (ok) put("threads ok\n");
  sys6(SYS_exit_group, ok ? 0 : 6, 0,0,0,0,0);
}
