/* freestanding: does mprotect actually take effect?
 *
 * mmap a writable page, write to it, then mprotect it read-only and write
 * again. The second write must trap. That is a real test of two things at once:
 * the stage-1 descriptors carrying the new permission, and the translation
 * noticing - a guest TLBI does not invalidate HVF's combined stage-1+2 entries,
 * so without an explicit flush the guest keeps running on the old permissions
 * and the tightening silently does nothing.
 *
 * The handler restores write permission and returns, so the faulting store
 * retries and completes; that is also how we get to report a result. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_rt_sigaction 134
#define PROT_READ 1
#define PROT_WRITE 2
#define SIGSEGV 11
#define PAGE (16*1024)

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static volatile long caught = 0;
static volatile long page_addr = 0;

static void handler(int sig)
{
  caught = 1;
  /* let the faulting store succeed on retry */
  sys6(SYS_mprotect, page_addr, PAGE, PROT_READ|PROT_WRITE, 0, 0, 0);
}

void _start(void)
{
  long p = sys6(SYS_mmap, 0, PAGE, PROT_READ|PROT_WRITE, 0x22, -1, 0);
  if (p < 0) { put("mmap FAIL\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
  page_addr = p;

  *(volatile long *)p = 0x1234;                 /* writable: fine */
  if (*(volatile long *)p != 0x1234) { put("write FAIL\n"); sys6(SYS_exit,2,0,0,0,0,0); }

  long act[4] = { (long)handler, 0, 0, 0 };
  sys6(SYS_rt_sigaction, SIGSEGV, (long)act, 0, 8, 0, 0);

  if (sys6(SYS_mprotect, p, PAGE, PROT_READ, 0, 0, 0) < 0) {
    put("mprotect FAIL\n"); sys6(SYS_exit, 3, 0,0,0,0,0);
  }

  if (*(volatile long *)p != 0x1234) { put("read-after-RO FAIL\n"); sys6(SYS_exit,4,0,0,0,0,0); }

  *(volatile long *)p = 0x5678;                 /* must trap */

  if (caught && *(volatile long *)p == 0x5678) put("mprotect ok\n");
  else if (!caught)                            put("mprotect NOT ENFORCED\n");
  else                                         put("retry FAIL\n");
  sys6(SYS_exit, (caught && *(volatile long *)p == 0x5678) ? 0 : 5, 0,0,0,0,0);
}
