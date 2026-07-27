/* freestanding: unmap part of a mapping, leaving live pages either side.
 *
 * A guest may unmap at 4KiB granularity, but the stage-2 mapping this is built
 * on is 16KiB, so such a range leaves live pages inside blocks it has partly
 * emptied. Those blocks cannot simply be unmapped - that would take the
 * survivors with them - and clearing the stage-1 descriptors alone is not enough
 * either, because a guest TLBI does not invalidate HVF's combined entries.
 *
 * Maps 32KiB, writes a marker in every 4KiB page, unmaps the middle, and checks
 * the pages either side still hold their markers. Then touches an unmapped page
 * and requires a fault, which is what proves the translation really went away
 * rather than merely being forgotten in a table. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit  93
#define SYS_mmap  222
#define SYS_munmap 215
#define SYS_rt_sigaction 134
#define SIGSEGV 11
#define K4 4096
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static volatile long faulted = 0;
static volatile long base = 0;
static int ok = 1;
static void handler(int s){ faulted = 1; if (ok) put("split munmap ok\n"); sys6(SYS_exit, ok ? 0 : 9, 0,0,0,0,0); }

void _start(void){
  long p = sys6(SYS_mmap, 0, 8*K4, 3, 0x22, -1, 0);
  if (p < 0) { put("mmap FAIL\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  base = p;
  for (int i = 0; i < 8; i++) *(volatile long *)(p + (long)i*K4) = 0x100 + i;

  /* unmap pages 1..4, so page 0 survives in the first 16KiB block and pages
   * 5..7 survive in the second */
  if (sys6(SYS_munmap, p + K4, 4*K4, 0,0,0,0) < 0) { put("munmap FAIL\n"); sys6(SYS_exit,2,0,0,0,0,0); }

  if (*(volatile long *)(p + 0*K4)  != 0x100) { put("survivor-low FAIL\n"); ok = 0; }
  if (*(volatile long *)(p + 5*K4)  != 0x105) { put("survivor-high FAIL\n"); ok = 0; }
  if (*(volatile long *)(p + 7*K4)  != 0x107) { put("survivor-top FAIL\n"); ok = 0; }

  long act[4] = { (long)handler, 0, 0, 0 };
  sys6(SYS_rt_sigaction, SIGSEGV, (long)act, 0, 8, 0, 0);

  /* an unmapped page must fault; the handler exits, so reaching past here is
   * itself the failure */
  (void) *(volatile long *)(p + 2*K4);
  put("unmapped page did NOT fault\n");
  sys6(SYS_exit, 3, 0,0,0,0,0);
}
