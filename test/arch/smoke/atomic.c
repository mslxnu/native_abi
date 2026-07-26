/* freestanding: load/store-exclusive and an LSE atomic on normal guest memory.
 * Guards SCTLR_EL1.C/.I being enabled at pt_enable: with the data cache off the
 * CPU treats all memory as Non-cacheable regardless of MAIR, and exclusives and
 * LSE atomics are unsupported there - the guest's first LDXR/STXR takes a data
 * abort with DFSC 0x35 and spins forever. Every real libc locks, so this is the
 * difference between "runs" and "hangs on startup". See PORTING-arm64.md 3.5. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit  93
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static long var = 5;

static long excl_inc(long *p){
  long v; int st;
  asm volatile("1: ldxr %0, [%2]\n"
               "   add %0, %0, #1\n"
               "   stxr %w1, %0, [%2]\n"
               "   cbnz %w1, 1b\n"
               : "=&r"(v), "=&r"(st) : "r"(p) : "memory");
  return v;
}

void _start(void){
  int ok = 1;
  if (excl_inc(&var) != 6) { put("ldxr/stxr FAIL\n"); ok = 0; }
  long s = 10;
  asm volatile("mov x9, #3\n staddl x9, [%0]\n" :: "r"(&s) : "x9","memory");
  if (s != 13) { put("lse FAIL\n"); ok = 0; }
  if (ok) put("atomics ok\n");
  sys6(SYS_exit, ok ? 0 : 1, 0,0,0,0,0);
}
