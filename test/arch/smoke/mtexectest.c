/* execve from a multi-threaded process.
 * new image must run. The spare thread deliberately sits in a syscall-free loop,
 * which is the case that needs the vCPUs kicked. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_execve 221
#define THREAD_FLAGS (0x100|0x200|0x400|0x800|0x10000|0x40000)
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static volatile long up = 0;
void _start(void){
  long st = sys6(SYS_mmap, 0, 1<<16, 3, 0x22, -1, 0);
  if (st < 0) { put("mmap FAIL\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  long tid = sys6(SYS_clone, THREAD_FLAGS, st + (1<<16) - 16, 0, 0, 0, 0);
  if (tid < 0) { put("clone FAIL\n"); sys6(SYS_exit_group,2,0,0,0,0,0); }
  if (tid == 0) { up = 1; for (;;) asm volatile("" ::: "memory"); }  /* no syscalls */
  for (long i = 0; i < 300000000 && up == 0; i++) asm volatile("" ::: "memory");
  if (!up) { put("thread FAIL\n"); sys6(SYS_exit_group,3,0,0,0,0,0); }
  static char *argv[] = { "/hello", 0 }; static char *envp[] = { 0 };
  sys6(SYS_execve, (long)"/hello", (long)argv, (long)envp, 0,0,0);
  put("mt-execve FAIL\n");
  sys6(SYS_exit_group, 4, 0,0,0,0,0);
}
