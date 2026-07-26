/* freestanding: execve /hello and let it produce the output.
 *
 * Guards the guest PC being set through ELR_EL1 rather than HV_REG_PC. When the
 * host handles a syscall the vCPU is parked in the EL1 trampoline, so HV_REG_PC
 * is the stub's own eret and the guest's PC is banked in ELR_EL1. execve sets a
 * new entry point via VREG_PC; if that wrote HV_REG_PC, the trampoline's eret
 * would discard it and return to the *old* image's address - whose mappings
 * execve just tore down - and the guest would wander off silently, no fault and
 * no syscall. See lib/vmm_arm64_exit.c. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write  64
#define SYS_exit   93
#define SYS_execve 221
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

void _start(void){
  static char *argv[] = { "/hello", 0 };
  static char *envp[] = { 0 };
  sys6(SYS_execve, (long)"/hello", (long)argv, (long)envp, 0, 0, 0);
  /* Only reached if execve failed - a successful execve never returns. */
  put("execve FAIL\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}
