/* freestanding: reboot(POWER_OFF) ends the guest.
 *
 * The half reboottest cannot check, because a test that verified it would have
 * nothing left to report with. Checked from the outside instead: this writes
 * nothing before the call and "not reached" after it, so run.sh asserting an
 * empty output and a zero exit is asserting that the guest stopped where it
 * was told to.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_reboot 142

void _start(void)
{
  sys6(SYS_reboot, (long)(int)0xfee1dead, 672274793, 0x4321FEDC, 0, 0, 0);
  sys6(SYS_write, 1, (long)"not reached\n", 12, 0, 0, 0);
  sys6(SYS_exit, 3, 0,0,0,0,0);
}
