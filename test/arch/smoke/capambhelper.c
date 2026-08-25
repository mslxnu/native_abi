/* The far side of capambtest's execve: reports, as an exit status, whether
 * CAP_CHOWN arrived in the permitted and effective sets.
 *
 * 0 = in both, which is what an ambient capability is for. 1 = in neither,
 * which is what happens when nothing carries it across. 2 = in one only.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_capget 90
#define SYS_exit_group 94
#define CAPVER3 0x20080522
#define CAP_CHOWN 0

struct cap_header { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };

void _start(void)
{
  struct cap_header h = { CAPVER3, 0 };
  struct cap_data d[2] = {{0,0,0},{0,0,0}};
  if (sys6(SYS_capget, (long)&h, (long)d, 0, 0, 0, 0) != 0)
    sys6(SYS_exit_group, 3, 0,0,0,0,0);
  int p = (d[0].permitted >> CAP_CHOWN) & 1;
  int e = (d[0].effective >> CAP_CHOWN) & 1;
  sys6(SYS_exit_group, (p && e) ? 0 : (p || e) ? 2 : 1, 0,0,0,0,0);
}
