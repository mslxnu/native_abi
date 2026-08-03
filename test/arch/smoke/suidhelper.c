/* freestanding: reports the effective uid it was started with.
 *
 * The other half of suidtest. Exec'd by it after dropping to an ordinary user,
 * so what it prints is whether the set-user-ID bit was honoured.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_geteuid 175

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}put(b+i+1);}

void _start(void)
{
  long euid = sys6(SYS_geteuid, 0,0,0,0,0,0);
  if (euid == 0) {
    put("suid ok\n");
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  put("suid FAIL: set-user-ID did not elevate; euid "); putd(euid); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}
