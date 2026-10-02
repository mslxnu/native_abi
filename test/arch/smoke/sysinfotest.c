/* freestanding: sysinfo(2) reports an uptime, not the instant of boot.
 *
 * info.uptime was kern.boottime's seconds assigned straight across - *when* the
 * machine booted rather than how long ago. That is a Unix timestamp, about
 * 1.79e9, where a few thousand belonged, and anything formatting it as a duration
 * reads a machine up for fifty-odd years. The two are orders of magnitude apart,
 * which is what makes this cheap to check: no uptime on a real machine approaches
 * 1e9 seconds (31 years), and no timestamp since 2001 is below it.
 *
 * freeram was pages times a hardcoded 4K, which on Apple Silicon's 16K pages came
 * out at a quarter of what was free. Checked only for being sane relative to
 * totalram, because the true value is whatever this host happens to have free -
 * the factor-of-four is not visible from inside without knowing the host's page
 * size, so the fix is verified against /proc/meminfo rather than here.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_sysinfo 179
#define SYS_exit_group 94

/* The aarch64 layout: longs throughout, then the pad to 64 bytes. */
struct l_sysinfo {
  long uptime;
  unsigned long loads[3];
  unsigned long totalram, freeram, sharedram, bufferram;
  unsigned long totalswap, freeswap;
  unsigned short procs, pad;
  unsigned long totalhigh, freehigh;
  unsigned int mem_unit;
  char _f[20];
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  struct l_sysinfo si;
  for (unsigned i = 0; i < sizeof si; i++) ((char *)&si)[i] = 0;

  want("sysinfo succeeds", sys6(SYS_sysinfo, (long)&si, 0,0,0,0,0), 0);

  /* The whole point: an elapsed count, not an epoch. */
  want("uptime is positive", si.uptime > 0, 1);
  if (si.uptime >= 1000000000L) {
    fails++;
    put("  FAIL uptime looks like a Unix timestamp, not elapsed seconds: ");
    putd(si.uptime); put("\n");
  }

  want("totalram is set", si.totalram > 0, 1);
  want("freeram does not exceed totalram", si.freeram <= si.totalram, 1);

  put(fails == 0 ? "sysinfo ok\n" : "sysinfo failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
