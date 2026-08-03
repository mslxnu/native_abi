/* freestanding: getpriority returns 20 - nice, not nice.
 *
 * Linux's getpriority syscall deliberately does not return the nice value. It
 * returns 20 - nice, so the result is 1..40 and can never be confused with a
 * negative errno - and glibc's wrapper converts it back. Darwin's
 * getpriority(3) returns the nice value itself, and handing that straight over
 * means the guest computes 20 - nice a second time.
 *
 * At the ordinary nice of 0 that reads as 20, the lowest priority there is, and
 * a guest has no way to tell. pam_limits believed it and applied it, which
 * really did drop the process to nice 20; putting it back to 0 was then a
 * *raise* in priority, which Darwin refuses to an unprivileged process. So sudo
 * stopped at "pam_open_session: Permission denied" - about a nice value, in a
 * message that mentions neither priority nor limits.
 *
 * Checked at the syscall rather than through a libc, because the encoding is
 * exactly what a libc hides.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_setpriority 140
#define SYS_getpriority 141
#define PRIO_PROCESS 0

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int n=v<0;if(n)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(n)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("prio FAIL: "); put(what); put(" "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static long getprio(void)
{ return sys6(SYS_getpriority, PRIO_PROCESS, 0, 0, 0, 0, 0); }

static long setprio(long nice)
{ return sys6(SYS_setpriority, PRIO_PROCESS, 0, nice, 0, 0, 0); }

void _start(void)
{
  /* Started at the ordinary nice of 0, so the encoded answer is 20. Reading 0
   * here is the bug: it is the nice value, unencoded. */
  long r = getprio();
  if (r == 0)
    fail("getpriority returned the nice value rather than 20 - nice;", r);
  if (r != 20)
    fail("getpriority at nice 0 should encode to 20; got", r);

  /* setpriority takes the nice value as it stands - no encoding on the way in,
   * which is the asymmetry worth pinning down. Raising it needs no privilege. */
  if ((r = setprio(10)) < 0)
    fail("setpriority(10) returned", r);
  if ((r = getprio()) != 10)
    fail("after nice 10 the encoded answer should be 10; got", r);

  if ((r = setprio(19)) < 0)
    fail("setpriority(19) returned", r);
  if ((r = getprio()) != 1)
    fail("after nice 19 the encoded answer should be 1; got", r);

  put("prio ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
