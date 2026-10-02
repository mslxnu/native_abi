/* freestanding: TIOCGPTPEER hands back the slave, and it is a working pty.
 *
 * glibc has reached for TIOCGPTPEER first since 2.24, falling back to ptsname()
 * plus open("/dev/pts/<n>") only if it fails. Unimplemented, it came back EPERM
 * and the fallback was taken - and that path is checked against the guest's own
 * credentials, while a Darwin slave is granted to the *host* user. So a guest
 * running as anyone but the host uid was refused a device this process already
 * owned, and every terminal emulator died on it: weston-terminal reported just
 * "failed to fork and create pty (Permission denied)".
 *
 * Asserted on the ioctl rather than on the fallback deliberately, so the test
 * does not depend on what uid it runs as: before the fix this returned EPERM for
 * root too.
 *
 * SIGALRM bounds it, because a pty that never answers would hang the suite.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_setitimer 103
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_NOCTTY 0400
#define TIOCGPTPEER 0x5441
#define TIOCSPTLCK  0x40045431
#define ITIMER_REAL 0

struct tv { long sec, usec; };
struct itv { struct tv interval, value; };

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
  struct itv guard = { { 0, 0 }, { 5, 0 } };
  sys6(SYS_setitimer, ITIMER_REAL, (long)&guard, 0, 0, 0, 0);

  long m = sys6(SYS_openat, AT_FDCWD, (long) "/dev/ptmx", O_RDWR, 0, 0, 0);
  want("open /dev/ptmx", m >= 0, 1);
  if (m < 0) { put("ptypeer failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  /* unlockpt, which is also where the slave gets granted. */
  int unlock = 0;
  want("TIOCSPTLCK", sys6(SYS_ioctl, m, TIOCSPTLCK, (long)&unlock, 0,0,0), 0);

  /*
   * The call under test. It returns the new descriptor, so anything negative is
   * the bug - EPERM was what an unimplemented one gave.
   */
  long s = sys6(SYS_ioctl, m, TIOCGPTPEER, O_RDWR | O_NOCTTY, 0, 0, 0);
  want("TIOCGPTPEER returns a descriptor", s >= 0, 1);

  if (s >= 0) {
    /* And it is really the other end: what goes into the master comes out of
     * the slave. A descriptor that is merely open proves less than this. */
    /* "x\n", not "x": the line discipline starts in canonical mode, so a read
     * on the slave blocks until a line is complete. Writing a bare character
     * hangs here rather than failing, which is its own small lesson. */
    char out[2] = { 'x', '\n' }; char in = 0;
    want("write to master", sys6(SYS_write, m, (long)out, 2, 0,0,0), 2);
    long r = sys6(SYS_read, s, (long)&in, 1, 0,0,0);
    want("read from slave", r, 1);
    want("byte survives the pty", in == 'x', 1);
    sys6(SYS_close, s, 0,0,0,0,0);
  }

  sys6(SYS_close, m, 0,0,0,0,0);
  put(fails == 0 ? "ptypeer ok\n" : "ptypeer failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
