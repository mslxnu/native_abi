/* freestanding: a guest can allocate a pty and talk through it.
 *
 * Linux and Darwin agree on /dev/ptmx and on nothing after it. unlockpt is
 * ioctl(TIOCSPTLCK) on one side and TIOCPTYUNLK on the other, ptsname is
 * TIOCGPTN returning a number on one side and TIOCPTYGNAME returning a name on
 * the other, and the slave is /dev/pts/<n> against /dev/ttys<nnn>. Unhandled,
 * TIOCSPTLCK fell through to the default arm of darwinfs_ioctl and came back
 * EPERM, which is how apt - which runs dpkg under a pty so it can drive
 * progress output - stopped with "Unlocking the slave of master fd 27 failed".
 *
 * The number and the path are checked together on purpose: they are two halves
 * of one translation, and a TIOCGPTN that answered plausibly while the path
 * mapping was wrong would still leave every guest that wants a terminal stuck.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_ioctl 29
#define SYS_exit 93
#define AT_FDCWD -100
#define O_RDWR 2
#define O_NOCTTY 0400
/* The values a real guest sends. asm-generic/ioctls.h stops handing out bare
 * 0x54xx numbers at TIOCSWINSZ and _IOC-encodes everything from 0x30 on, so
 * these are _IOR('T',0x30,unsigned int) and _IOW('T',0x31,int). Spelled out
 * rather than taken from NABI's own header on purpose: a test that shares a
 * constant with the code under test cannot catch that constant being wrong,
 * which is exactly how the first version of this test passed while every guest
 * pty allocation still failed. */
#define TIOCGPTN   0x80045430
#define TIOCSPTLCK 0x40045431
#define TCGETS     0x5401
#define TCSETSF    0x5404
/* The termios2 family, which is what a current glibc actually sends:
 * _IOR('T', 0x2a, struct termios2) and the three setters after it. glibc 2.42
 * moved to these so a baud rate could be given by number, and a nabi that knows
 * only TCGETS answers EPERM to every terminal query a modern distribution
 * makes - so isatty() reports that nothing is a terminal, bash starts
 * non-interactive with an empty PS1, and a login shows a blank screen. */
#define TCGETS2    0x802c542a
#define TCSETS2    0x402c542b
#define TCSETSF2   0x402c542d
#define TIOCSWINSZ 0x5414
#define TIOCGWINSZ 0x5413

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;if(v==0)b[i--]='0';
  while(v>0){b[i--]='0'+(v%10);v/=10;}put(b+i+1);}
static void fail(const char *what, long rc)
{
  put("pty FAIL: "); put(what); put(" -> "); putd(-rc); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

void _start(void)
{
  long m = sys6(SYS_openat, AT_FDCWD, (long) "/dev/ptmx", O_RDWR|O_NOCTTY, 0, 0, 0);
  if (m < 0) fail("open /dev/ptmx", m);

  /* unlockpt. glibc passes a pointer to a zero and treats EINVAL as success,
   * so a guest would not notice this failing - but apt checks and stops. */
  int unlock = 0;
  long r = sys6(SYS_ioctl, m, TIOCSPTLCK, (long) &unlock, 0, 0, 0);
  if (r < 0) fail("TIOCSPTLCK", r);

  unsigned int n = 0xffffffffu;
  if ((r = sys6(SYS_ioctl, m, TIOCGPTN, (long) &n, 0, 0, 0)) < 0)
    fail("TIOCGPTN", r);
  if (n == 0xffffffffu) { put("pty FAIL: TIOCGPTN wrote nothing\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  /*
   * The master must be a terminal the moment it is unlocked, before anything
   * has opened the slave.
   *
   * On Linux a pty is a pair from the start and the termios and window size
   * belong to the pair, so this is when programs set them - apt sizes the
   * terminal it will run dpkg under before it forks. Darwin attaches no line
   * discipline until the slave has been opened at least once, and until then
   * every one of these comes back ENOTTY.
   */
  struct { unsigned short row, col, xpixel, ypixel; } ws = { 24, 80, 0, 0 };
  if ((r = sys6(SYS_ioctl, m, TIOCSWINSZ, (long) &ws, 0, 0, 0)) < 0)
    fail("TIOCSWINSZ on a fresh master", r);
  ws.row = ws.col = 0;
  if ((r = sys6(SYS_ioctl, m, TIOCGWINSZ, (long) &ws, 0, 0, 0)) < 0)
    fail("TIOCGWINSZ on a fresh master", r);
  if (ws.row != 24 || ws.col != 80) {
    put("pty FAIL: window size did not stick, got "); putd(ws.row);
    put("x"); putd(ws.col); put("\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  /* termios too, in all three set forms - TCSETSF was missing entirely, and
   * an unhandled ioctl here returns EPERM, which reads as a permission
   * problem rather than a gap. */
  char tio[64];
  if ((r = sys6(SYS_ioctl, m, TCGETS, (long) tio, 0, 0, 0)) < 0)
    fail("TCGETS on a fresh master", r);
  if ((r = sys6(SYS_ioctl, m, TCSETSF, (long) tio, 0, 0, 0)) < 0)
    fail("TCSETSF on a fresh master", r);

  /* termios2, the form a current glibc uses for the very same question. Two
   * baud-rate fields longer than the struct above, and under an _IOC-encoded
   * number rather than a bare one. */
  char tio2[64];
  if ((r = sys6(SYS_ioctl, m, TCGETS2, (long) tio2, 0, 0, 0)) < 0)
    fail("TCGETS2 on a fresh master", r);
  if ((r = sys6(SYS_ioctl, m, TCSETS2, (long) tio2, 0, 0, 0)) < 0)
    fail("TCSETS2 on a fresh master", r);
  if ((r = sys6(SYS_ioctl, m, TCSETSF2, (long) tio2, 0, 0, 0)) < 0)
    fail("TCSETSF2 on a fresh master", r);

  /* The path the guest builds from that number has to reach the slave the
   * master is actually paired with, which is the half that lives in path
   * resolution rather than in the ioctl. */
  char path[32] = "/dev/pts/";
  {
    char d[12]; int i = 0;
    unsigned int v = n;
    if (v == 0) d[i++] = '0';
    while (v) { d[i++] = (char) ('0' + v % 10); v /= 10; }
    int p = 9;
    while (i) path[p++] = d[--i];
    path[p] = 0;
  }
  long s = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDWR|O_NOCTTY, 0, 0, 0);
  if (s < 0) fail("open the slave", s);

  /* Paired, not merely both open: a write to the master has to come out of the
   * slave. Canonical mode delivers a whole line, so the newline is required. */
  static const char msg[] = "ping\n";
  if ((r = sys6(SYS_write, m, (long) msg, sizeof msg - 1, 0, 0, 0)) < 0)
    fail("write to the master", r);

  char buf[16];
  if ((r = sys6(SYS_read, s, (long) buf, sizeof buf, 0, 0, 0)) < 0)
    fail("read from the slave", r);
  if (r != 5 || buf[0] != 'p' || buf[1] != 'i' || buf[2] != 'n' ||
      buf[3] != 'g' || buf[4] != '\n') {
    put("pty FAIL: slave read back "); putd(r); put(" wrong bytes\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  sys6(SYS_close, s, 0,0,0,0,0);
  sys6(SYS_close, m, 0,0,0,0,0);
  put("pty ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
