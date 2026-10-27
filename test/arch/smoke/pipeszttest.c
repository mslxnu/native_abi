/* freestanding: F_SETPIPE_SZ and F_GETPIPE_SZ, which Darwin has no fcntl for.
 *
 * They fell through to the unknown-command EINVAL, and that is where bionic's
 * crash handler died: its dump thread makes a pipe, asks for a buffer big
 * enough for a tombstone, and treats a failure as fatal - it logged and called
 * exit_group(1). So a crashing Android process produced no tombstone and the
 * fatal signal it was handling was never re-raised.
 *
 * What is checked is that the two agree with each other and with the pipe: a
 * size that comes back has to be a size the pipe will really take, so the test
 * fills it. A number alone would pass on an implementation that invents one.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_fcntl 25
#define SYS_openat 56
#define F_SETFL 4
#define F_SETPIPE_SZ 1031
#define F_GETPIPE_SZ 1032
#define O_NONBLOCK 0x800
#define AT_FDCWD -100
#define EINVAL 22

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static void puthex(unsigned long v)
{
  char b[19]; b[0]='0'; b[1]='x';
  for (int i = 0; i < 16; i++) {
    unsigned d = (v >> ((15 - i) * 4)) & 0xf;
    b[2+i] = d < 10 ? '0'+d : 'a'+d-10;
  }
  b[18] = 0;
  put(b);
}

static void fail(const char *what, unsigned long v)
{
  put("FAIL "); put(what); put(" "); puthex(v); put("\n");
  sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

static int fds[2];
static char buf[4096];

void _start(void)
{
  if (sys6(SYS_pipe2, (long) fds, 0, 0, 0, 0, 0) != 0)
    fail("pipe2", 0);

  long got = sys6(SYS_fcntl, fds[1], F_GETPIPE_SZ, 0, 0, 0, 0);
  if (got <= 0)
    fail("F_GETPIPE_SZ", (unsigned long) got);

  /* A request that fits comes back page-rounded, as Linux reports it. */
  long small = sys6(SYS_fcntl, fds[1], F_SETPIPE_SZ, 4748, 0, 0, 0);
  if (small != 8192)
    fail("F_SETPIPE_SZ(4748) was not rounded to a page", (unsigned long) small);

  /* A request past the capacity is answered with the capacity, not refused -
   * that refusal is what killed debuggerd. */
  long big = sys6(SYS_fcntl, fds[1], F_SETPIPE_SZ, 4 << 20, 0, 0, 0);
  if (big <= 0)
    fail("F_SETPIPE_SZ(4MiB) was refused", (unsigned long) big);
  if (big != got) {
    put("set "); puthex((unsigned long) big);
    put(" get "); puthex((unsigned long) got); put("\n");
    fail("the two commands disagree about the capacity", (unsigned long) big);
  }

  /*
   * And the number means something: the pipe takes that many bytes before it
   * would block. Non-blocking so a wrong answer fails the test instead of
   * hanging it.
   */
  if (sys6(SYS_fcntl, fds[1], F_SETFL, O_NONBLOCK, 0, 0, 0) < 0)
    fail("F_SETFL O_NONBLOCK", 0);
  long total = 0;
  for (;;) {
    long n = sys6(SYS_write, fds[1], (long) buf, sizeof buf, 0, 0, 0);
    if (n <= 0)
      break;
    total += n;
    if (total > got + (long) sizeof buf)
      break;
  }
  if (total != got) {
    put("reported "); puthex((unsigned long) got);
    put(" accepted "); puthex((unsigned long) total); put("\n");
    fail("the pipe does not hold what was reported", (unsigned long) total);
  }

  /* Anything that is not a pipe is EINVAL, which is Linux's answer too. */
  long dev = sys6(SYS_openat, AT_FDCWD, (long) "/dev/null", 0, 0, 0, 0);
  if (dev < 0)
    fail("open /dev/null", (unsigned long) dev);
  long bad = sys6(SYS_fcntl, dev, F_GETPIPE_SZ, 0, 0, 0, 0);
  if (bad != -EINVAL)
    fail("F_GETPIPE_SZ on a non-pipe was not EINVAL", (unsigned long) bad);

  put("ok pipesz\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
