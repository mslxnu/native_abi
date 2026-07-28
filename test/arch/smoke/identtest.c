/* freestanding: /proc says what the guest is, not what nabi is.
 *
 * cmdline, exe and comm all describe the process from XNU's side, where it is a
 * `nabi` executing a guest - cmdline came back as `nabi --resume 5 6 …`, which
 * is not merely unhelpful but leaks how fork is implemented. NABI records the
 * guest's argv and binary at exec and answers these itself.
 *
 * Checked after a fork as well, because that is where it is hard: arm64's fork
 * is fork + exec, so the child is a fresh nabi that never saw the original
 * execve and can only know any of this if the checkpoint carried it.
 *
 * The test knows its own path because run.sh puts it at /identtest, and that is
 * what argv[0] and exe must both say.
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
#define SYS_exit 93
#define SYS_readlinkat 78
#define SYS_clone 220
#define SYS_wait4 260
#define AT_FDCWD -100
#define SIGCHLD 17

#define SELF "/identtest"

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static int eq(const char *a, const char *b)
{
  while (*a && *a == *b) { a++; b++; }
  return *a == 0 && *b == 0;
}

static int slurp(const char *path, char *buf, int cap)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
  if (fd < 0) return -1;
  long n = sys6(SYS_read, fd, (long)buf, cap - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  if (n < 0) return -1;
  buf[n] = 0;
  return (int) n;
}

/* All three, or the first that is wrong. NULL means everything matched. */
static const char *
check(void)
{
  char buf[512];

  /* cmdline is NUL-separated, so the first entry is just a C string. */
  if (slurp("/proc/self/cmdline", buf, sizeof buf) < 0) return "cmdline missing";
  if (!eq(buf, SELF)) return "cmdline";

  if (slurp("/proc/self/comm", buf, sizeof buf) < 0) return "comm missing";
  {
    int i = 0;
    while (buf[i] && buf[i] != '\n') i++;
    buf[i] = 0;
  }
  if (!eq(buf, "identtest")) return "comm";

  long n = sys6(SYS_readlinkat, AT_FDCWD, (long)"/proc/self/exe",
                (long)buf, sizeof buf - 1, 0, 0);
  if (n < 0) return "exe missing";
  buf[n] = 0;
  if (!eq(buf, SELF)) return "exe";

  return 0;
}

void _start(void)
{
  const char *bad = check();
  if (bad) { put("ident FAIL: "); put(bad); put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0)
    sys6(SYS_exit, check() == 0 ? 0 : 1, 0, 0, 0, 0, 0);
  if (pid < 0) { put("ident FAIL: fork\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  int status = 0;
  sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
  if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) {
    put("ident FAIL: lost across fork\n");
    sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
  }

  put("ident ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
