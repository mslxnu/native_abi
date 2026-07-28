/* freestanding: what NABI passes through to the host is visible, and stays
 * visible across a fork.
 *
 * /proc and /sys are the mount points mSL/FHS declares for its sibling modules
 * to mount on, and NABI passes them through to the host when something has
 * actually mounted there - their contents are synthesised per-process by a real
 * filesystem, which is not something a rootfs can hold.
 *
 * The fork half is the point. Whether a path is passed through is decided by
 * probing the host at startup, and on arm64 fork is fork + exec: the child is a
 * fresh nabi resumed from a checkpoint, which does not run the normal
 * filesystem init at all. Probe only on the first path and the failure is a
 * puzzle rather than an error - `bash -c 'cat /proc/version'` works, because
 * bash execs a lone command without forking, while adding a second command
 * makes it fork first and the identical read fails.
 *
 * Both of NABI's tests for "the host provides this" are exercised: /proc has to
 * be *mounted*, since FHS creates the mount point whether or not anything fills
 * it, while /boot only has to *exist*, being a plain directory FHS owns. They
 * are separate code, so a machine with one and not the other still covers what
 * it has.
 *
 * Skipped, not failed, when the host offers neither: this is about NABI passing
 * through what is there, not about whether the sibling modules are installed.
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
#define SYS_clone 220
#define SYS_wait4 260
#define AT_FDCWD -100
#define SIGCHLD 17

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

/* Can this path be opened at all? */
static int openable(const char *path)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
  if (fd < 0)
    return 0;
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  return 1;
}

/* Whatever the host offers, as a bitmask, so parent and child can be compared
 * rather than each judged against a guess about the machine. */
#define HAVE_PROC 1
#define HAVE_BOOT 2
static int probe(void)
{
  int have = 0;
  if (openable("/proc/version")) have |= HAVE_PROC;
  if (openable("/boot"))         have |= HAVE_BOOT;
  return have;
}

void _start(void)
{
  int parent_has = probe();
  if (parent_has == 0) {
    /* Nothing mounted on the host, or no passthrough for it. Either way there
     * is nothing here to test, and saying so beats a failure that is really
     * about the machine. */
    put("procfs skipped\n");
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
  }

  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) {
    /* The child is a fresh nabi resumed from a checkpoint. It has to have
     * worked out the passthrough for itself. */
    sys6(SYS_exit, probe() == parent_has ? 0 : 1, 0, 0, 0, 0, 0);
  }
  if (pid < 0) {
    put("procfs FAIL: fork\n");
    sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
  }

  int status = 0;
  sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
  if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) {
    put("procfs FAIL: lost across fork\n");
    sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
  }

  put("procfs ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
