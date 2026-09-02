/* freestanding: the /proc files that describe the machine rather than a process.
 *
 * These were mSL/ProcFS's, and what it answered them with was the host Mac's.
 * /proc/filesystems listed apfs, devfs, procfs and ext2fs - which names nothing
 * a Linux guest can mount and omits everything it can, while Android looks for
 * ext4 there before it will use a partition. /proc/cmdline was the *macOS
 * kernel's* boot-args, "-arm64e_preview_abi kext-dev-mode=1 debug=0x144
 * keepsyms=1", handed to Android's init as the Linux command line it parses
 * androidboot.* out of.
 *
 * That is the failure mode the sysvipc files had and the one a fallback cannot
 * rescue: the file exists, it opens, it parses, and what it says is about the
 * wrong machine.
 *
 * /proc/kmsg is the sharper case, because it was not merely wrong. It is the
 * same log /dev/kmsg reads - both names have always been the one log on Linux -
 * and the difference is that a read at the end of it waits rather than
 * reporting end of file. The host's said end of file, forever, while poll kept
 * reporting the descriptor readable, so logd spun on it for the life of the
 * boot: a core spent saying there is nothing to say. So the check below is that
 * an exhausted kmsg is EAGAIN and never zero.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_newfstatat 79
#define SYS_ppoll 73
#define SYS_clock_gettime 113
#define SYS_epoll_create1 20
#define SYS_epoll_ctl 21
#define SYS_epoll_pwait 22
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_NONBLOCK 04000
#define EAGAIN 11
#define POLLIN 1
struct pollfd { int fd; short events, revents; };
struct timespec { long sec, nsec; };
struct epoll_event { unsigned int events; unsigned long long data; } __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static int has(const char *hay, long n, const char *needle){
  for (long i = 0; i < n; i++) {
    long j = 0;
    while (needle[j] && i + j < n && hay[i+j] == needle[j]) j++;
    if (!needle[j]) return 1;
  }
  return 0;
}

static char buf[8192];

static long slurp(const char *path, int flags)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, flags, 0, 0, 0);
  if (fd < 0) return fd;
  long n = sys6(SYS_read, fd, (long) buf, sizeof buf - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n >= 0) buf[n] = 0;
  return n;
}

void _start(void)
{
  /* /proc/filesystems names what this guest can mount, and nothing else. */
  long n = slurp("/proc/filesystems", O_RDONLY);
  want("/proc/filesystems opens and reads", n > 0, 1);
  if (n > 0) {
    want("  lists ext4, which Android looks for", has(buf, n, "\text4\n"), 1);
    want("  lists tmpfs as nodev", has(buf, n, "nodev\ttmpfs\n"), 1);
    want("  lists proc as nodev", has(buf, n, "nodev\tproc\n"), 1);
    want("  lists binderfs", has(buf, n, "binderfs"), 1);
    /* The host's own list, which is the bug this file had. */
    want("  says nothing about apfs", has(buf, n, "apfs"), 0);
    want("  says nothing about devfs", has(buf, n, "devfs"), 0);
  }

  /*
   * /proc/cmdline is a line, and it is the guest's - which here is an empty
   * one, there being no kernel to have been given arguments. What it must not
   * be is the host's boot-args.
   */
  n = slurp("/proc/cmdline", O_RDONLY);
  want("/proc/cmdline opens", n >= 0, 1);
  if (n > 0)
    want("  is not the host's boot-args", has(buf, n, "kext-dev-mode"), 0);

  n = slurp("/proc/bootconfig", O_RDONLY);
  want("/proc/bootconfig opens", n >= 0, 1);
  if (n > 0)
    want("  is not the host's boot-args either", has(buf, n, "kext-dev-mode"), 0);

  /*
   * The kernel log. Read non-blocking, because the point of it is that a
   * blocking read at the end waits - so a test that asked to wait would be
   * testing by hanging.
   */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/kmsg", O_RDONLY|O_NONBLOCK, 0,0,0);
  want("/proc/kmsg opens", fd >= 0, 1);
  if (fd >= 0) {
    /* Drain whatever the boot has already said. */
    long r = 0;
    for (int i = 0; i < 4096; i++) {
      r = sys6(SYS_read, fd, (long) buf, sizeof buf, 0, 0, 0);
      if (r <= 0) break;
    }
    /*
     * And at the end of it: not end of file. Zero here is what made logd spin,
     * because a reader that is told the log ended has nothing to wait for and
     * asks again immediately, for ever.
     */
    want("  an exhausted kmsg is EAGAIN, not end of file", r, -EAGAIN);

    /*
     * And poll has to agree with it. The log lives in a file, so the host calls
     * the descriptor readable whether or not a record is waiting - and a reader
     * told that reads, is given nothing, and asks again. Answering EAGAIN alone
     * only moves the spin: ppoll said ready and the read said EAGAIN, over and
     * over, which is where logd went next.
     */
    struct timespec now = { 0, 0 };
    struct pollfd pfd = { (int) fd, POLLIN, 0 };
    long pr = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0);
    want("  an exhausted kmsg does not poll readable", pr, 0);

    /* epoll has the opposite failing on the same descriptor - kqueue raises no
     * read event for a regular file - so it is asked too. */
    /*
     * And a wait on it has to wait. Reporting the descriptor unready is only
     * half the answer: if the call then returns zero straight away, a caller
     * that asked to block reads that as "look again" and asks immediately, for
     * ever - which is the same spin arrived at from the other side. So this
     * asks for a third of a second and checks that it took one.
     */
    struct timespec t0, t1;
    sys6(SYS_clock_gettime, 1 /* MONOTONIC */, (long) &t0, 0,0,0,0);
    struct timespec wait_for = { 0, 300000000L };
    pfd.revents = 0;
    long wr = sys6(SYS_ppoll, (long) &pfd, 1, (long) &wait_for, 0, 0, 0);
    sys6(SYS_clock_gettime, 1, (long) &t1, 0,0,0,0);
    long ms = (t1.sec - t0.sec) * 1000 + (t1.nsec - t0.nsec) / 1000000;
    want("  a bounded wait on an empty kmsg returns nothing ready", wr, 0);
    want("  and actually waits for it", ms >= 250, 1);

    long ep = sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
    if (ep >= 0) {
      struct epoll_event ev = { POLLIN, 0 };
      sys6(SYS_epoll_ctl, ep, 1 /* ADD */, fd, (long) &ev, 0, 0);
      struct epoll_event out[2];
      want("  and epoll does not report it ready either",
           sys6(SYS_epoll_pwait, ep, (long) out, 2, 0, 0, 0), 0);
      sys6(SYS_close, ep, 0,0,0,0,0);
    }
    sys6(SYS_close, fd, 0,0,0,0,0);
  }

  /* The modes Linux gives them, since something looking before it opens has to
   * be answered here too rather than falling through to the host. */
  unsigned char st[128];
  for (int i = 0; i < 128; i++) st[i] = 0;
  want("stat /proc/filesystems",
       sys6(SYS_newfstatat, AT_FDCWD, (long) "/proc/filesystems", (long) st, 0, 0, 0), 0);
  unsigned mode = (unsigned) st[16] | ((unsigned) st[17] << 8);
  want("  and it is r--r--r--", mode & 07777, 0444);

  put(fails == 0 ? "procsys ok\n" : "procsys failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
