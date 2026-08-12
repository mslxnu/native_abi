/* freestanding: close_range, epoll_pwait2, execveat, fchmodat2, adjtimex,
 * and the four that answer ENOSYS.
 *
 * A mixed batch, so what is checked is what distinguishes each from the call it
 * resembles:
 *
 *   - close_range really closes a *range*, and CLOSE_RANGE_CLOEXEC marks
 *     instead - a descriptor marked is still usable, which is the whole reason
 *     the flag exists and the thing an implementation that just closed would
 *     get wrong.
 *   - epoll_pwait2 takes a timespec, so a sub-millisecond timeout must not
 *     round down to a poll that does not wait - that is a busy loop where the
 *     caller asked to sleep.
 *   - execveat with AT_EMPTY_PATH runs a descriptor, which is fexecve.
 *   - fchmodat2 honours AT_SYMLINK_NOFOLLOW, which fchmodat never could: the
 *     mode must land on the *link* and leave its target alone.
 *   - adjtimex reads and refuses to write, because the clock it would steer is
 *     the host's and every process on the machine reads it.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_symlinkat      36
#define SYS_unlinkat       35
#define SYS_openat         56
#define SYS_close          57
#define SYS_write          64
#define SYS_read           63
#define SYS_pipe2          59
#define SYS_exit           93
#define SYS_fcntl          25
#define SYS_newfstatat     79
#define SYS_acct           89
#define SYS_clock_settime 112
#define SYS_adjtimex      171
#define SYS_add_key       217
#define SYS_clock_adjtime 266
#define SYS_execveat      281
#define SYS_bpf           280
#define SYS_epoll_create1  20
#define SYS_epoll_ctl      21
#define SYS_epoll_pwait2  441
#define SYS_close_range   436
#define SYS_fchmodat2     452
#define SYS_clock_gettime 113

#define AT_FDCWD          -100
#define AT_EMPTY_PATH   0x1000
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDONLY 0
#define O_RDWR   2
#define O_CREAT  0100
#define F_GETFD  1
#define FD_CLOEXEC 1
#define CLOSE_RANGE_CLOEXEC (1u << 2)
#define ENOSYS 38
#define EINVAL 22
#define EPERM   1
#define EBADF   9
#define POLLIN  1

#define ADJ_OFFSET 0x0001
#define ADJ_STATUS 0x0010

struct epev { unsigned events; unsigned pad; unsigned long long data; } __attribute__((packed));
struct tspec { long sec, nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("misc FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

/* struct stat's mode, at its aarch64 offset. */
#define STAT_MODE_OFF 16
static unsigned mode_at(const char *path, int flags)
{
  char st[256];
  for (int i = 0; i < 256; i++) st[i] = 0;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) st, flags, 0, 0) < 0)
    return 0;
  return (*(unsigned *)(st + STAT_MODE_OFF)) & 07777;
}

void _start(void)
{
  long r;

  /* ---- the four that cannot exist here ---- */
  if ((r = sys6(SYS_bpf, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("bpf, which has no kernel to load into", r, -ENOSYS);
  if ((r = sys6(SYS_add_key, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("add_key, which has no keyring to add to", r, -ENOSYS);
  if ((r = sys6(SYS_acct, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("acct, which has no single place every exit passes", r, -ENOSYS);

  /* ---- the clock is the host's ---- */
  { struct tspec t = { 0, 0 };
    if ((r = sys6(SYS_clock_settime, 0 /* REALTIME */, (long) &t, 0, 0, 0, 0)) != -EPERM)
      fail("setting the wall clock", r, -EPERM);
    if ((r = sys6(SYS_clock_settime, 1 /* MONOTONIC */, (long) &t, 0, 0, 0, 0)) != -EINVAL)
      fail("setting a clock that only counts forward", r, -EINVAL); }

  { char tx[256];
    for (int i = 0; i < 256; i++) tx[i] = 0;
    /* A bare read is answered. */
    if ((r = sys6(SYS_adjtimex, (long) tx, 0, 0, 0, 0, 0)) < 0)
      fail("adjtimex reading the clock's discipline", r, 0);
    /*
     * The time it reports has to be a real one rather than a zeroed struct.
     * struct timex on a 64-bit machine: modes at 0 with four bytes of padding
     * after it, then offset, freq, maxerror and esterror at 8, 16, 24 and 32,
     * status at 40 with padding, constant, precision and tolerance at 48, 56
     * and 64 - so the timeval starts at 72. Counted rather than guessed,
     * because the first guess landed on `constant` and read zero.
     */
    { long long sec = *(long long *)(tx + 72);
      if (sec < 1600000000LL)
        fail("the time adjtimex reported", (long) sec, 1600000000LL); }

    /* A write is refused, and refused before anything is applied. */
    for (int i = 0; i < 256; i++) tx[i] = 0;
    *(unsigned *) tx = ADJ_STATUS;
    if ((r = sys6(SYS_adjtimex, (long) tx, 0, 0, 0, 0, 0)) != -EPERM)
      fail("adjtimex writing the clock's discipline", r, -EPERM);
    for (int i = 0; i < 256; i++) tx[i] = 0;
    *(unsigned *) tx = ADJ_OFFSET;
    if ((r = sys6(SYS_clock_adjtime, 0, (long) tx, 0, 0, 0, 0)) != -EPERM)
      fail("clock_adjtime writing an offset", r, -EPERM);
    for (int i = 0; i < 256; i++) tx[i] = 0;
    if ((r = sys6(SYS_clock_adjtime, 1 /* MONOTONIC */, (long) tx, 0, 0, 0, 0)) != -EINVAL)
      fail("clock_adjtime on a clock with no discipline", r, -EINVAL); }

  /* ---- epoll_pwait2: a timeout finer than a millisecond ---- */
  { long ep = sys6(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
    if (ep < 0)
      fail("epoll_create1", ep, 0);
    struct epev got[2];
    struct tspec t0, t1;
    /* 20ms, expressed in nanoseconds. Nothing is registered, so this waits the
     * whole timeout - and must actually wait it. */
    struct tspec to = { 0, 20 * 1000 * 1000 };
    sys6(SYS_clock_gettime, 1, (long) &t0, 0, 0, 0, 0);
    if ((r = sys6(SYS_epoll_pwait2, ep, (long) got, 2, (long) &to, 0, 0)) != 0)
      fail("epoll_pwait2 with nothing registered", r, 0);
    sys6(SYS_clock_gettime, 1, (long) &t1, 0, 0, 0, 0);
    { long ns = (t1.sec - t0.sec) * 1000000000L + (t1.nsec - t0.nsec);
      if (ns < 10 * 1000 * 1000L)
        fail("how long epoll_pwait2 waited, in ms", ns / 1000000, 20); }

    /* A sub-millisecond timeout must round up, not down to no wait at all. */
    struct tspec tiny = { 0, 1000 };
    if ((r = sys6(SYS_epoll_pwait2, ep, (long) got, 2, (long) &tiny, 0, 0)) != 0)
      fail("epoll_pwait2 with a sub-millisecond timeout", r, 0);

    struct tspec bad = { 0, 2000000000L };
    if ((r = sys6(SYS_epoll_pwait2, ep, (long) got, 2, (long) &bad, 0, 0)) != -EINVAL)
      fail("epoll_pwait2 with a timespec that is not normalised", r, -EINVAL);
    sys6(SYS_close, ep, 0, 0, 0, 0, 0); }

  /* ---- fchmodat2 on a symlink ---- */
  { long f = sys6(SYS_openat, AT_FDCWD, (long) "/fcm-target", O_RDWR | O_CREAT, 0644, 0, 0);
    if (f < 0)
      fail("creating a file to link to", f, 0);
    sys6(SYS_close, f, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/fcm-link", 0, 0, 0, 0);
    if ((r = sys6(SYS_symlinkat, (long) "/fcm-target", AT_FDCWD, (long) "/fcm-link", 0, 0, 0)) != 0)
      fail("creating a symlink", r, 0);

    if ((r = sys6(SYS_fchmodat2, AT_FDCWD, (long) "/fcm-link", 0700, AT_SYMLINK_NOFOLLOW, 0, 0)) != 0)
      fail("fchmodat2 on the link itself", r, 0);

    /* The link changed and the target did not - which is the whole difference
     * from fchmodat, and what an implementation ignoring the flag reverses. */
    if (mode_at("/fcm-link", AT_SYMLINK_NOFOLLOW) != 0700)
      fail("the link's mode after fchmodat2",
           mode_at("/fcm-link", AT_SYMLINK_NOFOLLOW), 0700);
    if (mode_at("/fcm-target", 0) != 0644)
      fail("the target's mode, which should not have moved",
           mode_at("/fcm-target", 0), 0644);

    if ((r = sys6(SYS_fchmodat2, AT_FDCWD, (long) "/fcm-link", 0600, 1u << 20, 0, 0)) != -EINVAL)
      fail("fchmodat2 with a flag that does not exist", r, -EINVAL);

    sys6(SYS_unlinkat, AT_FDCWD, (long) "/fcm-link", 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/fcm-target", 0, 0, 0, 0); }

  /* ---- close_range ---- */
  { int a[2], b[2], c[2];
    sys6(SYS_pipe2, (long) a, 0, 0, 0, 0, 0);
    sys6(SYS_pipe2, (long) b, 0, 0, 0, 0, 0);
    sys6(SYS_pipe2, (long) c, 0, 0, 0, 0, 0);

    /* Marked, not closed: still usable, and now close-on-exec. */
    if ((r = sys6(SYS_close_range, a[0], a[1], CLOSE_RANGE_CLOEXEC, 0, 0, 0)) != 0)
      fail("close_range marking a range close-on-exec", r, 0);
    if ((r = sys6(SYS_fcntl, a[0], F_GETFD, 0, 0, 0, 0)) != FD_CLOEXEC)
      fail("the close-on-exec flag close_range set", r, FD_CLOEXEC);
    sys6(SYS_write, a[1], (long) "x", 1, 0, 0, 0);
    { char one = 0;
      if ((r = sys6(SYS_read, a[0], (long) &one, 1, 0, 0, 0)) != 1)
        fail("reading a descriptor close_range only marked", r, 1); }

    /* And now closed for real, across a span covering all three pairs. */
    if ((r = sys6(SYS_close_range, a[0], c[1], 0, 0, 0, 0)) != 0)
      fail("close_range closing a span", r, 0);
    { char one = 0;
      if ((r = sys6(SYS_read, a[0], (long) &one, 1, 0, 0, 0)) != -EBADF)
        fail("reading a descriptor close_range closed", r, -EBADF);
      if ((r = sys6(SYS_read, c[0], (long) &one, 1, 0, 0, 0)) != -EBADF)
        fail("reading the far end of the span", r, -EBADF); }

    if ((r = sys6(SYS_close_range, 10, 5, 0, 0, 0, 0)) != -EINVAL)
      fail("close_range with the range the wrong way round", r, -EINVAL);
    if ((r = sys6(SYS_close_range, 3, 4, 1u << 20, 0, 0, 0)) != -EINVAL)
      fail("close_range with a flag that does not exist", r, -EINVAL); }

  /*
   * ---- execveat, which is the last thing this does ----
   *
   * AT_EMPTY_PATH runs the descriptor itself - fexecve - and there is no way
   * back from a successful exec, so it goes last and the program it runs is the
   * one that prints the result.
   */
  { long fd = sys6(SYS_openat, AT_FDCWD, (long) "/miscdone", O_RDONLY, 0, 0, 0);
    if (fd < 0)
      fail("opening the program execveat should run", fd, 0);
    char *argv[] = { (char *) "/miscdone", 0 };
    char *envp[] = { 0 };
    r = sys6(SYS_execveat, fd, (long) "", (long) argv, (long) envp, AT_EMPTY_PATH, 0);
    fail("execveat of a descriptor", r, 0); }
}
