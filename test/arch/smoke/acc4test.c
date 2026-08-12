/* freestanding: accept4, kcmp and keyctl.
 *
 * What is worth checking, and why each of these would pass by accident:
 *
 *   - accept4's two flags have to be *set to* what was asked for, not merely
 *     turned on when asked. Linux hands back a blocking descriptor whatever the
 *     listening socket was; the BSD lineage has historically passed the
 *     listening socket's flags down. So the listening socket here is put into
 *     non-blocking mode first, and a plain accept4(..., 0) on it must still
 *     produce a *blocking* descriptor. An implementation that only ever sets
 *     flags passes every other check in this file.
 *   - a flag that does not exist is refused rather than dropped, and refused
 *     before the accept, so it is EINVAL and not EAGAIN on an empty queue.
 *   - kcmp's answer for two descriptors is about the open file description, not
 *     the file. A dup and its original must compare equal; the two ends of one
 *     pipe must not. Comparing st_dev and st_ino would get the first of those
 *     right and is the wrong answer for the second.
 *   - where the description cannot be identified at all - a vnode, which is
 *     most descriptors - the answer is refused rather than guessed. Two opens
 *     of the same directory are the pair that catches a guess: they are the
 *     same file and different descriptions.
 *   - kcmp about another process is EPERM, and about a process that is not
 *     there is ESRCH. Those being different is the point.
 *   - keyctl is absent, and says so.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getpid       172
#define SYS_write         64
#define SYS_exit          93
#define SYS_close         57
#define SYS_fcntl         25
#define SYS_openat        56
#define SYS_unlinkat      35
#define SYS_dup           23
#define SYS_pipe2         59
#define SYS_socket       198
#define SYS_bind         200
#define SYS_listen       201
#define SYS_accept       202
#define SYS_connect      203
#define SYS_accept4      242
#define SYS_kcmp         272
#define SYS_keyctl       219
#define SYS_epoll_create1 20
#define SYS_epoll_ctl     21
#define SYS_clone        220
#define SYS_wait4        260
#define SYS_nanosleep    101

#define EPERM         1
#define ENOENT        2
#define ESRCH         3
#define EBADF         9
#define EINVAL       22
#define ENOSYS       38
#define ENOTSOCK     88
#define EOPNOTSUPP   95

#define AF_UNIX          1
#define SOCK_STREAM      1
#define SOCK_NONBLOCK  0x800
#define SOCK_CLOEXEC 0x80000

#define F_GETFD        1
#define F_GETFL        3
#define F_SETFL        4
#define FD_CLOEXEC     1
#define O_NONBLOCK 0x800
#define O_RDONLY       0
#define O_DIRECTORY 0x4000
#define AT_FDCWD    (-100)

#define KCMP_FILE        0
#define KCMP_VM          1
#define KCMP_FILES       2
#define KCMP_SIGHAND     4
#define KCMP_EPOLL_TFD   7

struct sun { unsigned short family; char path[108]; };
struct epev { unsigned events; unsigned pad; unsigned long long data; } __attribute__((packed));
struct eslot { unsigned efd, tfd, toff; };
struct tspec { long sec, nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("acc4 FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static const char sockpath[] = "/a4.sock";

/* A client connection, so there is something in the accept queue. */
static long
dial(void)
{
  long fd = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  if (fd < 0)
    fail("socket for the client end", fd, 0);
  struct sun a; a.family = AF_UNIX;
  for (int i = 0; i < (int) sizeof a.path; i++)
    a.path[i] = i < (int) sizeof sockpath - 1 ? sockpath[i] : 0;
  long r = sys6(SYS_connect, fd, (long) &a, sizeof a, 0, 0, 0);
  if (r < 0)
    fail("connect", r, 0);
  return fd;
}

void _start(void)
{
  long r;
  long me = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);

  /* ---- a listening socket, deliberately non-blocking ---- */
  sys6(SYS_unlinkat, AT_FDCWD, (long) sockpath, 0, 0, 0, 0);

  long lfd = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  if (lfd < 0)
    fail("socket", lfd, 0);

  { struct sun a; a.family = AF_UNIX;
    for (int i = 0; i < (int) sizeof a.path; i++)
      a.path[i] = i < (int) sizeof sockpath - 1 ? sockpath[i] : 0;
    if ((r = sys6(SYS_bind, lfd, (long) &a, sizeof a, 0, 0, 0)) < 0)
      fail("bind", r, 0); }
  if ((r = sys6(SYS_listen, lfd, 8, 0, 0, 0, 0)) < 0)
    fail("listen", r, 0);
  if ((r = sys6(SYS_fcntl, lfd, F_SETFL, O_NONBLOCK, 0, 0, 0)) < 0)
    fail("making the listening socket non-blocking", r, 0);

  /* ---- what accept4 refuses, and when ---- */

  /*
   * The queue is empty, so a flag that does not exist has to be caught before
   * the accept is attempted - otherwise this is EAGAIN and nobody ever learns
   * the flag was wrong.
   */
  if ((r = sys6(SYS_accept4, lfd, 0, 0, 1u << 20, 0, 0)) != -EINVAL)
    fail("accept4 with a flag that does not exist", r, -EINVAL);
  if ((r = sys6(SYS_accept4, 1, 0, 0, 0, 0, 0)) != -ENOTSOCK)
    fail("accept4 on a descriptor that is not a socket", r, -ENOTSOCK);

  /* ---- accept4 with no flags: blocking, and not close-on-exec ---- */
  {
    long c = dial();
    long a = sys6(SYS_accept4, lfd, 0, 0, 0, 0, 0);
    if (a < 0)
      fail("accept4 with no flags", a, 0);

    /*
     * The check this file exists for. The listening socket is non-blocking; on
     * Linux the accepted one is not, and asking for no flags must mean no
     * flags rather than "whatever was inherited".
     */
    r = sys6(SYS_fcntl, a, F_GETFL, 0, 0, 0, 0);
    if (r < 0 || (r & O_NONBLOCK))
      fail("accept4(0) inherited O_NONBLOCK from the listening socket", r, 0);
    r = sys6(SYS_fcntl, a, F_GETFD, 0, 0, 0, 0);
    if (r < 0 || (r & FD_CLOEXEC))
      fail("accept4(0) set close-on-exec", r, 0);

    sys6(SYS_close, a, 0, 0, 0, 0, 0);
    sys6(SYS_close, c, 0, 0, 0, 0, 0);
  }

  /* ---- and with both flags ---- */
  {
    long c = dial();
    long a = sys6(SYS_accept4, lfd, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC, 0, 0);
    if (a < 0)
      fail("accept4 with SOCK_NONBLOCK|SOCK_CLOEXEC", a, 0);

    r = sys6(SYS_fcntl, a, F_GETFL, 0, 0, 0, 0);
    if (r < 0 || !(r & O_NONBLOCK))
      fail("accept4 did not set O_NONBLOCK", r, O_NONBLOCK);
    r = sys6(SYS_fcntl, a, F_GETFD, 0, 0, 0, 0);
    if (r < 0 || !(r & FD_CLOEXEC))
      fail("accept4 did not set close-on-exec", r, FD_CLOEXEC);

    sys6(SYS_close, a, 0, 0, 0, 0, 0);
    sys6(SYS_close, c, 0, 0, 0, 0, 0);
  }

  /* ---- plain accept still works, which the refactor could have broken ---- */
  {
    long c = dial();
    long a = sys6(SYS_accept, lfd, 0, 0, 0, 0, 0);
    if (a < 0)
      fail("accept", a, 0);
    r = sys6(SYS_fcntl, a, F_GETFL, 0, 0, 0, 0);
    if (r < 0 || (r & O_NONBLOCK))
      fail("accept produced a non-blocking descriptor", r, 0);
    sys6(SYS_close, a, 0, 0, 0, 0, 0);
    sys6(SYS_close, c, 0, 0, 0, 0, 0);
  }

  sys6(SYS_close, lfd, 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) sockpath, 0, 0, 0, 0);

  /* ---- kcmp: what it refuses ---- */
  if ((r = sys6(SYS_kcmp, me, me, 8, 0, 0, 0)) != -EINVAL)
    fail("kcmp with a type that does not exist", r, -EINVAL);
  if ((r = sys6(SYS_kcmp, me, 0x7ffffff, KCMP_VM, 0, 0, 0)) != -ESRCH)
    fail("kcmp naming a process that does not exist", r, -ESRCH);

  /* ---- a process shares everything with itself ---- */
  if ((r = sys6(SYS_kcmp, me, me, KCMP_VM, 0, 0, 0)) != 0)
    fail("kcmp of this process against itself, KCMP_VM", r, 0);
  if ((r = sys6(SYS_kcmp, me, me, KCMP_FILES, 0, 0, 0)) != 0)
    fail("kcmp of this process against itself, KCMP_FILES", r, 0);
  if ((r = sys6(SYS_kcmp, me, me, KCMP_SIGHAND, 0, 0, 0)) != 0)
    fail("kcmp of this process against itself, KCMP_SIGHAND", r, 0);

  /* ---- KCMP_FILE ---- */
  long p[2];
  { int fds[2];
    if ((r = sys6(SYS_pipe2, (long) fds, 0, 0, 0, 0, 0)) != 0)
      fail("pipe2", r, 0);
    p[0] = fds[0]; p[1] = fds[1]; }

  if ((r = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], p[0], 0)) != 0)
    fail("kcmp of a descriptor against itself", r, 0);

  /*
   * The two ends of one pipe are one object to stat and two open file
   * descriptions to kcmp. This is the answer st_dev/st_ino would get wrong.
   */
  r = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], p[1], 0);
  if (r != 1 && r != 2)
    fail("kcmp of the two ends of one pipe", r, 1);

  /* A dup shares the description, so it compares equal - and the ordering of
   * the unequal case above has to be stable, not merely non-zero. */
  { long d = sys6(SYS_dup, p[0], 0, 0, 0, 0, 0);
    if (d < 0)
      fail("dup", d, 0);
    if ((r = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], d, 0)) != 0)
      fail("kcmp of a descriptor against its dup", r, 0);
    long a1 = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], p[1], 0);
    long a2 = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], p[1], 0);
    if (a1 != a2)
      fail("kcmp gave two different orderings for one pair", a2, a1);
    sys6(SYS_close, d, 0, 0, 0, 0, 0); }

  if ((r = sys6(SYS_kcmp, me, me, KCMP_FILE, p[0], 999, 0)) != -EBADF)
    fail("kcmp naming a descriptor that is not open", r, -EBADF);

  /*
   * Two separate opens of one directory: the same file, different open file
   * descriptions, and nothing on this host says which. Refused rather than
   * answered - an implementation comparing st_dev and st_ino returns 0 here.
   */
  { long d1 = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    long d2 = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (d1 < 0 || d2 < 0)
      fail("opening the root directory twice", d1 < 0 ? d1 : d2, 0);
    if ((r = sys6(SYS_kcmp, me, me, KCMP_FILE, d1, d2, 0)) != -EOPNOTSUPP)
      fail("kcmp of two descriptors whose descriptions cannot be told apart",
           r, -EOPNOTSUPP);
    sys6(SYS_close, d1, 0, 0, 0, 0, 0);
    sys6(SYS_close, d2, 0, 0, 0, 0, 0); }

  /* ---- KCMP_EPOLL_TFD ---- */
  { long ep = sys6(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
    if (ep < 0)
      fail("epoll_create1", ep, 0);
    struct epev ev = { 1 /* EPOLLIN */, 0, 0x5678 };
    if ((r = sys6(SYS_epoll_ctl, ep, 1 /* ADD */, p[0], (long) &ev, 0, 0)) != 0)
      fail("epoll_ctl adding the pipe", r, 0);

    struct eslot s = { (unsigned) ep, (unsigned) p[0], 0 };
    if ((r = sys6(SYS_kcmp, me, me, KCMP_EPOLL_TFD, ep, (long) &s, 0)) != 0)
      fail("kcmp for a descriptor that is in the epoll set", r, 0);

    /* The other end of the same pipe is not in the set, and is a pipe, so this
     * is a real absence rather than an undecidable one. */
    s.tfd = (unsigned) p[1];
    if ((r = sys6(SYS_kcmp, me, me, KCMP_EPOLL_TFD, ep, (long) &s, 0)) != -ENOENT)
      fail("kcmp for a descriptor that is not in the epoll set", r, -ENOENT);

    s.tfd = (unsigned) p[0]; s.toff = 1;
    if ((r = sys6(SYS_kcmp, me, me, KCMP_EPOLL_TFD, ep, (long) &s, 0)) != -ENOENT)
      fail("kcmp for a second registration of one descriptor", r, -ENOENT);

    sys6(SYS_close, ep, 0, 0, 0, 0, 0); }

  /* ---- another process is out of reach, and that is not ESRCH ---- */
  { long child = sys6(SYS_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
    if (child < 0)
      fail("clone", child, 0);
    if (child == 0) {
      struct tspec nap = { 0, 50 * 1000 * 1000 };
      sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0);
      sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
    }
    if ((r = sys6(SYS_kcmp, me, child, KCMP_VM, 0, 0, 0)) != -EPERM)
      fail("kcmp against another process", r, -EPERM);
    sys6(SYS_wait4, child, 0, 0, 0, 0, 0); }

  sys6(SYS_close, p[0], 0, 0, 0, 0, 0);
  sys6(SYS_close, p[1], 0, 0, 0, 0, 0);

  /* ---- keyctl ---- */
  if ((r = sys6(SYS_keyctl, 0 /* GET_KEYRING_ID */, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("keyctl", r, -ENOSYS);

  put("acc4 ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
