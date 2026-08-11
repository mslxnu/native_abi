/* freestanding: pidfd_open, process_madvise and process_mrelease.
 *
 * The two that were asked for take a pidfd, and until pidfd_open there was no
 * way for a guest to obtain one - so all three are here together, which is the
 * order they have to be used in anyway.
 *
 * What is worth checking:
 *
 *   - a pidfd names a *process*, so a descriptor that is not one is EBADF and a
 *     pid that does not exist is ESRCH. Those two answers being different is
 *     the whole reason to prefer a pidfd to a pid.
 *   - a pidfd becomes readable when its process exits. Darwin has no descriptor
 *     that does that, so poll answers it by asking whether the process is still
 *     there - and a live process must therefore *not* be readable, which is the
 *     half that catches an implementation reporting readable always.
 *   - process_madvise takes a narrower set of advice than madvise does. The
 *     destructive ones are excluded on Linux because they change what a read
 *     returns, so passing one has to be refused rather than quietly treated as
 *     a hint.
 *   - process_mrelease acts only on a dying process, so a running one is EINVAL.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_ppoll               73
#define SYS_pselect6            72
#define SYS_epoll_create1       20
#define SYS_epoll_ctl           21
#define SYS_epoll_pwait         22
#define SYS_clone              220
#define SYS_wait4              260
#define SYS_nanosleep          101
#define SYS_getpid             172
#define SYS_close               57
#define SYS_write               64
#define SYS_exit                93
#define SYS_pidfd_open         434
#define SYS_process_madvise    440
#define SYS_process_mrelease   448

#define EBADF   9
#define EINVAL 22
#define ESRCH   3
#define EPERM   1
#define POLLIN  1

#define MADV_WILLNEED   3
#define MADV_DONTNEED   4
#define MADV_COLD      20
#define MADV_PAGEOUT   21

struct iov  { void *base; unsigned long len; };
struct pfd  { int fd; short events, revents; };
struct tspec { long sec, nsec; };
struct epev { unsigned events; unsigned pad; unsigned long long data; } __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("pidfd FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static char area[8192];

void _start(void)
{
  long r;
  long me = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);

  /* ---- what pidfd_open refuses ---- */
  if ((r = sys6(SYS_pidfd_open, me, 1u << 20, 0, 0, 0, 0)) != -EINVAL)
    fail("pidfd_open with a flag that does not exist", r, -EINVAL);
  if ((r = sys6(SYS_pidfd_open, 0, 0, 0, 0, 0, 0)) != -EINVAL)
    fail("pidfd_open of pid zero", r, -EINVAL);
  if ((r = sys6(SYS_pidfd_open, 0x7ffffff, 0, 0, 0, 0, 0)) != -ESRCH)
    fail("pidfd_open of a process that does not exist", r, -ESRCH);

  long pfd = sys6(SYS_pidfd_open, me, 0, 0, 0, 0, 0);
  if (pfd < 0)
    fail("pidfd_open of this process", pfd, 0);

  /*
   * ---- a live process is not readable ----
   *
   * This is the half that catches an implementation which reports a pidfd
   * readable whatever the process is doing. This process is plainly running,
   * so its pidfd must not be readable.
   */
  { struct pfd p = { (int) pfd, POLLIN, 0 };
    struct tspec to = { 0, 0 };
    r = sys6(SYS_ppoll, (long) &p, 1, (long) &to, 0, 0, 0);
    if (r != 0 || (p.revents & POLLIN))
      fail("polling the pidfd of a process that is still running", r, 0); }

  /* The same through select and epoll, which had the same trap: a pidfd is a
   * file, and both call a file readable always. */
  { unsigned long set = 1UL << pfd;
    struct tspec to = { 0, 0 };
    r = sys6(SYS_pselect6, (int) pfd + 1, (long) &set, 0, 0, (long) &to, 0);
    if (r != 0 || (set & (1UL << pfd)))
      fail("select on the pidfd of a process still running", r, 0); }

  { long ep = sys6(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
    if (ep < 0)
      fail("epoll_create1", ep, 0);
    struct epev ev = { POLLIN, 0, 0x1234 };
    if ((r = sys6(SYS_epoll_ctl, ep, 1 /* ADD */, pfd, (long) &ev, 0, 0)) != 0)
      fail("epoll_ctl adding the pidfd", r, 0);
    struct epev got[2];
    r = sys6(SYS_epoll_pwait, ep, (long) got, 2, 0, 0, 0);
    if (r != 0)
      fail("epoll on the pidfd of a process still running", r, 0);
    sys6(SYS_close, ep, 0, 0, 0, 0, 0); }

  /* ---- process_madvise ---- */
  { struct iov v[2] = { { area, 4096 }, { area + 4096, 4096 } };

    /* A hint it accepts, over two ranges: the count is bytes, not ranges. */
    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 2, MADV_COLD, 0, 0)) != 8192)
      fail("process_madvise over two ranges", r, 8192);
    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 1, MADV_PAGEOUT, 0, 0)) != 4096)
      fail("process_madvise over one range", r, 4096);
    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 1, MADV_WILLNEED, 0, 0)) != 4096)
      fail("process_madvise with MADV_WILLNEED", r, 4096);

    /*
     * A destructive advice is refused. Linux excludes these from
     * process_madvise because they change what a read returns, so treating one
     * as a harmless hint would be the wrong kind of permissive.
     */
    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 1, MADV_DONTNEED, 0, 0)) != -EINVAL)
      fail("process_madvise with a destructive advice", r, -EINVAL);

    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 1, MADV_COLD, 1, 0)) != -EINVAL)
      fail("process_madvise with a flag, of which there are none", r, -EINVAL);
    if ((r = sys6(SYS_process_madvise, pfd, (long) v, 0, MADV_COLD, 0, 0)) != 0)
      fail("process_madvise over no ranges", r, 0);

    /* A descriptor that is not a pidfd is not a process. */
    if ((r = sys6(SYS_process_madvise, 1, (long) v, 1, MADV_COLD, 0, 0)) != -EBADF)
      fail("process_madvise on a descriptor that is not a pidfd", r, -EBADF);

    /* Memory that is not there is EFAULT even for advice. */
    { struct iov bad[1] = { { (void *) 0x40000000000ULL, 4096 } };
      if ((r = sys6(SYS_process_madvise, pfd, (long) bad, 1, MADV_COLD, 0, 0)) != -14)
        fail("process_madvise over a range that is not mapped", r, -14); } }

  /* ---- process_mrelease ---- */
  {
    /* This process is running, so it is not a dying one - which is the only
     * kind this acts on, and EINVAL is what Linux says about the rest. */
    if ((r = sys6(SYS_process_mrelease, pfd, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("process_mrelease on a process that is not dying", r, -EINVAL);
    if ((r = sys6(SYS_process_mrelease, pfd, 1, 0, 0, 0, 0)) != -EINVAL)
      fail("process_mrelease with a flag that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_process_mrelease, 1, 0, 0, 0, 0, 0)) != -EBADF)
      fail("process_mrelease on a descriptor that is not a pidfd", r, -EBADF); }

  sys6(SYS_close, pfd, 0, 0, 0, 0, 0);

  /*
   * ---- and the other half: a pidfd whose process has gone ----
   *
   * Everything above checks that a live process is *not* reported ready, which
   * catches the trap that a pidfd is a file and the host calls files readable.
   * This checks the case the call exists for. A child is forked, a pidfd taken
   * for it while it is still alive, and the exit waited for - after which all
   * three of poll, select and epoll must say readable.
   *
   * epoll is the one that needed its own work: kqueue does not raise a read
   * event for a regular file at all, so without NABI adding the entry itself an
   * event loop would wait on a pidfd forever.
   */
  { long child = sys6(SYS_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
    if (child < 0)
      fail("clone", child, 0);
    if (child == 0) {
      struct tspec nap = { 0, 20 * 1000 * 1000 };
      sys6(SYS_nanosleep, (long) &nap, 0, 0, 0, 0, 0);
      sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
    }

    long cfd = sys6(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
    if (cfd < 0)
      fail("pidfd_open of a child", cfd, 0);

    /* Still running, so still not readable. */
    { struct pfd p = { (int) cfd, POLLIN, 0 };
      struct tspec to = { 0, 0 };
      r = sys6(SYS_ppoll, (long) &p, 1, (long) &to, 0, 0, 0);
      if (r != 0)
        fail("polling a child's pidfd before it exits", r, 0); }

    int status = 0;
    if ((r = sys6(SYS_wait4, child, (long) &status, 0, 0, 0, 0)) < 0)
      fail("waiting for the child", r, 0);

    { struct pfd p = { (int) cfd, POLLIN, 0 };
      struct tspec to = { 1, 0 };
      r = sys6(SYS_ppoll, (long) &p, 1, (long) &to, 0, 0, 0);
      if (r != 1 || !(p.revents & POLLIN))
        fail("polling a child's pidfd after it exits", r, 1); }

    { unsigned long set = 1UL << cfd;
      struct tspec to = { 0, 0 };
      r = sys6(SYS_pselect6, (int) cfd + 1, (long) &set, 0, 0, (long) &to, 0);
      if (r != 1 || !(set & (1UL << cfd)))
        fail("select on a child's pidfd after it exits", r, 1); }

    { long ep = sys6(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
      struct epev ev = { POLLIN, 0, 0xbeef };
      if ((r = sys6(SYS_epoll_ctl, ep, 1, cfd, (long) &ev, 0, 0)) != 0)
        fail("epoll_ctl adding a child's pidfd", r, 0);
      struct epev got[2];
      r = sys6(SYS_epoll_pwait, ep, (long) got, 2, 0, 0, 0);
      if (r != 1)
        fail("epoll on a child's pidfd after it exits", r, 1);
      if (got[0].data != 0xbeef)
        fail("which registration epoll reported", (long) got[0].data, 0xbeef);
      sys6(SYS_close, ep, 0, 0, 0, 0, 0); }

    sys6(SYS_close, cfd, 0, 0, 0, 0, 0); }

  put("pidfd ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
