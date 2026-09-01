/* freestanding: eventfd, and the descriptor number it is handed out as.
 *
 * Two bugs meet here, and the second one is why the first mattered.
 *
 * eventfd2 was not implemented at all, which is what stopped every download in
 * every guest: libcurl's multi interface creates one for curl_multi_wakeup and
 * treats the failure as fatal, so curl_multi_init returned NULL and curl
 * reported "Out of memory" on a machine with 32GiB free.
 *
 * Implementing it, the syscall returned register_fd's *status* rather than the
 * descriptor - and register_fd returns 0 for success. So every eventfd came
 * back as fd 0. Nothing complained: the guest wrote to it, read from it, and
 * polled it, all of which appear to work when what you are really holding is
 * stdin. It surfaced two layers away, when dnf closed the eventfd it had been
 * given, thereby closing the guest's real stdin, and the next open took the
 * free slot - leaving librepo asserting `dtarget->fd > 0` about a destination
 * file that had legitimately been given descriptor zero.
 *
 * So this checks the number as well as the behaviour. A test that only
 * exercised read and write would have passed throughout.
 *
 * And a third, found later: a dup of an eventfd was not one. The counter was
 * held per descriptor rather than per eventfd, so the copy was an ordinary
 * socketpair end again - a write to it moved no counter, made the original
 * poll no differently, and went to the end nabi keeps. adbd is built on that
 * exact pair, an eventfd for its epoll and a dup of it to write to, so every
 * wakeup it sent went nowhere: it completed the connection handshake, read
 * "OPEN shell,v2,raw:id", wrote to its dup to say so, and the thread in
 * epoll_pwait was never told. `adb shell` hung with the daemon idle.
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
#define SYS_ppoll 73
#define SYS_eventfd2 19
#define SYS_fcntl 25
#define F_DUPFD_CLOEXEC 1030
#define AT_FDCWD -100
#define O_RDONLY 0
#define EFD_CLOEXEC   02000000
#define EFD_NONBLOCK  04000
#define EFD_SEMAPHORE 1
#define EAGAIN 11

struct pollfd { int fd; short events, revents; };
struct timespec { long sec, nsec; };
#define POLLIN 1

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("eventfd FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static long ev_write(int fd, unsigned long long v)
{ return sys6(SYS_write, fd, (long) &v, sizeof v, 0, 0, 0); }

static long ev_read(int fd, unsigned long long *v)
{ return sys6(SYS_read, fd, (long) v, sizeof *v, 0, 0, 0); }

void _start(void)
{
  long r;
  unsigned long long v;

  /* An absolute path makes the directory descriptor irrelevant, and Linux does
   * not even check that it is open. rpm opens the root exactly this way before
   * unpacking, and NABI rejected it with EBADF - so `dnf install` failed on
   * "cpio: open failed - Bad file descriptor" about a directory that was there.
   * Checked here because it is the same class of bug: a descriptor argument
   * being taken seriously in a case where it carries no meaning. */
  long root = sys6(SYS_openat, -1, (long) "/", O_RDONLY, 0, 0, 0);
  if (root < 0)
    fail("openat(-1, \"/\") with an absolute path", root);
  sys6(SYS_close, root, 0,0,0,0,0);

  long fd = sys6(SYS_eventfd2, 0, EFD_CLOEXEC|EFD_NONBLOCK, 0, 0, 0, 0);
  if (fd < 0)
    fail("eventfd2", fd);

  /* The number itself. 0, 1 and 2 are the standard descriptors and are open;
   * handing any of them out means the syscall returned something that was not
   * a descriptor at all. */
  if (fd <= 2)
    fail("eventfd2 handed out a standard descriptor", fd);

  /* Empty and non-blocking reads EAGAIN rather than blocking or lying. */
  if ((r = ev_read((int) fd, &v)) != -EAGAIN)
    fail("read of an empty non-blocking eventfd", r);

  /* Counting, not queueing: three writes make one read of the total. A
   * socketpair used directly would return 1 here and leave two behind. */
  for (int i = 0; i < 3; i++)
    if ((r = ev_write((int) fd, 2)) != sizeof(unsigned long long))
      fail("write", r);
  if ((r = ev_read((int) fd, &v)) != sizeof v)
    fail("read after writing", r);
  if (v != 6)
    fail("counter did not accumulate; read back", (long) v);

  /* Drained, so empty again. */
  if ((r = ev_read((int) fd, &v)) != -EAGAIN)
    fail("read after draining", r);

  /* Pollable, which is the whole reason it is a descriptor: curl waits on this
   * alongside its sockets, and a counter it cannot poll would be useless. */
  /* A zero timespec, not a null pointer: ppoll reads NULL as "wait forever",
   * which for a deliberately empty eventfd is a hang rather than a result. */
  struct timespec now = { 0, 0 };
  struct pollfd pfd = { (int) fd, POLLIN, 0 };
  if ((r = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0)) < 0)
    fail("ppoll on an empty eventfd", r);
  if (r != 0)
    fail("an empty eventfd polled readable; ready count", r);

  if ((r = ev_write((int) fd, 1)) < 0)
    fail("write before poll", r);
  pfd.revents = 0;
  if ((r = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0)) < 0)
    fail("ppoll on a ready eventfd", r);
  if (r != 1 || !(pfd.revents & POLLIN))
    fail("a written eventfd did not poll readable; ready count", r);

  /*
   * A dup is the same eventfd. Everything below is done through the copy and
   * checked on the original, because that is the way round adbd uses them.
   */
  long dup = sys6(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 3, 0,0,0);
  if (dup < 0)
    fail("dup the eventfd", dup);
  if (dup == fd)
    fail("dup returned the same descriptor", dup);

  /* Drain whatever the poll checks above left behind. */
  ev_read((int) fd, &v);

  if ((r = ev_write((int) dup, 5)) < 0)
    fail("write through the dup", r);
  pfd.fd = (int) fd; pfd.revents = 0;
  if ((r = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0)) < 0)
    fail("ppoll after a write through the dup", r);
  if (r != 1 || !(pfd.revents & POLLIN))
    fail("a write through the dup did not make the original readable; ready count", r);
  if ((r = ev_read((int) fd, &v)) < 0)
    fail("read the original after writing the dup", r);
  if (v != 5)
    fail("the dup wrote to a different counter; read back", (long) v);

  /* And the other way, since a dup is symmetric. */
  if ((r = ev_write((int) fd, 2)) < 0)
    fail("write to the original", r);
  if ((r = ev_read((int) dup, &v)) < 0)
    fail("read through the dup", r);
  if (v != 2)
    fail("the original wrote to a different counter; read back through the dup", (long) v);

  /* Closing one of them leaves the other a working eventfd. */
  sys6(SYS_close, dup, 0,0,0,0,0);
  if ((r = ev_write((int) fd, 3)) < 0)
    fail("write after closing the dup", r);
  if ((r = ev_read((int) fd, &v)) < 0 || v != 3)
    fail("closing the dup took the eventfd with it; read back", (long) v);

  sys6(SYS_close, fd, 0,0,0,0,0);
  put("eventfd ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
