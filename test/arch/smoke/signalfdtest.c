/* freestanding: signalfd4 - the record, the consumption, the pollability.
 *
 * signalfd is how a process turns signals it has blocked into a read from a
 * descriptor, which is the shape every event loop wants. The things that can
 * go wrong are specific to an emulation:
 *
 *  - the syscall is aarch64's signalfd4 (74), which replaces the old 3-arg
 *    signalfd, so the argument order (fd, mask, sizemask, flags) is the first
 *    thing checked;
 *  - a signal already pending when the descriptor is created must still be
 *    readable - the byte that makes it so is only sent on arrival, so creation
 *    has to look at the pending set itself;
 *  - reading must *consume* the signal, or it would also be delivered to a
 *    handler;
 *  - the descriptor must poll readable while a wanted signal is pending and
 *    not readable once it has been read, which is what the socketpair byte is
 *    for.
 */
typedef unsigned long ulong;
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n;
  register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d;
  register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory");
  return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_ppoll 73
#define SYS_signalfd4 74
#define SYS_exit 93
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigpending 136
#define SYS_getpid 172

#define SIGUSR1 10
#define SIGUSR2 12
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SIGUSR1_BIT (1UL << (SIGUSR1 - 1))
#define SIGUSR2_BIT (1UL << (SIGUSR2 - 1))

#define SFD_NONBLOCK 04000
#define SFD_CLOEXEC  02000000
#define O_RDONLY 0
#define AT_FDCWD -100

#define EAGAIN 11
#define EINVAL 22
#define EBADF  9

#define POLLIN 1

#define SI_SIZE 128

struct pollfd { int fd; short events, revents; };
struct timespec { long sec, nsec; };

static volatile long caught = 0;
static void handler(int s){ caught = s; }

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("signalfd FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static long sf_create(ulong mask, long flags)
{
  return sys6(SYS_signalfd4, -1, (long) &mask, sizeof mask, flags, 0, 0);
}

static long sf_read(int fd, ulong *signo)
{
  char buf[SI_SIZE];
  long r = sys6(SYS_read, fd, (long) buf, sizeof buf, 0, 0, 0);
  if (r == SI_SIZE) {
    unsigned int s = *(unsigned int *) buf;
    *signo = s;
  }
  return r;
}

void _start(void)
{
  long r;
  ulong signo;

  /* Nothing may default-terminate behind a failing signalfd: the test has to
   * be able to report its own failure. */
  long act[4];
  act[0]=(long)handler; act[1]=0; act[2]=0; act[3]=0;
  sys6(SYS_rt_sigaction, SIGUSR1, (long)act, 0, 8, 0, 0);
  sys6(SYS_rt_sigaction, SIGUSR2, (long)act, 0, 8, 0, 0);
  long pid = sys6(SYS_getpid, 0,0,0,0,0,0);

  /* Creation: a non-blocking, close-on-exec descriptor above the standard
   * three, that reads EAGAIN while nothing is pending. */
  long fd = sf_create(SIGUSR1_BIT, SFD_NONBLOCK | SFD_CLOEXEC);
  if (fd < 0)
    fail("signalfd4 create", fd);
  if (fd <= 2)
    fail("signalfd4 handed out a standard descriptor", fd);
  if ((r = sf_read((int) fd, &signo)) != -EAGAIN)
    fail("read of an empty non-blocking signalfd", r);

  /* A signal that arrives while blocked is delivered to the descriptor: the
   * record names it, the read is a full record, and the signal is consumed -
   * neither still pending nor handed to the handler. */
  ulong m = SIGUSR1_BIT;
  sys6(SYS_rt_sigprocmask, SIG_BLOCK, (long) &m, 0, 8, 0, 0);
  sys6(SYS_kill, pid, SIGUSR1, 0,0,0,0);

  long bfd = sf_create(SIGUSR1_BIT, 0);       /* the blocking form */
  if (bfd < 0)
    fail("blocking signalfd4 create", bfd);
  if ((r = sf_read((int) bfd, &signo)) != SI_SIZE)
    fail("blocking read of a pending signalfd", r);
  if (signo != SIGUSR1)
    fail("ssi_signo", (long) signo);
  sys6(SYS_rt_sigpending, (long) &m, 8, 0, 0, 0, 0);
  if (m & SIGUSR1_BIT)
    fail("signal still pending after signalfd read", (long) m);
  if (caught != 0)
    fail("signal delivered to a handler despite signalfd read", caught);

  /* Pollable, which is why it is a descriptor at all: an event loop waits on
   * this alongside its sockets. Ready while wanted and pending, not ready once
   * read. Delivery is asynchronous (the host notices the kill in its own
   * time), so readiness is polled until it shows - which is also what an event
   * loop would do - and the drained side is the deterministic assertion. */
  struct timespec now = { 0, 0 };
  struct pollfd pfd = { (int) bfd, POLLIN, 0 };
  sys6(SYS_kill, pid, SIGUSR1, 0,0,0,0);
  int ready = 0;
  for (int i = 0; i < 100000 && !ready; i++) {
    pfd.revents = 0;
    r = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0);
    if (r < 0)
      fail("ppoll on a pending signalfd", r);
    ready = r == 1 && (pfd.revents & POLLIN);
  }
  if (!ready)
    fail("a pending signalfd never polled readable", r);
  if ((r = sf_read((int) bfd, &signo)) != SI_SIZE || signo != SIGUSR1)
    fail("read after poll", r);
  pfd.revents = 0;
  if ((r = sys6(SYS_ppoll, (long) &pfd, 1, (long) &now, 0, 0, 0)) < 0)
    fail("ppoll on a drained signalfd", r);
  if (r != 0)
    fail("a drained signalfd polled readable; ready count", r);

  /* A signal that was already pending when the descriptor was created must
   * still be readable: the poke happens on arrival, so creation has to look at
   * the pending set itself. A blocking read makes the check immune to how long
   * the host takes to deliver. */
  ulong m2 = SIGUSR2_BIT;
  sys6(SYS_rt_sigprocmask, SIG_BLOCK, (long) &m2, 0, 8, 0, 0);
  sys6(SYS_kill, pid, SIGUSR2, 0,0,0,0);
  long sfd = sf_create(SIGUSR2_BIT, 0);
  if (sfd < 0)
    fail("signalfd4 after raising", sfd);
  if ((r = sf_read((int) sfd, &signo)) != SI_SIZE)
    fail("read of a signal pending before creation", r);
  if (signo != SIGUSR2)
    fail("ssi_signo (pre-pending)", (long) signo);
  if (caught != 0)
    fail("pre-pending signal delivered instead of read", caught);

  /* Replacing the mask of an existing descriptor keeps the descriptor. */
  if ((r = sys6(SYS_signalfd4, fd, (long) &m2, sizeof m2, 0, 0, 0)) != fd)
    fail("signalfd4 mask update", r);

  /* The refusals: an fd that is not a signalfd, flags that are not SFD's, and
   * a sigset size that is not the one the ABI fixes. */
  long root = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY, 0, 0, 0);
  if (root >= 0) {
    if ((r = sys6(SYS_signalfd4, root, (long) &m, sizeof m, 0, 0, 0)) != -EBADF)
      fail("signalfd4 on a non-signalfd fd", r);
    sys6(SYS_close, root, 0,0,0,0,0);
  }
  if ((r = sys6(SYS_signalfd4, -1, (long) &m, sizeof m, 0x10000, 0, 0)) != -EINVAL)
    fail("signalfd4 with bad flags", r);
  if ((r = sys6(SYS_signalfd4, -1, (long) &m, 4, 0, 0, 0)) != -EINVAL)
    fail("signalfd4 with a short sigset", r);

  put("signalfd ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
