/* freestanding: passing a descriptor over a unix socket with SCM_RIGHTS.
 *
 * This is what Wayland is built out of. A client connects to the compositor's
 * socket and then sends it a memfd for every buffer it wants shown, so a nabi
 * that refuses ancillary data - which it did, with "we do not support ancillary
 * data yet" - lets a client connect and then never put a pixel on the screen.
 *
 * What is worth checking:
 *
 *   - the descriptor that arrives is a *working* one, and names the same file
 *     the sender had. Writing through the sent descriptor and reading it back
 *     through the received one is the check; a call that merely returns 0 with
 *     a number in the buffer would pass anything weaker.
 *   - the two cmsghdr layouts differ in size, so the header the guest reads
 *     back has to be Linux's. Walking it with Linux's own arithmetic is the
 *     test - a Darwin-layout header read at Linux offsets gives nonsense
 *     lengths.
 *   - a received descriptor has to be registered in nabi's own fd table, or the
 *     guest holds a number that its next close or dup says is not open. That is
 *     checked by using it, then closing it.
 *   - MSG_CMSG_CLOEXEC has to reach the descriptor flag.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_unlinkat    35
#define SYS_fcntl       25
#define SYS_openat      56
#define SYS_close       57
#define SYS_lseek       62
#define SYS_read        63
#define SYS_write       64
#define SYS_exit        93
#define SYS_socketpair 199
#define SYS_sendmsg    211
#define SYS_recvmsg    212
#define SYS_memfd_create 279

#define EBADF 9
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define MSG_CMSG_CLOEXEC 0x40000000
#define F_GETFD 1
#define FD_CLOEXEC 1
#define O_RDWR 2
#define AT_FDCWD (-100)

struct iov { void *base; unsigned long len; };
struct lmsghdr {
  void *name; int namelen; int _pad;
  struct iov *iov; unsigned long iovlen;
  void *control; unsigned long controllen;
  unsigned flags; unsigned _pad2;
};
/* Linux's layout: an 8-byte length, then two ints. */
struct lcmsghdr { unsigned long len; int level; int type; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got)
{ put("scm FAIL: "); put(what); put(" -> "); putd(got); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0); }

static char cbuf[256];

void _start(void)
{
  long r;
  int sv[2];
  if ((r = sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0, 0)) != 0)
    fail("socketpair", r);

  /* The thing being passed: a memfd with known contents. */
  long mfd = sys6(SYS_memfd_create, (long) "buffer", 0, 0, 0, 0, 0);
  if (mfd < 0) fail("memfd_create", mfd);
  static const char payload[] = "wayland buffer";
  if ((r = sys6(SYS_write, mfd, (long) payload, sizeof payload - 1, 0, 0, 0)) != sizeof payload - 1)
    fail("write to the memfd", r);

  /* ---- send it ---- */
  {
    char byte = 'x';
    struct iov v = { &byte, 1 };
    struct lcmsghdr *c = (struct lcmsghdr *) cbuf;
    c->len = sizeof *c + sizeof(int);
    c->level = SOL_SOCKET;
    c->type = SCM_RIGHTS;
    *(int *) (cbuf + sizeof *c) = (int) mfd;

    struct lmsghdr m = { 0, 0, 0, &v, 1, cbuf, c->len, 0, 0 };
    if ((r = sys6(SYS_sendmsg, sv[0], (long) &m, 0, 0, 0, 0)) != 1)
      fail("sendmsg with SCM_RIGHTS", r);
  }

  /* ---- receive it ---- */
  int got;
  {
    char byte = 0;
    struct iov v = { &byte, 1 };
    for (unsigned i = 0; i < sizeof cbuf; i++) cbuf[i] = 0;
    struct lmsghdr m = { 0, 0, 0, &v, 1, cbuf, sizeof cbuf, 0, 0 };
    if ((r = sys6(SYS_recvmsg, sv[1], (long) &m, MSG_CMSG_CLOEXEC, 0, 0, 0)) != 1)
      fail("recvmsg", r);
    if (byte != 'x') fail("the ordinary data did not arrive", byte);

    /* Walked with Linux's own arithmetic, which is the point: a Darwin-layout
     * header read here gives a nonsense length. */
    struct lcmsghdr *c = (struct lcmsghdr *) cbuf;
    if (m.controllen < sizeof *c) fail("no control data came back", (long) m.controllen);
    if (c->level != SOL_SOCKET) fail("cmsg_level", c->level);
    if (c->type != SCM_RIGHTS) fail("cmsg_type", c->type);
    if (c->len != sizeof *c + sizeof(int)) fail("cmsg_len", (long) c->len);
    got = *(int *) (cbuf + sizeof *c);
    if (got < 0) fail("the descriptor that came back", got);
  }

  /* ---- and it is a working descriptor for the same file ---- */
  {
    if ((r = sys6(SYS_fcntl, got, F_GETFD, 0, 0, 0, 0)) < 0)
      fail("the received descriptor is not open", r);
    if (!(r & FD_CLOEXEC))
      fail("MSG_CMSG_CLOEXEC did not reach the descriptor", r);

    /* Write through the original, read through the received one: the same
     * open file, not merely a number. */
    static const char more[] = "+more";
    if ((r = sys6(SYS_lseek, mfd, 0, 2 /* SEEK_END */, 0, 0, 0)) < 0) fail("lseek", r);
    if ((r = sys6(SYS_write, mfd, (long) more, sizeof more - 1, 0, 0, 0)) != sizeof more - 1)
      fail("appending through the sent descriptor", r);

    char rb[64];
    for (unsigned i = 0; i < sizeof rb; i++) rb[i] = 0;
    if ((r = sys6(SYS_lseek, got, 0, 0 /* SEEK_SET */, 0, 0, 0)) != 0) fail("lseek on the received fd", r);
    long n = sys6(SYS_read, got, (long) rb, sizeof rb, 0, 0, 0);
    if (n != (long)(sizeof payload - 1 + sizeof more - 1))
      fail("reading through the received descriptor", n);
    static const char want[] = "wayland buffer+more";
    for (int i = 0; i < (int)(sizeof want - 1); i++)
      if (rb[i] != want[i]) fail("the received descriptor names a different file", i);

    /* Registered, so closing it is a close and not an EBADF. */
    if ((r = sys6(SYS_close, got, 0,0,0,0,0)) != 0)
      fail("closing the received descriptor", r);
    if ((r = sys6(SYS_fcntl, got, F_GETFD, 0, 0, 0, 0)) >= 0)
      fail("the received descriptor was still open after close", r);
  }

  sys6(SYS_close, mfd, 0,0,0,0,0);
  sys6(SYS_close, sv[0], 0,0,0,0,0);
  sys6(SYS_close, sv[1], 0,0,0,0,0);
  put("scm ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
