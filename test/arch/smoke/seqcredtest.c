/* freestanding: the AF_UNIX features Android asks for that Darwin has not got.
 *
 * SOCK_SEQPACKET is connection-oriented like a stream and keeps message
 * boundaries like a datagram, and Darwin has neither combination. nabi
 * substituted a datagram socket, which is right for a socketpair - a connected
 * pair, and nothing will ever listen on it - and wrong for one made with
 * socket(2), which is on its way to bind, listen and accept. listen on a
 * datagram socket is EOPNOTSUPP, which is where Android's lmkd stopped: it
 * inherits its listening socket from init, calls listen, and exits. Four times,
 * and init calls it a critical process that will not start and reboots.
 *
 * SO_PASSCRED asks the receiver be told who sent each message. Darwin has no
 * such option - its SCM_CREDS is sent by the sender rather than asked for by
 * the receiver - so passing it on returned ENOPROTOOPT, and init treats that as
 * fatal to creating a socket: "Failed to set SO_PASSCRED 'lmkd'".
 *
 * What is checked:
 *
 *   - a socketpair of SOCK_SEQPACKET still keeps its message boundaries. That
 *     is what the datagram substitution was for and it must not be lost.
 *   - a SOCK_SEQPACKET socket can bind, listen, accept and connect. That is
 *     what the substitution cost.
 *   - SO_PASSCRED can be set and read back.
 *   - and it does something: a message received on such a socket carries
 *     SCM_CREDENTIALS naming the sender. Setting an option that changes what
 *     the guest sees and then not changing it would be the worse failure -
 *     silent, and only discovered by whatever trusted the credentials.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept4 242
#define SYS_connect 203
#define SYS_sendto 206
#define SYS_recvmsg 212
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define SOL_SOCKET 1
#define SO_PASSCRED 16
#define SCM_CREDENTIALS 2
#define SIGCHLD 17

struct l_sockaddr_un { unsigned short sun_family; char sun_path[108]; };
struct l_iovec { void *base; unsigned long len; };
struct l_msghdr {
  void *name; unsigned int namelen; unsigned int _pad;
  struct l_iovec *iov; unsigned long iovlen;
  void *control; unsigned long controllen;
  unsigned int flags; unsigned int _pad2;
};
struct l_cmsghdr { unsigned long len; int level; int type; };
struct l_ucred { unsigned int pid, uid, gid; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void setpath(struct l_sockaddr_un *a, const char *p){
  a->sun_family = AF_UNIX;
  int i = 0; while (p[i]) { a->sun_path[i] = p[i]; i++; }
  while (i < 108) a->sun_path[i++] = 0;
}
#define SPATH "/seqdir/s"

void _start(void)
{
  int sv[2];
  char buf[64];

  /* A socketpair keeps its boundaries: two sends, two receives, no coalescing. */
  want("socketpair(SOCK_SEQPACKET)",
       sys6(SYS_socketpair, AF_UNIX, SOCK_SEQPACKET, 0, (long) sv, 0, 0), 0);
  want("send the first message", sys6(SYS_write, sv[0], (long) "one", 3, 0,0,0), 3);
  want("send the second",        sys6(SYS_write, sv[0], (long) "two", 3, 0,0,0), 3);
  want("the first arrives alone", sys6(SYS_read, sv[1], (long) buf, sizeof buf, 0,0,0), 3);
  want("and so does the second",  sys6(SYS_read, sv[1], (long) buf, sizeof buf, 0,0,0), 3);
  sys6(SYS_close, sv[0], 0,0,0,0,0);
  sys6(SYS_close, sv[1], 0,0,0,0,0);

  /* A SOCK_SEQPACKET socket can be listened on, which is what lmkd needs. */
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/seqdir", 0755, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) SPATH, 0, 0,0,0);
  int ls = (int) sys6(SYS_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0,0,0);
  want("socket(SOCK_SEQPACKET)", ls >= 0, 1);
  struct l_sockaddr_un a;
  setpath(&a, SPATH);
  want("bind", sys6(SYS_bind, ls, (long)&a, sizeof a, 0,0,0), 0);
  long lr = sys6(SYS_listen, ls, 4, 0,0,0,0);
  want("listen", lr, 0);
  if (lr != 0) {
    /* Nothing below can work, and waiting for a connection that cannot be
     * accepted would hang rather than report - which is no better than the
     * bug this is here to catch. */
    put("seqcred failed\n");
    sys6(SYS_exit_group, 1, 0,0,0,0,0);
  }

  /* And it can be asked to report who is on the other end of each message. */
  int on = 1;
  want("setsockopt(SO_PASSCRED)",
       sys6(SYS_setsockopt, ls, SOL_SOCKET, SO_PASSCRED, (long)&on, sizeof on, 0), 0);
  int back = 0; unsigned int blen = sizeof back;
  want("getsockopt(SO_PASSCRED)",
       sys6(SYS_getsockopt, ls, SOL_SOCKET, SO_PASSCRED, (long)&back, (long)&blen, 0), 0);
  want("and it reads back set", back, 1);

  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    int c = (int) sys6(SYS_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0,0,0);
    struct l_sockaddr_un ca;
    setpath(&ca, SPATH);
    if (sys6(SYS_connect, c, (long)&ca, sizeof ca, 0,0,0) != 0)
      sys6(SYS_exit_group, 1, 0,0,0,0,0);
    sys6(SYS_write, c, (long) "hello", 5, 0,0,0);
    sys6(SYS_read, c, (long) &on, 1, 0,0,0);      /* hold it open */
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }
  want("fork", kid > 0, 1);

  int cs = (int) sys6(SYS_accept4, ls, 0, 0, 0, 0, 0);
  want("accept", cs >= 0, 1);
  if (cs >= 0) {
    /* The accepted socket wants credentials too - the option is per socket. */
    sys6(SYS_setsockopt, cs, SOL_SOCKET, SO_PASSCRED, (long)&on, sizeof on, 0);

    char cbuf[64];
    struct l_iovec iov = { buf, sizeof buf };
    struct l_msghdr m;
    for (unsigned i = 0; i < sizeof m; i++) ((char *)&m)[i] = 0;
    m.iov = &iov; m.iovlen = 1;
    m.control = cbuf; m.controllen = sizeof cbuf;
    long n = sys6(SYS_recvmsg, cs, (long)&m, 0, 0, 0, 0);
    want("recvmsg", n, 5);

    struct l_cmsghdr *c = (struct l_cmsghdr *) cbuf;
    want("a control message came with it", m.controllen >= sizeof *c ? 1 : 0, 1);
    if (m.controllen >= sizeof *c) {
      want("at the socket level", c->level, SOL_SOCKET);
      want("and it is the credentials", c->type, SCM_CREDENTIALS);
      struct l_ucred *u = (struct l_ucred *) (cbuf + sizeof *c);
      want("naming a real pid", u->pid != 0 ? 1 : 0, 1);
      want("and our own user", u->uid, (long) sys6(SYS_getuid, 0,0,0,0,0,0));
    }
    sys6(SYS_close, cs, 0,0,0,0,0);
  }
  long status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);

  sys6(SYS_close, ls, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) SPATH, 0, 0,0,0);
  put(fails == 0 ? "seqcred ok\n" : "seqcred failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
