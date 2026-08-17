/* freestanding: AF_NETLINK, which nabi had no address family for at all.
 *
 * socket(AF_NETLINK, ...) was EAFNOSUPPORT, so anything that asks the kernel
 * about the machine's network stopped there - `ip` for every subcommand
 * including the ones that only look, and glibc's getifaddrs, which is netlink
 * underneath and is reached by far more than networking code.
 *
 * What is checked:
 *
 *   - the socket opens, binds, and knows its own name. A netlink socket's name
 *     is a sockaddr_nl and Darwin has no such thing, so getsockname has to
 *     build the answer rather than translate one.
 *   - MSG_PEEK|MSG_TRUNC reports the size of a reply that does not fit. This is
 *     how every netlink reader sizes its buffer, and it is the one that looked
 *     like something else: Linux's MSG_TRUNC is an input flag meaning "tell me
 *     how big it was", Darwin's is an output flag meaning "some was lost", and
 *     mapping them onto each other returned the number of bytes that fitted -
 *     zero, for the empty buffer a reader peeks with. iproute2 reads 0 as the
 *     socket having closed and prints "EOF on netlink".
 *   - a dump comes back as a run of RTM_NEWLINK ending in NLMSG_DONE, and at
 *     least one of them names an interface. A reply that parsed but described
 *     nothing would pass a check that only counted bytes.
 *   - creating a link is refused with EPERM, in an NLMSG_ERROR. A guest here
 *     has no privilege over the host's interfaces, and the refusal has to reach
 *     the caller as netlink's own error rather than as a broken socket.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_socket      198
#define SYS_bind        200
#define SYS_getsockname 204
#define SYS_sendto      206
#define SYS_recvfrom    207

#define AF_NETLINK       16
#define SOCK_RAW          3
#define NETLINK_ROUTE     0
#define MSG_PEEK          2
#define MSG_TRUNC      0x20

#define NLM_F_REQUEST     1
#define NLM_F_MULTI       2
#define NLM_F_ACK         4
#define NLM_F_DUMP    0x300
#define NLM_F_CREATE  0x400
#define NLM_F_EXCL    0x200

#define NLMSG_ERROR       2
#define NLMSG_DONE        3
#define RTM_NEWLINK      16
#define RTM_GETLINK      18
#define IFLA_IFNAME       3
#define EPERM             1

struct sockaddr_nl { unsigned short family, pad; unsigned pid, groups; };
struct nlmsghdr { unsigned len; unsigned short type, flags; unsigned seq, pid; };
struct ifinfomsg { unsigned char family, pad; unsigned short type;
                   int index; unsigned flags, change; };
struct rtattr { unsigned short len, type; };
struct nlmsgerr { int error; struct nlmsghdr msg; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("netlink FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

#define ALIGN4(n) (((n) + 3) & ~3u)

static char reply[65536];
static char req[128];

void _start(void)
{
  long r;

  long fd = sys6(SYS_socket, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, 0, 0, 0);
  if (fd < 0) fail("socket(AF_NETLINK)", fd, 0);

  struct sockaddr_nl sa;
  sa.family = AF_NETLINK; sa.pad = 0; sa.pid = 0; sa.groups = 0;
  if ((r = sys6(SYS_bind, fd, (long) &sa, sizeof sa, 0, 0, 0)) != 0)
    fail("bind", r, 0);

  /* Its own name, which has to be a sockaddr_nl and not the unix address of
   * whatever descriptor is underneath. */
  struct sockaddr_nl me; me.family = 0; me.pid = 0;
  int melen = sizeof me;
  if ((r = sys6(SYS_getsockname, fd, (long) &me, (long) &melen, 0, 0, 0)) != 0)
    fail("getsockname", r, 0);
  if (me.family != AF_NETLINK) fail("getsockname family", me.family, AF_NETLINK);
  if (melen != (int) sizeof me) fail("getsockname length", melen, (int) sizeof me);
  if (me.pid == 0) fail("getsockname port id", me.pid, 1);

  /* Ask for every link. */
  struct nlmsghdr *h = (struct nlmsghdr *) req;
  struct ifinfomsg *ii = (struct ifinfomsg *) (req + sizeof *h);
  for (unsigned i = 0; i < sizeof *h + sizeof *ii; i++) req[i] = 0;
  h->len = sizeof *h + sizeof *ii;
  h->type = RTM_GETLINK;
  h->flags = NLM_F_REQUEST | NLM_F_DUMP;
  h->seq = 1;
  h->pid = 0;
  if ((r = sys6(SYS_sendto, fd, (long) req, h->len, 0, 0, 0)) != (long) h->len)
    fail("sendto RTM_GETLINK", r, h->len);

  /* How big is it? A peek with nowhere to put it must still say. */
  long peeked = sys6(SYS_recvfrom, fd, (long) reply, 0, MSG_PEEK | MSG_TRUNC, 0, 0);
  if (peeked <= 0)
    fail("MSG_PEEK|MSG_TRUNC size of a reply that does not fit", peeked, 1);

  long got = sys6(SYS_recvfrom, fd, (long) reply, sizeof reply, 0, 0, 0);
  if (got <= 0) fail("recvfrom of the dump", got, 1);
  if (got != peeked) fail("the peeked size against what was read", peeked, got);

  /* Walk it: at least one named link, and a DONE at the end. */
  int links = 0, named = 0, done = 0;
  unsigned off = 0;
  while (off + sizeof(struct nlmsghdr) <= (unsigned) got) {
    struct nlmsghdr *m = (struct nlmsghdr *) (reply + off);
    if (m->len < sizeof *m || off + m->len > (unsigned) got) break;
    if (m->type == NLMSG_DONE) { done = 1; break; }
    if (m->type == RTM_NEWLINK) {
      links++;
      if (!(m->flags & NLM_F_MULTI))
        fail("a dump message without NLM_F_MULTI", m->flags, NLM_F_MULTI);
      unsigned ao = sizeof *m + sizeof(struct ifinfomsg);
      while (ao + sizeof(struct rtattr) <= m->len) {
        struct rtattr *a = (struct rtattr *) (reply + off + ao);
        if (a->len < sizeof *a || ao + a->len > m->len) break;
        if (a->type == IFLA_IFNAME &&
            a->len > sizeof *a &&
            *((char *) a + sizeof *a) != '\0')
          named++;
        ao += ALIGN4(a->len);
      }
    }
    off += ALIGN4(m->len);
  }
  if (links == 0) fail("links in the dump", links, 1);
  if (named == 0) fail("links carrying a name", named, 1);
  if (!done) fail("NLMSG_DONE ending the dump", done, 1);

  /* Creating one is refused, and the refusal arrives as netlink's own error. */
  for (unsigned i = 0; i < sizeof *h + sizeof *ii; i++) req[i] = 0;
  h->len = sizeof *h + sizeof *ii;
  h->type = RTM_NEWLINK;
  h->flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  h->seq = 2;
  if ((r = sys6(SYS_sendto, fd, (long) req, h->len, 0, 0, 0)) != (long) h->len)
    fail("sendto RTM_NEWLINK", r, h->len);
  got = sys6(SYS_recvfrom, fd, (long) reply, sizeof reply, 0, 0, 0);
  if (got < (long) (sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr)))
    fail("the reply to RTM_NEWLINK", got, 1);
  struct nlmsghdr *m = (struct nlmsghdr *) reply;
  if (m->type != NLMSG_ERROR) fail("reply type for RTM_NEWLINK", m->type, NLMSG_ERROR);
  struct nlmsgerr *e = (struct nlmsgerr *) (reply + sizeof *m);
  if (e->error != -EPERM) fail("the error creating a link", e->error, -EPERM);
  if (e->msg.seq != 2) fail("the sequence echoed in the error", e->msg.seq, 2);

  put("netlink ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
