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
#define SYS_ioctl        29
#define SYS_openat       56
#define SYS_close        57
#define SYS_read         63
#define SYS_unshare      97
#define SIOCGIFHWADDR 0x8927
#define IFLA_ADDRESS      1
#define ENODEV           19
#define EFAULT           14

#define AF_NETLINK       16
#define SOCK_RAW          3
#define SOCK_DGRAM      2
#define NETLINK_ROUTE     0
#define NETLINK_NETFILTER 12
#define NETLINK_AUDIT     9
#define NETLINK_UEVENT   15
#define EPROTONOSUPPORT  93
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
static char netdev[65536];
struct ifreq { char name[16]; unsigned short family; unsigned char data[22]; };

/* Read the built-in procfs to EOF, including on hosts without mSL/ProcFS. */
static void read_netdev(void)
{
  long fd = sys6(SYS_openat, -100, (long) "/proc/net/dev", 0, 0, 0, 0);
  if (fd < 0) fail("open /proc/net/dev", fd, 0);
  long used = 0, n;
  while ((n = sys6(SYS_read, fd, (long) (netdev + used),
                   sizeof netdev - 1 - used, 0, 0, 0)) > 0) {
    used += n;
    if (used == sizeof netdev - 1) fail("net/dev exceeds test buffer", used, 0);
  }
  if (n < 0) fail("read /proc/net/dev", n, 0);
  netdev[used] = 0;
  sys6(SYS_close, fd, 0,0,0,0,0);
}

/* Find a named row and check that a caller can read all 16 Linux counters. */
static void counters(const char *name, int zero)
{
  for (const char *p = netdev; *p; ) {
    while (*p == ' ') p++;
    int i = 0;
    while (name[i] && p[i] == name[i]) i++;
    if (!name[i] && p[i] == ':') {
      p += i + 1;
      for (int field = 0; field < 16; field++) {
        while (*p == ' ') p++;
        if (*p < '0' || *p > '9') fail("missing net/dev counter", field, 16);
        while (*p >= '0' && *p <= '9') {
          if (zero && *p != '0') fail("namespace traffic counter", *p - '0', 0);
          p++;
        }
      }
      while (*p == ' ') p++;
      if (*p != '\n') fail("extra net/dev counter", *p, '\n');
      return;
    }
    while (*p && *p != '\n') p++;
    if (*p) p++;
  }
  fail("netlink interface missing from net/dev", 0, 1);
}

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

  /*
   * A protocol nothing here can answer is refused at open, with the error a
   * kernel built without that subsystem gives.
   *
   * This is a regression check with a name on it. These used to open and then
   * answer every request with an error, which reads as the gentler choice and
   * is not: libaudit takes a successful open as the audit subsystem being
   * present, had no path for the error that came back, and PAM turned it into
   * "System error" - su would not run at all, which is every `msl login`.
   */
  { long bad = sys6(SYS_socket, AF_NETLINK, SOCK_RAW, NETLINK_AUDIT, 0, 0, 0);
    if (bad != -EPROTONOSUPPORT)
      fail("socket(NETLINK_AUDIT) on a system with no audit", bad, -EPROTONOSUPPORT); }

  /* The event multicast opens, because waiting on it is answerable: nothing
   * publishes, so nothing arrives. */
  { long ue = sys6(SYS_socket, AF_NETLINK, SOCK_RAW, NETLINK_UEVENT, 0, 0, 0);
    if (ue < 0)
      fail("socket(NETLINK_KOBJECT_UEVENT)", ue, 0); }

  /*
   * Connection tracking opens too, for the same reason the event multicast does:
   * netd subscribes to it and nothing here publishes, so nothing arrives. It binds
   * and sets a receive buffer and asks nothing further - which is why refusing it
   * cost so much. netd took the refusal as fatal and exited, init answered a dead
   * netd by restarting zygote, and zygote's onrestart killed surfaceflinger,
   * audioserver, cameraserver, media and wificond: thirty-two netd starts a boot,
   * with a hundred and fifty "service not found" lines underneath that were all one
   * cascade.
   */
  { long ct = sys6(SYS_socket, AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER, 0, 0, 0);
    if (ct < 0) {
      fail("socket(NETLINK_NETFILTER)", ct, 0);
    } else {
      /* Bound and sized, which is all netd does to it. */
      struct sockaddr_nl a;
      for (unsigned i = 0; i < sizeof a; i++) ((char *) &a)[i] = 0;
      a.family = AF_NETLINK;
      long r2 = sys6(SYS_bind, ct, (long) &a, sizeof a, 0, 0, 0);
      if (r2 != 0) fail("bind(NETLINK_NETFILTER)", r2, 0);

      /*
       * And a dump of what is being tracked is answered empty rather than refused.
       * That is what keeps admitting this protocol from repeating the libaudit
       * mistake above: nothing it is asked returns an error it has no path for.
       */
      struct nlmsghdr *dh = (struct nlmsghdr *) req;
      for (unsigned i = 0; i < sizeof *dh; i++) req[i] = 0;
      dh->len = sizeof *dh;
      dh->type = 0x101;          /* IPCTNL_MSG_CT_GET, in the conntrack subsystem */
      dh->flags = NLM_F_REQUEST | NLM_F_DUMP;
      dh->seq = 99;
      long sent = sys6(SYS_sendto, ct, (long) req, dh->len, 0, 0, 0);
      if (sent != (long) dh->len) {
        fail("sendto(NETLINK_NETFILTER dump)", sent, (long) dh->len);
      } else {
        long got = sys6(SYS_recvfrom, ct, (long) reply, sizeof reply, 0, 0, 0);
        if (got < (long) sizeof(struct nlmsghdr)) {
          fail("a dump answered nothing at all", got, (long) sizeof(struct nlmsghdr));
        } else {
          struct nlmsghdr *rh = (struct nlmsghdr *) reply;
          /* NLMSG_DONE is 3; an error would be NLMSG_ERROR, which is 2. */
          if (rh->type != 3)
            fail("a dump of an empty table should be NLMSG_DONE", rh->type, 3);
        }
      }
    }
  }

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
  read_netdev();
  long inet = sys6(SYS_socket, 2 /* AF_INET */, SOCK_DGRAM, 0, 0, 0, 0);
  if (inet < 0) fail("socket for interface ioctl", inet, 0);
  struct ifreq first = {0};
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
      const char *name = 0;
      const unsigned char *address = 0;
      unsigned addrlen = 0;
      while (ao + sizeof(struct rtattr) <= m->len) {
        struct rtattr *a = (struct rtattr *) (reply + off + ao);
        if (a->len < sizeof *a || ao + a->len > m->len) break;
        if (a->type == IFLA_IFNAME &&
            a->len > sizeof *a &&
            *((char *) a + sizeof *a) != '\0') {
          named++;
          name = (char *) a + sizeof *a;
        }
        if (a->type == IFLA_ADDRESS) {
          address = (unsigned char *) a + sizeof *a;
          addrlen = a->len - sizeof *a;
        }
        ao += ALIGN4(a->len);
      }
      if (!name) fail("link without a name", 0, 1);
      struct ifreq hw = {0};
      unsigned ni = 0;
      while (ni < sizeof hw.name - 1 && name[ni]) {
        hw.name[ni] = name[ni]; ni++;
      }
      if (links == 1) first = hw;
      if ((r = sys6(SYS_ioctl, inet, SIOCGIFHWADDR, (long) &hw, 0,0,0)) != 0)
        fail("SIOCGIFHWADDR for a netlink interface", r, 0);
      struct ifinfomsg *info = (struct ifinfomsg *) (m + 1);
      if (hw.family != info->type)
        fail("hardware type agrees with netlink", hw.family, info->type);
      for (unsigned i = 0; i < 14; i++) {
        unsigned char expected = i < addrlen ? address[i] : 0;
        if (hw.data[i] != expected)
          fail("hardware address agrees with netlink", hw.data[i], expected);
      }
      counters(hw.name, 0);
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

  if ((r = sys6(SYS_ioctl, inet, SIOCGIFHWADDR, 0, 0,0,0)) != -EFAULT)
    fail("hardware address with invalid buffer", r, -EFAULT);
  struct ifreq missing = { .name = "nabi-missing" };
  if ((r = sys6(SYS_ioctl, inet, SIOCGIFHWADDR, (long) &missing, 0,0,0)) != -ENODEV)
    fail("hardware address for missing interface", r, -ENODEV);
  sys6(SYS_close, inet, 0,0,0,0,0);

  /* The namespace must keep its isolated, zero-traffic loopback view. */
  if ((r = sys6(SYS_unshare, 0x40000000 /* CLONE_NEWNET */, 0,0,0,0,0)) != 0)
    fail("unshare network namespace", r, 0);
  inet = sys6(SYS_socket, 2 /* AF_INET */, SOCK_DGRAM, 0, 0, 0, 0);
  if (inet < 0) fail("socket in network namespace", inet, 0);
  read_netdev();
  counters("lo", 1);
  int rows = 0;
  for (const char *p = netdev; *p; p++) if (*p == ':') rows++;
  if (rows != 1) fail("namespace interface count", rows, 1);
  struct ifreq loopback = { .name = "lo" };
  if ((r = sys6(SYS_ioctl, inet, SIOCGIFHWADDR, (long) &loopback, 0,0,0)) != 0)
    fail("namespace loopback hardware address", r, 0);
  if (loopback.family != 772) fail("namespace loopback type", loopback.family, 772);
  for (unsigned i = 0; i < 14; i++)
    if (loopback.data[i]) fail("namespace loopback address", loopback.data[i], 0);
  if ((r = sys6(SYS_ioctl, inet, SIOCGIFHWADDR, (long) &first, 0,0,0)) != -ENODEV)
    fail("host interface hidden in namespace", r, -ENODEV);

  put("netlink ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
