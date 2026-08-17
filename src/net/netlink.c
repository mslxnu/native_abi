/*
 * Netlink: the socket a Linux program asks the kernel about itself through.
 *
 * There is no host counterpart to translate to. Darwin answers some of the same
 * questions - getifaddrs, a routing socket, a pile of ioctls - but nothing on
 * this side speaks the protocol, and the protocol is the interface: a program
 * does not ask for "the interface list", it sends an RTM_GETLINK and parses
 * what comes back. So the protocol is what is implemented here, and the answers
 * are assembled from what the host does know.
 *
 * Everything reached for this. glibc's getifaddrs is netlink, so anything
 * enumerating interfaces failed before any of it got to a network. `ip` is
 * netlink for every subcommand, including the ones that only look.
 *
 * The descriptor is a socketpair, the same trick eventfd uses next door: the
 * guest holds one end, nabi holds the other, and a reply is written into it. A
 * netlink socket is read like any other, so read, recv, poll, select and epoll
 * all work without knowing any of this is here - and they work on the *guest's*
 * end, which is a real host descriptor. Only the sending side is intercepted,
 * because that is the only side with a request in it.
 *
 * What is served and what is not, stated plainly rather than discovered:
 *
 *   - RTM_GETLINK and RTM_GETADDR, dumped from the host's own interfaces. This
 *     is what `ip link show`, `ip addr show` and getifaddrs need, and it is the
 *     large majority of what asks.
 *
 *   - Anything that would *change* the host's network - RTM_NEWLINK creating a
 *     device, RTM_DELLINK, RTM_NEWADDR - is refused with EPERM. A guest here is
 *     an ordinary macOS process; it has no netlink to be privileged on, and
 *     creating a real host interface on its say-so is not something this should
 *     do quietly. waydroid asks for a `waydroid0` bridge and will be told no,
 *     which is a truthful answer and a different one from "netlink does not
 *     exist".
 *
 *   - Other protocols - uevent, audit, sock_diag - open and stay silent. That
 *     is what a socket bound to a group nothing publishes on looks like, and it
 *     is what a caller that subscribes and waits should see. Refusing the open
 *     instead sends callers down error paths for a facility that has no events
 *     rather than no implementation.
 */
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "util/khash.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/netlink.h"
#include "linux/socket.h"

struct netlink_state {
  int      reply_fd;    /* the end nabi keeps; the guest never sees it */
  int      protocol;
  uint32_t portid;      /* what bind settled on, or what was assigned */
  uint32_t groups;
  bool     bound;
};

KHASH_MAP_INIT_INT(nlsk, struct netlink_state)
static khash_t(nlsk) *netlinks;

/* NULL unless `fd` is one of ours, which is also the "is this netlink" test
 * every hook uses. */
static struct netlink_state *
netlink_lookup(int fd)
{
  if (netlinks == NULL)
    return NULL;
  khiter_t k = kh_get(nlsk, netlinks, fd);
  return k == kh_end(netlinks) ? NULL : &kh_value(netlinks, k);
}

bool
netlink_is(int fd)
{
  return netlink_lookup(fd) != NULL;
}

void
netlink_close(int fd)
{
  if (netlinks == NULL)
    return;
  khiter_t k = kh_get(nlsk, netlinks, fd);
  if (k == kh_end(netlinks))
    return;
  close(kh_value(netlinks, k).reply_fd);
  kh_del(nlsk, netlinks, k);
}

/* ------------------------------------------------------------------------
 * Building a reply.
 *
 * A dump is a run of messages ending in NLMSG_DONE, every one of them carrying
 * NLM_F_MULTI so the reader knows more is coming. The whole run is assembled
 * before any of it is written, because a reader is entitled to see a complete
 * message per read and a partial write would hand it half a header.
 * ------------------------------------------------------------------------ */

struct nlbuf {
  uint8_t *p;
  size_t   len, cap;
  bool     overflow;
};

static bool
nlbuf_room(struct nlbuf *b, size_t n)
{
  if (b->len + n <= b->cap)
    return true;
  size_t want = b->cap ? b->cap * 2 : 4096;
  while (want < b->len + n)
    want *= 2;
  uint8_t *q = realloc(b->p, want);
  if (q == NULL) {
    b->overflow = true;
    return false;
  }
  b->p = q;
  b->cap = want;
  return true;
}

static void *
nlbuf_put(struct nlbuf *b, size_t n)
{
  size_t aligned = LINUX_NLMSG_ALIGN(n);
  if (!nlbuf_room(b, aligned))
    return NULL;
  void *at = b->p + b->len;
  memset(at, 0, aligned);
  b->len += aligned;
  return at;
}

/* Start a message; the header's length is filled in when it is closed, since
 * the attributes that follow are what decide it. */
static struct l_nlmsghdr *
nlmsg_begin(struct nlbuf *b, uint16_t type, uint16_t flags, uint32_t seq,
            uint32_t portid, size_t payload)
{
  size_t off = b->len;
  struct l_nlmsghdr *h = nlbuf_put(b, LINUX_NLMSG_HDRLEN + payload);
  if (h == NULL)
    return NULL;
  h->nlmsg_type = type;
  h->nlmsg_flags = flags;
  h->nlmsg_seq = seq;
  h->nlmsg_pid = portid;
  h->nlmsg_len = (uint32_t) (b->len - off);
  return h;
}

/* The header may have moved: appending attributes can reallocate. */
static void
nlmsg_end(struct nlbuf *b, size_t off)
{
  struct l_nlmsghdr *h = (struct l_nlmsghdr *) (b->p + off);
  h->nlmsg_len = (uint32_t) (b->len - off);
}

static bool
nla_put(struct nlbuf *b, uint16_t type, const void *data, uint16_t len)
{
  struct l_rtattr *a = nlbuf_put(b, sizeof *a + len);
  if (a == NULL)
    return false;
  a->rta_type = type;
  a->rta_len = (uint16_t) (sizeof *a + len);
  memcpy((uint8_t *) a + sizeof *a, data, len);
  return true;
}

static bool
nla_put_u32(struct nlbuf *b, uint16_t type, uint32_t v)
{
  return nla_put(b, type, &v, sizeof v);
}

static bool
nla_put_u8(struct nlbuf *b, uint16_t type, uint8_t v)
{
  return nla_put(b, type, &v, sizeof v);
}

static bool
nla_put_str(struct nlbuf *b, uint16_t type, const char *s)
{
  return nla_put(b, type, s, (uint16_t) (strlen(s) + 1));
}

/* ------------------------------------------------------------------------
 * The host's interfaces, in Linux's terms.
 * ------------------------------------------------------------------------ */

/* Darwin's IFF_* and Linux's agree on the low bits by history, but not on all
 * of them, and a guest reading ifi_flags is reading Linux's. */
static uint32_t
if_flags_to_linux(unsigned df)
{
  uint32_t lf = 0;
  if (df & IFF_UP)          lf |= LINUX_IFF_UP;
  if (df & IFF_BROADCAST)   lf |= LINUX_IFF_BROADCAST;
  if (df & IFF_DEBUG)       lf |= LINUX_IFF_DEBUG;
  if (df & IFF_LOOPBACK)    lf |= LINUX_IFF_LOOPBACK;
  if (df & IFF_POINTOPOINT) lf |= LINUX_IFF_POINTOPOINT;
  if (df & IFF_NOARP)       lf |= LINUX_IFF_NOARP;
  if (df & IFF_PROMISC)     lf |= LINUX_IFF_PROMISC;
  if (df & IFF_RUNNING)     lf |= LINUX_IFF_RUNNING;
  if (df & IFF_MULTICAST)   lf |= LINUX_IFF_MULTICAST;
  return lf;
}

static int
if_mtu(const char *name)
{
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    return 1500;
  struct ifreq r;
  memset(&r, 0, sizeof r);
  strlcpy(r.ifr_name, name, sizeof r.ifr_name);
  int mtu = ioctl(s, SIOCGIFMTU, &r) == 0 ? r.ifr_mtu : 1500;
  close(s);
  return mtu;
}

/* One RTM_NEWLINK per interface, which is what a GETLINK dump is made of. */
static void
dump_links(struct nlbuf *b, uint32_t seq, uint32_t portid)
{
  struct ifaddrs *ifa0;
  if (getifaddrs(&ifa0) < 0)
    return;

  /* getifaddrs reports an interface once per address; a link dump wants it
   * once. The link-level entry is the one carrying the hardware address, so
   * that is the one taken, and an interface without one is taken on its first
   * appearance instead. */
  for (struct ifaddrs *ifa = ifa0; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
      continue;

    struct sockaddr_dl *dl = (struct sockaddr_dl *) ifa->ifa_addr;
    unsigned idx = if_nametoindex(ifa->ifa_name);
    if (idx == 0)
      continue;

    size_t off = b->len;
    struct l_ifinfomsg *ii =
      (struct l_ifinfomsg *) ((uint8_t *)
        nlmsg_begin(b, LINUX_RTM_NEWLINK, LINUX_NLM_F_MULTI, seq, portid,
                    sizeof *ii) + LINUX_NLMSG_HDRLEN);
    if (ii == NULL)
      break;
    ii->ifi_family = 0;         /* AF_UNSPEC, as the kernel sends */
    ii->ifi_type = (ifa->ifa_flags & IFF_LOOPBACK) ? LINUX_ARPHRD_LOOPBACK
                 : dl->sdl_alen == 6               ? LINUX_ARPHRD_ETHER
                 :                                   LINUX_ARPHRD_NONE;
    ii->ifi_index = (int32_t) idx;
    ii->ifi_flags = if_flags_to_linux(ifa->ifa_flags);
    ii->ifi_change = 0;

    nla_put_str(b, LINUX_IFLA_IFNAME, ifa->ifa_name);
    nla_put_u32(b, LINUX_IFLA_MTU, (uint32_t) if_mtu(ifa->ifa_name));
    if (dl->sdl_alen > 0)
      nla_put(b, LINUX_IFLA_ADDRESS, LLADDR(dl), dl->sdl_alen);
    nla_put_u32(b, LINUX_IFLA_TXQLEN, 1000);
    nla_put_u8(b, LINUX_IFLA_OPERSTATE,
               (ifa->ifa_flags & IFF_RUNNING) ? LINUX_IF_OPER_UP
                                              : LINUX_IF_OPER_DOWN);
    nla_put_u8(b, LINUX_IFLA_LINKMODE, 0);
    nla_put_u32(b, LINUX_IFLA_GROUP, 0);
    nlmsg_end(b, off);
  }
  freeifaddrs(ifa0);
}

/* How many leading one-bits a netmask has, which is what Linux reports instead
 * of the mask itself. */
static uint8_t
prefix_len(const struct sockaddr *mask)
{
  if (mask == NULL)
    return 0;
  const uint8_t *p;
  size_t n;
  if (mask->sa_family == AF_INET) {
    p = (const uint8_t *) &((const struct sockaddr_in *) mask)->sin_addr;
    n = 4;
  } else if (mask->sa_family == AF_INET6) {
    p = (const uint8_t *) &((const struct sockaddr_in6 *) mask)->sin6_addr;
    n = 16;
  } else {
    return 0;
  }
  uint8_t bits = 0;
  for (size_t i = 0; i < n; i++) {
    if (p[i] == 0xff) { bits += 8; continue; }
    uint8_t v = p[i];
    while (v & 0x80) { bits++; v = (uint8_t) (v << 1); }
    break;
  }
  return bits;
}

static void
dump_addrs(struct nlbuf *b, uint32_t seq, uint32_t portid, uint8_t want_family)
{
  struct ifaddrs *ifa0;
  if (getifaddrs(&ifa0) < 0)
    return;

  for (struct ifaddrs *ifa = ifa0; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    int df = ifa->ifa_addr->sa_family;
    if (df != AF_INET && df != AF_INET6)
      continue;
    uint8_t lfam = df == AF_INET ? LINUX_AF_INET : LINUX_AF_INET6;
    if (want_family != 0 && want_family != lfam)
      continue;
    unsigned idx = if_nametoindex(ifa->ifa_name);
    if (idx == 0)
      continue;

    const void *raw;
    uint16_t rawlen;
    if (df == AF_INET) {
      raw = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
      rawlen = 4;
    } else {
      raw = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
      rawlen = 16;
    }

    size_t off = b->len;
    struct l_ifaddrmsg *ia =
      (struct l_ifaddrmsg *) ((uint8_t *)
        nlmsg_begin(b, LINUX_RTM_NEWADDR, LINUX_NLM_F_MULTI, seq, portid,
                    sizeof *ia) + LINUX_NLMSG_HDRLEN);
    if (ia == NULL)
      break;
    ia->ifa_family = lfam;
    ia->ifa_prefixlen = prefix_len(ifa->ifa_netmask);
    ia->ifa_flags = 0;
    ia->ifa_scope = (ifa->ifa_flags & IFF_LOOPBACK) ? LINUX_RT_SCOPE_HOST
                                                    : LINUX_RT_SCOPE_UNIVERSE;
    ia->ifa_index = idx;

    /* IFA_ADDRESS and IFA_LOCAL differ only on a point-to-point link, and
     * getifaddrs does not distinguish them here. */
    nla_put(b, LINUX_IFA_ADDRESS, raw, rawlen);
    nla_put(b, LINUX_IFA_LOCAL, raw, rawlen);
    nla_put_str(b, LINUX_IFA_LABEL, ifa->ifa_name);
    if (df == AF_INET && ifa->ifa_broadaddr &&
        ifa->ifa_broadaddr->sa_family == AF_INET)
      nla_put(b, LINUX_IFA_BROADCAST,
              &((struct sockaddr_in *) ifa->ifa_broadaddr)->sin_addr, 4);
    nla_put_u32(b, LINUX_IFA_FLAGS, 0);
    nlmsg_end(b, off);
  }
  freeifaddrs(ifa0);
}

static void
put_done(struct nlbuf *b, uint32_t seq, uint32_t portid)
{
  nlmsg_begin(b, LINUX_NLMSG_DONE, LINUX_NLM_F_MULTI, seq, portid,
              sizeof(int32_t));
}

/* An error reply, which is also how a request is acknowledged: error 0 is the
 * ACK Linux sends for a request that carried NLM_F_ACK. */
static void
put_error(struct nlbuf *b, const struct l_nlmsghdr *req, int32_t err,
          uint32_t portid)
{
  size_t off = b->len;
  struct l_nlmsgerr *e =
    (struct l_nlmsgerr *) ((uint8_t *)
      nlmsg_begin(b, LINUX_NLMSG_ERROR, 0, req->nlmsg_seq, portid,
                  sizeof *e) + LINUX_NLMSG_HDRLEN);
  if (e == NULL)
    return;
  e->error = err;
  e->msg = *req;
  nlmsg_end(b, off);
}

/* ------------------------------------------------------------------------
 * Requests.
 * ------------------------------------------------------------------------ */

static void
handle_route(struct netlink_state *nl, const struct l_nlmsghdr *h,
             const void *payload, size_t paylen, struct nlbuf *out)
{
  bool dump = (h->nlmsg_flags & LINUX_NLM_F_DUMP) == LINUX_NLM_F_DUMP;

  switch (h->nlmsg_type) {
  case LINUX_RTM_GETLINK:
    if (!dump) {
      /* A single-link query is answered by the dump too: a caller filtering by
       * index gets its answer and ignores the rest, and the alternative is to
       * refuse a request that is ordinary. */
      dump_links(out, h->nlmsg_seq, nl->portid);
      put_done(out, h->nlmsg_seq, nl->portid);
      return;
    }
    dump_links(out, h->nlmsg_seq, nl->portid);
    put_done(out, h->nlmsg_seq, nl->portid);
    return;

  case LINUX_RTM_GETADDR: {
    uint8_t fam = 0;
    if (paylen >= sizeof(struct l_ifaddrmsg))
      fam = ((const struct l_ifaddrmsg *) payload)->ifa_family;
    else if (paylen >= sizeof(struct l_ifinfomsg))
      fam = ((const struct l_ifinfomsg *) payload)->ifi_family;
    dump_addrs(out, h->nlmsg_seq, nl->portid, fam);
    put_done(out, h->nlmsg_seq, nl->portid);
    return;
  }

  case LINUX_RTM_GETROUTE:
  case LINUX_RTM_GETNEIGH:
    /* Nothing to report rather than a failure: an empty dump is a valid
     * answer, and a caller that wanted the routing table gets an empty one
     * instead of an error it has to interpret. */
    put_done(out, h->nlmsg_seq, nl->portid);
    return;

  /*
   * The ones that would change the host's network. A guest here is an ordinary
   * macOS process with no privilege over the machine's interfaces, and EPERM is
   * both true and the answer Linux gives an unprivileged caller - so the
   * program's own "you need to be root" path is the one that runs.
   */
  case LINUX_RTM_NEWLINK:
  case LINUX_RTM_DELLINK:
  case LINUX_RTM_SETLINK:
  case LINUX_RTM_NEWADDR:
  case LINUX_RTM_DELADDR:
  case LINUX_RTM_NEWROUTE:
  case LINUX_RTM_DELROUTE:
  case LINUX_RTM_NEWNEIGH:
  case LINUX_RTM_DELNEIGH:
    put_error(out, h, -LINUX_EPERM, nl->portid);
    return;

  default:
    put_error(out, h, -LINUX_EOPNOTSUPP, nl->portid);
    return;
  }
}

/*
 * A send is a stream of messages, and every one of them is answered before the
 * call returns - a netlink socket is not a queue nabi services later, and a
 * caller that sends and then reads must find the reply already there.
 */
int
netlink_send(int fd, const void *buf, size_t len)
{
  struct netlink_state *nl = netlink_lookup(fd);
  if (nl == NULL)
    return -LINUX_ENOTSOCK;

  struct nlbuf out = { 0 };
  const uint8_t *p = buf;
  size_t off = 0;
  bool any = false;

  while (off + LINUX_NLMSG_HDRLEN <= len) {
    const struct l_nlmsghdr *h = (const struct l_nlmsghdr *) (p + off);
    if (h->nlmsg_len < (uint32_t) LINUX_NLMSG_HDRLEN ||
        off + h->nlmsg_len > len)
      break;
    any = true;

    const void *payload = p + off + LINUX_NLMSG_HDRLEN;
    size_t paylen = h->nlmsg_len - LINUX_NLMSG_HDRLEN;

    if (nl->protocol == LINUX_NETLINK_ROUTE) {
      handle_route(nl, h, payload, paylen, &out);
    } else if (h->nlmsg_flags & LINUX_NLM_F_ACK) {
      /* Nothing here speaks the other protocols, and a request on one is
       * acknowledged as refused rather than left to time out. */
      put_error(&out, h, -LINUX_EOPNOTSUPP, nl->portid);
    }

    off += LINUX_NLMSG_ALIGN(h->nlmsg_len);
  }

  if (!any) {
    free(out.p);
    return -LINUX_EINVAL;
  }
  if (out.overflow) {
    free(out.p);
    return -LINUX_ENOBUFS;
  }

  if (out.len > 0) {
    ssize_t w = write(nl->reply_fd, out.p, out.len);
    if (w < 0) {
      int e = errno;
      free(out.p);
      return -darwin_to_linux_errno(e);
    }
  }
  free(out.p);
  return (int) len;             /* the whole request was consumed */
}

/*
 * bind. The port id is the guest's to choose, and 0 means "assign me one" -
 * Linux uses the thread id for the first socket a process binds, and the only
 * property that matters is that it is unique and not zero.
 */
int
netlink_bind(int fd, const void *addr, size_t addrlen)
{
  struct netlink_state *nl = netlink_lookup(fd);
  if (nl == NULL)
    return -LINUX_ENOTSOCK;
  if (addrlen < sizeof(struct l_sockaddr_nl))
    return -LINUX_EINVAL;

  const struct l_sockaddr_nl *snl = addr;
  if (snl->nl_family != LINUX_AF_NETLINK)
    return -LINUX_EINVAL;

  nl->portid = snl->nl_pid ? snl->nl_pid : (uint32_t) getpid();
  nl->groups = snl->nl_groups;
  nl->bound = true;
  return 0;
}

int
netlink_getsockname(int fd, void *addr, size_t *addrlen)
{
  struct netlink_state *nl = netlink_lookup(fd);
  if (nl == NULL)
    return -LINUX_ENOTSOCK;

  struct l_sockaddr_nl snl;
  memset(&snl, 0, sizeof snl);
  snl.nl_family = LINUX_AF_NETLINK;
  /* An unbound socket is given its port id here, which is what Linux does: the
   * kernel binds it implicitly on first use. */
  if (!nl->bound)
    nl->portid = (uint32_t) getpid();
  snl.nl_pid = nl->portid;
  snl.nl_groups = nl->groups;

  size_t n = *addrlen < sizeof snl ? *addrlen : sizeof snl;
  memcpy(addr, &snl, n);
  *addrlen = sizeof snl;
  return 0;
}

/*
 * Create one. Returns the guest's descriptor, already registered, or -errno.
 *
 * SOCK_RAW and SOCK_DGRAM are the two Linux accepts and it treats them alike;
 * anything else is ESOCKTNOSUPPORT, as there.
 */
int
netlink_socket(int type, int protocol, int flags)
{
  if (type != LINUX_SOCK_RAW && type != LINUX_SOCK_DGRAM)
    return -LINUX_ESOCKTNOSUPPORT;

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
    return -darwin_to_linux_errno(errno);

  /* SOCK_DGRAM on the pair, so a reader gets one message per read the way a
   * netlink reader expects - a stream pair would let two replies coalesce and
   * a short read would split a header. */
  if ((flags & LINUX_SOCK_NONBLOCK) && fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0)
    goto fail;
  if ((flags & LINUX_SOCK_CLOEXEC) && fcntl(sv[0], F_SETFD, FD_CLOEXEC) < 0)
    goto fail;

  /* A dump of a machine with many addresses is larger than the default. */
  int bufsz = 512 * 1024;
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz);

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(sv[0], (flags & LINUX_SOCK_CLOEXEC) != 0);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(sv[0]);
    close(sv[1]);
    return err;
  }

  if (netlinks == NULL)
    netlinks = kh_init(nlsk);
  int ret;
  khiter_t k = kh_put(nlsk, netlinks, sv[0], &ret);
  kh_value(netlinks, k) = (struct netlink_state){
    .reply_fd = sv[1],
    .protocol = protocol,
    .portid = 0,
    .groups = 0,
    .bound = false,
  };
  return sv[0];

fail:;
  int e = errno;
  close(sv[0]);
  close(sv[1]);
  return -darwin_to_linux_errno(e);
}
