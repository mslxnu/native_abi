#include "noah.h"
#include "namespace.h"
#include "common.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <fcntl.h>

#include "linux/common.h"
#include "linux/socket.h"
#include "linux/misc.h"

/*
 * A network namespace here is an *empty* one, and that is the whole of it.
 *
 * The earlier notes in this series refused this namespace, and the reasoning
 * held for what it addressed: making sockets *work* inside a namespace of their
 * own would mean a virtual network stack - addresses, routes, an interface,
 * something to carry packets between namespaces - which is a different program.
 * None of that is here and none of it is coming.
 *
 * But a network namespace on Linux does not start with a working network. It
 * starts with a loopback interface that is *down*, no addresses and no routes,
 * and nothing in it can reach anything until it is configured. Reaching that
 * state needs no stack at all - and it is the state `unshare -n` is used for,
 * which is to run something with no network.
 *
 * So that is what this provides, exactly and permanently: a namespace whose
 * network is empty. What it cannot do is let the guest configure its way out
 * again - `ip link set lo up`, a veth pair, an address - because that is where
 * the stack would have to begin.
 *
 * A bind is refused rather than allowed, and that is a deliberate divergence:
 * Linux lets a process bind the wildcard address in an empty namespace, but
 * here the socket is a Darwin socket and binding it would take a port on the
 * *host* - so two namespaces would collide with each other and with the Mac,
 * which is the opposite of the isolation being asked for. Refusing keeps the
 * guarantee; allowing would keep the letter of one call and break the point of
 * the feature.
 *
 * AF_UNIX is untouched. Pathname sockets belong to the filesystem and are
 * isolated by the mount namespace, not this one, so they go on working - which
 * is correct, and is what lets anything inside a network namespace still talk
 * to things on the same machine the way Linux does.
 */
static bool
netns_blocks(int family)
{
  if (!netns_active())
    return false;
  return family == LINUX_AF_INET || family == LINUX_AF_INET6;
}

/* The family a sockaddr the guest handed us names, before conversion. */
static int
guest_sa_family(const char *addr, size_t addrlen)
{
  if (addrlen < sizeof(unsigned short))
    return -1;
  return (int) ((const struct l_sockaddr *) addr)->sa_family;
}

DEFINE_SYSCALL(socket, int, family, int, type, int, protocol)
{
  int ret;
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd = syswrap(socket(linux_to_darwin_sa_family(family), type & ~(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC), protocol));
  ret = fd;
  if (fd < 0) {
    goto err;
  }

  int e;
  if (type & LINUX_SOCK_NONBLOCK) {
    e = syswrap(fcntl(fd, F_SETFL, O_NONBLOCK));
    if (e < 0) {
      ret = e;
      goto err;
    }
  }
  if (type & LINUX_SOCK_CLOEXEC) {
    e = syswrap(fcntl(fd, F_SETFD, FD_CLOEXEC));
    if (e < 0) {
      ret = e;
      goto err;
    }
  }
  e = register_fd(fd, type & LINUX_SOCK_CLOEXEC);
  if (e < 0) {
    close(fd);
    ret = e;
  }
  
err:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  
  return ret;
}

int
linux_to_darwin_sockaddr(struct sockaddr **sockaddr, const struct l_sockaddr *l_sockaddr, size_t l_sockaddr_len)
{
  if (l_sockaddr == NULL) {
    return -1;
  }

  /* Enough for what comes out, not for what went in. A guest sends exactly as
   * many bytes as its path needs, but an AF_UNIX path is rewritten below into
   * one inside the rootfs, which is longer - so the allocation has to be the
   * full sockaddr_un rather than the guest's length, or the translation writes
   * off the end of it. It did: the overflow corrupted the malloc heap, and the
   * failure surfaced as connect() spinning at 100% CPU inside free(). */
  size_t alloc_len = l_sockaddr_len;
  if (linux_to_darwin_sa_family(l_sockaddr->sa_family) == AF_UNIX &&
      alloc_len < sizeof(struct sockaddr_un))
    alloc_len = sizeof(struct sockaddr_un);

  *sockaddr = calloc(1, alloc_len);
  if (*sockaddr == NULL)
    return -1;

  memcpy(*sockaddr, l_sockaddr, l_sockaddr_len);
  assert(offsetof(struct sockaddr, sa_data) == offsetof(struct l_sockaddr, sa_data));
  (*sockaddr)->sa_family = linux_to_darwin_sa_family(l_sockaddr->sa_family);


  switch (linux_to_darwin_sa_family(l_sockaddr->sa_family)) {
  case AF_UNIX: {
    int slen;
    struct sockaddr_un *sockaddr_un = (struct sockaddr_un*)*sockaddr;

    if (sockaddr_un->sun_path[0] == '\0') {
      // Linux abstract namespace starts with NULL, which we do not support yet
      printk("Abstract namespace: %20s\n", &sockaddr_un->sun_path[1]);
      slen = strnlen(&sockaddr_un->sun_path[1], l_sockaddr_len - offsetof(struct sockaddr_un, sun_path) - 1);
    } else {
      /* A filesystem socket names a path, and a guest path means nothing to the
       * host: /etc/pacman.d/gnupg/S.gpg-agent is inside the rootfs, not at the
       * host's /etc. Untranslated, gpg-agent's bind came back ENOENT and gpg
       * never got an agent to talk to, so pacman could not verify a signature
       * and stopped dead with the keyring half-built. */
      char host_path[sizeof sockaddr_un->sun_path];
      if (guest_to_host_path(sockaddr_un->sun_path, host_path,
                             sizeof host_path) == 0) {
        /* strlcpy, so a path that does not fit is refused rather than
         * truncated into one that names something else. */
        if (strlcpy(sockaddr_un->sun_path, host_path,
                    sizeof sockaddr_un->sun_path) >=
            sizeof sockaddr_un->sun_path)
          goto err;
      }
      slen = strnlen(sockaddr_un->sun_path, sizeof sockaddr_un->sun_path);
    }
    if (offsetof(struct sockaddr_un, sun_path) + slen >
        sizeof(struct sockaddr_un)) {
      // Name too long
      goto err;
    }
    /* The length the kernel is given must cover the path this call will
     * actually use, which after translation is not the one the guest sent. */
    (*sockaddr)->sa_len =
        (unsigned char) (offsetof(struct sockaddr_un, sun_path) + slen + 1);
    break;
  }

  case AF_INET:
    (*sockaddr)->sa_len = sizeof(struct sockaddr_in);
    break;

  case AF_INET6:
    assert(l_sockaddr_len != sizeof(struct sockaddr_in6) - sizeof(uint32_t));
    // Fall through

  default:
    (*sockaddr)->sa_len = l_sockaddr_len;
    break;

  case -1:
    warnk("Unimplemented sa_family: 0x%x(%s)\n", l_sockaddr->sa_family, linux_sa_family_str(l_sockaddr->sa_family));
    goto err;
  }

  return 0;

err:
  free(*sockaddr);
  return -1;
}

void
darwin_to_linux_sockaddr(struct l_sockaddr *l_sockaddr, const struct sockaddr *sockaddr)
{
  if (sockaddr == NULL || l_sockaddr == NULL) {
    return;
  }
  assert((void*)l_sockaddr != (void*)sockaddr);
  memcpy(l_sockaddr, sockaddr, sockaddr->sa_len);
  l_sockaddr->sa_family = darwin_to_linux_sa_family(sockaddr->sa_family);
}

DEFINE_SYSCALL(connect, int, sockfd, gaddr_t, addr_ptr, uint64_t, addrlen)
{
  char *addr = malloc(addrlen);

  int r;
  if (copy_from_user(addr, addr_ptr, addrlen)) {
    r = -LINUX_EFAULT;
    goto err;
  }

  if (netns_blocks(guest_sa_family(addr, addrlen))) {
    r = -LINUX_ENETUNREACH;     /* no interface, no route: nothing to reach */
    goto err;
  }

  struct sockaddr *sockaddr;
  if (linux_to_darwin_sockaddr(&sockaddr, (struct l_sockaddr *) addr, addrlen) < 0) {
    r = -LINUX_EINVAL;
    goto err;
  }

  r = syswrap(connect(sockfd, sockaddr, sockaddr->sa_len));
  
  free(sockaddr);
err:
  free(addr);
  return r;
}

int
linux_to_darwin_sockopt_level(int level)
{
  switch (level) {
  case LINUX_SOL_SOCKET: return SOL_SOCKET;
  default: return level; // Other values are the same as OSX as long as they exist.
  };
}

int
to_host_sockopt_name(int name)
{
  switch (name) {
  case LINUX_SO_DEBUG:
    return SO_DEBUG;
  case LINUX_SO_REUSEADDR:
    return SO_REUSEADDR;
  case LINUX_SO_TYPE:
    return SO_TYPE;
  case LINUX_SO_ERROR:
    return SO_ERROR;
  case LINUX_SO_DONTROUTE:
    return SO_DONTROUTE;
  case LINUX_SO_BROADCAST:
    return SO_BROADCAST;
  case LINUX_SO_SNDBUF:
    return SO_SNDBUF;
  case LINUX_SO_RCVBUF:
    return SO_RCVBUF;
  case LINUX_SO_KEEPALIVE:
    return SO_KEEPALIVE;
  case LINUX_SO_OOBINLINE:
    return SO_OOBINLINE;
  case LINUX_SO_LINGER:
    return SO_LINGER;
  case LINUX_SO_RCVLOWAT:
    return SO_RCVLOWAT;
  case LINUX_SO_SNDLOWAT:
    return SO_SNDLOWAT;
  case LINUX_SO_RCVTIMEO:
    return SO_RCVTIMEO;
  case LINUX_SO_SNDTIMEO:
    return SO_SNDTIMEO;
  case LINUX_SO_TIMESTAMP:
    return SO_TIMESTAMP;
  case LINUX_SO_ACCEPTCONN:
    return SO_ACCEPTCONN;
  default:
    warnk("Unsupported sockopt name: 0x%x\n", name);
    return -1;
  }
}

/*
 * Is an option NABI cannot translate safe to accept and ignore?
 *
 * The ones that matter here only ask to be *told* things, or tune queueing.
 * IP_RECVERR asks for ICMP errors to be queued on a UDP socket; Darwin has no
 * equivalent, and a caller without it falls back on timing out. Not having it
 * is a worse experience, not a wrong one.
 *
 * Failing the call instead is what breaks. glibc's resolver sets IP_RECVERR on
 * its UDP socket and, when that errors, closes the socket and gives up - so
 * every lookup in the guest returns "Temporary failure in name resolution" and
 * nothing that resolves a hostname works at all. That is one unimplemented
 * option costing the guest all of DNS, and with it apt, wget and anything else
 * that reaches the network by name.
 *
 * Reporting success for something not done is a lie worth telling only where
 * the truth cannot be told and the difference is unobservable, so this is a
 * list rather than a blanket default: an option that changes what the guest
 * would *see* still has to fail honestly.
 */
static bool
sockopt_is_advisory(int level, int name)
{
  switch (level) {
  case LINUX_SOL_SOCKET:
    switch (name) {
    case 11:  /* SO_NO_CHECK - skip the UDP checksum */
    case 12:  /* SO_PRIORITY - queueing hint         */
    case 36:  /* SO_MARK     - firewall mark         */
      return true;
    }
    return false;
  case LINUX_IPPROTO_IP:
    return name == 11;    /* IP_RECVERR   - queue ICMP errors  */
  case LINUX_IPPROTO_IPV6:
    return name == 25;    /* IPV6_RECVERR - the v6 counterpart */
  default:
    return false;
  }
}

DEFINE_SYSCALL(setsockopt, int, fd, int, level, int, optname, gaddr_t, optval_ptr, uint, opt_len)
{
  int r;
  char *optval = malloc(opt_len);
  
  if (copy_from_user(optval, optval_ptr, opt_len)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  int host_name = to_host_sockopt_name(optname);
  if (host_name < 0 && sockopt_is_advisory(level, optname)) {
    r = 0;              /* accepted and ignored - see sockopt_is_advisory */
    goto out;
  }
  // Darwin's optval is compatible with that of Linux
  r = syswrap(setsockopt(fd, linux_to_darwin_sockopt_level(level), host_name, optval, opt_len));
out:
  free(optval);
  return r;
}

DEFINE_SYSCALL(getsockopt, int, fd, int, level, int, optname, gaddr_t, optval_ptr, gaddr_t, optlen_ptr)
{
  l_socklen_t l_optlen;
  if (copy_from_user(&l_optlen, optlen_ptr, sizeof l_optlen))
    return -LINUX_EFAULT;
  char *optval = malloc(l_optlen);
  unsigned int optlen = l_optlen;
  // Darwin's optval is compatible with that of Linux
  int r = syswrap(getsockopt(fd, linux_to_darwin_sockopt_level(level), to_host_sockopt_name(optname), optval, &optlen));
  if (r >= 0) {
    if (copy_to_user(optval_ptr, optval, optlen)) {
      r = -LINUX_EFAULT;
      goto out;
    }
    l_optlen = optlen;
    if (copy_to_user(optlen_ptr, &l_optlen, sizeof l_optlen)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
out:
  free(optval);
  return r;
}

DEFINE_SYSCALL(shutdown, int, socket, int, how)
{
  return syswrap(shutdown(socket, how));
}

DEFINE_SYSCALL(sendto, int, socket, gaddr_t, buf_ptr, int, length, int, flags, gaddr_t, addr_ptr, socklen_t, addrlen)
{
  int ret;
  struct sockaddr *sockaddr = NULL;
  struct l_sockaddr l_sockaddr;

  if (addr_ptr != 0) {
    if (copy_from_user(&l_sockaddr, addr_ptr, addrlen))
      return -LINUX_EFAULT;
    if (netns_blocks((int) l_sockaddr.sa_family))
      return -LINUX_ENETUNREACH;
    if (linux_to_darwin_sockaddr(&sockaddr, &l_sockaddr, addrlen) < 0)
      return -LINUX_EINVAL;
  }
  char *buf = malloc(length);
  if (buf == NULL) {
    ret = -LINUX_ENOMEM;
    goto err;
  }
  ret = copy_from_user(buf, buf_ptr, length);
  if (ret < 0) {
    ret = -LINUX_EFAULT;
    goto out;
  }
  ret = syswrap(sendto(socket, buf, length, flags, sockaddr, addrlen));

 out:
  free(buf);
 err:
  if (sockaddr)
    free(sockaddr);
  return ret;
}

/*
 * The flags recvmsg reports back, which is a different set from the ones it is
 * given: only MSG_OOB, MSG_EOR, MSG_TRUNC and MSG_CTRUNC can come out. The two
 * operating systems number them differently - Linux has CTRUNC at 0x08 and EOR
 * at 0x80, Darwin has EOR at 0x08 and CTRUNC at 0x20 - so passing the word
 * through would tell a guest its control data was truncated whenever the record
 * simply ended.
 */
static l_int
darwin_to_linux_msg_flags(int flags)
{
  l_int ret = 0;
  if (flags & MSG_OOB)    ret |= LINUX_MSG_OOB;
  if (flags & MSG_EOR)    ret |= LINUX_MSG_EOR;
  if (flags & MSG_TRUNC)  ret |= LINUX_MSG_TRUNC;
  if (flags & MSG_CTRUNC) ret |= LINUX_MSG_CTRUNC;
  return ret;
}

int
linux_to_darwin_msg_flags(l_int flags)
{
  int ret = 0;
  if (flags & LINUX_MSG_OOB) {
    ret |= MSG_OOB;
    flags &= ~LINUX_MSG_OOB;
  }
  if (flags & LINUX_MSG_PEEK) {
    ret |= MSG_PEEK;
    flags &= ~LINUX_MSG_PEEK;
  }
  if (flags & LINUX_MSG_DONTROUTE) {
    ret |= MSG_DONTROUTE;
    flags &= ~LINUX_MSG_DONTROUTE;
  }
  if (flags & LINUX_MSG_EOR) {
    ret |= MSG_EOR;
    flags &= ~LINUX_MSG_EOR;
  }
  if (flags & LINUX_MSG_TRUNC) {
    ret |= MSG_TRUNC;
    flags &= ~LINUX_MSG_TRUNC;
  }
  if (flags & LINUX_MSG_CTRUNC) {
    ret |= MSG_CTRUNC;
    flags &= ~LINUX_MSG_CTRUNC;
  }
  if (flags & LINUX_MSG_WAITALL) {
    ret |= MSG_WAITALL;
    flags &= ~LINUX_MSG_WAITALL;
  }
  if (flags & LINUX_MSG_DONTWAIT) {
    ret |= MSG_DONTWAIT;
    flags &= ~LINUX_MSG_DONTWAIT;
  }

  if (flags) {
    warnk("unsupported msg_flags: 0x%x\n", flags);
    return -LINUX_EOPNOTSUPP;
  }

  return ret;
}

DEFINE_SYSCALL(recvfrom, int, socket, gaddr_t, buf_ptr, int, length, int, flags, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  if (addr_ptr != 0) {
    l_socklen_t addrbuflen;
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = addrbuflen;
    sock_ptr = alloca(addrbuflen);
  }
  char *buf = alloca(length);
  int ret = syswrap(recvfrom(socket, buf, length, flags, sock_ptr, socklen_ptr));
  if (ret < 0)
    return ret;
  if (copy_to_user(buf_ptr, buf, ret))
    return -LINUX_EFAULT;
  if (addr_ptr != 0) {
    char addr[sock_ptr->sa_len];
    darwin_to_linux_sockaddr((struct l_sockaddr *) addr, sock_ptr);
    if (copy_to_user(addr_ptr, addr, sizeof addr))
      return -LINUX_EFAULT;
    if (copy_to_user(addrlen_ptr, socklen_ptr, sizeof *socklen_ptr))
      return -LINUX_EFAULT;
  }
  return ret;
}

/* ---------------------------------------------------------------------------
 * Ancillary data
 *
 * Passing a descriptor over a unix socket is not a corner of the socket API
 * here, it is the thing Wayland is built out of: every buffer a client shows is
 * a memfd sent with SCM_RIGHTS, and wl_display_connect itself is followed
 * immediately by one. Refusing ancillary data - which is what this did, with
 * "we do not support ancillary data yet" - means a client can connect to a
 * compositor and then never put a pixel on the screen.
 *
 * Two things have to be got right, and the second is the one that bites.
 *
 * The layouts differ. Linux's cmsghdr starts with a size_t, so its header is 16
 * bytes; Darwin's starts with a socklen_t and is 12. A control buffer copied
 * across verbatim - which is what recvmsg used to do - hands the guest headers
 * whose length and level fields are read from the wrong offsets. It looked like
 * it worked because a buffer with nothing in it is the same either way.
 *
 * And a received descriptor is a *host* descriptor that nabi has never seen. It
 * has to be registered, or the guest holds a number its own fd table says is
 * closed - which fails at the next close or dup rather than here, so the
 * report would name the wrong call. MSG_CMSG_CLOEXEC decides how it is
 * registered, and it is applied on the way in rather than afterwards for the
 * same reason accept4 sets its flags on the way in.
 */

/* One Linux cmsghdr as the guest lays it out. */
struct l_cmsg_wire {
  uint64_t cmsg_len;
  int32_t  cmsg_level;
  int32_t  cmsg_type;
};

#define L_CMSG_ALIGN(n)  (((n) + 7u) & ~7u)

/*
 * The guest's control buffer, translated into one Darwin will accept.
 *
 * Only SCM_RIGHTS is carried. SCM_CREDENTIALS is Linux's struct ucred and
 * Darwin's SCM_CREDS is a different structure with different contents, so
 * translating it would mean inventing the parts Darwin does not send;
 * everything else is dropped rather than passed through as bytes. Dropping is
 * visible to the receiver, which is the right way round - a receiver that needs
 * credentials finds none, instead of finding something made up.
 */
static int
cmsg_to_host(gaddr_t control, size_t controllen, struct msghdr *hdr, void **buf_out)
{
  *buf_out = NULL;
  hdr->msg_control = NULL;
  hdr->msg_controllen = 0;
  if (control == 0 || controllen < sizeof(struct l_cmsg_wire))
    return 0;
  if (controllen > 64 * 1024)
    return -LINUX_ENOBUFS;

  char *in = malloc(controllen);
  if (in == NULL)
    return -LINUX_ENOMEM;
  if (copy_from_user(in, control, controllen)) {
    free(in);
    return -LINUX_EFAULT;
  }

  /* The Darwin buffer is never larger than the Linux one it came from: the
   * header is 4 bytes smaller and the payload is the same. */
  char *out = calloc(1, controllen);
  if (out == NULL) {
    free(in);
    return -LINUX_ENOMEM;
  }

  size_t off = 0, outlen = 0;
  while (off + sizeof(struct l_cmsg_wire) <= controllen) {
    struct l_cmsg_wire c;
    memcpy(&c, in + off, sizeof c);
    if (c.cmsg_len < sizeof c || off + c.cmsg_len > controllen)
      break;                    /* malformed, and Linux stops rather than errors */
    size_t payload = c.cmsg_len - sizeof c;

    if (c.cmsg_level == LINUX_SOL_SOCKET && c.cmsg_type == LINUX_SCM_RIGHTS) {
      int nfd = (int) (payload / sizeof(int));
      struct cmsghdr *dc = (struct cmsghdr *) (out + outlen);
      dc->cmsg_len = (socklen_t) CMSG_LEN(payload);
      dc->cmsg_level = SOL_SOCKET;
      dc->cmsg_type = SCM_RIGHTS;
      /*
       * A guest descriptor number is the host one here, so the fds go across
       * as they are - but they are checked first, because sendmsg with a
       * descriptor that is not open must be EBADF and not a message the peer
       * receives with a hole in it.
       */
      const int *src = (const int *) (in + off + sizeof c);
      int *dst = (int *) CMSG_DATA(dc);
      for (int i = 0; i < nfd; i++) {
        if (fcntl(src[i], F_GETFD) < 0) {
          free(in); free(out);
          return -LINUX_EBADF;
        }
        dst[i] = src[i];
      }
      outlen += CMSG_SPACE(payload);
    }
    off += L_CMSG_ALIGN(c.cmsg_len);
  }

  free(in);
  if (outlen == 0) {
    free(out);
    return 0;
  }
  hdr->msg_control = out;
  hdr->msg_controllen = (socklen_t) outlen;
  *buf_out = out;
  return 0;
}

/*
 * What came back, in the guest's layout, with every descriptor registered.
 *
 * Returns the number of bytes of control data written, or a negative errno.
 * Sets *truncated when the guest's buffer could not hold it all, which the
 * caller reports as MSG_CTRUNC - a receiver that ignores that and reads the
 * count would otherwise walk off the end of what it was given.
 */
static int
cmsg_to_guest(const struct msghdr *hdr, gaddr_t control, size_t controllen,
              int flags, bool *truncated)
{
  *truncated = false;
  if (control == 0 || hdr->msg_controllen == 0)
    return 0;

  char *out = calloc(1, controllen ? controllen : 1);
  if (out == NULL)
    return -LINUX_ENOMEM;

  size_t outlen = 0;
  int ret = 0;
  for (struct cmsghdr *dc = CMSG_FIRSTHDR((struct msghdr *) hdr); dc != NULL;
       dc = CMSG_NXTHDR((struct msghdr *) hdr, dc)) {
    if (dc->cmsg_level != SOL_SOCKET || dc->cmsg_type != SCM_RIGHTS)
      continue;
    size_t payload = dc->cmsg_len - CMSG_LEN(0);
    int nfd = (int) (payload / sizeof(int));
    const int *fds = (const int *) CMSG_DATA(dc);

    /*
     * Registered first, and unconditionally: these descriptors are already open
     * in this process whether or not the guest ends up being told about them,
     * so anything not handed over has to be closed rather than leaked.
     */
    size_t need = L_CMSG_ALIGN(sizeof(struct l_cmsg_wire)) + payload;
    bool room = outlen + need <= controllen;
    for (int i = 0; i < nfd; i++) {
      if (!room) {
        close(fds[i]);
        *truncated = true;
        continue;
      }
      int e = register_fd(fds[i], (flags & LINUX_MSG_CMSG_CLOEXEC) != 0);
      if (e < 0) {
        close(fds[i]);
        ret = e;
        continue;
      }
      if (flags & LINUX_MSG_CMSG_CLOEXEC)
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
    }
    if (!room)
      continue;

    struct l_cmsg_wire c = {
      .cmsg_len = sizeof(struct l_cmsg_wire) + payload,
      .cmsg_level = LINUX_SOL_SOCKET,
      .cmsg_type = LINUX_SCM_RIGHTS,
    };
    memcpy(out + outlen, &c, sizeof c);
    memcpy(out + outlen + sizeof c, fds, payload);
    outlen += L_CMSG_ALIGN(c.cmsg_len);
  }

  if (ret == 0 && outlen > 0 && copy_to_user(control, out, outlen))
    ret = -LINUX_EFAULT;
  free(out);
  return ret < 0 ? ret : (int) outlen;
}

static int
do_sendmsg(int sockfd, const struct l_msghdr *msg, int flags)
{
  struct msghdr hdr;

  if (msg->msg_controllen > INT_MAX)
    return -LINUX_ENOBUFS;

  hdr.msg_namelen = msg->msg_namelen;
  hdr.msg_name = NULL;
  if (hdr.msg_namelen > 0) {
    hdr.msg_name = alloca(hdr.msg_namelen);
    if (strncpy_from_user(hdr.msg_name, msg->msg_name, hdr.msg_namelen) < 0)
      return -LINUX_EFAULT;
  }
  hdr.msg_iovlen = msg->msg_iovlen;
  hdr.msg_iov = alloca(sizeof(struct iovec) * hdr.msg_iovlen);
  struct l_iovec *liov = alloca(sizeof(struct l_iovec) * hdr.msg_iovlen);
  if (copy_from_user(liov, msg->msg_iov, sizeof(struct l_iovec) * hdr.msg_iovlen))
    return -LINUX_EFAULT;
  for (int i = 0; i < hdr.msg_iovlen; ++i) {
    hdr.msg_iov[i].iov_len = liov[i].iov_len;
    hdr.msg_iov[i].iov_base = alloca(liov[i].iov_len);
    if (copy_from_user(hdr.msg_iov[i].iov_base, liov[i].iov_base, hdr.msg_iov[i].iov_len))
      return -LINUX_EFAULT;
  }

  void *ctl = NULL;
  int cr = cmsg_to_host(msg->msg_control, msg->msg_controllen, &hdr, &ctl);
  if (cr < 0)
    return cr;

  /*
    On Mac OS X MSG_NOSIGNAL is not supported, so we need to set SO_NOSIGPIPE
    option on the socket.
    See https://lists.apple.com/archives/macnetworkprog/2002/Dec/msg00091.html.
   */
  int msg_flags = linux_to_darwin_msg_flags(flags & ~LINUX_MSG_NOSIGNAL);
  if (msg_flags < 0) {
    warnk("do_sendmsg: unsupported flags\n");
    return hdr.msg_flags;
  }
  if (flags & LINUX_MSG_NOSIGNAL) {
    int val = 1;
    int r = syswrap(setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE,
			       (void*)&val, sizeof(val)));
    if (r < 0) {
      panic("NABI cannot set SO_NOSIGPIPE option.");
    }
  }

  int sr = syswrap(sendmsg(sockfd, &hdr, msg_flags));
  free(ctl);
  return sr;
}

DEFINE_SYSCALL(sendmsg, int, sockfd, gaddr_t, msg_ptr, int, flags)
{
  struct l_msghdr msg;
  if (copy_from_user(&msg, msg_ptr, sizeof msg))
    return -LINUX_EFAULT;
  return do_sendmsg(sockfd, &msg, flags);
}

DEFINE_SYSCALL(sendmmsg, int, sockfd, gaddr_t, msgvec_ptr, unsigned int, vlen, unsigned int, flags)
{
  int r;
  struct l_mmsghdr *msg = malloc(vlen * sizeof(struct l_mmsghdr));
  if (copy_from_user(msg, msgvec_ptr, vlen * sizeof(struct l_mmsghdr))) {
    r = -LINUX_EFAULT;
    goto out;
  }
  uint i;
  for (i = 0; i < vlen; ++i) {
    int err = do_sendmsg(sockfd, &msg[i].msg_hdr, flags);
    if (err < 0) {
      r = err;
      goto out;
    }
    if (copy_to_user(msgvec_ptr + sizeof msg[0] * i + offsetof(struct l_mmsghdr, msg_len), &err, sizeof err)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
  r = i;
  
out:
  free(msg);
  return r;
}

DEFINE_SYSCALL(recvmsg, int, sockfd, gaddr_t, msg_ptr, int, flags)
{
  int r;
  struct l_msghdr lmsg;
  if (copy_from_user(&lmsg, msg_ptr, sizeof lmsg)) {
    return -LINUX_EFAULT;
  }
  char *msg_name = malloc(lmsg.msg_name == 0 ? 0 : lmsg.msg_namelen);
  struct l_iovec *liov = malloc(lmsg.msg_iovlen * sizeof(struct l_iovec));
  if (copy_from_user(liov, lmsg.msg_iov, lmsg.msg_iovlen * sizeof(struct l_iovec))) {
    free(msg_name);
    free(liov);
    return -LINUX_EFAULT;
  }
  struct iovec *msg_iov = malloc(lmsg.msg_iovlen * sizeof(struct iovec));
  size_t iov_total_len = 0;
  for (size_t i = 0; i < lmsg.msg_iovlen; ++i) {
    iov_total_len += liov[i].iov_len;
  }
  char *iov_buf = malloc(iov_total_len), *iov_buf_ptr = iov_buf;
  for (size_t i = 0; i < lmsg.msg_iovlen; ++i) {
    msg_iov[i].iov_base = iov_buf_ptr;
    msg_iov[i].iov_len = liov[i].iov_len;
    iov_buf_ptr += liov[i].iov_len;
  }
  char *msg_control = malloc(lmsg.msg_controllen);
  struct msghdr dmsg;
  dmsg.msg_namelen = lmsg.msg_namelen;
  dmsg.msg_name = lmsg.msg_name == 0 ? 0 : msg_name;
  dmsg.msg_iov = msg_iov;
  dmsg.msg_iovlen = lmsg.msg_iovlen;
  dmsg.msg_control = msg_control;
  dmsg.msg_controllen = lmsg.msg_controllen;
  dmsg.msg_flags = linux_to_darwin_msg_flags(lmsg.msg_flags);
  r = syswrap(recvmsg(sockfd, &dmsg, flags));
  if (r < 0) {
    goto out;
  }
  if (lmsg.msg_name != 0) {
    if (copy_to_user(lmsg.msg_name, dmsg.msg_name, dmsg.msg_namelen)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
  if (copy_to_user(msg_ptr + offsetof(struct l_msghdr, msg_namelen), &dmsg.msg_namelen, sizeof dmsg.msg_namelen)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  for (size_t i = 0; i < lmsg.msg_iovlen; ++i) {
    if (copy_to_user(liov[i].iov_base, dmsg.msg_iov[i].iov_base, liov[i].iov_len)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
  /*
   * Translated rather than copied. The two cmsghdr layouts differ by the size
   * of their first field, so the bytes Darwin produced describe nothing the
   * guest's macros can walk - and any descriptors inside are host descriptors
   * this process has just acquired without its own fd table knowing.
   */
  {
    bool truncated = false;
    /* The syscall's flags, not the header's: MSG_CMSG_CLOEXEC is an argument
     * to recvmsg and never appears in msg_flags, which carries what came
     * *back*. Reading it from the wrong one leaves every passed descriptor
     * inheritable across exec. */
    int n = cmsg_to_guest(&dmsg, lmsg.msg_control, lmsg.msg_controllen,
                          flags, &truncated);
    if (n < 0) {
      r = n;
      goto out;
    }
    l_size_t got = (l_size_t) n;
    if (copy_to_user(msg_ptr + offsetof(struct l_msghdr, msg_controllen),
                     &got, sizeof got)) {
      r = -LINUX_EFAULT;
      goto out;
    }
    /* Say so when it did not fit, or a receiver reads the count it was given
     * and walks past the end of what was written. */
    l_uint mflags = darwin_to_linux_msg_flags(dmsg.msg_flags);
    if (truncated)
      mflags |= LINUX_MSG_CTRUNC;
    if (copy_to_user(msg_ptr + offsetof(struct l_msghdr, msg_flags),
                     &mflags, sizeof mflags)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
out:
  free(msg_name);
  free(liov);
  free(msg_iov);
  free(iov_buf);
  free(msg_control);
  return r;
}

DEFINE_SYSCALL(listen, int, socket, int, backlog)
{
  return syswrap(listen(socket, backlog));
}

/*
 * accept, with the flags accept4 adds.
 *
 * Written as one function taking them rather than as accept4 fixing up what
 * accept returned, because SOCK_CLOEXEC exists precisely to close the window
 * between a descriptor appearing and being marked - and setting it afterwards
 * reopens that window for any other thread that execs in between. The flag
 * would then be doing nothing except in the single-threaded case, where it was
 * never needed.
 */
static int
do_accept(int sockfd, gaddr_t addr_ptr, gaddr_t addrlen_ptr, int flags)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  if (addr_ptr != 0) {
    l_socklen_t addrbuflen;
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = addrbuflen;
    sock_ptr = alloca(addrbuflen);
  }
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = syswrap(accept(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0) {
    goto err;
  }
  /*
   * Both flags are set to the asked-for state rather than only turned on,
   * because BSD and Linux disagree about what an accepted socket starts as.
   * Linux hands back a blocking descriptor whatever the listening socket was,
   * and leaves inheriting to SOCK_NONBLOCK; the BSD lineage has historically
   * passed the listening socket's flags down. Saying so outright means the
   * answer does not depend on which of those this host turns out to do.
   */
  int e = syswrap(fcntl(ret, F_SETFL, (flags & LINUX_SOCK_NONBLOCK) ? O_NONBLOCK : 0));
  if (e < 0) {
    close(ret);
    ret = e;
    goto err;
  }
  e = syswrap(fcntl(ret, F_SETFD, (flags & LINUX_SOCK_CLOEXEC) ? FD_CLOEXEC : 0));
  if (e < 0) {
    close(ret);
    ret = e;
    goto err;
  }
  e = register_fd(ret, (flags & LINUX_SOCK_CLOEXEC) != 0);
  if (e < 0) {
    close(ret);
    ret = e;
    goto err;
  }
  if (addr_ptr != 0) {
    char addr[sock_ptr->sa_len];
    darwin_to_linux_sockaddr((struct l_sockaddr *) addr, sock_ptr);
    if (copy_to_user(addr_ptr, addr, sizeof addr)) {
      ret = -LINUX_EFAULT;
      goto err;
    }
    if (copy_to_user(addrlen_ptr, socklen_ptr, sizeof *socklen_ptr)) {
      ret = -LINUX_EFAULT;
      goto err;
    }
  }
  
err:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(accept, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  return do_accept(sockfd, addr_ptr, addrlen_ptr, 0);
}

DEFINE_SYSCALL(accept4, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr, int, flags)
{
  /*
   * Only the two flags exist. Anything else is refused rather than dropped,
   * because a caller that asked for something this does not do is better told
   * so than handed a descriptor that quietly is not what it wanted.
   */
  if (flags & ~(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC))
    return -LINUX_EINVAL;
  return do_accept(sockfd, addr_ptr, addrlen_ptr, flags);
}

DEFINE_SYSCALL(bind, int, sockfd, gaddr_t, addr_ptr, int, addrlen)
{
  struct sockaddr *sockaddr;
  char *addr = malloc(addrlen);
  if (copy_from_user(addr, addr_ptr, addrlen)) {
    free(addr);
    return -LINUX_EFAULT;
  }

  if (netns_blocks(guest_sa_family(addr, addrlen))) {
    free(addr);
    return -LINUX_EADDRNOTAVAIL;
  }

  if (linux_to_darwin_sockaddr(&sockaddr, (struct l_sockaddr *) addr, addrlen) < 0) {
    return -LINUX_EINVAL;
  }
  int ret = syswrap(bind(sockfd, sockaddr, sockaddr->sa_len));

  free(sockaddr);
  free(addr);
  return ret;
}

DEFINE_SYSCALL(getsockname, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  if (addr_ptr != 0) {
    l_socklen_t addrbuflen;
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = addrbuflen;
    sock_ptr = alloca(addrbuflen);
  }
  int ret = syswrap(getsockname(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0) {
    return ret;
  }
  if (addr_ptr != 0) {
    char addr[sock_ptr->sa_len];
    darwin_to_linux_sockaddr((struct l_sockaddr *) addr, sock_ptr);
    if (copy_to_user(addr_ptr, addr, sizeof addr))
      return -LINUX_EFAULT;
    if (copy_to_user(addrlen_ptr, socklen_ptr, sizeof *socklen_ptr))
      return -LINUX_EFAULT;
  }
  return ret;
}

DEFINE_SYSCALL(getpeername, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  if (addr_ptr != 0) {
    l_socklen_t addrbuflen;
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = addrbuflen;
    sock_ptr = alloca(addrbuflen);
  }
  int ret = syswrap(getpeername(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0) {
    return ret;
  }
  if (addr_ptr != 0) {
    char addr[sock_ptr->sa_len];
    darwin_to_linux_sockaddr((struct l_sockaddr *) addr, sock_ptr);
    if (copy_to_user(addr_ptr, addr, sizeof addr))
      return -LINUX_EFAULT;
    if (copy_to_user(addrlen_ptr, socklen_ptr, sizeof *socklen_ptr))
      return -LINUX_EFAULT;
  }
  return ret;
}

DEFINE_SYSCALL(socketpair, int, family, int, type, int, protocol, gaddr_t, usockvec_ptr)
{
  int fds[2];
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  /*
   * The flag bits come off before Darwin sees the type, exactly as socket()
   * has always done. SOCK_NONBLOCK and SOCK_CLOEXEC are Linux's, packed into
   * the same argument as the socket type; passing them through asks Darwin for
   * a type number that does not exist and it answers EPROTONOSUPPORT.
   *
   * This is what stopped dbus-daemon starting: it makes its reload channel with
   * socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC), failed with "Could not
   * create full-duplex pipe", and took the session bus down with it - so
   * `waydroid session start` could not reach its own session manager. The same
   * call with the same type through socket() worked, which is what made it look
   * like a socketpair-specific refusal rather than a flag being passed on.
   */
  int dtype = type & ~(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
  int ret = syswrap(socketpair(linux_to_darwin_sa_family(family), dtype, protocol, fds));
  if (ret < 0)
    goto err;
  /*
   * And the flags are then applied, which they never were: a caller asking for
   * a non-blocking pair got a blocking one, and one asking for close-on-exec
   * got descriptors that survived an exec. Both ends, since the pair is
   * symmetric and the flags describe each descriptor rather than the channel.
   */
  for (int i = 0; i < 2; i++) {
    int fl = (type & LINUX_SOCK_NONBLOCK) ? O_NONBLOCK : 0;
    if (syswrap(fcntl(fds[i], F_SETFL, fl)) < 0 ||
        syswrap(fcntl(fds[i], F_SETFD, (type & LINUX_SOCK_CLOEXEC) ? FD_CLOEXEC : 0)) < 0) {
      close(fds[0]);
      close(fds[1]);
      ret = -LINUX_EINVAL;
      goto err;
    }
  }
  int e = register_fd(fds[0], type & LINUX_SOCK_CLOEXEC);
  if (e < 0) {
    close(fds[0]);
    close(fds[1]);
    ret = e;
    goto err;
  }
  e = register_fd(fds[1], type & LINUX_SOCK_CLOEXEC);
  if (e < 0) {
    user_close(fds[0]);
    close(fds[1]);
    ret = e;
    goto err;
  }
  if (copy_to_user(usockvec_ptr, fds, sizeof fds)) {
    user_close(fds[0]);
    user_close(fds[1]);
    ret = -LINUX_EFAULT;
    goto err;
  }

err:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}
