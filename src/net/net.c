#include "noah.h"
#include <sys/stat.h>
#include "namespace.h"
#include "util/khash.h"
#include "common.h"

#include <sys/socket.h>
#include <sys/un.h>

/* Big enough for any address the guest can be handed: two bytes of family and
 * Linux's 108-byte sun_path, which is longer than every other family's. */
#define L_SOCKADDR_MAX (2 + 108)
#include <sys/ucred.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/poll.h>

#include "linux/common.h"
#include "linux/socket.h"
#include "linux/netlink.h"
#include "linux/misc.h"
#include "linux/time.h"

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

/*
 * AF_UNIX SOCK_SEQPACKET, which Darwin does not have.
 *
 * Linux gives local sockets a sequenced-packet mode: connection-oriented like a
 * stream, but with the message boundaries of a datagram. Darwin answers
 * EPROTONOSUPPORT for it, and that is what stopped Android's init - it makes
 * its channel to property_service with socketpair(AF_UNIX, SOCK_SEQPACKET) and
 * calls the failure fatal, so second-stage init died there having already got
 * as far as reading properties.
 *
 * A connected AF_UNIX datagram pair is the same channel in every respect that
 * the guest can observe but one. It keeps boundaries, it is reliable and
 * ordered, and an oversized message is truncated with MSG_TRUNC set, all of
 * which was measured on this host rather than assumed. The exception is the
 * peer going away: Linux reports end-of-file, Darwin reports ECONNRESET. So the
 * substituted descriptors are remembered and that one answer is translated
 * back, which is why this is a note-and-fix pair rather than a type swap.
 */
KHASH_MAP_INIT_INT(seqfd, bool)         /* fd -> the peer has gone */
static khash_t(seqfd) *seqpacket_fds;

/*
 * SO_PASSCRED: the receiver asking to be told who sent each message.
 *
 * Darwin has no such option - its SCM_CREDS is sent by the sender rather than
 * asked for by the receiver - so the request is remembered here and the
 * credentials are put together when a message is received. Passing it to the
 * host returned ENOPROTOOPT, and Android's init treats that as fatal to
 * creating the socket: "Failed to set SO_PASSCRED 'lmkd': Protocol not
 * available", so lmkd never got a socket, exited, and took init with it after
 * four tries.
 *
 * Kept per descriptor in this process. A process that merely *inherits* the
 * descriptor does not inherit the flag, which is a real gap and not one this
 * hides: on Linux the setting belongs to the socket. It costs nothing yet
 * because the setter and the reader are the same process in every case seen so
 * far - init sets it on the socket it hands to lmkd, and lmkd's own clients
 * arrive later on descriptors accept() returns here.
 */
KHASH_MAP_INIT_INT(passcred, bool)
static khash_t(passcred) *passcred_fds;

static void
passcred_set(int fd, bool on)
{
  if (passcred_fds == NULL)
    passcred_fds = kh_init(passcred);
  int ret;
  khiter_t k = kh_put(passcred, passcred_fds, fd, &ret);
  kh_value(passcred_fds, k) = on;
}

static bool
passcred_get(int fd)
{
  if (passcred_fds == NULL)
    return false;
  khiter_t k = kh_get(passcred, passcred_fds, fd);
  return k != kh_end(passcred_fds) && kh_value(passcred_fds, k);
}

void
passcred_close(int fd)
{
  if (passcred_fds == NULL)
    return;
  khiter_t k = kh_get(passcred, passcred_fds, fd);
  if (k != kh_end(passcred_fds))
    kh_del(passcred, passcred_fds, k);
}

static bool peer_ucred(int fd, struct l_ucred *out);

/*
 * Which of Darwin's two it becomes depends on what the caller will do with it,
 * because neither is the whole of what SOCK_SEQPACKET is.
 *
 * A socketpair is a connected pair and nothing else will ever be done to it -
 * no listen, no accept, no connect - so a datagram pair is the closer fit and
 * keeps the message boundaries. That is the case this was written for: init
 * makes its channel to property_service that way.
 *
 * A socket made with socket(2) is on its way to bind, listen and accept, or to
 * connect, and a datagram socket has none of those: listen on one is
 * EOPNOTSUPP, which is where Android's lmkd stopped. It inherits its listening
 * socket from init, calls listen, and exits when that fails - four times, after
 * which init calls it a critical process that will not start and reboots. So
 * that one becomes a stream, and the boundaries are what is given up.
 *
 * Losing them is a real difference and worth naming: two messages sent back to
 * back can arrive as one read. Every caller here frames its own messages -
 * lmkd's protocol carries a length, and so does property_service's - but a
 * caller that relied on the boundary alone would be wrong in a way nothing
 * reports.
 */
static int
seqpacket_darwin_type(int family, int dtype, bool pair)
{
  if (family == LINUX_AF_UNIX && dtype == LINUX_SOCK_SEQPACKET)
    return pair ? SOCK_DGRAM : SOCK_STREAM;
  return dtype;
}

static void
seqpacket_note(int fd, int family, int dtype)
{
  if (family != LINUX_AF_UNIX || dtype != LINUX_SOCK_SEQPACKET)
    return;
  if (seqpacket_fds == NULL)
    seqpacket_fds = kh_init(seqfd);
  int ret;
  khiter_t k = kh_put(seqfd, seqpacket_fds, fd, &ret);
  kh_value(seqpacket_fds, k) = false;
}

void
seqpacket_close(int fd)
{
  if (seqpacket_fds == NULL)
    return;
  khiter_t k = kh_get(seqfd, seqpacket_fds, fd);
  if (k != kh_end(seqpacket_fds))
    kh_del(seqfd, seqpacket_fds, k);
}

/*
 * A peer that has gone is end-of-file on Linux, not a reset connection - and
 * it stays end-of-file. Darwin hands the reset over once, having drained what
 * was queued behind it, and a read after that simply blocks: nothing more is
 * coming and nothing says so. So the answer is remembered, and every later
 * read gets it without going near the descriptor. Getting only the first one
 * right is worse than getting none of them right, because a reader that loops
 * until EOF then hangs on the read after the one that told it to stop.
 */
bool
seqpacket_gone(int fd, int *ret)
{
  if (seqpacket_fds == NULL)
    return false;
  khiter_t k = kh_get(seqfd, seqpacket_fds, fd);
  if (k == kh_end(seqpacket_fds) || !kh_value(seqpacket_fds, k))
    return false;
  *ret = 0;
  return true;
}

int
seqpacket_eof(int fd, int ret)
{
  if (ret != -LINUX_ECONNRESET || seqpacket_fds == NULL)
    return ret;
  khiter_t k = kh_get(seqfd, seqpacket_fds, fd);
  if (k == kh_end(seqpacket_fds))
    return ret;
  kh_value(seqpacket_fds, k) = true;
  return 0;
}


DEFINE_SYSCALL(socket, int, family, int, type, int, protocol)
{
  /* Netlink has no host socket behind it; it is answered here. Taken before the
   * fdtable lock, because netlink_socket registers its own descriptor. */
  if (family == LINUX_AF_NETLINK)
    return netlink_socket(type & ~(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC),
                          protocol, type);

  int ret;
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int dtype = type & ~(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
  int fd = syswrap(socket(linux_to_darwin_sa_family(family),
                          seqpacket_darwin_type(family, dtype, false), protocol));
  /*
   * The socket iptables opens to reach netfilter's tables. Darwin refuses a
   * raw socket to anything unprivileged, and would have nothing behind it if
   * it did not, so one is stood in for it - a socket that exists to be a
   * descriptor and to carry the table options, which are answered in
   * netfilter.c rather than by the host.
   *
   * Marked whether or not the real one succeeded, because a raw socket that
   * did open still has no netfilter under it here.
   */
  bool netfilter = netfilter_wants(family, dtype, protocol);
  if (fd < 0 && netfilter)
    fd = syswrap(socket(AF_UNIX, SOCK_DGRAM, 0));
  seqpacket_note(fd, family, dtype);
  ret = fd;
  if (fd < 0) {
    goto err;
  }
  if (netfilter)
    netfilter_note(fd, family);

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

/*
 * The abstract unix socket namespace, which Darwin does not have.
 *
 * A Linux abstract socket has a name beginning with a NUL and no filesystem
 * entry at all: it is not created, not looked up by path, and it vanishes when
 * the last descriptor on it closes. Darwin has only pathname sockets, so the
 * name is mapped onto one - in a directory of nabi's own, under the boot tag,
 * so two boots cannot collide and nothing outside is touched.
 *
 * The name is hashed rather than escaped. Darwin's sun_path is 104 bytes and an
 * abstract name may be a hundred bytes of arbitrary binary, so escaping it into
 * a filename overflows the field the moment the name is anything but short -
 * and it is exactly the long ones that matter: LXC's per-container command
 * socket is its full lxcpath with the container name on the end.
 *
 * They were previously not translated at all. The bind kept the leading NUL and
 * asked Darwin to create a file whose name was empty, which fails, so `lxc-info`
 * could not reach a running container and `lxc-start` reported one that was not
 * there as already running.
 */
#define ABSTRACT_DIR_FMT "/tmp/.nabi-abs-%s"

static uint64_t
abstract_hash(const char *p, size_t n)
{
  uint64_t h = 1469598103934665603ULL;          /* FNV-1a */
  for (size_t i = 0; i < n; i++) {
    h ^= (unsigned char) p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

/*
 * The host path standing in for an abstract name. The directory is created on
 * demand; a failure to create it is left to the bind that follows, which will
 * report it in terms of the socket rather than of a directory the guest has
 * never heard of.
 */
static void
abstract_to_host(const char *name, size_t namelen, char *out, size_t outsz)
{
  char dir[64];
  snprintf(dir, sizeof dir, ABSTRACT_DIR_FMT, nabi_boot_tag());
  mkdir(dir, 0700);
  snprintf(out, outsz, "%s/%016llx", dir,
           (unsigned long long) abstract_hash(name, namelen));
}

/*
 * Which bound abstract sockets this process owns, so they can be removed again.
 *
 * An abstract socket has no filesystem presence and so needs no unlinking on
 * Linux; here it is a file, and a file left behind is a name that stays taken.
 * The descriptor is the handle, exactly as it is for the ones nabi emulates
 * next door.
 */
struct abstract_bound {
  char *path;
  int   lock_fd;                /* held for as long as the name is ours */
};

KHASH_MAP_INIT_INT(absfd, struct abstract_bound)
static khash_t(absfd) *abstract_fds;

static void
abstract_forget(khiter_t k)
{
  struct abstract_bound *b = &kh_value(abstract_fds, k);
  unlink(b->path);
  if (b->lock_fd >= 0) {
    char lock[PATH_MAX];
    snprintf(lock, sizeof lock, "%s.lock", b->path);
    unlink(lock);
    close(b->lock_fd);          /* releases the flock with it */
  }
  free(b->path);
  kh_del(absfd, abstract_fds, k);
}

static void
abstract_note(int fd, const char *path, int lock_fd)
{
  if (abstract_fds == NULL)
    abstract_fds = kh_init(absfd);
  int ret;
  khiter_t k = kh_put(absfd, abstract_fds, fd, &ret);
  if (ret == 0) {               /* rebinding a descriptor: drop the old name */
    free(kh_value(abstract_fds, k).path);
    if (kh_value(abstract_fds, k).lock_fd >= 0)
      close(kh_value(abstract_fds, k).lock_fd);
  }
  kh_value(abstract_fds, k).path = strdup(path);
  kh_value(abstract_fds, k).lock_fd = lock_fd;
}

void
abstract_close(int fd)
{
  if (abstract_fds == NULL)
    return;
  khiter_t k = kh_get(absfd, abstract_fds, fd);
  if (k == kh_end(abstract_fds))
    return;
  abstract_forget(k);
}

/*
 * Claim an abstract name, or say who has it.
 *
 * Ownership is a lock file beside the socket rather than a probe of the socket
 * itself. The obvious test - connect to it and see whether anyone answers -
 * works, and costs too much: against a name that *is* live it leaves a real
 * connection sitting in the owner's accept queue, so a server hands out a
 * session to a caller that was only asking whether the name was free. It cost
 * this test its own first connection before it cost anything else.
 *
 * A flock is the right shape instead. The host releases it when the holder
 * dies, however it dies, so a name left behind by a killed process is free
 * again and one still held is not - which is what an abstract name does on
 * Linux, where the kernel owns the lifetime.
 *
 * Returns the lock descriptor, or -1 if somebody else holds the name.
 */
static int
abstract_claim(const char *path)
{
  char lock[PATH_MAX];
  snprintf(lock, sizeof lock, "%s.lock", path);
  int fd = open(lock, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return -1;
  if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
    close(fd);
    return -1;                  /* somebody has it */
  }
  /* Ours: anything left at the socket path is from an owner that is gone. */
  unlink(path);
  return fd;
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
      /* An abstract name, which is the bytes the guest gave and not a string:
       * it may contain NULs and is not terminated, so its length comes from
       * the address length and nowhere else. */
      size_t off = offsetof(struct sockaddr_un, sun_path);
      size_t namelen = l_sockaddr_len > off + 1 ? l_sockaddr_len - off - 1 : 0;
      char host_path[sizeof sockaddr_un->sun_path];
      abstract_to_host(&sockaddr_un->sun_path[1], namelen,
                       host_path, sizeof host_path);
      if (strlcpy(sockaddr_un->sun_path, host_path,
                  sizeof sockaddr_un->sun_path) >= sizeof sockaddr_un->sun_path)
        goto err;
      slen = strnlen(sockaddr_un->sun_path, sizeof sockaddr_un->sun_path);
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

socklen_t
darwin_to_linux_sockaddr(struct l_sockaddr *l_sockaddr, size_t outcap,
                         const struct sockaddr *sockaddr)
{
  if (sockaddr == NULL || l_sockaddr == NULL) {
    return 0;
  }
  assert((void*)l_sockaddr != (void*)sockaddr);
  size_t n = sockaddr->sa_len;
  if (n > outcap)
    n = outcap;
  memcpy(l_sockaddr, sockaddr, n);
  l_sockaddr->sa_family = darwin_to_linux_sa_family(sockaddr->sa_family);

  /*
   * A filesystem socket's address is a path, and the path the host knows is
   * not the one the guest asked for: bind translated it into the rootfs on the
   * way in, so getsockname has to translate it back on the way out. Handing
   * over the host's name gives the guest an address it never used and cannot
   * use.
   *
   * bionic's android_get_control_socket does exactly this comparison - it
   * getsocknames the descriptor init passed it and checks the path is
   * /dev/socket/<name> - so with the host's path coming back, every Android
   * service that takes a socket from init failed to recognise its own. That is
   * what stopped prng_seeder, which then hangs on purpose, and boringssl's
   * self test blocks forever reading from the socket prng_seeder never served.
   *
   * The length changes with the name, which is why this reports one rather
   * than leaving the caller to use the host's.
   *
   * Abstract names are not translated: the host name for one is a hash of the
   * guest's, and a hash does not come back. Nothing has needed it yet, and
   * doing it properly means remembering the name a socket was bound with.
   */
  if (sockaddr->sa_family == AF_UNIX) {
    const struct sockaddr_un *dun = (const struct sockaddr_un *) sockaddr;
    size_t off = offsetof(struct sockaddr_un, sun_path);
    if (sockaddr->sa_len > off && dun->sun_path[0] != '\0') {
      char guest[LINUX_PATH_MAX];
      if (guest_path_of_host(dun->sun_path, guest, sizeof guest)) {
        size_t glen = strlen(guest);
        if (off + glen + 1 <= outcap) {
          memcpy((char *) l_sockaddr + off, guest, glen + 1);
          n = off + glen + 1;
        }
      }
    }
  }
  return (socklen_t) n;
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

  /*
   * An abstract name nobody is listening on is ECONNREFUSED, not ENOENT.
   *
   * The two errors mean different things to a caller and Linux is precise about
   * which it gives: a *pathname* socket that is not there is ENOENT, because
   * the path is not there; an abstract name that is not bound is ECONNREFUSED,
   * because the namespace is always present and simply has nothing in it. Here
   * an abstract name is a file, so its absence surfaced as ENOENT and said the
   * wrong thing.
   *
   * lxc-info asks a container's command socket whether it is running. It reads
   * ECONNREFUSED as "stopped" and anything else as a failure to ask, so a
   * container that was not running came back as INVALID STATE - and lxc-start,
   * seeing no clean answer, refused to start one on the grounds that it was
   * already running.
   */
  if (r == -LINUX_ENOENT && sockaddr->sa_family == AF_UNIX &&
      addrlen > offsetof(struct l_sockaddr, sa_data) &&
      addr[offsetof(struct l_sockaddr, sa_data)] == '\0')
    r = -LINUX_ECONNREFUSED;

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
  /*
   * The forced buffer sizes are the same options, asked for by a caller
   * entitled to go past the system's ceiling. Darwin has no separate name for
   * that and no ceiling of Linux's to go past, so the plain option is the
   * whole of what can be done - and getting the size the host is willing to
   * give is what the caller wanted.
   *
   * Refusing them stopped Android's ueventd dead. libcutils asks for a large
   * receive buffer, reads back what it was actually given, and falls back to
   * SO_RCVBUFFORCE when that is short; the fallback failing is fatal, so it
   * logged "Could not open uevent socket" and aborted - and a critical service
   * dying is what sent init to the bootloader instead of to a boot.
   */
  case LINUX_SO_SNDBUFFORCE:
    return SO_SNDBUF;
  case LINUX_SO_RCVBUFFORCE:
    return SO_RCVBUF;
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
  /* Answered before the buffer is copied, because a table replacement is
   * larger than anything else that arrives here and is read straight out of
   * the guest. */
  if (netfilter_is(fd) && netfilter_level(fd, level))
    return netfilter_setsockopt(fd, optname, optval_ptr, opt_len);

  int r;
  char *optval = malloc(opt_len);
  
  if (copy_from_user(optval, optval_ptr, opt_len)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  /* Remembered rather than passed on: Darwin has no such option, and the
   * credentials it asks for are put together at receive time. */
  if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PASSCRED) {
    int on = 0;
    if (opt_len >= sizeof on)
      memcpy(&on, optval, sizeof on);
    passcred_set(fd, on != 0);
    r = 0;
    goto out;
  }

  int host_name = to_host_sockopt_name(optname);
  if (host_name < 0 && sockopt_is_advisory(level, optname)) {
    r = 0;              /* accepted and ignored - see sockopt_is_advisory */
    goto out;
  }
  // Darwin's optval is compatible with that of Linux
  r = syswrap(setsockopt(fd, linux_to_darwin_sockopt_level(level), host_name, optval, opt_len));

  /*
   * A buffer size is a request, not a demand. Linux clamps it - SO_RCVBUF to
   * the system's rmem_max, the forced form to a much higher ceiling - and the
   * call succeeds either way; what the socket actually got is what a later
   * getsockopt reports. Darwin refuses outright with ENOBUFS instead, and a
   * caller written against Linux has no path for a failure that cannot happen
   * there.
   *
   * Android's ueventd asks for sixteen megabytes on its netlink socket and
   * treats the refusal as fatal, so it logged "Could not open uevent socket"
   * and aborted - and a critical service dying is what sent init to the
   * bootloader rather than to a boot.
   *
   * Halving down to what the host will take is the clamp Linux would have
   * applied. The floor is there so this cannot become a long loop on a socket
   * that is refusing for some other reason.
   */
  if (r == -LINUX_ENOBUFS && level == LINUX_SOL_SOCKET && opt_len == sizeof(int) &&
      (optname == LINUX_SO_RCVBUF || optname == LINUX_SO_SNDBUF ||
       optname == LINUX_SO_RCVBUFFORCE || optname == LINUX_SO_SNDBUFFORCE)) {
    int want;
    memcpy(&want, optval, sizeof want);
    for (int try = want / 2; try >= 4096; try /= 2) {
      r = syswrap(setsockopt(fd, linux_to_darwin_sockopt_level(level), host_name,
                             &try, sizeof try));
      if (r == 0)
        break;
    }
  }
out:
  free(optval);
  return r;
}

/*
 * Who is on the other end, as Linux reports it.
 *
 * Used twice: for SO_PEERCRED, which asks about the connection, and for the
 * SCM_CREDENTIALS attached to a message when the receiver asked for those.
 */
static bool
peer_ucred(int fd, struct l_ucred *out)
{
  struct xucred xu;
  socklen_t xl = sizeof xu;
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &xu, &xl) < 0)
    return false;

  /* The pid is a separate option and a newer one; a peer that cannot be named
   * is reported as 0, which is what Linux does for a socket whose peer has
   * gone rather than an error. */
  pid_t hpid = 0;
  socklen_t pl = sizeof hpid;
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &hpid, &pl) < 0)
    hpid = 0;

  out->pid = hpid > 0 ? (int32_t) pidns_to_ns(hpid) : 0;

  /*
   * What the peer says it is, and only failing that what the host says.
   *
   * Darwin's answer is about the host account, which every guest process
   * shares, so translating it gives the same id for every peer alive - root,
   * since that is what the account nabi runs as maps to. A guest running as an
   * ordinary user therefore asked about its own socket and was told root; the
   * ids disagreed, and dbus-daemon's EXTERNAL auth stopped there. The peer's
   * own published credential is the one that answers the question; the host's
   * is kept for a peer that never published one, which is a peer that is not a
   * guest process at all.
   */
  uint32_t puid, pgid;
  if (hpid > 0 && cred_of_host_pid((int32_t) hpid, &puid, &pgid)) {
    out->uid = puid;
    out->gid = pgid;
  } else {
    out->uid = host_uid_to_guest(xu.cr_uid);
    out->gid = host_gid_to_guest(xu.cr_ngroups > 0 ? xu.cr_groups[0]
                                                   : xu.cr_uid);
  }
  return true;
}

static int
peercred_out(int fd, gaddr_t optval_ptr, gaddr_t optlen_ptr, l_socklen_t want)
{
  struct l_ucred uc;
  if (!peer_ucred(fd, &uc))
    return syswrap(-1);

  /* Linux truncates to the caller's buffer and reports how much it wrote. */
  l_socklen_t n = want < (l_socklen_t) sizeof uc ? want : (l_socklen_t) sizeof uc;
  if (copy_to_user(optval_ptr, &uc, n))
    return -LINUX_EFAULT;
  if (copy_to_user(optlen_ptr, &n, sizeof n))
    return -LINUX_EFAULT;
  return 0;
}

/*
 * SO_DOMAIN and SO_PROTOCOL: what a socket was made with.
 *
 * Darwin has neither, and neither needs it to - the answers are properties of
 * the socket that can be recovered. The domain is the family its own address
 * is in, which is what getsockname reports; the protocol is 0 for every family
 * nabi passes through, since none of them has more than one.
 *
 * Android's property service asks the domain of every connection it accepts,
 * and closed the connection when the question came back ENOPROTOOPT. The
 * client sees that as end-of-file where it expected a four-byte answer, so
 * every property set failed - which is how ueventd's "cold boot done" never
 * reached init, and init waited at wait_for_coldboot_done for ever.
 */
static int
sockinfo_out(int fd, int optname, gaddr_t optval_ptr, gaddr_t optlen_ptr,
             l_socklen_t want)
{
  int value = 0;
  if (optname == LINUX_SO_DOMAIN) {
    struct sockaddr_storage ss;
    socklen_t n = sizeof ss;
    if (getsockname(fd, (struct sockaddr *) &ss, &n) < 0)
      return -darwin_to_linux_errno(errno);
    value = darwin_to_linux_sa_family(ss.ss_family);
  }

  l_socklen_t give = want < (l_socklen_t) sizeof value
                         ? want : (l_socklen_t) sizeof value;
  if (copy_to_user(optval_ptr, &value, give))
    return -LINUX_EFAULT;
  if (copy_to_user(optlen_ptr, &give, sizeof give))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(getsockopt, int, fd, int, level, int, optname, gaddr_t, optval_ptr, gaddr_t, optlen_ptr)
{
  l_socklen_t l_optlen;
  if (copy_from_user(&l_optlen, optlen_ptr, sizeof l_optlen))
    return -LINUX_EFAULT;

  if (netfilter_is(fd) && netfilter_level(fd, level))
    return netfilter_getsockopt(fd, optname, optval_ptr, optlen_ptr);
  if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PEERCRED)
    return peercred_out(fd, optval_ptr, optlen_ptr, l_optlen);
  if (level == LINUX_SOL_SOCKET &&
      (optname == LINUX_SO_DOMAIN || optname == LINUX_SO_PROTOCOL))
    return sockinfo_out(fd, optname, optval_ptr, optlen_ptr, l_optlen);
  if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PASSCRED) {
    int on = passcred_get(fd) ? 1 : 0;
    l_socklen_t give = l_optlen < (l_socklen_t) sizeof on
                           ? l_optlen : (l_socklen_t) sizeof on;
    if (copy_to_user(optval_ptr, &on, give))
      return -LINUX_EFAULT;
    if (copy_to_user(optlen_ptr, &give, sizeof give))
      return -LINUX_EFAULT;
    return 0;
  }

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

  /*
   * A netlink destination is a sockaddr_nl, which has no Darwin counterpart to
   * translate to - and the translation is what runs first, so a send that named
   * where it was going failed before reaching the netlink code at all. glibc
   * addresses its requests that way and got EINVAL for every one; `ip` passes no
   * address and so slipped past.
   */
  bool to_netlink = netlink_is(socket);

  if (addr_ptr != 0 && !to_netlink) {
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
  if (to_netlink)
    ret = netlink_send(socket, buf, length);
  else
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

/*
 * Flags a receive handles itself, which must not reach the flag converter -
 * it refuses anything it does not recognise, and these have no Darwin
 * counterpart to convert to.
 *
 * MSG_CMSG_CLOEXEC is read straight from the argument where the passed
 * descriptors are registered; MSG_TRUNC is Linux's "how big was it" and is
 * served by peeking; MSG_NOSIGNAL is about a send. Passing the first of those
 * to the converter turned every recvmsg carrying it into EOPNOTSUPP, which is
 * every recvmsg that receives a descriptor.
 */
#define RECV_FLAGS_HANDLED_HERE \
  (LINUX_MSG_TRUNC | LINUX_MSG_CMSG_CLOEXEC | LINUX_MSG_NOSIGNAL)

/*
 * The real size of the datagram at the head of the queue.
 *
 * Linux's MSG_TRUNC, given *to* a receive, means "tell me how big the datagram
 * was even if it did not fit"; Darwin has no such input flag - its MSG_TRUNC is
 * something a receive reports back, and passing it in means nothing. The two
 * were being mapped onto each other, so a caller asking the size was told the
 * number of bytes that happened to fit, which for the zero-length buffer such a
 * caller uses is none of them.
 *
 * iproute2 sizes every netlink reply this way: recvmsg with MSG_PEEK|MSG_TRUNC
 * and nowhere to put the data, then a real receive into a buffer that big. It
 * reads 0 as the socket having closed - "EOF on netlink" - and gives up.
 *
 * Peeking is how the size is found, since the datagram has to stay where it is
 * for the caller's own receive to follow.
 */
static ssize_t
peek_datagram_len(int fd, int dflags)
{
  size_t cap = 8192;
  char *scratch = malloc(cap);
  if (scratch == NULL)
    return -1;
  for (;;) {
    /* MSG_WAITALL would wait for a full buffer that is never coming. */
    ssize_t n = recv(fd, scratch, cap, (dflags & ~MSG_WAITALL) | MSG_PEEK);
    if (n < 0) {
      free(scratch);
      return -1;
    }
    if ((size_t) n < cap) {
      free(scratch);
      return n;
    }
    size_t want = cap * 2;
    char *bigger = realloc(scratch, want);
    if (bigger == NULL) {
      free(scratch);
      return n;                 /* the best answer available */
    }
    scratch = bigger;
    cap = want;
  }
}

DEFINE_SYSCALL(recvfrom, int, socket, gaddr_t, buf_ptr, int, length, int, flags, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  l_socklen_t addrbuflen = 0;    /* the guest's buffer, kept for the answer */
  if (addr_ptr != 0) {
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    /*
     * The host is given room for the whole address rather than the guest's
     * buffer, because the guest's is not the measure of it: an address is
     * translated on the way out and the result can be longer, and a truncated
     * one cannot be translated at all. Linux has the whole address and copies
     * as much of it as the caller asked for, which is what happens below.
     */
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = sizeof(struct sockaddr_storage);
    sock_ptr = alloca(sizeof(struct sockaddr_storage));
  }
  /* The flags were being handed to Darwin unconverted. They are not the same
   * numbers: Linux's MSG_DONTWAIT is 0x40, which is Darwin's MSG_WAITALL, so a
   * receive asked not to block was asked to block until the buffer filled. */
  int dflags = linux_to_darwin_msg_flags(flags & ~RECV_FLAGS_HANDLED_HERE);
  if (dflags < 0)
    return dflags;

  ssize_t whole = -1;
  if (flags & LINUX_MSG_TRUNC) {
    whole = peek_datagram_len(socket, dflags);
    if (whole < 0)
      return syswrap(-1);
  }

  char *buf = alloca(length);
  int ret;
  if (!seqpacket_gone(socket, &ret))
    ret = seqpacket_eof(socket,
          syswrap(recvfrom(socket, buf, length, dflags, sock_ptr, socklen_ptr)));
  if (ret < 0)
    return ret;
  if (copy_to_user(buf_ptr, buf, ret))
    return -LINUX_EFAULT;
  if (addr_ptr != 0) {
    char addr[L_SOCKADDR_MAX];
    socklen_t n = darwin_to_linux_sockaddr((struct l_sockaddr *) addr,
                                           sizeof addr, sock_ptr);
    l_socklen_t give = addrbuflen < (l_socklen_t) n ? addrbuflen : (l_socklen_t) n;
    if (copy_to_user(addr_ptr, addr, give))
      return -LINUX_EFAULT;
    l_socklen_t told = (l_socklen_t) n;   /* Linux reports the whole address */
    if (copy_to_user(addrlen_ptr, &told, sizeof told))
      return -LINUX_EFAULT;
  }
  /* What was there, not what fitted. */
  return whole >= 0 ? (int) whole : ret;
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
cmsg_to_guest(int fd, const struct msghdr *hdr, gaddr_t control,
              size_t controllen, int flags, bool *truncated)
{
  *truncated = false;
  bool want_cred = passcred_get(fd);
  if (control == 0 || (hdr->msg_controllen == 0 && !want_cred))
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

  /*
   * And who sent it, if the receiver asked to be told. Linux puts this in
   * whether or not anything else is there, which is the whole use of the
   * option: a receiver that authenticates its clients gets the credentials
   * with the message rather than having to ask about the connection.
   */
  if (ret == 0 && want_cred) {
    struct l_ucred uc;
    size_t need = L_CMSG_ALIGN(sizeof(struct l_cmsg_wire)) + sizeof uc;
    if (outlen + need > controllen) {
      *truncated = true;
    } else if (peer_ucred(fd, &uc)) {
      struct l_cmsg_wire c = {
        .cmsg_len = sizeof(struct l_cmsg_wire) + sizeof uc,
        .cmsg_level = LINUX_SOL_SOCKET,
        .cmsg_type = LINUX_SCM_CREDENTIALS,
      };
      memcpy(out + outlen, &c, sizeof c);
      memcpy(out + outlen + sizeof c, &uc, sizeof uc);
      outlen += L_CMSG_ALIGN(c.cmsg_len);
    }
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

  /*
   * A netlink send is answered here rather than handed to Darwin. The request
   * is gathered into one buffer first: netlink counts in messages, and a
   * message is free to straddle two iovecs - `ip` builds its requests exactly
   * that way, with the header in one and the attributes in another.
   */
  if (netlink_is(sockfd)) {
    size_t total = 0;
    for (int i = 0; i < hdr.msg_iovlen; ++i)
      total += hdr.msg_iov[i].iov_len;
    if (total == 0)
      return -LINUX_EINVAL;
    uint8_t *flat = malloc(total);
    if (flat == NULL)
      return -LINUX_ENOMEM;
    size_t at = 0;
    for (int i = 0; i < hdr.msg_iovlen; ++i) {
      memcpy(flat + at, hdr.msg_iov[i].iov_base, hdr.msg_iov[i].iov_len);
      at += hdr.msg_iov[i].iov_len;
    }
    int nr = netlink_send(sockfd, flat, total);
    free(flat);
    return nr;
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

/*
 * Core recvmsg logic.  lmsg is a *local* copy of the guest's l_msghdr
 * (already copied from user by the caller).  msg_ptr is the guest address
 * of the l_msghdr so we can write back msg_namelen, msg_controllen, etc.
 *
 * Returns bytes received, or a negative Linux error.
 */
static int
do_recvmsg(int sockfd, struct l_msghdr *lmsg, gaddr_t msg_ptr, int flags)
{
  int r;
  char *msg_name = malloc(lmsg->msg_name == 0 ? 0 : lmsg->msg_namelen);
  struct l_iovec *liov = malloc(lmsg->msg_iovlen * sizeof(struct l_iovec));
  if (copy_from_user(liov, lmsg->msg_iov, lmsg->msg_iovlen * sizeof(struct l_iovec))) {
    free(msg_name);
    free(liov);
    return -LINUX_EFAULT;
  }
  struct iovec *msg_iov = malloc(lmsg->msg_iovlen * sizeof(struct iovec));
  size_t iov_total_len = 0;
  for (size_t i = 0; i < lmsg->msg_iovlen; ++i) {
    iov_total_len += liov[i].iov_len;
  }
  char *iov_buf = malloc(iov_total_len), *iov_buf_ptr = iov_buf;
  for (size_t i = 0; i < lmsg->msg_iovlen; ++i) {
    msg_iov[i].iov_base = iov_buf_ptr;
    msg_iov[i].iov_len = liov[i].iov_len;
    iov_buf_ptr += liov[i].iov_len;
  }
  char *msg_control = malloc(lmsg->msg_controllen);
  struct msghdr dmsg;
  dmsg.msg_namelen = lmsg->msg_namelen;
  dmsg.msg_name = lmsg->msg_name == 0 ? 0 : msg_name;
  dmsg.msg_iov = msg_iov;
  dmsg.msg_iovlen = lmsg->msg_iovlen;
  dmsg.msg_control = msg_control;
  dmsg.msg_controllen = lmsg->msg_controllen;
  dmsg.msg_flags = linux_to_darwin_msg_flags(lmsg->msg_flags);

  ssize_t whole = -1;

  int dflags = linux_to_darwin_msg_flags(flags & ~RECV_FLAGS_HANDLED_HERE);
  if (dflags < 0) {
    r = dflags;
    goto out;
  }

  if (flags & LINUX_MSG_TRUNC) {
    whole = peek_datagram_len(sockfd, dflags);
    if (whole < 0) {
      r = syswrap(-1);
      goto out;
    }
  }

  if (!seqpacket_gone(sockfd, &r))
    r = seqpacket_eof(sockfd, syswrap(recvmsg(sockfd, &dmsg, dflags)));
  if (r < 0) {
    goto out;
  }

  bool is_nl = netlink_is(sockfd);
  struct l_sockaddr_nl from_nl;
  if (is_nl) {
    memset(&from_nl, 0, sizeof from_nl);
    from_nl.nl_family = LINUX_AF_NETLINK;
    dmsg.msg_namelen = sizeof from_nl;
  }

  if (lmsg->msg_name != 0) {
    const void *name = is_nl ? (const void *) &from_nl : dmsg.msg_name;
    socklen_t namelen = dmsg.msg_namelen;
    if ((l_int) namelen > lmsg->msg_namelen)
      namelen = lmsg->msg_namelen;
    if (copy_to_user(lmsg->msg_name, name, namelen)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
  if (copy_to_user(msg_ptr + offsetof(struct l_msghdr, msg_namelen), &dmsg.msg_namelen, sizeof dmsg.msg_namelen)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  for (size_t i = 0; i < lmsg->msg_iovlen; ++i) {
    if (copy_to_user(liov[i].iov_base, dmsg.msg_iov[i].iov_base, liov[i].iov_len)) {
      r = -LINUX_EFAULT;
      goto out;
    }
  }
  {
    bool truncated = false;
    int n = cmsg_to_guest(sockfd, &dmsg, lmsg->msg_control,
                          lmsg->msg_controllen, flags, &truncated);
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
    l_uint mflags = darwin_to_linux_msg_flags(dmsg.msg_flags);
    if (truncated)
      mflags |= LINUX_MSG_CTRUNC;
    if (whole >= 0 && (size_t) whole > iov_total_len)
      mflags |= LINUX_MSG_TRUNC;
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
  return whole >= 0 && r >= 0 ? (int) whole : r;
}

DEFINE_SYSCALL(recvmsg, int, sockfd, gaddr_t, msg_ptr, int, flags)
{
  struct l_msghdr lmsg;
  if (copy_from_user(&lmsg, msg_ptr, sizeof lmsg)) {
    return -LINUX_EFAULT;
  }
  return do_recvmsg(sockfd, &lmsg, msg_ptr, flags);
}

/*
 * recvmmsg(2) — receive multiple messages at once.
 *
 * Calls do_recvmsg in a loop.  The first message blocks (unless the caller
 * passed MSG_DONTWAIT); subsequent messages are non-blocking.  When a
 * timeout is given it is a relative CLOCK_MONOTONIC deadline — we convert it
 * to an absolute deadline once, then poll(2) the socket before each blocking
 * recvmsg to respect the remaining time.
 */
DEFINE_SYSCALL(recvmmsg, int, sockfd, gaddr_t, msgvec_ptr, unsigned int, vlen, unsigned int, flags, gaddr_t, timeout_ptr)
{
  if (vlen == 0)
    return 0;

  /* Convert the optional relative timeout into an absolute deadline. */
  struct timespec deadline;
  bool has_deadline = false;
  if (timeout_ptr != 0) {
    struct l_timespec lts;
    if (copy_from_user(&lts, timeout_ptr, sizeof lts))
      return -LINUX_EFAULT;
    if (lts.tv_sec < 0 || lts.tv_nsec < 0 || lts.tv_nsec >= 1000000000L)
      return -LINUX_EINVAL;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += lts.tv_sec;
    deadline.tv_nsec += lts.tv_nsec;
    if (deadline.tv_nsec >= 1000000000L) {
      deadline.tv_sec  += 1;
      deadline.tv_nsec -= 1000000000L;
    }
    has_deadline = true;
  }

  /* Copy the whole mmsghdr array in one shot. */
  struct l_mmsghdr *msgs = malloc(vlen * sizeof(struct l_mmsghdr));
  if (msgs == NULL)
    return -LINUX_ENOMEM;
  if (copy_from_user(msgs, msgvec_ptr, vlen * sizeof(struct l_mmsghdr))) {
    free(msgs);
    return -LINUX_EFAULT;
  }

  unsigned int count = 0;
  for (unsigned int i = 0; i < vlen; ++i) {
    int mflags = (int) flags;

    /*
     * Linux: after the first message, MSG_WAITFORONE forces MSG_DONTWAIT
     * so subsequent calls never block.
     */
    if (i > 0 && (flags & LINUX_MSG_WAITFORONE))
      mflags |= LINUX_MSG_DONTWAIT;

    /*
     * If a deadline is set and the first message needs to block, poll(2)
     * the socket with the remaining time so we don't sleep forever.
     * Subsequent messages are always non-blocking (MSG_WAITFORONE or not).
     */
    if (i == 0 && has_deadline && !(mflags & LINUX_MSG_DONTWAIT)) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      long ms = (long)(deadline.tv_sec  - now.tv_sec)  * 1000 +
                (long)(deadline.tv_nsec - now.tv_nsec) / 1000000;
      if (ms <= 0) {
        /* Deadline already passed — return what we have (0). */
        break;
      }
      struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
      int pr = poll(&pfd, 1, (int) ms);
      if (pr < 0) {
        int err = syswrap(-1);
        if (count > 0)
          break;
        free(msgs);
        return err;
      }
      if (pr == 0) {
        /* Timeout expired before any data arrived. */
        break;
      }
      /* Socket is ready — fall through to a non-blocking recvmsg. */
      mflags |= LINUX_MSG_DONTWAIT;
    }

    int r = do_recvmsg(sockfd, &msgs[i].msg_hdr,
                       msgvec_ptr + sizeof(struct l_mmsghdr) * i
                                 + offsetof(struct l_mmsghdr, msg_hdr),
                       mflags);
    if (r < 0) {
      /*
       * EAGAIN / EWOULDBLOCK after at least one successful receive is
       * normal for recvmmsg — just return what we have.
       */
      if (r == -LINUX_EAGAIN || r == -LINUX_EWOULDBLOCK) {
        if (count > 0)
          break;
        free(msgs);
        return r;
      }
      /* Any other error on the first message is fatal. */
      if (count == 0) {
        free(msgs);
        return r;
      }
      break;
    }

    /* Write back msg_len for this entry. */
    if (copy_to_user(msgvec_ptr + sizeof(struct l_mmsghdr) * i
                              + offsetof(struct l_mmsghdr, msg_len),
                     &r, sizeof(l_uint))) {
      free(msgs);
      return -LINUX_EFAULT;
    }
    count++;
  }

  free(msgs);
  return (int) count;
}

/*
 * recvmmsg_time64(2) — identical to recvmmsg on a 64-bit host; the time64
 * variant exists only for 32-bit guests that need wider tv_sec.
 */
DEFINE_SYSCALL(recvmmsg_time64, int, sockfd, gaddr_t, msgvec_ptr, unsigned int, vlen, unsigned int, flags, gaddr_t, timeout_ptr)
{
  return sys_recvmmsg(sockfd, msgvec_ptr, vlen, flags, timeout_ptr);
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
 *
 * The lock that closes that window covers the descriptor's life from existing
 * to being registered, and nothing before it. It used to be taken first and
 * held across the accept itself, which is the one call here that waits without
 * a bound: a server parked waiting for a connection held the process's fd
 * table against every other thread in it, for as long as nobody connected.
 *
 * adbd is built out of exactly that. It has a thread in accept on the tcp
 * port, and its "server socket" and "jdwp control" threads both start by
 * calling socket() - so both stopped in socket() before they had done anything
 * at all, and stayed there. adbd listens, the connection is established by the
 * host, and the process that should read the handshake has never finished
 * starting up. Which looks from outside like adbd accepting a connection and
 * then ignoring it.
 *
 * Waiting for a connection needs no lock, because until accept returns there
 * is no descriptor to protect.
 */
static int
do_accept(int sockfd, gaddr_t addr_ptr, gaddr_t addrlen_ptr, int flags)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  l_socklen_t addrbuflen = 0;    /* the guest's buffer, kept for the answer */
  if (addr_ptr != 0) {
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    /*
     * The host is given room for the whole address rather than the guest's
     * buffer, because the guest's is not the measure of it: an address is
     * translated on the way out and the result can be longer, and a truncated
     * one cannot be translated at all. Linux has the whole address and copies
     * as much of it as the caller asked for, which is what happens below.
     */
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = sizeof(struct sockaddr_storage);
    sock_ptr = alloca(sizeof(struct sockaddr_storage));
  }
  int ret = syswrap(accept(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0)
    return ret;
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
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
    char addr[L_SOCKADDR_MAX];
    socklen_t n = darwin_to_linux_sockaddr((struct l_sockaddr *) addr,
                                           sizeof addr, sock_ptr);
    l_socklen_t give = addrbuflen < (l_socklen_t) n ? addrbuflen : (l_socklen_t) n;
    if (copy_to_user(addr_ptr, addr, give)) {
      ret = -LINUX_EFAULT;
      goto err;
    }
    *socklen_ptr = (socklen_t) n;
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

  if (netlink_is(sockfd)) {
    int r = netlink_bind(sockfd, addr, addrlen);
    free(addr);
    return r;
  }

  if (linux_to_darwin_sockaddr(&sockaddr, (struct l_sockaddr *) addr, addrlen) < 0) {
    return -LINUX_EINVAL;
  }
  /* Whether the guest asked for an abstract name, which is decided by the
   * address it gave and not by the path that came out of the translation. */
  bool abstract = sockaddr->sa_family == AF_UNIX &&
                  addrlen > (int) offsetof(struct l_sockaddr, sa_data) &&
                  addr[offsetof(struct l_sockaddr, sa_data)] == '\0';

  int lock_fd = -1;
  int ret;
  if (abstract) {
    /* The name is claimed before the socket is bound, so a stale file from a
     * dead owner is cleared and a live one is refused without touching it. */
    const struct sockaddr_un *sun = (const struct sockaddr_un *) sockaddr;
    lock_fd = abstract_claim(sun->sun_path);
    if (lock_fd < 0) {
      free(sockaddr);
      free(addr);
      return -LINUX_EADDRINUSE;
    }
  }

  ret = syswrap(bind(sockfd, sockaddr, sockaddr->sa_len));

  /* Remembered so closing the descriptor takes the name with it, which is what
   * having no filesystem entry means on Linux. */
  if (ret == 0 && abstract) {
    abstract_note(sockfd, ((struct sockaddr_un *) sockaddr)->sun_path, lock_fd);
  } else if (lock_fd >= 0) {
    char lock[PATH_MAX];
    snprintf(lock, sizeof lock, "%s.lock",
             ((struct sockaddr_un *) sockaddr)->sun_path);
    unlink(lock);
    close(lock_fd);
  }

  /*
   * A bound AF_UNIX socket is a file the guest just created, and every other
   * way of creating one stamps the guest's ownership beside it. This did not,
   * so a socket bound by an ordinary user was owned by root - the host account,
   * which is what an absent attribute means - and the user could then neither
   * chmod it nor unlink it out of a sticky /tmp. dbus-daemon chmods its socket
   * on startup and gave up on the EPERM, which is as far as a session bus got.
   *
   * The path here is the host's: linux_to_darwin_sockaddr rewrote it on the way
   * in. An abstract socket has no filesystem entry to stamp.
   */
  if (ret == 0 && sockaddr->sa_family == AF_UNIX) {
    const struct sockaddr_un *sun = (const struct sockaddr_un *) sockaddr;
    if (sun->sun_path[0] != '\0')
      guest_owner_stamp_new(AT_FDCWD, sun->sun_path);
  }

  free(sockaddr);
  free(addr);
  return ret;
}

DEFINE_SYSCALL(getsockname, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  l_socklen_t addrbuflen = 0;    /* the guest's buffer, kept for the answer */
  if (addr_ptr != 0) {
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    /*
     * The host is given room for the whole address rather than the guest's
     * buffer, because the guest's is not the measure of it: an address is
     * translated on the way out and the result can be longer, and a truncated
     * one cannot be translated at all. Linux has the whole address and copies
     * as much of it as the caller asked for, which is what happens below.
     */
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = sizeof(struct sockaddr_storage);
    sock_ptr = alloca(sizeof(struct sockaddr_storage));
  }
  if (netlink_is(sockfd)) {
    /* Darwin has no sockaddr for this; the answer is built whole. */
    struct l_sockaddr_nl snl;
    size_t n = sizeof snl;
    int r = netlink_getsockname(sockfd, &snl, &n);
    if (r < 0 || addr_ptr == 0)
      return r;
    l_socklen_t want;
    if (copy_from_user(&want, addrlen_ptr, sizeof want))
      return -LINUX_EFAULT;
    l_socklen_t give = want < (l_socklen_t) n ? want : (l_socklen_t) n;
    if (copy_to_user(addr_ptr, &snl, give))
      return -LINUX_EFAULT;
    l_socklen_t told = (l_socklen_t) n;   /* Linux reports the full size */
    if (copy_to_user(addrlen_ptr, &told, sizeof told))
      return -LINUX_EFAULT;
    return 0;
  }

  int ret = syswrap(getsockname(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0) {
    return ret;
  }
  if (addr_ptr != 0) {
    char addr[L_SOCKADDR_MAX];
    socklen_t n = darwin_to_linux_sockaddr((struct l_sockaddr *) addr,
                                           sizeof addr, sock_ptr);
    l_socklen_t give = addrbuflen < (l_socklen_t) n ? addrbuflen : (l_socklen_t) n;
    if (copy_to_user(addr_ptr, addr, give))
      return -LINUX_EFAULT;
    l_socklen_t told = (l_socklen_t) n;   /* Linux reports the whole address */
    if (copy_to_user(addrlen_ptr, &told, sizeof told))
      return -LINUX_EFAULT;
  }
  return ret;
}

DEFINE_SYSCALL(getpeername, int, sockfd, gaddr_t, addr_ptr, gaddr_t, addrlen_ptr)
{
  socklen_t *socklen_ptr = NULL;
  struct sockaddr *sock_ptr = NULL;
  l_socklen_t addrbuflen = 0;    /* the guest's buffer, kept for the answer */
  if (addr_ptr != 0) {
    if (copy_from_user(&addrbuflen, addrlen_ptr, sizeof addrbuflen))
      return -LINUX_EFAULT;
    /*
     * The host is given room for the whole address rather than the guest's
     * buffer, because the guest's is not the measure of it: an address is
     * translated on the way out and the result can be longer, and a truncated
     * one cannot be translated at all. Linux has the whole address and copies
     * as much of it as the caller asked for, which is what happens below.
     */
    socklen_ptr = alloca(sizeof *socklen_ptr);
    *socklen_ptr = sizeof(struct sockaddr_storage);
    sock_ptr = alloca(sizeof(struct sockaddr_storage));
  }
  int ret = syswrap(getpeername(sockfd, sock_ptr, socklen_ptr));
  if (ret < 0) {
    return ret;
  }
  if (addr_ptr != 0) {
    char addr[L_SOCKADDR_MAX];
    socklen_t n = darwin_to_linux_sockaddr((struct l_sockaddr *) addr,
                                           sizeof addr, sock_ptr);
    l_socklen_t give = addrbuflen < (l_socklen_t) n ? addrbuflen : (l_socklen_t) n;
    if (copy_to_user(addr_ptr, addr, give))
      return -LINUX_EFAULT;
    l_socklen_t told = (l_socklen_t) n;   /* Linux reports the whole address */
    if (copy_to_user(addrlen_ptr, &told, sizeof told))
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
  int ret = syswrap(socketpair(linux_to_darwin_sa_family(family),
                               seqpacket_darwin_type(family, dtype, true), protocol, fds));
  if (ret < 0)
    goto err;
  seqpacket_note(fds[0], family, dtype);
  seqpacket_note(fds[1], family, dtype);
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
