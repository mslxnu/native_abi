/*
 * The netfilter tables, as far as iptables can tell.
 *
 * iptables does not reach the kernel through netlink. It opens a raw socket and
 * reads and writes whole tables through four socket options: ask what a table
 * looks like, read its entries, write a new set back, and ask whether a
 * revision of some extension is understood. Nothing here filters a packet -
 * there is no path through nabi for a packet to be filtered on - so what this
 * provides is the conversation, not the firewall.
 *
 * Which is enough, and is needed. Android's netd keeps a persistent
 * iptables-restore child and streams rule batches to it. Without a table to
 * talk to, iptables-restore says "unable to initialize table 'filter'" and
 * exits; netd's next write to it is EPIPE and SIGPIPE, and netd dies. init
 * answers a dead netd by restarting zygote, and zygote's onrestart by killing
 * surfaceflinger, audioserver, cameraserver and media. The whole boot then
 * spends itself restarting, several times a minute, and adb goes from a working
 * shell to "device offline" from the load alone.
 *
 * A table starts out as the built-in chains and nothing else - each one empty
 * with a policy of ACCEPT, which is what a freshly booted Linux has - and a
 * replacement is kept, so a process that writes a table and reads it back sees
 * what it wrote. The store is per process, and a fresh iptables-restore
 * therefore starts from the built-in table again. That matches how netd uses
 * it, since its batches replace a table wholesale rather than adding to what
 * was there; a guest that expected rules to outlive the process that set them
 * would see them disappear, and nothing would filter differently either way.
 */
#include "common.h"
#include "noah.h"
#include "mm.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/socket.h"
#include "linux/netfilter.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define NF_MAX_SOCKETS 64
#define NF_MAX_TABLES  16

struct nf_socket {
  bool used;
  int  fd;
  int  family;                  /* LINUX_AF_INET or LINUX_AF_INET6 */
};

struct nf_table {
  bool     used;
  int      family;
  char     name[XT_TABLE_MAXNAMELEN];
  uint32_t valid_hooks;
  uint32_t hook_entry[NF_INET_NUMHOOKS];
  uint32_t underflow[NF_INET_NUMHOOKS];
  uint32_t num_entries;
  uint32_t size;
  unsigned char *entries;
};

static struct nf_socket nf_sockets[NF_MAX_SOCKETS];
static struct nf_table  nf_tables[NF_MAX_TABLES];
static pthread_mutex_t  nf_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Which hooks each table is built with, which is not a detail iptables will
 * take a guess at: it refuses a chain the table does not claim.
 */
static const struct {
  const char *name;
  uint32_t    valid_hooks;
} nf_known[] = {
  /* PREROUTING 0, INPUT 1, FORWARD 2, OUTPUT 3, POSTROUTING 4 */
  { "filter",   (1u << 1) | (1u << 2) | (1u << 3) },
  { "nat",      (1u << 0) | (1u << 1) | (1u << 3) | (1u << 4) },
  { "mangle",   (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) },
  { "raw",      (1u << 0) | (1u << 3) },
  { "security", (1u << 1) | (1u << 2) | (1u << 3) },
};

bool
netfilter_wants(int family, int type, int protocol)
{
  return (family == LINUX_AF_INET || family == LINUX_AF_INET6) &&
         type == LINUX_SOCK_RAW && protocol == LINUX_IPPROTO_RAW;
}

void
netfilter_note(int fd, int family)
{
  pthread_mutex_lock(&nf_lock);
  for (int i = 0; i < NF_MAX_SOCKETS; i++) {
    if (nf_sockets[i].used && nf_sockets[i].fd == fd) {
      nf_sockets[i].family = family;   /* reused number, new socket */
      pthread_mutex_unlock(&nf_lock);
      return;
    }
  }
  for (int i = 0; i < NF_MAX_SOCKETS; i++) {
    if (nf_sockets[i].used)
      continue;
    nf_sockets[i] = (struct nf_socket){ .used = true, .fd = fd, .family = family };
    break;
  }
  pthread_mutex_unlock(&nf_lock);
}

static int
nf_family_of(int fd)
{
  for (int i = 0; i < NF_MAX_SOCKETS; i++)
    if (nf_sockets[i].used && nf_sockets[i].fd == fd)
      return nf_sockets[i].family;
  return -1;
}

bool
netfilter_is(int fd)
{
  pthread_mutex_lock(&nf_lock);
  bool r = nf_family_of(fd) >= 0;
  pthread_mutex_unlock(&nf_lock);
  return r;
}

void
netfilter_close(int fd)
{
  pthread_mutex_lock(&nf_lock);
  for (int i = 0; i < NF_MAX_SOCKETS; i++)
    if (nf_sockets[i].used && nf_sockets[i].fd == fd)
      nf_sockets[i].used = false;
  pthread_mutex_unlock(&nf_lock);
}

/* The socket option levels these arrive at: IP for v4, IPV6 for v6. */
bool
netfilter_level(int fd, int level)
{
  pthread_mutex_lock(&nf_lock);
  int fam = nf_family_of(fd);
  pthread_mutex_unlock(&nf_lock);
  if (fam == LINUX_AF_INET)
    return level == LINUX_IPPROTO_IP;
  if (fam == LINUX_AF_INET6)
    return level == LINUX_IPPROTO_IPV6;
  return false;
}

static size_t
nf_entry_size(int family)
{
  return family == LINUX_AF_INET6 ? XT_ALIGN(sizeof(struct ip6t_entry))
                                  : XT_ALIGN(sizeof(struct ipt_entry));
}

/*
 * The table a kernel has before anything has been added to it: one entry per
 * built-in chain, each an empty chain whose policy is ACCEPT, and the error
 * entry that marks the end. libiptc walks this by the offsets in it, so the
 * two offsets in every entry have to describe where the target starts and
 * where the next entry does.
 */
static bool
nf_build_default(struct nf_table *t)
{
  size_t esz = nf_entry_size(t->family);
  size_t std = XT_ALIGN(sizeof(struct xt_standard_target));
  size_t err = XT_ALIGN(sizeof(struct xt_error_target));

  int chains = 0;
  for (int h = 0; h < NF_INET_NUMHOOKS; h++)
    if (t->valid_hooks & (1u << h))
      chains++;

  size_t total = (size_t) chains * (esz + std) + (esz + err);
  unsigned char *buf = calloc(1, total);
  if (buf == NULL)
    return false;

  size_t off = 0;
  for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
    if (!(t->valid_hooks & (1u << h)))
      continue;
    /*
     * An empty chain's first rule and its policy are the same entry, so the
     * hook and the underflow point at the same place.
     */
    t->hook_entry[h] = (uint32_t) off;
    t->underflow[h]  = (uint32_t) off;

    /* The two offsets live at the same place in either entry, so they are
     * written through whichever header this family uses. */
    if (t->family == LINUX_AF_INET6) {
      struct ip6t_entry *e = (struct ip6t_entry *)(void *)(buf + off);
      e->target_offset = (uint16_t) esz;
      e->next_offset   = (uint16_t)(esz + std);
    } else {
      struct ipt_entry *e = (struct ipt_entry *)(void *)(buf + off);
      e->target_offset = (uint16_t) esz;
      e->next_offset   = (uint16_t)(esz + std);
    }

    struct xt_standard_target *st =
        (struct xt_standard_target *)(void *)(buf + off + esz);
    st->target.u.user.target_size = (uint16_t) std;
    st->target.u.user.name[0] = '\0';   /* the standard target has no name */
    st->target.u.user.revision = 0;
    st->verdict = NF_VERDICT_ACCEPT;

    off += esz + std;
  }

  /* The end of the table, which libiptc looks for by name. */
  if (t->family == LINUX_AF_INET6) {
    struct ip6t_entry *e = (struct ip6t_entry *)(void *)(buf + off);
    e->target_offset = (uint16_t) esz;
    e->next_offset   = (uint16_t)(esz + err);
  } else {
    struct ipt_entry *e = (struct ipt_entry *)(void *)(buf + off);
    e->target_offset = (uint16_t) esz;
    e->next_offset   = (uint16_t)(esz + err);
  }
  struct xt_error_target *et = (struct xt_error_target *)(void *)(buf + off + esz);
  et->target.u.user.target_size = (uint16_t) err;
  strncpy(et->target.u.user.name, "ERROR", XT_EXTENSION_MAXNAMELEN - 1);
  et->target.u.user.revision = 0;
  strncpy(et->errorname, "ERROR", XT_FUNCTION_MAXNAMELEN - 1);
  off += esz + err;

  free(t->entries);
  t->entries     = buf;
  t->size        = (uint32_t) off;
  t->num_entries = (uint32_t)(chains + 1);
  return true;
}

/* The table by that name, made if this is the first time it has been asked
 * for. NULL for a name no kernel would have. */
static struct nf_table *
nf_table_get(int family, const char *name)
{
  for (int i = 0; i < NF_MAX_TABLES; i++)
    if (nf_tables[i].used && nf_tables[i].family == family &&
        strncmp(nf_tables[i].name, name, XT_TABLE_MAXNAMELEN) == 0)
      return &nf_tables[i];

  uint32_t hooks = 0;
  bool known = false;
  for (size_t i = 0; i < sizeof nf_known / sizeof nf_known[0]; i++)
    if (strncmp(nf_known[i].name, name, XT_TABLE_MAXNAMELEN) == 0) {
      hooks = nf_known[i].valid_hooks;
      known = true;
      break;
    }
  if (!known)
    return NULL;

  for (int i = 0; i < NF_MAX_TABLES; i++) {
    if (nf_tables[i].used)
      continue;
    struct nf_table *t = &nf_tables[i];
    memset(t, 0, sizeof *t);
    t->used   = true;
    t->family = family;
    strncpy(t->name, name, XT_TABLE_MAXNAMELEN - 1);
    t->valid_hooks = hooks;
    if (!nf_build_default(t)) {
      t->used = false;
      return NULL;
    }
    return t;
  }
  return NULL;
}

static int
nf_get_info(int family, gaddr_t optval_ptr, gaddr_t optlen_ptr, uint32_t optlen)
{
  if (optlen < sizeof(struct ipt_getinfo))
    return -LINUX_EINVAL;

  struct ipt_getinfo info;
  if (copy_from_user(&info, optval_ptr, sizeof info))
    return -LINUX_EFAULT;
  info.name[XT_TABLE_MAXNAMELEN - 1] = '\0';

  struct nf_table *t = nf_table_get(family, info.name);
  if (t == NULL)
    return -LINUX_ENOENT;

  memset(&info, 0, sizeof info);
  strncpy(info.name, t->name, XT_TABLE_MAXNAMELEN - 1);
  info.valid_hooks = t->valid_hooks;
  for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
    info.hook_entry[h] = t->hook_entry[h];
    info.underflow[h]  = t->underflow[h];
  }
  info.num_entries = t->num_entries;
  info.size        = t->size;

  if (copy_to_user(optval_ptr, &info, sizeof info))
    return -LINUX_EFAULT;
  uint32_t told = (uint32_t) sizeof info;
  if (copy_to_user(optlen_ptr, &told, sizeof told))
    return -LINUX_EFAULT;
  return 0;
}

static int
nf_get_entries(int family, gaddr_t optval_ptr, gaddr_t optlen_ptr, uint32_t optlen)
{
  if (optlen < sizeof(struct ipt_get_entries))
    return -LINUX_EINVAL;

  struct ipt_get_entries hdr;
  if (copy_from_user(&hdr, optval_ptr, sizeof hdr))
    return -LINUX_EFAULT;
  hdr.name[XT_TABLE_MAXNAMELEN - 1] = '\0';

  struct nf_table *t = nf_table_get(family, hdr.name);
  if (t == NULL)
    return -LINUX_ENOENT;
  /* The caller sized its buffer from what GET_INFO said, so a mismatch means
   * it is reading a table other than the one it measured. */
  if (hdr.size != t->size)
    return -LINUX_EAGAIN;
  if (optlen < sizeof hdr + t->size)
    return -LINUX_EINVAL;

  if (copy_to_user(optval_ptr + sizeof hdr, t->entries, t->size))
    return -LINUX_EFAULT;
  uint32_t told = (uint32_t)(sizeof hdr + t->size);
  if (copy_to_user(optlen_ptr, &told, sizeof told))
    return -LINUX_EFAULT;
  return 0;
}

static int
nf_set_replace(int family, gaddr_t optval_ptr, uint32_t opt_len)
{
  if (opt_len < sizeof(struct ipt_replace))
    return -LINUX_EINVAL;

  struct ipt_replace rep;
  if (copy_from_user(&rep, optval_ptr, sizeof rep))
    return -LINUX_EFAULT;
  rep.name[XT_TABLE_MAXNAMELEN - 1] = '\0';

  struct nf_table *t = nf_table_get(family, rep.name);
  if (t == NULL)
    return -LINUX_ENOENT;
  if (opt_len < sizeof rep + rep.size)
    return -LINUX_EINVAL;
  /* A table with no entries at all has no built-in chains either, which is not
   * something a kernel would accept. */
  if (rep.size == 0 || rep.num_entries == 0)
    return -LINUX_EINVAL;

  unsigned char *buf = malloc(rep.size);
  if (buf == NULL)
    return -LINUX_ENOMEM;
  if (copy_from_user(buf, optval_ptr + sizeof rep, rep.size)) {
    free(buf);
    return -LINUX_EFAULT;
  }

  free(t->entries);
  t->entries     = buf;
  t->size        = rep.size;
  t->num_entries = rep.num_entries;
  t->valid_hooks = rep.valid_hooks;
  for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
    t->hook_entry[h] = rep.hook_entry[h];
    t->underflow[h]  = rep.underflow[h];
  }
  return 0;
}

int
netfilter_getsockopt(int fd, int optname, gaddr_t optval_ptr, gaddr_t optlen_ptr)
{
  uint32_t optlen;
  if (copy_from_user(&optlen, optlen_ptr, sizeof optlen))
    return -LINUX_EFAULT;

  pthread_mutex_lock(&nf_lock);
  int family = nf_family_of(fd);
  int r;
  switch (optname) {
  case NF_SO_GET_INFO:
    r = nf_get_info(family, optval_ptr, optlen_ptr, optlen);
    break;
  case NF_SO_GET_ENTRIES:
    r = nf_get_entries(family, optval_ptr, optlen_ptr, optlen);
    break;
  default:
    /*
     * Which revision of an extension is understood. Every one is, because
     * nothing here interprets an extension's data - and saying no is not a
     * refusal iptables passes on, it is one it works around by using an older
     * revision, which has fewer options than the rule was written against.
     *
     * The numbers differ by family, so they are matched here rather than in
     * the switch above: IPv4 asks at BASE+2 and BASE+3, IPv6 at BASE+4 and
     * BASE+5.
     */
    if ((family == LINUX_AF_INET &&
         (optname == IPT_SO_GET_REVISION_MATCH ||
          optname == IPT_SO_GET_REVISION_TARGET)) ||
        (family == LINUX_AF_INET6 &&
         (optname == IP6T_SO_GET_REVISION_MATCH ||
          optname == IP6T_SO_GET_REVISION_TARGET)))
      r = optlen < sizeof(struct xt_get_revision) ? -LINUX_EINVAL : 0;
    else
      r = -LINUX_ENOPROTOOPT;
    break;
  }
  pthread_mutex_unlock(&nf_lock);
  return r;
}

int
netfilter_setsockopt(int fd, int optname, gaddr_t optval_ptr, uint32_t opt_len)
{
  pthread_mutex_lock(&nf_lock);
  int family = nf_family_of(fd);
  int r;
  switch (optname) {
  case NF_SO_SET_REPLACE:
    r = nf_set_replace(family, optval_ptr, opt_len);
    break;
  /* Counters are read back as zero whatever is added to them, since no packet
   * ever reaches a rule to be counted. */
  case NF_SO_SET_ADD_COUNTERS:
    r = 0;
    break;
  default:
    r = -LINUX_ENOPROTOOPT;
    break;
  }
  pthread_mutex_unlock(&nf_lock);
  return r;
}
