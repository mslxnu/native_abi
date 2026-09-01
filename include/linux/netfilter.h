#ifndef NABI_LINUX_NETFILTER_H
#define NABI_LINUX_NETFILTER_H

#include <stdint.h>

/*
 * The part of netfilter that iptables talks to.
 *
 * iptables does not use netlink for the tables themselves. It opens a raw
 * socket and reads and writes whole tables through four socket options, and
 * every structure below is the layout it expects to find on the other side.
 * They are written out rather than sized by hand because libiptc walks the
 * entry blob by the offsets inside it: a structure a few bytes out is not a
 * wrong answer, it is a parse that runs off the end.
 *
 * Sizes come out the same compiled here as on Linux/aarch64 - same LP64 rules,
 * same alignment - which is what makes declaring them enough. netfiltertest
 * checks that, so a host that disagreed would say so rather than produce a
 * table nothing could read.
 */

#define XT_TABLE_MAXNAMELEN     32
#define XT_FUNCTION_MAXNAMELEN  30
#define XT_EXTENSION_MAXNAMELEN 29
#define NF_INET_NUMHOOKS        5
#define LINUX_IFNAMSIZ          16

/*
 * The option numbers. The four that matter most are shared, and the two
 * revision probes are not: IPv4 puts them at BASE+2 and BASE+3, IPv6 at BASE+4
 * and BASE+5.
 *
 * Answering ENOPROTOOPT to a revision probe is not a failure iptables reports.
 * It means "this kernel does not know that revision", so iptables quietly uses
 * an older one - and an older revision of a target has fewer options. Asked for
 * the IPv6 numbers and told no, it fell back to revision 0 of MARK, whose only
 * option is --set-mark, and then rejected netd's rule with `unknown option
 * "--or-mark"`.
 */
#define NF_BASE_CTL             64
#define NF_SO_SET_REPLACE       (NF_BASE_CTL)
#define NF_SO_SET_ADD_COUNTERS  (NF_BASE_CTL + 1)
#define NF_SO_GET_INFO          (NF_BASE_CTL)
#define NF_SO_GET_ENTRIES       (NF_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH   (NF_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET  (NF_BASE_CTL + 3)
#define IP6T_SO_GET_REVISION_MATCH  (NF_BASE_CTL + 4)
#define IP6T_SO_GET_REVISION_TARGET (NF_BASE_CTL + 5)

/* Standard verdicts, as a standard target carries them: -NF_ACCEPT - 1 and so
 * on, which is how a policy of ACCEPT is written. */
#define NF_VERDICT_DROP   (-1)
#define NF_VERDICT_ACCEPT (-2)

struct xt_counters {
  uint64_t pcnt, bcnt;
};

struct xt_entry_target {
  union {
    struct {
      uint16_t target_size;
      char     name[XT_EXTENSION_MAXNAMELEN];
      uint8_t  revision;
    } user;
    struct {
      uint16_t target_size;
      void    *target;
    } kernel;
    uint16_t target_size;
  } u;
  unsigned char data[0];
};

struct xt_standard_target {
  struct xt_entry_target target;
  int verdict;
};

struct xt_error_target {
  struct xt_entry_target target;
  char errorname[XT_FUNCTION_MAXNAMELEN];
};

/*
 * Linux's in_addr and in6_addr are declared over __u32, so they align to four
 * and the structures holding them are padded accordingly. Declared over bytes
 * they align to one, and struct ip6t_ip6 comes out two bytes short - which the
 * padding inside ip6t_entry happens to absorb, so the entry layout is right by
 * luck rather than by construction. Aligned as Linux has them, it is neither.
 */
struct nf_in_addr  { uint32_t addr;     };
struct nf_in6_addr { uint32_t addr[4];  };

struct ipt_ip {
  struct nf_in_addr src, dst;
  struct nf_in_addr smsk, dmsk;
  char          iniface[LINUX_IFNAMSIZ];
  char          outiface[LINUX_IFNAMSIZ];
  unsigned char iniface_mask[LINUX_IFNAMSIZ];
  unsigned char outiface_mask[LINUX_IFNAMSIZ];
  uint16_t proto;
  uint8_t  flags;
  uint8_t  invflags;
};

struct ipt_entry {
  struct ipt_ip ip;
  unsigned int  nfcache;
  uint16_t      target_offset;
  uint16_t      next_offset;
  unsigned int  comefrom;
  struct xt_counters counters;
  unsigned char elems[0];
};

struct ip6t_ip6 {
  struct nf_in6_addr src, dst;
  struct nf_in6_addr smsk, dmsk;
  char          iniface[LINUX_IFNAMSIZ];
  char          outiface[LINUX_IFNAMSIZ];
  unsigned char iniface_mask[LINUX_IFNAMSIZ];
  unsigned char outiface_mask[LINUX_IFNAMSIZ];
  uint16_t proto;
  uint8_t  tos;
  uint8_t  flags;
  uint8_t  invflags;
};

struct ip6t_entry {
  struct ip6t_ip6 ipv6;
  unsigned int    nfcache;
  uint16_t        target_offset;
  uint16_t        next_offset;
  unsigned int    comefrom;
  struct xt_counters counters;
  unsigned char   elems[0];
};

/* What GET_INFO answers, and what SET_REPLACE is given, are the same table
 * described twice - the first without the entries and the second with them. */
struct ipt_getinfo {
  char         name[XT_TABLE_MAXNAMELEN];
  unsigned int valid_hooks;
  unsigned int hook_entry[NF_INET_NUMHOOKS];
  unsigned int underflow[NF_INET_NUMHOOKS];
  unsigned int num_entries;
  unsigned int size;
};

/*
 * The entries follow the header, and where they start is not where adding the
 * fields up puts them. Linux declares this with a trailing
 * "struct ipt_entry entrytable[0]", and an entry is eight-byte aligned because
 * it ends in two 64-bit counters - so the header is padded from 36 to 40, and
 * the blob begins at 40.
 *
 * Writing it at 36 puts every offset in the table four bytes from where
 * libiptc reads it, and libiptc walks the blob by those offsets. Nothing about
 * that looks like a size mistake from the outside: it reads the first entry,
 * fails to recognise it as any of the things an entry can be, and aborts with
 * "0 not a valid target)". The array is declared rather than the padding
 * written out, so the alignment stays whatever an entry's alignment is.
 */
struct ipt_get_entries {
  char         name[XT_TABLE_MAXNAMELEN];
  unsigned int size;
  struct ipt_entry entrytable[0];
};

struct ipt_replace {
  char         name[XT_TABLE_MAXNAMELEN];
  unsigned int valid_hooks;
  unsigned int num_entries;
  unsigned int size;
  unsigned int hook_entry[NF_INET_NUMHOOKS];
  unsigned int underflow[NF_INET_NUMHOOKS];
  unsigned int num_counters;
  uint64_t     counters;        /* a pointer in the guest, never followed */
  /* the entries follow */
};

struct xt_get_revision {
  char    name[XT_EXTENSION_MAXNAMELEN];
  uint8_t revision;
};

/* Everything in a table is rounded to this. */
#define XT_ALIGN(s) (((s) + 7u) & ~7u)

#endif
