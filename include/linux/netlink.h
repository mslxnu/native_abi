/*
 * Netlink, the socket a Linux program asks the kernel about itself through.
 *
 * There is no host counterpart. Darwin's routing socket answers some of the
 * same questions in a different shape, and its ioctls answer others, but
 * nothing on this side speaks the protocol - so the protocol is what has to be
 * spoken. See src/net/netlink.c.
 */
#ifndef NABI_LINUX_NETLINK_H
#define NABI_LINUX_NETLINK_H

#include "linux/common.h"
#include "linux/socket.h"

#define LINUX_AF_NETLINK        16
#define LINUX_PF_NETLINK        LINUX_AF_NETLINK

/* The protocols a netlink socket can be opened on; only the first is served. */
#define LINUX_NETLINK_ROUTE           0
#define LINUX_NETLINK_USERSOCK        2
#define LINUX_NETLINK_SOCK_DIAG       4
#define LINUX_NETLINK_KOBJECT_UEVENT 15
#define LINUX_NETLINK_AUDIT           9

/* struct l_sockaddr_nl lives in linux/socket.h, beside the other families. */

struct l_nlmsghdr {
  uint32_t nlmsg_len;
  uint16_t nlmsg_type;
  uint16_t nlmsg_flags;
  uint32_t nlmsg_seq;
  uint32_t nlmsg_pid;
};

struct l_nlmsgerr {
  int32_t  error;
  struct l_nlmsghdr msg;
};

/* Message flags. */
#define LINUX_NLM_F_REQUEST   0x001
#define LINUX_NLM_F_MULTI     0x002
#define LINUX_NLM_F_ACK       0x004
#define LINUX_NLM_F_ECHO      0x008
#define LINUX_NLM_F_ROOT      0x100
#define LINUX_NLM_F_MATCH     0x200
#define LINUX_NLM_F_ATOMIC    0x400
#define LINUX_NLM_F_DUMP      (LINUX_NLM_F_ROOT | LINUX_NLM_F_MATCH)
/* Flags for a request that creates something. */
#define LINUX_NLM_F_REPLACE   0x100
#define LINUX_NLM_F_EXCL      0x200
#define LINUX_NLM_F_CREATE    0x400
#define LINUX_NLM_F_APPEND    0x800

/* The message types every protocol has. */
#define LINUX_NLMSG_NOOP      1
#define LINUX_NLMSG_ERROR     2
#define LINUX_NLMSG_DONE      3
#define LINUX_NLMSG_OVERRUN   4
#define LINUX_NLMSG_MIN_TYPE  0x10

/* rtnetlink message types, the subset that means anything here. */
#define LINUX_RTM_NEWLINK     16
#define LINUX_RTM_DELLINK     17
#define LINUX_RTM_GETLINK     18
#define LINUX_RTM_SETLINK     19
#define LINUX_RTM_NEWADDR     20
#define LINUX_RTM_DELADDR     21
#define LINUX_RTM_GETADDR     22
#define LINUX_RTM_NEWROUTE    24
#define LINUX_RTM_DELROUTE    25
#define LINUX_RTM_GETROUTE    26
#define LINUX_RTM_NEWNEIGH    28
#define LINUX_RTM_DELNEIGH    29
#define LINUX_RTM_GETNEIGH    30

struct l_ifinfomsg {
  uint8_t  ifi_family;
  uint8_t  __ifi_pad;
  uint16_t ifi_type;
  int32_t  ifi_index;
  uint32_t ifi_flags;
  uint32_t ifi_change;
};

struct l_ifaddrmsg {
  uint8_t  ifa_family;
  uint8_t  ifa_prefixlen;
  uint8_t  ifa_flags;
  uint8_t  ifa_scope;
  uint32_t ifa_index;
};

struct l_rtattr {
  uint16_t rta_len;
  uint16_t rta_type;
};

/* Link attributes. */
#define LINUX_IFLA_UNSPEC      0
#define LINUX_IFLA_ADDRESS     1
#define LINUX_IFLA_BROADCAST   2
#define LINUX_IFLA_IFNAME      3
#define LINUX_IFLA_MTU         4
#define LINUX_IFLA_LINK        5
#define LINUX_IFLA_QDISC       6
#define LINUX_IFLA_STATS       7
#define LINUX_IFLA_TXQLEN     13
#define LINUX_IFLA_OPERSTATE  16
#define LINUX_IFLA_LINKMODE   17
#define LINUX_IFLA_GROUP      27

/* Address attributes. */
#define LINUX_IFA_UNSPEC       0
#define LINUX_IFA_ADDRESS      1
#define LINUX_IFA_LOCAL        2
#define LINUX_IFA_LABEL        3
#define LINUX_IFA_BROADCAST    4
#define LINUX_IFA_FLAGS        8

/* Interface flags, which are Linux's numbers and not Darwin's. */
#define LINUX_IFF_UP          0x0001
#define LINUX_IFF_BROADCAST   0x0002
#define LINUX_IFF_DEBUG       0x0004
#define LINUX_IFF_LOOPBACK    0x0008
#define LINUX_IFF_POINTOPOINT 0x0010
#define LINUX_IFF_NOARP       0x0080
#define LINUX_IFF_PROMISC     0x0100
#define LINUX_IFF_RUNNING     0x0040
#define LINUX_IFF_MULTICAST   0x1000

/* Hardware types. */
#define LINUX_ARPHRD_ETHER      1
#define LINUX_ARPHRD_LOOPBACK 772
#define LINUX_ARPHRD_NONE     0xfffe

/* operstate */
#define LINUX_IF_OPER_DOWN     2
#define LINUX_IF_OPER_UP       6

/* Address scopes. */
#define LINUX_RT_SCOPE_UNIVERSE   0
#define LINUX_RT_SCOPE_LINK     253
#define LINUX_RT_SCOPE_HOST     254

#define LINUX_NLMSG_ALIGNTO 4U
#define LINUX_NLMSG_ALIGN(len) (((len) + LINUX_NLMSG_ALIGNTO - 1) & ~(LINUX_NLMSG_ALIGNTO - 1))
#define LINUX_NLMSG_HDRLEN ((int) LINUX_NLMSG_ALIGN(sizeof(struct l_nlmsghdr)))
#define LINUX_RTA_ALIGNTO 4U
#define LINUX_RTA_ALIGN(len) (((len) + LINUX_RTA_ALIGNTO - 1) & ~(LINUX_RTA_ALIGNTO - 1))

#endif
