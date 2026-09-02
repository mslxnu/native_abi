/*
 * bpf(2), for the one thing iptables asks it.
 *
 * There is no eBPF here and no prospect of one: nothing in nabi runs a program
 * in a kernel context, and no packet passes through a place a filter could be
 * attached to. What exists is a descriptor.
 *
 * That turns out to be all `-m bpf --object-pinned` needs. iptables looks a
 * pinned object up, keeps the descriptor it gets in the rule's match data, and
 * hands the rule to IPT_SO_SET_REPLACE - which src/net/netfilter.c stores as an
 * opaque blob and never reads into. Nobody dereferences the descriptor, on
 * either side, so an inert one carries the rule as well as a real one would.
 *
 * The alternative was answering ENOSYS, which is where this started, and the
 * answer iptables gives to that is to fail the rule: `bpf: failed to get bpf
 * object`. That fails the batch, which ends iptables-restore, which is netd's
 * persistent child - so netd's next write is EPIPE and SIGPIPE, init answers a
 * dead netd by restarting zygote, and zygote's onrestart kills surfaceflinger,
 * audioserver, cameraserver and media. Measured over one boot, 46 of 48
 * iptables-restore children died on this and none died on anything else.
 *
 * Only BPF_OBJ_GET is answered. Everything else stays ENOSYS, deliberately:
 * netd's TrafficController decides at startup what it can do, and it currently
 * decides that with map creation and program loading failing. Making those
 * appear to work would move it onto a path that then needs maps to hold real
 * counters, which these cannot. A kernel that hands out a pinned object it
 * cannot have created is not a kernel - it is a descriptor for a rule that will
 * never match, which is what this is.
 */
#include "common.h"
#include "noah.h"
#include "mm.h"
#include "linux/common.h"
#include "linux/errno.h"

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define LINUX_BPF_OBJ_GET 7

/* The anonymous struct the BPF_OBJ_* commands use, at the head of the union
 * every bpf command shares. Callers pass the size they know: iptables sends
 * these sixteen bytes, libbpf the whole union. */
struct bpf_obj_attr {
  uint64_t pathname;
  uint32_t bpf_fd;
  uint32_t file_flags;
};

/* Where a pinned object can live. Nothing else gets a descriptor, so a guest
 * asking about some other path is told what it would be told on Linux. */
#define BPF_PIN_ROOT "/sys/fs/bpf/"

DEFINE_SYSCALL(bpf, int, cmd, gaddr_t, attr_ptr, unsigned int, size)
{
  if (cmd != LINUX_BPF_OBJ_GET)
    return -LINUX_ENOSYS;
  if (size < sizeof(struct bpf_obj_attr))
    return -LINUX_EINVAL;

  struct bpf_obj_attr attr;
  if (copy_from_user(&attr, attr_ptr, sizeof attr))
    return -LINUX_EFAULT;

  char path[LINUX_PATH_MAX];
  if (strncpy_from_user(path, (gaddr_t) attr.pathname, sizeof path) < 0)
    return -LINUX_EFAULT;
  if (strncmp(path, BPF_PIN_ROOT, sizeof BPF_PIN_ROOT - 1) != 0)
    return -LINUX_ENOENT;

  /*
   * Inert, and readable so that anything treating it as a file rather than as
   * a token gets an empty one rather than an error.
   *
   * Not close-on-exec: the kernel's is not, and on arm64 a fork here is an
   * exec, so marking it would take the descriptor away from the child that
   * inherited the rule.
   */
  int fd = open("/dev/null", O_RDONLY);
  if (fd < 0)
    return syswrap(-1);
  int r = register_fd(fd, false);
  if (r < 0) {
    close(fd);
    return r;
  }
  return fd;
}
