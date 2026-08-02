#ifndef NOAH_CHECKPOINT_H
#define NOAH_CHECKPOINT_H

/*
 * Handing a running guest to another process.
 *
 * fork on Apple Silicon cannot simply copy the address space: the child has to
 * `exec` before it may create a vCPU (spike/arm64-fork/), and `exec` throws the
 * copy away. What survives is descriptors, so the guest is handed over as the
 * arena descriptor (src/mm/arena.c) plus this: a flat, self-describing
 * description of everything about the guest that is *not* bytes of its memory.
 *
 * Nothing here contains a host pointer. A pointer is precisely what the other
 * process cannot use; every reference to memory is an arena offset instead.
 *
 * The format is deliberately dull - a header and three arrays, fixed-width
 * fields, no padding games - because it is written and read by the same binary
 * within milliseconds of itself. It is versioned anyway, so a mismatched pair
 * fails loudly rather than resuming a guest from misparsed state.
 */

#include <stdint.h>
#include <sys/types.h>

#include "vmm.h"
#include "linux/signal.h"

#define CHECKPOINT_MAGIC   0x4E414249434B5031ULL  /* "NABICKP1" */
#define CHECKPOINT_VERSION 3

/* One guest memory region, as src/mm/mmap.c tracks it, with the host address
 * replaced by the arena offset that names the same bytes elsewhere. */
struct checkpoint_region {
  uint64_t gaddr;
  uint64_t size;
  int64_t  arena_off;      /* -1: not arena-backed, cannot be handed over */
  int32_t  prot;
  int32_t  mm_flags;
  int32_t  mm_fd;
  int32_t  pgoff;
};

/* One stage-2 mapping: which guest-physical range is backed by which arena
 * bytes. The resuming side replays these into its fresh VM. */
struct checkpoint_s2 {
  uint64_t ipa;
  int64_t  arena_off;
  int32_t  prot;
  int32_t  _pad;
};

/* The stage-1 allocator's own state (src/mm/pt_arm64.c). The tables themselves
 * are guest pages and travel in the arena like any other; what cannot be
 * recomputed is where they are. */
struct checkpoint_pt_chunk {
  uint64_t ipa;
  int64_t  arena_off;
  uint32_t used;
  uint32_t _pad;
};

/*
 * One open guest file descriptor.
 *
 * Only the *table* travels. The host descriptors themselves survive fork and
 * exec on their own - that is the whole reason the handover is fork+exec rather
 * than a zygote (spike/arm64-fork/) - so what has to be written down is which
 * guest number refers to which host descriptor, and whether it is close-on-exec.
 * struct file holds nothing else worth saving: its ops pointer is the one static
 * table every file shares, and a pointer could not cross an exec anyway.
 */
struct checkpoint_fd {
  int32_t table;        /* 0 = the guest's fds, 1 = the vkernel's */
  int32_t index;        /* the guest-visible descriptor number */
  int32_t host_fd;
  int32_t cloexec;
};

struct checkpoint_header {
  uint64_t magic;
  uint32_t version;
  uint32_t _pad;

  struct vcpu_snapshot vcpu;

  /* mm scalars that are not derivable from the region list. */
  uint64_t start_brk, current_brk, current_mmap_top;

  /* stage-1 allocator */
  uint64_t ipa_brk;
  uint64_t l1_ipa;

  /*
   * Credentials, kept apart from the host's - see struct cred.
   *
   * The gids travel too, and did not until version 3. A fork on arm64 is a
   * fork plus an exec, so anything not written here is not merely stale in the
   * child, it is absent: every forked process came back with gid 0 and no
   * supplementary groups, however carefully su had set them a moment earlier.
   * The symptom is confusing because the uids did survive, so `id` reported a
   * real user in a root group.
   */
  uint32_t uid, euid, suid;
  uint32_t gid, egid, sgid;
  uint32_t nr_groups;       /* the list itself is a trailing blob */
  uint32_t _pad3;

  /* the task: what a resumed thread has to believe about itself */
  uint64_t tid;
  uint64_t set_child_tid, clear_child_tid;
  uint64_t robust_list;
  uint64_t sigmask;         /* l_sigset_t is one mask word */
  uint64_t sigpending;
  uint64_t sas_sp, sas_size;
  int32_t  sas_flags;

  /* the descriptor tables' shapes; the entries follow as checkpoint_fd[] */
  int32_t  rootfd;
  int32_t  user_start, user_size;
  int32_t  vkern_start, vkern_size;

  uint32_t nr_regions;
  uint32_t nr_s2;
  uint32_t nr_pt_chunks;
  uint32_t nr_fds;
  uint32_t nr_sigactions;

  /*
   * The guest's identity, as /proc must report it: the executable's guest path
   * and the flattened argv, both as trailing blobs after the arrays above.
   * Only NABI knows these - from outside, the process is a `nabi` - so they
   * cannot be re-derived on the far side and have to travel. Lengths include
   * the terminating NUL of each string.
   */
  uint32_t exe_len;
  uint32_t cmdline_len;
  uint32_t _pad2;
};

/*
 * Write the current guest to `fd`, or read one back. The reader only parses -
 * it does not touch the live machine - so a caller can inspect a checkpoint
 * without adopting it. Both return 0, or -1 with errno set.
 */
int checkpoint_write(int fd);
void checkpoint_restore(int ckpt_fd, int arena_fd);
int checkpoint_read(int fd, struct checkpoint_header *hdr,
                    struct checkpoint_region **regions,
                    struct checkpoint_s2 **s2,
                    struct checkpoint_pt_chunk **chunks,
                    struct checkpoint_fd **fds,
                    l_sigaction_t **sigactions,
                    char **exe, char **cmdline);

#endif
