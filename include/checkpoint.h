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

#define CHECKPOINT_MAGIC   0x4E414249434B5031ULL  /* "NABICKP1" */
#define CHECKPOINT_VERSION 1

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

  uint32_t nr_regions;
  uint32_t nr_s2;
  uint32_t nr_pt_chunks;
  uint32_t _pad2;
};

/*
 * Write the current guest to `fd`, or read one back. The reader only parses -
 * it does not touch the live machine - so a caller can inspect a checkpoint
 * without adopting it. Both return 0, or -1 with errno set.
 */
int checkpoint_write(int fd);
int checkpoint_read(int fd, struct checkpoint_header *hdr,
                    struct checkpoint_region **regions,
                    struct checkpoint_s2 **s2,
                    struct checkpoint_pt_chunk **chunks);

#endif
