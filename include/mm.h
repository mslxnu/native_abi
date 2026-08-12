#ifndef NOAH_MM_H
#define NOAH_MM_H

#include <pthread.h>
#include <stdbool.h>

/*
 * For hv_memory_flags_t, used in the prototypes below. Previously this header
 * relied on whoever included it having pulled in a Hypervisor header first,
 * which held only because vmm.h did so - and broke as soon as an arm64 file
 * included mm.h on its own.
 *
 * The umbrella header, not hv_types.h: that one is inside `#ifdef __x86_64__`,
 * and the arm64 definition lives in hv_vm_types.h behind `#ifdef __arm64__`.
 * Hypervisor.h resolves to whichever applies.
 */
#include <Hypervisor/Hypervisor.h>

#include "types.h"
#include "noah.h"

/*
 * The unit guest mappings are rounded to.
 *
 * On arm64 it is the stage-2 granule rather than the guest's own page size: a
 * mapping smaller than a 16KiB block cannot be given back independently, since
 * vmm_munmap works a block at a time. It lives here rather than in mmap.c
 * because brk has to agree with it - rounding the break to 4KiB while the
 * mapping behind it was rounded to 16KiB left the recorded region reaching past
 * current_brk, so the next brk mapped from inside a region that already existed
 * and record_region panicked with "recording overlapping regions".
 */
#if defined(__arm64__)
#include "arm64/vm.h"
#define GUEST_MMAP_GRANULE STAGE2_GRANULE
#else
#define GUEST_MMAP_GRANULE PAGE_SIZEOF(PAGE_4KB)
#endif
#include "util/list.h"
#include "util/tree.h"

RB_HEAD(mm_region_tree, mm_region);

struct mm_region {
  RB_ENTRY(mm_region) tree;
  void *haddr;
  /*
   * Where this region's memory lives in the guest arena, or -1 if it is not
   * arena-backed (x86, and file mappings that must stay real file mappings).
   * The host address means nothing to another process; the offset is what a
   * resuming child can act on. See src/mm/arena.c.
   */
  off_t arena_off;
  gaddr_t gaddr;
  size_t size;
  int prot;            /* Access permission that consists of LINUX_PROT_* */
  /*
   * mseal: this range's layout is frozen for the life of the mapping. Set once
   * and never cleared - the call is deliberately irreversible - and checked by
   * mmap, mprotect, mremap and munmap in src/mm/mmap.c. It travels in the
   * checkpoint, because a fork here is a fork plus an exec and a child that
   * lost its seals would be quietly less protected than its parent.
   */
  bool sealed;
  int mm_flags;        /* mm flags in the form of LINUX_MAP_* */
  int mm_fd;
  /*
   * The shared-memory segment this region is an attachment to, or -1.
   *
   * Kept on the region rather than in a table beside it because the region *is*
   * the attachment - there is exactly one per shmat - so the two cannot drift
   * apart, and because regions travel in the checkpoint, which is what lets a
   * forked child detach a segment it inherited.
   */
  int shm_id;
  int pgoff;           /* offset within mm_fd in page size */
  bool is_global;      /* global page flag. Preserved during exec if global */
  struct list_head list;
};

struct mm {
  struct mm_region_tree mm_region_tree;
  struct list_head mm_regions;
  uint64_t start_brk, current_brk;
  uint64_t current_mmap_top;
  pthread_rwlock_t alloc_lock;
};

extern const gaddr_t user_addr_max;

extern struct mm vkern_mm;

void init_page();
void init_segment();
void init_mm(struct mm *mm);
void init_shm_malloc();

gaddr_t kmap(void *ptr, size_t size, hv_memory_flags_t flags);

RB_PROTOTYPE(mm_region_tree, mm_region, tree, mm_region_cmp);
int region_compare(struct mm_region *r1, struct mm_region *r2);
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm);
struct mm_region *find_region_range(gaddr_t gaddr, size_t size, struct mm *mm);
struct mm_region *record_region(struct mm *mm, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff);
void split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr);
void destroy_mm(struct mm *mm);

bool is_region_private(struct mm_region*);

gaddr_t do_mmap(gaddr_t addr, size_t len, int d_prot, int l_prot, int l_flags, int fd, off_t offset);
int do_munmap(gaddr_t gaddr, size_t size);

int hv_mflag_to_linux_mprot(hv_memory_flags_t mflag);
hv_memory_flags_t linux_mprot_to_hv_mflag(int mprot);

/*
 * The guest-physical memory arena (src/mm/arena.c). Guest memory is carved out
 * of one unlinked, file-backed arena so that a descriptor - which survives
 * exec - names it, which is what lets a fork's child reach the parent's guest
 * memory after it has had to exec. See spike/arm64-fork/.
 */
void  arena_init(void);
void *arena_alloc(size_t size, off_t *off_out);
void  arena_free(off_t off, size_t size);
off_t arena_offset_of(void *addr);
int   arena_snapshot(void);
void *arena_hva_of(off_t off);
void  arena_unmap(void *addr, size_t size);
void *arena_map_private(off_t off, size_t size);
void  arena_adopt(int fd);
int   arena_fd(void);

#endif
