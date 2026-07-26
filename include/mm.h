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
  int mm_flags;        /* mm flags in the form of LINUX_MAP_* */
  int mm_fd;
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
