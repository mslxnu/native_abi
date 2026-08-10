#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <strings.h>

#include "common.h"
#include "util/list.h"
#include "mm.h"
#include "vmm.h"
#include "noah.h"

#include "page.h"
#include "linux/mman.h"


/* 
 * Manage kernel memory space allocated by kmap.
 * Some members related to user memory space such as start_brk are meaningless in vkern_mm.
 */
struct mm vkern_mm;

void init_mmap(struct mm *mm);

const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

gaddr_t
kmap(void *ptr, size_t size, hv_memory_flags_t flags)
{
  static uint64_t noah_kern_brk = user_addr_max;

  assert((size & 0xfff) == 0);
  assert(((uint64_t) ptr & 0xfff) == 0);

  pthread_rwlock_wrlock(&vkern_mm.alloc_lock);

  record_region(&vkern_mm, ptr, noah_kern_brk, size, hv_mflag_to_linux_mprot(flags), -1, -1, 0);
  vmm_mmap(noah_kern_brk, size, flags, ptr);
  noah_kern_brk += size;

  pthread_rwlock_unlock(&vkern_mm.alloc_lock);

  return noah_kern_brk - size;
}


void
init_mm(struct mm *mm)
{
  bzero(mm, sizeof(struct mm));
  init_mmap(mm);

  INIT_LIST_HEAD(&mm->mm_regions);
  RB_INIT(&mm->mm_region_tree);
  pthread_rwlock_init(&mm->alloc_lock, NULL);
}

void *
guest_to_host(gaddr_t gaddr)
{
  struct mm_region *region = find_region(gaddr, proc.mm);
  if (!region) {
    region = find_region(gaddr, &vkern_mm);
  }
  if (!region) {
    return NULL;
  }
  return region->haddr + gaddr - region->gaddr;
}


int
region_compare(struct mm_region *r1, struct mm_region *r2)
{
  if (r1->gaddr >= r2->gaddr + r2->size) {
    return 1;
  }
  if (r1->gaddr + r1->size <= r2->gaddr) {
    return -1;
  }
  
  return 0;
}

RB_GENERATE(mm_region_tree, mm_region, tree, region_compare);

struct mm_region*
/* Look up the mm_region which gaddr in [mm_region->gaddr, +size) */
find_region(gaddr_t gaddr, struct mm *mm)
{
  struct mm_region find = {.gaddr = gaddr, .size = 1};
  return RB_FIND(mm_region_tree, &mm->mm_region_tree, &find);
}

struct mm_region*
/* Look up the lowest mm_region that overlaps with the region */
find_region_range(gaddr_t gaddr, size_t size, struct mm *mm)
{
  struct mm_region find = {.gaddr = gaddr, .size = size};
  struct mm_region *leftmost = RB_FIND(mm_region_tree, &mm->mm_region_tree, &find);
  if (leftmost == NULL)
    return NULL;
  while (RB_LEFT(leftmost, tree) != NULL && region_compare(&find, RB_LEFT(leftmost, tree)) == 0)
    leftmost = RB_LEFT(leftmost, tree);
  return leftmost;
}

void
split_region(struct mm *mm, struct mm_region *region, gaddr_t gaddr)
{
  assert(is_page_aligned((void*)gaddr, PAGE_4KB));

  struct mm_region *tail = malloc(sizeof(struct mm_region));
  int offset = gaddr - region->gaddr;
  tail->haddr = region->haddr + offset;
  /* The tail's arena range is the parent's, advanced by the same amount as its
   * host address - the two are one allocation. */
  tail->arena_off = region->arena_off < 0 ? -1 : region->arena_off + offset;
  tail->gaddr = gaddr;
  tail->size = region->size - offset;
  tail->prot = region->prot;
  tail->mm_flags = region->mm_flags;
  tail->mm_fd = region->mm_fd;
  tail->pgoff = region->pgoff;
  tail->shm_id = region->shm_id;

  region->size = offset;
  list_add(&tail->list, &region->list);
  RB_INSERT(mm_region_tree, &mm->mm_region_tree, tail);
}

struct mm_region*
record_region(struct mm *mm, void *haddr, gaddr_t gaddr, size_t size, int prot, int mm_flags, int mm_fd, int pgoff)
{
  assert(gaddr != 0);

  struct mm_region *region = malloc(sizeof *region);
  *region = (struct mm_region) {
    .haddr = haddr,
    .arena_off = -1,      /* callers that allocate from the arena set this */
    .shm_id = -1,         /* shmat sets this; nothing else is an attachment */
    .gaddr = gaddr,
    .size = size,
    .prot = prot,
    .mm_flags = mm_flags,
    .mm_fd = mm_fd,
    .pgoff = pgoff
  };

  struct mm_region *clash = RB_INSERT(mm_region_tree, &mm->mm_region_tree, region);
  if (clash != NULL) {
    /* Naming both is the difference between a panic that ends an
     * investigation and one that starts it: the message alone says nothing
     * about which mapping was already there or how far the new one reached
     * into it. */
    panic("recording overlapping regions: new [%#llx, %#llx) over "
          "existing [%#llx, %#llx)\n",
          (unsigned long long) gaddr, (unsigned long long) (gaddr + size),
          (unsigned long long) clash->gaddr,
          (unsigned long long) (clash->gaddr + clash->size));
  }
  struct mm_region *prev = RB_PREV(mm_region_tree, &mm->mm_region_tree, region);
  if (prev == NULL) {
    list_add(&region->list, &mm->mm_regions);
  } else {
    list_add(&region->list, &prev->list);
  }

  return region;
}

bool
is_region_private(struct mm_region *region)
{
  return !(region->mm_flags & LINUX_MAP_SHARED) && region->mm_fd == -1;
}

void
destroy_mm(struct mm *mm)
{
  struct list_head *list, *t;
  list_for_each_safe (list, t, &mm->mm_regions) {
    struct mm_region *r = list_entry(list, struct mm_region, list);
    munmap(r->haddr, r->size);
    vmm_munmap(r->gaddr, r->size);
    if (r->arena_off >= 0)
      arena_free(r->arena_off, r->size);
    free(r);
  }
  RB_INIT(&mm->mm_region_tree);
  INIT_LIST_HEAD(&mm->mm_regions);
}

DEFINE_SYSCALL(madvise, gaddr_t, addr, size_t, length, int, advice)
{
  printk("madvise is not implemented\n");
  return 0;

}

DEFINE_SYSCALL(mlock, gaddr_t, addr, size_t, length)
{
  printk("mlock is not implemented\n");
  return 0;
}

DEFINE_SYSCALL(munlock, gaddr_t, addr, size_t, length)
{
  printk("munlock is not implemented\n");
  return 0;
}

DEFINE_SYSCALL(brk, unsigned long, brk)
{
  uint64_t ret;
  /* The granule the mapping behind the break is rounded to, not the guest's
   * page size. Rounding to 4KiB while do_mmap rounded the mapping to 16KiB left
   * the region reaching past current_brk, so the next brk started inside a
   * region that already existed. The guest is told AT_PAGESZ is 16KiB anyway,
   * so this is the size it already believes a page to be. */
  brk = roundup(brk, GUEST_MMAP_GRANULE);

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  if (brk < proc.mm->start_brk) {
    /*
     * Below the floor, so nothing moves - and the answer is the break as it
     * stands, not where it started.
     *
     * brk(0) is how every libc asks what the break *is*, and it lands here
     * because 0 is below any floor. Answering with start_brk told glibc the
     * heap was empty when it was not: static startup takes its TLS block with
     * sbrk, so by the time it asks, the break has already moved. glibc believed
     * the lower number, and the next allocation handed out the same memory a
     * second time, on top of the thread pointer.
     *
     * The symptom was a segfault on 0x6e756f46206572a7 - ASCII text rather than
     * an address, a pointer with a string written through it - and it only
     * appeared when LANG was set, because a C-locale process never allocates
     * again after TLS and so never notices that it was handed the same bytes
     * twice.
     */
    ret = proc.mm->current_brk;
    goto out;
  }

  if (brk < proc.mm->current_brk) {
    do_munmap(brk, proc.mm->current_brk - brk);
    ret = proc.mm->current_brk = brk;
  } else if (brk > proc.mm->current_brk) {
    /*
     * Stop at the first thing already mapped, and answer with the break as it
     * stands.
     *
     * That is what Linux does, and returning the *old* break is the signal
     * malloc uses to give up on the heap and switch to mmap - brk(2) reports
     * the break it managed, not the one it was asked for. Growing regardless
     * marched the heap straight into the mmap area: pacman took it from
     * 0x488000 to 0xc0000000 in 2MiB steps and then recorded a region on top of
     * a loaded image, which is a panic rather than an answer.
     */
    if (find_region_range(proc.mm->current_brk,
                          brk - proc.mm->current_brk, proc.mm) != NULL) {
      ret = proc.mm->current_brk;
      goto out;
    }
    do_mmap(proc.mm->current_brk, brk - proc.mm->current_brk, PROT_READ | PROT_WRITE, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);
    ret = proc.mm->current_brk = brk;
  } else {
    ret = proc.mm->current_brk;
  }

out:
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  return ret;
}

DEFINE_SYSCALL(get_mempolicy, gaddr_t, policy, gaddr_t, nmask, unsigned long, maxnode, unsigned long, addr, unsigned long, flags)
{
  maxnode = roundup(maxnode, sizeof(unsigned long));
  if (flags != 0) {
    printk("get_mempolicy: unsupported flags: 0x%lx\n", flags);
    return -LINUX_ENOSYS;
  }
  assert(addr == 0);
  int policy_val = LINUX_MPOL_DEFAULT;
  if (copy_to_user(policy, &policy_val, sizeof policy_val))
    return -LINUX_EFAULT;
  size_t size = maxnode / 64;
  unsigned long mask[size];
  memset(mask, 0, sizeof mask);
  if (copy_to_user(nmask, mask, sizeof mask))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(msync, gaddr_t, addr, size_t, len, int, flags)
{
  struct mm_region *region = find_region(addr, proc.mm);
  if (!region || addr - region->gaddr >= len || len + addr - region->gaddr > region->size) {
    return -LINUX_ENOMEM;
  }
  
  if (flags & ~(LINUX_MS_ASYNC | LINUX_MS_SYNC | LINUX_MS_INVALIDATE)) {
    return -LINUX_EINVAL;
  }
  int dflags = 0;
  if (flags & LINUX_MS_ASYNC) dflags |= MS_ASYNC;
  if (flags & LINUX_MS_SYNC) dflags |= MS_SYNC;
  if (flags & LINUX_MS_INVALIDATE) dflags |= MS_INVALIDATE;
  
  return syswrap(msync(addr - region->gaddr + region->haddr, len, dflags));
}
