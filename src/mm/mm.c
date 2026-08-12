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
  /* Both halves of a sealed region stay sealed; splitting is not a way out. */
  tail->sealed = region->sealed;

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

/*
 * Locking guest memory into RAM, which turns out to mean something here.
 *
 * mlock and munlock were stubs: they printed a line and returned 0, and the
 * syscall table said they worked. That is the shape of failure that matters
 * most for these two, because the callers are gpg, ssh-agent and the like,
 * locking a buffer so a passphrase cannot reach swap. Success without locking
 * is precisely the answer that leaves the secret swappable while the program
 * believes it is not.
 *
 * The lock is real. Guest memory is host memory - a private mapping of the
 * arena, on arm64 - so a guest range translates to a host range, and Darwin's
 * mlock wires it. A guest asking not to be paged out gets a process that is not
 * paged out over those addresses.
 *
 * What it is not is a promise about the *guest's* view of physical memory,
 * which nabi does not own: the hypervisor's stage-2 mapping is what makes a
 * host page a guest page, and this pins the host page underneath it. That is
 * the meaningful half, and it is the half mlock exists for.
 */
static int
mlock_range(gaddr_t addr, size_t length, bool lock)
{
  size_t ps = PAGE_SIZEOF(PAGE_4KB);
  if (length == 0)
    return 0;
  /* Linux rounds the range out to whole pages rather than refusing an
   * unaligned start, which is why this is not an EINVAL. */
  gaddr_t end = addr + length;
  if (end < addr)
    return -LINUX_ENOMEM;
  addr = addr & ~(gaddr_t) (ps - 1);
  end = roundup(end, ps);

  int ret = 0;
  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  for (gaddr_t p = addr; p < end; ) {
    struct mm_region *region = find_region(p, proc.mm);
    if (region == NULL) {
      /* Linux answers ENOMEM for a range that is not all mapped, and it does
       * so having locked nothing - so this stops rather than locking the part
       * it could reach. */
      ret = -LINUX_ENOMEM;
      break;
    }
    gaddr_t rend = region->gaddr + region->size;
    gaddr_t stop = rend < end ? rend : end;
    void *haddr = (char *) region->haddr + (p - region->gaddr);
    size_t len = (size_t) (stop - p);
    int r = lock ? mlock(haddr, len) : munlock(haddr, len);
    if (r < 0) {
      ret = syswrap(r);
      break;
    }
    p = stop;
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

DEFINE_SYSCALL(mlock, gaddr_t, addr, size_t, length)
{
  return mlock_range(addr, length, true);
}

DEFINE_SYSCALL(munlock, gaddr_t, addr, size_t, length)
{
  return mlock_range(addr, length, false);
}

/*
 * mlock2 is mlock with a flag, and the flag is the interesting part.
 *
 * MLOCK_ONFAULT says: do not fault the range in now, but keep whatever of it
 * does get faulted in. It exists because plain mlock populates the whole range
 * eagerly, which for a large sparse allocation is a lot of memory a program
 * never wanted resident.
 *
 * Darwin's mlock has no such mode - it wires what it is given - so honouring
 * the flag by ignoring it would populate exactly the range the caller asked not
 * to be populated, which is the cost it called mlock2 to avoid. Refused
 * instead, and a caller that gets EINVAL for a flag falls back to mlock and
 * gets what it would have got anyway, knowingly.
 */
DEFINE_SYSCALL(mlock2, gaddr_t, addr, size_t, length, int, flags)
{
  if (flags & ~LINUX_MLOCK_ONFAULT)
    return -LINUX_EINVAL;
  if (flags & LINUX_MLOCK_ONFAULT)
    return -LINUX_EINVAL;       /* see above: not silently the other thing */
  return mlock_range(addr, length, true);
}

/*
 * mlockall and munlockall, over the guest's mappings rather than the host's.
 *
 * Darwin has mlockall, and calling it would be the wrong thing: it would lock
 * nabi's entire address space - its own heap, its stacks, the whole arena
 * including memory belonging to no live mapping - when what was asked for was
 * the guest's. So this walks the guest's regions instead, which is the same set
 * Linux would act on.
 *
 * MCL_FUTURE is refused rather than accepted, and this is the same judgement
 * mlock2's flag gets. It promises that mappings made *later* are locked too, and
 * nothing here would do that - do_mmap knows nothing about it. Accepting it
 * would mean a program that locks everything and then allocates its secret
 * buffer finds the buffer unlocked, which is the case MCL_FUTURE is for.
 */
DEFINE_SYSCALL(mlockall, int, flags)
{
  if (flags & ~(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT))
    return -LINUX_EINVAL;
  if (flags == 0)
    return -LINUX_EINVAL;       /* neither current nor future is nothing */
  if (flags & (LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT))
    return -LINUX_EINVAL;       /* see above */

  int ret = 0;
  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  struct mm_region *region;
  list_for_each_entry (region, &proc.mm->mm_regions, list) {
    if (mlock(region->haddr, region->size) < 0) {
      ret = syswrap(-1);
      break;
    }
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

DEFINE_SYSCALL(munlockall)
{
  /*
   * Unlocking cannot half-fail into something a caller must undo, so unlike
   * mlockall this keeps going and reports the first complaint. Leaving later
   * regions locked because an earlier one objected is the worse outcome.
   */
  int ret = 0;
  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  struct mm_region *region;
  list_for_each_entry (region, &proc.mm->mm_regions, list) {
    if (munlock(region->haddr, region->size) < 0 && ret == 0)
      ret = syswrap(-1);
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
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
