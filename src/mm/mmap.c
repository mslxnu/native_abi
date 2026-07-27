#include "common.h"

#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "x86/vm.h"

#include "linux/mman.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <mach/vm_statistics.h>
#include <pthread.h>

#include <Hypervisor/hv.h>

/*
 * The granule the guest sees as its page size. On Apple Silicon the host (and
 * the stage-2 mapping) works in 16KiB pages, so the guest is told 16KiB via
 * AT_PAGESZ and every mmap region is kept 16KiB-aligned and 16KiB-granular -
 * otherwise ld.so mapping library segments at 4KiB boundaries would split a
 * 16KiB stage-2 block, which vmm_munmap cannot do. x86 keeps its native 4KiB.
 */
#if defined(__arm64__)
#include "arm64/vm.h"
void pt_protect(gaddr_t va, size_t size, int prot);
#define GUEST_MMAP_GRANULE STAGE2_GRANULE
/*
 * Guest permissions live in the stage-1 descriptors, so that is what mprotect
 * rewrites (pt_protect). Not hv_vm_protect, which the x86 path uses: it takes an
 * IPA, and region->gaddr is a guest *virtual* address - handing one to the other
 * reinterprets it and repermissions an unrelated region.
 */
#define NABI_VM_PROTECT(region) pt_protect((region)->gaddr, (region)->size, prot)
/*
 * ...and the host-side mprotect is skipped too.
 *
 * The host mapping is how NABI itself reaches guest memory - copy_to_user,
 * copy_from_user, and the arena flush that hands a guest to its forked child all
 * read and write through it. Mirroring a guest PROT_NONE onto it (ld.so does
 * exactly that for guard pages and RELRO) makes NABI unable to touch the guest's
 * own memory: the flush fails with EFAULT and the guest's fork reports "Bad
 * address". It buys nothing in exchange, because the permissions the guest is
 * actually subject to are the stage-1 descriptors, not this mapping's bits.
 */
#define NABI_HOST_PROTECT(region, prot) ((void)0)
#else
#define GUEST_MMAP_GRANULE PAGE_SIZEOF(PAGE_4KB)
#define NABI_VM_PROTECT(region) hv_vm_protect((region)->gaddr, (region)->size, hvprot)
#define NABI_HOST_PROTECT(region, prot) mprotect((region)->haddr, (region)->size, prot)
#endif

void
init_mmap(struct mm *mm)
{
  mm->current_mmap_top = 0x00000000c0000000;
}

gaddr_t
alloc_region(size_t len)
{
  len = roundup(len, GUEST_MMAP_GRANULE);
  proc.mm->current_mmap_top += len;
  return proc.mm->current_mmap_top - len;
}

int
do_munmap(gaddr_t gaddr, size_t size)
{
  if (!is_page_aligned((void*)gaddr, PAGE_4KB)) {
    return -LINUX_EINVAL;
  }
  /*
   * Round up to the guest page granule, as the kernel does - glibc's ld.so
   * passes raw, unrounded segment lengths to munmap and relies on the kernel to
   * extend them to a whole page. On arm64 the granule is 16KiB, so this is also
   * what keeps a munmap from ending mid-16KiB-block and splitting it (which the
   * stage-2 layer cannot do); see GUEST_MMAP_GRANULE.
   */
  size = roundup(size, GUEST_MMAP_GRANULE);

  struct mm_region *overlapping = find_region_range(gaddr, size, proc.mm);
  if (overlapping == NULL) {
    return -LINUX_ENOMEM;
  }

  struct mm_region key = {.gaddr = gaddr, .size = size};
  while (region_compare(&key, overlapping) == 0) {
    if (overlapping->gaddr < gaddr) {
      split_region(proc.mm, overlapping, gaddr);
      overlapping = list_entry(overlapping->list.next, struct mm_region, list);
    }
    if (overlapping->gaddr + overlapping->size > gaddr + size) {
      split_region(proc.mm, overlapping, gaddr + size);
    }
    struct list_head *next = overlapping->list.next;
    list_del(&overlapping->list);
    RB_REMOVE(mm_region_tree, &proc.mm->mm_region_tree, overlapping);
    vmm_munmap(overlapping->gaddr, overlapping->size);
    munmap(overlapping->haddr, overlapping->size);
    if (overlapping->arena_off >= 0)
      arena_free(overlapping->arena_off, overlapping->size);
    free(overlapping);
    if (next == &proc.mm->mm_regions)
      break;
    overlapping = list_entry(next, struct mm_region, list);
  }

  return 0;
}

#if !defined(__arm64__)
static int
linux_to_darwin_mflags(int l_flags)
{
  int d_flags = 0;
  if (l_flags & LINUX_MAP_SHARED) d_flags |= MAP_SHARED;
  if (l_flags & LINUX_MAP_PRIVATE) d_flags |= MAP_PRIVATE;
  if (l_flags & LINUX_MAP_ANON) d_flags |= MAP_ANON;
  if (l_flags & LINUX_MAP_HUGETLB) d_flags |= VM_FLAGS_SUPERPAGE_SIZE_ANY;
  return d_flags;
}
#endif

gaddr_t
do_mmap(gaddr_t addr, size_t len, int d_prot, int l_prot, int l_flags, int fd, off_t offset)
{
  assert((addr & 0xfff) == 0);

  /* some l_flags are obsolete and just ignored */
  l_flags &= ~LINUX_MAP_DENYWRITE;
  l_flags &= ~LINUX_MAP_EXECUTABLE;

  /* We ignore these currenlty */
  l_flags &= ~LINUX_MAP_NORESERVE;

  /* the linux kernel does nothing for LINUX_MAP_STACK */
  l_flags &= ~LINUX_MAP_STACK;

  len = roundup(len, GUEST_MMAP_GRANULE);

  if ((l_flags & ~(LINUX_MAP_SHARED | LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANON | LINUX_MAP_HUGETLB)) != 0) {
    warnk("unsupported mmap l_flags: 0x%x\n", l_flags);
    exit(1);
  }
  if (l_flags & LINUX_MAP_ANON) {
    fd = -1;
    offset = 0;
  }
  if ((l_flags & LINUX_MAP_FIXED) == 0) {
    addr = alloc_region(len);
  }

  void *ptr;
  off_t arena_off = -1;
#if defined(__arm64__)
  /*
   * Every guest region comes out of the arena, so that a descriptor names it and
   * a child that has had to exec can still reach it (src/mm/arena.c). That
   * subsumes what this path already had to do for files: Apple Silicon rejects
   * PROT_EXEC file maps (EPERM - an arbitrary file may not be mapped executable
   * under the hardened runtime) and wants 16KiB-aligned file offsets, while a
   * 4KiB-page guest's ld.so maps library segments R-X at 4KiB-aligned offsets,
   * so a file's bytes have to be copied into memory we own regardless. The
   * guest's real R/W/X comes from stage-2 (vmm_mmap below).
   *
   * A short read at EOF leaves the tail zero, which is what a file mapping past
   * end-of-file must read as. MAP_SHARED write-back to the file is not
   * preserved - no guest run so far needs it.
   */
  ptr = arena_alloc(len, &arena_off);
  if (fd >= 0 && pread(fd, ptr, len, offset) < 0) {
    int e = errno;
    munmap(ptr, len);
    arena_free(arena_off, len);
    return -darwin_to_linux_errno(e);
  }
#else
  {
    ptr = mmap(0, len, d_prot, linux_to_darwin_mflags(l_flags), fd, offset);
    if (ptr == MAP_FAILED)
      return -darwin_to_linux_errno(errno);
  }
#endif

  do_munmap(addr, len);
  struct mm_region *recorded =
      record_region(proc.mm, ptr, addr, len, l_prot, l_flags, fd, offset);
  recorded->arena_off = arena_off;

  vmm_mmap(addr, len, linux_mprot_to_hv_mflag(l_prot), ptr);

#if defined(__arm64__)
  /*
   * A file mapped executable was just written into guest memory by the host
   * (the pread copy above) - ld.so maps a shared library's .text this way. The
   * guest's instruction fetch will not see those bytes until the caches are
   * reconciled, exactly as the ELF loader does for its own PF_X segments. Skip
   * it for anonymous exec maps: nothing is written yet (JIT writes come later).
   */
  if ((l_prot & LINUX_PROT_EXEC) && fd >= 0)
    vmm_sync_guest_code(addr, len);
#endif

  return addr;
}

DEFINE_SYSCALL(mmap, gaddr_t, addr, size_t, len, int, prot, int, flags, int, fd, off_t, offset)
{
  uint64_t ret;
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  ret = do_mmap(addr, len, prot, prot, flags, fd, offset);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return  ret;
}

DEFINE_SYSCALL(mremap, gaddr_t, old_addr, size_t, old_size, size_t, new_size, int, flags, gaddr_t, new_addr)
{
  if (flags & ~(LINUX_MREMAP_FIXED | LINUX_MREMAP_MAYMOVE)) {
    return -LINUX_EINVAL;
  }
  if (flags & LINUX_MREMAP_FIXED && !(flags & LINUX_MREMAP_MAYMOVE))
    return -LINUX_EINVAL;
  if (!is_page_aligned((void*)old_addr, PAGE_4KB))
    return -LINUX_EINVAL;
  if (!(flags & LINUX_MREMAP_MAYMOVE)) {
    warnk("unsupported mremap flags: 0x%x\n", flags);
    return -LINUX_EINVAL;
  }

  if (new_size == 0)
    return -LINUX_EINVAL;

  /* Linux kernel also does these aligning */
  old_size = roundup(old_size, PAGE_SIZEOF(PAGE_4KB));
  new_size = roundup(new_size, PAGE_SIZEOF(PAGE_4KB));

  gaddr_t ret = old_addr;

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);

  struct mm_region *region = find_region(old_addr, proc.mm);
  /* Linux requires old_addr is the exact address of start of vm_area  */
  if (!region || region->gaddr != old_addr) {
    ret = -LINUX_EFAULT;
    goto out;
  }
  /* The region must not be across multiple regions */
  if (region->size < old_size) {
    ret = -LINUX_EFAULT;
    goto out;
  }

  /* new_size <= old_size. We can just shrink */
  if (new_size <= old_size) {
    munmap(region->haddr + new_size, region->size - new_size);
    vmm_munmap(region->gaddr + new_size, region->size - new_size);
    if (region->arena_off >= 0)
      arena_free(region->arena_off + new_size, region->size - new_size);
    region->size = new_size;
    goto out;
  }

  /* new_size > old_size */
  off_t moved_off = -1;
  void *moved_to;
#if defined(__arm64__)
  /* From the arena, like every other guest region - a region that lived outside
   * it would be unreachable to a child that has had to exec. The old contents
   * are copied across whatever the region was backed by, since the arena hands
   * back plain readable/writable memory either way. */
  moved_to = arena_alloc(new_size, &moved_off);
  if (region->mm_flags & LINUX_MAP_ANONYMOUS) {
    memcpy(moved_to, region->haddr, old_size);
  } else if (pread(region->mm_fd, moved_to, new_size, region->pgoff) < 0) {
    memcpy(moved_to, region->haddr, old_size);
  }
#else
  moved_to = mmap(0, new_size, PROT_NONE, linux_to_darwin_mflags(region->mm_flags), region->mm_fd, region->pgoff);
  if (moved_to == MAP_FAILED) {
    panic("mremap failed. old_addr :0x%llx, old_size: 0x%lux, new_size: 0x%lux, flags:0x%ux, new_addr: 0x%llx, mm_flags: 0x%ux, mm_fd: %d", old_addr, old_size, new_size, flags, new_addr, region->mm_flags, region->mm_fd);
  }
  if (!(region->mm_flags & LINUX_MAP_ANONYMOUS)) {
    /* A file is mapped to this region. We have to take the file permission into account */
    int d_prot = 0;
    if (region->prot & LINUX_PROT_READ) d_prot |= PROT_READ;
    if (region->prot & LINUX_PROT_WRITE) d_prot |= PROT_WRITE;
    mprotect(moved_to, new_size, d_prot);
  } else {
    /* Anonymous page. Copy contents to new area */
    mprotect(moved_to, new_size, PROT_READ | PROT_WRITE);
    memcpy(moved_to, region->haddr, old_size);
  }
#endif

  /* Unmap the old page */
  if (old_size < region->size) {
    split_region(proc.mm, region, region->gaddr + old_size);
  }
  list_del(&region->list);
  RB_REMOVE(mm_region_tree, &proc.mm->mm_region_tree, region);
  munmap(region->haddr, region->size);
  vmm_munmap(region->gaddr, region->size);
  if (region->arena_off >= 0)
    arena_free(region->arena_off, region->size);

  /* Map new one */
  ret = alloc_region(new_size);
  struct mm_region *new = record_region(proc.mm, moved_to, ret, new_size, region->prot, region->mm_flags, region->mm_fd, region->pgoff);
  new->arena_off = moved_off;
  vmm_mmap(new->gaddr, new->size, new->prot, new->haddr);

  free(region);

out:
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  return ret;
}

DEFINE_SYSCALL(mprotect, gaddr_t, addr, size_t, len, int, prot)
{
  if (!is_page_aligned((void*)addr, PAGE_4KB) || len == 0) {
    return -LINUX_EINVAL;
  }
  // TODO check if user is permiited to access the addr

  len = roundup(len, PAGE_SIZEOF(PAGE_4KB));
  gaddr_t end = addr + len;

  hv_memory_flags_t hvprot = 0;
  if (prot & LINUX_PROT_READ) hvprot |= HV_MEMORY_READ;
  if (prot & LINUX_PROT_WRITE) hvprot |= HV_MEMORY_WRITE;
  if (prot & LINUX_PROT_EXEC) hvprot |= HV_MEMORY_EXEC;

  int ret = 0;

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);

  struct mm_region *region = find_region(addr, proc.mm);
  if (!region) {
    ret = -LINUX_ENOMEM;
    goto out;
  }
  if (addr > region->gaddr) {
    split_region(proc.mm, region, addr);
    region = list_entry(region->list.next, struct mm_region, list);

    NABI_VM_PROTECT(region);
    NABI_HOST_PROTECT(region, prot);
    region->prot = hvprot;
  }
  while (region->gaddr + region->size <= end) {
    NABI_VM_PROTECT(region);
    NABI_HOST_PROTECT(region, prot);
    region->prot = hvprot;

    /*
     * Done: this region ends where the request does, so the whole range is
     * covered. Without this the loop goes looking for a region after the last
     * one and reports ENOMEM for an mprotect that in fact succeeded - which is
     * every mprotect of the highest mapping, and any whose range ends at a gap.
     */
    if (region->gaddr + region->size == end)
      goto out;

    if (region->list.next == &proc.mm->mm_regions) {
      ret = -LINUX_ENOMEM;
      goto out;
    }
    struct mm_region *next = list_entry(region->list.next, struct mm_region, list);
    if (next->gaddr != region->gaddr + region->size) {
      ret = -LINUX_ENOMEM;
      goto out;
    }
    region = next;
  }
  if (region->gaddr < end) {
    split_region(proc.mm, region, end);
    NABI_VM_PROTECT(region);
    NABI_HOST_PROTECT(region, prot);
    region->prot = hvprot;
  }

out:
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  return ret;
}

DEFINE_SYSCALL(munmap, gaddr_t, gaddr, size_t, size)
{
  uint64_t ret;
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  ret = do_munmap(gaddr, size);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

int
hv_mflag_to_linux_mprot(hv_memory_flags_t mflag)
{
  int l_prot = 0;
  if (mflag & HV_MEMORY_READ) l_prot |= LINUX_PROT_READ;
  if (mflag & HV_MEMORY_WRITE) l_prot |= LINUX_PROT_WRITE;
  if (mflag & HV_MEMORY_EXEC) l_prot |= LINUX_PROT_EXEC;
  return l_prot;
}

hv_memory_flags_t
linux_mprot_to_hv_mflag(int mprot)
{
  hv_memory_flags_t mflag = 0;
  if (mprot & LINUX_PROT_READ) mflag |= HV_MEMORY_READ;
  if (mprot & LINUX_PROT_WRITE) mflag |= HV_MEMORY_WRITE;
  if (mprot & LINUX_PROT_EXEC) mflag |= HV_MEMORY_EXEC;
  return mflag;
}
