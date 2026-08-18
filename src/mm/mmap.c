#include "common.h"

#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "x86/vm.h"

#include <signal.h>

#include "namespace.h"
#include "linux/mman.h"
#include "linux/socket.h"

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
  /*
   * find_region_range returns whichever overlapping node the tree search lands
   * on; when a range straddles two regions it is not guaranteed to be the first
   * one in address order, and the loop below only walks forward. Walk back to
   * the earliest overlap first, or the predecessor - which still overlaps the
   * range being unmapped - is never visited and the caller's record_region
   * panics "recording overlapping regions".
   */
  while (overlapping->list.prev != &proc.mm->mm_regions) {
    struct mm_region *prev = list_entry(overlapping->list.prev,
                                        struct mm_region, list);
    if (region_compare(&key, prev) != 0)
      break;
    overlapping = prev;
  }
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
    if (overlapping->reserved) {
      /* Nothing was ever mapped or allocated for it. */
    } else {
    vmm_munmap(overlapping->gaddr, overlapping->size);
    if (overlapping->arena_off < 0) {
      /* A real mapping (a shared file, or all of x86): the bytes belong to
       * whatever it was mapped from. Released only when this region owns whole
       * host blocks, for the same reason the arena case below is - a host page
       * is 16KiB here and a 4KiB region may be sharing one with a sibling. */
      if ((uintptr_t) overlapping->haddr % HOST_BLOCK_GRANULE == 0 &&
          overlapping->size % HOST_BLOCK_GRANULE == 0)
        munmap(overlapping->haddr, overlapping->size);
    } else {
      /*
       * Arena memory is released only as a whole chunk. A region that mprotect
       * or munmap has split shares its 16KiB block - host range and file bytes
       * alike - with the sibling it left behind. munmapping the host slice
       * would cut a hole in the block's host range while the block is still
       * live at stage 2; the next time a neighbour is unmapped the block is
       * re-established with hv_vm_map over a host range with a hole, which
       * refuses with HV_ERROR. arena_free rounds its size up to the block and
       * would punch a hole through the sibling's file bytes, which reads back
       * as zeros - so neither can go. A region that owns whole blocks has no
       * sibling in them and releases normally.
       */
      if (overlapping->arena_off % HOST_BLOCK_GRANULE == 0 &&
          overlapping->size % HOST_BLOCK_GRANULE == 0) {
        munmap(overlapping->haddr, overlapping->size);
        arena_free(overlapping->arena_off, overlapping->size);
      }
    }
    }
    if (overlapping->owns_fd && overlapping->mm_fd >= 0)
      close(overlapping->mm_fd);
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

  /* A prefault hint, and nothing a caller can observe except as speed. It is
   * ignored rather than rejected because the alternative here is exit(1), and
   * liburing passes it on every one of the three ring mappings - so an io_uring
   * guest would die at its first mmap over a flag that means "be quick". */
  l_flags &= ~LINUX_MAP_POPULATE;

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
  /* A shared file mapping's own descriptor; arm64 only, since only its fork
   * has to re-map the file in another process. */
  int owned_fd = -1;
  /*
   * A reservation is address space and nothing else: anonymous, private and
   * unreadable, so there is nothing for it to hold and nothing the guest can
   * do with it until it says otherwise. See mm_region::reserved.
   */
  bool reserve_only = (l_prot == LINUX_PROT_NONE) && fd < 0 &&
                      !(l_flags & LINUX_MAP_SHARED);
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
  /*
   * A shared file mapping is mapped for real, so the guest's writes reach the
   * file - which is the whole meaning of MAP_SHARED, and something a copy can
   * never provide. The reasons the copy exists do not apply here: the host
   * refuses a PROT_EXEC file map and wants a granule-aligned offset, and neither
   * is true of this case, so it is checked for rather than assumed.
   *
   * Such a region is deliberately NOT in the arena. Its bytes belong to the
   * file, so a handover re-establishes it from the file on the far side rather
   * than copying it - which is also what fork owes a shared mapping, since the
   * child must share it with the parent and not get a private snapshot.
   */
  /*
   * ...and only when the guest can actually write through it. A shared mapping
   * of a descriptor opened O_RDONLY cannot propagate anything to the file, now
   * or later - Linux clears VM_MAYWRITE for that case, so even a subsequent
   * mprotect to PROT_WRITE is refused - which makes a private copy of the bytes
   * indistinguishable from the real thing.
   *
   * Asking for one anyway does not merely waste effort, it fails: the host
   * mapping is made PROT_READ|PROT_WRITE so a later mprotect can grant write
   * without re-establishing it, and MAP_SHARED|PROT_WRITE on a read-only
   * descriptor is EACCES. Mapping it PROT_READ instead only moves the failure,
   * since hv_vm_map will not take a read-only host region. ldconfig opens every
   * library O_RDONLY and maps it PROT_READ|MAP_SHARED to read its SONAME, so
   * each one came back "Cannot mmap file" and the ld.so cache was never built.
   */
  int amode = fd >= 0 ? fcntl(fd, F_GETFL) : -1;
  bool fd_writable = amode >= 0 && ((amode & O_ACCMODE) == O_RDWR ||
                                    (amode & O_ACCMODE) == O_WRONLY);
  bool shared_file = fd >= 0 && (l_flags & LINUX_MAP_SHARED) &&
                     (offset & (GUEST_MMAP_GRANULE - 1)) == 0 &&
                     !(l_prot & LINUX_PROT_EXEC) && fd_writable;

  if (reserve_only) {
    ptr = NULL;
  } else if (shared_file) {
    ptr = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (ptr == MAP_FAILED)
      return -darwin_to_linux_errno(errno);
    /*
     * And a descriptor of our own for it. The guest is free to close its own
     * the moment the mapping exists - that is the ordinary way to map a file,
     * and bionic's property area does it - after which the number recorded
     * here names nothing. The parent never notices, because its mapping holds
     * its own reference; the child does, because a fork on arm64 is an exec
     * and the resumed child re-maps the file from this descriptor. Every fork
     * in Android's init died on that, one panic deep in the child, with no
     * trace of its own because the sinks are opened after the restore.
     */
    owned_fd = dup(fd);
    if (owned_fd >= 0)
      fcntl(owned_fd, F_SETFD, 0);        /* must survive the child's exec */
  } else {
    ptr = arena_alloc(len, &arena_off);
    if (fd >= 0 && pread(fd, ptr, len, offset) < 0) {
      int e = errno;
      arena_unmap(ptr, len);
      arena_free(arena_off, len);
      return -darwin_to_linux_errno(e);
    }
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
      record_region(proc.mm, ptr, addr, len, l_prot, l_flags,
                    owned_fd >= 0 ? owned_fd : fd, offset);
  recorded->arena_off = arena_off;
  recorded->owns_fd = owned_fd >= 0;
  recorded->reserved = reserve_only;

  if (!reserve_only)
    vmm_mmap(addr, len, linux_mprot_to_hv_mflag(l_prot), ptr);

#if defined(__arm64__)
  /*
   * A file mapping was just written into guest memory by the host (the pread
   * copy above), and the guest has to be able to see those bytes.
   *
   * This ran only for executable mappings, because the instruction path is
   * where it was first noticed - ld.so maps a shared library's .text this way
   * and the guest fetched stale instructions. But the copy is the same copy
   * whatever the mapping is for, and a reader can be handed stale bytes just
   * as a fetcher can. Android's linker reads a library's section headers from
   * a PROT_READ mapping and could not find SHT_DYNAMIC in it - "\"...\"
   * .dynamic section header was not found" - on a different library each run,
   * while the host memory demonstrably held the right bytes and the stage-1
   * and stage-2 translations were verified to land on them. Reconciling here
   * as well takes apexd from failing every time to linking in four runs out of
   * five.
   *
   * Four out of five, not five: something still gets through, so this is one
   * cause rather than necessarily the only one. Timing is the alternative
   * explanation worth keeping in mind - the call is not free and could be
   * hiding a race rather than fixing coherency - but the evidence that the
   * bytes were present and correctly mapped and the guest still did not see
   * them is what a coherency problem looks like.
   *
   * Still skipped for anonymous maps: nothing has been written into those yet.
   */
  if (fd >= 0)
    vmm_sync_guest_code(addr, len);
#endif

  return addr;
}

/*
 * mseal: freeze a range's layout, permanently.
 *
 * A sealed range cannot be unmapped, moved, re-protected, or mapped over. The
 * point is that an attacker who has reached the point of calling mprotect - to
 * make the relocation table writable again, or to turn a data page into code -
 * finds the call refused, and the process keeps the layout it was linked with.
 * glibc seals its own relocated sections after applying RELRO, so this is
 * something a guest gets for free rather than something it has to ask for.
 *
 * Unlike Landlock, which is refused a few hundred lines away for the opposite
 * reason, the enforcement surface here is small enough to enumerate and to
 * check. Everything that can change a mapping's layout goes through this file:
 *
 *   sys_mmap      - a MAP_FIXED mapping placed over the range
 *   sys_mprotect  - and pkey_mprotect, which delegates to it
 *   sys_mremap    - moving or resizing the range
 *   sys_munmap    - and do_munmap, which mmap and mremap call internally
 *
 * That is the whole list, and it is four functions in one file rather than
 * fifty across the tree. The seal also travels in the checkpoint, because a
 * fork here is a fork plus an exec, and a child that came back unsealed would
 * be quietly less protected than the parent with nothing saying so.
 *
 * A caller can only ever add seals. There is no unseal, on Linux or here, and
 * that is the feature: a call to undo it is a call an attacker can make too.
 */
static bool
range_is_sealed(gaddr_t addr, size_t size)
{
  struct mm_region *r;
  list_for_each_entry (r, &proc.mm->mm_regions, list) {
    if (!r->sealed)
      continue;
    if (r->gaddr < addr + size && addr < r->gaddr + r->size)
      return true;
  }
  return false;
}

/*
 * mincore: which pages of a range are resident.
 *
 * Guest memory is host memory, so this is Darwin's mincore over the host
 * address the region translates to. The unit is a page and the guest's page is
 * the host's in both builds - the same equality cachestat depends on - so a
 * residency byte maps one to one.
 *
 * Only the low bit is written. Linux defines the rest of the byte as reserved
 * and requires it to be zero, and Darwin has bits up there of its own
 * (MINCORE_REFERENCED and friends) that mean something different; passing them
 * through would hand a guest flags from another operating system in a field its
 * headers call reserved.
 */
DEFINE_SYSCALL(mincore, gaddr_t, addr, size_t, length, gaddr_t, vec_ptr)
{
  size_t ps = PAGE_SIZEOF(PAGE_4KB);
  if (addr & (ps - 1))
    return -LINUX_EINVAL;
  if (length == 0)
    return 0;
  if (addr + length < addr)
    return -LINUX_ENOMEM;

  size_t npages = (length + ps - 1) / ps;
  char *out = calloc(npages, 1);
  if (out == NULL)
    return -LINUX_ENOMEM;

  int ret = 0;
  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  for (size_t done = 0; done < npages; ) {
    gaddr_t p = addr + done * ps;
    struct mm_region *r = find_region(p, proc.mm);
    if (r == NULL) {
      /* Linux answers ENOMEM for a range that is not all mapped, and says
       * nothing about the part it could have reported. */
      ret = -LINUX_ENOMEM;
      break;
    }
    gaddr_t rend = r->gaddr + r->size;
    size_t n = (size_t) ((rend - p) / ps);
    if (n > npages - done)
      n = npages - done;
    void *haddr = (char *) r->haddr + (p - r->gaddr);
    char *tmp = calloc(n, 1);
    if (tmp == NULL) {
      ret = -LINUX_ENOMEM;
      break;
    }
    if (mincore(haddr, n * ps, tmp) < 0) {
      ret = syswrap(-1);
      free(tmp);
      break;
    }
    for (size_t i = 0; i < n; i++)
      out[done + i] = tmp[i] & MINCORE_INCORE ? 1 : 0;
    free(tmp);
    done += n;
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  if (ret == 0 && copy_to_user(vec_ptr, out, npages))
    ret = -LINUX_EFAULT;
  free(out);
  return ret;
}

/*
 * Give a reservation real memory, because something is about to be allowed to
 * touch it.
 *
 * The bytes read as zero, which is what an anonymous mapping owes its first
 * reader, and the arena gives that for free. Failure leaves the region as it
 * was - still a reservation, still unreachable - so a guest that cannot be
 * given the memory it asked to use is told, rather than handed a mapping that
 * faults later.
 */
static int
region_materialize(struct mm_region *r, int hvprot)
{
  off_t off = -1;
  void *ptr = arena_alloc(r->size, &off);
  if (ptr == NULL)
    return -LINUX_ENOMEM;
  r->haddr = ptr;
  r->arena_off = off;
  r->reserved = false;
  vmm_mmap(r->gaddr, r->size, hvprot, ptr);
  return 0;
}

/*
 * move_pages: where each page is, and where it should go.
 *
 * With a nodes array it asks for a move, and with a NULL one it only asks where
 * the pages are - which is the mode `numastat`-style tools and most libraries
 * actually use, and which can be answered exactly. Every page that exists is on
 * node 0, because node 0 is the only node; a page that is not mapped answers
 * -ENOENT in its own status slot, which is Linux's way of saying so per page
 * rather than failing the whole call.
 *
 * A move to node 0 is already done. A move anywhere else names a node this
 * machine does not have, and is refused per page rather than confirmed - the
 * same judgement mbind and migrate_pages make.
 */
DEFINE_SYSCALL(move_pages, l_pid_t, pid, unsigned long, count, gaddr_t, pages_ptr,
               gaddr_t, nodes_ptr, gaddr_t, status_ptr, int, flags)
{
  if (flags & ~(LINUX_MPOL_MF_MOVE | LINUX_MPOL_MF_MOVE_ALL))
    return -LINUX_EINVAL;
  if (count > (1UL << 20))
    return -LINUX_EINVAL;
  if (status_ptr == 0)
    return -LINUX_EFAULT;
  if (pid < 0)
    return -LINUX_EINVAL;

  int32_t host = pidns_to_host(pid == 0 ? (l_pid_t) pidns_to_ns(getpid()) : pid);
  if (host < 0)
    return -LINUX_ESRCH;
  if (host != getpid()) {
    if (kill(host, 0) < 0 && errno == ESRCH)
      return -LINUX_ESRCH;
    return -LINUX_EPERM;
  }
  if (count == 0)
    return 0;

  gaddr_t *pages = calloc(count, sizeof *pages);
  int32_t *status = calloc(count, sizeof *status);
  int32_t *nodes = nodes_ptr ? calloc(count, sizeof *nodes) : NULL;
  int ret = 0;
  if (pages == NULL || status == NULL || (nodes_ptr && nodes == NULL)) {
    ret = -LINUX_ENOMEM;
    goto out;
  }
  if (copy_from_user(pages, pages_ptr, count * sizeof *pages) ||
      (nodes && copy_from_user(nodes, nodes_ptr, count * sizeof *nodes))) {
    ret = -LINUX_EFAULT;
    goto out;
  }

  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  for (unsigned long i = 0; i < count; i++) {
    if (nodes && nodes[i] != 0) {
      status[i] = -LINUX_EINVAL;        /* a node that does not exist */
      continue;
    }
    struct mm_region *r = find_region(pages[i], proc.mm);
    status[i] = r == NULL ? -LINUX_ENOENT : 0;
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  if (copy_to_user(status_ptr, status, count * sizeof *status))
    ret = -LINUX_EFAULT;

out:
  free(pages); free(status); free(nodes);
  return ret;
}

DEFINE_SYSCALL(mseal, gaddr_t, addr, size_t, len, unsigned long, flags)
{
  size_t ps = PAGE_SIZEOF(PAGE_4KB);
  if (flags != 0)
    return -LINUX_EINVAL;       /* none are defined, and none are ignored */
  if (addr & (ps - 1))
    return -LINUX_EINVAL;
  if (len == 0)
    return 0;
  if (addr + len < addr)
    return -LINUX_EINVAL;

  gaddr_t end = roundup(addr + len, ps);

  int ret = 0;
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);

  /*
   * The whole range has to be mapped before any of it is sealed. Linux checks
   * this first for a reason worth keeping: sealing what it could reach and then
   * reporting ENOMEM would leave a caller believing nothing happened while part
   * of its address space had become permanently immovable.
   */
  for (gaddr_t p = addr; p < end; ) {
    struct mm_region *r = find_region(p, proc.mm);
    if (r == NULL) {
      ret = -LINUX_ENOMEM;
      goto out;
    }
    p = r->gaddr + r->size;
  }

  for (gaddr_t p = addr; p < end; ) {
    struct mm_region *r = find_region(p, proc.mm);
    /* Seal exactly what was asked for: a region that runs past either end is
     * split so the parts outside the range stay as they were. */
    if (r->gaddr < p) {
      split_region(proc.mm, r, p);
      r = list_entry(r->list.next, struct mm_region, list);
    }
    if (r->gaddr + r->size > end)
      split_region(proc.mm, r, end);
    r->sealed = true;
    p = r->gaddr + r->size;
  }

out:
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

DEFINE_SYSCALL(mmap, gaddr_t, addr, size_t, len, int, prot, int, flags, int, fd, off_t, offset)
{
  uint64_t ret;
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  /* Only a fixed mapping can land on an existing range; anything else is
   * placed where nothing is. */
  if ((flags & LINUX_MAP_FIXED) && len > 0 &&
      range_is_sealed(addr, roundup(len, GUEST_MMAP_GRANULE))) {
    pthread_rwlock_unlock(&proc.mm->alloc_lock);
    return -LINUX_EPERM;
  }
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

  /*
   * Linux rounds to its own page, and the region bookkeeping is measured in
   * that unit: mprotect and do_munmap split regions at 4KiB granularity, so a
   * mapping a guest has mprotected part of away can be a 4KiB multiple that is
   * not a 16KiB one. Rounding old_size to the 16KiB stage-2 block instead of
   * the guest page hands such a trimmed region back EFAULT where Linux would
   * succeed - the CFI shadow-rewrite flow hits exactly that, mremapping a
   * 4KiB page that an mprotect has just isolated. The stage-2 layer maps and
   * unmaps whole blocks, but vmm_mmap and vmm_munmap both walk the guest's
   * 4KiB pages and handle a range that only partly covers a block, so the
   * block granule is not a size to round to here. (It was rounded to before,
   * when vmm_munmap could not split a block at all; dpkg's unpack-buffer
   * mremap is what showed that. splitmunmaptest covers the since-added
   * handling.)
   */
  old_size = roundup(old_size, PAGE_SIZEOF(PAGE_4KB));
  new_size = roundup(new_size, PAGE_SIZEOF(PAGE_4KB));

  gaddr_t ret = old_addr;

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  /* Both ends: a sealed range cannot be moved away, and cannot be moved onto. */
  if (range_is_sealed(old_addr, old_size) ||
      ((flags & LINUX_MREMAP_FIXED) && range_is_sealed(new_addr, new_size))) {
    pthread_rwlock_unlock(&proc.mm->alloc_lock);
    return -LINUX_EPERM;
  }

  struct mm_region *region = find_region(old_addr, proc.mm);
  /* Linux requires old_addr is the exact address of start of vm_area  */
  if (!region || region->gaddr != old_addr) {
    warnk("mremap EFAULT: old_addr 0x%llx old_size 0x%zx new_size 0x%zx new_addr 0x%llx region %p", old_addr, old_size, new_size, new_addr, (void *) region);
    if (region)
      warnk("  region->gaddr 0x%llx size 0x%zx", region->gaddr, region->size);
    ret = -LINUX_EFAULT;
    goto out;
  }
  /* The region must not be across multiple regions */
  if (region->size < old_size) {
    ret = -LINUX_EFAULT;
    goto out;
  }

  /*
   * Where the region is going. A shrink with no MREMAP_FIXED stays where it is;
   * everything else lands at a destination - MREMAP_FIXED pins it, otherwise
   * alloc_region hands one out (which, from the top-down allocator, is old_addr
   * itself when the region above is free, i.e. a grow in place).
   */
  if (!(flags & LINUX_MREMAP_FIXED) && new_size <= old_size) {
    if (region->size > new_size) {
      /* Stage 2 first, host memory after - see the move path below. */
      vmm_munmap(region->gaddr + new_size, region->size - new_size);
      if (region->arena_off < 0)
        munmap(region->haddr + new_size, region->size - new_size);
      if (region->arena_off >= 0) {
        /*
         * Free arena space only from the next 16KiB boundary onward. A region
         * that mprotect or munmap has split shares its arena chunk with the
         * sibling it left behind, so freeing from new_size directly - and arena
         * rounding the size up to a block - could punch into the sibling's
         * range. The sub-block tail is left allocated in a sparse,
         * hole-punched file, which costs nothing.
         */
        size_t aligned = roundup(new_size, GUEST_MMAP_GRANULE);
        if (aligned < region->size)
          arena_free(region->arena_off + aligned, region->size - aligned);
      }
    }
    region->size = new_size;
    goto out;
  }

  gaddr_t dst = (flags & LINUX_MREMAP_FIXED) ? new_addr : alloc_region(new_size);

  /* new_size > old_size, or moving to a new address */
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

  /*
   * A fixed move replaces whatever is mapped at the destination first - that is
   * the meaning of MREMAP_FIXED, and the CFI shadow-rewrite flow parks a
   * temporary page on top of a protected one this way. The copy is already done
   * above, so the source bytes are safe even if this reaches into the source
   * range; only a destination that overlaps the source region itself is
   * refused, since that would free the region record still in use below.
   */
  if ((flags & LINUX_MREMAP_FIXED) && dst != old_addr) {
    if (dst < region->gaddr + region->size && dst + new_size > region->gaddr) {
      warnk("mremap: fixed destination 0x%llx overlaps source region [0x%llx, 0x%llx)\n",
            dst, region->gaddr, region->gaddr + region->size);
      ret = -LINUX_EINVAL;
      goto out;
    }
    do_munmap(dst, new_size);
  }

  /* Unmap the old page */
  if (old_size < region->size) {
    split_region(proc.mm, region, region->gaddr + old_size);
  }
  list_del(&region->list);
  RB_REMOVE(mm_region_tree, &proc.mm->mm_region_tree, region);
  /*
   * Stage 2 is torn down first, and only then is the host memory handled.
   *
   * vmm_munmap may have to re-establish a 16KiB block that still backs a
   * neighbouring region - the source was split by an mprotect and the tail
   * still lives - and re-establishing remaps the whole block with hv_vm_map,
   * which needs the block's host backing to be mapped. Unmapping the host
   * memory first (as this did) handed hv_vm_map a host range with a hole in
   * it and it refused with HV_ERROR, taking the guest down mid-mremap.
   */
  vmm_munmap(region->gaddr, region->size);
  if (region->arena_off < 0) {
    /* A real mapping (a shared file, or all of x86): the bytes belong to
     * whatever it was mapped from, and the region owned all of them. */
    munmap(region->haddr, region->size);
  } else {
    /*
     * Arena memory is released only as a whole free chunk, and this region is
     * not known to be one: an mprotect split leaves it sharing its 16KiB
     * block - host range and file bytes alike - with the sibling it left
     * behind. munmap would cut a hole in the block the sibling still reads
     * through, and arena_free rounds its size up to the block and would punch
     * a hole through the sibling's file bytes, which reads back as zeros.
     * Dead arena storage is sparse and costs nothing, so it is left alone.
     */
  }

  /* Map new one */
  ret = dst;
  struct mm_region *new = record_region(proc.mm, moved_to, ret, new_size, region->prot, region->mm_flags, region->mm_fd, region->pgoff);
  new->shm_id = region->shm_id;
  new->arena_off = moved_off;
  /* The descriptor moves with the mapping rather than being closed and
   * reopened: this is the same mapping at a new address. */
  new->owns_fd = region->owns_fd;
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

  if (range_is_sealed(addr, len)) {
    pthread_rwlock_unlock(&proc.mm->alloc_lock);
    return -LINUX_EPERM;
  }

  struct mm_region *region = find_region(addr, proc.mm);
  if (!region) {
    ret = -LINUX_ENOMEM;
    goto out;
  }
  /*
   * Trim what lies before addr off the first region, so that everything from
   * here on starts exactly at the requested range. Only the split happens here:
   * the upper half may still run past `end`, and protecting it now - as this
   * did - applies the new permission to the whole remainder of the mapping.
   * The tail is split off correctly a few lines below and its bookkeeping says
   * the old permission, but the descriptors have already been rewritten and
   * nothing puts them back.
   *
   * That is invisible for most of what a dynamic linker does, because the
   * over-protected tail is normally the next segment, which is immediately
   * re-mapped MAP_FIXED and so re-permissioned. It shows up when the tail is
   * left as it is - and then the bytes just past a PROT_NONE inter-segment hole
   * are unreadable, which is a library that loads and then faults on its own
   * data.
   */
  if (addr > region->gaddr) {
    split_region(proc.mm, region, addr);
    region = list_entry(region->list.next, struct mm_region, list);
  }
  while (region->gaddr + region->size <= end) {
    /* A reservation being made accessible has to become real first; one being
     * set to PROT_NONE again is already exactly that and stays cheap. */
    if (region->reserved && prot != LINUX_PROT_NONE) {
      int r = region_materialize(region, hvprot);
      if (r < 0)
        return r;
    }
    if (!region->reserved) {
      NABI_VM_PROTECT(region);
      NABI_HOST_PROTECT(region, prot);
    }
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
    /* The same as the loop body: the last piece is a region like any other,
     * and a reservation being opened up here has to become real too. This is
     * the shape a linker uses - reserve the whole span, then make the middle
     * of it accessible - so it is the common case, not the leftover one. */
    if (region->reserved && prot != LINUX_PROT_NONE) {
      int r = region_materialize(region, hvprot);
      if (r < 0) {
        ret = r;
        goto out;
      }
    }
    if (!region->reserved) {
      NABI_VM_PROTECT(region);
      NABI_HOST_PROTECT(region, prot);
    }
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
  if (size > 0 && range_is_sealed(gaddr, roundup(size, GUEST_MMAP_GRANULE))) {
    pthread_rwlock_unlock(&proc.mm->alloc_lock);
    return -LINUX_EPERM;
  }
  ret = do_munmap(gaddr, size);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

/*
 * Memory protection keys, which need hardware that is not here.
 *
 * A key is a few bits in the page table entry and a register the process writes
 * to say what those bits currently permit - PKU on x86, POE on newer arm64 -
 * so that a whole class of pages can be made unreadable and readable again
 * without a syscall. Apple Silicon has no POE, and the Hypervisor.framework
 * exposes nothing that would let a guest own such a register.
 *
 * So no key can be allocated, and pkey_alloc says so. That makes the rest
 * consistent rather than arbitrary: since a caller cannot hold a key, every
 * pkey it could pass to pkey_mprotect is one that was never allocated, and
 * EINVAL is the right answer for it.
 *
 * The exception is the one that matters. pkey_mprotect with a pkey of -1 means
 * "no key", and is defined to behave exactly as mprotect - which is what code
 * that calls it unconditionally relies on. That case is served, so a program
 * built to use pkey_mprotect everywhere and keys only when it has them works
 * here without a second code path.
 */
DEFINE_SYSCALL(pkey_mprotect, gaddr_t, addr, size_t, len, int, prot, int, pkey)
{
  if (pkey == -1)
    return sys_mprotect(addr, len, prot);
  if (pkey < 0)
    return -LINUX_EINVAL;
  return -LINUX_EINVAL;         /* no key was allocated, so none is valid */
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

/* ---------------------------------------------------------------- mbind */

/*
 * mbind: which NUMA nodes a range of memory should come from.
 *
 * There is exactly one node here, and that is not a shortcoming to work around
 * - it is the machine. A policy is a constraint on where pages are allocated,
 * and on a single-node system every constraint that permits that node is
 * already satisfied by every page. So this is not a stub that returns success:
 * it checks that what was asked for is satisfiable and then it *is* satisfied,
 * with nothing left to do.
 *
 * Which makes the validation the whole of the implementation, and worth doing
 * properly. A nodemask naming a node that does not exist cannot be honoured and
 * is refused, exactly as Linux refuses it - a program that binds to node 3 and
 * is told yes would go on believing its memory is somewhere it is not. MPOL_BIND
 * with an empty mask is the same case. And MPOL_DEFAULT means "no policy", so a
 * mask with anything in it contradicts the mode it came with.
 *
 * MPOL_MF_STRICT asks to be told if pages already in the range are on the wrong
 * node. None can be, so the answer is that none are.
 */
/* The modes and MF_ flags are in linux/mman.h already; these are the two the
 * header predates - a mode added later, and the flags packed into the mode's
 * high bits. */
#define LINUX_MPOL_LOCAL           4
#define LINUX_MPOL_PREFERRED_MANY  5

#define LINUX_MPOL_F_STATIC_NODES     (1 << 15)
#define LINUX_MPOL_F_RELATIVE_NODES   (1 << 14)
#define LINUX_MPOL_F_NUMA_BALANCING   (1 << 13)
#define LINUX_MPOL_MODE_FLAGS \
  (LINUX_MPOL_F_STATIC_NODES | LINUX_MPOL_F_RELATIVE_NODES | \
   LINUX_MPOL_F_NUMA_BALANCING)

/*
 * How many nodes a mask names, or a negative error.
 *
 * Shared with mbind's reasoning: node 0 is the only one this machine has, so a
 * bit anywhere else names a node that cannot exist and is refused rather than
 * ignored. Ignoring it would let a caller ask to move pages somewhere and be
 * told it worked.
 */
static int
read_nodemask(gaddr_t nodemask, unsigned long maxnode, bool *node0)
{
  *node0 = false;
  if (nodemask == 0 || maxnode == 0)
    return 0;
  unsigned long words = (maxnode + 63) / 64;
  for (unsigned long i = 0; i < words; i++) {
    uint64_t w;
    if (copy_from_user(&w, nodemask + i * sizeof w, sizeof w))
      return -LINUX_EFAULT;
    if (i == 0) {
      *node0 = (w & 1) != 0;
      if (w & ~1ULL)
        return -LINUX_EINVAL;
    } else if (w) {
      return -LINUX_EINVAL;
    }
  }
  return 0;
}

/*
 * migrate_pages: move a process's pages between NUMA nodes.
 *
 * There is one node, so every page is already on every node a caller can name,
 * and the number that could not be moved is zero. That is the truthful answer
 * rather than a convenient one - migrate_pages returns the count it failed to
 * migrate, and nothing failed because nothing had anywhere else to go.
 *
 * What is not waved through is a mask naming a node that does not exist. A
 * caller asking to move pages to node 1 has misunderstood the machine, and
 * saying "moved, none left behind" would confirm the misunderstanding.
 *
 * Another process is out of reach for the reason process_vm_readv documents,
 * and gets EPERM once it is known to exist.
 */
DEFINE_SYSCALL(migrate_pages, l_pid_t, pid, unsigned long, maxnode,
               gaddr_t, old_nodes, gaddr_t, new_nodes)
{
  if (maxnode > 1024 * 1024)
    return -LINUX_EINVAL;
  if (pid < 0)
    return -LINUX_EINVAL;

  int32_t host = pidns_to_host(pid == 0 ? (l_pid_t) pidns_to_ns(getpid()) : pid);
  if (host < 0)
    return -LINUX_ESRCH;
  if (host != getpid()) {
    if (kill(host, 0) < 0 && errno == ESRCH)
      return -LINUX_ESRCH;
    return -LINUX_EPERM;
  }

  bool from_node0, to_node0;
  int r;
  if ((r = read_nodemask(old_nodes, maxnode, &from_node0)) < 0)
    return r;
  if ((r = read_nodemask(new_nodes, maxnode, &to_node0)) < 0)
    return r;

  /* Nothing was left behind, because there was nowhere else for it to be. */
  return 0;
}

/*
 * set_mempolicy: the process's own default allocation policy.
 *
 * mbind's reasoning applied to the whole process rather than to a range, and
 * the same answer: node 0 is the only node, so a policy that names it or names
 * nothing is satisfiable and one that names another node is not. get_mempolicy
 * reports MPOL_DEFAULT with an empty mask, and this is written so the two agree
 * - a caller that sets a policy and reads it back gets a consistent story
 * rather than the one it set.
 *
 * Which is why nothing is recorded. Recording it would mean get_mempolicy
 * reporting MPOL_BIND over a set of one node, which is true in a sense and
 * misleading in the way that matters: it suggests placement is being honoured,
 * and there is nowhere for placement to differ.
 */
DEFINE_SYSCALL(set_mempolicy, int, mode, gaddr_t, nodemask, unsigned long, maxnode)
{
  int bare = mode & ~LINUX_MPOL_MODE_FLAGS;
  int mflags = mode & LINUX_MPOL_MODE_FLAGS;
  if (bare < LINUX_MPOL_DEFAULT || bare > LINUX_MPOL_PREFERRED_MANY)
    return -LINUX_EINVAL;
  if ((mflags & LINUX_MPOL_F_STATIC_NODES) && (mflags & LINUX_MPOL_F_RELATIVE_NODES))
    return -LINUX_EINVAL;
  if (maxnode > 1024 * 1024)
    return -LINUX_EINVAL;

  bool node0;
  int r = read_nodemask(nodemask, maxnode, &node0);
  if (r < 0)
    return r;

  switch (bare) {
  case LINUX_MPOL_DEFAULT:
    if (node0)
      return -LINUX_EINVAL;     /* "no policy" with a set is a contradiction */
    break;
  case LINUX_MPOL_BIND:
  case LINUX_MPOL_INTERLEAVE:
  case LINUX_MPOL_PREFERRED_MANY:
    if (!node0)
      return -LINUX_EINVAL;     /* an empty set constrains allocation to nowhere */
    break;
  case LINUX_MPOL_LOCAL:
    if (node0)
      return -LINUX_EINVAL;     /* local is where the thread is, not a set */
    break;
  case LINUX_MPOL_PREFERRED:
    break;                      /* an empty mask means no preference */
  }
  return 0;
}

/*
 * set_mempolicy_home_node: which node a range should prefer to be near.
 *
 * A hint about where to fault pages in for a range that already has a policy,
 * added so that a large interleaved mapping could still keep each thread's
 * working set close to it. With one node every page is already home, so the
 * only thing to check is that the caller is not naming a node that does not
 * exist - and that the range is one it actually has, because Linux answers
 * EFAULT for a hole rather than accepting a hint about nothing.
 */
DEFINE_SYSCALL(set_mempolicy_home_node, gaddr_t, start, unsigned long, len,
               unsigned long, home_node, unsigned long, flags)
{
  size_t ps = PAGE_SIZEOF(PAGE_4KB);
  if (flags != 0)
    return -LINUX_EINVAL;
  if (start & (ps - 1))
    return -LINUX_EINVAL;
  if (home_node != 0 && home_node != (unsigned long) -1)
    return -LINUX_EINVAL;       /* a node this machine does not have */
  if (len == 0)
    return 0;
  if (start + len < start)
    return -LINUX_EINVAL;

  gaddr_t end = roundup(start + len, ps);
  int ret = 0;
  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  for (gaddr_t p = start; p < end; ) {
    struct mm_region *r = find_region(p, proc.mm);
    if (r == NULL) {
      ret = -LINUX_EFAULT;
      break;
    }
    p = r->gaddr + r->size;
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);
  return ret;
}

DEFINE_SYSCALL(mbind, gaddr_t, addr, unsigned long, len, int, mode,
               gaddr_t, nodemask, unsigned long, maxnode, unsigned int, flags)
{
  if (flags & ~(unsigned) (LINUX_MPOL_MF_STRICT | LINUX_MPOL_MF_MOVE |
                           LINUX_MPOL_MF_MOVE_ALL))
    return -LINUX_EINVAL;

  int bare = mode & ~LINUX_MPOL_MODE_FLAGS;
  int mflags = mode & LINUX_MPOL_MODE_FLAGS;
  if (bare < LINUX_MPOL_DEFAULT || bare > LINUX_MPOL_PREFERRED_MANY)
    return -LINUX_EINVAL;
  /* Two ways of reinterpreting a nodemask, and they contradict each other. */
  if ((mflags & LINUX_MPOL_F_STATIC_NODES) &&
      (mflags & LINUX_MPOL_F_RELATIVE_NODES))
    return -LINUX_EINVAL;

  if (addr & (PAGE_SIZEOF(PAGE_4KB) - 1))
    return -LINUX_EINVAL;       /* a policy applies to whole pages */
  if (maxnode > 1024 * 1024)
    return -LINUX_EINVAL;

  /*
   * Whether node 0 - the only one - is in the mask. Only the first word is
   * read because any bit beyond it names a node that cannot exist, and that is
   * checked separately rather than ignored.
   */
  bool names_node0 = false, names_others = false;
  if (nodemask != 0 && maxnode > 0) {
    unsigned long words = (maxnode + 63) / 64;
    for (unsigned long i = 0; i < words; i++) {
      uint64_t w;
      if (copy_from_user(&w, nodemask + i * sizeof w, sizeof w))
        return -LINUX_EFAULT;
      if (i == 0) {
        names_node0 = (w & 1) != 0;
        if (w & ~1ULL)
          names_others = true;
      } else if (w) {
        names_others = true;
      }
    }
  }

  if (names_others)
    return -LINUX_EINVAL;       /* a node this machine does not have */

  switch (bare) {
  case LINUX_MPOL_DEFAULT:
    /* "No policy", so a mask is a contradiction rather than a refinement. */
    if (names_node0)
      return -LINUX_EINVAL;
    break;
  case LINUX_MPOL_BIND:
  case LINUX_MPOL_INTERLEAVE:
  case LINUX_MPOL_PREFERRED_MANY:
    /* These constrain allocation to the set, so an empty set constrains it to
     * nowhere and cannot be satisfied. */
    if (!names_node0)
      return -LINUX_EINVAL;
    break;
  case LINUX_MPOL_LOCAL:
    if (names_node0)
      return -LINUX_EINVAL;     /* local is where the thread is, not a set */
    break;
  case LINUX_MPOL_PREFERRED:
    /* An empty mask means "no preference", which is allowed. */
    break;
  }

  /* Satisfied by the only node there is. Nothing is recorded because nothing
   * could later disagree with it: a second node is not going to appear. */
  (void) len;
  return 0;
}

/* ------------------------------------------------- process_vm_readv/writev */

/*
 * process_vm_readv and process_vm_writev: copying between the address spaces of
 * two processes without either of them agreeing to it.
 *
 * On Linux the kernel is on both sides of that copy - it can reach into any
 * address space it is allowed to. Here the two sides are two *host* processes.
 * arm64's fork is fork-plus-exec, so a guest process is a host process with its
 * own guest memory, and nabi has no way into another one:
 *
 *   The arena that names guest memory is created and immediately unlinked, so
 *   it has no name a sibling could open, and the descriptor reaches only the
 *   children that inherited it across the exec.
 *
 *   The running guest's mappings are MAP_PRIVATE, so the arena does not hold
 *   what the guest currently has anyway - it holds what was written into it at
 *   the last handover. See src/mm/arena.c, where that is a deliberate choice:
 *   sharing it would take copy-on-write away from fork and let the two halves
 *   of `cmd | cmd` write over each other.
 *
 *   And a guest address means nothing without the region table that translates
 *   it, which is process memory in the process that owns it.
 *
 * Darwin does offer mach_vm_read_overwrite through a task port, but task_for_pid
 * on another process wants root and an entitlement nabi does not carry, and
 * would still leave the third problem: the address to read is a guest address
 * and only that process knows where it lives.
 *
 * So the same-process case is implemented and the cross-process case is
 * refused. That is not as narrow as it sounds - the call is defined for a
 * process to use on itself, where it is a gather-scatter copy that skips the
 * intermediate buffer readv into writev would need - but it is not what most
 * callers want, and they are told so rather than being given a wrong answer.
 *
 * EPERM rather than ENOSYS, because EPERM is the answer Linux gives when the
 * ptrace access check fails, and every caller of this already has a path for
 * it: they fall back to /proc/pid/mem, or to asking the other process nicely.
 * ENOSYS would say the call does not exist, which is not true of the half that
 * works.
 */
static int
process_vm_rw(int pid, gaddr_t lvec, unsigned long liovcnt,
              gaddr_t rvec, unsigned long riovcnt, unsigned long flags,
              bool writing)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (liovcnt > 1024 || riovcnt > 1024)
    return -LINUX_EINVAL;       /* UIO_MAXIOV */

  if (pid <= 0)
    return -LINUX_ESRCH;
  int32_t host = pidns_to_host(pid);
  if (host < 0)
    return -LINUX_ESRCH;        /* not a member of this pid namespace */
  /*
   * "No such process" and "not allowed" are different answers and a caller acts
   * on them differently, so the process is actually looked for rather than
   * assumed to exist because a number translated - outside a pid namespace the
   * translation is the identity and would accept anything. kill(pid, 0) is the
   * existence test, and it is the same one Linux would be doing.
   */
  if (host != getpid()) {
    if (kill(host, 0) < 0 && errno == ESRCH)
      return -LINUX_ESRCH;
    return -LINUX_EPERM;        /* see above: not refused for want of trying */
  }

  if (liovcnt == 0 || riovcnt == 0)
    return 0;

  struct l_iovec *liov = calloc(liovcnt, sizeof *liov);
  struct l_iovec *riov = calloc(riovcnt, sizeof *riov);
  if (!liov || !riov) {
    free(liov); free(riov);
    return -LINUX_ENOMEM;
  }
  if (copy_from_user(liov, lvec, liovcnt * sizeof *liov) ||
      copy_from_user(riov, rvec, riovcnt * sizeof *riov)) {
    free(liov); free(riov);
    return -LINUX_EFAULT;
  }

  /*
   * The transfer stops when either side runs out, which is why both are walked
   * together rather than one being flattened first: a short local vector is not
   * an error, it is how much was asked for.
   */
  unsigned long li = 0, ri = 0;
  size_t loff = 0, roff = 0;
  int64_t moved = 0;
  int err = 0;

  while (li < liovcnt && ri < riovcnt) {
    size_t lrem = liov[li].iov_len - loff;
    size_t rrem = riov[ri].iov_len - roff;
    if (lrem == 0) { li++; loff = 0; continue; }
    if (rrem == 0) { ri++; roff = 0; continue; }

    size_t n = lrem < rrem ? lrem : rrem;
    char *tmp = malloc(n);
    if (!tmp) { err = -LINUX_ENOMEM; break; }

    /* Both addresses are in this process, so each hop is two ordinary copies
     * through nabi rather than anything exotic. */
    gaddr_t from = writing ? liov[li].iov_base + loff : riov[ri].iov_base + roff;
    gaddr_t to   = writing ? riov[ri].iov_base + roff : liov[li].iov_base + loff;
    if (copy_from_user(tmp, from, n) || copy_to_user(to, tmp, n)) {
      free(tmp);
      /* A fault part way through is reported as what did move, if anything -
       * the bytes already copied cannot be taken back. */
      err = moved > 0 ? 0 : -LINUX_EFAULT;
      break;
    }
    free(tmp);

    loff += n;
    roff += n;
    moved += n;
  }

  free(liov);
  free(riov);
  if (err < 0)
    return err;
  return (int) moved;
}

DEFINE_SYSCALL(process_vm_readv, int, pid, gaddr_t, lvec, unsigned long, liovcnt,
               gaddr_t, rvec, unsigned long, riovcnt, unsigned long, flags)
{
  return process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, false);
}

DEFINE_SYSCALL(process_vm_writev, int, pid, gaddr_t, lvec, unsigned long, liovcnt,
               gaddr_t, rvec, unsigned long, riovcnt, unsigned long, flags)
{
  return process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, true);
}

/* ------------------------------------- process_madvise / process_mrelease */

/*
 * process_madvise and process_mrelease: reclaim, aimed at another process.
 *
 * Both name their target by pidfd, and both are about memory pressure - one
 * says which of a process's pages are cold enough to page out, the other
 * releases a dying process's pages now rather than waiting for it to finish
 * exiting. They are what a userspace out-of-memory daemon is built from.
 *
 * The cross-process half is unreachable here for the reasons process_vm_readv
 * sets out above: a guest process is a host process with its own guest memory,
 * the arena naming it is unlinked, its live mappings are private, and a guest
 * address means nothing without the region table belonging to the process that
 * owns it. So a target that is not this process answers EPERM, which is what
 * Linux answers when the ptrace access check fails and which callers have a
 * path for.
 *
 * The two differ in what is left after that, and it is worth being exact.
 *
 * process_madvise's advice is *purely advisory*: the set it accepts - COLD,
 * PAGEOUT, WILLNEED, COLLAPSE - are reclaim hints with no effect a program can
 * observe. Linux deliberately excludes the destructive ones, MADV_DONTNEED and
 * MADV_FREE, precisely because they change what a read returns. So a kernel
 * that takes the hint and does nothing with it is behaving within the contract,
 * and reporting the range as processed is true rather than a polite fiction.
 *
 * process_mrelease is not like that. What it promises is that the memory is
 * freed *now*, and nabi cannot free another process's memory at all. Every
 * input it can be given gets the answer Linux would give - a target that is not
 * dying is EINVAL, one that is gone is ESRCH, another process is EPERM - but
 * there is no input on this system for which it would do the work. That is a
 * narrower thing than the other and is written down rather than glossed.
 */
#define LINUX_MADV_WILLNEED  3
#define LINUX_MADV_COLD     20
#define LINUX_MADV_PAGEOUT  21
#define LINUX_MADV_COLLAPSE 25

DEFINE_SYSCALL(process_madvise, int, pidfd, gaddr_t, vec, unsigned long, vlen,
               int, advice, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (vlen > 1024)
    return -LINUX_EINVAL;       /* UIO_MAXIOV */

  /*
   * The advice is checked before the target, because the set this call accepts
   * is narrower than madvise's and a caller that passes a destructive one is
   * asking for something Linux refuses from here whatever the target is.
   */
  switch (advice) {
  case LINUX_MADV_COLD:
  case LINUX_MADV_PAGEOUT:
  case LINUX_MADV_WILLNEED:
  case LINUX_MADV_COLLAPSE:
    break;
  default:
    return -LINUX_EINVAL;
  }

  int host = pidfd_host_pid(pidfd);
  if (host < 0)
    return -LINUX_EBADF;        /* not a pidfd */
  if (kill(host, 0) < 0 && errno == ESRCH)
    return -LINUX_ESRCH;
  if (host != getpid())
    return -LINUX_EPERM;        /* see above */

  if (vlen == 0)
    return 0;

  struct l_iovec *iov = calloc(vlen, sizeof *iov);
  if (!iov)
    return -LINUX_ENOMEM;
  if (copy_from_user(iov, vec, vlen * sizeof *iov)) {
    free(iov);
    return -LINUX_EFAULT;
  }

  /*
   * Each range is checked for being real before it is counted. An advisory
   * call still has to say EFAULT for memory that is not there, or a caller
   * cannot tell a range it got wrong from one that was simply not worth acting
   * on.
   */
  int64_t total = 0;
  for (unsigned long i = 0; i < vlen; i++) {
    if (iov[i].iov_len == 0)
      continue;
    if (guest_to_host(iov[i].iov_base) == NULL ||
        guest_to_host(iov[i].iov_base + iov[i].iov_len - 1) == NULL) {
      free(iov);
      return total > 0 ? (int) total : -LINUX_EFAULT;
    }
    total += iov[i].iov_len;
  }
  free(iov);
  return (int) total;
}

DEFINE_SYSCALL(process_mrelease, int, pidfd, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;

  int host = pidfd_host_pid(pidfd);
  if (host < 0)
    return -LINUX_EBADF;
  if (kill(host, 0) < 0 && errno == ESRCH)
    return -LINUX_ESRCH;
  if (host != getpid())
    return -LINUX_EPERM;

  /*
   * Reaching here means the target is this process, and this process is
   * running - so it is not a dying one, which is the only kind this call acts
   * on. EINVAL is what Linux answers for that, and it is the right answer for
   * the right reason rather than a stand-in for "cannot".
   */
  return -LINUX_EINVAL;
}
