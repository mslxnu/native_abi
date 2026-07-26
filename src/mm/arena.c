/*
 * The guest-physical memory arena.
 *
 * Every page of memory the guest can address is carved out of one file-backed
 * arena instead of coming from the C heap or from private anonymous mappings.
 * The point is not allocation policy - it is that the arena has a *file
 * descriptor*, so a second process can obtain the same bytes by mapping it.
 *
 * That is what a working fork needs on Apple Silicon. Hypervisor.framework
 * cannot create a vCPU in a process that already had one (spike/arm64-fork/), so
 * a forked child has to `exec` before it can run a guest - and `exec` destroys
 * the address space that `fork` had just copied. Inherited file descriptors do
 * survive `exec`, so guest memory reached through this fd survives with them,
 * while memory reached only through a pointer does not.
 *
 * The running guest's mappings are MAP_PRIVATE, and that is not an accident.
 * MAP_SHARED would be the obvious choice - writes would land in the arena, so a
 * handover would need no copy at all - but it also removes copy-on-write from
 * an ordinary `fork`, and until the fork rework lands `fork` is still exactly
 * that. Sharing the arena makes a forked child write straight into its parent's
 * guest memory: measurably, guest pipelines stop working, because the two halves
 * of `cmd | cmd` corrupt each other. Private mappings keep today's semantics
 * correct and cost only that the handover has to write the live bytes into the
 * arena at fork time rather than finding them already there.
 *
 * What the arena buys today is therefore the *naming*, not the sharing: every
 * guest region has an offset, recorded alongside it, that means something in
 * another process. Filling those offsets and mapping them on the far side is
 * what the remaining fork work does.
 *
 * The backing file is created and immediately unlinked, so it has no name for
 * anyone else to find and disappears with the last descriptor.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"

/*
 * Granularity. hv_vm_map insists on 16KiB alignment for the host address, the
 * IPA and the length alike on Apple Silicon, and a mapping of a file offset is
 * only as aligned as the offset is - so offsets are handed out in the same
 * granule, not merely page-aligned. On x86 this is the 4KiB page and nothing
 * about the arena changes.
 */
#if defined(__arm64__)
#include "arm64/vm.h"
#define ARENA_GRANULE STAGE2_GRANULE
#else
#define ARENA_GRANULE 0x1000UL
#endif

/* Grow the backing file in chunks rather than once per allocation: a 16KiB
 * guest page would otherwise cost an ftruncate each. */
#define ARENA_GROW_STEP (4UL << 20)

static int    arena_backing_fd = -1;
static off_t  arena_brk;        /* next unallocated offset */
static off_t  arena_capacity;   /* how far the file has been grown */

/*
 * Live allocations, so a host address can be turned back into the offset that
 * names it elsewhere. Checkpointing needs exactly that direction: the stage-2
 * registry and the region list both hold host pointers, and a pointer is the one
 * thing that cannot be handed to another process.
 *
 * A flat array is enough - this is walked when a mapping is created or a
 * checkpoint is taken, never on a fault path.
 */
struct arena_span { void *addr; size_t size; off_t off; };
off_t arena_offset_of(void *addr);
#define ARENA_MAX_SPANS 16384
static struct arena_span arena_spans[ARENA_MAX_SPANS];
static size_t nr_arena_spans;

static void
arena_span_record(void *addr, size_t size, off_t off)
{
  if (nr_arena_spans == ARENA_MAX_SPANS)
    panic("too many live arena spans");
  arena_spans[nr_arena_spans++] = (struct arena_span){ addr, size, off };
}

/*
 * Remove [off, off+size) from whatever span covers it.
 *
 * Not simply "forget the span with this offset". A region can be split - the mm
 * layer does it whenever a guest unmaps part of one - and the halves are then
 * freed separately, so a release may take a prefix, a suffix or a hole out of
 * the middle of a span. Getting this wrong leaves a span describing memory the
 * caller has already unmapped, and the next flush reads from it: the guest's
 * fork then fails with EFAULT, or worse, silently hands its child stale bytes.
 */
static void
arena_span_forget(off_t off, size_t size)
{
  off_t lo = off, hi = off + (off_t) size;

  for (size_t i = 0; i < nr_arena_spans; i++) {
    off_t slo = arena_spans[i].off;
    off_t shi = slo + (off_t) arena_spans[i].size;
    if (hi <= slo || lo >= shi)
      continue;                                   /* no overlap */

    if (lo <= slo && hi >= shi) {                 /* whole span */
      arena_spans[i] = arena_spans[--nr_arena_spans];
      i--;
    } else if (lo <= slo) {                       /* prefix */
      size_t cut = (size_t)(hi - slo);
      arena_spans[i].addr = (char *) arena_spans[i].addr + cut;
      arena_spans[i].off += (off_t) cut;
      arena_spans[i].size -= cut;
    } else if (hi >= shi) {                       /* suffix */
      arena_spans[i].size = (size_t)(lo - slo);
    } else {                                      /* hole: keep both sides */
      struct arena_span tail = {
        .addr = (char *) arena_spans[i].addr + (hi - slo),
        .size = (size_t)(shi - hi),
        .off  = hi,
      };
      arena_spans[i].size = (size_t)(lo - slo);
      arena_span_record(tail.addr, tail.size, tail.off);
    }
  }
}

static void
arena_span_forget_addr(const void *addr, size_t size)
{
  off_t off = arena_offset_of((void *) addr);
  if (off >= 0)
    arena_span_forget(off, size);
}

/*
 * Drop a mapping and the span that described it.
 *
 * Unmapping behind the arena's back would leave a span pointing at nothing, and
 * the next flush would read from it - so anything mapped through the arena has
 * to be released through the arena.
 */
void
arena_unmap(void *addr, size_t size)
{
  size = roundup(size, ARENA_GRANULE);
  arena_span_forget_addr(addr, size);
  munmap(addr, size);
}

/*
 * The arena offset backing a host address, or -1 if it is not arena memory
 * (SysV shared segments and the vkernel's own bookkeeping are not). Interior
 * addresses resolve to their span's offset plus the distance in, so a caller
 * holding a pointer into the middle of a region gets a usable answer.
 */
/*
 * The other direction: where a resumed process mapped a given arena offset.
 * Restoring works from offsets - they are all a checkpoint can carry - and has
 * to turn them back into addresses for hv_vm_map and the region list.
 */
void *
arena_hva_of(off_t off)
{
  for (size_t i = 0; i < nr_arena_spans; i++) {
    if (off >= arena_spans[i].off &&
        off < arena_spans[i].off + (off_t) arena_spans[i].size)
      return (char *) arena_spans[i].addr + (off - arena_spans[i].off);
  }
  return NULL;
}

off_t
arena_offset_of(void *addr)
{
  for (size_t i = 0; i < nr_arena_spans; i++) {
    char *base = arena_spans[i].addr;
    if ((char *) addr >= base && (char *) addr < base + arena_spans[i].size)
      return arena_spans[i].off + ((char *) addr - base);
  }
  return -1;
}

int
arena_fd(void)
{
  return arena_backing_fd;
}

void
arena_init(void)
{
  if (arena_backing_fd >= 0)
    return;                     /* already set up; re-entered after exec */

  const char *tmp = getenv("TMPDIR");
  char path[1024];
  snprintf(path, sizeof path, "%s/nabi-arena-XXXXXX",
           tmp && *tmp ? tmp : "/tmp");

  int fd = mkstemp(path);
  if (fd < 0)
    panic("could not create the guest memory arena: %s", strerror(errno));
  /*
   * Unlink at once: the arena is reached through the descriptor, never through
   * the name, so there is nothing for another process to open and nothing left
   * behind if we die. Descriptors keep the storage alive.
   */
  unlink(path);

  /* Must survive exec - that is the entire reason the arena is a file. */
  if (fcntl(fd, F_SETFD, 0) < 0)
    panic("could not clear FD_CLOEXEC on the arena: %s", strerror(errno));

  arena_backing_fd = fd;
  arena_brk = 0;
  arena_capacity = 0;
}

/*
 * Reserve `size` bytes of arena and map them for this process.
 *
 * Returns the host address and, through `off_out`, the offset that names those
 * bytes in the arena - the offset is what a second process needs, since the
 * address is meaningless outside this one.
 */
void *
arena_alloc(size_t size, off_t *off_out)
{
  if (arena_backing_fd < 0)
    arena_init();

  size = roundup(size, ARENA_GRANULE);

  off_t off = arena_brk;
  arena_brk += size;

  if (arena_brk > arena_capacity) {
    off_t want = roundup(arena_brk, ARENA_GROW_STEP);
    if (ftruncate(arena_backing_fd, want) < 0)
      panic("could not grow the guest memory arena to %lld bytes: %s",
            (long long) want, strerror(errno));
    arena_capacity = want;
  }

  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                 arena_backing_fd, off);
  if (p == MAP_FAILED)
    panic("could not map guest memory arena offset %lld: %s",
          (long long) off, strerror(errno));

  arena_span_record(p, size, off);

  if (off_out)
    *off_out = off;
  return p;
}

/*
 * Release an arena range.
 *
 * The storage goes back to the filesystem; the offset does not go back to the
 * allocator. That asymmetry is deliberate. Reusing offsets would need a free
 * list and would invite fragmentation, whereas offsets are a 64-bit namespace
 * that a guest cannot plausibly exhaust - the arena's *apparent* size grows
 * monotonically but it is sparse, and what actually costs anything is the
 * storage, which punching the hole hands back straight away.
 *
 * Best-effort: a filesystem that cannot punch holes leaves the pages allocated,
 * which wastes space but breaks nothing, so it is not worth failing a guest
 * munmap over.
 */
void
arena_free(off_t off, size_t size)
{
  if (arena_backing_fd < 0)
    return;

  size = roundup(size, ARENA_GRANULE);
  arena_span_forget(off, size);
  struct fpunchhole hole = {
    .fp_flags = 0,
    .reserved = 0,
    .fp_offset = off,
    .fp_length = (off_t) size,
  };
  (void) fcntl(arena_backing_fd, F_PUNCHHOLE, &hole);
}

/*
 * Copy the guest, as it is now, into a fresh arena and return its descriptor.
 *
 * The running guest's mappings are private, so its writes live in this process
 * and not in any file; a handover has to put them somewhere the child can map.
 * This is the one eager copy the design costs, and it buys back ordinary
 * copy-on-write fork semantics for the guest while it runs.
 *
 * Each handover gets its *own* file, which is the part that is not optional.
 * Writing into the arena the parent is already using looks like it would work -
 * the parent's mappings are copy-on-write away from it, so the parent is
 * undisturbed - but a child that has already been handed that arena maps it
 * privately and reads any page it has not yet written straight out of the file.
 * Overwriting it therefore reaches into a live child and changes guest memory
 * underneath it. It is not even a rare race: a shell pipeline forks twice in
 * succession, and the second flush would rewrite the first child's memory to the
 * parent's later state, so both halves of `cmd | cmd` came up believing they
 * were the same half. A file nothing writes to again cannot do that.
 *
 * Offsets are preserved exactly, so the checkpoint's offsets mean the same thing
 * on both sides.
 */
int
arena_snapshot(void)
{
  const char *tmp = getenv("TMPDIR");
  char path[1024];
  snprintf(path, sizeof path, "%s/nabi-snap-XXXXXX", tmp && *tmp ? tmp : "/tmp");

  int fd = mkstemp(path);
  if (fd < 0)
    return -1;
  unlink(path);
  fcntl(fd, F_SETFD, 0);                /* must survive the child's exec */

  if (ftruncate(fd, arena_capacity) < 0) {
    close(fd);
    return -1;
  }

  for (size_t i = 0; i < nr_arena_spans; i++) {
    const char *p = arena_spans[i].addr;
    size_t left = arena_spans[i].size;
    off_t off = arena_spans[i].off;
    while (left > 0) {
      ssize_t n = pwrite(fd, p, left, off);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        close(fd);
        return -1;
      }
      p += n; off += n; left -= (size_t) n;
    }
  }
  return fd;
}

/*
 * Map an existing arena range privately.
 *
 * For the resuming side of a fork: the child starts out seeing exactly the
 * bytes the parent had at handover and diverges copy-on-write from its first
 * write, which is what fork promises, without copying the address space.
 */
void *
arena_map_private(off_t off, size_t size)
{
  if (arena_backing_fd < 0)
    panic("arena_map_private before the arena exists");

  size = roundup(size, ARENA_GRANULE);
  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                 arena_backing_fd, off);
  if (p == MAP_FAILED)
    panic("could not privately map arena offset %lld: %s",
          (long long) off, strerror(errno));
  /* Registered like any other span, so the restore can look the mapping up by
   * offset and so a later handover from this process flushes it. */
  arena_span_record(p, size, off);
  return p;
}

/* Adopt an arena handed over by another process (the exec'd child's side). */
void
arena_adopt(int fd)
{
  struct stat st;
  if (fstat(fd, &st) < 0)
    panic("arena_adopt: bad descriptor %d: %s", fd, strerror(errno));
  arena_backing_fd = fd;
  arena_capacity = st.st_size;
  arena_brk = st.st_size;
}
