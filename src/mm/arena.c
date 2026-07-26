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
  struct fpunchhole hole = {
    .fp_flags = 0,
    .reserved = 0,
    .fp_offset = off,
    .fp_length = (off_t) size,
  };
  (void) fcntl(arena_backing_fd, F_PUNCHHOLE, &hole);
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
