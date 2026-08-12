/*
 * cachestat: how much of a file range is in the page cache.
 *
 * Linux answers five numbers - cached, dirty, under writeback, evicted, and
 * recently evicted. Exactly one of them can be answered here, and it is the one
 * the call is named for.
 *
 * nr_cache comes from mincore over a read-only shared mapping of the range, and
 * that is a real answer rather than a plausible one, which was worth checking
 * before relying on it. Darwin's mincore reports the residency of the vnode's
 * pages in the unified buffer cache, not the faults this mapping has taken: a
 * file just written reads back fully resident through a mapping nothing has
 * touched, and a file this process has never opened reads back as zero. That is
 * the same quantity Linux counts. The mapping itself does not disturb what it
 * measures - PROT_READ, never touched, unmapped straight away, so no page is
 * faulted in by the asking.
 *
 * The other four are left zero, and a caller should know that means "not known
 * here" rather than "known to be none". Darwin exposes no per-file dirty or
 * writeback count and keeps no shadow entry for a page it has evicted, so there
 * is nothing to read and nothing that could be derived. They are zeroed rather
 * than invented for the same reason adjtimex leaves `tick` alone: a number
 * nobody set is worse than a number that is missing.
 *
 * The unit is a page, and the page here is the guest's own - AT_PAGESZ is
 * STAGE2_GRANULE on arm64 and 4KiB on x86-64, which in both builds is the host
 * page size. So one residency bit is one guest page and no conversion is needed.
 * That equality is what makes this simple rather than something this file may
 * assume, so it is checked once rather than believed - see guest_page_size().
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "x86/vm.h"
#include "arm64/vm.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"

struct l_cachestat_range {
  uint64_t off;
  uint64_t count;
};

struct l_cachestat {
  uint64_t nr_cache;
  uint64_t nr_dirty;
  uint64_t nr_writeback;
  uint64_t nr_evicted;
  uint64_t nr_recently_evicted;
};

/*
 * The page cachestat counts in, which is the guest's and not necessarily the
 * host's. They are equal in both builds today, and mincore can only speak in
 * host pages - so a divergence would silently scale every answer. It is caught
 * here instead, once, and loudly.
 */
static size_t
guest_page_size(void)
{
#if defined(__arm64__)
  size_t guest = STAGE2_GRANULE;
#else
  size_t guest = PAGE_SIZEOF(PAGE_4KB);
#endif
  static bool warned;
  if (guest != (size_t) getpagesize() && !warned) {
    warned = true;
    warnk("cachestat: guest page %zu, host page %d; counts are in host pages\n",
          guest, getpagesize());
  }
  return (size_t) getpagesize();
}

/* 64MiB at a time, so the residency vector stays small whatever the file is. */
#define CACHESTAT_CHUNK  (64ULL << 20)

/*
 * A descriptor this can map, which is not always the one that was passed.
 *
 * cachestat is legal on a write-only descriptor - a writer asking how much of
 * what it produced is still cached is the obvious use - and a shared read
 * mapping of one is refused. The file is reopened by its own path in that case,
 * which reaches the same vnode and therefore the same cached pages.
 *
 * Returns a descriptor to map and sets *opened when it is a new one to close.
 */
static int
mappable_fd(int fd, bool *opened)
{
  *opened = false;
  int fl = fcntl(fd, F_GETFL);
  if (fl >= 0 && ((fl & O_ACCMODE) == O_RDONLY || (fl & O_ACCMODE) == O_RDWR))
    return fd;

  char path[PATH_MAX];
  if (fcntl(fd, F_GETPATH, path) < 0)
    return -1;
  int nfd = open(path, O_RDONLY | O_CLOEXEC);
  if (nfd < 0)
    return -1;
  *opened = true;
  return nfd;
}

static int
count_resident(int fd, uint64_t start, uint64_t last, uint64_t *out)
{
  size_t ps = guest_page_size();
  char vec[CACHESTAT_CHUNK / 4096];   /* enough at any page size >= 4KiB */
  uint64_t total = 0;

  for (uint64_t o = start; o < last; o += CACHESTAT_CHUNK) {
    size_t len = (size_t) (last - o < CACHESTAT_CHUNK ? last - o : CACHESTAT_CHUNK);
    void *p = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_SHARED, fd, (off_t) o);
    if (p == MAP_FAILED)
      return -1;
    size_t n = (len + ps - 1) / ps;
    if (mincore(p, len, vec) < 0) {
      int e = errno;
      munmap(p, len);
      errno = e;
      return -1;
    }
    munmap(p, len);
    for (size_t i = 0; i < n; i++)
      if (vec[i] & MINCORE_INCORE)
        total++;
  }
  *out = total;
  return 0;
}

DEFINE_SYSCALL(cachestat, unsigned int, fd, gaddr_t, range_ptr,
               gaddr_t, cstat_ptr, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (fcntl((int) fd, F_GETFD) < 0)
    return -LINUX_EBADF;

  struct l_cachestat_range range;
  if (copy_from_user(&range, range_ptr, sizeof range))
    return -LINUX_EFAULT;
  if (range.off + range.count < range.off)      /* the overflow Linux checks */
    return -LINUX_EINVAL;

  struct l_cachestat cs;
  memset(&cs, 0, sizeof cs);

  struct stat st;
  if (fstat((int) fd, &st) < 0)
    return syswrap(-1);

  /*
   * Anything without a page cache has nothing cached, and reporting zero is not
   * a shortcut: a pipe or a socket holds no pages, which is the same answer
   * Linux arrives at by walking an empty mapping.
   */
  if (S_ISREG(st.st_mode)) {
    uint64_t size = (uint64_t) st.st_size;
    uint64_t off = range.off;
    uint64_t end = range.count == 0 ? size : off + range.count;
    if (end > size)
      end = size;

    if (off < end) {
      size_t ps = guest_page_size();
      uint64_t start = off & ~(uint64_t) (ps - 1);
      uint64_t last = (end + ps - 1) & ~(uint64_t) (ps - 1);

      bool opened;
      int mfd = mappable_fd((int) fd, &opened);
      if (mfd < 0)
        return -LINUX_EBADF;
      int r = count_resident(mfd, start, last, &cs.nr_cache);
      int e = errno;
      if (opened)
        close(mfd);
      if (r < 0) {
        errno = e;
        return syswrap(-1);
      }
    }
  }

  if (copy_to_user(cstat_ptr, &cs, sizeof cs))
    return -LINUX_EFAULT;
  return 0;
}
