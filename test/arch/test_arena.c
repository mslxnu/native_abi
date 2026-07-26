/*
 * The guest-physical memory arena (src/mm/arena.c).
 *
 * Checks the properties fork-by-exec will depend on, none of which need a VM:
 * allocations are aligned and distinct, the arena is reachable through a plain
 * file descriptor, a private mapping of it starts out seeing the allocator's
 * bytes, and writes on either side of that private mapping stay on their own
 * side. That last one is the whole point - it is copy-on-write, which is what
 * fork owes a child.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"
#include "mm.h"

#if defined(__arm64__)
#include "arm64/vm.h"
#define EXPECTED_GRANULE STAGE2_GRANULE
#else
#define EXPECTED_GRANULE 0x1000UL
#endif

static int failures, checks;
#define CHECK(cond, ...)                                                       \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("  FAIL: "); printf(__VA_ARGS__);                                 \
      printf("\n        (%s:%d: %s)\n", __FILE__, __LINE__, #cond);            \
    }                                                                          \
  } while (0)

void printk(const char *fmt, ...) { (void) fmt; }
void warnk(const char *fmt, ...) { (void) fmt; }
void
panic(const char *fmt, ...)
{
  va_list ap; va_start(ap, fmt);
  printf("  PANIC: "); vprintf(fmt, ap); printf("\n");
  va_end(ap); exit(2);
}

int
main(void)
{
  printf("== guest memory arena ==\n\n");

  arena_init();

  int fd = arena_fd();
  CHECK(fd >= 0, "arena_fd() = %d, want a real descriptor", fd);

  /* The descriptor must survive exec, or a child could not inherit the arena. */
  int flags = fcntl(fd, F_GETFD);
  CHECK(flags >= 0 && !(flags & FD_CLOEXEC),
        "arena fd has FD_CLOEXEC set - it would not survive exec");

  /* Allocations: aligned, distinct, zeroed. */
  off_t off_a = -1, off_b = -1;
  unsigned char *a = arena_alloc(EXPECTED_GRANULE, &off_a);
  arena_alloc(EXPECTED_GRANULE, &off_b);

  CHECK(((uintptr_t) a % EXPECTED_GRANULE) == 0,
        "first allocation %p is not %lu-aligned", (void *) a, EXPECTED_GRANULE);
  CHECK((off_a % EXPECTED_GRANULE) == 0 && (off_b % EXPECTED_GRANULE) == 0,
        "arena offsets %lld,%lld are not granule-aligned",
        (long long) off_a, (long long) off_b);
  CHECK(off_a != off_b, "two allocations share arena offset %lld",
        (long long) off_a);
  CHECK(a[0] == 0 && a[EXPECTED_GRANULE - 1] == 0,
        "a fresh arena allocation is not zeroed");

  /* A sub-granule request still consumes a whole granule, so the next offset
   * stays mappable - a mapping is only as aligned as its offset. */
  off_t off_c = -1;
  arena_alloc(1, &off_c);
  CHECK((off_c % EXPECTED_GRANULE) == 0,
        "a small allocation left offset %lld unaligned", (long long) off_c);

  /* The bytes are reachable through the descriptor, by anyone holding it. */
  memset(a, 0xA5, EXPECTED_GRANULE);
  unsigned char *shared = mmap(NULL, EXPECTED_GRANULE, PROT_READ, MAP_SHARED,
                               fd, off_a);
  CHECK(shared != MAP_FAILED, "could not map the arena through its descriptor");
  if (shared != MAP_FAILED) {
    CHECK(shared[0] == 0xA5 && shared[EXPECTED_GRANULE - 1] == 0xA5,
          "a shared mapping does not see the allocator's writes");
    munmap(shared, EXPECTED_GRANULE);
  }

  /*
   * The handover property: a private mapping sees what was there at map time
   * and then diverges. This is what makes a fork child's memory correct - it
   * inherits the parent's guest state and its own writes stay its own.
   */
  unsigned char *priv = arena_map_private(off_a, EXPECTED_GRANULE);
  CHECK(priv[0] == 0xA5, "a private mapping does not start from the arena's bytes");

  priv[0] = 0x5A;                       /* child-side write */
  CHECK(a[0] == 0xA5, "a private mapping's write leaked into the arena");
  CHECK(priv[0] == 0x5A && a[0] == 0xA5,
        "private and shared mappings still alias after a copy-on-write");

  munmap(priv, EXPECTED_GRANULE);

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
