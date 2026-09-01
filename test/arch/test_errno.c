/*
 * Every Darwin errno has to come back as a Linux errno, and never as success.
 *
 * The generated map answers -1 for a value it does not know, and every caller
 * negates what it gets - syswrap is written as -darwin_to_linux_errno(errno) -
 * so an unmapped errno came back as +1. Not an error at all: a positive return,
 * which the guest reads as the call having succeeded and returned 1.
 *
 * Darwin's ENOTSUP was the one with no entry. Linux has a single "not
 * supported" and Darwin has two, EOPNOTSUPP and ENOTSUP, with different
 * numbers; the list declared the second with DECL_ALIAS, which names the
 * Linux-side constant and adds no case to the darwin-to-linux switch.
 *
 * What that cost was a boot. flock on the Android image answers ENOTSUP - it is
 * an ext2 volume over FUSE, which cannot lock - so iptables-restore was told
 * its flock returned 1, and it exits 4 when it cannot take the xtables lock.
 * That is netd's persistent child, so netd's next write to it was EPIPE and
 * SIGPIPE; init answers a dead netd by restarting zygote, and zygote's
 * onrestart by killing surfaceflinger, audioserver, cameraserver and media.
 * The system spent every boot restarting itself.
 *
 * So the sweep below is the point: not that some particular errno maps, but
 * that no errno at all can produce something a caller would read as success.
 */
#include <errno.h>
#include <stdio.h>
#include <sys/errno.h>
#include "linux/errno.h"

/* The map warns about what it does not know, which here is the expected case
 * rather than news; the test is about what it returns. */
void
warnk(const char *fmt, ...)
{
  (void) fmt;
}

static int fails;

static void
want_error(const char *what, int darwin_errno)
{
  int r = darwin_to_linux_errno(darwin_errno);
  if (r > 0)
    return;
  fails++;
  printf("  FAIL %s (darwin %d) mapped to %d; -r would be %d, which reads as "
         "success\n", what, darwin_errno, r, -r);
}

int
main(void)
{
  /* Every errno Darwin defines, which is what a host syscall can hand back. */
  for (int e = 1; e <= ELAST; e++) {
    char name[32];
    snprintf(name, sizeof name, "errno %d", e);
    want_error(name, e);
  }

  /* And the two that started it, by name. */
  want_error("ENOTSUP", ENOTSUP);
  want_error("EOPNOTSUPP", EOPNOTSUPP);
  if (darwin_to_linux_errno(ENOTSUP) != LINUX_EOPNOTSUPP) {
    fails++;
    printf("  FAIL ENOTSUP mapped to %d, want LINUX_EOPNOTSUPP (%d)\n",
           darwin_to_linux_errno(ENOTSUP), LINUX_EOPNOTSUPP);
  }

  /* The ordinary ones still have to be themselves. */
  if (darwin_to_linux_errno(ENOENT) != LINUX_ENOENT) {
    fails++;
    printf("  FAIL ENOENT did not map to LINUX_ENOENT\n");
  }
  if (darwin_to_linux_errno(EPERM) != LINUX_EPERM) {
    fails++;
    printf("  FAIL EPERM did not map to LINUX_EPERM\n");
  }

  printf(fails == 0 ? "errno ok\n" : "errno failed\n");
  return fails ? 1 : 0;
}
