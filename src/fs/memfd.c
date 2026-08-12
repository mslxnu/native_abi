/*
 * memfd_create: a file that is only ever a descriptor.
 *
 * The pattern is the one mqueues, io_uring rings, mount contexts and pidfds all
 * use here - create a file, unlink it immediately, and hand back the
 * descriptor. The descriptor *is* the object: it survives fork and exec, it can
 * be sent over a unix socket with SCM_RIGHTS, two holders share one file, and
 * when the last one closes it the storage goes. That is memfd's contract
 * exactly, which is why this needs no side table and no cleanup path.
 *
 * It matters more than most of the batch because it is load-bearing for
 * desktop software: wl_shm passes one of these for every Wayland buffer, dbus
 * uses them for large messages, and Chromium and systemd both allocate them
 * early. Without it those fall back to a named temporary file or fail outright.
 *
 * What is missing is sealing. F_ADD_SEALS is how a sender promises a receiver
 * that a shared buffer will not change under it, and Darwin has no equivalent -
 * a seal is a property of the inode, enforced by the kernel on every write, and
 * there is no kernel here to enforce it. MFD_ALLOW_SEALING is therefore
 * accepted, because all it does is permit a later seal, and the later seal is
 * what fails: fcntl answers EINVAL, which is what Linux answers for a file that
 * does not support sealing. A caller learns it at the point where it matters
 * and can decline to trust the buffer, rather than being told a seal was
 * applied that nothing honours.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"

#define LINUX_MFD_CLOEXEC        0x0001U
#define LINUX_MFD_ALLOW_SEALING  0x0002U
#define LINUX_MFD_HUGETLB        0x0004U
#define LINUX_MFD_NOEXEC_SEAL    0x0008U
#define LINUX_MFD_EXEC           0x0010U

/* Linux's limit on the name, which is a debugging label and nothing more: it
 * appears in /proc/self/fd and is not a path and need not be unique. */
#define MFD_NAME_MAX  249

DEFINE_SYSCALL(memfd_create, gstr_t, name_ptr, unsigned int, flags)
{
  if (flags & ~(LINUX_MFD_CLOEXEC | LINUX_MFD_ALLOW_SEALING |
                LINUX_MFD_HUGETLB | LINUX_MFD_NOEXEC_SEAL | LINUX_MFD_EXEC))
    return -LINUX_EINVAL;
  /*
   * Huge pages are a placement request the host cannot be asked for, and the
   * point of them is that the allocation *is* backed that way. Refused rather
   * than served with ordinary pages.
   */
  if (flags & LINUX_MFD_HUGETLB)
    return -LINUX_EINVAL;
  /* These two contradict each other: one asks for the file to be sealed
   * non-executable at birth and the other asks for it to stay executable. */
  if ((flags & LINUX_MFD_NOEXEC_SEAL) && (flags & LINUX_MFD_EXEC))
    return -LINUX_EINVAL;

  char name[MFD_NAME_MAX + 1];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  if (strlen(name) > MFD_NAME_MAX)
    return -LINUX_EINVAL;

  /*
   * The template only has to be unique for the instant between creating the
   * file and unlinking it. The guest's name goes nowhere near it - it may
   * contain a slash, and it is not a path.
   */
  const char *tmp = getenv("TMPDIR");
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/nabi-memfd-%s-XXXXXX",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag());

  int fd = mkstemp(path);
  if (fd < 0)
    return syswrap(-1);
  /*
   * Gone from the filesystem before anything else can reach it, which is both
   * what memfd means and what keeps a crashed guest from leaving these behind.
   */
  unlink(path);

  if (flags & LINUX_MFD_CLOEXEC) {
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
      int e = errno;
      close(fd);
      errno = e;
      return syswrap(-1);
    }
  }

  int r = register_fd(fd, (flags & LINUX_MFD_CLOEXEC) != 0);
  if (r < 0) {
    close(fd);
    return r;
  }
  return fd;
}
