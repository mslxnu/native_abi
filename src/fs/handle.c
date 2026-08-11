/*
 * File handles: name_to_handle_at and open_by_handle_at.
 *
 * A handle is a name for a file that does not go through a path - hand it back
 * later, possibly in another process, and get the same object. Linux's is
 * opaque bytes produced by the filesystem, and the only requirement on anyone
 * implementing it is that the bytes round-trip.
 *
 * Darwin has the same idea under a different name. A volume that supports volfs
 * - HFS+ and APFS both do - resolves /.vol/<device>/<inode> to the file, which
 * is `open_by_handle_at` with the handle spelled out as a path. So the handle
 * here is the pair that names it, and resolving one is an open of that path.
 *
 * These were ENOSYS, and that had already been noticed from the other side: the
 * comment on statx's STATX_MNT_ID says software asks statx first and falls back
 * to name_to_handle_at, "which Darwin has nothing to implement". Darwin does;
 * it is just not called that.
 *
 * They exist here because fanotify's FAN_REPORT_FID reports a handle instead of
 * a descriptor, and a handle a listener cannot resolve would be a number to
 * compare and nothing more. With these, a listener that is told which file an
 * event concerned can go and open it, which is the point of the mode.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/misc.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/handle.h"

/*
 * The bytes in our handle. Opaque to the guest, as Linux's are - what matters
 * is that this side can turn them back into the file, and that a handle taken
 * now still names the same object later, which an inode number does and a path
 * does not.
 */
struct nabi_handle {
  uint64_t ino;
  uint32_t dev;
  uint32_t _pad;
};

#define NABI_HANDLE_TYPE 0x81   /* ours; Linux's FILEID_* are equally private */

int
handle_build(const char *hostpath, struct nabi_handle *out, uint32_t *dev_out)
{
  struct stat st;
  if (stat(hostpath, &st) < 0)
    return -darwin_to_linux_errno(errno);
  out->ino = (uint64_t) st.st_ino;
  out->dev = (uint32_t) st.st_dev;
  out->_pad = 0;
  if (dev_out)
    *dev_out = (uint32_t) st.st_dev;
  return 0;
}

DEFINE_SYSCALL(name_to_handle_at, int, dirfd, gstr_t, path_ptr,
               gaddr_t, handle_ptr, gaddr_t, mount_id_ptr, int, flags)
{
  char guestpath[LINUX_PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0)
    return -LINUX_EFAULT;
  if (flags & ~(LINUX_AT_SYMLINK_FOLLOW | LINUX_AT_EMPTY_PATH))
    return -LINUX_EINVAL;

  char host[PATH_MAX];
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;

  struct nabi_handle h;
  uint32_t dev;
  if ((r = handle_build(host, &h, &dev)) < 0)
    return r;

  /*
   * The caller sizes the buffer by asking once with handle_bytes too small and
   * being told how much is wanted. Answering EOVERFLOW *and* writing the size
   * is the whole protocol - a caller told only that it was too small has no way
   * to try again.
   */
  struct l_file_handle fh;
  if (copy_from_user(&fh, handle_ptr, sizeof fh))
    return -LINUX_EFAULT;
  if (fh.handle_bytes < sizeof h) {
    fh.handle_bytes = sizeof h;
    if (copy_to_user(handle_ptr, &fh, sizeof fh))
      return -LINUX_EFAULT;
    return -LINUX_EOVERFLOW;
  }

  fh.handle_bytes = sizeof h;
  fh.handle_type = NABI_HANDLE_TYPE;
  if (copy_to_user(handle_ptr, &fh, sizeof fh) ||
      copy_to_user(handle_ptr + sizeof fh, &h, sizeof h))
    return -LINUX_EFAULT;

  if (mount_id_ptr != 0) {
    /* st_dev, which is what statx reports as the mount id here too - one
     * number per filesystem, and the two have to agree or software comparing
     * them concludes two files on one volume are on different ones. */
    int mid = (int) dev;
    if (copy_to_user(mount_id_ptr, &mid, sizeof mid))
      return -LINUX_EFAULT;
  }
  return 0;
}

/*
 * Resolving a handle.
 *
 * Linux takes the filesystem from `mount_fd` and the object from the handle.
 * The handle here carries both, so the descriptor is not consulted - which is
 * more permissive than Linux by exactly the amount a caller cannot observe,
 * since a handle from another filesystem would not have resolved there either.
 */
DEFINE_SYSCALL(open_by_handle_at, int, mount_fd, gaddr_t, handle_ptr,
               int, flags)
{
  /* CAP_DAC_READ_SEARCH on Linux: a handle bypasses the directory permissions
   * that a path would have been checked against. Guest root here, as
   * everything else that stands in for a capability is. */
  pthread_rwlock_rdlock(&proc.cred.lock);
  bool root = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (!root)
    return -LINUX_EPERM;

  struct l_file_handle fh;
  if (copy_from_user(&fh, handle_ptr, sizeof fh))
    return -LINUX_EFAULT;
  if (fh.handle_type != NABI_HANDLE_TYPE || fh.handle_bytes != sizeof(struct nabi_handle))
    return -LINUX_ESTALE;

  struct nabi_handle h;
  if (copy_from_user(&h, handle_ptr + sizeof fh, sizeof h))
    return -LINUX_EFAULT;

  char path[PATH_MAX];
  snprintf(path, sizeof path, "/.vol/%u/%llu",
           (unsigned) h.dev, (unsigned long long) h.ino);

  int fd = open(path, linux_to_darwin_o_flags(flags));
  if (fd < 0)
    return -darwin_to_linux_errno(errno);

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, (flags & LINUX_O_CLOEXEC) != 0);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(fd);
    return err;
  }
  return fd;
}
