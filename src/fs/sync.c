/*
 * sync_file_range.
 *
 * Refused, this was the most frequently reached unimplemented call in the tree
 * by a wide margin - dpkg asks for it several hundred times unpacking a single
 * package.
 */
#include <errno.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"

/*
 * sync_file_range: the range is ignored, and the direction that costs is safe.
 *
 * dpkg calls this several hundred times unpacking a package, so it was the most
 * frequently refused call in the tree by a wide margin. Darwin has no ranged
 * flush - fsync is whole-file or nothing - so the range is widened to the file,
 * which writes back more than was asked and never less.
 *
 * The waiting matters more than the range. SYNC_FILE_RANGE_WRITE only *starts*
 * writeback and promises nothing about when it lands, so it is answered without
 * doing anything: the data reaches the file either way, and Linux's own manual
 * is emphatic that this form is not a durability guarantee. The WAIT forms do
 * promise the writeback has finished, and get an fsync, which is the promise
 * they asked for.
 */
#define LINUX_SYNC_FILE_RANGE_WAIT_BEFORE 1
#define LINUX_SYNC_FILE_RANGE_WRITE       2
#define LINUX_SYNC_FILE_RANGE_WAIT_AFTER  4

DEFINE_SYSCALL(sync_file_range, int, fd, off_t, offset, off_t, nbytes,
               unsigned int, flags)
{
  if (flags & ~(unsigned) (LINUX_SYNC_FILE_RANGE_WAIT_BEFORE |
                           LINUX_SYNC_FILE_RANGE_WRITE |
                           LINUX_SYNC_FILE_RANGE_WAIT_AFTER))
    return -LINUX_EINVAL;
  if (offset < 0 || nbytes < 0)
    return -LINUX_EINVAL;

  if (flags & (LINUX_SYNC_FILE_RANGE_WAIT_BEFORE |
               LINUX_SYNC_FILE_RANGE_WAIT_AFTER))
    return syswrap(fsync(fd));
  return 0;
}
