/*
 * sendfile(2) and copy_file_range(2) - moving bytes without routing them
 * through the caller.
 *
 * Both exist so a program does not have to read into its own memory and write
 * the same bytes back out. On Linux that saves the two copies across the user
 * boundary, and copy_file_range can go further: on a filesystem that supports
 * it the kernel may share extents instead of copying at all, so a gigabyte
 * "copy" costs almost nothing.
 *
 * Neither shortcut is available here. Darwin's own sendfile(2) is a different
 * call with a different shape - its destination must be a socket, which Linux
 * has not required since 2.6.33 - so using it would implement a narrower
 * syscall than the one being asked for. APFS does have copy-on-write cloning,
 * but clonefile(2) clones a whole file to a new path; it cannot place a range
 * inside a file that already exists, which is precisely what copy_file_range
 * does. So the bytes go through a buffer in nabi, and what the guest gets is
 * the behaviour without the saving: the same bytes, the same count, the same
 * effect on every offset - just not the speed. That is the honest trade, and
 * it is the same one splice makes for the same reason.
 *
 * The part that needs care is not the copying, it is the bookkeeping, and it is
 * the reason both are written the way they are below.
 *
 * A short write loses data if the read has already moved a file position. Read
 * 64K from in_fd with read(2), have write(2) accept only 8K, and the other 56K
 * is gone: consumed from the source, never delivered, and not reported. So
 * nothing here reads with read(2). Every read is a pread from a cursor this
 * code owns, and a file position is only set at the end, from the count that
 * actually made it out. A short write then costs nothing - it just ends the
 * call early with a smaller number, which is what both syscalls are allowed to
 * do and what every correct caller already handles.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"

#define COPY_CHUNK 65536

/*
 * Where a transfer starts, and where it must be left.
 *
 * An offset the caller passed is its own: the descriptor's position must not
 * move, and the offset must, by however much was transferred. No offset means
 * the opposite - the position is the cursor and is where the result lands. One
 * struct for both so the two cases cannot drift apart.
 */
struct cursor {
  gaddr_t user;                 /* the guest's offset, or 0 for "use the file's" */
  int64_t at;
  bool from_file;
};

static int
cursor_open(struct cursor *c, int fd, gaddr_t user)
{
  c->user = user;
  c->from_file = (user == 0);
  if (user) {
    if (copy_from_user(&c->at, user, sizeof c->at))
      return -LINUX_EFAULT;
    if (c->at < 0)
      return -LINUX_EINVAL;
    return 0;
  }
  off_t cur = lseek(fd, 0, SEEK_CUR);
  if (cur < 0)
    return -darwin_to_linux_errno(errno);
  c->at = cur;
  return 0;
}

static int
cursor_close(struct cursor *c, int fd, int64_t moved)
{
  if (c->from_file)
    return lseek(fd, c->at + moved, SEEK_SET) < 0
             ? -darwin_to_linux_errno(errno) : 0;
  int64_t end = c->at + moved;
  return copy_to_user(c->user, &end, sizeof end) ? -LINUX_EFAULT : 0;
}

/* An offset cannot be honoured on a descriptor opened to append. */
static bool
appends(int fd)
{
  int fl = fcntl(fd, F_GETFL);
  return fl >= 0 && (fl & O_APPEND);
}

DEFINE_SYSCALL(sendfile, int, out_fd, int, in_fd, gaddr_t, offset_ptr,
               size_t, count)
{
  /*
   * The source must be something that can be read at an offset - Linux says
   * "an mmap-like operation", which in practice means a regular file, and
   * refuses a pipe here. The destination has no such rule since 2.6.33: a
   * socket, a pipe or a file all work, which is why nothing below assumes the
   * output is seekable.
   */
  struct stat si;
  if (fstat(in_fd, &si) < 0)
    return -LINUX_EBADF;
  if (!S_ISREG(si.st_mode))
    return -LINUX_EINVAL;

  if (count == 0)
    return 0;

  struct cursor in;
  int r = cursor_open(&in, in_fd, offset_ptr);
  if (r < 0)
    return r;

  char *buf = malloc(COPY_CHUNK);
  if (!buf)
    return -LINUX_ENOMEM;

  int64_t moved = 0;
  int err = 0;
  while ((size_t) moved < count) {
    size_t want = count - (size_t) moved;
    if (want > COPY_CHUNK)
      want = COPY_CHUNK;

    ssize_t n = pread(in_fd, buf, want, (off_t) (in.at + moved));
    if (n < 0) {
      if (moved == 0)
        err = -darwin_to_linux_errno(errno);
      break;
    }
    if (n == 0)
      break;                    /* end of file, however much that leaves */

    ssize_t w = write(out_fd, buf, (size_t) n);
    if (w < 0) {
      if (moved == 0)
        err = -darwin_to_linux_errno(errno);
      break;
    }
    moved += w;
    if (w < n)
      break;                    /* the destination is full or would block */
  }
  free(buf);

  if (err && moved == 0)
    return err;

  /* Only what was written counts, which is the whole point of reading from a
   * cursor: nothing was consumed that did not arrive. */
  if ((r = cursor_close(&in, in_fd, moved)) < 0)
    return r;
  return (int) moved;
}

DEFINE_SYSCALL(copy_file_range, int, fd_in, gaddr_t, off_in_ptr, int, fd_out,
               gaddr_t, off_out_ptr, size_t, len, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;       /* none are defined; Linux refuses the rest */

  struct stat si, so;
  if (fstat(fd_in, &si) < 0 || fstat(fd_out, &so) < 0)
    return -LINUX_EBADF;
  if (S_ISDIR(si.st_mode) || S_ISDIR(so.st_mode))
    return -LINUX_EISDIR;
  /* Regular files only - this one has no pipe end, which is the difference
   * between it and splice. */
  if (!S_ISREG(si.st_mode) || !S_ISREG(so.st_mode))
    return -LINUX_EINVAL;
  if (off_out_ptr && appends(fd_out))
    return -LINUX_EINVAL;

  if (len == 0)
    return 0;

  struct cursor in, out;
  int r = cursor_open(&in, fd_in, off_in_ptr);
  if (r < 0)
    return r;
  if ((r = cursor_open(&out, fd_out, off_out_ptr)) < 0)
    return r;

  /*
   * Copying a range of a file onto an overlapping range of the same file has no
   * defined answer - the source is being rewritten as it is read - so Linux
   * refuses it rather than producing whichever result the copy order happens to
   * give. Same file means same inode, not same descriptor: two opens of one
   * file are the case that would otherwise slip through.
   */
  if (si.st_dev == so.st_dev && si.st_ino == so.st_ino) {
    int64_t a = in.at, b = out.at;
    if (a < b + (int64_t) len && b < a + (int64_t) len)
      return -LINUX_EINVAL;
  }

  char *buf = malloc(COPY_CHUNK);
  if (!buf)
    return -LINUX_ENOMEM;

  int64_t moved = 0;
  int err = 0;
  while ((size_t) moved < len) {
    size_t want = len - (size_t) moved;
    if (want > COPY_CHUNK)
      want = COPY_CHUNK;

    ssize_t n = pread(fd_in, buf, want, (off_t) (in.at + moved));
    if (n < 0) {
      if (moved == 0)
        err = -darwin_to_linux_errno(errno);
      break;
    }
    if (n == 0)
      break;

    ssize_t w = pwrite(fd_out, buf, (size_t) n, (off_t) (out.at + moved));
    if (w < 0) {
      if (moved == 0)
        err = -darwin_to_linux_errno(errno);
      break;
    }
    moved += w;
    if (w < n)
      break;
  }
  free(buf);

  if (err && moved == 0)
    return err;

  if ((r = cursor_close(&in, fd_in, moved)) < 0)
    return r;
  if ((r = cursor_close(&out, fd_out, moved)) < 0)
    return r;
  return (int) moved;
}
