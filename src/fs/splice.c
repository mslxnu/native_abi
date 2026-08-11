/*
 * splice(2) and vmsplice(2) - the rest of the family tee(2) belongs to.
 *
 * These are much less trouble than tee, and for one reason: they *consume* what
 * they move. Tee's whole difficulty was leaving the source untouched on a host
 * that cannot look into a pipe without taking from it; splice is allowed to
 * take, so taking is the implementation.
 *
 * What they cannot do is the reason the family exists. On Linux these move
 * pipe buffers by reference - splice never copies, which is the point of using
 * it instead of read-then-write, and vmsplice hands the kernel the caller's own
 * pages. A guest pipe here is a Darwin pipe, and Darwin has no way to attach a
 * page to one, so the bytes go through a buffer. That costs a copy and changes
 * nothing a caller can observe: the same bytes arrive, in the same order, and
 * the same count comes back. It is the guarantee of speed that is lost, not the
 * guarantee of behaviour.
 *
 * SPLICE_F_MOVE is documented as a hint that the kernel is free to ignore, and
 * Linux itself has ignored it since 2.6.21 - so ignoring it is not a shortfall.
 * SPLICE_F_GIFT says the caller is donating its pages and must not touch them
 * again; copying honours that promise without taking it up, which is the
 * conservative direction and the only one available here.
 *
 * The part they do share with tee is the pushback. A pipe that tee has taken
 * bytes out of is holding them in front of the pipe (see src/fs/tee.c), and
 * splicing or vmsplicing from that pipe has to see them first, exactly as read
 * does - otherwise a guest that tees and then splices gets its stream back out
 * of order, which is the failure the pushback exists to prevent.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/fs.h"
#include "linux/socket.h"

#define LINUX_SPLICE_F_MOVE     0x01
#define LINUX_SPLICE_F_NONBLOCK 0x02
#define LINUX_SPLICE_F_MORE     0x04
#define LINUX_SPLICE_F_GIFT     0x08
#define SPLICE_F_ALL (LINUX_SPLICE_F_MOVE | LINUX_SPLICE_F_NONBLOCK | \
                      LINUX_SPLICE_F_MORE | LINUX_SPLICE_F_GIFT)

#define SPLICE_CHUNK 65536

static bool
is_pipe(int fd, bool *ok)
{
  struct stat st;
  if (fstat(fd, &st) < 0) {
    *ok = false;
    return false;
  }
  *ok = true;
  return S_ISFIFO(st.st_mode);
}

/*
 * Read from a pipe the way every other reader in nabi has to: whatever tee is
 * holding for it comes first, and the pipe itself only once that is empty.
 */
static ssize_t
pipe_in(int fd, char *buf, size_t len)
{
  ssize_t held = tee_take(fd, buf, len);
  if (held >= 0)
    return held;
  return read(fd, buf, len);
}

DEFINE_SYSCALL(splice, int, fd_in, gaddr_t, off_in_ptr, int, fd_out,
               gaddr_t, off_out_ptr, size_t, len, unsigned int, flags)
{
  if (flags & ~(unsigned) SPLICE_F_ALL)
    return -LINUX_EINVAL;

  bool ok_in, ok_out;
  bool pipe_src = is_pipe(fd_in, &ok_in);
  bool pipe_dst = is_pipe(fd_out, &ok_out);
  if (!ok_in || !ok_out)
    return -LINUX_EBADF;
  if (!pipe_src && !pipe_dst)
    return -LINUX_EINVAL;       /* one end must be a pipe; that is the call */

  /*
   * An offset only means something for the end that is seekable. Linux answers
   * ESPIPE rather than EINVAL when one is supplied for the pipe end, and the
   * distinction is worth keeping: it tells a caller it named the wrong side
   * rather than that the whole call was malformed.
   */
  if ((pipe_src && off_in_ptr) || (pipe_dst && off_out_ptr))
    return -LINUX_ESPIPE;

  /* Splicing to a file opened O_APPEND cannot honour an offset, so Linux
   * refuses the combination rather than quietly writing at the end. */
  if (off_out_ptr) {
    int fl = fcntl(fd_out, F_GETFL);
    if (fl >= 0 && (fl & O_APPEND))
      return -LINUX_EINVAL;
  }

  if (len == 0)
    return 0;
  if (len > SPLICE_CHUNK)
    len = SPLICE_CHUNK;

  int64_t off_in = 0, off_out = 0;
  if (off_in_ptr && copy_from_user(&off_in, off_in_ptr, sizeof off_in))
    return -LINUX_EFAULT;
  if (off_out_ptr && copy_from_user(&off_out, off_out_ptr, sizeof off_out))
    return -LINUX_EFAULT;

  char *buf = malloc(len);
  if (!buf)
    return -LINUX_ENOMEM;

  /*
   * SPLICE_F_NONBLOCK is about the pipe, not about the file: Linux says it does
   * not make a blocking *file* descriptor behave differently, so it is applied
   * to the pipe end only - and put back afterwards, since the flag belongs to
   * the open file description and would otherwise outlive the call and change
   * how every other user of that descriptor behaves.
   */
  int nb_fd = -1, nb_saved = 0;
  if ((flags & LINUX_SPLICE_F_NONBLOCK) && (pipe_src || pipe_dst)) {
    nb_fd = pipe_src ? fd_in : fd_out;
    nb_saved = fcntl(nb_fd, F_GETFL);
    if (nb_saved >= 0 && !(nb_saved & O_NONBLOCK))
      fcntl(nb_fd, F_SETFL, nb_saved | O_NONBLOCK);
    else
      nb_fd = -1;               /* already non-blocking; nothing to restore */
  }

  ssize_t n = pipe_src ? pipe_in(fd_in, buf, len)
                       : (off_in_ptr ? pread(fd_in, buf, len, (off_t) off_in)
                                     : read(fd_in, buf, len));
  int err = errno;

  if (nb_fd >= 0)
    fcntl(nb_fd, F_SETFL, nb_saved);

  if (n < 0) {
    free(buf);
    return -darwin_to_linux_errno(err);
  }
  if (n == 0) {
    free(buf);
    return 0;                   /* end of input, as splice reports it */
  }

  ssize_t w = off_out_ptr ? pwrite(fd_out, buf, (size_t) n, (off_t) off_out)
                          : write(fd_out, buf, (size_t) n);
  err = errno;
  free(buf);
  if (w < 0)
    return -darwin_to_linux_errno(err);

  /*
   * An offset the caller supplied is advanced by what moved, and the file's own
   * position is left alone - that separation is the whole reason for passing
   * one. A short write here is not recoverable: the bytes came out of the
   * source and the count reports where the stream now stands.
   */
  if (off_in_ptr) {
    off_in += w;
    if (copy_to_user(off_in_ptr, &off_in, sizeof off_in))
      return -LINUX_EFAULT;
  }
  if (off_out_ptr) {
    off_out += w;
    if (copy_to_user(off_out_ptr, &off_out, sizeof off_out))
      return -LINUX_EFAULT;
  }
  return (int) w;
}

/*
 * vmsplice: the same movement, with user memory on one side instead of a
 * descriptor. Which way it goes is decided by which end of the pipe was handed
 * over - the write end takes memory in, the read end gives it out - and that is
 * readable straight off the descriptor's access mode.
 */
DEFINE_SYSCALL(vmsplice, int, fd, gaddr_t, iov_ptr, unsigned long, nr_segs,
               unsigned int, flags)
{
  if (flags & ~(unsigned) SPLICE_F_ALL)
    return -LINUX_EINVAL;

  bool ok;
  if (!is_pipe(fd, &ok) || !ok)
    return -LINUX_EBADF;        /* not a pipe: EBADF here, not EINVAL */
  if (nr_segs == 0)
    return 0;
  if (nr_segs > 1024)          /* UIO_MAXIOV, as Linux caps every iovec */
    return -LINUX_EINVAL;

  struct l_iovec *iov = calloc(nr_segs, sizeof *iov);
  if (!iov)
    return -LINUX_ENOMEM;
  if (copy_from_user(iov, iov_ptr, nr_segs * sizeof *iov)) {
    free(iov);
    return -LINUX_EFAULT;
  }

  size_t total = 0;
  for (unsigned long i = 0; i < nr_segs; i++)
    total += iov[i].iov_len;
  if (total == 0) {
    free(iov);
    return 0;
  }
  if (total > SPLICE_CHUNK)
    total = SPLICE_CHUNK;

  char *buf = malloc(total);
  if (!buf) {
    free(iov);
    return -LINUX_ENOMEM;
  }

  int fl = fcntl(fd, F_GETFL);
  bool to_pipe = fl >= 0 && (fl & O_ACCMODE) != O_RDONLY;

  int nb_saved = -1;
  if ((flags & LINUX_SPLICE_F_NONBLOCK) && fl >= 0 && !(fl & O_NONBLOCK)) {
    nb_saved = fl;
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  }

  ssize_t n;
  if (to_pipe) {
    /* Gather the caller's memory and put it in the pipe. On Linux the pages
     * would be attached rather than copied; the bytes are the same either
     * way, and with SPLICE_F_GIFT copying is the safe reading of the promise. */
    size_t got = 0;
    for (unsigned long i = 0; i < nr_segs && got < total; i++) {
      size_t want = MIN(iov[i].iov_len, total - got);
      if (want && copy_from_user(buf + got, iov[i].iov_base, want)) {
        if (nb_saved >= 0) fcntl(fd, F_SETFL, nb_saved);
        free(buf); free(iov);
        return -LINUX_EFAULT;
      }
      got += want;
    }
    n = write(fd, buf, got);
  } else {
    n = pipe_in(fd, buf, total);
  }
  int err = errno;

  if (nb_saved >= 0)
    fcntl(fd, F_SETFL, nb_saved);

  if (n < 0) {
    free(buf); free(iov);
    return -darwin_to_linux_errno(err);
  }

  if (!to_pipe && n > 0) {
    /* Scatter what came out of the pipe back across the caller's vector. */
    size_t left = (size_t) n, done = 0;
    for (unsigned long i = 0; i < nr_segs && left; i++) {
      size_t s = MIN(left, iov[i].iov_len);
      if (s && copy_to_user(iov[i].iov_base, buf + done, s)) {
        free(buf); free(iov);
        return -LINUX_EFAULT;
      }
      done += s;
      left -= s;
    }
  }

  free(buf);
  free(iov);
  return (int) n;
}
