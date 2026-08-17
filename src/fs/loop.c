/*
 * Loop devices: a regular file made to look like a block device.
 *
 * nabi can mount an image already - the host is asked to do it, see
 * diskimage.c - but nothing could reach that, because util-linux's `mount`
 * never calls mount(2) on a regular file. It sets up a loop device first, in
 * userspace, and gives up when it cannot: "failed to setup loop device". The
 * mount(2) that would have worked is never attempted. waydroid mounts its
 * images with that mount, so this is what stands between the two.
 *
 * So the devices exist here. There is no block layer under them and they move
 * no data: a loop device in nabi is a *name* for a backing file, and the only
 * thing that reads it is mount, which hands the name back and gets the file
 * mounted. That is the whole of what the abstraction is used for here, and
 * pretending otherwise - a device that could be read and written as a disk -
 * would be a much larger lie for no caller.
 *
 * The table is a file, like the mount table and the pid namespace beside it,
 * because the processes that use it are separate: `losetup` sets one up and
 * `mount` uses it, and a device bound in one has to be visible in the next.
 *
 * /dev is a host passthrough, so these paths cannot be created as real nodes -
 * they are answered here instead, the same way /proc entries nabi serves
 * itself are. open and stat both have to know, because util-linux stats the
 * device before it opens it and reports a missing one as a setup failure.
 */
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "util/khash.h"
#include "namespace.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/loop.h"

#define LOOP_MAX 8

bool loop_backing(const char *path, char *out, size_t outsz);

struct loop_dev {
  int32_t  bound;                    /* 0 when free */
  uint64_t offset, sizelimit;
  uint32_t flags;
  char     host[PATH_MAX];           /* what to mount */
  char     guest[PATH_MAX];          /* what the guest called it */
};

struct loop_file {
  struct loop_dev dev[LOOP_MAX];
};

static void
loop_path(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-loop-%s", tmp && *tmp ? tmp : "/tmp",
           nabi_boot_tag());
}

static int
loop_table_open(bool lock)
{
  char path[PATH_MAX];
  loop_path(path, sizeof path);
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return -1;
  if (lock && flock(fd, LOCK_EX) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool
loop_read(int fd, struct loop_file *f)
{
  ssize_t n = pread(fd, f, sizeof *f, 0);
  if (n == (ssize_t) sizeof *f)
    return true;
  memset(f, 0, sizeof *f);       /* a table that does not exist yet is empty */
  return n >= 0;
}

/* ------------------------------------------------------------------------
 * Which path is which device.
 * ------------------------------------------------------------------------ */

/*
 * -1 for /dev/loop-control, 0..LOOP_MAX-1 for /dev/loopN, and false for
 * anything else.
 */
bool
loop_path_index(const char *path, int *idx)
{
  if (strcmp(path, "/dev/loop-control") == 0) {
    *idx = -1;
    return true;
  }
  if (strncmp(path, "/dev/loop", 9) != 0)
    return false;
  const char *p = path + 9;
  if (*p < '0' || *p > '9')
    return false;
  int n = 0;
  for (; *p >= '0' && *p <= '9'; p++)
    n = n * 10 + (*p - '0');
  if (*p != '\0' || n >= LOOP_MAX)
    return false;
  *idx = n;
  return true;
}

/*
 * What stat should say. The numbers are Linux's, because something comparing
 * st_rdev against makedev(7, n) is asking whether this is a loop device.
 */
bool
loop_stat(const char *path, uint32_t *mode, uint64_t *rdev, uint64_t *ino)
{
  int idx;
  if (!loop_path_index(path, &idx))
    return false;
  /* S_IFCHR and S_IFBLK are the same numbers on both systems, so the host's
   * are the guest's. */
  if (idx < 0) {
    *mode = S_IFCHR | 0600;
    *rdev = ((uint64_t) LINUX_LOOP_CTL_MAJOR << 8) | LINUX_LOOP_CTL_MINOR;
    *ino = 1000;
  } else {
    *mode = S_IFBLK | 0660;
    *rdev = ((uint64_t) LINUX_LOOP_MAJOR << 8) | (uint64_t) idx;
    *ino = 1001 + (uint64_t) idx;
  }
  return true;
}

/* ------------------------------------------------------------------------
 * The descriptors.
 * ------------------------------------------------------------------------ */

KHASH_MAP_INIT_INT(loopfd, int)      /* guest fd -> device index, -1 control */
static khash_t(loopfd) *loopfds;

static bool
loop_fd_index(int fd, int *idx)
{
  if (loopfds == NULL)
    return false;
  khiter_t k = kh_get(loopfd, loopfds, fd);
  if (k == kh_end(loopfds))
    return false;
  *idx = kh_value(loopfds, k);
  return true;
}

bool
loop_is(int fd)
{
  int idx;
  return loop_fd_index(fd, &idx);
}

void
loop_close(int fd)
{
  if (loopfds == NULL)
    return;
  khiter_t k = kh_get(loopfd, loopfds, fd);
  if (k != kh_end(loopfds))
    kh_del(loopfd, loopfds, k);
}

/*
 * Open one. The descriptor has to be real - the guest holds it, closes it, and
 * may have it survive an exec - but there is nothing for it to refer to, so it
 * refers to /dev/null and the table says what it means.
 */
int
loop_open(const char *path, int *out_fd)
{
  int idx;
  if (!loop_path_index(path, &idx))
    return -1;

  /*
   * A device already bound is opened on the file behind it, so it reads as the
   * device it is standing in for. One not yet bound has nothing to read, and
   * /dev/null is what an unbound loop device behaves like: empty.
   */
  char backing[PATH_MAX];
  int fd;
  if (idx >= 0 && loop_backing(path, backing, sizeof backing))
    fd = open(backing, O_RDONLY | O_CLOEXEC);
  else
    fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    return -1;

  if (loopfds == NULL)
    loopfds = kh_init(loopfd);
  int ret;
  khiter_t k = kh_put(loopfd, loopfds, fd, &ret);
  kh_value(loopfds, k) = idx;
  *out_fd = fd;
  return 0;
}

/* ------------------------------------------------------------------------
 * The ioctls.
 * ------------------------------------------------------------------------ */

/*
 * Bind a device to whatever a descriptor names.
 *
 * `loop_fd` is the descriptor the guest holds the device open on, and it is
 * re-pointed at the backing file here. That is not a trick: reading a loop
 * device *is* reading the file behind it, and something has to be there to
 * read. util-linux probes the device the moment it is bound - blkid identifies
 * the filesystem before mount will touch it - and against a descriptor with
 * nothing behind it that probe read zero bytes forever without ever finishing.
 */
static int
bind_fd(int loop_fd, int idx, int backing_fd)
{
  char host[PATH_MAX];
  if (fcntl(backing_fd, F_GETPATH, host) != 0)
    return -LINUX_EBADF;

  struct stat st;
  if (fstat(backing_fd, &st) < 0 || !S_ISREG(st.st_mode))
    return -LINUX_EINVAL;

  int fd = loop_table_open(true);
  if (fd < 0)
    return -LINUX_ENOENT;
  struct loop_file f;
  int r = -LINUX_EBUSY;
  if (loop_read(fd, &f)) {
    if (!f.dev[idx].bound) {
      memset(&f.dev[idx], 0, sizeof f.dev[idx]);
      f.dev[idx].bound = 1;
      snprintf(f.dev[idx].host, sizeof f.dev[idx].host, "%s", host);
      pwrite(fd, &f, sizeof f, 0);
      r = 0;
    }
  }
  flock(fd, LOCK_UN);
  close(fd);

  if (r == 0) {
    int real = open(host, O_RDONLY);
    if (real < 0)
      return -darwin_to_linux_errno(errno);
    /* In place, so the descriptor the guest already has starts reading the
     * file. Its number does not change and the table still knows what it is. */
    if (dup2(real, loop_fd) < 0) {
      int e = errno;
      close(real);
      return -darwin_to_linux_errno(e);
    }
    close(real);
  }
  return r;
}

static int
clear_fd(int idx)
{
  int fd = loop_table_open(true);
  if (fd < 0)
    return -LINUX_ENOENT;
  struct loop_file f;
  int r = -LINUX_ENXIO;
  if (loop_read(fd, &f) && f.dev[idx].bound) {
    memset(&f.dev[idx], 0, sizeof f.dev[idx]);
    pwrite(fd, &f, sizeof f, 0);
    r = 0;
  }
  flock(fd, LOCK_UN);
  close(fd);
  return r;
}

int
loop_ioctl(int fd, int cmd, uint64_t arg)
{
  int idx;
  if (!loop_fd_index(fd, &idx))
    return -LINUX_ENOTTY;

  /* The control device hands out numbers; it has no device of its own. */
  if (idx < 0) {
    switch (cmd) {
    case LINUX_LOOP_CTL_GET_FREE: {
      int tfd = loop_table_open(true);
      if (tfd < 0)
        return -LINUX_ENOENT;
      struct loop_file f;
      int found = -LINUX_ENOSPC;
      if (loop_read(tfd, &f)) {
        for (int i = 0; i < LOOP_MAX; i++)
          if (!f.dev[i].bound) { found = i; break; }
      }
      flock(tfd, LOCK_UN);
      close(tfd);
      return found;
    }
    case LINUX_LOOP_CTL_ADD:
      /* The devices all exist already; adding one is asking for a number. */
      return (int) arg < LOOP_MAX ? (int) arg : -LINUX_ENOSPC;
    case LINUX_LOOP_CTL_REMOVE:
      return 0;
    default:
      return -LINUX_ENOTTY;
    }
  }

  switch (cmd) {
  case LINUX_LOOP_SET_FD:
    return bind_fd(fd, idx, (int) arg);

  case LINUX_LOOP_CLR_FD:
    return clear_fd(idx);

  case LINUX_LOOP_CONFIGURE: {
    struct l_loop_config cfg;
    if (copy_from_user(&cfg, (gaddr_t) arg, sizeof cfg))
      return -LINUX_EFAULT;
    int r = bind_fd(fd, idx, (int) cfg.fd);
    if (r < 0)
      return r;
    /* The rest of the configuration is recorded so GET_STATUS64 can report it
     * back; nothing here acts on an offset, because nothing here reads the
     * device - the file is mounted whole. A caller that asked for one is told
     * so rather than silently given the whole file. */
    if (cfg.info.lo_offset != 0 || cfg.info.lo_sizelimit != 0) {
      clear_fd(idx);
      return -LINUX_EINVAL;
    }
    return 0;
  }

  case LINUX_LOOP_SET_STATUS:
  case LINUX_LOOP_SET_STATUS64: {
    struct l_loop_info64 info;
    if (cmd == LINUX_LOOP_SET_STATUS64) {
      if (copy_from_user(&info, (gaddr_t) arg, sizeof info))
        return -LINUX_EFAULT;
      if (info.lo_offset != 0 || info.lo_sizelimit != 0)
        return -LINUX_EINVAL;   /* see LOOP_CONFIGURE */
    }
    return 0;
  }

  case LINUX_LOOP_GET_STATUS64: {
    int tfd = loop_table_open(false);
    if (tfd < 0)
      return -LINUX_ENXIO;
    struct loop_file f;
    bool ok = loop_read(tfd, &f);
    close(tfd);
    if (!ok || !f.dev[idx].bound)
      return -LINUX_ENXIO;

    struct l_loop_info64 info;
    memset(&info, 0, sizeof info);
    info.lo_number = (uint32_t) idx;
    info.lo_flags = LINUX_LO_FLAGS_READ_ONLY;
    info.lo_rdevice = ((uint64_t) LINUX_LOOP_MAJOR << 8) | (uint64_t) idx;
    snprintf((char *) info.lo_file_name, sizeof info.lo_file_name, "%s",
             f.dev[idx].guest[0] ? f.dev[idx].guest : f.dev[idx].host);
    if (copy_to_user((gaddr_t) arg, &info, sizeof info))
      return -LINUX_EFAULT;
    return 0;
  }

  /*
   * Accepted and unacted on, which is what they amount to when nothing reads
   * the device: capacity is the file's, there is no I/O to make direct, and a
   * block size describes reads that do not happen. Refusing them would fail a
   * setup that is otherwise fine.
   */
  case LINUX_LOOP_SET_CAPACITY:
  case LINUX_LOOP_SET_DIRECT_IO:
  case LINUX_LOOP_SET_BLOCK_SIZE:
    return 0;

  case LINUX_LOOP_GET_STATUS:
  case LINUX_LOOP_CHANGE_FD:
    return -LINUX_ENOTTY;

  default:
    return -LINUX_ENOTTY;
  }
}

/*
 * What a loop device is backed by, for mount to use. The path is the host's,
 * recorded when the device was bound.
 */
bool
loop_backing(const char *path, char *out, size_t outsz)
{
  int idx;
  if (!loop_path_index(path, &idx) || idx < 0)
    return false;

  int fd = loop_table_open(false);
  if (fd < 0)
    return false;
  struct loop_file f;
  bool ok = loop_read(fd, &f);
  close(fd);
  if (!ok || !f.dev[idx].bound)
    return false;
  snprintf(out, outsz, "%s", f.dev[idx].host);
  return true;
}
