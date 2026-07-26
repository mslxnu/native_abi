/*-
 * Copyright (c) 2016 Yuichi Nishiwaki and Takaya Saeki
 * Copyright (c) 1994-1995 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "noah.h"
#include "checkpoint.h"

#include "linux/common.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/ioctl.h"
#include "linux/termios.h"
#include "linux/socket.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/syslimits.h>
#include <dirent.h>
#include <termios.h>
#include <sys/ioctl.h>

#include <mach-o/dyld.h>

struct file {
  struct file_operations *ops;
  int fd;
};

struct file_operations {
  int (*readv)(struct file *f, struct iovec *iov, size_t iovcnt);
  int (*writev)(struct file *f, const struct iovec *iov, size_t iovcnt);
  int (*close)(struct file *f);
  int (*ioctl)(struct file *f, int cmd, uint64_t val0);
  int (*lseek)(struct file *f, l_off_t offset, int whence);
  int (*getdents)(struct file *f, char *buf, uint count, bool is64);
  int (*fcntl)(struct file *f, unsigned int cmd, unsigned long arg);
  int (*fsync)(struct file *f);
  /* inode operations */
  int (*fstat)(struct file *f, struct l_newstat *stat);
  int (*fstatfs)(struct file *f, struct l_statfs *buf);
  int (*fchown)(struct file *f, l_uid_t uid, l_gid_t gid);
  int (*fchmod)(struct file *f, l_mode_t mode);
};

static inline bool in_userfd(int fd);
static const int user_fdtable_initsize = 64;
static const int vkern_fdtable_maxsize = 64;
static const int fdtable_alloc_unit = 64; // must be a multiple of 64

static inline void set_fdbit(struct fdtable *table, uint64_t *fdbits, int fd);
static inline void clear_fdbit(struct fdtable *table, uint64_t *fdbits, int fd);

static inline int div_ceil(int x, int y) { return (x + y - 1) / y; }

int
alloc_fdtable(struct fdtable *fdtable, int newsize)
{
  newsize = div_ceil(newsize, fdtable_alloc_unit) * fdtable_alloc_unit;
  int oldsize = fdtable->size;
  if (newsize <= oldsize)
    return 0;

  int newunit = newsize / fdtable_alloc_unit;
  int oldunit = oldsize / fdtable_alloc_unit;
  fdtable->files = realloc(fdtable->files, sizeof(struct file *) * newunit);
  if (fdtable->files == NULL)
    return -LINUX_ENOMEM;
  for (int i = oldunit; i < newunit; i++) {
    fdtable->files[i] = calloc(fdtable_alloc_unit, sizeof(struct file));
    if (fdtable->files[i] == NULL)
      return -LINUX_ENOMEM;
  }

  int newfdslen = newsize / 8;
  fdtable->open_fds = realloc(fdtable->open_fds, newfdslen);
  if (fdtable->open_fds == NULL)
      return -LINUX_ENOMEM;
  fdtable->cloexec_fds = realloc(fdtable->cloexec_fds, newfdslen);
  if (fdtable->cloexec_fds == NULL)
      return -LINUX_ENOMEM;

  int offset = oldsize / 8;
  int size = newfdslen - offset;

  bzero(fdtable->open_fds + oldunit, size);
  bzero(fdtable->cloexec_fds + oldunit, size);

  fdtable->size = newsize;
  return 0;
}

void
init_fileinfo(int rootfd)
{
  struct rlimit limit;
  struct fileinfo *fileinfo = &proc.fileinfo;

  getrlimit(RLIMIT_NOFILE, &limit);
  fileinfo->vkern_fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fileinfo->vkern_fdtable.start = limit.rlim_cur - vkern_fdtable_maxsize;
  alloc_fdtable(&fileinfo->vkern_fdtable, vkern_fdtable_maxsize);
  fileinfo->fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  alloc_fdtable(&fileinfo->fdtable, user_fdtable_initsize);

  for (int i = 0; i < (int) limit.rlim_cur; i++) {
    if (i == rootfd) {
      continue;
    }
    int flag = fcntl(i, F_GETFD);
    if (flag < 0) {
      continue;
    }
    if (in_userfd(i)) {
      register_fd(i, flag & FD_CLOEXEC);
    } else {
      warnk("closing a file whose fd overlaps with vkern_fdtable, fd: %d\n", i);
      fprintf(stderr, "NABI uses high file descriptor numbers as the system file descriptors. fd[%d] is closed because it overlaps with the system area.\n", i);
      close(i);
    }
  }
  fileinfo->rootfd = vkern_dup_fd(rootfd, false);
}

void
darwin_to_linux_rlimit_nofile(struct rlimit *darwin_rlimit, struct l_rlimit *linux_rlimit)
{
  linux_rlimit->rlim_cur = darwin_rlimit->rlim_cur;
  linux_rlimit->rlim_max = darwin_rlimit->rlim_max - vkern_fdtable_maxsize;
}

int
darwinfs_writev(struct file *file, const struct iovec *iov, size_t iovcnt)
{
  return syswrap(writev(file->fd, iov, iovcnt));
}

int
darwinfs_readv(struct file *file, struct iovec *iov, size_t iovcnt)
{
  return syswrap(readv(file->fd, iov, iovcnt));
}

int
darwinfs_close(struct file *file)
{
  return syswrap(close(file->fd));
}

int
darwinfs_ioctl(struct file *file, int cmd, uint64_t val0)
{
  uint64_t sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
  int fd = file->fd;
  int r;

  switch (cmd) {
  case LINUX_TCGETS: {
    struct termios dios;
    struct linux_termios lios;

    if ((r = syswrap(tcgetattr(fd, &dios))) < 0) {
      return r;
    }
    darwin_to_linux_termios(&dios, &lios);
    if (copy_to_user(val0, &lios, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TCSETS: {
    struct termios dios;
    struct linux_termios lios;
    if (copy_from_user(&lios, val0, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_termios(&lios, &dios);
    return syswrap(tcsetattr(fd, TCSANOW, &dios));
  }
  case LINUX_TCSETSW: {
    struct termios dios;
    struct linux_termios lios;
    if (copy_from_user(&lios, val0, sizeof lios)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_termios(&lios, &dios);
    return syswrap(tcsetattr(fd, TCSADRAIN, &dios));
  }
  case LINUX_TIOCGPGRP: {
    l_pid_t pgrp;
    if ((r = syswrap(ioctl(fd, TIOCGPGRP, &pgrp))) < 0) {
      return r;
    }
    if (copy_to_user(val0, &pgrp, sizeof pgrp)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TIOCSPGRP: {
    l_pid_t pgrp;
    if (copy_from_user(&pgrp, val0, sizeof pgrp)) {
      return -LINUX_EFAULT;
    }
    if ((r = syswrap(ioctl(fd, TIOCSPGRP, &pgrp))) < 0) {
      return r;
    }
    return 0;
  }
  case LINUX_TIOCGWINSZ: {
    struct winsize ws;
    if ((r = syswrap(ioctl(fd, TIOCGWINSZ, &ws))) < 0) {
      return r;
    }
    struct linux_winsize lws;
    darwin_to_linux_winsize(&ws, &lws);
    if (copy_to_user(val0, &lws, sizeof lws)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_TIOCSWINSZ: {
    struct linux_winsize lws;
    struct winsize ws;
    if (copy_from_user(&lws, val0, sizeof lws)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_winsize(&ws, &lws);
    return syswrap(ioctl(fd, TIOCSWINSZ, &ws));
  }
  case LINUX_TCXONC: {
    int sel;
    switch(val0) {
    case LINUX_TCOOFF: sel = TCOOFF; break;
    case LINUX_TCOON: sel = TCOON; break;
    case LINUX_TCIOFF: sel = TCIOFF; break;
    case LINUX_TCION: sel = TCION; break;
    default:
      return -LINUX_EINVAL;
    }
    return syswrap(tcflow(fd, sel));
  }
  case LINUX_TCFLSH: {
    int sel;
    switch (val0) {
    case LINUX_TCIFLUSH: sel = TCIFLUSH; break;
    case LINUX_TCOFLUSH: sel = TCOFLUSH; break;
    case LINUX_TCIOFLUSH: sel = TCIOFLUSH; break;
    default:
      return -LINUX_EINVAL;
    }
    return syswrap(tcflush(fd, sel));
  }
  case LINUX_FIONREAD: {
    int val;
    int r = syswrap(ioctl(fd, FIONREAD, &val));
    if (r < 0) {
      return r;
    }
    if (copy_to_user(val0, &val, sizeof val)) {
      return -LINUX_EFAULT;
    }
    return r;
  }
  case LINUX_FIONBIO: {
    int val;
    if (copy_from_user(&val, val0, sizeof val)) {
      return -LINUX_EFAULT;
    }
    return syswrap(ioctl(fd, FIONBIO, &val));
  }
  case LINUX_FIOCLEX: {
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    int r = sys_fcntl(fd, LINUX_F_SETFD, 1);
    if (r >= 0) {
      set_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, fd);
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  }
  default:
    warnk("unhandled darwinfs ioctl (fd = %08x, cmd = 0x%08x)\n", fd, cmd);
    return -LINUX_EPERM;
  }
}

int
darwinfs_lseek(struct file *file, l_off_t offset, int whence)
{
  return syswrap(lseek(file->fd, offset, whence));
}

ssize_t
darwin_to_linux_dent(struct dirent *d_dent, void *l_dent, size_t buflen, int is64)
{
  /*
   * The name has to be counted in both cases. Without the parentheses the
   * "+ d_namlen + 2" bound to the else branch alone, so a 64-bit record was a
   * fixed roundup(offsetof(d_name), 8) = 24 bytes however long the name was -
   * room for five characters. Longer names ran past the record and the next
   * entry's d_ino overwrote their tail, so a directory listing came back with
   * some names silently mangled ("lost+found" -> "lost+@�C") and others
   * intact, depending on whether the clobbering inode happened to start with a
   * zero byte. The +2 covers the NUL and, for the 32-bit layout, the d_type
   * byte stored at reclen-1; one spare byte in the 64-bit case is free after
   * the 8-byte roundup.
   */
  unsigned reclen = roundup((is64 ? offsetof(struct l_dirent64, d_name)
                                  : offsetof(struct l_dirent, d_name))
                            + d_dent->d_namlen + 2, 8);
  if (reclen > buflen) {
    return -1;
  }
  /* fill dirent buffer */
  if (is64) {
    struct l_dirent64 *dp = (struct l_dirent64 *) l_dent;
    dp->d_reclen = reclen;
    dp->d_ino = d_dent->d_ino;
    dp->d_off = d_dent->d_seekoff;
    dp->d_type = d_dent->d_type;
    memcpy(dp->d_name, d_dent->d_name, d_dent->d_namlen + 1);
  } else {
    struct l_dirent *dp = (struct l_dirent *) l_dent;
    dp->d_reclen = reclen;
    dp->d_ino = d_dent->d_ino;
    dp->d_off = d_dent->d_seekoff;
    memcpy(dp->d_name, d_dent->d_name, d_dent->d_namlen + 1);
    ((char *) dp)[reclen - 1] = d_dent->d_type;
  }
  return reclen;
}

int
darwinfs_getdents(struct file *file, char *direntp, unsigned count, bool is64)
{
  int fd = dup(file->fd);
  DIR *dir = fdopendir(fd);
  
  if (dir == NULL) {
    return -darwin_to_linux_errno(errno);
  }
  struct dirent *dent;
  size_t pos = 0;
  long loc = telldir(dir);
  errno = 0;
  while ((dent = readdir(dir)) != NULL) {
    ssize_t reclen = darwin_to_linux_dent(dent, direntp + pos, count - pos, is64);
    if (reclen < 0) {
      seekdir(dir, loc);
      goto end;
    }
    pos += reclen;
    loc = telldir(dir);
  }
  if (errno) {
    return -darwin_to_linux_errno(errno);
  }
 end:
  closedir(dir);
  return pos;
}

void linux_to_darwin_flock(struct l_flock *linux_flock, struct flock *darwin_flock);

void darwin_to_linux_flock(struct flock *darwin_flock, struct l_flock *linux_flock);

int
darwinfs_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
  int r;
  struct l_flock lflock;
  struct flock dflock;

  switch (cmd) {
  case LINUX_F_DUPFD:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_DUPFD, arg)); /* FIXME */
    if (r >= 0) {
      int err = register_fd(r, false);
      if (err < 0) {
        close(r);
        r = err;
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  case LINUX_F_DUPFD_CLOEXEC:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_DUPFD_CLOEXEC, arg));
    if (r >= 0) {
      int err = register_fd(r, true);
      if (err < 0) {
        close(r);
        r = err;
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
    /* no translation required for fd flags (i.e. CLOEXEC==1 */
  case LINUX_F_GETFD:
    return syswrap(fcntl(file->fd, F_GETFD));
  case LINUX_F_SETFD:
    pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
    r = syswrap(fcntl(file->fd, F_SETFD, arg));
    if (r >= 0) {
      if (arg & FD_CLOEXEC) {
        set_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, file->fd);
      } else {
        clear_fdbit(&proc.fileinfo.fdtable, proc.fileinfo.fdtable.cloexec_fds, file->fd);
      }
    }
    pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
    return r;
  case LINUX_F_GETFL:
    r = syswrap(fcntl(file->fd, F_GETFL));
    if (r < 0)
      return r;
    return darwin_to_linux_o_flags(r);
  case LINUX_F_SETFL:
    return syswrap(fcntl(file->fd, F_SETFL, linux_to_darwin_o_flags(arg)));
  case LINUX_F_GETLK:
    if (copy_from_user(&lflock, arg, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_flock(&lflock, &dflock);
    r = syswrap(fcntl(file->fd, F_GETLK, &dflock));
    if (r < 0) {
      return r;
    }
    darwin_to_linux_flock(&dflock, &lflock);
    if (copy_to_user(arg, &lflock, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    return 0;
  case LINUX_F_SETLK: case LINUX_F_SETLKW:
    if (copy_from_user(&lflock, arg, sizeof lflock)) {
      return -LINUX_EFAULT;
    }
    linux_to_darwin_flock(&lflock, &dflock);
    return syswrap(fcntl(file->fd, (cmd == LINUX_F_SETLK) ? F_SETLK : F_SETLKW, &dflock));
  default:
    warnk("unknown fcntl cmd: %d\n", cmd);
    return -LINUX_EINVAL;
  }
}

int
darwinfs_fsync(struct file *file)
{
  return syswrap(fsync(file->fd));
}

int
darwinfs_fstat(struct file *file, struct l_newstat *l_st)
{
  struct stat st;
  int ret = syswrap(fstat(file->fd, &st));
  if (ret < 0) {
    return ret;
  }
  stat_darwin_to_linux(&st, l_st);
  return ret;
}

int
darwinfs_fchown(struct file *file, l_uid_t uid, l_gid_t gid)
{
  return syswrap(fchown(file->fd, uid, gid));
}

int
darwinfs_fchmod(struct file *file, l_mode_t mode)
{
  return syswrap(fchmod(file->fd, mode));
}

int
darwinfs_fstatfs(struct file *file, struct l_statfs *buf)
{
  struct statfs st;
  int r = syswrap(fstatfs(file->fd, &st));
  if (r < 0)
    return r;
  statfs_darwin_to_linux(&st, buf);
  return r;
}

static inline bool
in_userfd(int fd)
{
  return (fd >= 0 && fd < proc.fileinfo.vkern_fdtable.start);
}

static inline void
set_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  fdbits[idx_table] |= (1ULL << (idx_bit));
}

static inline void
clear_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  fdbits[idx_table] &= ~(1ULL << (idx_bit));
}

static inline bool
test_fdbit(struct fdtable *table, uint64_t *fdbits, int fd)
{
  int idx_table = (fd - table->start) / 64;
  int idx_bit = (fd - table->start) - idx_table * 64;
  return fdbits[idx_table] & (1ULL << (idx_bit));
}

static void
alloc_file(struct fdtable *table, int fd)
{
  static struct file_operations ops = {
    darwinfs_readv,
    darwinfs_writev,
    darwinfs_close,
    darwinfs_ioctl,
    darwinfs_lseek,
    darwinfs_getdents,
    darwinfs_fcntl,
    darwinfs_fsync,
    darwinfs_fstat,
    darwinfs_fstatfs,
    darwinfs_fchown,
    darwinfs_fchmod,
  };

  int offset = fd - table->start;
  struct file *file = &table->files[offset / fdtable_alloc_unit][offset % fdtable_alloc_unit];
  file->ops = &ops;
  file->fd = fd;
}

/*
 * The caller of register_fd and vkern_dup_fd must acquire the lock properly if necessary
 */

int
register_fd(int fd, bool is_cloexec)
{
  if (fd >= proc.fileinfo.vkern_fdtable.start) {
    // Relocation of vkern_fdtable is not implemented currently
    return -LINUX_EMFILE;
  }
  struct fdtable *fdtable = &proc.fileinfo.fdtable;
  if (proc.fileinfo.fdtable.size <= fd) {
    int err = alloc_fdtable(fdtable, fd + 1);
    if (err < 0)
      return err;
  }
  set_fdbit(fdtable, fdtable->open_fds, fd);
  if (is_cloexec) {
    set_fdbit(fdtable, fdtable->cloexec_fds, fd);
  } else {
    clear_fdbit(fdtable, fdtable->cloexec_fds, fd);
  }
  alloc_file(fdtable, fd);
  return 0;
}

static inline int
find_emptyfd(struct fdtable *table)
{
  for (int i = 0; i < table->size / 64; i++) {
    int ret = ffs(~table->open_fds[i]);
    if (ret > 0) {
      return table->start + ret - 1 + i * 64;
    }
  }
  return -1;
}

int
vkern_dup_fd(int fd, bool is_cloexec)
{
  int vkern_fd = find_emptyfd(&proc.fileinfo.vkern_fdtable);
  if (vkern_fd == -1) {
    panic("Too many files opened in the kernel space");
  }
  dup2(fd, vkern_fd);
  set_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.open_fds, vkern_fd);
  if (is_cloexec) {
    set_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.cloexec_fds, vkern_fd);
  } else {
    clear_fdbit(&proc.fileinfo.vkern_fdtable, proc.fileinfo.vkern_fdtable.cloexec_fds, vkern_fd);
  }
  alloc_file(&proc.fileinfo.vkern_fdtable, vkern_fd);
  return vkern_fd;
}

struct file *
do_get_file(struct fdtable *table, int fd)
{
  if (!test_fdbit(table, table->open_fds, fd)) {
    return NULL;
  }
  int offset = fd - table->start;
  return &table->files[offset / fdtable_alloc_unit][offset % fdtable_alloc_unit];
}

struct file *
get_file(int fd)
{
  struct file *ret = NULL;
  struct fdtable *table = &proc.fileinfo.fdtable;
  pthread_rwlock_rdlock(&proc.fileinfo.fdtable_lock);
  if (fd < 0 || fd >= table->size) {
    goto out;
  }
  ret = do_get_file(table, fd);

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(write, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);
  if (copy_from_user(buf, buf_ptr, size)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->writev == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  struct iovec iov = { buf, size };
  r =  file->ops->writev(file, &iov, 1);
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(read, int, fd, gaddr_t, buf_ptr, size_t, size)
{
  int r;
  char *buf = malloc(size);
  struct file *file = get_file(fd);
  if (file == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  if (file->ops->readv == NULL) {
    r = -LINUX_EBADF;
    goto out;
  }
  struct iovec iov = { buf, size };
  r = file->ops->readv(file, &iov, 1);
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, r)) {
    r = -LINUX_EFAULT;
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(writev, int, fd, gaddr_t, iov_ptr, int, iovcnt)
{
  struct l_iovec *liov = alloca(sizeof(struct l_iovec) * iovcnt);

  if (copy_from_user(liov, iov_ptr, sizeof(struct l_iovec) * iovcnt))
    return -LINUX_EFAULT;

  struct iovec *iov = alloca(sizeof(struct iovec) * iovcnt);
  for (int i = 0; i < iovcnt; ++i) {
    iov[i].iov_len = liov[i].iov_len;
    iov[i].iov_base = alloca(liov[i].iov_len);
    if (copy_from_user(iov[i].iov_base, liov[i].iov_base, iov[i].iov_len))
      return -LINUX_EFAULT;
  }

  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->writev == NULL) {
    return -LINUX_EBADF;
  }
  return file->ops->writev(file, iov, iovcnt);
}

DEFINE_SYSCALL(readv, int, fd, gaddr_t, iov_ptr, int, iovcnt)
{
  struct l_iovec *liov = alloca(sizeof(struct l_iovec) * iovcnt);

  if (copy_from_user(liov, iov_ptr, sizeof(struct l_iovec) * iovcnt))
    return -LINUX_EFAULT;

  struct iovec *iov = alloca(sizeof(struct iovec) * iovcnt);
  for (int i = 0; i < iovcnt; ++i) {
    iov[i].iov_base = alloca(liov[i].iov_len);
    iov[i].iov_len = liov[i].iov_len;
  }

  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->readv == NULL) {
    return -LINUX_EBADF;
  }
  int r = file->ops->readv(file, iov, iovcnt);
  if (r < 0) {
    return r;
  }
  size_t size = r;
  for (int i = 0; i < iovcnt; ++i) {
    size_t s = MIN(size, iov[i].iov_len);
    if (copy_to_user(liov[i].iov_base, iov[i].iov_base, s)) {
      return -LINUX_EFAULT;
    }
    size -= s;
    if (size == 0)
      break;
  }
  return r;
}

DEFINE_SYSCALL(fstat, int, fd, gaddr_t, st_ptr)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  struct l_newstat st;
  int n = file->ops->fstat(file, &st);
  if (n < 0)
    return n;
  if (copy_to_user(st_ptr, &st, sizeof st)) {
    return -LINUX_EFAULT;
  }
  return n;
}

DEFINE_SYSCALL(fchown, int, fd, l_uid_t, uid, l_gid_t, gid)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fchown(file, uid, gid);
}

DEFINE_SYSCALL(fchmod, int, fd, l_mode_t, mode)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fchmod(file, mode);
}

DEFINE_SYSCALL(ioctl, int, fd, int, cmd, uint64_t, val0)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  if (file->ops->ioctl == NULL) {
    return -LINUX_ENOTTY;
  }
  return file->ops->ioctl(file, cmd, val0);
}

DEFINE_SYSCALL(lseek, int, fd, off_t, offset, int, whence)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->lseek(file, offset, whence);
}

DEFINE_SYSCALL(getdents64, unsigned int, fd, gaddr_t, dirent_ptr, unsigned int, count)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  char *buf = malloc(count);
  int r = file->ops->getdents(file, buf, count, true);
  if (r < 0) {
    goto out;
  }
  /* Only the r bytes actually filled: copying the whole buffer would hand the
   * guest whatever was in the uninitialized tail of a host malloc. */
  if (copy_to_user(dirent_ptr, buf, r)) {
    r = -LINUX_EFAULT;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(getdents, unsigned int, fd, gaddr_t, dirent_ptr, unsigned int, count)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  char *buf = malloc(count);
  int r = file->ops->getdents(file, buf, count, false);
  if (r < 0) {
    goto out;
  }
  /* See getdents64: only the bytes actually filled. */
  if (copy_to_user(dirent_ptr, buf, r)) {
    r = -LINUX_EFAULT;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fcntl(file, cmd, arg);
}

DEFINE_SYSCALL(fstatfs, int, fd, gaddr_t, buf_ptr)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  struct l_statfs st;
  int n = file->ops->fstatfs(file, &st);
  if (n < 0)
    return n;
  if (copy_to_user(buf_ptr, &st, sizeof st)) {
    return -LINUX_EFAULT;
  }
  return n;
}

DEFINE_SYSCALL(fsync, int, fd)
{
  struct file *file = get_file(fd);
  if (file == NULL)
    return -LINUX_EBADF;
  return file->ops->fsync(file);
}

struct dir {
  int fd;
};

struct path {
  struct fs *fs;
  struct dir *dir;
  char subpath[LINUX_PATH_MAX];
};

struct fs {
  struct fs_operations *ops;
};

struct fs_operations {
  int (*openat)(struct fs *fs, struct dir *dir, const char *path, int flags, int mode); /* TODO: return struct file * instaed of file descripter */
  int (*symlinkat)(struct fs *fs, const char *target, struct dir *dir, const char *name);
  int (*faccessat)(struct fs *fs, struct dir *dir, const char *path, int mode);
  int (*renameat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to);
  int (*linkat)(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to, int flags);
  int (*unlinkat)(struct fs *fs, struct dir *dir, const char *path, int flags);
  int (*readlinkat)(struct fs *fs, struct dir *dir, const char *path, char *buf, int bufsize);
  int (*mkdirat)(struct fs *fs, struct dir *dir, const char *path, int mode);
  /* inode operations */
  int (*fstatat)(struct fs *fs, struct dir *dir, const char *path, struct l_newstat *stat, int flags);
  int (*statfs)(struct fs *fs, struct dir *dir, const char *path, struct l_statfs *buf);
  int (*fchownat)(struct fs *fs, struct dir *dir, const char *path, l_uid_t uid, l_gid_t gid, int flags);
  int (*fchmodat)(struct fs *fs, struct dir *dir, const char *path, l_mode_t mode);
};

int
darwinfs_openat(struct fs *fs, struct dir *dir, const char *path, int l_flags, int mode)
{
  int flags = linux_to_darwin_o_flags(l_flags);
  return syswrap(openat(dir->fd, path, flags, mode));
}

int
darwinfs_symlinkat(struct fs *fs, const char *target, struct dir *dir, const char *name)
{
  return syswrap(symlinkat(target, dir->fd, name));
}

int
darwinfs_faccessat(struct fs *fs, struct dir *dir, const char *path, int mode)
{
  return syswrap(faccessat(dir->fd, path, mode, 0));
}

int
darwinfs_renameat(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to)
{
  return syswrap(renameat(dir1->fd, from, dir2->fd, to));
}

int
darwinfs_linkat(struct fs *fs, struct dir *dir1, const char *from, struct dir *dir2, const char *to, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  return syswrap(linkat(dir1->fd, from, dir2->fd, to, flags));
}

int
darwinfs_unlinkat(struct fs *fs, struct dir *dir, const char *path, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  /* You must treat E_ACCESS as E_REMOVEDIR in unlinkat */
  if (flags & AT_EACCESS) {
    flags &= ~AT_EACCESS;
    flags |= AT_REMOVEDIR;
  }
  return syswrap(unlinkat(dir->fd, path, flags));
}

int
darwinfs_readlinkat(struct fs *fs, struct dir *dir, const char *path, char *buf, int bufsize)
{
  return syswrap(readlinkat(dir->fd, path, buf, bufsize));
}

int
darwinfs_mkdirat(struct fs *fs, struct dir *dir, const char *path, int mode)
{
  return syswrap(mkdirat(dir->fd, path, mode));
}

int
darwinfs_fstatat(struct fs *fs, struct dir *dir, const char *path, struct l_newstat *l_st, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  struct stat st;
  int ret = syswrap(fstatat(dir->fd, path, &st, flags));
  if (ret < 0) {
    return ret;
  }
  stat_darwin_to_linux(&st, l_st);
  return ret;
}

int
darwinfs_statfs(struct fs *fs, struct dir *dir, const char *path, struct l_statfs *buf)
{
  char full_path[LINUX_PATH_MAX];
  const char *path_to_statfs;

  if (dir->fd != AT_FDCWD) {
    path_to_statfs = full_path;
    char at_path[PATH_MAX];
    // fd must be a regular directory to which fcntl should succeed
    int r = fcntl(dir->fd, F_GETPATH, at_path);
    if (r != 0) {
      panic("fcntl failed");
    }
    if (snprintf(full_path, PATH_MAX, "%s/%s", at_path, path) >= PATH_MAX) {
      return -LINUX_ENAMETOOLONG;
    }
  } else {
    path_to_statfs = path;
  }

  struct statfs st;
  int r = syswrap(statfs(path_to_statfs, &st));
  if (r < 0)
    return r;
  statfs_darwin_to_linux(&st, buf);
  return r;
}

int
darwinfs_fchownat(struct fs *fs, struct dir *dir, const char *path, l_uid_t uid, l_gid_t gid, int l_flags)
{
  int flags = linux_to_darwin_at_flags(l_flags);
  return syswrap(fchownat(dir->fd, path, uid, gid, flags));
}

int
darwinfs_fchmodat(struct fs *fs, struct dir *dir, const char *path, l_mode_t mode)
{
  return syswrap(fchmodat(dir->fd, path, mode, 0));
}

#define LOOKUP_NOFOLLOW   0x0001
#define LOOKUP_DIRECTORY  0x0002
/* #define LOOKUP_CONTINUE   0x0004 */
/* #define LOOKUP_AUTOMOUNT  0x0008 */
/* #define LOOKUP_PARENT     0x0010 */
/* #define LOOKUP_REVAL      0x0020 */

#define LOOP_MAX 20

int
resolve_path(const struct dir *parent, const char *name, int flags, struct path *path, int loop)
{
  static struct fs_operations ops = {
    darwinfs_openat,
    darwinfs_symlinkat,
    darwinfs_faccessat,
    darwinfs_renameat,
    darwinfs_linkat,
    darwinfs_unlinkat,
    darwinfs_readlinkat,
    darwinfs_mkdirat,
    darwinfs_fstatat,
    darwinfs_statfs,
    darwinfs_fchownat,
    darwinfs_fchmodat,
  };
  static struct fs darwinfs = {
    .ops = &ops,
  };
  struct fs *fs = &darwinfs;

  if (loop > LOOP_MAX)
    return -LINUX_ELOOP;

  struct dir dir = *parent;

  /* resolve mountpoints */
  if (*name == '/') {
    if (name[1] == '\0') {
      dir.fd = proc.fileinfo.rootfd;
      strcpy(path->subpath, ".");
      goto out;
    }
    if (strncmp(name, "/Users", sizeof "/Users" - 1) && strncmp(name, "/Volumes", sizeof "/Volumes" - 1) && strncmp(name, "/dev", sizeof "/dev" - 1) && strncmp(name, "/tmp", sizeof "/tmp" - 1) && strncmp(name, "/private", sizeof "/private" - 1)) {
      dir.fd = proc.fileinfo.rootfd;
      name++;
    }
  }

  /* resolve symlinks */
  char *sp = path->subpath;
  *sp = 0;
  const char *c = name;
  assert(*c);
  while (*c) {
    while (*c && *c != '/') {
      *sp++ = *c++;
    }
    *sp = 0;
    if ((flags & LOOKUP_NOFOLLOW) == 0) {
      char buf[LINUX_PATH_MAX];
      int n;
      if ((n = fs->ops->readlinkat(fs, &dir, path->subpath, buf, sizeof buf)) > 0) {
        strcpy(buf + n, c);
        if (buf[0] == '/') {
          return resolve_path(&dir, buf, flags, path, loop + 1);
        } else {
          /* remove the last component */
          while (sp >= path->subpath && *--sp != '/')
            ;
          *++sp = 0;
          char buf2[LINUX_PATH_MAX];
          strcpy(buf2, path->subpath);
          strcat(buf2, buf);
          return resolve_path(&dir, buf2, flags, path, loop + 1);
        }
      }
    }
    if (*c) {
      *sp++ = *c++;
    }
    *sp = 0;
  }

 out:
  path->fs = fs;
  path->dir = malloc(sizeof(struct dir));
  path->dir->fd = dir.fd;
  return 0;
}

int
vfs_grab_dir(int dirfd, const char *name, int flags, struct path *path)
{
  struct dir dir;

  if (flags & ~(LOOKUP_NOFOLLOW | LOOKUP_DIRECTORY)) {
    return -LINUX_EINVAL;
  }

  if (*name == 0) {
    return -LINUX_ENOENT;
  }

  if (dirfd == LINUX_AT_FDCWD) {
    dir.fd = AT_FDCWD;
  } else {
    dir.fd = dirfd;
    if (!in_userfd(dir.fd)) {
      return -LINUX_EBADF;
    }
  }
  return resolve_path(&dir, name, flags, path, 0);
}

void
vfs_ungrab_dir(struct path *path)
{
  free(path->dir);
}

static int
do_openat(int dirfd, const char *name, int flags, int mode)
{
  int lkflag = 0;
  if (flags & LINUX_O_NOFOLLOW) {
    lkflag |= LOOKUP_NOFOLLOW;
  }
  if (flags & LINUX_O_DIRECTORY) {
    lkflag |= LOOKUP_DIRECTORY;
  }

  struct path path;
  int r = vfs_grab_dir(dirfd, name, lkflag, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->openat(path.fs, path.dir, path.subpath, flags, mode);
  vfs_ungrab_dir(&path);
  return r;
}

int
vkern_openat(int atdirfd, const char *name, int flags, int mode)
{
  int ret;

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd = do_openat(atdirfd, name, flags, mode);
  if (fd < 0) {
    ret = fd;
    goto out;
  }
  ret = vkern_dup_fd(fd, flags & LINUX_O_CLOEXEC);
  close(fd);

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

int
vkern_open(const char *path, int l_flags, int mode)
{
  return vkern_openat(LINUX_AT_FDCWD, path, l_flags, mode);
}

int
user_openat(int atdirfd, const char *name, int flags, int mode)
{
  int fd;
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  fd = do_openat(atdirfd, name, flags, mode);
  if (fd < 0) {
    goto out;
  }
  int err = register_fd(fd, flags & LINUX_O_CLOEXEC);
  if (err < 0) {
    fd = err;
    close(fd);
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return fd;
}

int
user_open(const char *path, int l_flags, int mode)
{
  return user_openat(LINUX_AT_FDCWD, path, l_flags, mode);
}

int
do_close(struct fdtable *table, int fd)
{
  if (fd < table->start || fd >= table->start + table->size) {
    return -LINUX_EBADF;
  }
  if (!test_fdbit(table, table->open_fds, fd)) {
    return -LINUX_EBADF;
  }
  struct file *file = do_get_file(table, fd);
  if (file == NULL)
    return -LINUX_EBADF;
  int n = file->ops->close(file);
  clear_fdbit(table, table->open_fds, fd);
  clear_fdbit(table, table->cloexec_fds, fd);
  return n;
}

int
user_close(int fd)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = do_close(&proc.fileinfo.fdtable, fd);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

int
vkern_close(int fd)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int n = do_close(&proc.fileinfo.vkern_fdtable, fd);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return n;
}

void
close_cloexec()
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  struct fdtable *fdtable = &proc.fileinfo.fdtable;
  for (int i = 0; i < fdtable->size / 64; i++) {
    for (int j = 0; j < 64; j++) {
      if (fdtable->cloexec_fds[i] == 0) {
        break;
      }
      if ((fdtable->cloexec_fds[i] >> j) & 1) {
        do_close(fdtable, j + i * 64);
      }
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
}

DEFINE_SYSCALL(openat, int, dirfd, gstr_t, path_ptr, int, flags, int, mode)
{
  char path[LINUX_PATH_MAX];
  strncpy_from_user(path, path_ptr, sizeof path);
  return user_openat(dirfd, path, flags, mode);
}

DEFINE_SYSCALL(open, gstr_t, path_ptr, int, flags, int, mode)
{
  return sys_openat(LINUX_AT_FDCWD, path_ptr, flags, mode);
}

DEFINE_SYSCALL(close, int, fd)
{
  return user_close(fd);
}

DEFINE_SYSCALL(creat, gstr_t, path_ptr, int, mode)
{
  return sys_open(path_ptr, LINUX_O_CREAT | LINUX_O_TRUNC | LINUX_O_WRONLY, mode);
}

DEFINE_SYSCALL(symlinkat, gstr_t, path1_ptr, int, dirfd, gstr_t, path2_ptr)
{
  char path1[LINUX_PATH_MAX], path2[LINUX_PATH_MAX];

  strncpy_from_user(path1, path1_ptr, sizeof path1);
  strncpy_from_user(path2, path2_ptr, sizeof path2);

  struct path path;
  int r = vfs_grab_dir(dirfd, path2, 0, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->symlinkat(path.fs, path1, path.dir, path.subpath);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(symlink, gstr_t, path1_ptr, gstr_t, path2_ptr)
{
  return sys_symlinkat(path1_ptr, LINUX_AT_FDCWD, path2_ptr);
}

DEFINE_SYSCALL(newfstatat, int, dirfd, gstr_t, path_ptr, gaddr_t, st_ptr, int, flags)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  if (flags & ~(LINUX_AT_SYMLINK_NOFOLLOW)) {
    return -LINUX_EINVAL;
  }
  int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
  struct path path;
  int r = vfs_grab_dir(dirfd, pathname, grab_flags, &path);
  if (r < 0) {
    return r;
  }
  struct l_newstat st;
  r = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st, flags);
  vfs_ungrab_dir(&path);
  if (0 <= r && copy_to_user(st_ptr, &st, sizeof st))
    return -LINUX_EFAULT;
  return r;
}

/*
 * statx is what modern glibc/musl route stat()/lstat()/fstatat() through. It
 * reuses the same fstatat fs op as newfstatat and then repacks the arch-specific
 * struct l_newstat into the fixed struct l_statx (field-for-field, all names are
 * common to both stat layouts). Only the SYMLINK_NOFOLLOW lookup flag is honored
 * from `flags`; the AT_STATX_* sync hints and AT_EMPTY_PATH are not, and `mask`
 * is advisory - we always return the STATX_BASIC_STATS set. btime is not filled.
 */
DEFINE_SYSCALL(statx, int, dirfd, gstr_t, path_ptr, int, flags, unsigned int, mask, gaddr_t, stx_ptr)
{
  char pathname[LINUX_PATH_MAX];
  if (strncpy_from_user(pathname, path_ptr, sizeof pathname) < 0)
    return -LINUX_EFAULT;

  int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
  struct path path;
  int r = vfs_grab_dir(dirfd, pathname, grab_flags, &path);
  if (r < 0)
    return r;

  struct l_newstat st;
  r = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st,
                            flags & LINUX_AT_SYMLINK_NOFOLLOW);
  vfs_ungrab_dir(&path);
  if (r < 0)
    return r;

  struct l_statx stx;
  memset(&stx, 0, sizeof stx);
  stx.stx_mask       = LINUX_STATX_BASIC_STATS;
  stx.stx_blksize    = st.st_blksize;
  stx.stx_nlink      = st.st_nlink;
  stx.stx_uid        = st.st_uid;
  stx.stx_gid        = st.st_gid;
  stx.stx_mode       = st.st_mode;
  stx.stx_ino        = st.st_ino;
  stx.stx_size       = st.st_size;
  stx.stx_blocks     = st.st_blocks;
  stx.stx_atime.tv_sec  = st.st_atim.tv_sec;  stx.stx_atime.tv_nsec = st.st_atim.tv_nsec;
  stx.stx_mtime.tv_sec  = st.st_mtim.tv_sec;  stx.stx_mtime.tv_nsec = st.st_mtim.tv_nsec;
  stx.stx_ctime.tv_sec  = st.st_ctim.tv_sec;  stx.stx_ctime.tv_nsec = st.st_ctim.tv_nsec;
  stx.stx_rdev_major = major(st.st_rdev);  stx.stx_rdev_minor = minor(st.st_rdev);
  stx.stx_dev_major  = major(st.st_dev);   stx.stx_dev_minor  = minor(st.st_dev);

  if (copy_to_user(stx_ptr, &stx, sizeof stx))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(stat, gstr_t, path, gaddr_t, st)
{
  return sys_newfstatat(LINUX_AT_FDCWD, path, st, 0);
}

DEFINE_SYSCALL(lstat, gstr_t, path, gaddr_t, st)
{
  return sys_newfstatat(LINUX_AT_FDCWD, path, st, LINUX_AT_SYMLINK_NOFOLLOW);
}

DEFINE_SYSCALL(fchownat, int, dirfd, gstr_t, path_ptr, l_uid_t, user, l_gid_t, group, int, flags)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  if (flags & ~(LINUX_AT_SYMLINK_NOFOLLOW)) {
    return -LINUX_EINVAL;
  }
  int grab_flags = flags & LINUX_AT_SYMLINK_NOFOLLOW ? LOOKUP_NOFOLLOW : 0;
  struct path path;
  int r = vfs_grab_dir(dirfd, pathname, grab_flags, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->fchownat(path.fs, path.dir, path.subpath, user, group, flags);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(chown, gstr_t, path, int, uid, int, gid)
{
  return sys_fchownat(LINUX_AT_FDCWD, path, uid, gid, 0);
}

DEFINE_SYSCALL(lchown, gstr_t, path, int, uid, int, gid)
{
  return sys_fchownat(LINUX_AT_FDCWD, path, uid, gid, LINUX_AT_SYMLINK_NOFOLLOW);
}

DEFINE_SYSCALL(fchmodat, int, dirfd, gstr_t, path_ptr, l_mode_t, mode)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  struct path path;
  int r = vfs_grab_dir(dirfd, pathname, 0, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->fchmodat(path.fs, path.dir, path.subpath, mode);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(chmod, gstr_t, path, int, mode)
{
  return sys_fchmodat(LINUX_AT_FDCWD, path, mode);
}

DEFINE_SYSCALL(statfs, gstr_t, path_ptr, gaddr_t, buf_ptr)
{
  char pathname[LINUX_PATH_MAX];
  strncpy_from_user(pathname, path_ptr, sizeof pathname);
  struct path path;
  int r = vfs_grab_dir(LINUX_AT_FDCWD, pathname, 0, &path);
  if (r < 0) {
    return r;
  }
  struct l_statfs st;
  r = path.fs->ops->statfs(path.fs, path.dir, path.subpath, &st);
  vfs_ungrab_dir(&path);
  if (0 <= r && copy_to_user(buf_ptr, &st, sizeof st))
    return -LINUX_EFAULT;
  return r;
}

int
do_faccessat(int dirfd, const char *name, int mode)
{
  struct path path;
  int r = vfs_grab_dir(dirfd, name, 0, &path);
  if (r < 0) {
    return r;
  }
  r = path.fs->ops->faccessat(path.fs, path.dir, path.subpath, mode);
  vfs_ungrab_dir(&path);
  return r;
}

int do_access(const char *path, int mode)
{
  return do_faccessat(LINUX_AT_FDCWD, path, mode);
}

DEFINE_SYSCALL(faccessat, int, dirfd, gstr_t, path_ptr, int, mode)
{
  char path[LINUX_PATH_MAX];
  if (strncpy_from_user(path, path_ptr, sizeof path) < 0)
    return -LINUX_EFAULT;
  return do_faccessat(dirfd, path, mode);
}

DEFINE_SYSCALL(access, gstr_t, path_ptr, int, mode)
{
  return sys_faccessat(LINUX_AT_FDCWD, path_ptr, mode);
}

DEFINE_SYSCALL(renameat, int, oldfd, gstr_t, oldpath_ptr, int, newfd, gstr_t, newpath_ptr)
{
  char oldname[LINUX_PATH_MAX], newname[LINUX_PATH_MAX];

  strncpy_from_user(oldname, oldpath_ptr, sizeof oldname);
  strncpy_from_user(newname, newpath_ptr, sizeof newname);

  struct path oldpath, newpath;
  int r;
  if ((r = vfs_grab_dir(oldfd, oldname, LOOKUP_NOFOLLOW, &oldpath)) < 0) {
    goto out1;
  }
  if ((r = vfs_grab_dir(newfd, newname, LOOKUP_NOFOLLOW, &newpath)) < 0) {
    goto out2;
  }
  if (oldpath.fs != newpath.fs) {
    r = -LINUX_EXDEV;
    goto out2;
  }
  r = newpath.fs->ops->renameat(newpath.fs, oldpath.dir, oldpath.subpath, newpath.dir, newpath.subpath);
  vfs_ungrab_dir(&newpath);
 out2:
  vfs_ungrab_dir(&oldpath);
 out1:
  return r;
}

DEFINE_SYSCALL(rename, gstr_t, oldpath_ptr, gstr_t, newpath_ptr)
{
  return sys_renameat(LINUX_AT_FDCWD, oldpath_ptr, LINUX_AT_FDCWD, newpath_ptr);
}

DEFINE_SYSCALL(unlinkat, int, dirfd, gstr_t, path_ptr, int, flags)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  struct path path;
  int r;
  if ((r = vfs_grab_dir(dirfd, name, LOOKUP_NOFOLLOW, &path)) < 0) {
    return r;
  }
  r = path.fs->ops->unlinkat(path.fs, path.dir, path.subpath, flags);
  if (r == -LINUX_EPERM) {
    struct l_newstat st;
    int r2 = path.fs->ops->fstatat(path.fs, path.dir, path.subpath, &st,
				   LINUX_AT_SYMLINK_NOFOLLOW);
    if (r2 == 0 && S_ISDIR(st.st_mode)) {
      r = -LINUX_EISDIR;
    }
  }
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(unlink, gstr_t, path)
{
  return sys_unlinkat(LINUX_AT_FDCWD, path, 0);
}

DEFINE_SYSCALL(rmdir, gstr_t, path)
{
  return sys_unlinkat(LINUX_AT_FDCWD, path, LINUX_AT_REMOVEDIR);
}

DEFINE_SYSCALL(linkat, int, oldfd, gstr_t, oldpath_ptr, int, newfd, gstr_t, newpath_ptr, int, flags)
{
  char oldname[LINUX_PATH_MAX], newname[LINUX_PATH_MAX];

  strncpy_from_user(oldname, oldpath_ptr, sizeof oldname);
  strncpy_from_user(newname, newpath_ptr, sizeof newname);

  if (flags & ~LINUX_AT_SYMLINK_FOLLOW) {
    return -LINUX_EINVAL;
  }

  int lkflag = flags & LINUX_AT_SYMLINK_FOLLOW ? 0 : LOOKUP_NOFOLLOW;
  struct path oldpath, newpath;
  int r;
  if ((r = vfs_grab_dir(oldfd, oldname, lkflag, &oldpath)) < 0) {
    goto out1;
  }
  if ((r = vfs_grab_dir(newfd, newname, 0, &newpath)) < 0) {
    goto out2;
  }
  if (oldpath.fs != newpath.fs) {
    r = -LINUX_EXDEV;
    goto out2;
  }
  r = newpath.fs->ops->linkat(newpath.fs, oldpath.dir, oldpath.subpath, newpath.dir, newpath.subpath, flags);
  vfs_ungrab_dir(&newpath);
 out2:
  vfs_ungrab_dir(&oldpath);
 out1:
  return r;
}

DEFINE_SYSCALL(link, gstr_t, oldpath, gstr_t, newpath)
{
  return sys_linkat(LINUX_AT_FDCWD, oldpath, LINUX_AT_FDCWD, newpath, 0);
}

DEFINE_SYSCALL(readlinkat, int, dirfd, gstr_t, path_ptr, gaddr_t, buf_ptr, int, bufsize)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  int r;
  struct path path;
  if ((r = vfs_grab_dir(dirfd, name, LOOKUP_NOFOLLOW, &path)) < 0) {
    return r;
  }
  char *buf = malloc(bufsize);
  if (buf == NULL) {
    r = -LINUX_ENOMEM;
    goto out;
  }
  r = path.fs->ops->readlinkat(path.fs, path.dir, path.subpath, buf, bufsize);
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, bufsize)) {
    r = -LINUX_EFAULT;
    goto out;
  }
 out:
  if (buf) {
    free(buf);
  }
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(readlink, gstr_t, path_ptr, gaddr_t, buf_ptr, int, bufsize)
{
  return sys_readlinkat(LINUX_AT_FDCWD, path_ptr, buf_ptr, bufsize);
}

DEFINE_SYSCALL(mkdirat, int, dirfd, gstr_t, path_ptr, int, mode)
{
  char name[LINUX_PATH_MAX];
  strncpy_from_user(name, path_ptr, sizeof name);

  struct path path;
  int r;
  if ((r = vfs_grab_dir(dirfd, name, 0, &path)) < 0) {
    return r;
  }
  r = path.fs->ops->mkdirat(path.fs, path.dir, path.subpath, mode);
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(mkdir, gstr_t, path_ptr, int, mode)
{
  return sys_mkdirat(LINUX_AT_FDCWD, path_ptr, mode);
}

int
vfs_getcwd(char *buf, size_t size)
{
  errno = 0;
  char *ptr = getcwd(buf, size); /* FIXME: path translation */
  if (! ptr) {
    return -darwin_to_linux_errno(errno);
  }
  return 0;
}

int
vfs_fchdir(int fd)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  return syswrap(fchdir(fd));
}

int
vfs_umask(int mask)
{
  return syswrap(umask(mask));
}

/*
 * The syscall version of getcwd differs from that provided by glibc!
 * Quoting a part of source code of linux:
 *
 * > NOTE! The user-level library version returns a
 * > character pointer. The kernel system call just
 * > returns the length of the buffer filled (which
 * > includes the ending '\0' character), or a negative
 * > error value. So libc would do something like
 */
DEFINE_SYSCALL(getcwd, gaddr_t, buf_ptr, unsigned long, size)
{
  char *buf = malloc(size);
  if (buf == NULL) {
    return -LINUX_ENOMEM;
  }
  memset(buf, 0, size);
  int r;
  if ((r = vfs_getcwd(buf, size)) < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, size)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  r = strlen(buf) + 1;
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(fchdir, int, fd)
{
  return vfs_fchdir(fd);
}

DEFINE_SYSCALL(chdir, gstr_t, path_ptr)
{
  char path[LINUX_PATH_MAX];
  strncpy_from_user(path, path_ptr, sizeof path);
  int fd = user_openat(LINUX_AT_FDCWD, path, LINUX_O_DIRECTORY, 0);
  if (fd < 0)
    return fd;
  int r = sys_fchdir(fd);
  user_close(fd);
  return r;
}

DEFINE_SYSCALL(umask, int, mask)
{
  return vfs_umask(mask);
}

DEFINE_SYSCALL(mknodat, int, dirfd, gaddr_t, path_ptr, l_mode_t, mode, l_dev_t, dev) {
  char name[LINUX_PATH_MAX];
  if (strncpy_from_user(name, path_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;

  struct path path;
  int r = 0;
  switch(mode & S_IFMT) {
  case S_IFIFO: {
    if ((r = vfs_grab_dir(dirfd, name, 0, &path)) < 0) {
      goto out;
    }
    r = syswrap(mkfifo(path.subpath, mode));
    break;
  }
  default:
    warnk("unsupported mknod mode: %d", mode);
    return -LINUX_EINVAL;
  }
 out:
  vfs_ungrab_dir(&path);
  return r;
}

DEFINE_SYSCALL(mknod, gaddr_t, path_ptr, l_mode_t, mode, l_dev_t, dev) {
  return sys_mknodat(LINUX_AT_FDCWD, path_ptr, mode, dev);
}


/* TODO: functions below are not yet ported to the new vfs archtecture. */


DEFINE_SYSCALL(pipe, gaddr_t, fildes_ptr)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fd[2];
  int r = syswrap(pipe(fd));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(fildes_ptr, fd, sizeof fd)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  int err0 = register_fd(fd[0], false);
  int err1 = register_fd(fd[1], false);
  if (err0 < 0 || err1 < 0) {
    r = (err0 < 0) ? err0 : err1;
    close(err0);
    close(err1);
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);

  return r;
}

DEFINE_SYSCALL(pipe2, gaddr_t, fildes_ptr, int, flags)
{
  if (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC | LINUX_O_DIRECT)) {
    return -LINUX_EINVAL;
  }

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int fildes[2];

  int ret = pipe(fildes);
  if (ret < 0) {
    goto out;
  }

  int err0, err1;
  if (flags & LINUX_O_CLOEXEC) {
    err0 = syswrap(fcntl(fildes[0], F_SETFD, FD_CLOEXEC));
    err1 = syswrap(fcntl(fildes[1], F_SETFD, FD_CLOEXEC));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }
  if (flags & LINUX_O_NONBLOCK) {
    err0 = syswrap(fcntl(fildes[0], F_SETFL, O_NONBLOCK));
    err1 = syswrap(fcntl(fildes[1], F_SETFL, O_NONBLOCK));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }
  if (flags & LINUX_O_DIRECT) {
    err0 = syswrap(fcntl(fildes[0], F_NOCACHE, 1));
    err1 = syswrap(fcntl(fildes[1], F_NOCACHE, 1));
    if (err0 < 0 || err1 < 0) {
      goto close_by_fail;
    }
  }

  err0 = register_fd(fildes[0], flags & LINUX_O_CLOEXEC);
  err1 = register_fd(fildes[1], flags & LINUX_O_CLOEXEC);
  if (err0 < 0 || err1 < 0) {
    goto close_by_fail;
  }

  if (copy_to_user(fildes_ptr, fildes, sizeof(fildes))) {
    ret = -LINUX_EFAULT;
  }

  goto out;

close_by_fail:
  close(fildes[0]);
  close(fildes[1]);
  ret = (err0 < 0) ? err0 : err1;

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);

  return ret;
}

DEFINE_SYSCALL(dup, unsigned int, fd)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = sys_fcntl(fd, LINUX_F_DUPFD, 0);
  if (ret >= 0) {
    int err = register_fd(ret, false);
    if (err < 0) {
      close(ret);
      ret = err;
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(dup2, unsigned int, fd1, unsigned int, fd2)
{
  if (!in_userfd(fd1) || !in_userfd(fd2)) {
    return -LINUX_EBADF;
  }
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = syswrap(dup2(fd1, fd2));
  if (ret >= 0) {
    int err = register_fd(ret, false);
    if (err < 0) {
      close(ret);
      ret = err;
    }
  }
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
  if (flags & ~LINUX_O_CLOEXEC) {
    return -LINUX_EINVAL;
  }
  if (oldfd == newfd) {
    return -LINUX_EINVAL;
  }

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int ret = syswrap(dup2(oldfd, newfd));
  if (ret < 0) {
    goto out;
  }
  if (flags & LINUX_O_CLOEXEC) {
    int fcntl_err = syswrap(fcntl(newfd, F_SETFD, FD_CLOEXEC));
    if (fcntl_err < 0) {
      close(ret);
      ret = fcntl_err;
      goto out;
    }
  }
  int err = register_fd(ret, flags & LINUX_O_CLOEXEC);
  if (err < 0) {
    close(ret);
    ret = err;
  }

out:
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  return ret;
}

DEFINE_SYSCALL(pread64, unsigned int, fd, gstr_t, buf_ptr, size_t, count, off_t, pos)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  char *buf = malloc(count);
  int r = syswrap(pread(fd, buf, count, pos));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, r)) {
    r = -LINUX_EFAULT;
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(pwrite64, unsigned int, fd, gstr_t, buf_ptr, size_t, count, off_t, pos)
{
  if (!in_userfd(fd)) {
    return -LINUX_EBADF;
  }
  int r;
  char *buf = malloc(count);
  if (copy_from_user(buf, buf_ptr, count)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  r = syswrap(pwrite(fd, buf, count, pos));
  if (r < 0) {
    goto out;
  }
out:
  free(buf);
  return r;
}

DEFINE_SYSCALL(getxattr, gstr_t, path_ptr, gstr_t, name_ptr, gaddr_t, value, size_t, size)
{
  warnk("getxattr is unimplemented\n");
  return -LINUX_ENOTSUP;
}

DEFINE_SYSCALL(fgetxattr, int, fd, gaddr_t, name, gaddr_t, value, size_t, size)
{
  warnk("fgetxattr is unimplemented\n");
  return -LINUX_ENOTSUP;
}

DEFINE_SYSCALL(setxattr, gstr_t, pathname, gstr_t, name, gaddr_t, value, size_t, size, int, flags)
{
  warnk("setxattr is unimplemented\n");
  return 0;
}

DEFINE_SYSCALL(fsetxattr, int, fd, gaddr_t, name, gaddr_t, value, size_t, size, int, flags)
{
  warnk("fsetxattr is unimplemented\n");
  return 0;
}

DEFINE_SYSCALL(fadvise64, int, fd, off_t, offset, size_t, len, int, advice)
{
  return 0;
}

DEFINE_SYSCALL(select, int, nfds, gaddr_t, readfds_ptr, gaddr_t, writefds_ptr, gaddr_t, errorfds_ptr, gaddr_t, timeout_ptr)
{
  // TODO: Check if fd is in userspace
  // Darwin's fd_set and timeval is compatible with those of Linux

  struct timeval timeout;
  fd_set readfds, writefds, errorfds;
  struct timeval *to;
  fd_set *rfds, *wfds, *efds;

  if (nfds - 1 >= proc.fileinfo.vkern_fdtable.start) {
    return -LINUX_EBADF;
  }

  if (timeout_ptr == 0) {
    to = NULL;
  } else {
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
      return -LINUX_EFAULT;
    to = &timeout;
  }
  if (readfds_ptr == 0) {
    rfds = NULL;
  } else {
    if (copy_from_user(&readfds, readfds_ptr, sizeof readfds))
      return -LINUX_EFAULT;
    rfds = &readfds;
  }
  if (writefds_ptr == 0) {
    wfds = NULL;
  } else {
    if (copy_from_user(&writefds, writefds_ptr, sizeof writefds))
      return -LINUX_EFAULT;
    wfds = &writefds;
  }
  if (errorfds_ptr == 0) {
    efds = NULL;
  } else {
    if (copy_from_user(&errorfds, errorfds_ptr, sizeof errorfds))
      return -LINUX_EFAULT;
    efds = &errorfds;
  }

  int r = syswrap(select(nfds, rfds, wfds, efds, to));
  if (r < 0)
    return r;

  if (readfds_ptr != 0 && copy_to_user(readfds_ptr, &readfds, sizeof readfds))
    return -LINUX_EFAULT;
  if (writefds_ptr != 0 && copy_to_user(writefds_ptr, &writefds, sizeof writefds))
    return -LINUX_EFAULT;
  if (errorfds_ptr != 0 && copy_to_user(errorfds_ptr, &errorfds, sizeof errorfds))
    return -LINUX_EFAULT;
  return r;
}

DEFINE_SYSCALL(pselect6, int, nfds, gaddr_t, readfds_ptr, gaddr_t, writefds_ptr, gaddr_t, errorfds_ptr, gaddr_t, timeout_ptr, gaddr_t, sigmask_ptr)
{
  // TODO: Check if fd is in userspace
  // Darwin's fd_set and timeval is compatible with those of Linux

  struct timespec timeout;
  fd_set readfds, writefds, errorfds;
  struct timespec *to;
  fd_set *rfds, *wfds, *efds;

  if (nfds - 1 >= proc.fileinfo.vkern_fdtable.start) {
    return -LINUX_EBADF;
  }

  if (timeout_ptr == 0) {
    to = NULL;
  } else {
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
      return -LINUX_EFAULT;
    to = &timeout;
  }
  if (readfds_ptr == 0) {
    rfds = NULL;
  } else {
    if (copy_from_user(&readfds, readfds_ptr, sizeof readfds))
      return -LINUX_EFAULT;
    rfds = &readfds;
  }
  if (writefds_ptr == 0) {
    wfds = NULL;
  } else {
    if (copy_from_user(&writefds, writefds_ptr, sizeof writefds))
      return -LINUX_EFAULT;
    wfds = &writefds;
  }
  if (errorfds_ptr == 0) {
    efds = NULL;
  } else {
    if (copy_from_user(&errorfds, errorfds_ptr, sizeof errorfds))
      return -LINUX_EFAULT;
    efds = &errorfds;
  }

  // FIXME: Ignore sigmask now. Support it after implementing signal handling
  int r = syswrap(pselect(nfds, rfds, wfds, efds, to, NULL));
  if (r < 0)
    return r;

  if (readfds_ptr != 0 && copy_to_user(readfds_ptr, &readfds, sizeof readfds))
    return -LINUX_EFAULT;
  if (writefds_ptr != 0 && copy_to_user(writefds_ptr, &writefds, sizeof writefds))
    return -LINUX_EFAULT;
  if (errorfds_ptr != 0 && copy_to_user(errorfds_ptr, &errorfds, sizeof errorfds))
    return -LINUX_EFAULT;
  return r;
}

/* Shared body of poll and ppoll: marshal the guest pollfd array, poll the host
 * descriptors (kernel-owned fds are masked to -1), and write the results back.
 * timeout is in milliseconds, -1 for no timeout - the same units poll() takes. */
static int
poll_common(gaddr_t fds_ptr, int nfds, int timeout)
{
  /* FIXME! event numbers should be translated */

  struct pollfd *l_fds = malloc(nfds * sizeof(struct pollfd)), *d_fds = malloc(nfds * sizeof(struct pollfd));

  if (l_fds == NULL || d_fds == NULL) {
    if (l_fds) {
      free(l_fds);
    }
    if (d_fds) {
      free(d_fds);
    }
    return -LINUX_ENOMEM;
  }

  int r;
  if (nfds > OPEN_MAX) {
    r = -LINUX_EINVAL;
    goto out;
  }

  if (copy_from_user(l_fds, fds_ptr, nfds * sizeof(struct pollfd))) {
    r = -LINUX_EFAULT;
    goto out;
  }

  for (int i = 0; i < nfds; i++) {
    d_fds[i] = l_fds[i];
    if (!in_userfd(l_fds[i].fd)) {
      d_fds[i].fd = -1;
    }
  }

  r = syswrap(poll(d_fds, nfds, timeout));
  if (r < 0)
    goto out;

  for (int i = 0; i < nfds; i++) {
    if (in_userfd(l_fds[i].fd) || l_fds[i].fd < 0 || l_fds[i].events == 0) {
      l_fds[i].revents = d_fds[i].revents;
    } else {
      l_fds[i].revents = LINUX_POLLNVAL;
      r++;
    }
  }

  if (copy_to_user(fds_ptr, l_fds, nfds * sizeof(struct pollfd))) {
    r = -LINUX_EFAULT;
  }

out:
  free(l_fds);
  free(d_fds);
  return r;
}

DEFINE_SYSCALL(poll, gaddr_t, fds_ptr, int, nfds, int, timeout)
{
  return poll_common(fds_ptr, nfds, timeout);
}

/*
 * ppoll is aarch64's primary poll (there is no plain poll in the syscall set a
 * modern libc uses on this arch). It differs from poll in two ways: the timeout
 * is a relative struct timespec (NULL = block forever) rather than a millisecond
 * int, and it takes an optional signal mask to install for the duration.
 *
 * The mask is applied around the wait rather than atomically inside it - close
 * enough for the common poll-with-a-mask use, though a signal delivered in the
 * gap between installing the mask and entering poll() will not cut the wait
 * short the way a truly atomic ppoll would. Linux leaves *tmo unmodified on
 * return here (unlike select), so it is only read.
 */
DEFINE_SYSCALL(ppoll, gaddr_t, fds_ptr, int, nfds, gaddr_t, tmo_ptr, gaddr_t, sigmask_ptr, size_t, sigsetsize)
{
  int timeout = -1;
  if (tmo_ptr) {
    struct l_timespec ts;
    if (copy_from_user(&ts, tmo_ptr, sizeof ts))
      return -LINUX_EFAULT;
    /* Round a sub-millisecond remainder up so a short wait is not truncated to
     * a busy zero-timeout poll. */
    timeout = ts.tv_sec * 1000 + (ts.tv_nsec + 999999) / 1000000;
  }

  sigset_t saved;
  bool have_mask = false;
  if (sigmask_ptr) {
    if (sigsetsize != sizeof(l_sigset_t))
      return -LINUX_EINVAL;
    l_sigset_t lset;
    if (copy_from_user(&lset, sigmask_ptr, sizeof lset))
      return -LINUX_EFAULT;
    sigset_t dset;
    linux_to_darwin_sigset(&lset, &dset);
    sigprocmask(SIG_SETMASK, &dset, &saved);
    have_mask = true;
  }

  int r = poll_common(fds_ptr, nfds, timeout);

  if (have_mask)
    sigprocmask(SIG_SETMASK, &saved, NULL);

  return r;
}

DEFINE_SYSCALL(chroot, gstr_t, path_ptr)
{
  char path[PATH_MAX];
  int len = strncpy_from_user(path, path_ptr, sizeof path);
  if (len == PATH_MAX) {
    return -LINUX_ENAMETOOLONG;
  }
  if (len < 0) {
    return -LINUX_EFAULT;
  }

  /* We have not impelemented caps, just check if user is root */
  if (getuid() != 0) {
    return -LINUX_EPERM;
  }

  /* for pacman */
  if (! (path[0] == '/' && path[1] == '\0')) {
    return -LINUX_EACCES;
  }
  return 0;
}

DEFINE_SYSCALL(ftruncate, unsigned int, fd, unsigned long, length)
{
  return syswrap(ftruncate(fd, length));
}

DEFINE_SYSCALL(flistxattr, int, fd, gaddr_t, list, size_t, size)
{
  assert(size == 0);
  return 0;
}

DEFINE_SYSCALL(flock, int, fd, int, operation)
{
  // Linux's and Darwin's operation are compatible
  return syswrap(flock(fd, operation));
}

DEFINE_SYSCALL(fallocate, int, fd, int, mode, l_off_t, offset, l_off_t, len)
{
  if (mode != 0) {
    // FreeBSD's Linuxulator also implements only mode zero
    warnk("Unsupported fallocate mode\n");
    return -ENOSYS;
  }
  
  // Emulate posix_fallocate
  assert(offset == 0);
  struct fstore store = {F_ALLOCATEALL, F_PEOFPOSMODE, 0, len, 0};
  return syswrap(fcntl(fd, F_PREALLOCATE, &store));
}

DEFINE_SYSCALL(sync)
{
  sync();
  return 0;
}

/*
 * The descriptor tables, for a handover.
 *
 * Walks both tables' open bits and records which guest number maps to which
 * host descriptor. The host descriptors need no saving of their own - they
 * survive fork and exec, offsets and all - so this table is the entire mapping
 * a resumed process needs to keep the guest's I/O pointing where it was.
 *
 * Returns the number of open descriptors, which may exceed `max`.
 */
static size_t
fdtable_snapshot_one(struct fdtable *t, int32_t which,
                     struct checkpoint_fd *out, size_t max, size_t n)
{
  for (int fd = t->start; fd < t->start + t->size; fd++) {
    int i = (fd - t->start) / 64, b = (fd - t->start) - i * 64;
    if (!(t->open_fds[i] & (1ULL << b)))
      continue;
    if (n < max) {
      int off = fd - t->start;
      struct file *f = &t->files[off / fdtable_alloc_unit][off % fdtable_alloc_unit];
      out[n] = (struct checkpoint_fd){
        .table = which,
        .index = fd,
        .host_fd = f->fd,
        .cloexec = (t->cloexec_fds[i] & (1ULL << b)) ? 1 : 0,
      };
    }
    n++;
  }
  return n;
}

size_t
fdtable_snapshot(struct checkpoint_fd *out, size_t max, struct checkpoint_header *hdr)
{
  struct fileinfo *fi = &proc.fileinfo;

  if (hdr) {
    hdr->rootfd      = fi->rootfd;
    hdr->user_start  = fi->fdtable.start;
    hdr->user_size   = fi->fdtable.size;
    hdr->vkern_start = fi->vkern_fdtable.start;
    hdr->vkern_size  = fi->vkern_fdtable.size;
  }

  size_t n = fdtable_snapshot_one(&fi->fdtable, 0, out, max, 0);
  n = fdtable_snapshot_one(&fi->vkern_fdtable, 1, out, max, n);
  return n;
}

/*
 * Rebuild both descriptor tables from a checkpoint.
 *
 * The host descriptors are already open - they came through fork and exec
 * untouched, with their offsets and flags - so nothing here opens anything. It
 * rebuilds the tables that say which of them the guest can see and under which
 * number, and re-attaches the one static ops table every file shares.
 */
void
fdtable_restore(const struct checkpoint_fd *fds, size_t n,
                const struct checkpoint_header *hdr)
{
  struct fileinfo *fi = &proc.fileinfo;

  pthread_rwlock_init(&fi->fdtable_lock, NULL);

  fi->vkern_fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fi->vkern_fdtable.start = hdr->vkern_start;
  alloc_fdtable(&fi->vkern_fdtable, hdr->vkern_size);

  fi->fdtable = (struct fdtable) { 0, 0, NULL, NULL, NULL };
  fi->fdtable.start = hdr->user_start;
  alloc_fdtable(&fi->fdtable, hdr->user_size);

  fi->rootfd = hdr->rootfd;

  for (size_t i = 0; i < n; i++) {
    struct fdtable *t = fds[i].table ? &fi->vkern_fdtable : &fi->fdtable;
    alloc_file(t, fds[i].index);
    set_fdbit(t, t->open_fds, fds[i].index);
    if (fds[i].cloexec)
      set_fdbit(t, t->cloexec_fds, fds[i].index);
  }
}

/*
 * Clear FD_CLOEXEC on every descriptor the guest has open.
 *
 * For the child of a guest fork, between the host fork and the host exec.
 *
 * The guest asked to fork, and fork does not close close-on-exec descriptors -
 * only exec does. But this fork is implemented as fork+exec (the framework
 * cannot give a forked child a vCPU, see spike/arm64-fork/), so the kernel would
 * apply exec semantics the guest never asked for and close them: a shell
 * pipeline, whose pipe ends are exactly such descriptors, would come up with
 * nothing connected.
 *
 * The flags are not lost, only moved: the checkpoint carries each descriptor's
 * close-on-exec bit, so the resumed process restores the table exactly, and a
 * later *guest* execve still closes the right ones through close_cloexec().
 */
void
fdtable_clear_host_cloexec(void)
{
  struct fileinfo *fi = &proc.fileinfo;
  struct fdtable *tables[] = { &fi->fdtable, &fi->vkern_fdtable };

  for (int t = 0; t < 2; t++) {
    struct fdtable *tab = tables[t];
    for (int fd = tab->start; fd < tab->start + tab->size; fd++) {
      int i = (fd - tab->start) / 64, b = (fd - tab->start) - i * 64;
      if (!(tab->open_fds[i] & (1ULL << b)))
        continue;
      int flags = fcntl(fd, F_GETFD);
      if (flags >= 0 && (flags & FD_CLOEXEC))
        fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
  }
}
