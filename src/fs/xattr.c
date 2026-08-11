/*
 * Extended attributes.
 *
 * These were stubs, and one of them was the bad kind: setxattr warned and
 * returned 0, so a guest was told its attribute had been stored when nothing
 * had happened. dpkg and rpm set attributes while unpacking, tar and rsync copy
 * them, and every one of those was quietly doing nothing.
 *
 * Darwin has the whole family under the same names, with two differences that
 * matter. It carries a `position` argument, which is for resource forks and is
 * zero for everything else, and it spells "do not follow the symlink" as an
 * option flag rather than as a separate l-prefixed call - so the twelve Linux
 * entry points are four Darwin ones with XATTR_NOFOLLOW set or not.
 *
 * The part that is not a translation is hiding nabi's own attributes.
 *
 * File ownership and the guest's mode bits are kept in msl.nabi.owner and
 * msl.nabi.mode, because Darwin cannot hold a uid the host account does not
 * have (see struct cred). They are bookkeeping, not the guest's data, and a
 * guest that could see them would be able to do three things it must not: read
 * them, remove them - destroying the ownership of its own files - and, worst,
 * *copy* them. `tar -p`, `cp -a` and `rsync -X` all read every attribute from
 * one file and write them to another, so a single archive extraction would
 * stamp one file's owner onto everything it touched.
 *
 * So they are filtered from listings and refused by name. The guest sees the
 * attributes it set and no others, which is what it would see on Linux, where
 * this bookkeeping does not exist at all.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"

/* Linux's setxattr flags; Darwin numbers its own differently. */
#define LINUX_XATTR_CREATE  1
#define LINUX_XATTR_REPLACE 2

#define NABI_XATTR_PREFIX "msl.nabi."
#define DARWIN_XATTR_PREFIX "com.apple."

/*
 * Attributes the guest has no business seeing: nabi's own, and Darwin's.
 *
 * Darwin's are hidden for a different reason from ours. They are real, and they
 * are the *host's* - com.apple.provenance is how macOS tracks where a file came
 * from - and a Linux program cannot make sense of one: Linux only has the four
 * namespaces user, system, security and trusted, and setxattr refuses anything
 * else. So a guest can neither create one nor understand one, and the only
 * thing it can do with them is copy them: `cp -a` and `tar --xattrs` read every
 * attribute and write them somewhere else, which would spread the host's
 * provenance marks onto files that did not come from there.
 */
static bool
is_hidden(const char *name)
{
  return strncmp(name, NABI_XATTR_PREFIX, sizeof NABI_XATTR_PREFIX - 1) == 0 ||
         strncmp(name, DARWIN_XATTR_PREFIX, sizeof DARWIN_XATTR_PREFIX - 1) == 0;
}

/* Ours specifically: hidden like Darwin's, but a write is refused rather than
 * merely unseen, because writing one would rewrite who owns the file. */
static bool
is_ours(const char *name)
{
  return strncmp(name, NABI_XATTR_PREFIX, sizeof NABI_XATTR_PREFIX - 1) == 0;
}

static int
to_darwin_flags(int l_flags)
{
  int d = 0;
  if (l_flags & LINUX_XATTR_CREATE)
    d |= XATTR_CREATE;
  if (l_flags & LINUX_XATTR_REPLACE)
    d |= XATTR_REPLACE;
  return d;
}

/*
 * Copy a listing out, dropping nabi's own names.
 *
 * A listing is NUL-separated names, and the length has to be recomputed rather
 * than adjusted: a caller sizes its buffer from a first call with size 0 and
 * then asks again, so the two answers must agree about what is in there.
 */
static int
filter_list(char *buf, ssize_t n, gaddr_t out, size_t size)
{
  size_t kept = 0;
  for (ssize_t i = 0; i < n; ) {
    size_t len = strlen(buf + i) + 1;
    if (!is_hidden(buf + i)) {
      if (kept != (size_t) i)
        memmove(buf + kept, buf + i, len);
      kept += len;
    }
    i += (ssize_t) len;
  }
  if (size == 0)
    return (int) kept;          /* just the size, as Linux answers it */
  if (kept > size)
    return -LINUX_ERANGE;
  if (kept && copy_to_user(out, buf, kept))
    return -LINUX_EFAULT;
  return (int) kept;
}

/* ------------------------------------------------------------------- get */

static int
do_getxattr(const char *host, int fd, const char *name, gaddr_t value,
            size_t size, int options)
{
  if (is_hidden(name))
    return -LINUX_ENODATA;      /* as far as the guest is concerned, absent */

  char *buf = size ? malloc(size) : NULL;
  if (size && !buf)
    return -LINUX_ENOMEM;

  ssize_t n = host ? getxattr(host, name, buf, size, 0, options)
                   : fgetxattr(fd, name, buf, size, 0, options);
  int r;
  if (n < 0)
    r = -darwin_to_linux_errno(errno);
  else if (size == 0 || !copy_to_user(value, buf, (size_t) n))
    r = (int) n;
  else
    r = -LINUX_EFAULT;
  free(buf);
  return r;
}

static int
getxattr_path(gstr_t path_ptr, gstr_t name_ptr, gaddr_t value, size_t size,
              int options)
{
  char guestpath[LINUX_PATH_MAX], name[256], host[PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0 ||
      strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;
  return do_getxattr(host, -1, name, value, size, options);
}

DEFINE_SYSCALL(getxattr, gstr_t, path, gstr_t, name, gaddr_t, value, size_t, size)
{
  return getxattr_path(path, name, value, size, 0);
}

DEFINE_SYSCALL(lgetxattr, gstr_t, path, gstr_t, name, gaddr_t, value, size_t, size)
{
  return getxattr_path(path, name, value, size, XATTR_NOFOLLOW);
}

DEFINE_SYSCALL(fgetxattr, int, fd, gaddr_t, name_ptr, gaddr_t, value, size_t, size)
{
  char name[256];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  return do_getxattr(NULL, fd, name, value, size, 0);
}

/* ------------------------------------------------------------------- set */

static int
do_setxattr(const char *host, int fd, const char *name, gaddr_t value,
            size_t size, int l_flags, int options)
{
  /* Refused by name rather than silently ignored: a guest that could write
   * here would be rewriting the record of who owns its files. */
  if (is_ours(name))
    return -LINUX_EPERM;

  char *buf = size ? malloc(size) : NULL;
  if (size && !buf)
    return -LINUX_ENOMEM;
  if (size && copy_from_user(buf, value, size)) {
    free(buf);
    return -LINUX_EFAULT;
  }
  int opts = options | to_darwin_flags(l_flags);
  int n = host ? setxattr(host, name, buf, size, 0, opts)
               : fsetxattr(fd, name, buf, size, 0, opts);
  int r = n < 0 ? -darwin_to_linux_errno(errno) : 0;
  free(buf);
  return r;
}

static int
setxattr_path(gstr_t path_ptr, gstr_t name_ptr, gaddr_t value, size_t size,
              int flags, int options)
{
  char guestpath[LINUX_PATH_MAX], name[256], host[PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0 ||
      strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;
  return do_setxattr(host, -1, name, value, size, flags, options);
}

DEFINE_SYSCALL(setxattr, gstr_t, path, gstr_t, name, gaddr_t, value,
               size_t, size, int, flags)
{
  return setxattr_path(path, name, value, size, flags, 0);
}

DEFINE_SYSCALL(lsetxattr, gstr_t, path, gstr_t, name, gaddr_t, value,
               size_t, size, int, flags)
{
  return setxattr_path(path, name, value, size, flags, XATTR_NOFOLLOW);
}

DEFINE_SYSCALL(fsetxattr, int, fd, gaddr_t, name_ptr, gaddr_t, value,
               size_t, size, int, flags)
{
  char name[256];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  return do_setxattr(NULL, fd, name, value, size, flags, 0);
}

/* ------------------------------------------------------------------ list */

static int
do_listxattr(const char *host, int fd, gaddr_t out, size_t size, int options)
{
  /* Asked for the whole listing even when the guest wanted only its size,
   * because the size it is owed is the size *after* ours are removed. */
  ssize_t need = host ? listxattr(host, NULL, 0, options)
                      : flistxattr(fd, NULL, 0, options);
  if (need < 0)
    return -darwin_to_linux_errno(errno);
  if (need == 0)
    return 0;

  char *buf = malloc((size_t) need);
  if (!buf)
    return -LINUX_ENOMEM;
  ssize_t n = host ? listxattr(host, buf, (size_t) need, options)
                   : flistxattr(fd, buf, (size_t) need, options);
  int r = n < 0 ? -darwin_to_linux_errno(errno)
                : filter_list(buf, n, out, size);
  free(buf);
  return r;
}

static int
listxattr_path(gstr_t path_ptr, gaddr_t out, size_t size, int options)
{
  char guestpath[LINUX_PATH_MAX], host[PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0)
    return -LINUX_EFAULT;
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;
  return do_listxattr(host, -1, out, size, options);
}

DEFINE_SYSCALL(listxattr, gstr_t, path, gaddr_t, list, size_t, size)
{
  return listxattr_path(path, list, size, 0);
}

DEFINE_SYSCALL(llistxattr, gstr_t, path, gaddr_t, list, size_t, size)
{
  return listxattr_path(path, list, size, XATTR_NOFOLLOW);
}

DEFINE_SYSCALL(flistxattr, int, fd, gaddr_t, list, size_t, size)
{
  return do_listxattr(NULL, fd, list, size, 0);
}

/* ---------------------------------------------------------------- remove */

static int
do_removexattr(const char *host, int fd, const char *name, int options)
{
  if (is_ours(name))
    return -LINUX_EPERM;
  int n = host ? removexattr(host, name, options)
               : fremovexattr(fd, name, options);
  return n < 0 ? -darwin_to_linux_errno(errno) : 0;
}

static int
removexattr_path(gstr_t path_ptr, gstr_t name_ptr, int options)
{
  char guestpath[LINUX_PATH_MAX], name[256], host[PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0 ||
      strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;
  return do_removexattr(host, -1, name, options);
}

DEFINE_SYSCALL(removexattr, gstr_t, path, gstr_t, name)
{
  return removexattr_path(path, name, 0);
}

DEFINE_SYSCALL(lremovexattr, gstr_t, path, gstr_t, name)
{
  return removexattr_path(path, name, XATTR_NOFOLLOW);
}

DEFINE_SYSCALL(fremovexattr, int, fd, gaddr_t, name_ptr)
{
  char name[256];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  return do_removexattr(NULL, fd, name, 0);
}
