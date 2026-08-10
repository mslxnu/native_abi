/*
 * System V IPC objects as files, one directory per IPC namespace.
 * See include/sysv.h for why they cannot be Darwin's.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "sysv.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/ipc.h"

static const char *const kind_name[SYSV_KINDS] = {
  [SYSV_SHM] = "shm",
  [SYSV_SEM] = "sem",
  [SYSV_MSG] = "msg",
};

static void
ns_dir(uint64_t ino, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-ipc-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) ino);
}

/* This process's namespace directory, created if this is the first use. */
static int
here(char *out, size_t n)
{
  ns_dir(ns_ino_of(NS_IPC), out, n);
  if (mkdir(out, 0700) < 0 && errno != EEXIST)
    return -darwin_to_linux_errno(errno);
  return 0;
}

static void
obj_path(const char *dir, enum sysv_kind kind, int id, char suffix,
         char *out, size_t n)
{
  snprintf(out, n, "%s/%s.%d.%c", dir, kind_name[kind], id, suffix);
}

static void
key_path(const char *dir, enum sysv_kind kind, int32_t key, char *out, size_t n)
{
  snprintf(out, n, "%s/%s.k%u", dir, kind_name[kind], (unsigned) key);
}

static int64_t
now(void)
{
  return (int64_t) time(NULL);
}

bool
sysv_perm_ok(const struct sysv_meta *m, int want)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  l_uid_t euid = proc.cred.euid;
  l_gid_t egid = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);

  if (euid == 0)
    return true;                /* guest root, which is a fiction we keep */

  unsigned bits;
  if (m->uid == euid || m->cuid == euid)
    bits = m->mode >> 6;
  else if (m->gid == egid || m->cgid == egid)
    bits = m->mode >> 3;
  else
    bits = m->mode;
  return (bits & (unsigned) want) == (unsigned) want;
}

bool
sysv_owner_ok(const struct sysv_meta *m)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  l_uid_t euid = proc.cred.euid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return euid == 0 || m->uid == euid || m->cuid == euid;
}

/*
 * Which Darwin semaphore array stands behind one of ours.
 *
 * Derived rather than agreed on, and that is what makes it safe: every process
 * in the namespace computes the same number from the namespace and the id, so
 * whoever calls semget first creates the array and the rest find it, with
 * nothing to coordinate and no window in which one process has published an
 * object whose backing another cannot yet see.
 *
 * It is a hash, so two of these could in principle land on the same Darwin key
 * and share an array that should be separate. With 31 bits and objects counted
 * in tens it will not happen; it is written down because "in principle" is the
 * only place it lives.
 */
int32_t
sysv_host_key(uint64_t ino, int id)
{
  uint64_t h = (ino * 1099511628211ULL) ^ ((uint64_t) id + 0x9e3779b97f4a7c15ULL);
  h ^= h >> 29;
  h *= 0xbf58476d1ce4e5b9ULL;
  h ^= h >> 32;
  int32_t k = (int32_t) (h & 0x7fffffff);
  return k ? k : 1;
}

/* Map an already-open meta file. */
static int
map_meta(int fd, struct sysv_obj *out, int id)
{
  void *p = mmap(NULL, sizeof(struct sysv_meta), PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) {
    int e = errno;
    close(fd);
    return -darwin_to_linux_errno(e);
  }
  out->id = id;
  out->meta_fd = fd;
  out->m = p;
  return 0;
}

void
sysv_close(struct sysv_obj *o)
{
  if (o->m) {
    munmap(o->m, sizeof *o->m);
    o->m = NULL;
  }
  if (o->meta_fd >= 0) {
    close(o->meta_fd);
    o->meta_fd = -1;
  }
}

int
sysv_open(enum sysv_kind kind, int id, struct sysv_obj *out)
{
  char dir[PATH_MAX], path[PATH_MAX];
  int r;

  if (id < 0 || id >= SYSV_MAX_ID)
    return -LINUX_EINVAL;
  if ((r = here(dir, sizeof dir)) < 0)
    return r;
  obj_path(dir, kind, id, 'm', path, sizeof path);

  int fd = open(path, O_RDWR);
  if (fd < 0)
    return -LINUX_EINVAL;       /* Linux's answer for an id that is not one */
  if ((r = map_meta(fd, out, id)) < 0)
    return r;
  if (out->m->magic != SYSV_MAGIC || out->m->kind != (uint32_t) kind) {
    sysv_close(out);
    return -LINUX_EINVAL;
  }
  return 0;
}

/* The id `key` is bound to, or -1. */
static int
key_lookup(const char *dir, enum sysv_kind kind, int32_t key)
{
  char link[PATH_MAX], target[NAME_MAX + 1];
  key_path(dir, kind, key, link, sizeof link);
  ssize_t n = readlink(link, target, sizeof target - 1);
  if (n < 0)
    return -1;
  target[n] = '\0';

  int id = -1;
  /* "<kind>.<id>.m" */
  if (sscanf(target + strlen(kind_name[kind]) + 1, "%d", &id) != 1)
    return -1;
  return id;
}

/*
 * Take the lowest free id. O_EXCL is the whole of the allocator: whoever
 * creates the meta file owns that id, and two processes racing for it cannot
 * both win.
 *
 * Linux's ids carry a sequence number as well as an index, so that an id kept
 * past its object's removal is rejected rather than silently landing on the
 * next object to take the slot. That is not emulated - an id here is the index
 * alone - so a guest that uses a stale id gets whatever now occupies it where
 * Linux would give it EINVAL. It makes a guest bug quieter; it does not make
 * one.
 */
static int
alloc_id(const char *dir, enum sysv_kind kind, int *fd_out)
{
  char path[PATH_MAX];
  for (int id = 0; id < SYSV_MAX_ID; id++) {
    obj_path(dir, kind, id, 'm', path, sizeof path);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
      if (ftruncate(fd, sizeof(struct sysv_meta)) < 0) {
        int e = errno;
        close(fd);
        unlink(path);
        return -darwin_to_linux_errno(e);
      }
      *fd_out = fd;
      return id;
    }
    if (errno != EEXIST)
      return -darwin_to_linux_errno(errno);
  }
  return -LINUX_ENOSPC;
}

static void
destroy_object(const char *dir, enum sysv_kind kind, int id)
{
  char path[PATH_MAX];
  obj_path(dir, kind, id, 'm', path, sizeof path);
  unlink(path);
  obj_path(dir, kind, id, 'd', path, sizeof path);
  unlink(path);
}

int
sysv_get(enum sysv_kind kind, int32_t key, uint64_t size, int l_flags,
         struct sysv_obj *out)
{
  char dir[PATH_MAX], path[PATH_MAX], link[PATH_MAX];
  int r;

  if ((r = here(dir, sizeof dir)) < 0)
    return r;

  /* What the low bits of the flag word ask for, as an access check. */
  int want = 0;
  if (l_flags & 0444) want |= SYSV_R;
  if (l_flags & 0222) want |= SYSV_W;

 again:
  if (key != LINUX_IPC_PRIVATE) {
    int id = key_lookup(dir, kind, key);
    if (id >= 0) {
      if ((l_flags & LINUX_IPC_CREAT) && (l_flags & LINUX_IPC_EXCL))
        return -LINUX_EEXIST;
      if ((r = sysv_open(kind, id, out)) < 0)
        return r;
      if (!sysv_perm_ok(out->m, want)) {
        sysv_close(out);
        return -LINUX_EACCES;
      }
      /* Asking for more than the object has is EINVAL, for both kinds. */
      if (size > out->m->size) {
        sysv_close(out);
        return -LINUX_EINVAL;
      }
      return id;
    }
    if (!(l_flags & LINUX_IPC_CREAT))
      return -LINUX_ENOENT;
  }

  int meta_fd = -1;
  int id = alloc_id(dir, kind, &meta_fd);
  if (id < 0)
    return id;

  /* Both of the kinds whose contents are nabi's get a file for them. A
   * segment is sized up front; a queue starts empty and grows. */
  if (kind != SYSV_SEM) {
    obj_path(dir, kind, id, 'd', path, sizeof path);
    int dfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0 || ftruncate(dfd, kind == SYSV_SHM ? (off_t) size : 0) < 0) {
      int e = errno;
      if (dfd >= 0) close(dfd);
      close(meta_fd);
      destroy_object(dir, kind, id);
      return -darwin_to_linux_errno(e);
    }
    close(dfd);
  }

  if ((r = map_meta(meta_fd, out, id)) < 0) {
    destroy_object(dir, kind, id);
    return r;
  }

  pthread_rwlock_rdlock(&proc.cred.lock);
  l_uid_t euid = proc.cred.euid;
  l_gid_t egid = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);

  *out->m = (struct sysv_meta) {
    .magic = SYSV_MAGIC,
    .kind  = (uint32_t) kind,
    .key   = key,
    .mode  = (uint32_t) (l_flags & 0777),
    .uid = euid, .gid = egid, .cuid = euid, .cgid = egid,
    .size  = size,
    .host_id = -1,
    .cpid  = getpid(),
    .ctime = now(),
  };

  if (key != LINUX_IPC_PRIVATE) {
    char target[NAME_MAX + 1];
    snprintf(target, sizeof target, "%s.%d.m", kind_name[kind], id);
    key_path(dir, kind, key, link, sizeof link);
    if (symlink(target, link) < 0) {
      /*
       * Another process bound this key while we were building ours. It won -
       * the symlink is the binding - so ours is discarded and the lookup runs
       * again rather than leaving two objects where the guest asked for one.
       */
      sysv_close(out);
      destroy_object(dir, kind, id);
      if (errno == EEXIST)
        goto again;
      return -darwin_to_linux_errno(errno);
    }
  }
  return id;
}

int
sysv_data_open(enum sysv_kind kind, int id, int flags)
{
  char dir[PATH_MAX], path[PATH_MAX];
  int r;
  if ((r = here(dir, sizeof dir)) < 0)
    return r;
  obj_path(dir, kind, id, 'd', path, sizeof path);
  int fd = open(path, flags);
  if (fd < 0)
    return -darwin_to_linux_errno(errno);
  return fd;
}

int
sysv_remove(enum sysv_kind kind, int id, struct sysv_obj *o)
{
  char dir[PATH_MAX], path[PATH_MAX];
  int r;
  if ((r = here(dir, sizeof dir)) < 0)
    return r;

  /*
   * The key binding goes first, so nothing can find the object by name again,
   * and the files follow. Unlinking a mapped file does not disturb the mapping
   * - which is precisely Linux's rule for a removed segment: it stays until the
   * last attachment lets go, and then there is nothing left to collect.
   */
  if (o->m->key != LINUX_IPC_PRIVATE) {
    key_path(dir, kind, o->m->key, path, sizeof path);
    unlink(path);
  }
  o->m->removed = 1;
  o->m->ctime = now();
  destroy_object(dir, kind, id);
  return 0;
}

/*
 * Every object of a kind in this namespace. The directory is the table, so
 * listing it is the enumeration - there is no index to keep consistent with the
 * objects, because there is no index.
 */
int
sysv_list(enum sysv_kind kind, struct sysv_meta *out, int max)
{
  char dir[PATH_MAX];
  int found = 0;

  if (here(dir, sizeof dir) < 0)
    return 0;
  DIR *d = opendir(dir);
  if (!d)
    return 0;

  size_t pfxlen = strlen(kind_name[kind]);
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t n = strlen(e->d_name);
    if (n < pfxlen + 3 || strncmp(e->d_name, kind_name[kind], pfxlen) != 0)
      continue;
    if (e->d_name[n - 1] != 'm' || e->d_name[n - 2] != '.')
      continue;
    int id = -1;
    if (sscanf(e->d_name + pfxlen + 1, "%d", &id) != 1 || id < 0)
      continue;
    struct sysv_obj o;
    if (sysv_open(kind, id, &o) < 0)
      continue;
    if (out && found < max) {
      out[found] = *o.m;
      out[found].host_id = id;    /* the id the guest was given */
    }
    found++;
    sysv_close(&o);
  }
  closedir(d);
  return found;
}

void
sysv_count(enum sysv_kind kind, int *used, int *high, uint64_t *total)
{
  struct sysv_meta *all = calloc(SYSV_MAX_ID, sizeof *all);
  *used = 0; *high = 0; *total = 0;
  if (!all)
    return;
  int n = sysv_list(kind, all, SYSV_MAX_ID);
  for (int i = 0; i < n && i < SYSV_MAX_ID; i++) {
    (*used)++;
    if (all[i].host_id > *high)
      *high = all[i].host_id;
    *total += all[i].size;
  }
  free(all);
}

static void
rmtree(const char *dir)
{
  DIR *d = opendir(dir);
  if (d) {
    struct dirent *e;
    char path[PATH_MAX];
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
        continue;
      snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
      unlink(path);
    }
    closedir(d);
  }
  rmdir(dir);
}

/*
 * Semaphores have a Darwin array behind them, and unlinking a file does not
 * remove that. Every semaphore in the directory is released before the
 * directory is, or the host's tables keep them until it reboots - which is the
 * leak this whole arrangement exists to stop.
 */
static void
release_host_semaphores(const char *dir)
{
  DIR *d = opendir(dir);
  if (!d)
    return;
  struct dirent *e;
  char path[PATH_MAX];
  while ((e = readdir(d)) != NULL) {
    size_t n = strlen(e->d_name);
    if (n < 6 || strncmp(e->d_name, "sem.", 4) != 0)
      continue;
    if (e->d_name[n - 1] != 'm' || e->d_name[n - 2] != '.')
      continue;
    snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
      continue;
    struct sysv_meta m;
    if (read(fd, &m, sizeof m) == (ssize_t) sizeof m &&
        m.magic == SYSV_MAGIC && m.host_id >= 0)
      semctl(m.host_id, 0, IPC_RMID);
    close(fd);
  }
  closedir(d);
}

void
sysv_ns_destroy(uint64_t ino)
{
  char dir[PATH_MAX];
  ns_dir(ino, dir, sizeof dir);
  release_host_semaphores(dir);
  rmtree(dir);
}

/* Written when a namespace is made, so a sweep can tell whether it is over. */
void
sysv_ns_claim(uint64_t ino)
{
  char dir[PATH_MAX], path[PATH_MAX];
  ns_dir(ino, dir, sizeof dir);
  if (mkdir(dir, 0700) < 0 && errno != EEXIST)
    return;
  snprintf(path, sizeof path, "%s/.owner", dir);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  char buf[32];
  int n = snprintf(buf, sizeof buf, "%d\n", getpid());
  (void) !write(fd, buf, n);
  close(fd);
}

/* Destroy the namespace only if this process is the one that made it. */
void
sysv_ns_release_owned(uint64_t ino)
{
  char dir[PATH_MAX], path[PATH_MAX];
  ns_dir(ino, dir, sizeof dir);
  snprintf(path, sizeof path, "%s/.owner", dir);

  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return;                     /* the initial namespace, or not ours */
  char buf[32] = {0};
  ssize_t n = read(fd, buf, sizeof buf - 1);
  close(fd);
  if (n > 0 && (pid_t) atoi(buf) == getpid())
    sysv_ns_destroy(ino);
}

void
sysv_sweep(void)
{
  const char *tmp = getenv("TMPDIR");
  char base[PATH_MAX];
  snprintf(base, sizeof base, "%s", tmp && *tmp ? tmp : "/tmp");

  DIR *d = opendir(base);
  if (!d)
    return;

  char mine[64], dir[PATH_MAX], path[PATH_MAX];
  snprintf(mine, sizeof mine, "nabi-ipc-%s-", nabi_boot_tag());

  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strncmp(e->d_name, "nabi-ipc-", 9) != 0)
      continue;
    snprintf(dir, sizeof dir, "%s/%s", base, e->d_name);

    /*
     * A different boot session's, so nobody is in it by definition - the
     * processes are gone and so is anything they were sharing.
     */
    if (strncmp(e->d_name, mine, strlen(mine)) != 0) {
      release_host_semaphores(dir);
      rmtree(dir);
      continue;
    }

    /*
     * This boot's. The initial namespace has no owner recorded and is left
     * alone, exactly as a machine's own IPC objects outlive the programs that
     * made them. One created by unshare has its creator's pid, and is over when
     * that process is.
     */
    snprintf(path, sizeof path, "%s/.owner", dir);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
      continue;
    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    pid_t owner = n > 0 ? (pid_t) atoi(buf) : 0;
    if (owner > 0 && kill(owner, 0) < 0 && errno == ESRCH) {
      release_host_semaphores(dir);
      rmtree(dir);
    }
  }
  closedir(d);
}
