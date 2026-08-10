/*
 * mount(2), umount2(2), and the table they act on.
 * See include/mount.h for what a mount can be on a host with no mounting.
 */
#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "mount.h"
#include "cgroup.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/misc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Flags nabi can honour or can safely record. Anything else is refused. */
#define MS_KNOWN                                                              \
  (LINUX_MS_RDONLY | LINUX_MS_NOSUID | LINUX_MS_NODEV | LINUX_MS_NOEXEC |     \
   LINUX_MS_REMOUNT | LINUX_MS_BIND | LINUX_MS_MOVE | LINUX_MS_REC |          \
   LINUX_MS_SILENT | LINUX_MS_NOATIME | LINUX_MS_NODIRATIME |                 \
   LINUX_MS_RELATIME | LINUX_MS_STRICTATIME | LINUX_MS_PRIVATE |              \
   LINUX_MS_SHARED | LINUX_MS_SLAVE | LINUX_MS_UNBINDABLE)

static void
table_path(uint64_t ino, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-mnt-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) ino);
}

/*
 * The table lives in a file, like every other namespace's contents and for the
 * same reason: nabi's processes are separate host processes, so a mount made in
 * one has to be visible in the next. It is read on each lookup rather than
 * cached, because a mount made by a sibling has to be seen without anything
 * telling this process to go and look.
 */
static bool
table_load(uint64_t ino, struct mount_table *t)
{
  char path[PATH_MAX];
  table_path(ino, path, sizeof path);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return false;
  bool ok = read(fd, t, sizeof *t) == (ssize_t) sizeof *t;
  close(fd);
  return ok;
}

static void
table_store(uint64_t ino, const struct mount_table *t)
{
  char path[PATH_MAX], tmppath[PATH_MAX];
  table_path(ino, path, sizeof path);
  snprintf(tmppath, sizeof tmppath, "%s.new", path);

  int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  bool ok = write(fd, t, sizeof *t) == (ssize_t) sizeof *t;
  close(fd);
  if (ok)
    rename(tmppath, path);
  else
    unlink(tmppath);
}

static bool
current_table(struct mount_table *t)
{
  if (table_load(ns_ino_of(NS_MNT), t))
    return true;
  memset(t, 0, sizeof *t);
  t->next_id = 30;              /* Linux's ids start well above the roots */
  return false;
}

static size_t under(const char *path, const char *mnt);

/*
 * Peer group numbers are shared between namespaces, so the counter has to be
 * too - two namespaces handing out group 1 for unrelated mounts would make
 * them propagate to each other.
 */
static uint32_t
peer_group_new(void)
{
  char path[PATH_MAX];
  const char *tmp = getenv("TMPDIR");
  snprintf(path, sizeof path, "%s/nabi-mntpeer-%s",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag());

  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return 0;
  flock(fd, LOCK_EX);
  uint32_t next = 0;
  if (pread(fd, &next, sizeof next, 0) != (ssize_t) sizeof next || next == 0)
    next = 1;
  uint32_t mine = next++;
  (void) !pwrite(fd, &next, sizeof next, 0);
  flock(fd, LOCK_UN);
  close(fd);
  return mine;
}

/*
 * What a namespace's copy of a mount inherits, which is where propagation is
 * actually decided.
 *
 * A shared mount stays shared and stays in its group, so the copy and the
 * original are peers and events travel between them - that is the whole of
 * what `unshare -m` does *not* isolate, and why a container recipe starts by
 * making things private. A slave keeps listening to its master. A private
 * mount, or an unbindable one, has no relationship to keep.
 */
void
mount_ns_clone(uint64_t from_ino, uint64_t to_ino)
{
  struct mount_table t;
  if (!table_load(from_ino, &t)) {
    memset(&t, 0, sizeof t);
    t.next_id = 30;
  }
  for (uint32_t i = 0; i < t.n; i++) {
    if (t.m[i].propagation == LINUX_MS_SHARED)
      continue;                 /* same group: the copy is a peer */
    if (t.m[i].propagation == LINUX_MS_SLAVE)
      continue;                 /* still listening to the same master */
    t.m[i].peer = 0;
    t.m[i].master = 0;
  }
  table_store(to_ino, &t);
}

/* Every mount table of this boot, so an event can be given to peers. */
static int
each_table(uint64_t skip_ino, uint64_t *inos, int max)
{
  const char *tmp = getenv("TMPDIR");
  char base[PATH_MAX], prefix[64];
  snprintf(base, sizeof base, "%s", tmp && *tmp ? tmp : "/tmp");
  snprintf(prefix, sizeof prefix, "nabi-mnt-%s-", nabi_boot_tag());

  DIR *d = opendir(base);
  if (!d)
    return 0;
  int n = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL && n < max) {
    size_t pl = strlen(prefix);
    if (strncmp(e->d_name, prefix, pl) != 0)
      continue;
    if (strchr(e->d_name + pl, '.'))
      continue;                 /* the .new written during a store */
    uint64_t ino = strtoull(e->d_name + pl, NULL, 10);
    if (ino == 0 || ino == skip_ino)
      continue;
    inos[n++] = ino;
  }
  closedir(d);
  return n;
}

/*
 * Give an event to the peers of the mount it happened under.
 *
 * `parent_peer` is the group of the mount containing the target. A namespace
 * whose table has a member of that group is watching this place, so the same
 * entry is added there (or removed, when `add` is false). A slave receives but
 * does not send, which falls out of only ever looking at the parent's peer
 * group: a slave has a master rather than a group of its own.
 */
static void
propagate(uint32_t parent_peer, const struct mount_entry *e, bool add)
{
  if (parent_peer == 0)
    return;

  uint64_t inos[64];
  int n = each_table(ns_ino_of(NS_MNT), inos, 64);
  for (int i = 0; i < n; i++) {
    struct mount_table t;
    if (!table_load(inos[i], &t))
      continue;

    bool watching = false;
    for (uint32_t k = 0; k < t.n; k++)
      if (t.m[k].peer == parent_peer || t.m[k].master == parent_peer)
        watching = true;
    if (!watching)
      continue;

    int at = -1;
    for (uint32_t k = 0; k < t.n; k++)
      if (strcmp(t.m[k].target, e->target) == 0)
        at = (int) k;

    if (add) {
      if (at >= 0)
        t.m[at] = *e;
      else if (t.n < MOUNT_MAX)
        t.m[t.n++] = *e;
      else
        continue;
    } else {
      if (at < 0)
        continue;
      memmove(&t.m[at], &t.m[at + 1], (t.n - (uint32_t) at - 1) * sizeof t.m[0]);
      t.n--;
    }
    table_store(inos[i], &t);
  }
}

/* The mount a new target falls under, which is the one that propagates it. */
static uint32_t
parent_peer_of(const struct mount_table *t, const char *target)
{
  int best = -1;
  size_t best_len = 0;
  for (uint32_t i = 0; i < t->n; i++) {
    if (strcmp(t->m[i].target, target) == 0)
      continue;                 /* itself is not its own parent */
    size_t n = under(target, t->m[i].target);
    if (n > best_len) {
      best_len = n;
      best = (int) i;
    }
  }
  return best < 0 ? 0 : t->m[best].peer;
}

/*
 * Whether `path` is at or below `mnt`, matching whole components so that
 * /tmpfoo is not taken to be inside /tmp. Returns the length matched, or 0.
 */
static size_t
under(const char *path, const char *mnt)
{
  size_t n = strlen(mnt);
  if (n == 1 && mnt[0] == '/')
    return strncmp(path, "/", 1) == 0 ? 1 : 0;
  if (strncmp(path, mnt, n) != 0)
    return 0;
  if (path[n] == '\0' || path[n] == '/')
    return n;
  return 0;
}

/* The mount a path falls in, or -1. Longest target wins. */
static int
find_mount(const struct mount_table *t, const char *guest_path)
{
  int best = -1;
  size_t best_len = 0;
  for (uint32_t i = 0; i < t->n; i++) {
    if (t->m[i].hostdir[0] == '\0')
      continue;                 /* served elsewhere; nothing to rewrite */
    size_t n = under(guest_path, t->m[i].target);
    if (n > best_len) {
      best_len = n;
      best = (int) i;
    }
  }
  return best;
}

bool
mount_resolve(const char *guest_path, char *out, size_t outsz, bool *rdonly)
{
  struct mount_table t;
  if (!current_table(&t) || t.n == 0)
    return false;

  int i = find_mount(&t, guest_path);
  if (i < 0)
    return false;

  size_t n = under(guest_path, t.m[i].target);
  const char *rest = guest_path + n;
  snprintf(out, outsz, "%s%s", t.m[i].hostdir, rest);
  if (rdonly)
    *rdonly = (t.m[i].flags & LINUX_MS_RDONLY) != 0;
  return true;
}

bool
mount_is_rdonly(const char *guest_path)
{
  struct mount_table t;
  if (!current_table(&t) || t.n == 0)
    return false;
  int i = find_mount(&t, guest_path);
  return i >= 0 && (t.m[i].flags & LINUX_MS_RDONLY) != 0;
}

static const char *
opts_of(uint32_t flags)
{
  static char buf[96];
  snprintf(buf, sizeof buf, "%s%s%s%s",
           (flags & LINUX_MS_RDONLY) ? "ro" : "rw",
           (flags & LINUX_MS_NOSUID) ? ",nosuid" : "",
           (flags & LINUX_MS_NODEV)  ? ",nodev"  : "",
           (flags & LINUX_MS_NOEXEC) ? ",noexec" : "");
  return buf;
}

/*
 * The mounts nabi always has, whether or not anything asked for them. They are
 * as real as any entry below - the rootfs is served, /dev and /tmp are passed
 * through - and a listing that omitted them would describe a machine the guest
 * is not running on.
 */
static const struct { const char *src, *tgt, *type, *opts; } base[] = {
  { "rootfs",    "/",     "rootfs",    "rw" },
  { "devtmpfs",  "/dev",  "devtmpfs",  "rw,nosuid" },
  { "tmpfs",     "/tmp",  "tmpfs",     "rw,nosuid,nodev" },
  { "proc",      "/proc", "proc",      "rw,nosuid,nodev,noexec,relatime" },
  { "sysfs",     "/sys",  "sysfs",     "rw,nosuid,nodev,noexec,relatime" },
};

int
mount_build_mounts(char *out, size_t n)
{
  int len = 0;
  for (size_t i = 0; i < sizeof base / sizeof base[0] && (size_t) len < n; i++)
    len += snprintf(out + len, n - (size_t) len, "%s %s %s %s 0 0\n",
                    base[i].src, base[i].tgt, base[i].type, base[i].opts);

  struct mount_table t;
  if (current_table(&t))
    for (uint32_t i = 0; i < t.n && (size_t) len < n; i++)
      len += snprintf(out + len, n - (size_t) len, "%s %s %s %s 0 0\n",
                      t.m[i].source, t.m[i].target, t.m[i].type,
                      opts_of(t.m[i].flags));
  return len;
}

int
mount_build_mountinfo(char *out, size_t n)
{
  int len = 0;
  int id = 1;
  for (size_t i = 0; i < sizeof base / sizeof base[0] && (size_t) len < n; i++, id++)
    len += snprintf(out + len, n - (size_t) len,
                    "%d 0 0:%d / %s %s - %s %s %s\n",
                    id, id + 1, base[i].tgt, base[i].opts,
                    base[i].type, base[i].src, base[i].opts);

  struct mount_table t;
  if (current_table(&t))
    for (uint32_t i = 0; i < t.n && (size_t) len < n; i++) {
      const char *o = opts_of(t.m[i].flags);

      /*
       * The optional fields, which are where propagation is reported and the
       * only place anything can read it back. A private mount has none, which
       * is why it is written as their absence rather than as a word.
       */
      char prop[64] = "";
      int pl = 0;
      if (t.m[i].peer)
        pl += snprintf(prop + pl, sizeof prop - (size_t) pl, " shared:%u",
                       t.m[i].peer);
      if (t.m[i].master)
        pl += snprintf(prop + pl, sizeof prop - (size_t) pl, " master:%u",
                       t.m[i].master);
      if (t.m[i].propagation == LINUX_MS_UNBINDABLE)
        pl += snprintf(prop + pl, sizeof prop - (size_t) pl, " unbindable");

      len += snprintf(out + len, n - (size_t) len,
                      "%u 1 0:%u / %s %s%s - %s %s %s\n",
                      t.m[i].id, t.m[i].id, t.m[i].target, o, prop,
                      t.m[i].type, t.m[i].source, o);
    }
  return len;
}

/* Mounting is an administrative act, and a user namespace does not make one an
 * administrator here - see include/mount.h. */
static bool
may_mount(void)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  bool ok = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ok;
}

static bool
type_is(const char *type, const char *want)
{
  return type && strcmp(type, want) == 0;
}

DEFINE_SYSCALL(mount, gstr_t, source_ptr, gstr_t, target_ptr, gstr_t, type_ptr,
               unsigned long, flags, gaddr_t, data_ptr)
{
  char source[MOUNT_PATH_MAX] = "none";
  char target[MOUNT_PATH_MAX];
  char type[16] = "";

  if (!may_mount())
    return -LINUX_EPERM;

  if (target_ptr == 0)
    return -LINUX_EFAULT;
  if (strncpy_from_user(target, target_ptr, sizeof target) < 0)
    return -LINUX_EFAULT;
  if (source_ptr != 0 && strncpy_from_user(source, source_ptr, sizeof source) < 0)
    return -LINUX_EFAULT;
  if (type_ptr != 0 && strncpy_from_user(type, type_ptr, sizeof type) < 0)
    return -LINUX_EFAULT;
  if (target[0] != '/')
    return -LINUX_EINVAL;

  if (flags & ~(unsigned long) MS_KNOWN)
    return -LINUX_EINVAL;

  struct mount_table t;
  current_table(&t);

  /* Find an existing mount on exactly this target. */
  int at = -1;
  for (uint32_t i = 0; i < t.n; i++)
    if (strcmp(t.m[i].target, target) == 0)
      at = (int) i;

  /*
   * Setting a propagation type, which changes a mount's relationship to other
   * namespaces rather than what is mounted.
   *
   * The rootfs is allowed an entry of its own here even though nothing is
   * mounted on it, because `mount --make-rshared /` is how a machine declares
   * that its mounts should reach the namespaces made from it - and with no
   * entry for "/" there would be nothing for that to be recorded on, and
   * nothing under it would ever propagate.
   */
  unsigned long prop = flags & (LINUX_MS_PRIVATE | LINUX_MS_SHARED |
                                LINUX_MS_SLAVE | LINUX_MS_UNBINDABLE);
  if (prop && !(flags & LINUX_MS_BIND)) {
    if (at < 0) {
      if (t.n == MOUNT_MAX)
        return -LINUX_ENOSPC;
      at = (int) t.n++;
      memset(&t.m[at], 0, sizeof t.m[at]);
      snprintf(t.m[at].target, sizeof t.m[at].target, "%s", target);
      snprintf(t.m[at].source, sizeof t.m[at].source, "%s",
               strcmp(target, "/") == 0 ? "rootfs" : "none");
      snprintf(t.m[at].type, sizeof t.m[at].type, "%s",
               strcmp(target, "/") == 0 ? "rootfs" : "none");
      t.m[at].id = t.next_id++;
    }

    switch (prop) {
    case LINUX_MS_SHARED:
      /* A group of its own if it has none; peers join it by being copies. */
      if (t.m[at].peer == 0)
        t.m[at].peer = peer_group_new();
      t.m[at].master = 0;
      break;
    case LINUX_MS_SLAVE:
      /* Stops sending and starts listening to what it used to be a peer of.
       * A mount that was never shared has nothing to be a slave of, and Linux
       * makes it private rather than failing. */
      t.m[at].master = t.m[at].peer;
      t.m[at].peer = 0;
      break;
    case LINUX_MS_PRIVATE:
    case LINUX_MS_UNBINDABLE:
      t.m[at].peer = 0;
      t.m[at].master = 0;
      break;
    default:
      return -LINUX_EINVAL;     /* more than one type at once is not a type */
    }
    t.m[at].propagation = (uint32_t) prop;
    table_store(ns_ino_of(NS_MNT), &t);
    return 0;
  }

  if (flags & LINUX_MS_REMOUNT) {
    if (at < 0)
      return -LINUX_EINVAL;
    t.m[at].flags = (uint32_t) (flags & ~(unsigned long) LINUX_MS_REMOUNT);
    table_store(ns_ino_of(NS_MNT), &t);
    return 0;
  }

  /*
   * MS_MOVE: the mount at `source` appears at `target` instead.
   *
   * In a table of prefix rewrites this is what it sounds like - the entry keeps
   * everything about itself and changes where it is seen from. Nothing is
   * unmounted and nothing is mounted, which matters: a moved bind keeps the
   * host object it resolved at mount time, so moving it cannot fail the way
   * mounting it again might.
   *
   * Everything at or below the source moves with it. A flat table would
   * otherwise leave a mount on /a/b pointing at a path that has just been
   * uncovered, while Linux carries it to /c/b - the subtree moves as a subtree,
   * which is the only reading under which the mounts inside one survive.
   */
  if (flags & LINUX_MS_MOVE) {
    if (source[0] != '/')
      return -LINUX_EINVAL;

    int from = -1;
    for (uint32_t i = 0; i < t.n; i++)
      if (strcmp(t.m[i].target, source) == 0)
        from = (int) i;
    if (from < 0)
      return -LINUX_EINVAL;     /* not a mount point, as Linux says */

    /*
     * Into its own subtree, or onto itself, is refused. A mount that contained
     * the place it was mounted at could not be resolved at all - the longest
     * match would be the mount, whose own path now runs through it.
     */
    if (under(target, source))
      return -LINUX_EINVAL;

    size_t slen = strlen(source);
    for (uint32_t i = 0; i < t.n; i++) {
      if (!under(t.m[i].target, source))
        continue;
      char moved[MOUNT_PATH_MAX];
      snprintf(moved, sizeof moved, "%s%s", target, t.m[i].target + slen);
      snprintf(t.m[i].target, sizeof t.m[i].target, "%s", moved);
    }
    table_store(ns_ino_of(NS_MNT), &t);
    return 0;
  }

  if (t.n == MOUNT_MAX)
    return -LINUX_ENOSPC;

  struct mount_entry e;
  memset(&e, 0, sizeof e);
  snprintf(e.target, sizeof e.target, "%s", target);
  e.flags = (uint32_t) flags;
  e.id = t.next_id++;

  if (flags & LINUX_MS_BIND) {
    /*
     * The source is resolved once, here, to the host object it names. A bind
     * binds the object rather than the name - if the source is later moved or
     * itself unmounted, what was bound stays bound, which is Linux's behaviour
     * and also the only one available when the answer has to be a host path.
     */
    char host[PATH_MAX];
    if (source[0] != '/')
      return -LINUX_EINVAL;

    /* Unbindable is the one propagation type that is enforced at the moment it
     * matters: it exists so that a recursive bind cannot copy a subtree into
     * itself, which would not terminate. */
    for (uint32_t i = 0; i < t.n; i++)
      if (t.m[i].propagation == LINUX_MS_UNBINDABLE &&
          strcmp(t.m[i].target, source) == 0)
        return -LINUX_EINVAL;

    int gr = guest_to_host_path(source, host, sizeof host);
    if (gr < 0)
      return gr;
    struct stat st;
    if (stat(host, &st) < 0)
      return -darwin_to_linux_errno(errno);
    snprintf(e.source, sizeof e.source, "%s", source);
    snprintf(e.hostdir, sizeof e.hostdir, "%s", host);
    snprintf(e.type, sizeof e.type, "none");
  } else if (type_is(type, "tmpfs")) {
    char dirtpl[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    snprintf(dirtpl, sizeof dirtpl, "%s/nabi-tmpfs-XXXXXX",
             tmp && *tmp ? tmp : "/tmp");
    if (mkdtemp(dirtpl) == NULL)
      return -darwin_to_linux_errno(errno);
    snprintf(e.source, sizeof e.source, "tmpfs");
    snprintf(e.hostdir, sizeof e.hostdir, "%s", dirtpl);
    snprintf(e.type, sizeof e.type, "tmpfs");
  } else if (type_is(type, "cgroup2") || type_is(type, "cgroup")) {
    /*
     * The one hierarchy, wherever it is asked for. cgroups are not per-mount:
     * mounting cgroup2 twice shows the same tree, which is what the mount is
     * for - a place to see it from.
     */
    char host[PATH_MAX];
    int cr = cgroup_hierarchy(host, sizeof host);
    if (cr < 0)
      return cr;
    snprintf(e.source, sizeof e.source, "cgroup2");
    snprintf(e.hostdir, sizeof e.hostdir, "%s", host);
    snprintf(e.type, sizeof e.type, "cgroup2");
  } else if (type_is(type, "proc") || type_is(type, "sysfs") ||
             type_is(type, "devtmpfs") || type_is(type, "devpts") ||
             type_is(type, "mqueue") || type_is(type, "securityfs") ||
             type_is(type, "debugfs")) {
    /*
     * Already served, or harmlessly absent. Recorded with no host directory,
     * so resolution ignores it and only the listing changes - which is the
     * point: a container that mounts /proc and cannot then find it in
     * /proc/mounts decides the mount failed.
     */
    snprintf(e.source, sizeof e.source, "%s", source);
    snprintf(e.type, sizeof e.type, "%s", type);
  } else {
    /* A real filesystem, and there is no block layer here to give it. */
    return -LINUX_ENODEV;
  }

  uint32_t pp = parent_peer_of(&t, target);

  if (at >= 0)
    t.m[at] = e;                /* mounting over a target replaces it */
  else
    t.m[t.n++] = e;
  table_store(ns_ino_of(NS_MNT), &t);

  /* And to everyone watching the place it landed in. */
  propagate(pp, &e, true);
  return 0;
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
      struct stat st;
      if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
        rmtree(path);
      else
        unlink(path);
    }
    closedir(d);
  }
  rmdir(dir);
}

DEFINE_SYSCALL(umount2, gstr_t, target_ptr, int, flags)
{
  char target[MOUNT_PATH_MAX];

  if (!may_mount())
    return -LINUX_EPERM;
  if (strncpy_from_user(target, target_ptr, sizeof target) < 0)
    return -LINUX_EFAULT;

  struct mount_table t;
  if (!current_table(&t))
    return -LINUX_EINVAL;

  for (uint32_t i = 0; i < t.n; i++) {
    if (strcmp(t.m[i].target, target) != 0)
      continue;
    /* A tmpfs is its contents, and they go with it - which is the property
     * anything that mounted one was relying on. */
    if (strcmp(t.m[i].type, "tmpfs") == 0 && t.m[i].hostdir[0])
      rmtree(t.m[i].hostdir);

    struct mount_entry gone = t.m[i];
    uint32_t pp = parent_peer_of(&t, gone.target);

    memmove(&t.m[i], &t.m[i + 1], (t.n - i - 1) * sizeof t.m[0]);
    t.n--;
    table_store(ns_ino_of(NS_MNT), &t);

    propagate(pp, &gone, false);
    return 0;
  }
  return -LINUX_EINVAL;         /* not a mount point, as Linux says */
}
