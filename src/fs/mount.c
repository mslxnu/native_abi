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

/*
 * pivot_root's effect on the mount table.
 *
 * The root moves to put_old and new_root becomes the root, so every target in
 * the table has to be re-expressed in the namespace that results. Two cases,
 * and they are the whole of it:
 *
 *   - a mount that was under new_root keeps its object and loses the prefix.
 *     /newroot/proc becomes /proc.
 *   - everything else was under the old root, which is now reachable only at
 *     put_old, so it gains that prefix. /dev becomes /old/dev.
 *
 * And the old root itself becomes an entry, pointing at the host directory it
 * always was. That entry is what makes put_old real rather than an empty
 * directory the guest was told about - a caller that pivots and then unmounts
 * the old root through that path is doing something that means what it says.
 *
 * This rewrites state the whole mount namespace shares, which is right for
 * pivot_root and would be wrong for chroot: pivot_root restructures the
 * namespace, chroot only changes one process's view of it. The divergence worth
 * naming is that a *second* process already in this namespace keeps its own
 * root descriptor and would now see rewritten targets against an unchanged
 * root. Container runtimes pivot immediately after unshare, with one process in
 * the namespace, which is the case this serves.
 */
bool
mount_pivot(const char *new_root, const char *put_old_after,
            const char *old_root_host)
{
  struct mount_table t;
  current_table(&t);

  for (uint32_t i = 0; i < t.n; i++) {
    char re[sizeof t.m[i].target];
    size_t n = under(t.m[i].target, new_root);
    if (n > 0) {
      const char *rest = t.m[i].target + n;
      snprintf(re, sizeof re, "%s", rest[0] ? rest : "/");
    } else {
      snprintf(re, sizeof re, "%s%s", put_old_after,
               strcmp(t.m[i].target, "/") == 0 ? "" : t.m[i].target);
    }
    snprintf(t.m[i].target, sizeof t.m[i].target, "%s", re);
  }

  if (t.n == MOUNT_MAX)
    return false;
  struct mount_entry e;
  memset(&e, 0, sizeof e);
  snprintf(e.target, sizeof e.target, "%s", put_old_after);
  snprintf(e.hostdir, sizeof e.hostdir, "%s", old_root_host);
  snprintf(e.source, sizeof e.source, "/dev/root");
  snprintf(e.type, sizeof e.type, "rootfs");
  e.id = t.next_id++;
  t.m[t.n++] = e;

  table_store(ns_ino_of(NS_MNT), &t);
  return true;
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

/*
 * What backs a mount of a given filesystem type.
 *
 * Split out because two callers ask it: mount(2), and fsmount() by way of the
 * context fsopen() named a type on. A second answer here would be a second set
 * of filesystems NABI claims to support.
 */
static int
backing_for_type(const char *type, const char *source, unsigned long flags,
                 bool probe_only, struct mount_entry *e)
{
  if (type_is(type, "tmpfs")) {
    char dirtpl[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    snprintf(dirtpl, sizeof dirtpl, "%s/nabi-tmpfs-XXXXXX",
             tmp && *tmp ? tmp : "/tmp");
    if (mkdtemp(dirtpl) == NULL)
      return -darwin_to_linux_errno(errno);
    snprintf(e->source, sizeof e->source, "tmpfs");
    snprintf(e->hostdir, sizeof e->hostdir, "%s", dirtpl);
    snprintf(e->type, sizeof e->type, "tmpfs");
    return 0;
  }
  if (type_is(type, "cgroup2") || type_is(type, "cgroup")) {
    /*
     * The one hierarchy, wherever it is asked for. cgroups are not per-mount:
     * mounting cgroup2 twice shows the same tree, which is what the mount is
     * for - a place to see it from.
     */
    char host[PATH_MAX];
    int cr = cgroup_hierarchy(host, sizeof host);
    if (cr < 0)
      return cr;
    snprintf(e->source, sizeof e->source, "cgroup2");
    snprintf(e->hostdir, sizeof e->hostdir, "%s", host);
    snprintf(e->type, sizeof e->type, "cgroup2");
    return 0;
  }
  if (type_is(type, "devtmpfs")) {
    /*
     * The kernel's device tree, which here is the host's /dev. Backing it with
     * the real /dev is what makes a container's own /dev reach the same
     * devices the passthrough /dev already does - /dev/binder, /dev/null, and
     * the rest are the actual host objects, not copies of them.
     */
    snprintf(e->source, sizeof e->source, "%s", source);
    snprintf(e->hostdir, sizeof e->hostdir, "%s", "/dev");
    snprintf(e->type, sizeof e->type, "%s", type);
    return 0;
  }
  if (type_is(type, "devpts")) {
    /*
     * The pty slave side, as the same rewrite that serves the passthrough /dev
     * sees it: Darwin has no /dev/pts directory, so the number underneath is
     * rewritten to the host's /dev/ttysNNN during path resolution. Backing
     * with "/dev" is enough for the rewrite to find it.
     */
    snprintf(e->source, sizeof e->source, "%s", source);
    snprintf(e->hostdir, sizeof e->hostdir, "%s", "/dev");
    snprintf(e->type, sizeof e->type, "%s", type);
    return 0;
  }
  if (type_is(type, "binderfs")) {
    /* The binder control files, which live at /dev/binderfs on the host. */
    snprintf(e->source, sizeof e->source, "%s", source);
    snprintf(e->hostdir, sizeof e->hostdir, "%s", "/dev/binderfs");
    snprintf(e->type, sizeof e->type, "%s", type);
    return 0;
  }
  if (type_is(type, "proc") || type_is(type, "sysfs") ||
      type_is(type, "mqueue") || type_is(type, "securityfs") ||
      type_is(type, "debugfs")) {
    /*
     * Already served, or harmlessly absent. Recorded with no host directory,
     * so resolution ignores it and only the listing changes - which is the
     * point: a container that mounts /proc and cannot then find it in
     * /proc/mounts decides the mount failed.
     */
    snprintf(e->source, sizeof e->source, "%s", source);
    snprintf(e->type, sizeof e->type, "%s", type);
    return 0;
  }
  /*
   * A filesystem in a file, which the host is asked to mount. Android ships
   * this way and `waydroid session start` mounts system.img before it does
   * anything else; there is no block layer here to give it any other way.
   */
  if (type_is(type, "ext4") || type_is(type, "ext3") || type_is(type, "ext2")) {
    /*
     * A type probe - fsopen naming a filesystem before it has been told what to
     * mount - is answered on the type alone: there is nothing to attach yet,
     * and calling the type unknown would send the caller away from something
     * that does work once it says what to mount. Said explicitly rather than
     * inferred from the source not looking like a path, which would also make
     * mount(2) with a relative source succeed while mounting nothing.
     */
    if (probe_only) {
      snprintf(e->type, sizeof e->type, "%s", type);
      return 0;
    }

    /*
     * A loop device names the file it was bound to, and that name is already
     * the host's - it was taken from the descriptor at the time. This is the
     * form util-linux arrives in: it binds the device itself and then mounts
     * the device, never the file.
     */
    char host_img[PATH_MAX];
    if (!loop_backing(source, host_img, sizeof host_img)) {
      if (source[0] != '/' ||
          guest_to_host_path(source, host_img, sizeof host_img) != 0)
        return -LINUX_ENOENT;
    }

    /*
     * Read-only, and a writable mount is refused rather than downgraded. A
     * guest told its mount succeeded would find out otherwise at the first
     * write, somewhere else entirely.
     */
    if (!(flags & LINUX_MS_RDONLY))
      return -LINUX_EROFS;

    char dev[64], dir[PATH_MAX];
    int r = image_mount_ro(host_img, dev, sizeof dev, dir, sizeof dir);
    if (r < 0)
      return r;

    snprintf(e->source, sizeof e->source, "%s", source);
    snprintf(e->hostdir, sizeof e->hostdir, "%s", dir);
    snprintf(e->hostdev, sizeof e->hostdev, "%s", dev);
    snprintf(e->type, sizeof e->type, "%s", type);
    return 0;
  }

  /* A real filesystem, and there is no block layer here to give it. */
  return -LINUX_ENODEV;
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
  } else {
    /* Everything a filesystem *type* can be here, which is also everything
     * fsopen can name - so the two ask the same function rather than growing
     * two answers that could disagree. */
    int br = backing_for_type(type, source, flags, false, &e);
    if (br < 0)
      return br;
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
    /*
     * An image mount is a host mount and an attached device, and both have to
     * go. If the filesystem is busy it does not go, and the mount stays: saying
     * it was unmounted and dropping the record would strand the host mount and
     * its device with nothing left that knows about them. EBUSY is what Linux
     * answers for a mount something still has open.
     */
    if (t.m[i].hostdev[0] && !image_unmount(t.m[i].hostdev, t.m[i].hostdir))
      return -LINUX_EBUSY;

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

/* ------------------------------------------------------- mount_setattr */

/*
 * mount_setattr: changing a mount's attributes after it exists.
 *
 * This is umount's opposite number and mount(2)'s successor for the flags half
 * of the job. What makes it worth having rather than a synonym for a remount is
 * that it is *precise* - it says which attributes to set and which to clear,
 * instead of handing over a whole flag word and hoping the ones not mentioned
 * survive - and that it can descend a subtree in one call.
 *
 * Both of those land well here, because a mount is a row in a table: setting an
 * attribute is a masked update of that row, and AT_RECURSIVE is the same update
 * on every row whose target falls under it. MS_RDONLY is honoured by path
 * resolution already, so making a mount read-only this way genuinely refuses
 * writes rather than recording an intention.
 *
 * MOUNT_ATTR_IDMAP is refused. It asks for the mount's uids to be shifted
 * through a user namespace, which needs the file's owner to be translated on
 * every access, and the identity nabi keeps in an xattr is not something a
 * mount can re-map. Accepting it would hand back a mount whose ownership a
 * caller believes was shifted and which behaves as though it were not.
 */
DEFINE_SYSCALL(mount_setattr, int, dfd, gstr_t, path_ptr, unsigned int, flags,
               gaddr_t, uattr, size_t, usize)
{
  if (!may_mount())
    return -LINUX_EPERM;
  /* AT_RECURSIVE is the only one of these that changes what happens; the
   * others are about how the path is resolved, which a table of prefixes does
   * the same way regardless. */
  if (flags & ~(unsigned) (LINUX_AT_RECURSIVE | LINUX_AT_SYMLINK_NOFOLLOW |
                           LINUX_AT_EMPTY_PATH | LINUX_AT_NO_AUTOMOUNT))
    return -LINUX_EINVAL;
  if (usize < sizeof(struct l_mount_attr))
    return -LINUX_EINVAL;

  struct l_mount_attr a;
  if (copy_from_user(&a, uattr, sizeof a))
    return -LINUX_EFAULT;
  /* A caller from a future with more fields must not be told its extra request
   * was honoured. */
  for (size_t i = sizeof a; i < usize; i++) {
    char pad;
    if (copy_from_user(&pad, uattr + i, 1))
      return -LINUX_EFAULT;
    if (pad != 0)
      return -LINUX_E2BIG;
  }

  const uint64_t known = LINUX_MOUNT_ATTR_RDONLY | LINUX_MOUNT_ATTR_NOSUID |
                         LINUX_MOUNT_ATTR_NODEV | LINUX_MOUNT_ATTR_NOEXEC |
                         LINUX_MOUNT_ATTR__ATIME | LINUX_MOUNT_ATTR_NODIRATIME |
                         LINUX_MOUNT_ATTR_IDMAP | LINUX_MOUNT_ATTR_NOSYMFOLLOW;
  if ((a.attr_set | a.attr_clr) & ~known)
    return -LINUX_EINVAL;
  /* Setting and clearing the same attribute has no answer, so it is refused
   * rather than resolved by whichever happens to be applied second. */
  if (a.attr_set & a.attr_clr & ~(uint64_t) LINUX_MOUNT_ATTR__ATIME)
    return -LINUX_EINVAL;
  /* The atime bits are one choice spelled in three values, so clearing them is
   * clearing the field, and asking to set two at once is asking for two. */
  if ((a.attr_set & LINUX_MOUNT_ATTR__ATIME) == LINUX_MOUNT_ATTR__ATIME)
    return -LINUX_EINVAL;
  if (a.attr_set & LINUX_MOUNT_ATTR_IDMAP)
    return -LINUX_EINVAL;       /* see above: cannot be honoured, so refused */

  char target[MOUNT_PATH_MAX];
  if (strncpy_from_user(target, path_ptr, sizeof target) < 0)
    return -LINUX_EFAULT;
  /*
   * An absolute path, as mount(2) here also requires. A dirfd-relative one
   * would have to be resolved against a descriptor's path, and the mount table
   * is keyed by the guest path a mount answers to - so a relative name has
   * nothing to match against until that resolution exists.
   */
  if (target[0] != '/')
    return -LINUX_EINVAL;
  (void) dfd;

  struct mount_table t;
  if (!current_table(&t))
    return -LINUX_EINVAL;

  /* Which flags a mount carries, in the words the table already speaks. */
  uint32_t set = 0, clr = 0;
  if (a.attr_set & LINUX_MOUNT_ATTR_RDONLY) set |= LINUX_MS_RDONLY;
  if (a.attr_set & LINUX_MOUNT_ATTR_NOSUID) set |= LINUX_MS_NOSUID;
  if (a.attr_set & LINUX_MOUNT_ATTR_NODEV)  set |= LINUX_MS_NODEV;
  if (a.attr_set & LINUX_MOUNT_ATTR_NOEXEC) set |= LINUX_MS_NOEXEC;
  if (a.attr_clr & LINUX_MOUNT_ATTR_RDONLY) clr |= LINUX_MS_RDONLY;
  if (a.attr_clr & LINUX_MOUNT_ATTR_NOSUID) clr |= LINUX_MS_NOSUID;
  if (a.attr_clr & LINUX_MOUNT_ATTR_NODEV)  clr |= LINUX_MS_NODEV;
  if (a.attr_clr & LINUX_MOUNT_ATTR_NOEXEC) clr |= LINUX_MS_NOEXEC;

  bool found = false;
  for (uint32_t i = 0; i < t.n; i++) {
    bool hit = strcmp(t.m[i].target, target) == 0;
    if (!hit && (flags & LINUX_AT_RECURSIVE))
      hit = under(t.m[i].target, target) > 0;
    if (!hit)
      continue;
    found = true;
    t.m[i].flags = (t.m[i].flags & ~clr) | set;
    if (a.propagation)
      t.m[i].propagation = (uint32_t) a.propagation;
  }
  if (!found)
    return -LINUX_EINVAL;       /* not a mount point, as Linux says */

  table_store(ns_ino_of(NS_MNT), &t);
  return 0;
}

/* ----------------------------------------------------------- listmount */

/*
 * listmount: the ids of the mounts under one mount.
 *
 * The newer half of the pair whose other half is statmount - one says which
 * mounts exist, the other describes one of them. Reading /proc/mounts answers
 * the same question, and this exists because parsing it is a text format that
 * has to stay compatible forever; a list of numbers does not.
 *
 * Which makes it cheap here: the mounts already are a list of numbered rows,
 * and /proc/mounts is built from the same table, so the two cannot disagree.
 */
DEFINE_SYSCALL(listmount, gaddr_t, req_ptr, gaddr_t, ids_ptr,
               size_t, nr_ids, unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;

  struct l_mnt_id_req req;
  memset(&req, 0, sizeof req);
  uint32_t size;
  if (copy_from_user(&size, req_ptr, sizeof size))
    return -LINUX_EFAULT;
  if (size < LINUX_MNT_ID_REQ_SIZE_VER0)
    return -LINUX_EINVAL;
  if (copy_from_user(&req, req_ptr, sizeof req > size ? size : sizeof req))
    return -LINUX_EFAULT;

  struct mount_table t;
  if (!current_table(&t))
    return 0;                   /* no mounts of its own is not an error */

  /*
   * The root request lists everything; anything else lists what is *under* the
   * mount named, which for a table of path prefixes is exactly the entries
   * whose target falls inside its target and is not it.
   */
  const char *parent = NULL;
  if (req.mnt_id != LINUX_LSMT_ROOT) {
    for (uint32_t i = 0; i < t.n; i++) {
      if (t.m[i].id == (uint32_t) req.mnt_id) {
        parent = t.m[i].target;
        break;
      }
    }
    if (!parent)
      return -LINUX_ENOENT;
  }

  size_t n = 0;
  for (uint32_t i = 0; i < t.n && n < nr_ids; i++) {
    if (parent) {
      if (strcmp(t.m[i].target, parent) == 0 || under(t.m[i].target, parent) == 0)
        continue;
    }
    uint64_t id = t.m[i].id;
    if (copy_to_user(ids_ptr + n * sizeof id, &id, sizeof id))
      return -LINUX_EFAULT;
    n++;
  }
  return (int) n;
}

/* ======================================================== the new mount API */

/*
 * fsopen, fsconfig, fsmount, open_tree, move_mount - Linux's second way to
 * mount something, and the reason it exists is worth stating because it decides
 * how it is built here.
 *
 * mount(2) does everything in one call: name a filesystem, configure it, and
 * attach it, with one errno to explain whichever part failed. The new API takes
 * those apart. fsopen names a type and gives back a *context*; fsconfig
 * configures it one parameter at a time, so a bad option is reported against
 * that option; fsmount turns a configured context into a mount that exists but
 * is attached nowhere; move_mount attaches it. open_tree is the same idea from
 * the other end - it takes an existing mount and hands back a detached copy.
 *
 * So there are two new kinds of object a guest holds by descriptor: a context
 * being configured, and a mount that exists but has no place yet. Both are
 * files here, unlinked at once, with a magic in the header - the same shape as
 * the POSIX message queues, and for the same reasons. The descriptor is the
 * object, so it survives fork and the exec arm64's fork is built on, it goes
 * when the guest closes it, and nothing here has to track which descriptors are
 * live.
 *
 * fsconfig was not asked for and is implemented anyway, because without it the
 * other two are unreachable: a context must be created before fsmount will take
 * it, and FSCONFIG_CMD_CREATE is the only thing that creates one. Shipping
 * fsopen and fsmount without it would be shipping a chain with a missing link.
 */

#define FSCTX_MAGIC    0x6673630au
#define DETACHED_MAGIC 0x646d6e74u

struct fsctx_hdr {
  uint32_t magic;
  uint32_t created;             /* FSCONFIG_CMD_CREATE has been issued */
  char     type[16];
  char     source[MOUNT_PATH_MAX];
};

struct detached_hdr {
  uint32_t magic;
  uint32_t pad;
  struct mount_entry e;
};

/*
 * Whether a descriptor is one of the objects above.
 *
 * They are backed by temp files holding a header nabi wrote, and a guest that
 * reads one gets those bytes - its own kernel's bookkeeping, served as file
 * contents. On Linux, reading an fs_context descriptor returns the messages the
 * filesystem produced while being configured, and EAGAIN when there are none.
 *
 * util-linux reads it after every step. Handed nabi's header it read the magic,
 * then read 0 for ever after and never stopped asking - a mount that hung
 * rather than failed, and only reachable once fsopen started accepting a
 * filesystem it could really provide.
 */
bool
mount_is_context_fd(int fd)
{
  uint32_t magic;
  if (pread(fd, &magic, sizeof magic, 0) != (ssize_t) sizeof magic)
    return false;
  return magic == FSCTX_MAGIC || magic == DETACHED_MAGIC;
}

/* A file nothing else can reach, whose descriptor is the object. */
static int
anon_file(const char *what)
{
  const char *tmp = getenv("TMPDIR");
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/nabi-%s-%s-XXXXXX",
           tmp && *tmp ? tmp : "/tmp", what, nabi_boot_tag());
  int fd = mkstemp(path);
  if (fd < 0)
    return -darwin_to_linux_errno(errno);
  unlink(path);
  return fd;
}

static int
read_hdr(int fd, void *hdr, size_t n, uint32_t magic)
{
  if (pread(fd, hdr, n, 0) != (ssize_t) n)
    /* A descriptor that is not one at all is EBADF, which is what Linux says
     * and what a caller probing for the syscall's existence is written to
     * expect; EINVAL is for a descriptor that exists and is the wrong kind. */
    return errno == EBADF ? -LINUX_EBADF : -LINUX_EINVAL;
  uint32_t got;
  memcpy(&got, hdr, sizeof got);
  if (got != magic)
    return -LINUX_EINVAL;       /* a descriptor, but not this kind of object */
  return 0;
}

static int
give_to_guest(int fd, bool cloexec)
{
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, cloexec);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(fd);
    return err;
  }
  return fd;
}

DEFINE_SYSCALL(fsopen, gstr_t, fsname_ptr, unsigned int, flags)
{
  if (!may_mount())
    return -LINUX_EPERM;
  if (flags & ~(unsigned) LINUX_FSOPEN_CLOEXEC)
    return -LINUX_EINVAL;

  char type[16];
  if (strncpy_from_user(type, fsname_ptr, sizeof type) < 0)
    return -LINUX_EFAULT;

  /*
   * The type is checked now rather than at fsmount, which is the whole point of
   * the split: a caller that names a filesystem this cannot provide finds out
   * from the call that named it, not three calls later.
   */
  struct mount_entry probe;
  memset(&probe, 0, sizeof probe);
  /* A type check, with nothing yet named to mount. */
  int r = backing_for_type(type, type, 0, true, &probe);
  if (r < 0)
    return r;
  /* Nothing is allocated yet - that probe may have made a tmpfs directory, and
   * the real one is made at fsmount. Undo it. */
  if (strcmp(probe.type, "tmpfs") == 0 && probe.hostdir[0])
    rmdir(probe.hostdir);

  int fd = anon_file("fsctx");
  if (fd < 0)
    return fd;
  struct fsctx_hdr h;
  memset(&h, 0, sizeof h);
  h.magic = FSCTX_MAGIC;
  snprintf(h.type, sizeof h.type, "%s", type);
  snprintf(h.source, sizeof h.source, "%s", type);
  if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h) {
    close(fd);
    return -LINUX_EIO;
  }
  return give_to_guest(fd, (flags & LINUX_FSOPEN_CLOEXEC) != 0);
}

DEFINE_SYSCALL(fsconfig, int, fd, unsigned int, cmd, gstr_t, key_ptr,
               gaddr_t, value, int, aux)
{
  struct fsctx_hdr h;
  int r = read_hdr(fd, &h, sizeof h, FSCTX_MAGIC);
  if (r < 0)
    return r;

  switch (cmd) {
  case LINUX_FSCONFIG_SET_FLAG:
  case LINUX_FSCONFIG_SET_STRING:
  case LINUX_FSCONFIG_SET_BINARY:
  case LINUX_FSCONFIG_SET_PATH:
  case LINUX_FSCONFIG_SET_PATH_EMPTY:
  case LINUX_FSCONFIG_SET_FD: {
    if (h.created)
      return -LINUX_EBUSY;      /* configured before creation, not after */
    char key[64];
    if (key_ptr == 0 || strncpy_from_user(key, key_ptr, sizeof key) < 0)
      return -LINUX_EFAULT;
    /*
     * `source` is the one parameter that means something here - it is what
     * /proc/mounts shows a mount as coming from. The rest are filesystem
     * options, and the filesystems this can provide have none it could honour:
     * a tmpfs here is a host directory, so a size= it cannot enforce would be
     * a limit the guest believes in and nothing applies. They are accepted and
     * dropped, which is what mount(2) here already does with its data argument.
     */
    if (strcmp(key, "source") == 0 && value != 0) {
      if (strncpy_from_user(h.source, value, sizeof h.source) < 0)
        return -LINUX_EFAULT;
      if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h)
        return -LINUX_EIO;
    }
    (void) aux;
    return 0;
  }

  case LINUX_FSCONFIG_CMD_CREATE:
    h.created = 1;
    if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h)
      return -LINUX_EIO;
    return 0;

  case LINUX_FSCONFIG_CMD_RECONFIGURE:
    /*
     * Reconfiguring the superblock a context describes. fspick makes such a
     * context, and it arrives here already created - so this is reachable now,
     * and what it has to reconfigure is the set of options fsconfig can carry,
     * which is `source` and nothing else. Saying yes to that is saying yes to
     * what was actually asked.
     */
    if (!h.created)
      return -LINUX_EINVAL;
    return 0;

  default:
    return -LINUX_EINVAL;
  }
}

/* Wrap a mount entry up as a detached mount and give the guest its descriptor. */
static int
detach(const struct mount_entry *e, bool cloexec)
{
  int fd = anon_file("detached");
  if (fd < 0)
    return fd;
  struct detached_hdr d;
  memset(&d, 0, sizeof d);
  d.magic = DETACHED_MAGIC;
  d.e = *e;
  if (pwrite(fd, &d, sizeof d, 0) != (ssize_t) sizeof d) {
    close(fd);
    return -LINUX_EIO;
  }
  return give_to_guest(fd, cloexec);
}

DEFINE_SYSCALL(fsmount, int, fsfd, unsigned int, flags, unsigned int, attr_flags)
{
  if (!may_mount())
    return -LINUX_EPERM;
  if (flags & ~(unsigned) LINUX_FSMOUNT_CLOEXEC)
    return -LINUX_EINVAL;

  struct fsctx_hdr h;
  int r = read_hdr(fsfd, &h, sizeof h, FSCTX_MAGIC);
  if (r < 0)
    return r;
  if (!h.created)
    return -LINUX_EINVAL;       /* nothing has been created to mount */

  struct mount_entry e;
  memset(&e, 0, sizeof e);
  /* fsmount carries read-only as a mount attribute rather than a mount flag;
   * the two mean the same thing to anything that has to honour it. */
  if ((r = backing_for_type(h.type, h.source,
                            (attr_flags & LINUX_MOUNT_ATTR_RDONLY)
                              ? LINUX_MS_RDONLY : 0, false, &e)) < 0)
    return r;
  snprintf(e.source, sizeof e.source, "%s", h.source);

  /* The mount attributes, in the same words mount_setattr uses. */
  if (attr_flags & ~(unsigned) (LINUX_MOUNT_ATTR_RDONLY | LINUX_MOUNT_ATTR_NOSUID |
                                LINUX_MOUNT_ATTR_NODEV | LINUX_MOUNT_ATTR_NOEXEC |
                                LINUX_MOUNT_ATTR__ATIME | LINUX_MOUNT_ATTR_NODIRATIME))
    return -LINUX_EINVAL;
  if (attr_flags & LINUX_MOUNT_ATTR_RDONLY) e.flags |= LINUX_MS_RDONLY;
  if (attr_flags & LINUX_MOUNT_ATTR_NOSUID) e.flags |= LINUX_MS_NOSUID;
  if (attr_flags & LINUX_MOUNT_ATTR_NODEV)  e.flags |= LINUX_MS_NODEV;
  if (attr_flags & LINUX_MOUNT_ATTR_NOEXEC) e.flags |= LINUX_MS_NOEXEC;

  return detach(&e, (flags & LINUX_FSMOUNT_CLOEXEC) != 0);
}

DEFINE_SYSCALL(open_tree, int, dfd, gstr_t, path_ptr, unsigned int, flags)
{
  char path[MOUNT_PATH_MAX];
  if (strncpy_from_user(path, path_ptr, sizeof path) < 0)
    return -LINUX_EFAULT;
  if (path[0] != '/')
    return -LINUX_EINVAL;       /* as elsewhere here: the table is keyed by
                                 * absolute guest paths */
  (void) dfd;

  if (!(flags & LINUX_OPEN_TREE_CLONE)) {
    /*
     * Without CLONE this is a descriptor on the path and nothing more - which
     * is what O_PATH already gives, so that is what it is.
     */
    return user_openat(LINUX_AT_FDCWD, path, LINUX_O_PATH |
                       (flags & LINUX_OPEN_TREE_CLOEXEC ? LINUX_O_CLOEXEC : 0),
                       0);
  }

  if (!may_mount())
    return -LINUX_EPERM;

  struct mount_table t;
  if (!current_table(&t))
    return -LINUX_EINVAL;
  for (uint32_t i = 0; i < t.n; i++) {
    if (strcmp(t.m[i].target, path) != 0)
      continue;
    if (t.m[i].propagation == LINUX_MS_UNBINDABLE)
      return -LINUX_EINVAL;     /* refuses to be copied, which is its purpose */
    struct mount_entry e = t.m[i];
    e.target[0] = '\0';         /* detached: it is nowhere until move_mount */
    e.id = 0;
    return detach(&e, (flags & LINUX_OPEN_TREE_CLOEXEC) != 0);
  }

  /*
   * Not a mount point, which is not a failure: Linux clones the mount that
   * *contains* the path, and what comes back is a detached bind of the path
   * itself. Everything is inside the root mount here, so that is a bind of
   * whatever the path names - and a plain file is a legitimate thing to bind,
   * which is how a single file is put over another.
   *
   * This is the form util-linux uses for every bind it performs. Refusing it
   * left `mount -o bind` on a file reporting a bad superblock, and waydroid
   * cannot place its waydroid.prop into the read-only vendor image without it.
   */
  char host[PATH_MAX];
  int gr = guest_to_host_path(path, host, sizeof host);
  if (gr < 0)
    return gr;
  struct stat st;
  if (stat(host, &st) < 0)
    return -darwin_to_linux_errno(errno);

  struct mount_entry e;
  memset(&e, 0, sizeof e);
  snprintf(e.source, sizeof e.source, "%s", path);
  snprintf(e.hostdir, sizeof e.hostdir, "%s", host);
  snprintf(e.type, sizeof e.type, "none");
  return detach(&e, (flags & LINUX_OPEN_TREE_CLOEXEC) != 0);
}

DEFINE_SYSCALL(move_mount, int, from_dfd, gstr_t, from_ptr, int, to_dfd,
               gstr_t, to_ptr, unsigned int, flags)
{
  if (!may_mount())
    return -LINUX_EPERM;
  if (flags & ~(unsigned) LINUX_MOVE_MOUNT__MASK)
    return -LINUX_EINVAL;
  if (flags & LINUX_MOVE_MOUNT_SET_GROUP)
    return -LINUX_EOPNOTSUPP;   /* shares a peer group between two mounts;
                                 * propagation here is set through mount(2) */

  char to[MOUNT_PATH_MAX];
  if (strncpy_from_user(to, to_ptr, sizeof to) < 0)
    return -LINUX_EFAULT;
  if (to[0] != '/')
    return -LINUX_EINVAL;
  (void) to_dfd;

  char from[MOUNT_PATH_MAX] = "";
  if (from_ptr != 0 && strncpy_from_user(from, from_ptr, sizeof from) < 0)
    return -LINUX_EFAULT;

  struct mount_table t;
  current_table(&t);

  /*
   * An empty from-path means the descriptor *is* the thing being moved, which
   * is how a detached mount from fsmount or open_tree gets attached. That is
   * the case the new API exists for.
   */
  if ((flags & LINUX_MOVE_MOUNT_F_EMPTY_PATH) && from[0] == '\0') {
    struct detached_hdr d;
    int r = read_hdr(from_dfd, &d, sizeof d, DETACHED_MAGIC);
    if (r < 0)
      return r;
    if (d.e.target[0] != '\0')
      return -LINUX_EINVAL;     /* already attached; a detached mount is used
                                 * once, as on Linux */
    if (t.n >= MOUNT_MAX)
      return -LINUX_ENOMEM;

    struct mount_entry e = d.e;
    snprintf(e.target, sizeof e.target, "%s", to);
    e.id = t.next_id++;
    t.m[t.n++] = e;
    table_store(ns_ino_of(NS_MNT), &t);

    /* Mark the descriptor spent, so a second move cannot attach the same
     * mount in two places. */
    d.e.target[0] = 'x';
    (void) !pwrite(from_dfd, &d, sizeof d, 0);
    return 0;
  }

  /* Otherwise this is mount --move: the mount at `from` answers to `to` now. */
  if (from[0] != '/')
    return -LINUX_EINVAL;
  for (uint32_t i = 0; i < t.n; i++) {
    if (strcmp(t.m[i].target, from) != 0)
      continue;
    snprintf(t.m[i].target, sizeof t.m[i].target, "%s", to);
    table_store(ns_ino_of(NS_MNT), &t);
    return 0;
  }
  return -LINUX_EINVAL;         /* not a mount point */
}

/* ---------------------------------------------------------- statmount */

/*
 * statmount: everything about one mount, chosen by a mask.
 *
 * listmount says which mounts exist and this describes one, and together they
 * are what /proc/mounts was doing badly - a text format that has to stay
 * compatible forever, parsed by everyone. The mask is statx's idea: a caller
 * asks for what it needs, and what came back is reported rather than assumed.
 */
DEFINE_SYSCALL(statmount, gaddr_t, req_ptr, gaddr_t, buf_ptr, size_t, bufsize,
               unsigned int, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (bufsize < sizeof(struct l_statmount))
    return -LINUX_EOVERFLOW;

  uint32_t size;
  if (copy_from_user(&size, req_ptr, sizeof size))
    return -LINUX_EFAULT;
  if (size < LINUX_MNT_ID_REQ_SIZE_VER0)
    return -LINUX_EINVAL;
  struct l_mnt_id_req req;
  memset(&req, 0, sizeof req);
  if (copy_from_user(&req, req_ptr, sizeof req > size ? size : sizeof req))
    return -LINUX_EFAULT;

  struct mount_table t;
  if (!current_table(&t))
    return -LINUX_ENOENT;
  const struct mount_entry *m = NULL;
  for (uint32_t i = 0; i < t.n; i++)
    if (t.m[i].id == (uint32_t) req.mnt_id) {
      m = &t.m[i];
      break;
    }
  if (!m)
    return -LINUX_ENOENT;

  /* The strings go after the fixed part, each named by its offset into that
   * run - so they are laid out first and the offsets recorded as they go. */
  char strs[3 * MOUNT_PATH_MAX + 32];
  size_t used = 0;
  uint32_t off_root = 0, off_point = 0, off_type = 0, off_opts = 0;
  uint64_t got = 0;

#define PUT_STR(field, want, src)                                   \
  do {                                                              \
    if (req.param & (want)) {                                       \
      size_t len = strlen(src) + 1;                                 \
      if (used + len <= sizeof strs) {                              \
        memcpy(strs + used, (src), len);                            \
        (field) = (uint32_t) used;                                  \
        used += len;                                                \
        got |= (want);                                              \
      }                                                             \
    }                                                               \
  } while (0)

  PUT_STR(off_root,  LINUX_STATMOUNT_MNT_ROOT,  m->source);
  PUT_STR(off_point, LINUX_STATMOUNT_MNT_POINT, m->target);
  PUT_STR(off_type,  LINUX_STATMOUNT_FS_TYPE,   m->type);
  PUT_STR(off_opts,  LINUX_STATMOUNT_MNT_OPTS,
          (m->flags & LINUX_MS_RDONLY) ? "ro" : "rw");
#undef PUT_STR

  struct l_statmount st;
  memset(&st, 0, sizeof st);
  st.size = (uint32_t) (sizeof st + used);
  st.mnt_root = off_root;
  st.mnt_point = off_point;
  st.fs_type = off_type;
  st.mnt_opts = off_opts;

  if (req.param & LINUX_STATMOUNT_MNT_BASIC) {
    st.mnt_id = m->id;
    st.mnt_id_old = m->id;
    st.mnt_parent_id = 1;       /* the root, which is not itself a table row */
    st.mnt_parent_id_old = 1;
    st.mnt_attr = m->flags;
    st.mnt_propagation = m->propagation;
    st.mnt_peer_group = m->peer;
    st.mnt_master = m->master;
    got |= LINUX_STATMOUNT_MNT_BASIC;
  }
  if (req.param & LINUX_STATMOUNT_SB_BASIC) {
    /* There is no superblock behind any of this - a mount here is a rewrite of
     * a path prefix - so what is reported is the flags, which are real, and
     * zeroes for the device and magic, which are not. */
    st.sb_flags = m->flags;
    got |= LINUX_STATMOUNT_SB_BASIC;
  }
  if (req.param & LINUX_STATMOUNT_MNT_NS_ID) {
    st.mnt_ns_id = ns_ino_of(NS_MNT);
    got |= LINUX_STATMOUNT_MNT_NS_ID;
  }
  /* What was actually filled in, which is not always what was asked for. */
  st.mask = got;

  if (bufsize < sizeof st + used)
    return -LINUX_EOVERFLOW;
  if (copy_to_user(buf_ptr, &st, sizeof st) ||
      (used && copy_to_user(buf_ptr + sizeof st, strs, used)))
    return -LINUX_EFAULT;
  return 0;
}

/*
 * fspick: a filesystem context for a mount that already exists.
 *
 * fsopen names a filesystem *type* and builds a context for something new;
 * fspick names a *path* and builds one for something already mounted, so that
 * fsconfig can reconfigure it. It is the new API's remount.
 *
 * The context it returns is the same object fsopen returns, marked as already
 * created - because it is: the superblock it describes exists. That is what
 * makes FSCONFIG_CMD_RECONFIGURE reachable, and why that command answered
 * EOPNOTSUPP until now with the note that there was no context it could arrive
 * on. There is one now.
 */
#define LINUX_FSPICK_CLOEXEC          0x00000001
#define LINUX_FSPICK_SYMLINK_NOFOLLOW 0x00000002
#define LINUX_FSPICK_NO_AUTOMOUNT     0x00000004
#define LINUX_FSPICK_EMPTY_PATH       0x00000008

DEFINE_SYSCALL(fspick, int, dfd, gstr_t, path_ptr, unsigned int, flags)
{
  if (!may_mount())
    return -LINUX_EPERM;
  if (flags & ~(unsigned) (LINUX_FSPICK_CLOEXEC | LINUX_FSPICK_SYMLINK_NOFOLLOW |
                           LINUX_FSPICK_NO_AUTOMOUNT | LINUX_FSPICK_EMPTY_PATH))
    return -LINUX_EINVAL;

  char target[MOUNT_PATH_MAX];
  if (strncpy_from_user(target, path_ptr, sizeof target) < 0)
    return -LINUX_EFAULT;
  if (target[0] != '/')
    return -LINUX_EINVAL;       /* as elsewhere: the table is keyed by absolute
                                 * guest paths */
  (void) dfd;

  struct mount_table t;
  if (!current_table(&t))
    return -LINUX_EINVAL;
  const struct mount_entry *m = NULL;
  for (uint32_t i = 0; i < t.n; i++)
    if (strcmp(t.m[i].target, target) == 0) {
      m = &t.m[i];
      break;
    }
  if (!m)
    return -LINUX_EINVAL;       /* not a mount point, as Linux says */

  int fd = anon_file("fsctx");
  if (fd < 0)
    return fd;
  struct fsctx_hdr h;
  memset(&h, 0, sizeof h);
  h.magic = FSCTX_MAGIC;
  h.created = 1;                /* the thing it describes already exists */
  snprintf(h.type, sizeof h.type, "%s", m->type);
  snprintf(h.source, sizeof h.source, "%s", m->source);
  if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h) {
    close(fd);
    return -LINUX_EIO;
  }
  return give_to_guest(fd, (flags & LINUX_FSPICK_CLOEXEC) != 0);
}
