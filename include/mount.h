/*
 * The mount table, and therefore the mount namespace.
 *
 * There was neither. nabi had a rootfs and a compile-time list of host prefixes
 * that are passed through, which is a policy rather than a table: nothing could
 * be added to it, nothing removed, and so a mount namespace had nothing to
 * isolate. mount(2) and umount2(2) were not implemented and were in neither
 * syscall table. That is why namespace.h called this one "little to isolate
 * yet" and made it wait.
 *
 * What a mount can be here is decided by what the host can actually provide:
 *
 *   bind    Fully, and it is the one that matters. A bind mount is a rewrite of
 *           one path prefix to another, which is exactly what nabi's path
 *           resolution already does for the rootfs and the passthroughs - so a
 *           bind is a table entry consulted at the same point, and needs
 *           nothing from Darwin at all. MS_REC changes nothing because a prefix
 *           rewrite is recursive by construction.
 *
 *   tmpfs   A directory under TMPDIR. Its contents go when it is unmounted,
 *           which is the property anything mounting one is relying on.
 *
 *   proc, sysfs, devtmpfs, devpts
 *           Accepted and recorded, because nabi already serves all four and the
 *           mount is asking for something that is already true. Recording it is
 *           not a formality: /proc/mounts is built from this table, and a
 *           container that mounts /proc and then cannot see it in the list
 *           concludes the mount failed.
 *
 * Everything else - a real filesystem, overlay - is EINVAL or ENODEV rather
 * than a success that did nothing. There is no block device layer here to mount
 * anything on.
 *
 * MS_MOVE works and costs almost nothing: a mount here is a prefix rewrite, so
 * moving one is changing the prefix it answers to. The host object it resolved
 * to when it was mounted is not consulted again, which is why a move cannot
 * fail the way a fresh mount might.
 *
 * MS_RDONLY is honoured rather than recorded, because a read-only bind that
 * silently accepted writes would be worse than one that refused to exist: the
 * whole reason to ask for one is to be sure.
 *
 * Mounting needs guest root, and a user namespace does not confer it. That
 * follows from what the user namespace is here - an identity and not an
 * authority (see namespace.h) - and it fails closed: `unshare -Ur -m` gets its
 * namespace and is then refused the mounts, rather than being handed authority
 * over the host that nothing downstream would check.
 */
#ifndef NABI_MOUNT_H
#define NABI_MOUNT_H

#include <stdint.h>
#include <stdbool.h>

/*
 * mount_setattr's argument. Fixed ABI: a caller passes its size, which is how
 * the kernel tells an old caller from a new one.
 */
struct l_mount_attr {
  uint64_t attr_set;
  uint64_t attr_clr;
  uint64_t propagation;
  uint64_t userns_fd;
};

#define LINUX_MOUNT_ATTR_RDONLY      0x00000001
#define LINUX_MOUNT_ATTR_NOSUID      0x00000002
#define LINUX_MOUNT_ATTR_NODEV       0x00000004
#define LINUX_MOUNT_ATTR_NOEXEC      0x00000008
#define LINUX_MOUNT_ATTR__ATIME      0x00000070
#define LINUX_MOUNT_ATTR_RELATIME    0x00000000
#define LINUX_MOUNT_ATTR_NOATIME     0x00000010
#define LINUX_MOUNT_ATTR_STRICTATIME 0x00000020
#define LINUX_MOUNT_ATTR_NODIRATIME  0x00000080
#define LINUX_MOUNT_ATTR_IDMAP       0x00100000
#define LINUX_MOUNT_ATTR_NOSYMFOLLOW 0x00200000

/* listmount's request, and the id that means "start at the root". */
struct l_mnt_id_req {
  uint32_t size;
  uint32_t spare;
  uint64_t mnt_id;
  uint64_t param;
};
#define LINUX_MNT_ID_REQ_SIZE_VER0 24
#define LINUX_LSMT_ROOT 0xffffffffffffffffULL

#define MOUNT_MAX      64
#define MOUNT_PATH_MAX 256

struct mount_entry {
  char     source[MOUNT_PATH_MAX];   /* what the guest named */
  char     target[MOUNT_PATH_MAX];   /* where it appears */
  char     type[16];
  char     hostdir[MOUNT_PATH_MAX];  /* what backs it, or "" */
  uint32_t flags;
  uint32_t id;
  /*
   * Propagation. `peer` is the group a shared mount belongs to and `master` the
   * group a slave listens to; either is 0 when it does not apply. A private
   * mount has neither, which is what makes private the absence of a
   * relationship rather than a kind of one.
   */
  uint32_t propagation;              /* LINUX_MS_SHARED, _PRIVATE, _SLAVE, _UNBINDABLE */
  uint32_t peer;
  uint32_t master;
};

struct mount_table {
  struct mount_entry m[MOUNT_MAX];
  uint32_t n;
  uint32_t next_id;
};

/*
 * Propagation, which is the part of mounting that is about other namespaces.
 *
 * A shared mount and the copy of it a new namespace receives are *peers*: a
 * mount made under one appears under the other, and that is what propagation
 * is for. Here a namespace's mounts are a table in a file, so peers are entries
 * in different files carrying the same group number, and propagating an event
 * means writing it into every table that has one.
 *
 * The four types are Linux's and are honoured rather than recorded:
 *
 *   shared      events travel both ways with every peer.
 *   private     no relationship in either direction. The default, as on Linux.
 *   slave       receives from its master's group, sends to nobody. `unshare`
 *               makes one when a shared mount is copied with --make-rslave,
 *               which is how a container watches the host's mounts without
 *               being able to disturb them.
 *   unbindable  private, and refuses to be the source of a bind. This one is
 *               enforced rather than noted: it exists to stop a recursive bind
 *               from copying a subtree into itself forever.
 */
void mount_ns_clone(uint64_t from_ino, uint64_t to_ino);

/*
 * Whether an absolute guest path falls inside a mount, and where it really is.
 *
 * The longest matching target wins, so a mount on /a/b shadows one on /a, which
 * is the order Linux resolves them in. `rdonly` reports the mount's flag so the
 * caller can refuse a write without looking the mount up again.
 */
bool mount_resolve(const char *guest_path, char *out, size_t outsz, bool *rdonly);

/* Whether this path is under a read-only mount, for the operations that write. */
bool mount_is_rdonly(const char *guest_path);

/* /proc/mounts and /proc/self/mountinfo, from the table rather than a fixed
 * string that could only ever describe the day it was written. */
int  mount_build_mounts(char *out, size_t n);
int  mount_build_mountinfo(char *out, size_t n);

#endif
