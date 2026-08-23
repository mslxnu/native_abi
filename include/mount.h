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
 *   proc, sysfs, mqueue, securityfs, debugfs
 *           Accepted and recorded, because nabi already serves them and the
 *           mount is asking for something that is already true. Recording it is
 *           not a formality: /proc/mounts is built from this table, and a
 *           container that mounts /proc and then cannot see it in the list
 *           concludes the mount failed.
 *
 *   devtmpfs, devpts, binderfs
 *           Backed with the host's device tree. A devtmpfs mount is the
 *           kernel's /dev, which is the host's /dev here, so a container's own
 *           /dev reaches the real devices; devpts is served by the same
 *           /dev/ttysNNN rewrite the passthrough uses. binderfs answers with
 *           /dev/binderfs while the kext is loaded, and with a directory of
 *           nabi's own otherwise - holding a control node to start with, and
 *           the devices the guest creates through it as it creates them.
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

/*
 * statmount's answer. A fixed part and a run of NUL-terminated strings after
 * it, each named by its byte offset into that run - the same shape as any
 * variable-length kernel reply, and the reason `size` is reported back.
 */
struct l_statmount {
  uint32_t size;
  uint32_t mnt_opts;
  uint64_t mask;
  uint32_t sb_dev_major;
  uint32_t sb_dev_minor;
  uint64_t sb_magic;
  uint32_t sb_flags;
  uint32_t fs_type;
  uint64_t mnt_id;
  uint64_t mnt_parent_id;
  uint32_t mnt_id_old;
  uint32_t mnt_parent_id_old;
  uint64_t mnt_attr;
  uint64_t mnt_propagation;
  uint64_t mnt_peer_group;
  uint64_t mnt_master;
  uint64_t propagate_from;
  uint32_t mnt_root;
  uint32_t mnt_point;
  uint64_t mnt_ns_id;
  uint64_t __spare2[49];
  char     str[];
};

#define LINUX_STATMOUNT_SB_BASIC       0x00000001
#define LINUX_STATMOUNT_MNT_BASIC      0x00000002
#define LINUX_STATMOUNT_PROPAGATE_FROM 0x00000004
#define LINUX_STATMOUNT_MNT_ROOT       0x00000008
#define LINUX_STATMOUNT_MNT_POINT      0x00000010
#define LINUX_STATMOUNT_FS_TYPE        0x00000020
#define LINUX_STATMOUNT_MNT_NS_ID      0x00000040
#define LINUX_STATMOUNT_MNT_OPTS       0x00000080

/* open_tree */
#define LINUX_OPEN_TREE_CLONE   1
#define LINUX_OPEN_TREE_CLOEXEC 02000000   /* O_CLOEXEC */

/* move_mount */
#define LINUX_MOVE_MOUNT_F_SYMLINKS   0x00000001
#define LINUX_MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#define LINUX_MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define LINUX_MOVE_MOUNT_T_SYMLINKS   0x00000010
#define LINUX_MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#define LINUX_MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#define LINUX_MOVE_MOUNT_SET_GROUP    0x00000100
#define LINUX_MOVE_MOUNT_BENEATH      0x00000200
#define LINUX_MOVE_MOUNT__MASK        0x00000377

/* fsopen, and fsconfig's commands. */
#define LINUX_FSOPEN_CLOEXEC 0x00000001

#define LINUX_FSCONFIG_SET_FLAG        0
#define LINUX_FSCONFIG_SET_STRING      1
#define LINUX_FSCONFIG_SET_BINARY      2
#define LINUX_FSCONFIG_SET_PATH        3
#define LINUX_FSCONFIG_SET_PATH_EMPTY  4
#define LINUX_FSCONFIG_SET_FD          5
#define LINUX_FSCONFIG_CMD_CREATE      6
#define LINUX_FSCONFIG_CMD_RECONFIGURE 7

#define LINUX_FSMOUNT_CLOEXEC 0x00000001

#define MOUNT_MAX      64
#define MOUNT_PATH_MAX 256

struct mount_entry {
  char     source[MOUNT_PATH_MAX];   /* what the guest named */
  char     target[MOUNT_PATH_MAX];   /* where it appears */
  char     type[16];
  char     hostdir[MOUNT_PATH_MAX];  /* what backs it, or "" */
  /* The device an image mount was attached on, so unmounting can detach it
   * again. Empty for every mount that is not one. See src/fs/diskimage.c. */
  char     hostdev[64];
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

/* The guest path a host path is reached by, if a mount puts it there. The
 * reverse of mount_resolve; see src/fs/mount.c. */
bool mount_guest_path_of(const char *host_path, char *out, size_t outsz);

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
