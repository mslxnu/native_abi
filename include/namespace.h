/*
 * Linux namespaces, on a host that has none.
 *
 * macOS has no namespaces of any kind, so nothing here can be delegated: a
 * namespace is either emulated in nabi's own bookkeeping or it does not exist.
 * That is the same position credentials are in (struct cred) and file ownership
 * (msl.nabi.owner), and it has the same consequence - what can be emulated must
 * be emulated completely, and what cannot must say so rather than pretend.
 *
 * They differ enormously in how far they can be taken:
 *
 *   uts     Fully. It is a hostname and a domainname per namespace, and nabi
 *           already answers uname. Implemented.
 *
 *   ipc     Reachable. SysV semaphores and shared memory are nabi's own
 *           (src/ipc/), so their keys could be scoped to a namespace.
 *
 *   time    Fully, for what it covers. It is an offset added to CLOCK_MONOTONIC
 *           and CLOCK_BOOTTIME, both of which nabi already translates, and it
 *           deliberately does not touch CLOCK_REALTIME - neither does Linux's.
 *           Implemented.
 *
 *   user    Implemented as an identity, not as an authority. The maps are real
 *           - uid_map, gid_map and setgroups, translating at the syscall
 *           boundary - so a process can be uid 0 inside while remaining its own
 *           unprivileged self outside, and files owned by unmapped ids read
 *           back as nobody, exactly as on Linux. What is *not* modelled is
 *           capabilities: being root in a namespace here confers no permission
 *           that the guest credentials did not already carry. See below.
 *
 *   pid     Renumbering, which is most of it, and not concealment, which is
 *           not available from here. getpid, getppid, kill, wait4, clone's
 *           return and /proc/<pid> all translate together, so the failure the
 *           old note warned of - an init told it is pid 1 while signals and
 *           waits use another number - cannot happen. What a pid namespace
 *           cannot do here is hide: /proc is the host's, passed through by
 *           mSL/ProcFS, so a guest sees every process on the Mac either way.
 *           And there is no init to reparent orphans to. See src/proc/pidns.c.
 *
 *   mnt     Implemented, together with the mount(2) it was waiting on. A bind
 *           mount is a rewrite of one path prefix to another, which is what
 *           path resolution here already does for the rootfs and the
 *           passthroughs, so it needs nothing from Darwin. tmpfs is a directory
 *           under TMPDIR; proc, sysfs and the rest are recorded because nabi
 *           already serves them. See include/mount.h.
 *
 *   cgroup  Nothing to isolate. There are no cgroups.
 *
 *   net     No. Sockets are the host's, and isolating them would mean a virtual
 *           network stack rather than a namespace.
 *
 * So unshare and setns accept CLONE_NEWUTS and refuse the rest with EINVAL,
 * which is exactly what Linux returns for a namespace its kernel was not built
 * with. A guest gets a real answer either way and never a silent no-op.
 *
 * Every type still has a /proc/<pid>/ns/ entry, because Linux always does and
 * software reads them to compare namespaces rather than to change them. The
 * ones that cannot be unshared report the initial namespace, which is the truth:
 * every guest is in it.
 */
#ifndef NABI_NAMESPACE_H
#define NABI_NAMESPACE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

enum ns_type {
  NS_MNT, NS_UTS, NS_IPC, NS_PID, NS_NET, NS_USER, NS_CGROUP, NS_TIME,
  NS_COUNT
};

/*
 * What a namespace is called in /proc/<pid>/ns, and the inode number that
 * identifies it there.
 *
 * Linux numbers them from the nsfs and starts the initial set at 4026531835;
 * the values are opaque, but software does compare them, and starting anywhere
 * else would make a guest's numbers look unlike every other Linux it has seen.
 */
#define NS_INO_FIRST 4026531835u

struct uts_namespace {
  char nodename[65];
  char domainname[65];
};

/*
 * What a time namespace is: two offsets, and nothing else.
 *
 * Added to the initial namespace's clocks to give this one's, which is Linux's
 * definition exactly. CLOCK_REALTIME is not among them and cannot be - a
 * container that disagreed with the host about the wall clock would disagree
 * with everything it talks to, and the namespace was designed for restoring
 * checkpointed processes whose monotonic clock must appear not to have jumped.
 *
 * `frozen` is set once any process is actually in the namespace. Offsets may be
 * written only before that: a clock that changed under a running process would
 * be a clock that went backwards, which is the one thing CLOCK_MONOTONIC
 * promises never to do.
 */
struct time_namespace {
  int64_t mono_sec, mono_nsec;
  int64_t boot_sec, boot_nsec;
  int32_t frozen;
  int32_t _pad;
};

/*
 * A user namespace: what the ids inside it mean outside it.
 *
 * Held as ranges, as Linux holds them, and written once - a map that could
 * change under a running process would silently reinterpret every id it had
 * already been told.
 */
#define USERNS_MAX_RANGES 5
#define USERNS_OVERFLOW   65534         /* Linux's overflowuid: "nobody" */

struct id_range {
  uint32_t inside, outside, count;
};

struct user_namespace {
  struct id_range uid[USERNS_MAX_RANGES];
  struct id_range gid[USERNS_MAX_RANGES];
  uint32_t n_uid, n_gid;
  int32_t  setgroups_allowed;   /* until "deny" is written, which gid_map wants */
  int32_t  uid_written, gid_written;
  uint32_t creator;             /* the outside uid that made it */
  uint32_t _pad;
};

struct namespace {
  enum ns_type type;
  uint64_t     ino;          /* what /proc/<pid>/ns/<name> reports */
  unsigned     refcount;
  /* Only uts and time carry anything; the rest exist to have an identity. */
  struct uts_namespace  uts;
  struct time_namespace time;
  struct user_namespace user;
};

/*
 * One per process: which namespace of each type it is in - and, for time, which
 * one its children will be in, which is not the same thing.
 *
 * unshare(CLONE_NEWTIME) is the one that does not move the caller. Every other
 * CLONE_NEW* takes effect on the process that asked; this one only sets what
 * children get, because a process's own CLOCK_MONOTONIC cannot be shifted
 * underneath it without the clock appearing to jump. So the new namespace is
 * held here until a fork puts somebody in it, and /proc/<pid>/ns/time goes on
 * naming the old one - which is why Linux has a time_for_children link at all.
 */
struct nsproxy {
  struct namespace *ns[NS_COUNT];
  struct namespace *time_for_children;
  struct namespace *pid_for_children;
};

/* The current boot session, short and filename-safe. Namespace state is kept in
 * files, and none of it should outlive the machine. */
const char *nabi_boot_tag(void);

const char *ns_type_name(enum ns_type type);
bool ns_type_from_name(const char *name, enum ns_type *out);

/* The initial set, which every guest starts in. */
void nsproxy_init(void);

/* Called by fork: the child shares its parent's namespaces unless a CLONE_NEW*
 * flag asks for a new one. */
int nsproxy_clone(unsigned long clone_flags);

/* unshare(2)'s namespace half, factored out because clone wants it too. */
int nsproxy_unshare(unsigned long flags);

/* The time namespace this process's children will be in, which after an
 * unshare is not the one this process is in. */
uint64_t ns_ino_time_for_children(void);

/*
 * The pid namespace, which unshare treats the same way as time: the caller
 * stays where it is and the new namespace is for its children. A process
 * cannot be renumbered underneath itself any more than its clock can be moved.
 */
uint64_t ns_ino_pid_for_children(void);
bool     pidns_active(void);
int32_t  pidns_to_ns(int32_t host);     /* 0 when it is not a member */
int32_t  pidns_to_host(int32_t ns);     /* -1 when there is no such pid */
int32_t  pidns_add_child(int32_t host); /* the parent registers; returns its own view */
void     pidns_create(uint64_t ino, uint64_t parent_ino);

/*
 * Move a timestamp between the host's clocks and this namespace's. `boottime`
 * picks which of the two offsets applies; `sign` is +1 coming out of the host
 * and -1 going back in, which is what an absolute deadline needs.
 */
void timens_shift(struct timespec *ts, bool boottime, int sign);

/*
 * The user namespace, as a translation at the syscall boundary.
 *
 * Credentials are *not* rewritten. struct cred goes on holding the ids the
 * process really has, and only what crosses to the guest is mapped - which is
 * what makes the containment come out right without a capability model to
 * enforce it. A process that maps itself to uid 0 inside is still its own
 * unprivileged self to every check nabi makes, so it gains the appearance of
 * root and none of the reach: exactly the part of Linux's behaviour that
 * matters, arrived at by not implementing the part that does not.
 *
 * The cost of that shortcut is real and worth stating. On Linux, root in a user
 * namespace genuinely may act on ids mapped into it - chown a file it owns to
 * another mapped id, for instance - and here it may not, because the check that
 * would allow it looks at credentials that never changed. Programs that ask
 * "am I root" and proceed will work; programs that then rely on the authority
 * will be refused as the unprivileged process they actually are.
 */
bool     userns_active(void);
uint32_t userns_uid_inward(uint32_t outside);   /* nobody, if unmapped */
uint32_t userns_gid_inward(uint32_t outside);
bool     userns_uid_outward(uint32_t inside, uint32_t *out);  /* false if unmapped */
bool     userns_gid_outward(uint32_t inside, uint32_t *out);

int userns_map_read(bool gid, char *out, size_t n);
int userns_map_write(bool gid, const char *text);
int userns_setgroups_read(char *out, size_t n);
int userns_setgroups_write(const char *text);

/* /proc/<pid>/timens_offsets, which is the only way to set them. */
int timens_offsets_read(char *out, size_t n);
int timens_offsets_write(const char *text);

/* The uts namespace this process is in, never NULL. */
struct uts_namespace *current_uts(void);
void current_uts_commit(void);

/* For /proc/<pid>/ns/<name>: the inode of the namespace this process is in. */
uint64_t ns_ino_of(enum ns_type type);

/* Called on the way out: give up namespaces this process created. */
void nsproxy_release(void);

/* Checkpoint support: arm64's fork is fork plus exec, so a child rebuilds these
 * from the parent's rather than inheriting them in memory. */
void nsproxy_snapshot(uint64_t inos[NS_COUNT], struct uts_namespace *uts);
void nsproxy_restore(const uint64_t inos[NS_COUNT], const struct uts_namespace *uts);

#endif
