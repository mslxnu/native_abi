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
 *   user    Reachable, and the largest of the reachable ones: credentials are
 *           already software, so what is missing is uid_map/gid_map and a
 *           capability model to go with them.
 *
 *   pid     Large. Guest pids *are* host pids today - getpid, kill, wait4,
 *           signals, /proc and the fork checkpoint all use them directly - so a
 *           pid namespace means a translation layer through all of it. Doing
 *           half of it would be worse than none: a container init that is told
 *           it is pid 1 while signals and waits use another number is a bug
 *           that surfaces far from here.
 *
 *   mnt     Little to isolate yet. There is no mount table - there is a rootfs
 *           and a list of passthrough prefixes - so this waits on mount(2).
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

struct namespace {
  enum ns_type type;
  uint64_t     ino;          /* what /proc/<pid>/ns/<name> reports */
  unsigned     refcount;
  /* Only uts and time carry anything; the rest exist to have an identity. */
  struct uts_namespace  uts;
  struct time_namespace time;
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
 * Move a timestamp between the host's clocks and this namespace's. `boottime`
 * picks which of the two offsets applies; `sign` is +1 coming out of the host
 * and -1 going back in, which is what an absolute deadline needs.
 */
void timens_shift(struct timespec *ts, bool boottime, int sign);

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
