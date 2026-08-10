/*
 * Linux namespaces. See include/namespace.h for what is and is not reachable
 * on a host with none of its own, and why.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <pthread.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "sysv.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/misc.h"

/*
 * The flag that asks for each type, and its name under /proc/<pid>/ns.
 *
 * `supported` is the whole policy in one column: a type that cannot be
 * isolated is refused by unshare and setns rather than accepted and ignored.
 */
static const struct {
  enum ns_type  type;
  const char   *name;
  unsigned long flag;
  bool          supported;
} ns_kinds[NS_COUNT] = {
  [NS_MNT]    = { NS_MNT,    "mnt",    LINUX_CLONE_NEWNS,     false },
  [NS_UTS]    = { NS_UTS,    "uts",    LINUX_CLONE_NEWUTS,    true  },
  [NS_IPC]    = { NS_IPC,    "ipc",    LINUX_CLONE_NEWIPC,    true  },
  [NS_PID]    = { NS_PID,    "pid",    LINUX_CLONE_NEWPID,    false },
  [NS_NET]    = { NS_NET,    "net",    LINUX_CLONE_NEWNET,    false },
  [NS_USER]   = { NS_USER,   "user",   LINUX_CLONE_NEWUSER,   false },
  [NS_CGROUP] = { NS_CGROUP, "cgroup", LINUX_CLONE_NEWCGROUP, false },
  [NS_TIME]   = { NS_TIME,   "time",   LINUX_CLONE_NEWTIME,   true  },
};

/* Every CLONE_NEW* bit, for telling "asked for a namespace" from other flags. */
#define NS_ALL_FLAGS                                                         \
  (LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUTS | LINUX_CLONE_NEWIPC |             \
   LINUX_CLONE_NEWPID | LINUX_CLONE_NEWNET | LINUX_CLONE_NEWUSER |           \
   LINUX_CLONE_NEWCGROUP | LINUX_CLONE_NEWTIME)

/*
 * A namespace's contents live in a file, not in this process.
 *
 * That is the whole difficulty of namespaces here. A namespace is shared state
 * between every process in it, and nabi's processes are separate host processes
 * that rebuild themselves from a checkpoint - so an in-memory copy per process
 * gives each one a private namespace that merely looks shared. It passes any
 * test written inside one process and fails the first real use: `unshare -u sh
 * -c 'hostname box; hostname'` sets the name in the process that runs hostname
 * and reads it back in a different one, and the write is lost.
 *
 * A small file per namespace, named by the inode that already identifies it, is
 * shared by construction - across forks, across execs, and across guests that
 * are genuinely in the same namespace, which is exactly who should see it. The
 * cost is a read per uname, which is not a hot path.
 */
/*
 * Named for the boot session as well as the namespace.
 *
 * A hostname outlives the process that set it - that is what makes it shared -
 * but it should not outlive the machine. Without the boot id in the name, a
 * guest that renamed itself left that name in TMPDIR for every guest started
 * afterwards, including days later, which is not what "until reboot" means
 * anywhere else.
 */
int sysctlbyname(const char *, void *, size_t *, void *, size_t);

const char *
nabi_boot_tag(void)
{
  static char boot[48];
  if (boot[0] == '\0') {
    size_t len = sizeof boot;
    if (sysctlbyname("kern.bootsessionuuid", boot, &len, NULL, 0) < 0)
      strcpy(boot, "noboot");
    for (char *p = boot; *p; p++)
      if (*p == '-')
        *p = '\0';              /* the first field is plenty, and short */
  }
  return boot;
}

static void
ns_state_path(const char *kind, uint64_t ino, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-%s-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", kind, nabi_boot_tag(),
           (unsigned long long) ino);
}

static void
uts_path(uint64_t ino, char *out, size_t n)
{
  ns_state_path("uts", ino, out, n);
}

/* The offsets are shared state for the same reason a hostname is: every
 * process in the namespace has to agree, and they are separate host
 * processes. */
static bool
timens_load(uint64_t ino, struct time_namespace *out)
{
  char path[PATH_MAX];
  ns_state_path("timens", ino, path, sizeof path);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return false;
  bool ok = read(fd, out, sizeof *out) == (ssize_t) sizeof *out;
  close(fd);
  return ok;
}

static void
timens_store(uint64_t ino, const struct time_namespace *t)
{
  char path[PATH_MAX], tmppath[PATH_MAX];
  ns_state_path("timens", ino, path, sizeof path);
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
uts_load(uint64_t ino, struct uts_namespace *out)
{
  char path[PATH_MAX];
  uts_path(ino, path, sizeof path);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return false;
  bool ok = read(fd, out, sizeof *out) == (ssize_t) sizeof *out;
  close(fd);
  if (ok) {
    out->nodename[sizeof out->nodename - 1] = '\0';
    out->domainname[sizeof out->domainname - 1] = '\0';
  }
  return ok;
}

static void
uts_store(uint64_t ino, const struct uts_namespace *uts)
{
  char path[PATH_MAX], tmppath[PATH_MAX];
  uts_path(ino, path, sizeof path);
  snprintf(tmppath, sizeof tmppath, "%s.new", path);

  /* Written whole and renamed, so a reader never sees half a hostname. */
  int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  bool ok = write(fd, uts, sizeof *uts) == (ssize_t) sizeof *uts;
  close(fd);
  if (ok)
    rename(tmppath, path);
  else
    unlink(tmppath);
}

static struct nsproxy current_nsproxy;
static struct namespace initial_ns[NS_COUNT];
static uint64_t next_ino = NS_INO_FIRST + NS_COUNT;
static pthread_mutex_t ns_lock = PTHREAD_MUTEX_INITIALIZER;

const char *
ns_type_name(enum ns_type type)
{
  return (type >= 0 && type < NS_COUNT) ? ns_kinds[type].name : NULL;
}

bool
ns_type_from_name(const char *name, enum ns_type *out)
{
  for (int i = 0; i < NS_COUNT; i++) {
    if (strcmp(name, ns_kinds[i].name) == 0) {
      if (out)
        *out = (enum ns_type) i;
      return true;
    }
  }
  return false;
}

void
nsproxy_init(void)
{
  for (int i = 0; i < NS_COUNT; i++) {
    initial_ns[i] = (struct namespace) {
      .type = (enum ns_type) i,
      .ino = NS_INO_FIRST + (unsigned) i,
      .refcount = 1,
    };
    current_nsproxy.ns[i] = &initial_ns[i];
  }
  current_nsproxy.time_for_children = &initial_ns[NS_TIME];

  /*
   * The initial uts namespace starts from the host's idea of the machine, so a
   * guest that never touches it reports what the Mac is called - which is what
   * it did before namespaces existed here, and what a user expects to see.
   */
  struct uts_namespace *uts = &initial_ns[NS_UTS].uts;
  if (!uts_load(initial_ns[NS_UTS].ino, uts)) {
    if (gethostname(uts->nodename, sizeof uts->nodename - 1) < 0)
      strcpy(uts->nodename, "localhost");
    strcpy(uts->domainname, "(none)");
    uts_store(initial_ns[NS_UTS].ino, uts);
  }
}

static struct namespace *
ns_new(enum ns_type type, const struct namespace *from)
{
  struct namespace *ns = calloc(1, sizeof *ns);
  if (ns == NULL)
    return NULL;
  ns->type = type;
  ns->ino = next_ino++;
  ns->refcount = 1;
  /* A new namespace starts as a copy of the one being left, which is what
   * Linux does for uts - unshare does not blank the hostname. */
  if (from != NULL) {
    ns->uts = from->uts;
    ns->time = from->time;
    if (type == NS_UTS) {
      uts_load(from->ino, &ns->uts);      /* whatever it is *now* */
      uts_store(ns->ino, &ns->uts);
    }
    if (type == NS_TIME) {
      /*
       * The offsets carry over and the freeze does not. A namespace nobody is
       * in yet is exactly the one whose offsets may still be set, which is the
       * whole reason unshare leaves the caller where it was.
       */
      timens_load(from->ino, &ns->time);
      ns->time.frozen = 0;
      timens_store(ns->ino, &ns->time);
    }
  }
  return ns;
}

static void
ns_put(struct namespace *ns)
{
  if (ns == NULL || ns >= initial_ns) {
    /* The initial set is static and outlives everything. */
    if (ns != NULL && (ns < initial_ns || ns >= initial_ns + NS_COUNT))
      goto dynamic;
    return;
  }
dynamic:
  if (--ns->refcount == 0)
    free(ns);
}

/*
 * The namespace half of unshare(2) and of clone(2).
 *
 * Flags naming a type that cannot be isolated here are EINVAL - the same answer
 * Linux gives for a namespace its kernel was not built with - and nothing is
 * changed when any flag is refused, so a caller asking for several at once does
 * not end up half moved.
 */
int
nsproxy_unshare(unsigned long flags)
{
  unsigned long wanted = flags & NS_ALL_FLAGS;
  if (wanted == 0)
    return 0;

  for (int i = 0; i < NS_COUNT; i++)
    if ((wanted & ns_kinds[i].flag) && !ns_kinds[i].supported)
      return -LINUX_EINVAL;

  pthread_mutex_lock(&ns_lock);
  for (int i = 0; i < NS_COUNT; i++) {
    if (!(wanted & ns_kinds[i].flag))
      continue;
    struct namespace *ns = ns_new((enum ns_type) i, current_nsproxy.ns[i]);
    /*
     * A new IPC namespace starts empty, as Linux's does - unshare does not
     * carry the objects across - and it is claimed for this process so that a
     * later sweep can tell an abandoned namespace from the initial one, which
     * nothing should ever collect.
     */
    if (ns == NULL) {
      pthread_mutex_unlock(&ns_lock);
      return -LINUX_ENOMEM;
    }
    if (i == NS_IPC)
      sysv_ns_claim(ns->ino);

    /*
     * Time is the exception, and the only one: the caller stays where it is and
     * the new namespace waits for its children. Moving the caller would move
     * its CLOCK_MONOTONIC, and a monotonic clock that jumps is not one.
     */
    if (i == NS_TIME) {
      ns_put(current_nsproxy.time_for_children);
      current_nsproxy.time_for_children = ns;
      continue;
    }
    ns_put(current_nsproxy.ns[i]);
    current_nsproxy.ns[i] = ns;
  }
  pthread_mutex_unlock(&ns_lock);
  return 0;
}

int
nsproxy_clone(unsigned long clone_flags)
{
  return nsproxy_unshare(clone_flags);
}

/*
 * The uts namespace as it stands, which may have been changed by another
 * process in it since this one last looked - which is the point.
 */
struct uts_namespace *
current_uts(void)
{
  struct namespace *ns = current_nsproxy.ns[NS_UTS];
  uts_load(ns->ino, &ns->uts);
  return &ns->uts;
}

/* Publish a change so every other process in the namespace sees it. */
void
current_uts_commit(void)
{
  struct namespace *ns = current_nsproxy.ns[NS_UTS];
  uts_store(ns->ino, &ns->uts);
}

uint64_t
ns_ino_of(enum ns_type type)
{
  if (type < 0 || type >= NS_COUNT)
    return 0;
  return current_nsproxy.ns[type]->ino;
}

void
nsproxy_snapshot(uint64_t inos[NS_COUNT], struct uts_namespace *uts)
{
  for (int i = 0; i < NS_COUNT; i++)
    inos[i] = current_nsproxy.ns[i]->ino;

  /*
   * Except time, where the child goes where the parent said children go rather
   * than where the parent is. This is the whole of unshare(CLONE_NEWTIME)'s
   * effect - the parent kept its own clocks and set these aside - and the
   * checkpoint is written by a parent for one child, so substituting it here is
   * exactly the handover. Nothing else consults this snapshot.
   */
  inos[NS_TIME] = current_nsproxy.time_for_children->ino;
  *uts = current_nsproxy.ns[NS_UTS]->uts;
}

/*
 * Rebuild what the parent had.
 *
 * A resumed child is a fresh process that never ran nsproxy_init's caller, so
 * the namespaces have to be reconstructed rather than inherited. The identities
 * matter as much as the contents: a child that shares its parent's uts
 * namespace must report the same inode from /proc/self/ns/uts, or anything
 * comparing the two is told they are in different namespaces when they are not.
 */
void
nsproxy_restore(const uint64_t inos[NS_COUNT], const struct uts_namespace *uts)
{
  nsproxy_init();
  for (int i = 0; i < NS_COUNT; i++) {
    if (inos[i] == current_nsproxy.ns[i]->ino)
      continue;                 /* still the initial one */

    /*
     * Built by hand rather than with ns_new, and that is not tidiness.
     *
     * ns_new allocates a *fresh* identity and writes the namespace's contents
     * out under it - which is right when a namespace is being created, and
     * destructive here. next_ino starts at the same value in every rebuilt
     * process, so a child restoring its parent's namespace was handed the very
     * number the parent already had, and stored the initial hostname over the
     * parent's file before relabelling itself. Every fork silently reset the
     * namespace: `unshare -u sh -c 'hostname box; hostname'` set the name and
     * read back the old one.
     *
     * Rejoining an existing namespace only ever reads.
     */
    struct namespace *ns = calloc(1, sizeof *ns);
    if (ns == NULL)
      continue;
    ns->type = (enum ns_type) i;
    ns->ino = inos[i];
    ns->refcount = 1;
    ns_put(current_nsproxy.ns[i]);
    current_nsproxy.ns[i] = ns;
    if (i == NS_TIME)
      current_nsproxy.time_for_children = ns;
  }

  /*
   * Now that somebody is actually in the time namespace, its offsets are fixed.
   * Freezing here rather than at unshare is what makes the window right: the
   * parent may go on adjusting them until the moment a child arrives, and after
   * that a change would move a running process's CLOCK_MONOTONIC.
   */
  {
    struct namespace *tns = current_nsproxy.ns[NS_TIME];
    if (timens_load(tns->ino, &tns->time) && !tns->time.frozen) {
      tns->time.frozen = 1;
      timens_store(tns->ino, &tns->time);
    }
  }

  /* The contents come from the file rather than the checkpoint when the file
   * exists, because the parent may have changed them after forking. The
   * checkpoint's copy is the fallback for a namespace whose file is gone. */
  if (!uts_load(current_nsproxy.ns[NS_UTS]->ino, &current_nsproxy.ns[NS_UTS]->uts)) {
    current_nsproxy.ns[NS_UTS]->uts = *uts;
    uts_store(current_nsproxy.ns[NS_UTS]->ino, uts);
  }

  /* Handed-out inodes must not be reissued to a later unshare. */
  for (int i = 0; i < NS_COUNT; i++)
    if (inos[i] >= next_ino)
      next_ino = inos[i] + 1;
}

/* ------------------------------------------------------------- syscalls */

DEFINE_SYSCALL(unshare, unsigned long, flags)
{
  /*
   * Only the namespace flags are acted on. The rest of what unshare can ask
   * for - CLONE_FILES, CLONE_FS, CLONE_SYSVSEM - is about undoing sharing that
   * a clone set up, and nothing here shares those between processes to begin
   * with, so accepting them changes nothing and refusing them would break
   * callers that pass them harmlessly.
   */
  return nsproxy_unshare(flags);
}

/*
 * setns(2).
 *
 * The descriptor names a namespace, and comes from opening /proc/<pid>/ns/<t>.
 * Which namespace that is, is recorded when the file is opened (src/fs/procfs.c
 * keeps the mapping), because the host file behind it is an ordinary temporary
 * file and carries nothing of its own.
 *
 * Joining an existing namespace by descriptor is only meaningful once there is
 * more than one guest to join, which needs the pid work described in
 * namespace.h. What works today is the case that matters for a single guest:
 * re-entering the namespace it is already in, which is what a program checking
 * that setns exists will do, and which must not lie.
 */
DEFINE_SYSCALL(setns, int, fd, int, nstype)
{
  enum ns_type type;
  uint64_t ino;

  if (!procfs_ns_of_fd(fd, &type, &ino))
    return -LINUX_EINVAL;

  /* nstype 0 means "whatever this descriptor is"; anything else has to agree
   * with it, which is how a caller asserts what it thinks it is joining. */
  if (nstype != 0) {
    bool matched = false;
    for (int i = 0; i < NS_COUNT; i++)
      if (ns_kinds[i].flag == (unsigned long) nstype && (enum ns_type) i == type)
        matched = true;
    if (!matched)
      return -LINUX_EINVAL;
  }

  if (!ns_kinds[type].supported)
    return -LINUX_EINVAL;

  if (ns_ino_of(type) == ino) {
    /*
     * setns is the call that *does* move a process into a time namespace, so
     * joining the one already occupied has to bring time_for_children along -
     * otherwise a process that unshared and then set itself back would go on
     * handing children the namespace it had abandoned.
     */
    if (type == NS_TIME && current_nsproxy.time_for_children != current_nsproxy.ns[NS_TIME]) {
      ns_put(current_nsproxy.time_for_children);
      current_nsproxy.time_for_children = current_nsproxy.ns[NS_TIME];
      current_nsproxy.time_for_children->refcount++;
    }
    return 0;                   /* already there */
  }

  /*
   * The namespace an unshare set aside for children is reachable, and it is the
   * one case that matters: unshare(CLONE_NEWTIME) does not move the caller, so
   * setns on the time_for_children descriptor is how a process joins what it
   * just made. Doing so freezes the offsets, since from here on a process is in
   * it.
   */
  if (type == NS_TIME && current_nsproxy.time_for_children->ino == ino) {
    struct namespace *ns = current_nsproxy.time_for_children;
    if (!timens_load(ns->ino, &ns->time))
      ;
    ns->time.frozen = 1;
    timens_store(ns->ino, &ns->time);
    ns_put(current_nsproxy.ns[NS_TIME]);
    ns->refcount++;
    current_nsproxy.ns[NS_TIME] = ns;
    return 0;
  }

  /* A namespace this process is not in belongs to another guest, and there is
   * no way to reach it until namespaces outlive the process that made them. */
  return -LINUX_EINVAL;
}

/*
 * The namespaces this process brought into being, released.
 *
 * Only the ones it created: a process that merely joined one must not take it
 * away from everyone else, and every forked child is in its parent's. The
 * ownership recorded when the namespace was made is what tells them apart.
 *
 * This is the prompt path, not the guarantee. A process killed outright never
 * runs it, so sysv_sweep at startup does the same job for anything left behind.
 */
void
nsproxy_release(void)
{
  if (ns_kinds[NS_IPC].supported)
    sysv_ns_release_owned(ns_ino_of(NS_IPC));
}

uint64_t
ns_ino_time_for_children(void)
{
  return current_nsproxy.time_for_children->ino;
}

/*
 * The offsets in force for this process, read fresh.
 *
 * From the file rather than from memory, because a parent that unshared and
 * then set them did so in another process - the same reason a hostname is not
 * kept here either.
 */
static void
timens_current(struct time_namespace *out)
{
  struct namespace *tns = current_nsproxy.ns[NS_TIME];
  if (!timens_load(tns->ino, out))
    *out = tns->time;
}

void
timens_shift(struct timespec *ts, bool boottime, int sign)
{
  struct time_namespace t;
  timens_current(&t);

  int64_t sec  = boottime ? t.boot_sec  : t.mono_sec;
  int64_t nsec = boottime ? t.boot_nsec : t.mono_nsec;
  if (sec == 0 && nsec == 0)
    return;

  ts->tv_sec  += sign * sec;
  ts->tv_nsec += sign * nsec;
  if (ts->tv_nsec >= 1000000000L) {
    ts->tv_nsec -= 1000000000L;
    ts->tv_sec++;
  } else if (ts->tv_nsec < 0) {
    ts->tv_nsec += 1000000000L;
    ts->tv_sec--;
  }
  /*
   * A namespace may not push a clock below zero. Linux refuses an offset that
   * would, when it is set; refusing it here as well costs nothing and means no
   * arithmetic downstream has to cope with a negative timespec.
   */
  if (ts->tv_sec < 0) {
    ts->tv_sec = 0;
    ts->tv_nsec = 0;
  }
}

int
timens_offsets_read(char *out, size_t n)
{
  struct time_namespace t;
  struct namespace *tns = current_nsproxy.time_for_children;
  if (!timens_load(tns->ino, &t))
    t = tns->time;
  return snprintf(out, n,
                  "monotonic %11lld %9lld\n"
                  "boottime  %11lld %9lld\n",
                  (long long) t.mono_sec, (long long) t.mono_nsec,
                  (long long) t.boot_sec, (long long) t.boot_nsec);
}

/*
 * Writing offsets, which is the only way a guest sets them.
 *
 * They belong to the namespace this process's *children* will be in, never to
 * the one it is in itself - so in the initial namespace, where those are the
 * same, there is nothing to write and Linux says so too. `unshare -T` and
 * anything like it does exactly this: unshare, write, fork.
 */
int
timens_offsets_write(const char *text)
{
  struct namespace *tns = current_nsproxy.time_for_children;

  if (tns == current_nsproxy.ns[NS_TIME])
    return -LINUX_EPERM;        /* the one we are in; not ours to move */

  struct time_namespace t;
  if (!timens_load(tns->ino, &t))
    t = tns->time;
  if (t.frozen)
    return -LINUX_EACCES;       /* somebody is in it now */

  /*
   * Nothing to parse is not a failure. A shell splits `echo x > file` into more
   * than one write and the trailing newline can arrive on its own, so rejecting
   * an all-whitespace write made a redirect that had already taken effect
   * report an I/O error afterwards.
   */
  const char *p = text;
  while (*p == ' ' || *p == '\t' || *p == '\n')
    p++;
  if (*p == '\0')
    return 0;

  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == '\n')
      p++;
    if (*p == '\0')
      break;

    /* Linux takes either the clock's name or its number. */
    bool boot;
    if (strncmp(p, "monotonic", 9) == 0) { boot = false; p += 9; }
    else if (strncmp(p, "boottime", 8) == 0) { boot = true; p += 8; }
    else if (*p == '1') { boot = false; p += 1; }
    else if (*p == '7') { boot = true; p += 1; }
    else return -LINUX_EINVAL;

    char *end;
    long long sec = strtoll(p, &end, 10);
    if (end == p)
      return -LINUX_EINVAL;
    p = end;
    long long nsec = strtoll(p, &end, 10);
    if (end == p)
      nsec = 0;
    else
      p = end;
    if (nsec < 0 || nsec >= 1000000000LL)
      return -LINUX_EINVAL;

    if (boot) { t.boot_sec = sec; t.boot_nsec = nsec; }
    else      { t.mono_sec = sec; t.mono_nsec = nsec; }
  }
  tns->time = t;
  timens_store(tns->ino, &t);
  return 0;
}
