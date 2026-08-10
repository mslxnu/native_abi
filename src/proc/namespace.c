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
  [NS_IPC]    = { NS_IPC,    "ipc",    LINUX_CLONE_NEWIPC,    false },
  [NS_PID]    = { NS_PID,    "pid",    LINUX_CLONE_NEWPID,    false },
  [NS_NET]    = { NS_NET,    "net",    LINUX_CLONE_NEWNET,    false },
  [NS_USER]   = { NS_USER,   "user",   LINUX_CLONE_NEWUSER,   false },
  [NS_CGROUP] = { NS_CGROUP, "cgroup", LINUX_CLONE_NEWCGROUP, false },
  [NS_TIME]   = { NS_TIME,   "time",   LINUX_CLONE_NEWTIME,   false },
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

static void
uts_path(uint64_t ino, char *out, size_t n)
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
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-uts-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", boot, (unsigned long long) ino);
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
    if (type == NS_UTS) {
      uts_load(from->ino, &ns->uts);      /* whatever it is *now* */
      uts_store(ns->ino, &ns->uts);
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
    if (ns == NULL) {
      pthread_mutex_unlock(&ns_lock);
      return -LINUX_ENOMEM;
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

  if (ns_ino_of(type) == ino)
    return 0;                   /* already there */

  /* A namespace this process is not in belongs to another guest, and there is
   * no way to reach it until namespaces outlive the process that made them. */
  return -LINUX_EINVAL;
}
