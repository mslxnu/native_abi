/*
 * The pid namespace: a translation between the pids a guest is told and the
 * host pids nabi actually has.
 *
 * Guest pids *are* host pids everywhere else in nabi - getpid, kill, wait4,
 * signals, /proc and the fork checkpoint all use them directly - which is why
 * namespace.h called this the large one. What makes it tractable is that the
 * initial namespace is the identity: a process that never unshares gets its
 * host pid back from every call here, on the first line, and nothing about it
 * changes. The translation exists only for processes that asked for one, which
 * is where the whole blast radius of this change lives.
 *
 * The membership table is per namespace and lives in a file, like every other
 * namespace's contents and for the same reason - nabi's processes are separate
 * host processes, so a pid allocated in one has to be the same pid in the next.
 *
 * A process is registered by its *parent*, immediately after fork returns,
 * rather than by itself when it resumes. That is deliberate: the parent's
 * return value from clone has to be the child's pid in the parent's namespace,
 * and a child that registered itself might not have done so yet. Registering
 * from the side that already knows the number removes the race rather than
 * closing it.
 *
 * What this does not do, and what a reader should not assume from the word
 * "namespace":
 *
 *   - It does not conceal. /proc is mSL/ProcFS's passthrough of the host's, so
 *     a guest already sees every process on the Mac and goes on doing so inside
 *     a pid namespace. Renumbering is real; hiding is not available from here.
 *     kill and /proc/<pid> *are* contained - a pid that is not a member does
 *     not translate, and gets ESRCH - so what leaks is the listing, not reach.
 *
 *   - There is no init. Linux reparents orphans to pid 1 of their namespace and
 *     tears the namespace down when that process dies; both are supervisor
 *     behaviour, and nabi has no supervisor - the host reparents orphans to
 *     launchd. A container whose init exits here leaves its children running.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"

#include "linux/common.h"
#include "linux/errno.h"

#define PIDNS_MAX 512

struct pidns_file {
  uint64_t parent_ino;
  uint32_t next;                /* the next namespace pid to hand out */
  uint32_t n;
  struct { int32_t host, ns; } map[PIDNS_MAX];
};

static void
pidns_path(uint64_t ino, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-pidns-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) ino);
}

static uint64_t
initial_pid_ino(void)
{
  return NS_INO_FIRST + (unsigned) NS_PID;
}

bool
pidns_active(void)
{
  return ns_ino_of(NS_PID) != initial_pid_ino();
}

/* Open the table, locked for a read-modify-write. -1 if there is none. */
static int
pidns_open(uint64_t ino, bool lock)
{
  char path[PATH_MAX];
  pidns_path(ino, path, sizeof path);
  int fd = open(path, O_RDWR);
  if (fd < 0)
    return -1;
  if (lock && flock(fd, LOCK_EX) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool
pidns_read(int fd, struct pidns_file *f)
{
  return pread(fd, f, sizeof *f, 0) == (ssize_t) sizeof *f;
}

static bool
pidns_write(int fd, const struct pidns_file *f)
{
  return pwrite(fd, f, sizeof *f, 0) == (ssize_t) sizeof *f;
}

void
pidns_create(uint64_t ino, uint64_t parent_ino)
{
  char path[PATH_MAX];
  pidns_path(ino, path, sizeof path);

  struct pidns_file f;
  memset(&f, 0, sizeof f);
  f.parent_ino = parent_ino;
  f.next = 1;                   /* the first process in it is pid 1 */

  int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  pidns_write(fd, &f);
  close(fd);
}

int32_t
pidns_to_ns(int32_t host)
{
  if (!pidns_active())
    return host;                /* the initial namespace is the identity */

  int fd = pidns_open(ns_ino_of(NS_PID), false);
  if (fd < 0)
    return 0;
  struct pidns_file f;
  bool ok = pidns_read(fd, &f);
  close(fd);
  if (!ok)
    return 0;

  for (uint32_t i = 0; i < f.n; i++)
    if (f.map[i].host == host)
      return f.map[i].ns;
  return 0;                     /* not a member: it does not exist here */
}

int32_t
pidns_to_host(int32_t ns)
{
  if (!pidns_active())
    return ns;

  int fd = pidns_open(ns_ino_of(NS_PID), false);
  if (fd < 0)
    return -1;
  struct pidns_file f;
  bool ok = pidns_read(fd, &f);
  close(fd);
  if (!ok)
    return -1;

  for (uint32_t i = 0; i < f.n; i++)
    if (f.map[i].ns == ns)
      return f.map[i].host;
  return -1;
}

/* Add a host pid to one namespace's table, under its lock. */
static void
enrol(uint64_t ino, int32_t host)
{
  int fd = pidns_open(ino, true);
  if (fd < 0)
    return;
  struct pidns_file f;
  if (pidns_read(fd, &f) && f.n < PIDNS_MAX) {
    bool already = false;
    for (uint32_t i = 0; i < f.n; i++)
      if (f.map[i].host == host)
        already = true;
    if (!already) {
      f.map[f.n].host = host;
      f.map[f.n].ns = (int32_t) f.next++;
      f.n++;
      pidns_write(fd, &f);
    }
  }
  flock(fd, LOCK_UN);
  close(fd);
}

int32_t
pidns_add_child(int32_t host)
{
  uint64_t child_ns = ns_ino_pid_for_children();

  /*
   * Registered in the namespace it is joining and in every ancestor, because a
   * process has a pid in each of them - that is what nesting means, and a
   * grandparent that could not name its own descendant would have no way to
   * wait for it.
   */
  for (uint64_t ino = child_ns; ino != initial_pid_ino(); ) {
    enrol(ino, host);

    int fd = pidns_open(ino, false);
    if (fd < 0)
      break;
    struct pidns_file f;
    bool ok = pidns_read(fd, &f);
    close(fd);
    if (!ok || f.parent_ino == 0 || f.parent_ino == ino)
      break;
    ino = f.parent_ino;
  }

  /* What the caller should be told, which is the child's pid in the caller's
   * own namespace and not in the one the child went into. */
  return pidns_to_ns(host);
}
