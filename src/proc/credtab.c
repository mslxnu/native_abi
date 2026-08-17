/*
 * What a socket's peer is, in the guest's own terms.
 *
 * SO_PEERCRED asks who is on the other end of a unix socket, and the answer
 * decides things: D-Bus authenticates with EXTERNAL, where the client states a
 * uid and the bus believes it only if the kernel agrees. Darwin will answer the
 * question - LOCAL_PEERCRED - but it answers about the *host*, and every guest
 * process is the same host account, so the honest translation of that answer is
 * "the account nabi runs as" for every peer alive. A guest running as an
 * ordinary user asking about its own socket got root, disagreed with itself,
 * and the bus never replied.
 *
 * The credential a peer has is the peer's own, and it lives in the peer's
 * address space where nothing else can reach it. So each process publishes it:
 * a small table in TMPDIR, keyed by host pid, written at startup and again
 * whenever the ids change, read by whoever needs to name a peer. Same shape as
 * the pid namespace table next door, and tagged with the same boot tag, so a
 * table left behind by an earlier boot is never read as this one's.
 *
 * What this does not reproduce: Linux records a peer's credentials at connect
 * time and reports those forever after, so a process that connects and then
 * drops privilege still shows the ids it connected with. Here the table holds
 * what the peer is *now*. Reaching the connect-time answer would mean a hook on
 * the far side of an accept, which is not something a peer can be made to run.
 * The difference is visible only to a program that changes uid on a connection
 * it keeps open, and the callers that matter - the buses - do the opposite:
 * they authenticate once, at the start, before anything has moved.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"

#define CREDTAB_MAX 1024

struct credtab_file {
  uint32_t n;
  struct {
    int32_t  pid;
    uint32_t uid, gid;
  } map[CREDTAB_MAX];
};

static void
credtab_path(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-cred-%s", tmp && *tmp ? tmp : "/tmp",
           nabi_boot_tag());
}

/* Opened for a read-modify-write, created on first use. */
static int
credtab_open(bool lock)
{
  char path[PATH_MAX];
  credtab_path(path, sizeof path);
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return -1;
  if (lock && flock(fd, LOCK_EX) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool
credtab_read(int fd, struct credtab_file *f)
{
  ssize_t n = pread(fd, f, sizeof *f, 0);
  if (n == (ssize_t) sizeof *f)
    return true;
  /* A table that does not exist yet is an empty one, not a failure. */
  memset(f, 0, sizeof *f);
  return n >= 0;
}

/*
 * Publish this process's ids.
 *
 * Called with proc.cred.lock already held by the writers, so the ids come in as
 * arguments rather than being read back out from under the caller.
 */
void
cred_publish(uint32_t uid, uint32_t gid)
{
  int fd = credtab_open(true);
  if (fd < 0)
    return;

  struct credtab_file f;
  if (credtab_read(fd, &f)) {
    int32_t me = (int32_t) getpid();
    uint32_t slot = f.n;

    for (uint32_t i = 0; i < f.n; i++)
      if (f.map[i].pid == me) {
        slot = i;                       /* our own entry, or a pid reused */
        break;
      }
    /*
     * A full table is made room in by dropping an entry whose process is gone.
     * Entries are only ever removed this way: a process cannot be relied on to
     * clean up after itself - it can be killed - and a stale entry is harmless
     * until its pid comes round again, which is exactly when it gets replaced.
     */
    if (slot == f.n && f.n == CREDTAB_MAX) {
      for (uint32_t i = 0; i < f.n; i++)
        if (kill(f.map[i].pid, 0) < 0 && errno == ESRCH) {
          slot = i;
          break;
        }
    }
    if (slot < CREDTAB_MAX) {
      f.map[slot].pid = me;
      f.map[slot].uid = uid;
      f.map[slot].gid = gid;
      if (slot == f.n)
        f.n++;
      pwrite(fd, &f, sizeof f, 0);
    }
  }

  flock(fd, LOCK_UN);
  close(fd);
}

/*
 * The ids a host pid published, if it published any.
 *
 * False for a pid that is not a guest process at all, which leaves the caller
 * to fall back on what the host says - the right answer for a peer that really
 * is outside.
 */
bool
cred_of_host_pid(int32_t pid, uint32_t *uid, uint32_t *gid)
{
  int fd = credtab_open(false);
  if (fd < 0)
    return false;

  struct credtab_file f;
  bool ok = credtab_read(fd, &f);
  close(fd);
  if (!ok)
    return false;

  for (uint32_t i = 0; i < f.n; i++)
    if (f.map[i].pid == pid) {
      *uid = f.map[i].uid;
      *gid = f.map[i].gid;
      return true;
    }
  return false;
}
