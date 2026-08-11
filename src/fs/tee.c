/*
 * tee(2): copying between pipes without consuming, on a host that cannot peek.
 *
 * tee's whole point is that what it copied is still there to be read. Darwin
 * offers no way to look into a pipe without taking from it - FIONREAD gives a
 * count and not the bytes, and there is no pread on one - so the obvious
 * implementation is to read and write back, and the obvious implementation is
 * wrong in two ways that are worth spelling out, because the second one is what
 * rules out every variation of it.
 *
 *   Reading part of a queue and appending it returns it *behind* what was left:
 *   "ABCDEF" tee'd four bytes at a time comes back "EFABCD". Draining the whole
 *   queue and restoring it fixes that.
 *
 *   But restoring is not atomic with respect to writers, and a writer is not an
 *   exotic case here - it is the process feeding the pipe, which is the entire
 *   topology tee is used in. Anything it writes while the data is out lands in
 *   front of the restored bytes. Holding a lock across the restore does not fix
 *   it either: a writer would have to take that lock *before* deciding to
 *   write, which costs every pipe write in the system, and a writer blocked on
 *   a full pipe while holding it deadlocks the drain that would empty it.
 *
 * So nothing is ever restored. The bytes tee removes are kept in front of the
 * pipe instead of back in it: a pushback that reads are served from first, and
 * the pipe read only when it is empty. That has no writer hazard at all,
 * because a writer appends to the pipe, which is exactly where its bytes belong
 * - after everything tee is still holding. Order is preserved by construction
 * rather than by exclusion.
 *
 * It works because nabi is the only thing that ever reads a guest pipe. There
 * is no host process on the other end to bypass this.
 *
 * The pushback is shared, not per-process, because a pipe is. It is keyed by the
 * pipe itself, so the two processes sharing one share its pushback too, and a
 * guest with no pending pushback pays one load from a shared mapping to find
 * that out.
 *
 * Naming the pipe took two goes. A read end's inode is stable across fork and
 * across the exec nabi's fork is built on, which is what sharing needs - but it
 * is *not* unique over time. Darwin's pipe inodes look random and are drawn from
 * a pool that is reused: three runs of a two-pipe program produced the same
 * value twice. Keyed on the inode alone, a pushback left behind by a process
 * that teed and exited without reading would be picked up by an unrelated later
 * pipe that drew the same number, and its bytes injected into that stream. That
 * is the exact corruption this file exists to avoid, arriving by the back door.
 *
 * So a pipe is named by *both* ends: its own handle and its peer's, which
 * proc_pidfdinfo reports and which are allocated independently. A stale file
 * cannot be mistaken for a live pipe unless a new pipe draws both numbers as the
 * same matched pair, rather than either one of them. The peer is in the name and
 * not in a header, so a mismatch is simply a file that is not found.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/errno.h"

/* Last on purpose: libproc.h reaches sys/param.h, whose roundup() macro eats
 * the inline of that name in util/misc.h if it gets there first. */
#include <libproc.h>

/*
 * How many pipes currently hold pushback, in a mapping every process shares.
 * Read on the way into read(2) and poll(2), so it has to be answerable without
 * a syscall - which is the whole reason it is a mapping rather than a lookup.
 */
struct tee_counter {
  uint32_t magic;
  uint32_t pending;
};
#define TEE_MAGIC 0x65657400u   /* "tee" */

static struct tee_counter *counter;

static void
counter_path(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-teecount-%s",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag());
}

static void
pushback_path(uint64_t self, uint64_t peer, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-tee-%s-%llu-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) self, (unsigned long long) peer);
}

static struct tee_counter *
counter_map(bool create)
{
  if (counter)
    return counter;
  char path[PATH_MAX];
  counter_path(path, sizeof path);
  int fd = open(path, create ? (O_RDWR | O_CREAT) : O_RDWR, 0600);
  if (fd < 0)
    return NULL;
  if (ftruncate(fd, sizeof(struct tee_counter)) < 0 && errno != EINVAL) {
    close(fd);
    return NULL;
  }
  void *p = mmap(NULL, sizeof(struct tee_counter), PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
  close(fd);
  if (p == MAP_FAILED)
    return NULL;
  counter = p;
  if (counter->magic != TEE_MAGIC) {
    counter->magic = TEE_MAGIC;
    counter->pending = 0;
  }
  return counter;
}

bool
tee_pending(void)
{
  struct tee_counter *c = counter ? counter : counter_map(false);
  return c != NULL && c->pending != 0;
}

/*
 * A pipe's two handles: its own and the far end's. False for anything that is
 * not a pipe, which is also how the callers below test for one - proc_pidfdinfo
 * answers for pipes and refuses everything else, so it settles both questions at
 * once.
 */
static bool
pipe_ids(int fd, uint64_t *self, uint64_t *peer)
{
  struct pipe_fdinfo pi;
  if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDPIPEINFO, &pi, sizeof pi)
      != sizeof pi)
    return false;
  if (self)
    *self = (uint64_t) pi.pipeinfo.pipe_handle;
  if (peer)
    *peer = (uint64_t) pi.pipeinfo.pipe_peerhandle;
  return true;
}

/* --------------------------------------------------------------- the store */

/*
 * Take bytes from a pipe's pushback. Returns how many, 0 if there is none, or
 * -1 if this descriptor has no pushback at all - which is the answer read(2)
 * uses to decide it is an ordinary read.
 */
ssize_t
tee_take(int fd, char *buf, size_t want)
{
  if (!tee_pending() || want == 0)
    return -1;
  uint64_t self, peer;
  if (!pipe_ids(fd, &self, &peer))
    return -1;

  char path[PATH_MAX];
  pushback_path(self, peer, path, sizeof path);
  int f = open(path, O_RDWR);
  if (f < 0)
    return -1;
  flock(f, LOCK_EX);

  off_t size = lseek(f, 0, SEEK_END);
  if (size <= 0) {
    flock(f, LOCK_UN);
    close(f);
    return -1;
  }

  size_t n = (size_t) size < want ? (size_t) size : want;
  if (pread(f, buf, n, 0) != (ssize_t) n) {
    flock(f, LOCK_UN);
    close(f);
    return -1;
  }

  /* What is left moves to the front, so the next read continues in order. */
  size_t left = (size_t) size - n;
  if (left) {
    char *rest = malloc(left);
    if (rest) {
      if (pread(f, rest, left, (off_t) n) == (ssize_t) left) {
        (void) !pwrite(f, rest, left, 0);
        (void) !ftruncate(f, (off_t) left);
      }
      free(rest);
    }
  } else {
    /* Drained. The file goes, and with it this pipe's share of the count that
     * keeps every other read from having to look. */
    ftruncate(f, 0);
    unlink(path);
    if (counter)
      __sync_fetch_and_sub(&counter->pending, 1);
  }

  flock(f, LOCK_UN);
  close(f);
  return (ssize_t) n;
}

/* Whether a descriptor is readable because of pushback, for poll and friends. */
bool
tee_readable(int fd)
{
  if (!tee_pending())
    return false;
  uint64_t self, peer;
  if (!pipe_ids(fd, &self, &peer))
    return false;
  char path[PATH_MAX];
  pushback_path(self, peer, path, sizeof path);
  struct stat st;
  return stat(path, &st) == 0 && st.st_size > 0;
}

/*
 * The same question for select's three bitmaps.
 *
 * select answers by rewriting the set it was given, so deciding and marking
 * cannot be one pass: the caller keeps a copy of what it asked about, asks
 * whether any of those has pushback - and if so does not wait - then marks the
 * ones select did not already report.
 */
bool
tee_any_readable(int nfds, const fd_set *want)
{
  if (!want || !tee_pending())
    return false;
  for (int fd = 0; fd < nfds; fd++)
    if (FD_ISSET(fd, want) && tee_readable(fd))
      return true;
  return false;
}

int
tee_mark_readable(int nfds, fd_set *out, const fd_set *want)
{
  if (!out || !want || !tee_pending())
    return 0;
  int n = 0;
  for (int fd = 0; fd < nfds; fd++) {
    if (FD_ISSET(fd, want) && !FD_ISSET(fd, out) && tee_readable(fd)) {
      FD_SET(fd, out);
      n++;
    }
  }
  return n;
}

/*
 * Sweep pushback left by a boot that is over.
 *
 * Within a boot a pipe's inode is not reused - macOS hands out 64-bit values
 * that are not sequential - so a stale file cannot be mistaken for a live
 * pipe's. Across boots the name would collide, which is what the boot tag in it
 * prevents and what this removes.
 */
void
tee_sweep(void)
{
  const char *tmp = getenv("TMPDIR");
  char base[PATH_MAX], mine[64];
  snprintf(base, sizeof base, "%s", tmp && *tmp ? tmp : "/tmp");
  snprintf(mine, sizeof mine, "nabi-tee-%s-", nabi_boot_tag());

  DIR *d = opendir(base);
  if (!d)
    return;
  struct dirent *e;
  char path[PATH_MAX];
  while ((e = readdir(d)) != NULL) {
    bool ours = strncmp(e->d_name, "nabi-tee-", 9) == 0 ||
                strncmp(e->d_name, "nabi-teecount-", 14) == 0;
    if (!ours)
      continue;
    if (strncmp(e->d_name, mine, strlen(mine)) == 0)
      continue;                 /* this boot's, and possibly in use */
    snprintf(path, sizeof path, "%s/%s", base, e->d_name);
    unlink(path);
  }
  closedir(d);
}

/* ------------------------------------------------------------------ tee(2) */

DEFINE_SYSCALL(tee, int, fd_in, int, fd_out, size_t, len, unsigned int, flags)
{
  /* SPLICE_F_NONBLOCK is the only one that means anything to tee; the rest are
   * about page moving, which is not what happens here. */
#define LINUX_SPLICE_F_NONBLOCK 0x02
  if (flags & ~(unsigned) (0x01 | LINUX_SPLICE_F_NONBLOCK | 0x04 | 0x08))
    return -LINUX_EINVAL;
  if (len == 0)
    return 0;

  uint64_t in_self, in_peer, out_self;
  if (!pipe_ids(fd_in, &in_self, &in_peer) ||
      !pipe_ids(fd_out, &out_self, NULL))
    return -LINUX_EINVAL;       /* both must be pipes, as on Linux */
  /* And not the two ends of one pipe. Linux detects that by the shared inode
   * its two ends have; Darwin gives them unrelated numbers, so the question is
   * put to the pipe itself - the far end of fd_in is exactly fd_out. */
  if (in_peer == out_self)
    return -LINUX_EINVAL;

  if (len > 65536)
    len = 65536;
  char *buf = malloc(len);
  if (!buf)
    return -LINUX_ENOMEM;

  /*
   * What is already in the pushback comes first: it is in front of the pipe, so
   * it is what a reader would see next, and therefore what tee must copy.
   */
  ssize_t n = 0;
  char path[PATH_MAX];
  pushback_path(in_self, in_peer, path, sizeof path);
  int pb = open(path, O_RDWR);
  off_t have = 0;
  if (pb >= 0) {
    flock(pb, LOCK_EX);
    have = lseek(pb, 0, SEEK_END);
    if (have > 0) {
      size_t take = (size_t) have < len ? (size_t) have : len;
      if (pread(pb, buf, take, 0) == (ssize_t) take)
        n = (ssize_t) take;
    }
  }

  /* Then the pipe itself, for whatever is still wanted. */
  if ((size_t) n < len) {
    int fl = fcntl(fd_in, F_GETFL);
    bool nonblock = (flags & LINUX_SPLICE_F_NONBLOCK) ||
                    (fl >= 0 && (fl & O_NONBLOCK));
    if (nonblock && fl >= 0)
      fcntl(fd_in, F_SETFL, fl | O_NONBLOCK);

    ssize_t r = read(fd_in, buf + n, len - (size_t) n);
    if (nonblock && fl >= 0)
      fcntl(fd_in, F_SETFL, fl);

    if (r > 0) {
      /* Taken out of the pipe, so it has to go into the pushback or it is
       * lost. That is the whole contract of this call. */
      if (pb < 0) {
        pb = open(path, O_RDWR | O_CREAT, 0600);
        if (pb < 0) {
          free(buf);
          return -LINUX_ENOMEM;
        }
        flock(pb, LOCK_EX);
        have = lseek(pb, 0, SEEK_END);
        if (counter_map(true))
          __sync_fetch_and_add(&counter->pending, 1);
      }
      if (pwrite(pb, buf + n, (size_t) r, have) != r) {
        flock(pb, LOCK_UN);
        close(pb);
        free(buf);
        return -LINUX_EIO;
      }
      n += r;
    } else if (r < 0 && n == 0) {
      int e = errno;
      if (pb >= 0) { flock(pb, LOCK_UN); close(pb); }
      free(buf);
      return -darwin_to_linux_errno(e);
    }
  }

  if (pb >= 0) {
    flock(pb, LOCK_UN);
    close(pb);
  }

  if (n == 0) {
    free(buf);
    return 0;                   /* end of stream, as tee reports it */
  }

  ssize_t w = write(fd_out, buf, (size_t) n);
  free(buf);
  if (w < 0)
    return -darwin_to_linux_errno(errno);
  return (int) w;
}
