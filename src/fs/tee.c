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
 * The pushback is shared, not per-process, because a pipe is. It is keyed by
 * the read end's inode, which macOS gives a 64-bit value that is identical in a
 * forked child and across the exec nabi's fork is built on - verified, not
 * assumed - so the two processes sharing a pipe share its pushback too. A guest
 * with no pending pushback pays one load in read and in poll to find that out.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
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
pushback_path(uint64_t ino, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-tee-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) ino);
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

/* The read end's inode, or 0 for anything that is not a pipe. */
static uint64_t
pipe_id(int fd)
{
  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISFIFO(st.st_mode))
    return 0;
  return (uint64_t) st.st_ino;
}

/*
 * Which write end belongs to which read end.
 *
 * tee(p[0], p[1]) is EINVAL on Linux, and the check is easy there because both
 * ends of a pipe share one inode. Darwin gives them unrelated ones - measured,
 * not assumed - so nothing in fstat says the two descriptors are the same pipe,
 * and the pairing has to be remembered from the one place that sees both, which
 * is pipe2.
 *
 * A ring of the last few hundred, because pipes are made and dropped constantly
 * and a table keyed by inode would only grow. Falling off the end means the
 * check is skipped for a very old pipe, and means the same for one inherited
 * across a fork, since this is per-process. Both are the wrong answer to a call
 * no working program makes - a guest that teed a pipe into itself would get its
 * bytes duplicated instead of EINVAL - and neither is worth making every pipe in
 * the system pay for a shared mapping to catch.
 */
#define PAIRS 256
static struct { uint64_t r, w; } pairs[PAIRS];
static int pairs_next;
static pthread_mutex_t pairs_lock = PTHREAD_MUTEX_INITIALIZER;

void
tee_note_pipe(int rfd, int wfd)
{
  struct stat r, w;
  if (fstat(rfd, &r) < 0 || fstat(wfd, &w) < 0)
    return;
  pthread_mutex_lock(&pairs_lock);
  pairs[pairs_next].r = (uint64_t) r.st_ino;
  pairs[pairs_next].w = (uint64_t) w.st_ino;
  pairs_next = (pairs_next + 1) % PAIRS;
  pthread_mutex_unlock(&pairs_lock);
}

static bool
same_pipe(uint64_t r, uint64_t w)
{
  bool found = false;
  pthread_mutex_lock(&pairs_lock);
  for (int i = 0; i < PAIRS && !found; i++)
    found = pairs[i].r == r && pairs[i].w == w;
  pthread_mutex_unlock(&pairs_lock);
  return found;
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
  uint64_t id = pipe_id(fd);
  if (id == 0)
    return -1;

  char path[PATH_MAX];
  pushback_path(id, path, sizeof path);
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
  uint64_t id = pipe_id(fd);
  if (id == 0)
    return false;
  char path[PATH_MAX];
  pushback_path(id, path, sizeof path);
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

  struct stat si, so;
  if (fstat(fd_in, &si) < 0 || fstat(fd_out, &so) < 0)
    return -LINUX_EBADF;
  if (!S_ISFIFO(si.st_mode) || !S_ISFIFO(so.st_mode))
    return -LINUX_EINVAL;       /* both must be pipes, as on Linux */
  if (same_pipe((uint64_t) si.st_ino, (uint64_t) so.st_ino))
    return -LINUX_EINVAL;       /* and not the two ends of the same one */

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
  pushback_path((uint64_t) si.st_ino, path, sizeof path);
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
