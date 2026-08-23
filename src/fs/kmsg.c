/*
 * /dev/kmsg: the kernel log, for a system whose kernel is a userspace process.
 *
 * There is no kernel here to keep a ring buffer, so nabi keeps one. It matters
 * more than it sounds: a guest's most important diagnostics go here and
 * nowhere else. Android's init writes every line of its boot to /dev/kmsg -
 * every "Command 'x' failed", every service that would not start - and until
 * now that device was mapped onto /dev/null, so those lines were discarded at
 * the moment they were written. They could be recovered only by running a
 * syscall trace and reading the buffers out of the write() records, which is
 * how several of this port's bugs actually had to be diagnosed.
 *
 * The log is a file shared by every process of the instance, because that is
 * what the guest expects: init writes and logd reads, and they are different
 * processes. It is keyed by the boot tag, like the mount tables, so two guests
 * do not write into each other's log.
 *
 * The file holds records in exactly the form a reader is given them, which is
 * Linux's:
 *
 *     <priority>,<sequence>,<microseconds>,-;<message>
 *
 * so serving a read is finding the next line rather than reformatting
 * anything. A record is written under an exclusive lock and read with pread,
 * so a reader never sees half of one and two writers never interleave.
 */
#include "common.h"
#include "noah.h"
#include "namespace.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"

#define KMSG_MAX_RECORD 8192       /* Linux's own limit is about this */
#define KMSG_MAX_READERS 32

/*
 * A reader's place in the log, which is a byte offset because the records are
 * lines. Linux gives each open descriptor its own position and starts it at
 * the oldest record it still has; nothing here is ever discarded, so that is
 * the beginning of the file.
 */
struct kmsg_reader {
  int   fd;                        /* the descriptor the guest holds; -1 free */
  off_t pos;
};

static struct kmsg_reader readers[KMSG_MAX_READERS];
static pthread_mutex_t readers_lock = PTHREAD_MUTEX_INITIALIZER;

void
kmsg_init(void)
{
  for (int i = 0; i < KMSG_MAX_READERS; i++)
    readers[i].fd = -1;
}

#define KMSG_ENV "NABI_KMSG"

/*
 * Where this instance's log lives.
 *
 * Per instance, not per boot: a kernel log belongs to one running system, and
 * a guest starting again is a new one. Keyed by the boot tag alone it outlived
 * every guest that had ever run on the host, so a fresh boot opened a log
 * already full of somebody else's records - and read them back as its own.
 *
 * The first process picks the name and leaves it in the environment; every
 * forked child inherits it, which is the same way the binder broker finds its
 * rendezvous and the debug sinks find their files. A guest exec does not
 * disturb it, because exec rebuilds the guest's stack and not nabi's
 * environment.
 */
static void
kmsg_path(char *out, size_t n)
{
  const char *set = getenv(KMSG_ENV);
  if (set != NULL && *set != '\0') {
    snprintf(out, n, "%s", set);
    return;
  }
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-kmsg-%s-%d", tmp && *tmp ? tmp : "/tmp",
           nabi_boot_tag(), (int) getpid());
  setenv(KMSG_ENV, out, 1);
}

/* The log itself, created on first use. Opened afresh each time rather than
 * cached, because a resumed child inherits none of this file's state. */
static int
kmsg_log_open(void)
{
  char path[PATH_MAX];
  kmsg_path(path, sizeof path);
  return open(path, O_RDWR | O_CREAT | O_APPEND, 0600);
}

/*
 * A slot for a descriptor the guest holds. Negative descriptors are refused
 * rather than searched for, because a free slot *is* fd < 0 - looking one up
 * would answer with the first unused slot and hand its owner somebody else's
 * log position. Finding a free slot is a different question and has its own
 * function below.
 */
static struct kmsg_reader *
kmsg_lookup(int fd)
{
  if (fd < 0)
    return NULL;
  for (int i = 0; i < KMSG_MAX_READERS; i++)
    if (readers[i].fd == fd)
      return &readers[i];
  return NULL;
}

static struct kmsg_reader *
kmsg_free_slot(void)
{
  for (int i = 0; i < KMSG_MAX_READERS; i++)
    if (readers[i].fd < 0)
      return &readers[i];
  return NULL;
}

bool
kmsg_is(int fd)
{
  pthread_mutex_lock(&readers_lock);
  bool yes = kmsg_lookup(fd) != NULL;
  pthread_mutex_unlock(&readers_lock);
  return yes;
}

/*
 * Open the device. The descriptor the guest gets is one on the log file, so
 * that closing and dup'ing behave without anything special; what it is read
 * and written with is decided here rather than by the file's own contents.
 */
int
kmsg_open(int flags, int *out_fd)
{
  int fd = kmsg_log_open();
  if (fd < 0)
    return -1;
  if (flags & LINUX_O_CLOEXEC)
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  /* O_NONBLOCK has to reach the descriptor, because that is where a read looks
   * to decide whether the guest wanted to wait at the end of the log. Left
   * off, a reader that asked not to block waits forever for a record nobody is
   * going to write. */
  if (flags & LINUX_O_NONBLOCK)
    fcntl(fd, F_SETFL, O_NONBLOCK);

  pthread_mutex_lock(&readers_lock);
  struct kmsg_reader *r = kmsg_free_slot();
  if (r == NULL) {
    pthread_mutex_unlock(&readers_lock);
    close(fd);
    errno = EMFILE;
    return -1;
  }
  r->pos = 0;                      /* the oldest record, as Linux does */
  r->fd = fd;
  pthread_mutex_unlock(&readers_lock);

  *out_fd = fd;
  return 0;
}

void
kmsg_close(int fd)
{
  pthread_mutex_lock(&readers_lock);
  struct kmsg_reader *r = kmsg_lookup(fd);
  if (r != NULL)
    r->fd = -1;
  pthread_mutex_unlock(&readers_lock);
}

/*
 * A write is one record.
 *
 * The guest may put a priority on the front as "<N>", which is what every
 * logger does and what init does for every line; without one the record is
 * KERN_INFO, as Linux assumes. The newline a caller supplies is dropped
 * because the record format supplies its own - a line that kept both would
 * read back as an empty record following the real one.
 */
bool
kmsg_write(int fd, const char *buf, size_t size, int *ret)
{
  if (!kmsg_is(fd))
    return false;

  int prio = 6;                    /* KERN_INFO */
  const char *msg = buf;
  size_t left = size;
  if (left >= 3 && msg[0] == '<') {
    const char *close_at = memchr(msg, '>', left < 5 ? left : 5);
    if (close_at != NULL) {
      int v = 0;
      bool digits = close_at > msg + 1;
      for (const char *p = msg + 1; p < close_at; p++) {
        if (*p < '0' || *p > '9') { digits = false; break; }
        v = v * 10 + (*p - '0');
      }
      if (digits && v >= 0 && v <= 255) {
        prio = v;
        left -= (size_t)(close_at + 1 - msg);
        msg = close_at + 1;
      }
    }
  }
  while (left > 0 && (msg[left - 1] == '\n' || msg[left - 1] == '\0'))
    left--;
  if (left > KMSG_MAX_RECORD)
    left = KMSG_MAX_RECORD;

  int log = kmsg_log_open();
  if (log < 0) {
    *ret = -LINUX_EIO;
    return true;
  }
  flock(log, LOCK_EX);

  /*
   * The sequence number is the count of records already there. Derived rather
   * than kept, so it survives a process that never saw the earlier ones - a
   * forked child has no memory of what its parent logged.
   */
  uint64_t seq = 0;
  {
    char scan[4096];
    off_t at = 0;
    ssize_t n;
    while ((n = pread(log, scan, sizeof scan, at)) > 0) {
      for (ssize_t i = 0; i < n; i++)
        if (scan[i] == '\n')
          seq++;
      at += n;
    }
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);
  uint64_t usec = (uint64_t) tv.tv_sec * 1000000u + (uint64_t) tv.tv_usec;

  char head[64];
  int hn = snprintf(head, sizeof head, "%d,%llu,%llu,-;",
                    prio, (unsigned long long) seq, (unsigned long long) usec);
  struct iovec iov[3] = {
    { head, (size_t) hn },
    { (void *) msg, left },
    { (void *) "\n", 1 },
  };
  ssize_t w = writev(log, iov, 3);
  flock(log, LOCK_UN);
  close(log);

  if (w < 0) {
    *ret = -LINUX_EIO;
    return true;
  }
  *ret = (int) size;               /* the guest wrote all of what it gave */
  return true;
}

/*
 * A read is one record, and never part of one.
 *
 * Linux answers EINVAL when the buffer cannot hold the whole record rather
 * than truncating it, because a half record is not a record. At the end of the
 * log a reader is told to wait; there is no wakeup to sleep on across
 * processes here - the writer is a different process with no handle on this
 * one - so a blocking reader looks again on a short interval, and can be
 * interrupted by a signal like any other blocking read.
 */
bool
kmsg_read(int fd, char *buf, size_t size, int *ret)
{
  pthread_mutex_lock(&readers_lock);
  struct kmsg_reader *r = kmsg_lookup(fd);
  off_t pos = r ? r->pos : 0;
  pthread_mutex_unlock(&readers_lock);
  if (r == NULL)
    return false;

  int log = kmsg_log_open();
  if (log < 0) {
    *ret = -LINUX_EIO;
    return true;
  }

  for (;;) {
    char rec[KMSG_MAX_RECORD + 128];
    ssize_t n = pread(log, rec, sizeof rec, pos);
    char *nl = (n > 0) ? memchr(rec, '\n', (size_t) n) : NULL;

    if (nl != NULL) {
      size_t len = (size_t)(nl - rec) + 1;
      if (len > size) {
        close(log);
        *ret = -LINUX_EINVAL;      /* a record does not arrive in pieces */
        return true;
      }
      memcpy(buf, rec, len);
      pthread_mutex_lock(&readers_lock);
      struct kmsg_reader *rr = kmsg_lookup(fd);
      if (rr != NULL)
        rr->pos = pos + (off_t) len;
      pthread_mutex_unlock(&readers_lock);
      close(log);
      *ret = (int) len;
      return true;
    }

    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK)) {
      close(log);
      *ret = -LINUX_EAGAIN;
      return true;
    }
    if (has_sigpending()) {
      close(log);
      *ret = -LINUX_EINTR;
      return true;
    }
    usleep(20 * 1000);
  }
}

/*
 * Seeking is how a reader says which end of the log it wants: the beginning
 * for everything that was ever written, the end for only what happens next.
 * Linux gives SEEK_DATA the same meaning as SEEK_SET here, since nothing is
 * ever cleared away.
 */
bool
kmsg_lseek(int fd, off_t offset, int whence, int *ret)
{
  pthread_mutex_lock(&readers_lock);
  struct kmsg_reader *r = kmsg_lookup(fd);
  pthread_mutex_unlock(&readers_lock);
  if (r == NULL)
    return false;

  off_t to;
  if (whence == SEEK_SET || whence == 3 /* SEEK_DATA */) {
    to = offset;
  } else if (whence == SEEK_END) {
    struct stat st;
    int log = kmsg_log_open();
    if (log < 0) {
      *ret = -LINUX_EIO;
      return true;
    }
    to = fstat(log, &st) == 0 ? st.st_size : 0;
    close(log);
  } else {
    *ret = -LINUX_EINVAL;
    return true;
  }

  pthread_mutex_lock(&readers_lock);
  struct kmsg_reader *rr = kmsg_lookup(fd);
  if (rr != NULL)
    rr->pos = to;
  pthread_mutex_unlock(&readers_lock);
  *ret = 0;
  return true;
}
