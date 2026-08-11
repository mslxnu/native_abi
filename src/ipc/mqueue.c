/*
 * POSIX message queues - mq_open and the rest.
 *
 * Not to be confused with the System V queues in msg.c, which are a different
 * interface to a similar idea: those are named by a key and reached by an id,
 * these are named by a path and reached by a *descriptor*. That difference is
 * the whole design here.
 *
 * Darwin has none of this. mq_open does not exist on macOS at all, so all of it
 * is built from scratch, and it is built the way the System V queues are: an
 * object is a file in a directory belonging to the IPC namespace, and the
 * ordering rules are enforced by nabi under an exclusive lock on that file.
 * Linux scopes these to the IPC namespace too - unshare(CLONE_NEWIPC) and the
 * same name is a different queue - so using the same directory scheme gets that
 * for nothing.
 *
 * A descriptor is what makes them different, and it is also what makes them
 * easy. The queue *is* the file, so the descriptor a guest gets back is an open
 * descriptor on it and there is no side table mapping one to the other. That
 * falls out well: the descriptor survives fork, survives the exec arm64's fork
 * is built on, and closes when the guest closes it, all without any of this
 * code being involved. What identifies a descriptor as a queue rather than an
 * ordinary file is the magic in its header, which is checked on the way in.
 *
 * A queue file is a header and a fixed array of slots. Messages are not stored
 * in order; each slot carries the priority it was sent with and a sequence
 * number, and the receiver picks the highest priority and the oldest within it.
 * Storing them ordered would mean moving the tail of the file on every send,
 * and the ordering has to be computed on receive anyway.
 *
 * What is missing is notification. mq_notify asks for a signal when an empty
 * queue becomes non-empty, and the signals it is asked for are realtime ones,
 * which nabi cannot deliver - the same wall timer_create ran into, and refused
 * at for the same reason. See the note there and on mq_notify below.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/time.h"
#include "linux/errno.h"
#include "linux/fs.h"


#define MQ_MAGIC 0x6d710001u

/* Linux's own defaults, from /proc/sys/fs/mqueue. */
#define MQ_DEFAULT_MAXMSG   10
#define MQ_DEFAULT_MSGSIZE  8192
#define MQ_LIMIT_MAXMSG     1024
#define MQ_LIMIT_MSGSIZE    (1024 * 1024)

struct mq_hdr {
  uint32_t magic;
  uint32_t maxmsg;
  uint32_t msgsize;
  uint32_t curmsgs;
  uint64_t seq;                 /* ever-increasing; orders equal priorities */
  int32_t  notify_pid;          /* 0 when nobody is registered */
  int32_t  pad;
};

struct mq_slot {
  uint32_t used;
  uint32_t prio;
  uint32_t len;
  uint32_t pad;
  uint64_t seq;
  /* msgsize bytes of message follow */
};

/* Linux's struct mq_attr. */
struct l_mq_attr {
  int64_t mq_flags;
  int64_t mq_maxmsg;
  int64_t mq_msgsize;
  int64_t mq_curmsgs;
  int64_t __reserved[4];
};

static size_t
slot_stride(const struct mq_hdr *h)
{
  return sizeof(struct mq_slot) + h->msgsize;
}

static off_t
slot_at(const struct mq_hdr *h, uint32_t i)
{
  return (off_t) sizeof *h + (off_t) i * (off_t) slot_stride(h);
}

/* ------------------------------------------------------------------ names */

/*
 * The directory this namespace's queues live in, created on first use.
 *
 * Keyed by the IPC namespace's inode, exactly as the System V objects are, so
 * that unshare(CLONE_NEWIPC) separates these too without anything here knowing
 * about namespaces beyond asking which one it is in.
 */
static int
mq_dir(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-mq-%s-%llu",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(),
           (unsigned long long) ns_ino_of(NS_IPC));
  if (mkdir(out, 0700) < 0 && errno != EEXIST)
    return -darwin_to_linux_errno(errno);
  return 0;
}

/*
 * A queue name is "/something": a leading slash and no others. Linux is strict
 * about this and programs rely on the strictness - a name with a slash in the
 * middle would otherwise reach outside the directory these live in.
 */
static int
mq_path(const char *name, char *out, size_t n)
{
  if (name[0] != '/' || name[1] == '\0')
    return -LINUX_EINVAL;
  if (strchr(name + 1, '/') != NULL)
    return -LINUX_EACCES;       /* what Linux answers for a name with a path */
  if (strlen(name + 1) > NAME_MAX)
    return -LINUX_ENAMETOOLONG;

  char dir[PATH_MAX];
  int r = mq_dir(dir, sizeof dir);
  if (r < 0)
    return r;
  snprintf(out, n, "%s/%s", dir, name + 1);
  return 0;
}

/*
 * Is this descriptor one of ours, and what shape is the queue behind it?
 *
 * The check is the magic rather than a table of descriptors nabi keeps, which
 * is what lets a queue descriptor be inherited across fork and exec without
 * anything here tracking it.
 */
static int
mq_header(int fd, struct mq_hdr *h)
{
  if (pread(fd, h, sizeof *h, 0) != (ssize_t) sizeof *h)
    return -LINUX_EBADF;
  if (h->magic != MQ_MAGIC)
    return -LINUX_EBADF;        /* a descriptor, but not a message queue */
  return 0;
}

/* ------------------------------------------------------------------- open */

DEFINE_SYSCALL(mq_open, gstr_t, name_ptr, int, oflag, int, mode,
               gaddr_t, attr_ptr)
{
  char name[NAME_MAX + 2];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;

  char path[PATH_MAX];
  int r = mq_path(name, path, sizeof path);
  if (r < 0)
    return r;

  uint32_t maxmsg = MQ_DEFAULT_MAXMSG, msgsize = MQ_DEFAULT_MSGSIZE;
  if ((oflag & LINUX_O_CREAT) && attr_ptr != 0) {
    struct l_mq_attr a;
    if (copy_from_user(&a, attr_ptr, sizeof a))
      return -LINUX_EFAULT;
    if (a.mq_maxmsg <= 0 || a.mq_msgsize <= 0 ||
        a.mq_maxmsg > MQ_LIMIT_MAXMSG || a.mq_msgsize > MQ_LIMIT_MSGSIZE)
      return -LINUX_EINVAL;
    maxmsg = (uint32_t) a.mq_maxmsg;
    msgsize = (uint32_t) a.mq_msgsize;
  }

  /*
   * The descriptor is opened read-write whatever the guest asked for, because
   * nabi has to write the header and the slots to service a *receive* - taking
   * a message out of a queue is a write to the file it lives in. The guest's
   * own access mode is therefore not enforced by the host descriptor, and this
   * does not enforce it separately: a queue opened O_RDONLY here will accept a
   * send. That is a real gap rather than a decision, and it is the one place
   * this is more permissive than Linux.
   */
  int flags = O_RDWR;
  if (oflag & LINUX_O_CREAT)
    flags |= O_CREAT;
  if (oflag & LINUX_O_EXCL)
    flags |= O_EXCL;

  int fd = open(path, flags, 0600);
  if (fd < 0)
    return -darwin_to_linux_errno(errno);

  flock(fd, LOCK_EX);
  struct mq_hdr h;
  ssize_t got = pread(fd, &h, sizeof h, 0);
  if (got != (ssize_t) sizeof h || h.magic != MQ_MAGIC) {
    if (!(oflag & LINUX_O_CREAT)) {
      /* An existing file with no header is not a queue; refusing beats
       * pretending it is an empty one. */
      flock(fd, LOCK_UN);
      close(fd);
      return -LINUX_EBADF;
    }
    memset(&h, 0, sizeof h);
    h.magic = MQ_MAGIC;
    h.maxmsg = maxmsg;
    h.msgsize = msgsize;
    if (pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h ||
        ftruncate(fd, slot_at(&h, h.maxmsg)) < 0) {
      int e = errno;
      flock(fd, LOCK_UN);
      close(fd);
      unlink(path);
      return -darwin_to_linux_errno(e);
    }
  }
  flock(fd, LOCK_UN);

  if (oflag & LINUX_O_NONBLOCK)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(fd, (oflag & LINUX_O_CLOEXEC) != 0);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(fd);
    return err;
  }
  return fd;
}

DEFINE_SYSCALL(mq_unlink, gstr_t, name_ptr)
{
  char name[NAME_MAX + 2];
  if (strncpy_from_user(name, name_ptr, sizeof name) < 0)
    return -LINUX_EFAULT;
  char path[PATH_MAX];
  int r = mq_path(name, path, sizeof path);
  if (r < 0)
    return r;
  /*
   * The name goes; the queue itself lives on for whoever still has it open,
   * because the file does. That is what unlink means here and what mq_unlink
   * means on Linux, and it comes free from using a file.
   */
  if (unlink(path) < 0)
    return -darwin_to_linux_errno(errno);
  return 0;
}

/* --------------------------------------------------------------- waiting */

/*
 * How long is left, in milliseconds, or -1 for "no deadline".
 *
 * An absolute timeout is against CLOCK_REALTIME, which is what mq_timedsend
 * and mq_timedreceive are specified in terms of.
 */
static int
time_left(const struct l_timespec *abs, bool have)
{
  if (!have)
    return -1;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  int64_t ms = (int64_t) (abs->tv_sec - now.tv_sec) * 1000 +
               (abs->tv_nsec - now.tv_nsec) / 1000000;
  return ms < 0 ? 0 : (int) (ms > INT_MAX ? INT_MAX : ms);
}

/* A short sleep between attempts, as the System V queues do: there is no
 * cross-process condition variable here, and a file lock cannot be waited on
 * for a *change* to the file, only for the lock itself. */
static void
backoff(void)
{
  struct timespec ts = { 0, 2 * 1000 * 1000 };
  nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------- send */

static int
do_send(int fd, const char *msg, size_t len, uint32_t prio,
        const struct l_timespec *abs, bool timed)
{
  if (prio > 32768)
    return -LINUX_EINVAL;       /* MQ_PRIO_MAX */

  for (;;) {
    flock(fd, LOCK_EX);
    struct mq_hdr h;
    int r = mq_header(fd, &h);
    if (r < 0) {
      flock(fd, LOCK_UN);
      return r;
    }
    if (len > h.msgsize) {
      flock(fd, LOCK_UN);
      return -LINUX_EMSGSIZE;
    }

    if (h.curmsgs < h.maxmsg) {
      uint32_t i;
      struct mq_slot s;
      for (i = 0; i < h.maxmsg; i++) {
        if (pread(fd, &s, sizeof s, slot_at(&h, i)) != (ssize_t) sizeof s) {
          flock(fd, LOCK_UN);
          return -LINUX_EIO;
        }
        if (!s.used)
          break;
      }
      if (i == h.maxmsg) {
        /* The count said there was room and the slots say otherwise. */
        flock(fd, LOCK_UN);
        return -LINUX_EIO;
      }

      memset(&s, 0, sizeof s);
      s.used = 1;
      s.prio = prio;
      s.len = (uint32_t) len;
      s.seq = ++h.seq;
      h.curmsgs++;
      if (pwrite(fd, &s, sizeof s, slot_at(&h, i)) != (ssize_t) sizeof s ||
          (len && pwrite(fd, msg, len, slot_at(&h, i) + sizeof s) !=
                  (ssize_t) len) ||
          pwrite(fd, &h, sizeof h, 0) != (ssize_t) sizeof h) {
        flock(fd, LOCK_UN);
        return -LINUX_EIO;
      }
      flock(fd, LOCK_UN);
      return 0;
    }
    flock(fd, LOCK_UN);

    /* Full. */
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK))
      return -LINUX_EAGAIN;
    if (timed && time_left(abs, true) <= 0)
      return -LINUX_ETIMEDOUT;
    backoff();
  }
}

DEFINE_SYSCALL(mq_timedsend, int, mqdes, gaddr_t, msg_ptr, size_t, msg_len,
               unsigned int, msg_prio, gaddr_t, abs_timeout)
{
  struct l_timespec abs;
  bool timed = (abs_timeout != 0);
  if (timed && copy_from_user(&abs, abs_timeout, sizeof abs))
    return -LINUX_EFAULT;
  if (timed && (abs.tv_nsec < 0 || abs.tv_nsec >= 1000000000L))
    return -LINUX_EINVAL;

  char *buf = msg_len ? malloc(msg_len) : NULL;
  if (msg_len && !buf)
    return -LINUX_ENOMEM;
  if (msg_len && copy_from_user(buf, msg_ptr, msg_len)) {
    free(buf);
    return -LINUX_EFAULT;
  }
  int r = do_send(mqdes, buf, msg_len, msg_prio, &abs, timed);
  free(buf);
  return r;
}

/* ---------------------------------------------------------------- receive */

DEFINE_SYSCALL(mq_timedreceive, int, mqdes, gaddr_t, msg_ptr, size_t, msg_len,
               gaddr_t, prio_ptr, gaddr_t, abs_timeout)
{
  struct l_timespec abs;
  bool timed = (abs_timeout != 0);
  if (timed && copy_from_user(&abs, abs_timeout, sizeof abs))
    return -LINUX_EFAULT;
  if (timed && (abs.tv_nsec < 0 || abs.tv_nsec >= 1000000000L))
    return -LINUX_EINVAL;

  for (;;) {
    flock(mqdes, LOCK_EX);
    struct mq_hdr h;
    int r = mq_header(mqdes, &h);
    if (r < 0) {
      flock(mqdes, LOCK_UN);
      return r;
    }
    /*
     * A receive buffer smaller than the queue's message size is refused before
     * anything is taken. A message is delivered whole or not at all, so there
     * is no partial read to fall back on - which is why this is checked against
     * the queue's size rather than against the message that happens to be next.
     */
    if (msg_len < h.msgsize) {
      flock(mqdes, LOCK_UN);
      return -LINUX_EMSGSIZE;
    }

    if (h.curmsgs > 0) {
      /* Highest priority, and the oldest among those - which is what the
       * sequence number is for. */
      uint32_t best = h.maxmsg;
      struct mq_slot bs, s;
      memset(&bs, 0, sizeof bs);
      for (uint32_t i = 0; i < h.maxmsg; i++) {
        if (pread(mqdes, &s, sizeof s, slot_at(&h, i)) != (ssize_t) sizeof s)
          continue;
        if (!s.used)
          continue;
        if (best == h.maxmsg || s.prio > bs.prio ||
            (s.prio == bs.prio && s.seq < bs.seq)) {
          best = i;
          bs = s;
        }
      }
      if (best == h.maxmsg) {
        flock(mqdes, LOCK_UN);
        return -LINUX_EIO;
      }

      char *buf = bs.len ? malloc(bs.len) : NULL;
      if (bs.len && !buf) {
        flock(mqdes, LOCK_UN);
        return -LINUX_ENOMEM;
      }
      if (bs.len && pread(mqdes, buf, bs.len,
                          slot_at(&h, best) + sizeof bs) != (ssize_t) bs.len) {
        free(buf);
        flock(mqdes, LOCK_UN);
        return -LINUX_EIO;
      }

      struct mq_slot empty;
      memset(&empty, 0, sizeof empty);
      h.curmsgs--;
      (void) !pwrite(mqdes, &empty, sizeof empty, slot_at(&h, best));
      (void) !pwrite(mqdes, &h, sizeof h, 0);
      flock(mqdes, LOCK_UN);

      if (bs.len && copy_to_user(msg_ptr, buf, bs.len)) {
        free(buf);
        return -LINUX_EFAULT;
      }
      free(buf);
      if (prio_ptr) {
        unsigned int p = bs.prio;
        if (copy_to_user(prio_ptr, &p, sizeof p))
          return -LINUX_EFAULT;
      }
      return (int) bs.len;
    }
    flock(mqdes, LOCK_UN);

    int fl = fcntl(mqdes, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK))
      return -LINUX_EAGAIN;
    if (timed && time_left(&abs, true) <= 0)
      return -LINUX_ETIMEDOUT;
    backoff();
  }
}

/* ------------------------------------------------------------- attributes */

DEFINE_SYSCALL(mq_getsetattr, int, mqdes, gaddr_t, newattr, gaddr_t, oldattr)
{
  flock(mqdes, LOCK_EX);
  struct mq_hdr h;
  int r = mq_header(mqdes, &h);
  if (r < 0) {
    flock(mqdes, LOCK_UN);
    return r;
  }

  if (oldattr) {
    int fl = fcntl(mqdes, F_GETFL);
    struct l_mq_attr a;
    memset(&a, 0, sizeof a);
    a.mq_flags = (fl >= 0 && (fl & O_NONBLOCK)) ? LINUX_O_NONBLOCK : 0;
    a.mq_maxmsg = h.maxmsg;
    a.mq_msgsize = h.msgsize;
    a.mq_curmsgs = h.curmsgs;
    if (copy_to_user(oldattr, &a, sizeof a)) {
      flock(mqdes, LOCK_UN);
      return -LINUX_EFAULT;
    }
  }

  if (newattr) {
    struct l_mq_attr a;
    if (copy_from_user(&a, newattr, sizeof a)) {
      flock(mqdes, LOCK_UN);
      return -LINUX_EFAULT;
    }
    /*
     * Only O_NONBLOCK can be set. The sizes are fixed when the queue is created
     * and Linux ignores them here rather than refusing, so they are ignored -
     * a caller that passes the attributes it just read back would otherwise
     * fail for having done the obvious thing.
     */
    int fl = fcntl(mqdes, F_GETFL);
    if (fl >= 0) {
      if (a.mq_flags & LINUX_O_NONBLOCK)
        fcntl(mqdes, F_SETFL, fl | O_NONBLOCK);
      else
        fcntl(mqdes, F_SETFL, fl & ~O_NONBLOCK);
    }
  }

  flock(mqdes, LOCK_UN);
  return 0;
}

/* ---------------------------------------------------------- notification */

/*
 * mq_notify: refused for the notifications it cannot deliver, and honoured for
 * the bookkeeping it can.
 *
 * A registration asks to be told, once, when an empty queue becomes non-empty.
 * The telling is by signal - and glibc's SIGEV_THREAD is a realtime signal with
 * a thread started from its handler - and nabi drops every signal at or above
 * SIGRTMIN, because Darwin has none to map them onto. That is the wall
 * timer_create ran into, and this refuses at it for the same reason: a
 * registration accepted and never acted on is worse than one refused, because
 * the caller waits forever for a notification instead of falling back to a
 * blocking receive, which works perfectly.
 *
 * What is real is the exclusivity. Only one process may be registered on a
 * queue at a time, a second gets EBUSY, and passing NULL cancels - and programs
 * do use that as a lock of sorts. So it is kept, in the queue's header where
 * every process sharing the queue can see it.
 */
DEFINE_SYSCALL(mq_notify, int, mqdes, gaddr_t, sevp)
{
  flock(mqdes, LOCK_EX);
  struct mq_hdr h;
  int r = mq_header(mqdes, &h);
  if (r < 0) {
    flock(mqdes, LOCK_UN);
    return r;
  }

  if (sevp == 0) {
    /* Deregistering, which only the registered process may do. */
    if (h.notify_pid != 0 && h.notify_pid != getpid()) {
      flock(mqdes, LOCK_UN);
      return -LINUX_EBUSY;
    }
    h.notify_pid = 0;
    (void) !pwrite(mqdes, &h, sizeof h, 0);
    flock(mqdes, LOCK_UN);
    return 0;
  }

  struct l_sigevent ev;
  if (copy_from_user(&ev, sevp, sizeof ev)) {
    flock(mqdes, LOCK_UN);
    return -LINUX_EFAULT;
  }
  if (h.notify_pid != 0 && h.notify_pid != getpid()) {
    flock(mqdes, LOCK_UN);
    return -LINUX_EBUSY;
  }

  switch (ev.sigev_notify) {
  case LINUX_SIGEV_NONE:
    /* Asks to be registered and told nothing, which is exactly what this can
     * provide - so it is the one form that is honoured outright. */
    h.notify_pid = getpid();
    (void) !pwrite(mqdes, &h, sizeof h, 0);
    flock(mqdes, LOCK_UN);
    return 0;

  case LINUX_SIGEV_SIGNAL:
  case LINUX_SIGEV_THREAD:
  default:
    flock(mqdes, LOCK_UN);
    /* See above. Refused where the caller can still do something about it. */
    return -LINUX_EINVAL;
  }
}
