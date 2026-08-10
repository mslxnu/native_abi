/*
 * System V message queues.
 *
 * These were absent entirely - msgget was in neither syscall table - so unlike
 * shared memory and semaphores there was nothing to correct, only something to
 * build. It closes the one hole the IPC namespace was documented as still
 * having: message queues needed no isolating while they did not exist, and that
 * guarantee held only for as long as they did not.
 *
 * A queue is a file in the namespace's directory, like a shared segment and for
 * the same reasons. Darwin does have message queues, and they were never a
 * candidate: 40 for the entire machine, 40 messages in the system at once, and
 * 2048 bytes per queue, in tables shared with the host and with every other
 * guest. Linux's defaults are 32000 queues of 16KiB. A guest sized against the
 * second and given the first fails in ways that look like its own bug.
 *
 * The queue's bytes are therefore nabi's, held under flock while they are
 * changed - flock rather than a semaphore because it needs no initialising and,
 * more to the point, the kernel drops it when the holder dies. A lock that must
 * be released by the process holding it is a lock that wedges the queue for
 * everyone the first time a guest is killed at the wrong moment.
 *
 * A receiver with nothing to receive waits by looking again, with a backoff to
 * a few milliseconds, rather than being woken. There is no cross-process wait
 * primitive here that survives a participant dying: macOS has no futex, and a
 * counting semaphore used as a wakeup loses its token if the sender dies
 * between appending the message and posting it, which strands the receiver
 * forever - a worse failure than a short delay, and a much harder one to see.
 * Polling also makes the two conditions Linux specifies fall out naturally,
 * since both are just things the next look notices: a signal arriving is EINTR,
 * and the queue being removed underneath is EIDRM.
 */
#include "common.h"
#include "noah.h"
#include "mm.h"
#include "namespace.h"
#include "sysv.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/ipc.h"
#include "linux/time.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

/* Linux's MSGMNB: what a queue holds unless its owner raises it. */
#define MSG_QBYTES_DEFAULT 16384
#define MSG_MAX            8192           /* MSGMAX: one message's text */

/*
 * The queue's own header, at the front of the data file. `head` and `tail`
 * bracket the records in use; a record taken out of the middle by a
 * type-selective receive is marked dead and skipped, and the whole file resets
 * to empty the moment the last one leaves - so a queue that drains does not
 * grow without bound however long it runs.
 */
struct msgq_hdr {
  uint32_t magic;
  uint32_t _pad;
  uint64_t head, tail;
  uint64_t qnum, cbytes;
};

struct msgq_rec {
  uint32_t live;
  uint32_t _pad;
  int64_t  type;
  uint64_t size;
  /* the text follows, rounded up to eight */
};

#define MSGQ_MAGIC 0x5173676du            /* "msgq" */

static int64_t
now(void)
{
  return (int64_t) time(NULL);
}

static uint64_t
rec_span(uint64_t size)
{
  return sizeof(struct msgq_rec) + roundup(size, 8);
}

/* The data file, locked. The caller unlocks by closing. */
static int
queue_open(int id)
{
  int fd = sysv_data_open(SYSV_MSG, id, O_RDWR);
  if (fd < 0)
    return fd;
  if (flock(fd, LOCK_EX) < 0) {
    int e = errno;
    close(fd);
    return -darwin_to_linux_errno(e);
  }
  return fd;
}

static void
queue_close(int fd)
{
  flock(fd, LOCK_UN);
  close(fd);
}

static int
hdr_read(int fd, struct msgq_hdr *h)
{
  if (pread(fd, h, sizeof *h, 0) != (ssize_t) sizeof *h || h->magic != MSGQ_MAGIC)
    return -LINUX_EINVAL;
  return 0;
}

static int
hdr_write(int fd, const struct msgq_hdr *h)
{
  return pwrite(fd, h, sizeof *h, 0) == (ssize_t) sizeof *h ? 0 : -LINUX_EIO;
}

/*
 * Which queued message this receive should take, by Linux's rules: any, one of
 * a type, anything but a type, or the lowest type not above a bound.
 * Returns the record's offset, or 0 if nothing matches.
 */
static uint64_t
pick(int fd, const struct msgq_hdr *h, int64_t msgtyp, int msgflg,
     struct msgq_rec *out)
{
  uint64_t best_off = 0;
  struct msgq_rec best;
  memset(&best, 0, sizeof best);

  for (uint64_t off = h->head; off < h->tail; ) {
    struct msgq_rec r;
    if (pread(fd, &r, sizeof r, (off_t) off) != (ssize_t) sizeof r)
      break;
    uint64_t span = rec_span(r.size);
    if (!r.live) {
      off += span;
      continue;
    }
    bool match;
    if (msgtyp == 0)
      match = true;
    else if (msgtyp > 0)
      match = (msgflg & LINUX_MSG_EXCEPT) ? r.type != msgtyp : r.type == msgtyp;
    else
      match = r.type <= -msgtyp;

    if (match) {
      if (msgtyp >= 0) {                  /* the first one that fits */
        *out = r;
        return off;
      }
      /* msgtyp < 0 wants the *lowest* type, so the search runs on. */
      if (best_off == 0 || r.type < best.type) {
        best_off = off;
        best = r;
      }
    }
    off += span;
  }
  if (best_off)
    *out = best;
  return best_off;
}

/* Drop dead records from the front, and reset the file once it is empty. */
static void
compact(int fd, struct msgq_hdr *h)
{
  while (h->head < h->tail) {
    struct msgq_rec r;
    if (pread(fd, &r, sizeof r, (off_t) h->head) != (ssize_t) sizeof r)
      break;
    if (r.live)
      break;
    h->head += rec_span(r.size);
  }
  if (h->head >= h->tail) {
    h->head = h->tail = sizeof *h;
    if (ftruncate(fd, (off_t) sizeof *h) < 0)
      ;                                   /* the offsets are what matter */
  }
}

/*
 * One turn of a wait: is the object still there, has a signal arrived, and if
 * neither, sleep a little longer than last time.
 */
static int
wait_a_moment(int id, unsigned *usec)
{
  struct sysv_obj o;
  int r = sysv_open(SYSV_MSG, id, &o);
  if (r < 0)
    return -LINUX_EIDRM;                  /* removed while we waited */
  bool gone = o.m->removed;
  sysv_close(&o);
  if (gone)
    return -LINUX_EIDRM;

  if (has_sigpending())
    return -LINUX_EINTR;

  struct timespec ts = { 0, (long) *usec * 1000 };
  nanosleep(&ts, NULL);
  if (*usec < 4000)
    *usec *= 2;
  if (has_sigpending())
    return -LINUX_EINTR;
  return 0;
}

/*
 * Put a header on a queue that has not got one yet.
 *
 * Done here rather than where the file is created because the store makes the
 * file and knows nothing of what goes in it. Under the lock and conditional on
 * the file being empty, so of two processes reaching a brand new queue at once
 * exactly one writes the header and the other finds it already written.
 */
static int
queue_init(int id)
{
  int fd = queue_open(id);
  if (fd < 0)
    return fd;

  struct msgq_hdr h;
  if (pread(fd, &h, sizeof h, 0) != (ssize_t) sizeof h || h.magic != MSGQ_MAGIC) {
    h = (struct msgq_hdr){ .magic = MSGQ_MAGIC,
                           .head = sizeof h, .tail = sizeof h };
    int r = hdr_write(fd, &h);
    if (r < 0) {
      queue_close(fd);
      return r;
    }
  }
  queue_close(fd);
  return 0;
}

DEFINE_SYSCALL(msgget, l_key_t, key, int, msgflg)
{
  struct sysv_obj o;
  int id = sysv_get(SYSV_MSG, key, MSG_QBYTES_DEFAULT, msgflg, &o);
  if (id < 0)
    return id;
  sysv_close(&o);

  int r = queue_init(id);
  return r < 0 ? r : id;
}

DEFINE_SYSCALL(msgsnd, int, msqid, gaddr_t, msgp, size_t, msgsz,
               int, msgflg)
{
  struct sysv_obj o;
  int r;

  if (msgsz > MSG_MAX)
    return -LINUX_EINVAL;

  /* The type is the first word of the guest's buffer, the text is the rest. */
  int64_t mtype;
  if (copy_from_user(&mtype, msgp, sizeof mtype))
    return -LINUX_EFAULT;
  if (mtype < 1)
    return -LINUX_EINVAL;

  char *text = malloc(msgsz ? msgsz : 1);
  if (!text)
    return -LINUX_ENOMEM;
  if (msgsz && copy_from_user(text, msgp + sizeof mtype, msgsz)) {
    free(text);
    return -LINUX_EFAULT;
  }

  if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0) {
    free(text);
    return r;
  }
  if (!sysv_perm_ok(o.m, SYSV_W)) {
    sysv_close(&o);
    free(text);
    return -LINUX_EACCES;
  }
  uint64_t qbytes = o.m->size;
  sysv_close(&o);

  unsigned usec = 250;
  for (;;) {
    int fd = queue_open(msqid);
    if (fd < 0) {
      free(text);
      return fd;
    }
    struct msgq_hdr h;
    if ((r = hdr_read(fd, &h)) < 0) {
      queue_close(fd);
      free(text);
      return r;
    }

    if (h.cbytes + msgsz <= qbytes) {
      struct msgq_rec rec = { .live = 1, .type = mtype, .size = msgsz };
      uint64_t off = h.tail;
      bool ok = pwrite(fd, &rec, sizeof rec, (off_t) off) == (ssize_t) sizeof rec;
      if (ok && msgsz)
        ok = pwrite(fd, text, msgsz, (off_t) (off + sizeof rec)) ==
             (ssize_t) msgsz;
      if (!ok) {
        queue_close(fd);
        free(text);
        return -LINUX_EIO;
      }
      h.tail += rec_span(msgsz);
      h.qnum++;
      h.cbytes += msgsz;
      r = hdr_write(fd, &h);
      queue_close(fd);
      free(text);
      if (r < 0)
        return r;

      if (sysv_open(SYSV_MSG, msqid, &o) == 0) {
        o.m->atime = now();               /* msg_stime */
        o.m->cpid  = o.m->cpid ? o.m->cpid : getpid();
        o.m->lpid  = getpid();            /* msg_lspid */
        sysv_close(&o);
      }
      return 0;
    }

    queue_close(fd);
    if (msgflg & LINUX_IPC_NOWAIT) {
      free(text);
      return -LINUX_EAGAIN;
    }
    if ((r = wait_a_moment(msqid, &usec)) < 0) {
      free(text);
      return r;
    }
  }
}

DEFINE_SYSCALL(msgrcv, int, msqid, gaddr_t, msgp, size_t, msgsz,
               long, msgtyp, int, msgflg)
{
  struct sysv_obj o;
  int r;

  if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0)
    return r;
  if (!sysv_perm_ok(o.m, SYSV_R)) {
    sysv_close(&o);
    return -LINUX_EACCES;
  }
  sysv_close(&o);

  unsigned usec = 250;
  for (;;) {
    int fd = queue_open(msqid);
    if (fd < 0)
      return fd;
    struct msgq_hdr h;
    if ((r = hdr_read(fd, &h)) < 0) {
      queue_close(fd);
      return r;
    }

    struct msgq_rec rec;
    uint64_t off = pick(fd, &h, msgtyp, msgflg, &rec);
    if (off != 0) {
      /* Too long for the buffer is an error unless the caller said to trim. */
      if (rec.size > msgsz && !(msgflg & LINUX_MSG_NOERROR)) {
        queue_close(fd);
        return -LINUX_E2BIG;
      }
      size_t take = rec.size > msgsz ? msgsz : rec.size;
      char *text = malloc(take ? take : 1);
      if (!text) {
        queue_close(fd);
        return -LINUX_ENOMEM;
      }
      if (take && pread(fd, text, take, (off_t) (off + sizeof rec)) !=
                      (ssize_t) take) {
        free(text);
        queue_close(fd);
        return -LINUX_EIO;
      }

      rec.live = 0;
      if (pwrite(fd, &rec, sizeof rec, (off_t) off) != (ssize_t) sizeof rec) {
        free(text);
        queue_close(fd);
        return -LINUX_EIO;
      }
      h.qnum--;
      h.cbytes -= rec.size;
      compact(fd, &h);
      hdr_write(fd, &h);
      queue_close(fd);

      /*
       * Copied out only once the queue no longer holds it and the lock is
       * gone. A fault here loses the message, as it does on Linux - what it
       * must not do is fault while holding the queue locked.
       */
      if (copy_to_user(msgp, &rec.type, sizeof rec.type) ||
          (take && copy_to_user(msgp + sizeof rec.type, text, take))) {
        free(text);
        return -LINUX_EFAULT;
      }
      free(text);

      if (sysv_open(SYSV_MSG, msqid, &o) == 0) {
        o.m->dtime = now();               /* msg_rtime */
        o.m->lpid  = getpid();            /* msg_lrpid */
        sysv_close(&o);
      }
      return (uint64_t) take;
    }

    queue_close(fd);
    if (msgflg & LINUX_IPC_NOWAIT)
      return -LINUX_ENOMSG;
    if ((r = wait_a_moment(msqid, &usec)) < 0)
      return r;
  }
}

/*
 * How much a queue is holding. Lives here because the layout does; /proc's
 * listing needs it and has no business knowing where in the file it is.
 */
void
sysv_msg_stats(int id, uint64_t *qnum, uint64_t *cbytes)
{
  *qnum = 0;
  *cbytes = 0;
  int fd = sysv_data_open(SYSV_MSG, id, O_RDONLY);
  if (fd < 0)
    return;
  struct msgq_hdr h;
  if (pread(fd, &h, sizeof h, 0) == (ssize_t) sizeof h && h.magic == MSGQ_MAGIC) {
    *qnum = h.qnum;
    *cbytes = h.cbytes;
  }
  close(fd);
}

static void
fill_msqid_ds(struct l_msqid64_ds *ds, const struct sysv_obj *o)
{
  memset(ds, 0, sizeof *ds);
  ds->msg_perm.key  = o->m->key;
  ds->msg_perm.uid  = o->m->uid;
  ds->msg_perm.gid  = o->m->gid;
  ds->msg_perm.cuid = o->m->cuid;
  ds->msg_perm.cgid = o->m->cgid;
  ds->msg_perm.mode = o->m->mode;
  ds->msg_stime     = o->m->atime;
  ds->msg_rtime     = o->m->dtime;
  ds->msg_ctime     = o->m->ctime;
  ds->msg_qbytes    = o->m->size;
  ds->msg_lspid     = o->m->lpid;
  ds->msg_lrpid     = o->m->lpid;

  /* qnum and cbytes live with the messages, not beside them, so they are read
   * from the queue rather than kept in a second place that could disagree. */
  sysv_msg_stats(o->id, &ds->msg_qnum, &ds->msg_cbytes);
}

DEFINE_SYSCALL(msgctl, int, msqid, int, cmd, gaddr_t, buf_ptr)
{
  struct sysv_obj o;
  struct l_msqid64_ds ds;
  int r;

  cmd &= ~LINUX_IPC_64;

  switch (cmd) {
  case LINUX_IPC_INFO:
  case LINUX_MSG_INFO: {
    struct l_msginfo info;
    int used, high;
    uint64_t total;
    memset(&info, 0, sizeof info);
    sysv_count(SYSV_MSG, &used, &high, &total);
    info.msgpool = SYSV_MAX_ID * MSG_QBYTES_DEFAULT / 1024;
    info.msgmap  = SYSV_MAX_ID;
    info.msgmax  = MSG_MAX;
    info.msgmnb  = MSG_QBYTES_DEFAULT;
    info.msgmni  = SYSV_MAX_ID;
    info.msgssz  = 16;
    info.msgtql  = SYSV_MAX_ID;
    info.msgseg  = SYSV_MAX_ID;
    if (cmd == LINUX_MSG_INFO) {
      info.msgpool = used;                /* MSG_INFO overloads these three */
      info.msgmap  = 0;
      info.msgtql  = 0;
    }
    if (copy_to_user(buf_ptr, &info, sizeof info))
      return -LINUX_EFAULT;
    return high;
  }

  case LINUX_MSG_STAT:
  case LINUX_MSG_STAT_ANY:
    if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0)
      return r;
    if (cmd == LINUX_MSG_STAT && !sysv_perm_ok(o.m, SYSV_R)) {
      sysv_close(&o);
      return -LINUX_EACCES;
    }
    fill_msqid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(buf_ptr, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return msqid;

  case LINUX_IPC_STAT:
    if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0)
      return r;
    if (!sysv_perm_ok(o.m, SYSV_R)) {
      sysv_close(&o);
      return -LINUX_EACCES;
    }
    fill_msqid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(buf_ptr, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return 0;

  case LINUX_IPC_SET:
    if (copy_from_user(&ds, buf_ptr, sizeof ds))
      return -LINUX_EFAULT;
    if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    o.m->uid   = ds.msg_perm.uid;
    o.m->gid   = ds.msg_perm.gid;
    o.m->mode  = ds.msg_perm.mode & 0777;
    if (ds.msg_qbytes)
      o.m->size = ds.msg_qbytes;
    o.m->ctime = now();
    sysv_close(&o);
    return 0;

  case LINUX_IPC_RMID:
    if ((r = sysv_open(SYSV_MSG, msqid, &o)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    /*
     * Marked removed before the files go, because that flag is what a waiting
     * msgrcv in another process notices in order to return EIDRM. Unlinking
     * alone would leave it looking at a queue nobody can reach.
     */
    r = sysv_remove(SYSV_MSG, msqid, &o);
    sysv_close(&o);
    return r;

  default:
    warnk("msgctl: unimplemented cmd = %d\n", cmd);
    return -LINUX_EINVAL;
  }
}
