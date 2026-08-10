/*
 * System V semaphores.
 *
 * Unlike shared memory, these keep a Darwin semaphore array underneath. Darwin
 * allows 87381 of them rather than 32, and its semop already has the two hard
 * parts right - blocking until a whole set of operations can be applied at
 * once, and undoing a dead process's SEM_UNDO adjustments - which a
 * reimplementation over files would have to rebuild in order to arrive back at
 * the same behaviour.
 *
 * What comes from the namespace is identity and scoping. The guest's key names
 * a file in this IPC namespace's directory; the Darwin key behind it is derived
 * from the namespace and the id and is nabi's alone. So two namespaces asking
 * for key 5 get two unrelated arrays, neither of which is whatever the host Mac
 * happens to keep at key 5 - which is what the old code handed them.
 */
#include "common.h"
#include "noah.h"
#include "mm.h"
#include "namespace.h"
#include "sysv.h"
#include "linux/common.h"
#include "linux/futex.h"
#include "linux/time.h"
#include "linux/ipc.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <time.h>
#include <unistd.h>

int
linux_to_darwin_semflg(int l_semflg)
{
  int d_semflg = 0;
  if (l_semflg & LINUX_IPC_CREAT)
    d_semflg |= IPC_CREAT;
  if (l_semflg & LINUX_IPC_EXCL)
    d_semflg |= IPC_EXCL;
  if (l_semflg & LINUX_IPC_NOWAIT)
    d_semflg |= IPC_NOWAIT;
  return d_semflg;
}

/*
 * The Darwin array behind an object of ours, created if it is not there yet.
 * Idempotent by construction: the key is a function of the namespace and the
 * id, so every process in the namespace asks for the same one.
 */
static int
host_sem(struct sysv_obj *o)
{
  key_t k = sysv_host_key(ns_ino_of(NS_IPC), o->id);
  int hid = semget(k, (int) o->m->size, IPC_CREAT | 0600);
  if (hid < 0)
    return -darwin_to_linux_errno(errno);
  /* Recorded for the sweep, which has to release these when the namespace
   * goes - unlinking a file would not. Written every time, always the same. */
  o->m->host_id = hid;
  return hid;
}

/* Open by id and get at the array behind it, checking access on the way. */
static int
sem_open(int semid, int want, struct sysv_obj *o, int *hid)
{
  int r = sysv_open(SYSV_SEM, semid, o);
  if (r < 0)
    return r;
  if (want && !sysv_perm_ok(o->m, want)) {
    sysv_close(o);
    return -LINUX_EACCES;
  }
  if (hid) {
    if ((*hid = host_sem(o)) < 0) {
      int e = *hid;
      sysv_close(o);
      return e;
    }
  }
  return 0;
}

DEFINE_SYSCALL(semget, l_key_t, key, int, nsems, int, semflg)
{
  if (nsems < 0)
    return -LINUX_EINVAL;

  struct sysv_obj o;
  int id = sysv_get(SYSV_SEM, key, (uint64_t) nsems, semflg, &o);
  if (id < 0)
    return id;
  int hid = host_sem(&o);
  sysv_close(&o);
  return hid < 0 ? hid : id;
}

/*
 * Whether a semaphore array has gone while somebody was working on it.
 *
 * Darwin says EINVAL for an id that is no longer an id, which is also what it
 * says for one that never was; Linux distinguishes them, and a caller blocked
 * in semop when the array is removed is owed EIDRM. Ours is removed when the
 * meta file says so, and that is a question this side can answer.
 */
static bool
sem_gone(int semid)
{
  struct sysv_obj o;
  if (sysv_open(SYSV_SEM, semid, &o) < 0)
    return true;
  bool gone = o.m->removed;
  sysv_close(&o);
  return gone;
}

/*
 * semop and semtimedop are the same call, and the timeout is the whole of the
 * difference.
 *
 * Without one the operations go to Darwin's semop and block there, which is a
 * real wait: its wait queue, its wakeup, its ordering, and the SEM_UNDO it owes
 * a process that dies holding an adjustment.
 *
 * With one there is nothing to hand the deadline to - Darwin has no
 * semtimedop, and no timed variant of semop at all - so the operations are
 * retried with IPC_NOWAIT until they take or the deadline passes. Atomicity
 * survives that, which is the part that would have mattered: a semop with
 * IPC_NOWAIT either applies the whole set or applies none of it and says
 * EAGAIN, so polling it can never leave a caller half applied.
 *
 * What does not survive is the queue. A waiter that polls takes its turn
 * whenever it happens to look rather than in the order it arrived, so under
 * contention it can be passed over by a later arrival. Linux does not promise
 * fairness here either, but it is a difference, and it is confined to the timed
 * form - the ordinary blocking semop is untouched and still waits properly.
 */
static int
sem_do(int semid, gaddr_t tsops_ptr, unsigned nsops,
       const struct timespec *deadline)
{
  if (nsops == 0 || nsops > 1024)
    return -LINUX_EINVAL;

  struct sysv_obj o;
  int hid, r;
  if ((r = sem_open(semid, SYSV_W, &o, &hid)) < 0)
    return r;

  struct l_sembuf *l_tsops = malloc(sizeof l_tsops[0] * nsops);
  struct sembuf *tsops = malloc(sizeof tsops[0] * nsops);
  if (!l_tsops || !tsops) {
    r = -LINUX_ENOMEM;
    goto out;
  }
  /*
   * The guest's array, not the pointer to it. This read `&l_tsops`, which
   * copied the operations over the pointer variable itself and then freed
   * whatever the first eight bytes of guest data happened to look like.
   */
  if (copy_from_user(l_tsops, tsops_ptr, sizeof l_tsops[0] * nsops)) {
    r = -LINUX_EFAULT;
    goto out;
  }
  for (uint i = 0; i < nsops; ++i) {
    tsops[i].sem_num = l_tsops[i].sem_num;
    tsops[i].sem_op = l_tsops[i].sem_op;
    tsops[i].sem_flg = 0;
    if (l_tsops[i].sem_flg & LINUX_IPC_NOWAIT)
      tsops[i].sem_flg |= IPC_NOWAIT;
    if (l_tsops[i].sem_flg & LINUX_SEM_UNDO)
      tsops[i].sem_flg |= SEM_UNDO;
    if (deadline)
      tsops[i].sem_flg |= IPC_NOWAIT;   /* the waiting is done up here instead */
  }

  if (!deadline) {
    r = syswrap(semop(hid, tsops, nsops));
    if (r == -LINUX_EINVAL && sem_gone(semid))
      r = -LINUX_EIDRM;
    goto done;
  }

  unsigned usec = 250;
  for (;;) {
    r = syswrap(semop(hid, tsops, nsops));
    if (r != -LINUX_EAGAIN) {
      if (r == -LINUX_EINVAL && sem_gone(semid))
        r = -LINUX_EIDRM;
      break;
    }
    if (sem_gone(semid)) {
      r = -LINUX_EIDRM;
      break;
    }
    if (has_sigpending()) {
      r = -LINUX_EINTR;
      break;
    }

    struct timespec nowts;
    clock_gettime(CLOCK_MONOTONIC, &nowts);
    if (nowts.tv_sec > deadline->tv_sec ||
        (nowts.tv_sec == deadline->tv_sec && nowts.tv_nsec >= deadline->tv_nsec)) {
      r = -LINUX_EAGAIN;                /* the timeout expired, as Linux says */
      break;
    }

    struct timespec nap = { 0, (long) usec * 1000 };
    nanosleep(&nap, NULL);
    if (usec < 2000)
      usec *= 2;
  }

 done:
  if (r == 0)
    o.m->otime = (int64_t) time(NULL);
 out:
  free(l_tsops);
  free(tsops);
  sysv_close(&o);
  return r;
}

DEFINE_SYSCALL(semop, int, semid, gaddr_t, tsops_ptr, unsigned, nsops)
{
  return sem_do(semid, tsops_ptr, nsops, NULL);
}

DEFINE_SYSCALL(semtimedop, int, semid, gaddr_t, tsops_ptr, unsigned, nsops,
               gaddr_t, timeout_ptr)
{
  /* A null timeout is exactly semop, and takes the path that really waits. */
  if (timeout_ptr == 0)
    return sem_do(semid, tsops_ptr, nsops, NULL);

  struct l_timespec l_ts;
  if (copy_from_user(&l_ts, timeout_ptr, sizeof l_ts))
    return -LINUX_EFAULT;
  if (l_ts.tv_sec < 0 || l_ts.tv_nsec < 0 || l_ts.tv_nsec >= 1000000000)
    return -LINUX_EINVAL;

  /* Relative, and against the monotonic clock, so that the wait is not
   * lengthened or cut short by the wall clock being set. */
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += l_ts.tv_sec;
  deadline.tv_nsec += l_ts.tv_nsec;
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_nsec -= 1000000000;
    deadline.tv_sec++;
  }
  return sem_do(semid, tsops_ptr, nsops, &deadline);
}

static void
fill_semid_ds(struct l_semid64_ds *ds, const struct sysv_obj *o)
{
  memset(ds, 0, sizeof *ds);
  ds->sem_perm.key  = o->m->key;
  ds->sem_perm.uid  = o->m->uid;
  ds->sem_perm.gid  = o->m->gid;
  ds->sem_perm.cuid = o->m->cuid;
  ds->sem_perm.cgid = o->m->cgid;
  ds->sem_perm.mode = o->m->mode;
  ds->sem_otime     = o->m->otime;
  ds->sem_ctime     = o->m->ctime;
  ds->sem_nsems     = o->m->size;
}

DEFINE_SYSCALL(semctl, int, semid, int, semnum, int, cmd, union l_semun, arg)
{
  struct sysv_obj o;
  struct l_semid64_ds ds;
  int hid, r;

  cmd &= ~LINUX_IPC_64;

  switch (cmd) {
  case LINUX_IPC_INFO:
  case LINUX_SEM_INFO: {
    struct l_seminfo info;
    int used, high;
    uint64_t total;
    memset(&info, 0, sizeof info);
    sysv_count(SYSV_SEM, &used, &high, &total);
    info.semmni = SYSV_MAX_ID;
    info.semmns = SYSV_MAX_ID * 32;
    info.semmnu = SYSV_MAX_ID * 32;
    info.semmsl = 32000;
    info.semopm = 1024;
    info.semume = 32;
    info.semvmx = 32767;
    info.semaem = 32767;
    if (cmd == LINUX_SEM_INFO) {
      info.semusz = used;         /* SEM_INFO overloads these two */
      info.semaem = (l_int) total;
    }
    if (copy_to_user(arg.buf, &info, sizeof info))
      return -LINUX_EFAULT;
    return high;
  }

  case LINUX_SEM_STAT:
  case LINUX_SEM_STAT_ANY:
    if ((r = sem_open(semid, cmd == LINUX_SEM_STAT ? SYSV_R : 0, &o, NULL)) < 0)
      return r;
    fill_semid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(arg.buf, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return semid;

  case LINUX_IPC_STAT:
    if ((r = sem_open(semid, SYSV_R, &o, NULL)) < 0)
      return r;
    fill_semid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(arg.buf, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return 0;

  case LINUX_IPC_SET:
    if (copy_from_user(&ds, arg.buf, sizeof ds))
      return -LINUX_EFAULT;
    if ((r = sem_open(semid, 0, &o, NULL)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    o.m->uid   = ds.sem_perm.uid;
    o.m->gid   = ds.sem_perm.gid;
    o.m->mode  = ds.sem_perm.mode & 0777;
    o.m->ctime = (int64_t) time(NULL);
    sysv_close(&o);
    return 0;

  case LINUX_IPC_RMID:
    if ((r = sem_open(semid, 0, &o, &hid)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    semctl(hid, 0, IPC_RMID);
    r = sysv_remove(SYSV_SEM, semid, &o);
    sysv_close(&o);
    return r;

  case LINUX_GETVAL:
  case LINUX_GETPID:
  case LINUX_GETNCNT:
  case LINUX_GETZCNT: {
    if ((r = sem_open(semid, SYSV_R, &o, &hid)) < 0)
      return r;
    if (semnum < 0 || (uint64_t) semnum >= o.m->size) {
      sysv_close(&o);
      return -LINUX_EINVAL;
    }
    int dcmd = cmd == LINUX_GETVAL  ? GETVAL
             : cmd == LINUX_GETPID  ? GETPID
             : cmd == LINUX_GETNCNT ? GETNCNT : GETZCNT;
    r = syswrap(semctl(hid, semnum, dcmd));
    sysv_close(&o);
    return r;
  }

  case LINUX_SETVAL: {
    if ((r = sem_open(semid, SYSV_W, &o, &hid)) < 0)
      return r;
    if (semnum < 0 || (uint64_t) semnum >= o.m->size) {
      sysv_close(&o);
      return -LINUX_EINVAL;
    }
    r = syswrap(semctl(hid, semnum, SETVAL, arg.val));
    if (r == 0)
      o.m->ctime = (int64_t) time(NULL);
    sysv_close(&o);
    return r;
  }

  case LINUX_GETALL:
  case LINUX_SETALL: {
    if ((r = sem_open(semid, cmd == LINUX_GETALL ? SYSV_R : SYSV_W, &o, &hid)) < 0)
      return r;
    size_t n = (size_t) o.m->size;
    unsigned short *vals = calloc(n ? n : 1, sizeof *vals);
    if (!vals) {
      sysv_close(&o);
      return -LINUX_ENOMEM;
    }
    if (cmd == LINUX_GETALL) {
      r = syswrap(semctl(hid, 0, GETALL, vals));
      if (r == 0 && copy_to_user(arg.array, vals, n * sizeof *vals))
        r = -LINUX_EFAULT;
    } else {
      if (copy_from_user(vals, arg.array, n * sizeof *vals))
        r = -LINUX_EFAULT;
      else {
        r = syswrap(semctl(hid, 0, SETALL, vals));
        if (r == 0)
          o.m->ctime = (int64_t) time(NULL);
      }
    }
    free(vals);
    sysv_close(&o);
    return r;
  }

  default:
    warnk("semctl: unsupported command: 0x%x\n", cmd);
    return -LINUX_EINVAL;
  }
}
