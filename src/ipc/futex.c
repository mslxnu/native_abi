#include "common.h"
#include "noah.h"
#include "mm.h"
#include "linux/common.h"
#include "linux/futex.h"
#include "linux/time.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

/*
FUTEX_UNLOCK_PI_PRIVATE
FUTEX_LOCK_PI_PRIVATE
FUTEX_WAIT_BITSET_PRIVATE
FUTEX_CMP_REQUEUE_PI_PRIVATE
FUTEX_CMP_REQUEUE_PI_PRIVATE
FUTEX_WAIT_PRIVATE
FUTEX_WAKE_PRIVATE
FUTEX_WAIT_REQUEUE_PI_PRIVATE
FUTEX_WAKE_OP_PRIVATE
FUTEX_WAIT
*/

static struct list_head *
pfutex_get(gaddr_t uaddr)
{
  int ret;
  khiter_t k = kh_put(pfutex, proc.pfutex, uaddr, &ret);
  assert(ret != -1);
  if (ret != 0) {             /* not present */
    assert(ret == 1);
    struct list_head *head = malloc(sizeof *head);
    INIT_LIST_HEAD(head);
    kh_value(proc.pfutex, k) = head;
  }
  return kh_value(proc.pfutex, k);
}

static int
do_private_futex_wake(gaddr_t uaddr, int count, bool use_bitset, uint32_t bitset)
{
  struct list_head *p, *n, *head = pfutex_get(uaddr);
  int ret = 0;
  list_for_each_safe (p, n, head) {
    if (count == 0)
      break;
    struct pfutex_entry *entry = container_of(p, struct pfutex_entry, head);
    if (use_bitset) {
      if ((entry->bitset & bitset) == 0)
        continue;
    }
    list_del_init(p);
    if (entry->woken)
      *entry->woken = entry->index;
    pthread_cond_signal(entry->condp);
    ret++; count--;
  }
  return ret;
}

int
do_futex_wake(gaddr_t uaddr, int count)
{
  pthread_mutex_lock(&proc.futex_mutex);
  int ret = do_private_futex_wake(uaddr, count, false, 0);
  pthread_mutex_unlock(&proc.futex_mutex);
  return ret;
}

/*
 * Whether the futex being waited on lives in memory another process can reach.
 * Held across one call under proc.futex_mutex, which is also what serialises
 * every futex operation, so it needs nothing of its own.
 */
static bool futex_shared;

/* How long a shared futex sleeps before looking at the word again. */
#define FUTEX_SHARED_POLL_NS (20 * 1000 * 1000)

static int
__cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex, bool use_timeout, struct timespec *ts)
{
  /*
   * A shared futex cannot be woken from here, so it is looked at again rather
   * than waited on. The caller re-checks the word and decides; this only has to
   * stop sleeping.
   */
  if (futex_shared) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += FUTEX_SHARED_POLL_NS;
    if (until.tv_nsec >= 1000000000L) {
      until.tv_nsec -= 1000000000L;
      until.tv_sec++;
    }
    if (use_timeout && (ts->tv_sec < until.tv_sec ||
                        (ts->tv_sec == until.tv_sec && ts->tv_nsec < until.tv_nsec)))
      until = *ts;
    int r = pthread_cond_timedwait(cond, mutex, &until);
    if (r == 0)
      return 0;                 /* really woken, by somebody in this process */
    if (r == ETIMEDOUT) {
      /* The caller's own deadline, or just our look-again interval. The second
       * is a spurious wake, which every futex caller already loops around;
       * EAGAIN would have claimed the word did not match when it did. */
      if (use_timeout && ts->tv_sec == until.tv_sec &&
          ts->tv_nsec == until.tv_nsec)
        return -LINUX_ETIMEDOUT;
      return 0;
    }
    return -LINUX_EINTR;
  }

  if (! use_timeout) {
    pthread_cond_wait(cond, mutex);
    return 0;
  }
  int ret = pthread_cond_timedwait(cond, mutex, ts);
  if (ret != 0) {
    if (ret == ETIMEDOUT)
      return -LINUX_ETIMEDOUT;
    else
      return -LINUX_EINTR;
  }
  return 0;
}

static int
do_private_wait(gaddr_t uaddr, bool use_timeout, struct timespec *ts, bool check_requeue, gaddr_t uaddr2, bool use_bitset, uint32_t bitset)
{
  struct pfutex_entry *entry = malloc(sizeof *entry);
  INIT_LIST_HEAD(&entry->head);
  pthread_cond_init(&entry->cond, NULL);
  entry->uaddr = uaddr;
  entry->bitset = use_bitset ? bitset : FUTEX_BITSET_MATCH_ANY;
  entry->condp = &entry->cond;
  entry->index = 0;
  entry->woken = NULL;
  list_add_tail(&entry->head, pfutex_get(uaddr));
  int r = __cond_wait(&entry->cond, &proc.futex_mutex, use_timeout, ts);
  if (check_requeue) {
    if (entry->uaddr != uaddr2)
      r = -LINUX_EAGAIN;
  }
  /*
   * A woken entry has already been unlinked by the waker, but a timed-out or
   * spuriously woken one has not - and freeing it while it is still on the list
   * leaves the list pointing at freed memory for the next wake to walk. The
   * entry is on whichever list it ended up on, which after a requeue is not the
   * one it started on, so it is removed by its own links rather than by uaddr.
   */
  list_del_init(&entry->head);
  pthread_cond_destroy(&entry->cond);
  free(entry);
  return r;
}


/*
 * A guest futex timeout as an absolute deadline for pthread_cond_timedwait.
 *
 * The two forms are not the same, and the difference is easy to miss: FUTEX_WAIT
 * takes a *relative* timeout, while FUTEX_WAIT_BITSET and the PI operations take
 * an absolute one. Copying the guest's struct straight into the deadline is
 * right for the second and badly wrong for the first - it asks to wait until a
 * moment a few seconds after the epoch, which has long passed, so the wait
 * returns ETIMEDOUT immediately and the guest spins at a full core instead of
 * sleeping.
 *
 * An absolute deadline is against CLOCK_MONOTONIC unless the guest set
 * FUTEX_CLOCK_REALTIME, while pthread_cond_timedwait measures against the real
 * time clock, so the monotonic case is rebased rather than passed through.
 */
static void
futex_deadline(const struct l_timespec *t, bool relative, bool realtime,
               struct timespec *out)
{
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

  if (relative) {
    out->tv_sec  = now.tv_sec + t->tv_sec;
    out->tv_nsec = now.tv_nsec + t->tv_nsec;
  } else if (realtime) {
    out->tv_sec  = t->tv_sec;
    out->tv_nsec = t->tv_nsec;
    return;
  } else {
    /* Absolute against CLOCK_MONOTONIC: keep the interval, move the origin. */
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    long sec  = t->tv_sec - mono.tv_sec;
    long nsec = t->tv_nsec - mono.tv_nsec;
    out->tv_sec  = now.tv_sec + sec;
    out->tv_nsec = now.tv_nsec + nsec;
  }
  while (out->tv_nsec >= 1000000000L) { out->tv_sec++;  out->tv_nsec -= 1000000000L; }
  while (out->tv_nsec < 0)            { out->tv_sec--;  out->tv_nsec += 1000000000L; }
}

/*
 * The compare-and-block every waiting futex operation has to do.
 *
 * The guest reads the word, decides it should sleep, and calls futex with the
 * value it saw. Between those two the value may have changed and a wake may
 * already have been sent, so the kernel re-reads it under the futex lock and
 * refuses to sleep if it no longer matches. Skipping that turns a wake that
 * arrived a moment early into a wait that nothing will ever satisfy.
 */
static int
futex_should_block(gaddr_t uaddr, uint32_t val)
{
  uint32_t uval;
  if (copy_from_user(&uval, uaddr, sizeof uval))
    return -LINUX_EFAULT;
  if (uval != val)
    return -LINUX_EAGAIN;
  return 0;
}

static int
do_private_futex(gaddr_t uaddr, int op, uint32_t val, gaddr_t timeout_ptr, gaddr_t uaddr2, int val3)
{
  /* Which clock an absolute deadline is measured against. */
  bool realtime_clock = (op & LINUX_FUTEX_CLOCK_REALTIME) != 0;

  switch (op & LINUX_FUTEX_CMD_MASK) {
  case LINUX_FUTEX_WAKE: {
    return do_private_futex_wake(uaddr, val, false, 0);
  }
  case LINUX_FUTEX_WAIT: {
    int r = futex_should_block(uaddr, val);
    if (r < 0)
      return r;             /* -LINUX_EAGAIN, not Darwin's EWOULDBLOCK */
    struct timespec ts;
    if (timeout_ptr != 0) {
      struct l_timespec timeout;
      if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
        return -LINUX_EFAULT;
      /* FUTEX_WAIT's timeout is relative. */
      futex_deadline(&timeout, true, false, &ts);
    }
    return do_private_wait(uaddr, timeout_ptr, &ts, false, 0, false, 0);
  }
  case LINUX_FUTEX_WAKE_OP: {
    int ret = 0;
    int oldval;
    if (copy_from_user(&oldval, uaddr2, sizeof oldval)) {
      ret = -LINUX_EFAULT;
      goto out;
    }
    int newval = 0;
    switch (LINUX_FUTEX_GETOP(val3)) {
    default:
      panic("unknown op for futex_wake_op\n");
    case FUTEX_OP_SET: newval = LINUX_FUTEX_GETOPARG(val3); break;
    case FUTEX_OP_ADD: newval = oldval + LINUX_FUTEX_GETOPARG(val3); break;
    case FUTEX_OP_OR: newval = oldval | LINUX_FUTEX_GETOPARG(val3); break;
    case FUTEX_OP_ANDN: newval = oldval & ~LINUX_FUTEX_GETOPARG(val3); break;
    case FUTEX_OP_XOR: newval = oldval ^ LINUX_FUTEX_GETOPARG(val3); break;
    }
    if (copy_to_user(uaddr2, &newval, sizeof newval)) {
      ret = -LINUX_EFAULT;
      goto out;
    }
    if ((ret = do_private_futex_wake(uaddr, val, false, 0)) < 0) {
      goto out;
    }
    bool cond;
    switch (LINUX_FUTEX_GETCMP(val3)) {
    default:
      panic("unknown cmp for futex_wake_op\n");
    case FUTEX_OP_CMP_EQ: cond = oldval == LINUX_FUTEX_GETCMPARG(val3); break;
    case FUTEX_OP_CMP_NE: cond = oldval != LINUX_FUTEX_GETCMPARG(val3); break;
    case FUTEX_OP_CMP_LT: cond = oldval < LINUX_FUTEX_GETCMPARG(val3); break;
    case FUTEX_OP_CMP_LE: cond = oldval <= LINUX_FUTEX_GETCMPARG(val3); break;
    case FUTEX_OP_CMP_GT: cond = oldval > LINUX_FUTEX_GETCMPARG(val3); break;
    case FUTEX_OP_CMP_GE: cond = oldval >= LINUX_FUTEX_GETCMPARG(val3); break;
    }
    uint32_t val2 = timeout_ptr;
    if (cond) {
      int ret2;
      if ((ret2 = do_private_futex_wake(uaddr2, val2, false, 0)) < 0) {
        goto out;
      }
      ret += ret2;
    }
    out:
    return ret;
  }
  case LINUX_FUTEX_LOCK_PI: {
    struct timespec ts;
    if (timeout_ptr != 0) {
      struct l_timespec timeout;
      if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
        return -LINUX_EFAULT;
      futex_deadline(&timeout, false, realtime_clock, &ts);
    }
    int tid = do_gettid();
    /* TODO: check mprotect flags */
    atomic_int *mem = (atomic_int *) guest_to_host(uaddr); /* FIXME: don't cast to atomic_int */
    assert(mem);
    /* first update mem's value to something else to prevent other user processes getting the lock of this futex */
    int value = atomic_exchange(mem, tid);
    if (value == 0) {
      /* acquired the lock */
      return 0; /* NOTE: man page is telling ambiguous things about this path. My interpretation can be wrong. */
    }
    /* there are waiters other than me */
    atomic_store(mem, value | FUTEX_WAITERS);
    return do_private_wait(uaddr, timeout_ptr, &ts, false, 0, false, 0);
  }
  case LINUX_FUTEX_UNLOCK_PI: {
    do_private_futex_wake(uaddr, 1, false, 0);
    return 0;
  }
  case LINUX_FUTEX_CMP_REQUEUE_PI: {
    if (val != 1) {
      return -LINUX_EINVAL;
    }
    int oldval;
    if (copy_from_user(&oldval, uaddr, sizeof oldval)) /* FIXME: this operation must be atomic */
      return -LINUX_EFAULT;
    if (oldval != val3)
      return -LINUX_EAGAIN;
    int num = do_private_futex_wake(uaddr, val, false, 0);
    struct list_head *p, *n, *list = pfutex_get(uaddr), *list2 = pfutex_get(uaddr2);
    int val2 = timeout_ptr;
    list_for_each_safe (p, n, list) {
      if (val2 == 0)
        break;
      list_del_init(p);
      list_add_tail(p, list2);
      container_of(p, struct pfutex_entry, head)->uaddr = uaddr2;
      val2--;
      num++;
    }
    return num;
  }
  case LINUX_FUTEX_WAIT_REQUEUE_PI: {
    struct timespec ts;
    if (timeout_ptr != 0) {
      struct l_timespec timeout;
      if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
        return -LINUX_EFAULT;
      futex_deadline(&timeout, false, realtime_clock, &ts);
    }
    return do_private_wait(uaddr, timeout_ptr, &ts, true, uaddr2, false, 0);
  }
  case LINUX_FUTEX_WAIT_BITSET: {
    /* The compare was missing here, and this is the operation glibc actually
     * uses - pthread_cond_wait and sem_wait go through it. Without it a wake
     * that lands between the guest's read of the word and this call is lost,
     * and the thread sleeps forever on a condition that has already happened. */
    int r = futex_should_block(uaddr, val);
    if (r < 0)
      return r;
    struct timespec ts;
    if (timeout_ptr != 0) {
      struct l_timespec timeout;
      if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
        return -LINUX_EFAULT;
      /* FUTEX_WAIT_BITSET's timeout is absolute - that is the difference from
       * FUTEX_WAIT - against CLOCK_MONOTONIC unless the guest asked otherwise. */
      futex_deadline(&timeout, false, realtime_clock, &ts);
    }
    return do_private_wait(uaddr, timeout_ptr, &ts, false, 0, true, val3);
  }
  case LINUX_FUTEX_WAKE_BITSET: {
    return do_private_futex_wake(uaddr, val, true, val3);
  }
  /*
   * Moving waiters from one futex to another without waking them.
   *
   * This is what a broadcast is for: pthread_cond_broadcast has to hand every
   * waiter to the mutex they will contend for next, and waking them all so that
   * each can queue itself again is the thundering herd requeue exists to avoid.
   * The compare form checks the futex has not changed under it first, which is
   * how a caller detects that the condition it read is already stale.
   */
  case LINUX_FUTEX_REQUEUE:
  case LINUX_FUTEX_CMP_REQUEUE: {
    if ((op & LINUX_FUTEX_CMD_MASK) == LINUX_FUTEX_CMP_REQUEUE) {
      uint32_t uval;
      if (copy_from_user(&uval, uaddr, sizeof uval))
        return -LINUX_EFAULT;
      if (uval != (uint32_t) val3)
        return -LINUX_EAGAIN;
    }
    int woken = do_private_futex_wake(uaddr, val, false, 0);

    /* val2 arrives in the timeout slot: the argument is a count here, not a
     * pointer, which is the one place futex reuses a register for two types. */
    int val2 = (int) timeout_ptr;
    struct list_head *p, *n, *from = pfutex_get(uaddr), *to = pfutex_get(uaddr2);
    list_for_each_safe (p, n, from) {
      if (val2 <= 0)
        break;
      list_del_init(p);
      list_add_tail(p, to);
      container_of(p, struct pfutex_entry, head)->uaddr = uaddr2;
      val2--;
    }
    /* Linux counts only the woken, not the requeued. */
    return woken;
  }

  /*
   * The non-blocking half of LOCK_PI. Taking it is the same exchange; not
   * taking it is the whole difference, so there is no wait here at all.
   */
  case LINUX_FUTEX_TRYLOCK_PI: {
    atomic_int *mem = (atomic_int *) guest_to_host(uaddr);
    if (mem == NULL)
      return -LINUX_EFAULT;
    int expected = 0;
    if (atomic_compare_exchange_strong(mem, &expected, do_gettid()))
      return 0;
    return -LINUX_EAGAIN;
  }

  /*
   * FUTEX_FD handed out a descriptor that became readable when the futex was
   * woken. It was racy by construction and Linux removed it in 2.6.26; saying
   * so is the honest answer rather than pretending to a thing that no longer
   * exists anywhere.
   */
  case LINUX_FUTEX_FD:
    return -LINUX_ENOSYS;

  default:
    warnk("unsupported futex command: %d\n", op);
    return -LINUX_ENOSYS;
  }
}

DEFINE_SYSCALL(futex, gaddr_t, uaddr, int, op, uint32_t, val, gaddr_t, timeout_ptr, gaddr_t, uaddr2, uint32_t, val3)
{
  bool shared = false;
  if (op & LINUX_FUTEX_PRIVATE_FLAG) {
    op &= ~LINUX_FUTEX_PRIVATE_FLAG;
  } else {
    // Check if op is actually private
    struct mm_region *region = find_region(uaddr, proc.mm);
    if (region == NULL) {
      return -LINUX_EFAULT;
    }
    /*
     * A futex in shared memory used to panic here, which killed the guest for
     * doing something ordinary - and it became reachable the moment System V
     * shared memory started working, since a pthread mutex marked
     * PTHREAD_PROCESS_SHARED in a segment is exactly this.
     *
     * The wait queue is this process's, so a waiter here cannot be woken by
     * another process and does not see its wakes. Within one process - which is
     * most uses of a shared mapping, and all of the ones that were panicking -
     * that is exactly right. Across processes it would be a missed wakeup, so
     * the wait is bounded and re-checks the futex word instead of sleeping on
     * it forever: a cross-process wake becomes a short delay rather than a
     * hang, and neither becomes a dead machine.
     */
    shared = true;
  }
  pthread_mutex_lock(&proc.futex_mutex);
  futex_shared = shared;
  int ret = do_private_futex(uaddr, op, val, timeout_ptr, uaddr2, val3);
  futex_shared = false;
  pthread_mutex_unlock(&proc.futex_mutex);
  return ret;
}

/*
 * get_robust_list: what set_robust_list was told.
 *
 * The list itself is the guest's own linked list of held robust mutexes, walked
 * by the kernel when a thread dies so that whoever waits on one is told the
 * owner is gone rather than waiting forever. nabi does not walk it - a guest
 * thread is a host thread and dies without passing through here - so what this
 * pair provides is the bookkeeping and not the recovery. Reporting the pointer
 * back is still the truth about what was registered, and it is what a caller
 * asking uses it for.
 */
DEFINE_SYSCALL(get_robust_list, int, pid, gaddr_t, head_ptr, gaddr_t, len_ptr)
{
  /* Another thread's list is not reachable from here: the registration is per
   * task and nabi keeps no table of other tasks' to look in. */
  if (pid != 0 && pid != (int) do_gettid())
    return -LINUX_EPERM;

  uint64_t head = task.robust_list;
  uint64_t len = sizeof(struct linux_robust_list_head);
  if (copy_to_user(head_ptr, &head, sizeof head) ||
      copy_to_user(len_ptr, &len, sizeof len))
    return -LINUX_EFAULT;
  return 0;
}

/* ------------------------------------------------------- the futex2 family */

/*
 * futex_wake, futex_wait and futex_requeue are the same operations with the
 * arguments untangled - a mask instead of a bitset packed into val3, a size in
 * the flags instead of an assumption, and no register doing double duty as both
 * a pointer and a count. They are what a caller written today reaches for.
 *
 * Only 32-bit futexes are served. Linux's flags can ask for 8, 16 or 64 bits,
 * and the smaller ones are not what any libc uses; answering EINVAL for a width
 * that is not implemented is what Linux does when the architecture cannot do it
 * either, and is better than reading four bytes where two were meant.
 */
#define LINUX_FUTEX2_SIZE_MASK 0x03
#define LINUX_FUTEX2_SIZE_U32  0x02
#define LINUX_FUTEX2_NUMA      0x04
#define LINUX_FUTEX2_PRIVATE   LINUX_FUTEX_PRIVATE_FLAG

static int
futex2_check_flags(unsigned int flags)
{
  if ((flags & LINUX_FUTEX2_SIZE_MASK) != LINUX_FUTEX2_SIZE_U32)
    return -LINUX_EINVAL;
  if (flags & LINUX_FUTEX2_NUMA)
    return -LINUX_EINVAL;
  if (flags & ~(unsigned) (LINUX_FUTEX2_SIZE_MASK | LINUX_FUTEX2_PRIVATE))
    return -LINUX_EINVAL;
  return 0;
}

DEFINE_SYSCALL(futex_wake, gaddr_t, uaddr, uint64_t, mask, int, nr,
               unsigned int, flags)
{
  int r = futex2_check_flags(flags);
  if (r < 0)
    return r;
  if (nr < 0)
    return -LINUX_EINVAL;

  pthread_mutex_lock(&proc.futex_mutex);
  r = do_private_futex_wake(uaddr, nr, true, (uint32_t) mask);
  pthread_mutex_unlock(&proc.futex_mutex);
  return r;
}

DEFINE_SYSCALL(futex_wait, gaddr_t, uaddr, uint64_t, val, uint64_t, mask,
               unsigned int, flags, gaddr_t, timeout_ptr, int, clockid)
{
  int r = futex2_check_flags(flags);
  if (r < 0)
    return r;
  if (clockid != LINUX_CLOCK_MONOTONIC && clockid != LINUX_CLOCK_REALTIME)
    return -LINUX_EINVAL;

  struct timespec ts;
  if (timeout_ptr != 0) {
    struct l_timespec timeout;
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout))
      return -LINUX_EFAULT;
    /* futex2's timeout is absolute, unlike FUTEX_WAIT's. */
    futex_deadline(&timeout, false, clockid == LINUX_CLOCK_REALTIME, &ts);
  }

  pthread_mutex_lock(&proc.futex_mutex);
  r = futex_should_block(uaddr, (uint32_t) val);
  if (r == 0)
    r = do_private_wait(uaddr, timeout_ptr != 0, &ts, false, 0,
                        true, (uint32_t) mask);
  pthread_mutex_unlock(&proc.futex_mutex);
  return r;
}

DEFINE_SYSCALL(futex_requeue, gaddr_t, waiters_ptr, unsigned int, flags,
               int, nr_wake, int, nr_requeue)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (nr_wake < 0 || nr_requeue < 0)
    return -LINUX_EINVAL;

  /* Exactly two: the futex to wake from and the one to move the rest to. */
  struct l_futex_waitv w[2];
  if (copy_from_user(w, waiters_ptr, sizeof w))
    return -LINUX_EFAULT;
  int r = futex2_check_flags(w[0].flags);
  if (r < 0)
    return r;
  if ((r = futex2_check_flags(w[1].flags)) < 0)
    return r;

  pthread_mutex_lock(&proc.futex_mutex);
  uint32_t uval;
  if (copy_from_user(&uval, (gaddr_t) w[0].uaddr, sizeof uval)) {
    pthread_mutex_unlock(&proc.futex_mutex);
    return -LINUX_EFAULT;
  }
  if (uval != (uint32_t) w[0].val) {
    pthread_mutex_unlock(&proc.futex_mutex);
    return -LINUX_EAGAIN;
  }

  int woken = do_private_futex_wake((gaddr_t) w[0].uaddr, nr_wake, false, 0);
  struct list_head *p, *n;
  struct list_head *from = pfutex_get((gaddr_t) w[0].uaddr);
  struct list_head *to = pfutex_get((gaddr_t) w[1].uaddr);
  list_for_each_safe (p, n, from) {
    if (nr_requeue <= 0)
      break;
    list_del_init(p);
    list_add_tail(p, to);
    container_of(p, struct pfutex_entry, head)->uaddr = (gaddr_t) w[1].uaddr;
    nr_requeue--;
  }
  pthread_mutex_unlock(&proc.futex_mutex);
  return woken;
}

/*
 * futex_waitv: wait on several futexes and return which one woke.
 *
 * The waiter is one sleep and many queues. Each futex gets an entry of its own,
 * because that is what a wake walks, and all of them share the condition
 * variable the sleep is on and a slot to write the index into - so whichever
 * waker gets there first says which futex it was, and the others find their
 * entries already unlinked.
 */
DEFINE_SYSCALL(futex_waitv, gaddr_t, waiters_ptr, unsigned int, nr_futexes,
               unsigned int, flags, gaddr_t, timeout_ptr, int, clockid)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (nr_futexes == 0 || nr_futexes > 128)
    return -LINUX_EINVAL;
  if (timeout_ptr != 0 && clockid != LINUX_CLOCK_MONOTONIC &&
      clockid != LINUX_CLOCK_REALTIME)
    return -LINUX_EINVAL;

  struct l_futex_waitv *w = malloc(sizeof *w * nr_futexes);
  if (!w)
    return -LINUX_ENOMEM;
  if (copy_from_user(w, waiters_ptr, sizeof *w * nr_futexes)) {
    free(w);
    return -LINUX_EFAULT;
  }
  for (unsigned i = 0; i < nr_futexes; i++) {
    int fr = futex2_check_flags(w[i].flags);
    if (fr < 0 || w[i].__reserved != 0) {
      free(w);
      return fr < 0 ? fr : -LINUX_EINVAL;
    }
  }

  struct timespec ts;
  if (timeout_ptr != 0) {
    struct l_timespec timeout;
    if (copy_from_user(&timeout, timeout_ptr, sizeof timeout)) {
      free(w);
      return -LINUX_EFAULT;
    }
    futex_deadline(&timeout, false, clockid == LINUX_CLOCK_REALTIME, &ts);
  }

  struct pfutex_entry **e = calloc(nr_futexes, sizeof *e);
  if (!e) {
    free(w);
    return -LINUX_ENOMEM;
  }

  pthread_cond_t shared_cond;
  pthread_cond_init(&shared_cond, NULL);
  int woken_index = -1;
  int ret = 0;

  pthread_mutex_lock(&proc.futex_mutex);

  /* Every word is checked before anything sleeps: one that already differs
   * means the caller's view is stale and there is nothing to wait for. */
  for (unsigned i = 0; i < nr_futexes; i++) {
    uint32_t uval;
    if (copy_from_user(&uval, (gaddr_t) w[i].uaddr, sizeof uval)) {
      ret = -LINUX_EFAULT;
      goto out;
    }
    if (uval != (uint32_t) w[i].val) {
      ret = -LINUX_EAGAIN;
      goto out;
    }
  }

  for (unsigned i = 0; i < nr_futexes; i++) {
    e[i] = malloc(sizeof **e);
    if (!e[i]) {
      ret = -LINUX_ENOMEM;
      goto out;
    }
    INIT_LIST_HEAD(&e[i]->head);
    pthread_cond_init(&e[i]->cond, NULL);
    e[i]->uaddr = (gaddr_t) w[i].uaddr;
    e[i]->bitset = FUTEX_BITSET_MATCH_ANY;
    e[i]->condp = &shared_cond;
    e[i]->index = (int) i;
    e[i]->woken = &woken_index;
    list_add_tail(&e[i]->head, pfutex_get((gaddr_t) w[i].uaddr));
  }

  ret = __cond_wait(&shared_cond, &proc.futex_mutex, timeout_ptr != 0, &ts);
  if (ret == 0)
    ret = woken_index >= 0 ? woken_index : -LINUX_EAGAIN;

 out:
  for (unsigned i = 0; i < nr_futexes; i++)
    if (e[i]) {
      list_del_init(&e[i]->head);
      pthread_cond_destroy(&e[i]->cond);
      free(e[i]);
    }
  pthread_mutex_unlock(&proc.futex_mutex);
  pthread_cond_destroy(&shared_cond);
  free(e);
  free(w);
  return ret;
}
