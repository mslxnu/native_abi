/*
 * userfaultfd — on-demand page resolution for PROT_NONE regions.
 *
 * A guest thread that touches an unmaterialised page blocks until a resolver
 * thread feeds the page content through UFFDIO_COPY.  Android relies on this
 * for the ART GC's concurrent compactor and for the app freezer.
 *
 * The fd is a socketpair underneath (like signalfd): the guest reads fault
 * messages from end 0; end 1 is poked to wake poll/read.  Fault messages
 * are queued in a ring buffer and delivered through the read interception.
 */

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "namespace.h"
#include "linux/userfaultfd.h"
#include "linux/errno.h"
#include "linux/mman.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>

/* The O_ flags we need (avoid pulling all of linux/fs.h). */
#ifndef LINUX_O_NONBLOCK
#define LINUX_O_NONBLOCK  00004000
#endif
#ifndef LINUX_O_CLOEXEC
#define LINUX_O_CLOEXEC   02000000
#endif

/* ── static state ──────────────────────────────────────────────────────── */

#define UFFD_MAX 16

static struct uffd_state uffds[UFFD_MAX];
static struct list_head  pending_faults;
static pthread_mutex_t   faults_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── init ──────────────────────────────────────────────────────────────── */

void
userfaultfd_init(void)
{
  INIT_LIST_HEAD(&pending_faults);
  for (int i = 0; i < UFFD_MAX; i++) {
    uffds[i].fd  = -1;
    uffds[i].wr  = -1;
  }
}

/* ── lookup helpers ────────────────────────────────────────────────────── */

/* Find the uffd_state slot that owns a given guest fd, or NULL. */
static struct uffd_state *
uffd_lookup(int fd)
{
  for (int i = 0; i < UFFD_MAX; i++)
    if (uffds[i].fd == fd)
      return &uffds[i];
  return NULL;
}

/* Whether `fd` belongs to a userfaultfd (used before lock acquisition). */
bool
userfaultfd_is(int fd)
{
  return uffd_lookup(fd) != NULL;
}

/*
 * Find the first uffd whose registered ranges contain `addr`.
 * Caller must NOT hold faults_lock.
 */
static struct uffd_state *
uffd_for_addr(uint64_t addr)
{
  for (int i = 0; i < UFFD_MAX; i++) {
    struct uffd_state *u = &uffds[i];
    if (u->fd < 0)
      continue;
    pthread_mutex_lock(&u->lock);
    for (int j = 0; j < u->nr_ranges; j++) {
      if (addr >= u->ranges[j].start &&
          addr <  u->ranges[j].start + u->ranges[j].len) {
        pthread_mutex_unlock(&u->lock);
        return u;
      }
    }
    pthread_mutex_unlock(&u->lock);
  }
  return NULL;
}

/*
 * Find the pending-fault entry for `addr`, or NULL.
 * Caller must hold faults_lock.
 */
static struct uffd_pending_fault *
find_pending_fault(uint64_t addr)
{
  struct list_head *pos;
  list_for_each(pos, &pending_faults) {
    struct uffd_pending_fault *f = list_entry(pos, struct uffd_pending_fault, list);
    if (f->addr == addr)
      return f;
  }
  return NULL;
}

/* ── poke the socketpair to wake read / poll ───────────────────────────── */

static void
uffd_poke(struct uffd_state *u)
{
  char one = 1;
  (void)send(u->wr, &one, 1, MSG_NOSIGNAL);
}

/* ── pending-message ring buffer ───────────────────────────────────────── */

/*
 * Enqueue a fault message.  Returns 0 on success, -EAGAIN if the ring is
 * full (the message is silently dropped — the faulting thread will retry).
 */
static int
uffd_enqueue(struct uffd_state *u, const struct uffd_msg *msg)
{
  pthread_mutex_lock(&u->lock);
  if (u->nr_pending >= UFFD_MAX_PENDING) {
    pthread_mutex_unlock(&u->lock);
    return -LINUX_EAGAIN;
  }
  u->pending[u->tail] = *msg;
  u->tail = (u->tail + 1) % UFFD_MAX_PENDING;
  u->nr_pending++;
  pthread_mutex_unlock(&u->lock);
  return 0;
}

/*
 * Dequeue one fault message.  Returns true and fills *msg, or false if
 * the queue is empty.
 */
static bool
uffd_dequeue(struct uffd_state *u, struct uffd_msg *msg)
{
  pthread_mutex_lock(&u->lock);
  if (u->nr_pending == 0) {
    pthread_mutex_unlock(&u->lock);
    return false;
  }
  *msg = u->pending[u->head];
  u->head = (u->head + 1) % UFFD_MAX_PENDING;
  u->nr_pending--;
  pthread_mutex_unlock(&u->lock);
  return true;
}

/* ── the syscall itself ────────────────────────────────────────────────── */

DEFINE_SYSCALL(userfaultfd, int, flags)
{
  if (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC))
    return -LINUX_EINVAL;

  /* Allocate a slot. */
  int slot = -1;
  for (int i = 0; i < UFFD_MAX; i++) {
    if (uffds[i].fd < 0) {
      slot = i;
      break;
    }
  }
  if (slot < 0)
    return -LINUX_EMFILE;

  /* Create the socketpair. */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return -darwin_to_linux_errno(errno);

  /* Guest end gets the caller's flags; nabi end is always non-blocking. */
  if ((flags & LINUX_O_NONBLOCK) && fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0)
    goto fail;
  if ((flags & LINUX_O_CLOEXEC) && fcntl(sv[0], F_SETFD, FD_CLOEXEC) < 0)
    goto fail;
  fcntl(sv[1], F_SETFL, O_NONBLOCK);

  /* Register the guest-visible fd. */
  pthread_rwlock_wrlock(&proc.fileinfo.fdtable_lock);
  int err = register_fd(sv[0], (flags & LINUX_O_CLOEXEC) != 0);
  pthread_rwlock_unlock(&proc.fileinfo.fdtable_lock);
  if (err < 0) {
    close(sv[0]);
    close(sv[1]);
    return err;
  }

  /* Publish the slot (fd last so nothing is half-built). */
  uffds[slot].wr = sv[1];
  uffds[slot].fd = sv[0];
  pthread_mutex_init(&uffds[slot].lock, NULL);

  return sv[0];

fail:;
  int e = errno;
  close(sv[0]);
  close(sv[1]);
  return -darwin_to_linux_errno(e);
}

/* ── read interception ─────────────────────────────────────────────────── */

/*
 * Intercept read(2) on a uffd.  Delivers queued fault messages.
 * If nothing is pending, blocks by reading from the socketpair (a poke
 * from the fault handler wakes us).
 */
bool
userfaultfd_read(int fd, char *out, size_t size, int *ret)
{
  struct uffd_state *u = uffd_lookup(fd);
  if (u == NULL)
    return false;

  if (size < sizeof(struct uffd_msg)) {
    *ret = -LINUX_EINVAL;
    return true;
  }

  for (;;) {
    /* Drain any stale poke bytes. */
    char drain[64];
    while (recv(fd, drain, sizeof drain, MSG_DONTWAIT) > 0)
      ;

    /* Deliver the next pending message. */
    struct uffd_msg msg;
    if (uffd_dequeue(u, &msg)) {
      memcpy(out, &msg, sizeof msg);
      *ret = (int)sizeof msg;
      return true;
    }

    /* Nothing pending — check non-blocking. */
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0 && (fl & O_NONBLOCK)) {
      *ret = -LINUX_EAGAIN;
      return true;
    }

    /* Block until someone pokes us. */
    char b;
    ssize_t r = read(fd, &b, 1);
    if (r < 0) {
      if (errno == EINTR && sigrestart_wanted())
        continue;
      *ret = -darwin_to_linux_errno(errno);
      return true;
    }
    if (r == 0) {
      *ret = -LINUX_EBADF;
      return true;
    }
  }
}

/* ── ioctl interception ────────────────────────────────────────────────── */

bool
userfaultfd_ioctl(int fd, int cmd, uint64_t val0, int *ret)
{
  struct uffd_state *u = uffd_lookup(fd);
  if (u == NULL)
    return false;

  /* The ioctl command numbers have the high bit set (IOC_OUT/IOC_INOUT);
   * compare as unsigned to avoid signed-overflow warnings. */
  unsigned int uc = (unsigned int)cmd;

  switch (uc) {

  case (unsigned int)UFFDIO_API: {
    struct uffdio_api api;
    if (copy_from_user(&api, (gaddr_t)val0, sizeof api)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    /* Only UFFD_API version 0xAA is understood. */
    if (api.api != UFFD_API) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    /* No optional features are supported yet. */
    if (api.features != 0) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    u->api_set  = true;
    u->api      = UFFD_API;
    u->features = 0;
    /* Fill the reply: features we accept, and the range ioctls available. */
    api.api      = UFFD_API;
    api.features = 0;
    api.ioctls   = ((1ULL << _UFFDIO_REGISTER)  |
                    (1ULL << _UFFDIO_UNREGISTER) |
                    (1ULL << _UFFDIO_WAKE)       |
                    (1ULL << _UFFDIO_COPY)       |
                    (1ULL << _UFFDIO_ZEROPAGE));
    if (copy_to_user((gaddr_t)val0, &api, sizeof api)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    *ret = 0;
    return true;
  }

  case (unsigned int)UFFDIO_REGISTER: {
    if (!u->api_set) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    struct uffdio_register reg;
    if (copy_from_user(&reg, (gaddr_t)val0, sizeof reg)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    if (reg.range.start & 0xFFF || reg.range.len == 0 ||
        (reg.range.start + reg.range.len) < reg.range.start) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    if (reg.mode != UFFDIO_REGISTER_MODE_MISSING) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    if (u->nr_ranges >= UFFD_MAX_RANGES) {
      *ret = -LINUX_ENOMEM;
      return true;
    }
    /* Check for overlapping ranges. */
    for (int i = 0; i < u->nr_ranges; i++) {
      uint64_t a_start = u->ranges[i].start;
      uint64_t a_end   = a_start + u->ranges[i].len;
      uint64_t b_start = reg.range.start;
      uint64_t b_end   = b_start + reg.range.len;
      if (b_start < a_end && a_start < b_end) {
        *ret = -LINUX_EINVAL;
        return true;
      }
    }
    u->ranges[u->nr_ranges].start = reg.range.start;
    u->ranges[u->nr_ranges].len   = reg.range.len;
    u->nr_ranges++;
    /* Report which range ioctls are available for this range. */
    reg.ioctls = ((1ULL << _UFFDIO_WAKE)  |
                  (1ULL << _UFFDIO_COPY)  |
                  (1ULL << _UFFDIO_ZEROPAGE));
    if (copy_to_user((gaddr_t)val0, &reg, sizeof reg)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    *ret = 0;
    return true;
  }

  case (unsigned int)UFFDIO_UNREGISTER: {
    struct uffdio_range range;
    if (copy_from_user(&range, (gaddr_t)val0, sizeof range)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    bool found = false;
    for (int i = 0; i < u->nr_ranges; i++) {
      if (u->ranges[i].start == range.start && u->ranges[i].len == range.len) {
        /* Shift remaining ranges down. */
        memmove(&u->ranges[i], &u->ranges[i + 1],
                (u->nr_ranges - i - 1) * sizeof(struct uffd_range));
        u->nr_ranges--;
        found = true;
        break;
      }
    }
    if (!found) {
      *ret = -LINUX_EINVAL;
      return true;
    }
    *ret = 0;
    return true;
  }

  case (unsigned int)UFFDIO_WAKE: {
    /* Wake a blocked fault at the given address (if any). */
    struct uffdio_range range;
    if (copy_from_user(&range, (gaddr_t)val0, sizeof range)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    pthread_mutex_lock(&faults_lock);
    for (uint64_t a = range.start; a < range.start + range.len; a += 0x1000) {
      struct uffd_pending_fault *f = find_pending_fault(a);
      if (f != NULL) {
        pthread_mutex_lock(&f->lock);
        f->resolved = true;
        pthread_cond_signal(&f->cond);
        pthread_mutex_unlock(&f->lock);
      }
    }
    pthread_mutex_unlock(&faults_lock);
    *ret = 0;
    return true;
  }

  case (unsigned int)UFFDIO_COPY: {
    struct uffdio_copy ucopy;
    if (copy_from_user(&ucopy, (gaddr_t)val0, sizeof ucopy)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    if (ucopy.dst & 0xFFF || ucopy.src & 0xFFF || ucopy.len == 0 ||
        ucopy.len & 0xFFF) {
      *ret = -LINUX_EINVAL;
      return true;
    }

    /*
     * Copy the source pages to the destination.  Both are guest addresses.
     * The source must be mapped (the resolver prepared it); the destination
     * may be reserved (PROT_NONE, no backing).  If the destination region
     * is reserved, materialise it first so the copy has somewhere to land.
     */
    int copied = 0;
    for (uint64_t off = 0; off < ucopy.len; off += 0x1000) {
      uint64_t dst_addr = ucopy.dst + off;
      uint64_t src_addr = ucopy.src + off;

      /* Materialise the destination page if it is still reserved. */
      pthread_rwlock_wrlock(&proc.mm->alloc_lock);
      struct mm_region *r = find_region(dst_addr, proc.mm);
      if (r && r->reserved) {
        off_t aoff = -1;
        void *ptr  = arena_alloc(r->size, &aoff);
        if (ptr == NULL) {
          pthread_rwlock_unlock(&proc.mm->alloc_lock);
          *ret = -LINUX_ENOMEM;
          return true;
        }
        r->haddr    = ptr;
        r->arena_off = aoff;
        r->reserved = false;
        hv_memory_flags_t hvprot = HV_MEMORY_READ | HV_MEMORY_WRITE;
        vmm_mmap(r->gaddr, r->size, hvprot, ptr);
      }
      pthread_rwlock_unlock(&proc.mm->alloc_lock);

      /* Perform the copy. */
      void *hdst = guest_to_host(dst_addr);
      void *hsrc = guest_to_host(src_addr);
      if (hdst == NULL || hsrc == NULL) {
        *ret = -LINUX_EFAULT;
        return true;
      }
      memcpy(hdst, hsrc, 0x1000);
      copied += 0x1000;
    }

    /* Wake the blocked faulting thread(s) in this range. */
    pthread_mutex_lock(&faults_lock);
    for (uint64_t a = ucopy.dst; a < ucopy.dst + ucopy.len; a += 0x1000) {
      struct uffd_pending_fault *f = find_pending_fault(a);
      if (f != NULL) {
        pthread_mutex_lock(&f->lock);
        f->resolved = true;
        pthread_cond_signal(&f->cond);
        pthread_mutex_unlock(&f->lock);
      }
    }
    pthread_mutex_unlock(&faults_lock);

    ucopy.copy = copied;
    if (copy_to_user((gaddr_t)val0, &ucopy, sizeof ucopy)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    *ret = 0;
    return true;
  }

  case (unsigned int)UFFDIO_ZEROPAGE: {
    struct uffdio_zeropage uzp;
    if (copy_from_user(&uzp, (gaddr_t)val0, sizeof uzp)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    if (uzp.range.start & 0xFFF || uzp.range.len == 0 ||
        uzp.range.len & 0xFFF) {
      *ret = -LINUX_EINVAL;
      return true;
    }

    /* Zero each page in the range.  Materialise if reserved. */
    int zeroed = 0;
    for (uint64_t off = 0; off < uzp.range.len; off += 0x1000) {
      uint64_t dst_addr = uzp.range.start + off;

      pthread_rwlock_wrlock(&proc.mm->alloc_lock);
      struct mm_region *r = find_region(dst_addr, proc.mm);
      if (r && r->reserved) {
        off_t aoff = -1;
        void *ptr  = arena_alloc(r->size, &aoff);
        if (ptr == NULL) {
          pthread_rwlock_unlock(&proc.mm->alloc_lock);
          *ret = -LINUX_ENOMEM;
          return true;
        }
        r->haddr     = ptr;
        r->arena_off = aoff;
        r->reserved  = false;
        hv_memory_flags_t hvprot = HV_MEMORY_READ | HV_MEMORY_WRITE;
        vmm_mmap(r->gaddr, r->size, hvprot, ptr);
      }
      pthread_rwlock_unlock(&proc.mm->alloc_lock);

      void *hdst = guest_to_host(dst_addr);
      if (hdst == NULL) {
        *ret = -LINUX_EFAULT;
        return true;
      }
      memset(hdst, 0, 0x1000);
      zeroed += 0x1000;
    }

    /* Wake the blocked faulting thread(s). */
    pthread_mutex_lock(&faults_lock);
    for (uint64_t a = uzp.range.start; a < uzp.range.start + uzp.range.len;
         a += 0x1000) {
      struct uffd_pending_fault *f = find_pending_fault(a);
      if (f != NULL) {
        pthread_mutex_lock(&f->lock);
        f->resolved = true;
        pthread_cond_signal(&f->cond);
        pthread_mutex_unlock(&f->lock);
      }
    }
    pthread_mutex_unlock(&faults_lock);

    uzp.zeropage = zeroed;
    if (copy_to_user((gaddr_t)val0, &uzp, sizeof uzp)) {
      *ret = -LINUX_EFAULT;
      return true;
    }
    *ret = 0;
    return true;
  }

  default:
    return false;  /* not handled — fall through to darwinfs_ioctl */
  }
}

/* ── close interception ────────────────────────────────────────────────── */

void
userfaultfd_close(int fd)
{
  struct uffd_state *u = uffd_lookup(fd);
  if (u == NULL)
    return;

  /* Clear any pending faults owned by this uffd. */
  pthread_mutex_lock(&faults_lock);
  struct list_head *pos, *tmp;
  list_for_each_safe(pos, tmp, &pending_faults) {
    struct uffd_pending_fault *f =
        list_entry(pos, struct uffd_pending_fault, list);
    if (f->uffd_idx == (int)(u - uffds)) {
      pthread_mutex_lock(&f->lock);
      f->resolved = true;
      pthread_cond_signal(&f->cond);
      pthread_mutex_unlock(&f->lock);
      list_del(pos);
      pthread_mutex_destroy(&f->lock);
      pthread_cond_destroy(&f->cond);
      free(f);
    }
  }
  pthread_mutex_unlock(&faults_lock);

  /* Release the socketpair and the slot. */
  pthread_mutex_lock(&u->lock);
  int wr = u->wr;
  u->fd  = -1;
  u->wr  = -1;
  u->nr_ranges  = 0;
  u->nr_pending = 0;
  u->head = 0;
  u->tail = 0;
  pthread_mutex_unlock(&u->lock);
  pthread_mutex_destroy(&u->lock);
  close(wr);
}

/* ── page-fault handler hook ───────────────────────────────────────────── */

/*
 * Called from the VMM's EXIT_MMU_FAULT path when addr_ok() fails.
 * If the faulting address is in a registered range, we:
 *   1. Build a uffd_msg for the fault.
 *   2. Enqueue it on the owning uffd.
 *   3. Poke the socketpair so poll/read wake up.
 *   4. Create a pending-fault entry and block on its condvar.
 *   5. When UFFDIO_COPY / UFFDIO_ZEROPAGE resolves it, the condvar is
 *      signalled and the thread retries the faulting instruction.
 */
bool
userfaultfd_handle_fault(uint64_t addr, int fault_access)
{
  /* Round down to page boundary for range lookup. */
  uint64_t page = addr & ~0xFFFULL;

  struct uffd_state *u = uffd_for_addr(page);
  if (u == NULL)
    return false;

  /* Build the fault message. */
  struct uffd_msg msg;
  memset(&msg, 0, sizeof msg);
  msg.event = UFFD_EVENT_PAGEFAULT;
  msg.arg.pagefault.address = page;
  msg.arg.pagefault.flags   = (fault_access == VM_ACCESS_WRITE)
                                  ? UFFD_PAGEFAULT_FLAG_WRITE
                                  : 0;

  /* Enqueue and poke. */
  uffd_enqueue(u, &msg);
  uffd_poke(u);

  /* Create the blocking entry. */
  struct uffd_pending_fault *f = calloc(1, sizeof *f);
  if (f == NULL)
    return false;   /* allocation failed — fall through to SIGSEGV */

  f->uffd_idx = (int)(u - uffds);
  f->addr     = page;
  f->resolved = false;
  pthread_mutex_init(&f->lock, NULL);
  pthread_cond_init(&f->cond, NULL);

  pthread_mutex_lock(&faults_lock);
  list_add_tail(&f->list, &pending_faults);
  pthread_mutex_unlock(&faults_lock);

  /* Block until the resolver calls UFFDIO_COPY / UFFDIO_ZEROPAGE. */
  pthread_mutex_lock(&f->lock);
  while (!f->resolved)
    pthread_cond_wait(&f->cond, &f->lock);
  pthread_mutex_unlock(&f->lock);

  /* Remove from the global list and free. */
  pthread_mutex_lock(&faults_lock);
  list_del(&f->list);
  pthread_mutex_unlock(&faults_lock);
  pthread_mutex_destroy(&f->lock);
  pthread_cond_destroy(&f->cond);
  free(f);

  return true;  /* fault resolved — caller retries the instruction */
}
