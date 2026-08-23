/*
 * Binder, served by nabi rather than by a driver.
 *
 * /dev/binder has been a passthrough to mSL/DevFS, which implements the Linux
 * binder ABI as a real kernel extension. That works and is fast, and it cannot
 * be the only answer: a kext is a thing to install, sign and keep current with
 * the host, and nabi has to be able to run Android without one. So this is the
 * same ABI implemented inside nabi, chosen by NABI_BINDER and otherwise used
 * whenever the host has no binder device to borrow.
 *
 * The arena is the part worth understanding first. mSL's binder does not have
 * the guest mmap the device; the guest allocates ordinary anonymous memory and
 * registers it with BINDER_MSL_SET_ARENA, and that region is where transaction
 * payloads are delivered. It exists because the driver had to be told a host
 * address for guest memory. Here there is no driver to tell - nabi already
 * knows where the guest's memory is - so registration is bookkeeping, but the
 * ioctl stays because it is the ABI the guest speaks and the probe checks it.
 *
 * What this file does *not* do yet is deliver between processes. A transaction
 * whose target is in another nabi process needs that process's arena to be
 * shared memory rather than private anonymous memory, and needs a way to wake
 * a receiver that is blocked in another process. Both are the next increment;
 * the single-process engine below is the whole of the mechanism otherwise -
 * allocate in the receiver's arena, copy, deliver, free - which is why the
 * probe calls its one-thread stage "the whole engine in one thread".
 */
#include "common.h"
#include "noah.h"
#include "mm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/ioctl.h"

/* The protocol version this speaks, which is what BINDER_VERSION answers. */
#define BINDER_CURRENT_PROTOCOL_VERSION 8

/* Commands the guest writes. */
#define BC_TRANSACTION      0x40406300u
#define BC_REPLY            0x40406301u
#define BC_FREE_BUFFER      0x40086303u
#define BC_INCREFS          0x40046304u
#define BC_ACQUIRE          0x40046305u
#define BC_RELEASE          0x40046306u
#define BC_DECREFS          0x40046307u
#define BC_INCREFS_DONE     0x40106308u
#define BC_ACQUIRE_DONE     0x40106309u
#define BC_REGISTER_LOOPER  0x0000630Bu
#define BC_ENTER_LOOPER     0x0000630Cu
#define BC_EXIT_LOOPER      0x0000630Du

/* Commands the guest reads. */
#define BR_TRANSACTION           0x80407202u
#define BR_REPLY                 0x80407203u
#define BR_TRANSACTION_COMPLETE  0x00007206u
#define BR_NOOP                  0x0000720Cu

#define TF_ONE_WAY 0x01u

#define BINDER_MAX_EP     64
#define BINDER_MAX_ALLOCS 128
#define BINDER_PENDING    (64 * 1024)

struct binder_alloc {
  uint64_t addr, size;
  bool     live;
};

/* One open of the device. Binder state is per open, not per process: a process
 * that opens it twice has two of everything, which is what the ABI says. */
struct binder_ep {
  int      fd;                   /* the descriptor the guest holds; -1 free */
  int      wr;                   /* the end nabi pokes to make fd readable */
  bool     is_mgr;
  uint32_t max_threads;

  uint64_t arena_addr, arena_size, arena_brk;
  struct binder_alloc allocs[BINDER_MAX_ALLOCS];

  /* Commands waiting to be read, as the bytes the guest will be given. */
  unsigned char pending[BINDER_PENDING];
  size_t   pending_len, pending_off;
};

static struct binder_ep eps[BINDER_MAX_EP];
static pthread_mutex_t eps_lock = PTHREAD_MUTEX_INITIALIZER;

void
binder_emul_init(void)
{
  for (int i = 0; i < BINDER_MAX_EP; i++) {
    eps[i].fd = -1;
    eps[i].wr = -1;
  }
}

/* A descriptor the guest holds. Negative is refused rather than searched for:
 * a free slot is fd < 0, so looking one up would answer with somebody else's. */
static struct binder_ep *
ep_of(int fd)
{
  if (fd < 0)
    return NULL;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (eps[i].fd == fd)
      return &eps[i];
  return NULL;
}

static struct binder_ep *
ep_free(void)
{
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (eps[i].fd < 0)
      return &eps[i];
  return NULL;
}

bool
binder_emul_is(int fd)
{
  pthread_mutex_lock(&eps_lock);
  bool yes = ep_of(fd) != NULL;
  pthread_mutex_unlock(&eps_lock);
  return yes;
}

/*
 * Which endpoint a handle names. Only handle 0 exists so far, and it is the
 * context manager - the one object every binder client can find without having
 * been given a reference to it first.
 */
static struct binder_ep *
ep_for_handle(uint32_t handle)
{
  if (handle != 0)
    return NULL;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (eps[i].fd >= 0 && eps[i].is_mgr)
      return &eps[i];
  return NULL;
}

/* Readable when something is waiting, the way signalfd and eventfd do it. */
static void
ep_poke(struct binder_ep *e)
{
  char one = 1;
  if (e->wr >= 0)
    (void) send(e->wr, &one, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void
ep_queue(struct binder_ep *e, const void *bytes, size_t n)
{
  if (e->pending_len + n > sizeof e->pending)
    return;                      /* dropped rather than overrun; see BR_NOOP */
  memcpy(e->pending + e->pending_len, bytes, n);
  e->pending_len += n;
  ep_poke(e);
}

static void
ep_queue_cmd(struct binder_ep *e, uint32_t cmd)
{
  ep_queue(e, &cmd, sizeof cmd);
}

/*
 * Space in the receiver's arena for a payload.
 *
 * A bump allocator with a free list of one bit per allocation. Binder's own is
 * a best-fit over a red-black tree, which matters when an arena lives for the
 * lifetime of a process; this does not reuse space yet, and says so rather
 * than pretending otherwise.
 */
static uint64_t
arena_take(struct binder_ep *e, uint64_t size)
{
  if (e->arena_size == 0)
    return 0;
  uint64_t want = (size + 7) & ~(uint64_t) 7;
  if (e->arena_brk + want > e->arena_size)
    return 0;
  for (int i = 0; i < BINDER_MAX_ALLOCS; i++) {
    if (e->allocs[i].live)
      continue;
    if (e->allocs[i].addr != 0)
      continue;                  /* a freed record, kept so a double free is seen */
    e->allocs[i].addr = e->arena_addr + e->arena_brk;
    e->allocs[i].size = want;
    e->allocs[i].live = true;
    e->arena_brk += want;
    return e->allocs[i].addr;
  }
  return 0;
}

/* True if the buffer was live and is now freed; false for anything else, which
 * is what makes freeing twice an error rather than a no-op. */
static bool
arena_release(struct binder_ep *e, uint64_t addr)
{
  for (int i = 0; i < BINDER_MAX_ALLOCS; i++)
    if (e->allocs[i].addr == addr && e->allocs[i].live) {
      e->allocs[i].live = false;
      return true;
    }
  return false;
}

int
binder_emul_open(int flags, int *out_fd)
{
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return -1;
  if (flags & LINUX_O_CLOEXEC)
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);
  if (flags & LINUX_O_NONBLOCK)
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
  fcntl(sv[1], F_SETFL, O_NONBLOCK);

  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_free();
  if (e == NULL) {
    pthread_mutex_unlock(&eps_lock);
    close(sv[0]);
    close(sv[1]);
    errno = EMFILE;
    return -1;
  }
  memset(e, 0, sizeof *e);
  e->wr = sv[1];
  e->fd = sv[0];                 /* published last, as the poke walks the table */
  pthread_mutex_unlock(&eps_lock);

  *out_fd = sv[0];
  return 0;
}

void
binder_emul_close(int fd)
{
  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_of(fd);
  if (e != NULL) {
    if (e->wr >= 0)
      close(e->wr);
    e->wr = -1;
    e->fd = -1;
  }
  pthread_mutex_unlock(&eps_lock);
}

/* The 64-byte transaction on the wire, at the offsets binder.h lays out. */
struct btr {
  uint64_t target, cookie;
  uint32_t code, flags;
  uint32_t sender_pid, sender_euid;
  uint64_t data_size, offsets_size;
  uint64_t buffer, offsets;
};

/*
 * One BC_TRANSACTION or BC_REPLY: allocate in the *receiver's* arena, copy the
 * payload there, and hand the receiver a pointer into its own memory. That
 * copy is what binder is: the sender's buffer is never shared, so neither side
 * can change what the other is reading.
 */
static int
do_transaction(struct binder_ep *from, const struct btr *tr, bool reply)
{
  struct binder_ep *to = reply ? from : ep_for_handle((uint32_t) tr->target);
  if (to == NULL)
    return -LINUX_ENOENT;

  uint64_t total = tr->data_size + tr->offsets_size;
  uint64_t at = arena_take(to, total ? total : 8);
  if (at == 0)
    return -LINUX_ENOMEM;

  if (tr->data_size > 0) {
    void *dst = guest_to_host(at);
    void *src = guest_to_host(tr->buffer);
    if (dst == NULL || src == NULL)
      return -LINUX_EFAULT;
    memcpy(dst, src, tr->data_size);
  }
  if (tr->offsets_size > 0) {
    void *dst = guest_to_host(at + tr->data_size);
    void *src = guest_to_host(tr->offsets);
    if (dst == NULL || src == NULL)
      return -LINUX_EFAULT;
    memcpy(dst, src, tr->offsets_size);
  }

  struct btr out = *tr;
  out.buffer = at;
  out.offsets = tr->offsets_size ? at + tr->data_size : 0;
  out.sender_pid = (uint32_t) getpid();
  out.sender_euid = 0;

  ep_queue_cmd(to, reply ? BR_REPLY : BR_TRANSACTION);
  ep_queue(to, &out, sizeof out);

  /* The sender is told its transaction was handed over. For a one-way call
   * that is the whole of the answer it gets. */
  ep_queue_cmd(from, BR_TRANSACTION_COMPLETE);
  return 0;
}

/* Walk the commands the guest wrote. Returns 0, or the first error - binder
 * stops at one rather than carrying on with the rest of the buffer. */
static int
consume_writes(struct binder_ep *e, uint64_t buf, uint64_t size,
               uint64_t *consumed)
{
  uint64_t off = 0;
  while (off + 4 <= size) {
    uint32_t cmd;
    void *p = guest_to_host(buf + off);
    if (p == NULL)
      return -LINUX_EFAULT;
    memcpy(&cmd, p, 4);
    off += 4;

    switch (cmd) {
    case BC_ENTER_LOOPER:
    case BC_REGISTER_LOOPER:
    case BC_EXIT_LOOPER:
      break;                     /* thread bookkeeping; nothing to answer */

    case BC_INCREFS:
    case BC_ACQUIRE:
    case BC_RELEASE:
    case BC_DECREFS:
      off += 4;                  /* a handle, whose refcount nothing yet needs */
      break;

    case BC_INCREFS_DONE:
    case BC_ACQUIRE_DONE:
      off += 16;                 /* node pointer and cookie */
      break;

    case BC_FREE_BUFFER: {
      uint64_t addr;
      void *q = guest_to_host(buf + off);
      if (q == NULL)
        return -LINUX_EFAULT;
      memcpy(&addr, q, 8);
      off += 8;
      if (!arena_release(e, addr))
        return -LINUX_EINVAL;    /* not ours, or already given back */
      break;
    }

    case BC_TRANSACTION:
    case BC_REPLY: {
      struct btr tr;
      void *q = guest_to_host(buf + off);
      if (q == NULL)
        return -LINUX_EFAULT;
      memcpy(&tr, q, sizeof tr);
      off += sizeof tr;
      int r = do_transaction(e, &tr, cmd == BC_REPLY);
      if (r < 0)
        return r;
      break;
    }

    default:
      return -LINUX_EINVAL;
    }
    *consumed = off;
  }
  return 0;
}

static int
serve_reads(struct binder_ep *e, uint64_t buf, uint64_t size,
            uint64_t *consumed)
{
  if (size == 0)
    return 0;
  size_t have = e->pending_len - e->pending_off;
  if (have == 0)
    return 0;
  size_t n = have < size ? have : (size_t) size;
  void *dst = guest_to_host(buf);
  if (dst == NULL)
    return -LINUX_EFAULT;
  memcpy(dst, e->pending + e->pending_off, n);
  e->pending_off += n;
  if (e->pending_off == e->pending_len)
    e->pending_off = e->pending_len = 0;
  *consumed = n;

  /* Drain the readability byte with the data it stood for. */
  char drain[64];
  while (recv(e->fd, drain, sizeof drain, MSG_DONTWAIT) > 0)
    ;
  return 0;
}

int
binder_emul_ioctl(int fd, int cmd, uint64_t arg)
{
  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_of(fd);
  if (e == NULL) {
    pthread_mutex_unlock(&eps_lock);
    return -LINUX_ENOTTY;
  }

  int r = 0;
  switch ((unsigned) cmd) {
  case LINUX_BINDER_VERSION: {
    uint32_t v = BINDER_CURRENT_PROTOCOL_VERSION;
    void *p = guest_to_host(arg);
    if (p == NULL) { r = -LINUX_EFAULT; break; }
    memcpy(p, &v, sizeof v);
    break;
  }

  case LINUX_BINDER_SET_MAX_THREADS: {
    void *p = guest_to_host(arg);
    if (p == NULL) { r = -LINUX_EFAULT; break; }
    memcpy(&e->max_threads, p, sizeof e->max_threads);
    break;
  }

  case LINUX_BINDER_SET_CONTEXT_MGR:
  case LINUX_BINDER_SET_CONTEXT_MGR_EXT:
    /* Only one at a time, which is what makes handle 0 mean one thing. */
    for (int i = 0; i < BINDER_MAX_EP; i++)
      if (eps[i].fd >= 0 && eps[i].is_mgr && &eps[i] != e) {
        r = -LINUX_EBUSY;
        break;
      }
    if (r == 0)
      e->is_mgr = true;
    break;

  case LINUX_BINDER_MSL_SET_ARENA: {
    struct { uint64_t addr, size; } a;
    void *p = guest_to_host(arg);
    if (p == NULL) { r = -LINUX_EFAULT; break; }
    memcpy(&a, p, sizeof a);
    /* Refused rather than trusted: a null or tiny arena is a caller that has
     * not really registered one, and the first transaction would write into
     * whatever is there. */
    if (a.addr == 0 || a.size < 4096) { r = -LINUX_EINVAL; break; }
    if (guest_to_host(a.addr) == NULL) { r = -LINUX_EFAULT; break; }
    /*
     * Once only. Buffers already handed out point into the arena that was
     * registered when they were allocated, so accepting a second one would
     * leave the guest holding pointers this no longer believes in - and the
     * receiver would go on reading a region nothing is delivering into.
     */
    if (e->arena_addr != 0) { r = -LINUX_EBUSY; break; }
    e->arena_addr = a.addr;
    e->arena_size = a.size;
    e->arena_brk = 0;
    memset(e->allocs, 0, sizeof e->allocs);
    break;
  }

  case LINUX_BINDER_MSL_ABI_VERSION: {
    uint32_t v = 1;
    void *p = guest_to_host(arg);
    if (p == NULL) { r = -LINUX_EFAULT; break; }
    memcpy(p, &v, sizeof v);
    break;
  }

  case LINUX_BINDER_THREAD_EXIT:
  case LINUX_BINDER_SET_IDLE_TIMEOUT:
  case LINUX_BINDER_SET_IDLE_PRIORITY:
  case LINUX_BINDER_ENABLE_ONEWAY_SPAM_DETECTION:
    break;                       /* accepted; nothing here acts on them */

  case LINUX_BINDER_WRITE_READ: {
    struct { uint64_t ws, wc, wb, rs, rc, rb; } wr;
    void *p = guest_to_host(arg);
    if (p == NULL) { r = -LINUX_EFAULT; break; }
    memcpy(&wr, p, sizeof wr);

    if (wr.ws > wr.wc)
      r = consume_writes(e, wr.wb + wr.wc, wr.ws - wr.wc, &wr.wc);
    if (r == 0 && wr.rs > wr.rc)
      r = serve_reads(e, wr.rb + wr.rc, wr.rs - wr.rc, &wr.rc);
    if (r == 0)
      memcpy(p, &wr, sizeof wr);
    break;
  }

  default:
    r = -LINUX_ENOTTY;
    break;
  }

  pthread_mutex_unlock(&eps_lock);
  return r;
}
