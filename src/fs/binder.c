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
#include "namespace.h"
#include "mm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <limits.h>
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

/*
 * A flat_binder_object on the wire: type and flags, then the binder pointer or
 * handle, then the cookie. Twenty-four bytes, with the cookie at sixteen.
 */
#define FLAT_OBJ_SIZE   24
#define FLAT_OBJ_COOKIE 16
/* B_PACK_CHARS('f','d','*',B_TYPE_LARGE), as mSL-DevFS's binder.h spells it. */
#define LINUX_BINDER_TYPE_FD_EMUL 0x66642a85u

#define BINDER_MAX_EP     32
#define BINDER_MAX_ALLOCS 128
#define BINDER_PENDING    (64 * 1024)

/*
 * The part of binder that cannot live in one process.
 *
 * Endpoints are in different nabi processes - that is what binder is for - so
 * the registry of who exists, which of them is the context manager, and what
 * is waiting for each has to be somewhere they can all reach. It is a file
 * mapped shared by every process of the instance, locked while it is touched.
 *
 * A message carries its payload rather than a pointer to it. The obvious
 * design - have the sender write straight into the receiver's arena - cannot
 * work here and does not need to: the arena is the guest's own anonymous
 * memory, private to its process, and no other nabi can reach it. What has to
 * cross is the *payload*, and once it has, the receiver allocates in its own
 * arena and copies it in locally, which is the same code the one-process
 * engine already used. The guest cannot tell the difference; it is handed a
 * pointer into its own arena either way.
 *
 * The payload cap is the price of staging it. Binder's own limit is the
 * receiver's arena; here a transaction larger than a record is refused rather
 * than truncated. Android's ordinary traffic is far below this - bulk data
 * goes by descriptor or shared memory, not in the parcel.
 */
#define BSHM_MSG_MAX  8
#define BSHM_PAYLOAD  8192
#define BSHM_MAGIC    0x42494e44u

struct bmsg {
  uint32_t used;
  uint32_t is_reply;
  uint64_t cookie;
  uint32_t code, flags;
  uint32_t sender_pid, sender_euid;
  uint64_t data_size, offsets_size;
  unsigned char data[BSHM_PAYLOAD];
};

struct bep_shared {
  uint32_t used;
  int32_t  pid;
  uint32_t id;
  uint32_t is_mgr;
  struct bmsg q[BSHM_MSG_MAX];
};

struct bshm {
  uint32_t magic;
  uint32_t next_id;
  struct bep_shared ep[BINDER_MAX_EP];
};

static struct bshm *shm;
static int shm_fd = -1;

struct binder_alloc {
  uint64_t addr, size;
  bool     live;
};

/* One open of the device. Binder state is per open, not per process: a process
 * that opens it twice has two of everything, which is what the ABI says. */
struct binder_ep {
  int      fd;                   /* the descriptor the guest holds; -1 free */
  int      wr;                   /* our own end, for waking a local reader */
  uint32_t id;                   /* this endpoint's place in the shared table */
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

/*
 * The shared registry, made by whichever process needs it first and found by
 * the rest through the environment - the same way the binder broker publishes
 * its rendezvous and the kernel log its file. A forked child inherits the name
 * and maps the same memory.
 */
#define BINDER_SHM_ENV "NABI_BINDER_SHM"

static void
shm_path(char *out, size_t n)
{
  const char *set = getenv(BINDER_SHM_ENV);
  if (set != NULL && *set != '\0') {
    snprintf(out, n, "%s", set);
    return;
  }
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-binder-%s-%d", tmp && *tmp ? tmp : "/tmp",
           nabi_boot_tag(), (int) getpid());
  setenv(BINDER_SHM_ENV, out, 1);
}

/* The wake channel for one endpoint: a fifo, because any process may open it
 * by name and a byte written to it wakes a poll on the read end. A socketpair
 * cannot do that - only the process holding the other end can poke it. */
static void
wake_path(uint32_t id, char *out, size_t n)
{
  char base[PATH_MAX];
  shm_path(base, sizeof base);
  snprintf(out, n, "%s-wake-%u", base, id);
}

static bool
shm_attach(void)
{
  if (shm != NULL)
    return true;
  char path[PATH_MAX];
  shm_path(path, sizeof path);
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return false;
  if (ftruncate(fd, sizeof(struct bshm)) < 0) {
    close(fd);
    return false;
  }
  void *p = mmap(NULL, sizeof(struct bshm), PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) {
    close(fd);
    return false;
  }
  shm = p;
  shm_fd = fd;
  if (shm->magic != BSHM_MAGIC) {
    memset(shm, 0, sizeof *shm);
    shm->magic = BSHM_MAGIC;
    shm->next_id = 1;
  }
  return true;
}

static void shm_lock(void)   { if (shm_fd >= 0) flock(shm_fd, LOCK_EX); }
static void shm_unlock(void) { if (shm_fd >= 0) flock(shm_fd, LOCK_UN); }

void
binder_emul_init(void)
{
  for (int i = 0; i < BINDER_MAX_EP; i++) {
    eps[i].fd = -1;
    eps[i].wr = -1;
  }
  /* The mapping does not survive an exec, and a forked child is an exec. */
  shm = NULL;
  shm_fd = -1;
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
/*
 * Which endpoint a handle names, across the whole instance. Only handle 0
 * exists so far and it is the context manager - the one object every client
 * can find without having been given a reference to it first. Answered from
 * the shared registry, because the manager is usually in another process.
 */
static int
shm_ep_for_handle(uint32_t handle)
{
  if (handle != 0 || !shm_attach())
    return -1;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (shm->ep[i].used && shm->ep[i].is_mgr)
      return i;
  return -1;
}

/* Wake whoever is waiting on an endpoint, wherever it is. */
static void
shm_wake(uint32_t id)
{
  char path[PATH_MAX];
  wake_path(id, path, sizeof path);
  int fd = open(path, O_WRONLY | O_NONBLOCK);
  if (fd < 0)
    return;                      /* nobody listening; the queue still has it */
  char one = 1;
  (void) write(fd, &one, 1);
  close(fd);
}

/* Readable when something is waiting, the way signalfd and eventfd do it. */
/* Make this endpoint readable for a poll in *this* process. A sender in
 * another one uses shm_wake, which opens the same fifo by name. */
static void
ep_poke(struct binder_ep *e)
{
  if (e->id != 0)
    shm_wake(e->id);
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
  if (!shm_attach()) {
    errno = ENOMEM;
    return -1;
  }

  /* A place in the shared registry, so senders in other processes can find
   * this endpoint and leave work for it. */
  shm_lock();
  int slot = -1;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (!shm->ep[i].used) { slot = i; break; }
  if (slot < 0) {
    shm_unlock();
    errno = EMFILE;
    return -1;
  }
  memset(&shm->ep[slot], 0, sizeof shm->ep[slot]);
  shm->ep[slot].id = shm->next_id++;
  shm->ep[slot].pid = (int32_t) getpid();
  shm->ep[slot].used = 1;
  uint32_t id = shm->ep[slot].id;
  shm_unlock();

  /* The descriptor the guest holds is the reading end of a fifo, which is what
   * lets a sender in another process wake it: a fifo has a name, and a
   * socketpair has only the two ends its maker holds. Opened read-write so it
   * never reports end-of-file when no writer happens to have it open. */
  char path[PATH_MAX];
  wake_path(id, path, sizeof path);
  unlink(path);
  if (mkfifo(path, 0600) < 0 && errno != EEXIST) {
    shm_lock(); shm->ep[slot].used = 0; shm_unlock();
    return -1;
  }
  int fd = open(path, O_RDWR | O_NONBLOCK);
  if (fd < 0) {
    shm_lock(); shm->ep[slot].used = 0; shm_unlock();
    return -1;
  }
  if (flags & LINUX_O_CLOEXEC)
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  if (!(flags & LINUX_O_NONBLOCK))
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_free();
  if (e == NULL) {
    pthread_mutex_unlock(&eps_lock);
    close(fd);
    shm_lock(); shm->ep[slot].used = 0; shm_unlock();
    errno = EMFILE;
    return -1;
  }
  memset(e, 0, sizeof *e);
  e->wr = -1;
  e->id = id;
  e->fd = fd;                    /* published last, as the poke walks the table */
  pthread_mutex_unlock(&eps_lock);

  *out_fd = fd;
  return 0;
}

void
binder_emul_close(int fd)
{
  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_of(fd);
  uint32_t id = e ? e->id : 0;
  if (e != NULL) {
    e->wr = -1;
    e->fd = -1;
  }
  pthread_mutex_unlock(&eps_lock);
  if (id == 0)
    return;

  if (shm_attach()) {
    shm_lock();
    for (int i = 0; i < BINDER_MAX_EP; i++)
      if (shm->ep[i].used && shm->ep[i].id == id) {
        shm->ep[i].used = 0;     /* the manager goes with it, if it was one */
        break;
      }
    shm_unlock();
  }
  char path[PATH_MAX];
  wake_path(id, path, sizeof path);
  unlink(path);
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
  int slot = reply ? -1 : shm_ep_for_handle((uint32_t) tr->target);
  if (reply) {
    /* A reply goes back to whoever is waiting for it. Only the same endpoint
     * so far, which is what the one-thread case needs; a reply across
     * processes needs the transaction stack that is not built yet. */
    slot = -1;
    for (int i = 0; i < BINDER_MAX_EP && shm_attach(); i++)
      if (shm->ep[i].used && shm->ep[i].id == from->id) { slot = i; break; }
  }
  if (slot < 0)
    return -LINUX_ENOENT;

  uint64_t total = tr->data_size + tr->offsets_size;
  if (total > BSHM_PAYLOAD)
    return -LINUX_ENOMEM;        /* staged, so a record is the limit */

  /*
   * Staged into shared memory rather than written into the receiver's arena.
   * The arena is the receiver's own anonymous memory and no other process can
   * reach it; what has to cross is the payload. The receiver copies it into
   * its arena when it collects the message, in its own process, with the same
   * code that always did it.
   */
  shm_lock();
  struct bep_shared *dst = &shm->ep[slot];
  struct bmsg *m = NULL;
  for (int i = 0; i < BSHM_MSG_MAX; i++)
    if (!dst->q[i].used) { m = &dst->q[i]; break; }
  if (m == NULL) {
    shm_unlock();
    return -LINUX_EAGAIN;        /* the receiver is behind; binder blocks here */
  }

  m->is_reply = reply;
  m->cookie = tr->cookie;
  m->code = tr->code;
  m->flags = tr->flags;
  m->sender_pid = (uint32_t) getpid();
  m->sender_euid = 0;
  m->data_size = tr->data_size;
  m->offsets_size = tr->offsets_size;
  int err = 0;
  if (tr->data_size > 0) {
    void *src = guest_to_host(tr->buffer);
    if (src == NULL) err = -LINUX_EFAULT;
    else memcpy(m->data, src, tr->data_size);
  }
  if (err == 0 && tr->offsets_size > 0) {
    void *src = guest_to_host(tr->offsets);
    if (src == NULL) err = -LINUX_EFAULT;
    else memcpy(m->data + tr->data_size, src, tr->offsets_size);
  }
  if (err != 0) {
    shm_unlock();
    return err;
  }

  /*
   * Descriptors named in the parcel.
   *
   * A BINDER_TYPE_FD object carries a descriptor number, and a number means
   * nothing in another process. Linux's driver installs the file in the
   * receiver and rewrites the number; nothing on macOS can do that from here,
   * so the object keeps the sender's number and the driver stamps the sender's
   * pid into the cookie. That pair is what the receiver hands the descriptor
   * broker to get a real descriptor of its own - the same arrangement the kext
   * uses, kept identical so both binders behave the same way.
   */
  if (m->offsets_size >= 8) {
    unsigned char *data = m->data;
    uint64_t *offs = (uint64_t *)(void *)(m->data + m->data_size);
    size_t n = (size_t)(m->offsets_size / 8);
    for (size_t i = 0; i < n; i++) {
      uint64_t at = offs[i];
      if (at + FLAT_OBJ_SIZE > m->data_size)
        continue;                /* not an object we can read; leave it alone */
      uint32_t type;
      memcpy(&type, data + at, sizeof type);
      if (type != LINUX_BINDER_TYPE_FD_EMUL)
        continue;
      uint64_t cookie = (uint64_t) getpid();
      memcpy(data + at + FLAT_OBJ_COOKIE, &cookie, sizeof cookie);
    }
  }

  m->used = 1;
  uint32_t wake_id = dst->id;
  shm_unlock();

  shm_wake(wake_id);

  /* The sender is told its transaction was handed over. For a one-way call
   * that is the whole of the answer it gets. */
  ep_queue_cmd(from, BR_TRANSACTION_COMPLETE);
  return 0;
}

/*
 * Collect whatever has been left for this endpoint and turn it into the
 * commands the guest will read. This is where a message becomes a pointer into
 * the reader's own arena, which is why it happens here and not where the
 * message was posted.
 */
static void
collect_messages(struct binder_ep *e)
{
  if (!shm_attach())
    return;
  shm_lock();
  int slot = -1;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (shm->ep[i].used && shm->ep[i].id == e->id) { slot = i; break; }
  if (slot < 0) {
    shm_unlock();
    return;
  }
  for (int i = 0; i < BSHM_MSG_MAX; i++) {
    struct bmsg *m = &shm->ep[slot].q[i];
    if (!m->used)
      continue;
    uint64_t total = m->data_size + m->offsets_size;
    uint64_t at = arena_take(e, total ? total : 8);
    if (at == 0)
      break;                     /* no room yet; it stays queued */
    void *dst = guest_to_host(at);
    if (dst == NULL)
      break;
    memcpy(dst, m->data, total);

    struct btr out;
    memset(&out, 0, sizeof out);
    out.cookie = m->cookie;
    out.code = m->code;
    out.flags = m->flags;
    out.sender_pid = m->sender_pid;
    out.sender_euid = m->sender_euid;
    out.data_size = m->data_size;
    out.offsets_size = m->offsets_size;
    out.buffer = at;
    out.offsets = m->offsets_size ? at + m->data_size : 0;

    ep_queue_cmd(e, m->is_reply ? BR_REPLY : BR_TRANSACTION);
    ep_queue(e, &out, sizeof out);
    m->used = 0;
  }
  shm_unlock();
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
  collect_messages(e);           /* anything another process left for us */
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

  /* Drain the wake bytes along with the work they stood for. */
  char drain[64];
  int fl = fcntl(e->fd, F_GETFL);
  fcntl(e->fd, F_SETFL, fl | O_NONBLOCK);
  while (read(e->fd, drain, sizeof drain) > 0)
    ;
  fcntl(e->fd, F_SETFL, fl);
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
    /* One at a time across the whole instance, not just this process - that is
     * what makes handle 0 mean one thing to everybody. */
    if (!shm_attach()) { r = -LINUX_ENOMEM; break; }
    shm_lock();
    for (int i = 0; i < BINDER_MAX_EP; i++)
      if (shm->ep[i].used && shm->ep[i].is_mgr && shm->ep[i].id != e->id) {
        r = -LINUX_EBUSY;
        break;
      }
    if (r == 0)
      for (int i = 0; i < BINDER_MAX_EP; i++)
        if (shm->ep[i].used && shm->ep[i].id == e->id) {
          shm->ep[i].is_mgr = 1;
          e->is_mgr = true;
          break;
        }
    shm_unlock();
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
