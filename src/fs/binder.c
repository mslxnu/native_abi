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
#include <poll.h>
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
#define BC_TRANSACTION_SG   0x40486311u
#define BC_REPLY_SG         0x40486312u
#define BC_REGISTER_LOOPER  0x0000630Bu
#define BC_ENTER_LOOPER     0x0000630Cu
#define BC_EXIT_LOOPER      0x0000630Du

/* Commands the guest reads. */
#define BR_TRANSACTION           0x80407202u
#define BR_TRANSACTION_SEC_CTX   0x80487202u

/* flat_binder_object.flags: this node wants the sec-ctx form. */
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000u
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
#define LINUX_BINDER_TYPE_FD_EMUL  0x66642a85u
#define LINUX_BINDER_TYPE_FDA_EMUL 0x66646185u
#define LINUX_BINDER_TYPE_PTR_EMUL 0x70742a85u

/* A scatter-gather buffer object: a pointer into the sender's memory that the
 * receiver must be given a copy of, and where in its parent to write the copy's
 * address. Forty bytes. */
struct bbuf_obj {
  uint32_t type, flags;
  uint64_t buffer, length, parent, parent_offset;
};
/* An array of descriptors living inside a buffer object. Thirty-two bytes. */
struct bfda_obj {
  uint32_t type, pad;
  uint64_t num_fds, parent, parent_offset;
};
#define BUFFER_FLAG_HAS_PARENT 0x01u

/* Everything binder puts in a buffer is eight-byte aligned. */
static uint64_t balign(uint64_t v) { return (v + 7) & ~(uint64_t) 7; }

#define BINDER_MAX_EP     32
#define BINDER_MAX_ALLOCS 128
/* Longest binder context name kept; binderfs allows 255, nothing uses it. */
#define BINDER_CTX_NAME 32

#define BINDER_MAX_FIXUPS 4
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
  /* Where the parts sit inside `data`, which is the buffer as the receiver
   * will see it: the parcel, the offsets, then the scatter-gather copies. */
  uint64_t offs_at, extra_at, total;
  /*
   * For each descriptor this message names, in the order they are walked: the
   * endpoint it is an open of, or zero if it is an ordinary file.
   *
   * A descriptor that arrives from the broker is a real descriptor, but only
   * the process that opened it knows it was a binder device - here it is the
   * reading end of a fifo, and an ioctl on it would go to the host and come
   * back ENOTTY. Saying so with the message is what lets the receiver adopt it
   * as an endpoint rather than guess from the file it points at.
   */
  uint32_t fd_ep[16];
  uint32_t fd_n;
  unsigned char data[BSHM_PAYLOAD];
};

struct bep_shared {
  uint32_t used;
  /*
   * How many descriptors, in any process, are open on this endpoint.
   *
   * A descriptor is not the endpoint. One is inherited across a fork and
   * another arrives from the broker, and closing either must not take the
   * endpoint away from whoever else still holds one. Without this, a child
   * that inherited its parent's binder descriptors destroyed them on exit -
   * the parent's own opens went on working locally while every other process
   * stopped being able to find them.
   */
  uint32_t refs;
  int32_t  pid;
  uint32_t id;
  uint32_t is_mgr;
  /*
   * Which binder this endpoint is an open of.
   *
   * Not one driver with one namespace: /dev/binder, /dev/hwbinder and
   * /dev/vndbinder are separate contexts on a device, and binderfs exists to
   * make more of them. Each has its own context manager, so handle 0 means a
   * different object depending on which one you opened - which is the whole
   * point of the split, since it is what keeps framework calls and vendor
   * calls from reaching each other.
   */
  char     ctx[BINDER_CTX_NAME];
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
  char     ctx[BINDER_CTX_NAME]; /* the binder this is an open of */
  bool     is_mgr;
  bool     secctx;               /* wants transactions in the sec-ctx form */
  uint32_t max_threads;

  uint64_t arena_addr, arena_size, arena_brk;
  struct binder_alloc allocs[BINDER_MAX_ALLOCS];

  /* Commands waiting to be read, as the bytes the guest will be given. */
  unsigned char pending[BINDER_PENDING];
  size_t   pending_len, pending_off;

  /*
   * Pointers inside the pending bytes that point at other pending bytes.
   *
   * The security-context string travels in the read buffer with a pointer to
   * it beside it, so the pointer's value is the guest address the string will
   * land at - which nothing knows until the guest asks for a read and names
   * the buffer. Queueing records the two offsets and the read patches them.
   */
  struct { size_t at, to; } fixups[BINDER_MAX_FIXUPS];
  unsigned fixup_n;
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

static void ep_adopt(int fd, uint32_t id);
static void ep_adopt_locked(int fd, uint32_t id);

static struct binder_ep *
ep_free(void)
{
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (eps[i].fd < 0)
      return &eps[i];
  return NULL;
}

/*
 * Take a descriptor that arrived from another process and treat it as what it
 * is: an open of an endpoint. It gets a slot of its own here so ioctls on it
 * are answered, and shares the shared-table entry with the process that opened
 * it, because it is the same endpoint - not a second one.
 *
 * Two of them: the plain one takes both locks, and the _locked one is for the
 * paths that already hold them - a caller holding eps_lock cannot ask for it
 * again, and the shared table is guarded by a file lock that does not nest.
 */
static void
ep_adopt_locked(int fd, uint32_t id)
{
  if (ep_of(fd) != NULL)
    return;
  struct binder_ep *e = ep_free();
  if (e == NULL)
    return;
  memset(e, 0, sizeof *e);
  e->wr = -1;
  e->id = id;
  e->fd = fd;

  /* Another descriptor on the endpoint, so it must outlive this one. */
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (shm->ep[i].used && shm->ep[i].id == id) {
      shm->ep[i].refs++;
      snprintf(e->ctx, sizeof e->ctx, "%s", shm->ep[i].ctx);
      break;
    }
}

static void
ep_adopt(int fd, uint32_t id)
{
  if (!shm_attach())
    return;
  pthread_mutex_lock(&eps_lock);
  shm_lock();
  ep_adopt_locked(fd, id);
  shm_unlock();
  pthread_mutex_unlock(&eps_lock);
}

/*
 * The endpoint a descriptor is an open of, or zero.
 *
 * Asked of the descriptor's *name*. Every endpoint's wake channel is a fifo
 * called "...-wake-<id>", so the id is recoverable from the descriptor alone -
 * no table, no registry walk, and it works however the descriptor arrived.
 * That matters because they arrive by routes that leave no record: inherited
 * across a fork, which on arm64 is an exec into an empty table, or handed over
 * by the broker from another process entirely.
 */
static uint32_t
ep_id_of_fd(int fd)
{
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
    return 0;

  char path[PATH_MAX];
  if (fcntl(fd, F_GETPATH, path) != 0)
    return 0;
  /*
   * Matched on the shape of the name rather than on a path prefix. The two
   * spellings of one directory do not compare equal: macOS answers F_GETPATH
   * with /private/var/... for what was created as /var/..., and TMPDIR
   * conventionally ends in a separator, so the path built from it has a
   * doubled one. Requiring "nabi-binder-" and "-wake-" in the last component
   * says the same thing without depending on how the directory is spelled.
   */
  const char *leaf = strrchr(path, '/');
  leaf = leaf ? leaf + 1 : path;
  if (strncmp(leaf, "nabi-binder-", 12) != 0)
    return 0;
  const char *mark = strstr(leaf, "-wake-");
  if (mark == NULL)
    return 0;

  unsigned long id = strtoul(mark + 6, NULL, 10);
  return (uint32_t) id;
}

/*
 * Is this descriptor an open of one of our endpoints?
 *
 * The local table first, and the name only when the table has never heard of
 * it - which is the first time a descriptor arrives from elsewhere, and only
 * that once, because the answer is written down.
 */
bool
binder_emul_is(int fd)
{
  pthread_mutex_lock(&eps_lock);
  bool yes = ep_of(fd) != NULL;
  pthread_mutex_unlock(&eps_lock);
  if (yes || fd < 0)
    return yes;

  uint32_t id = ep_id_of_fd(fd);
  if (id == 0)
    return false;
  ep_adopt(fd, id);
  return true;
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
shm_ep_for_handle(uint32_t handle, const char *ctx)
{
  if (handle != 0 || !shm_attach())
    return -1;
  for (int i = 0; i < BINDER_MAX_EP; i++)
    if (shm->ep[i].used && shm->ep[i].is_mgr &&
        strcmp(shm->ep[i].ctx, ctx) == 0)
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

/* Note that the eight bytes at "at" are to hold the address of "to". */
static void
ep_queue_fixup(struct binder_ep *e, size_t at, size_t to)
{
  if (e->fixup_n < BINDER_MAX_FIXUPS) {
    e->fixups[e->fixup_n].at = at;
    e->fixups[e->fixup_n].to = to;
    e->fixup_n++;
  }
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
binder_emul_open(const char *ctx, int flags, int *out_fd)
{
  if (ctx == NULL || *ctx == '\0')
    ctx = "binder";
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
  shm->ep[slot].refs = 1;
  snprintf(shm->ep[slot].ctx, sizeof shm->ep[slot].ctx, "%s", ctx);
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
  snprintf(e->ctx, sizeof e->ctx, "%s", ctx);
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

  bool last = false;
  if (shm_attach()) {
    shm_lock();
    for (int i = 0; i < BINDER_MAX_EP; i++)
      if (shm->ep[i].used && shm->ep[i].id == id) {
        if (shm->ep[i].refs > 0)
          shm->ep[i].refs--;
        if (shm->ep[i].refs == 0) {
          shm->ep[i].used = 0;   /* the manager goes with it, if it was one */
          last = true;
        }
        break;
      }
    shm_unlock();
  }
  /* Only the last descriptor takes the endpoint's wake channel with it. */
  if (last) {
    char path[PATH_MAX];
    wake_path(id, path, sizeof path);
    unlink(path);
  }
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
do_transaction(struct binder_ep *from, const struct btr *tr, bool reply,
               uint64_t buffers_size)
{
  int slot = reply ? -1 : shm_ep_for_handle((uint32_t) tr->target, from->ctx);
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

  /*
   * The receiver's buffer is the data, then the offsets, then whatever the
   * scatter-gather objects point at - each part eight-byte aligned, which is
   * how the receiver knows where to look without being told.
   */
  uint64_t data_at = 0;
  uint64_t offs_at = balign(tr->data_size);
  uint64_t extra_at = offs_at + balign(tr->offsets_size);
  uint64_t total = extra_at + buffers_size;
  if (total > BSHM_PAYLOAD)
    return -LINUX_ENOMEM;        /* staged, so a record is the limit */
  (void) data_at;

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
  m->fd_n = 0;
  m->extra_at = extra_at;
  m->offs_at = offs_at;
  m->total = total;
  int err = 0;
  memset(m->data, 0, total);
  if (tr->data_size > 0) {
    void *src = guest_to_host(tr->buffer);
    if (src == NULL) err = -LINUX_EFAULT;
    else memcpy(m->data, src, tr->data_size);
  }
  if (err == 0 && tr->offsets_size > 0) {
    void *src = guest_to_host(tr->offsets);
    if (src == NULL) err = -LINUX_EFAULT;
    else memcpy(m->data + offs_at, src, tr->offsets_size);
  }
  if (err != 0) {
    shm_unlock();
    return err;
  }

  /*
   * Scatter-gather: an object that points somewhere else in the sender's
   * memory has that memory copied in beside the parcel, and its pointer
   * rewritten to say where. The rewrite here is an *offset* into the buffer
   * rather than an address, because the address is not known yet - it depends
   * on where the receiver's arena allocation lands, which only the receiving
   * process can decide. collect_messages turns these into real pointers.
   */
  if (m->offsets_size >= 8) {
    uint64_t *offs = (uint64_t *)(void *)(m->data + offs_at);
    size_t n = (size_t)(m->offsets_size / 8);
    uint64_t put = extra_at;
    for (size_t i = 0; i < n && err == 0; i++) {
      uint64_t at = offs[i];
      if (at + sizeof(uint32_t) > m->data_size)
        continue;
      uint32_t type;
      memcpy(&type, m->data + at, sizeof type);
      if (type != LINUX_BINDER_TYPE_PTR_EMUL)
        continue;
      if (at + sizeof(struct bbuf_obj) > m->data_size)
        continue;
      struct bbuf_obj bo;
      memcpy(&bo, m->data + at, sizeof bo);
      if (put + bo.length > total) { err = -LINUX_ENOMEM; break; }
      void *src = guest_to_host(bo.buffer);
      if (src == NULL) { err = -LINUX_EFAULT; break; }
      memcpy(m->data + put, src, bo.length);
      bo.buffer = put;           /* an offset for now; see above */
      memcpy(m->data + at, &bo, sizeof bo);
      put += balign(bo.length);
    }
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

  /*
   * Descriptor arrays. The numbers live inside a buffer object rather than in
   * the parcel, so they are found through the parent the object names - an
   * offset into the parcel, which is where mSL's driver puts it. Each one is
   * registered with the broker so the receiver can ask for a descriptor of its
   * own; the numbers themselves stay the sender's until then.
   */
  if (m->offsets_size >= 8) {
    uint64_t *offs = (uint64_t *)(void *)(m->data + offs_at);
    size_t n = (size_t)(m->offsets_size / 8);
    for (size_t i = 0; i < n; i++) {
      uint64_t at = offs[i];
      if (at + sizeof(struct bfda_obj) > m->data_size)
        continue;
      uint32_t type;
      memcpy(&type, m->data + at, sizeof type);
      if (type != LINUX_BINDER_TYPE_FDA_EMUL)
        continue;
      struct bfda_obj fo;
      memcpy(&fo, m->data + at, sizeof fo);
      if (fo.parent + sizeof(struct bbuf_obj) > m->data_size)
        continue;
      struct bbuf_obj parent;
      memcpy(&parent, m->data + fo.parent, sizeof parent);
      uint64_t base = parent.buffer + fo.parent_offset;   /* an offset by now */
      for (uint64_t k = 0; k < fo.num_fds; k++) {
        if (base + (k + 1) * 8 > total)
          break;
        uint64_t num;
        memcpy(&num, m->data + base + k * 8, sizeof num);
        binder_broker_register((uint32_t) getpid(), (uint32_t) num);
        struct binder_ep *fe = ep_of((int) num);
        if (m->fd_n < 16)
          m->fd_ep[m->fd_n++] = fe ? fe->id : 0;
      }
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
    uint64_t total = m->total ? m->total : (m->data_size + m->offsets_size);
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
    out.offsets = m->offsets_size ? at + m->offs_at : 0;

    /*
     * The pointers can be made real now, because the arena address is finally
     * known. A buffer object's offset becomes an address in this process's
     * arena, and if it said where its parent should point, that is written too.
     */
    uint32_t fdi = 0;
    if (m->offsets_size >= 8) {
      unsigned char *base = (unsigned char *) dst;
      uint64_t *offs = (uint64_t *)(void *)(base + m->offs_at);
      size_t n = (size_t)(m->offsets_size / 8);
      for (size_t i = 0; i < n; i++) {
        uint64_t o = offs[i];
        if (o + sizeof(uint32_t) > m->data_size)
          continue;
        uint32_t type;
        memcpy(&type, base + o, sizeof type);

        if (type == LINUX_BINDER_TYPE_PTR_EMUL &&
            o + sizeof(struct bbuf_obj) <= m->data_size) {
          struct bbuf_obj bo;
          memcpy(&bo, base + o, sizeof bo);
          uint64_t addr = at + bo.buffer;
          bo.buffer = addr;
          memcpy(base + o, &bo, sizeof bo);
          if ((bo.flags & BUFFER_FLAG_HAS_PARENT) &&
              bo.parent + sizeof(struct bbuf_obj) <= m->data_size) {
            struct bbuf_obj par;
            memcpy(&par, base + bo.parent, sizeof par);
            uint64_t slot = (par.buffer - at) + bo.parent_offset;
            if (slot + 8 <= m->total)
              memcpy(base + slot, &addr, sizeof addr);
          }
          continue;
        }

        /*
         * A descriptor array: each number is the sender's, and means nothing
         * here. The broker gives this process a descriptor of its own for each
         * one, and the number it gets is written back into the array - which is
         * the substitution Linux's driver does when it installs the file.
         */
        if (type == LINUX_BINDER_TYPE_FDA_EMUL &&
            o + sizeof(struct bfda_obj) <= m->data_size) {
          struct bfda_obj fo;
          memcpy(&fo, base + o, sizeof fo);
          if (fo.parent + sizeof(struct bbuf_obj) > m->data_size)
            continue;
          struct bbuf_obj par;
          memcpy(&par, base + fo.parent, sizeof par);
          uint64_t slot = (par.buffer - at) + fo.parent_offset;
          for (uint64_t k = 0; k < fo.num_fds; k++) {
            if (slot + (k + 1) * 8 > m->total)
              break;
            uint64_t num;
            memcpy(&num, base + slot + k * 8, sizeof num);
            int got = binder_broker_request(m->sender_pid, (uint32_t) num);
            /*
             * The guest has to be able to use it, which means it has to be in
             * the descriptor table - a host descriptor the guest was never
             * given is EBADF the moment it tries, before anything gets far
             * enough to notice it names a binder endpoint.
             */
            if (got >= 0 && register_fd(got, false) != 0) {
              close(got);
              got = -1;
            }
            uint64_t mine = (got >= 0) ? (uint64_t) got : (uint64_t) -1;
            if (got >= 0 && fdi < m->fd_n && m->fd_ep[fdi] != 0)
              ep_adopt_locked(got, m->fd_ep[fdi]);
            fdi++;
            memcpy(base + slot + k * 8, &mine, sizeof mine);
          }
        }
      }
    }

    /*
     * A node registered with TXN_SECURITY_CTX is told who the sender is, in
     * the longer form that carries the label: the same transaction followed by
     * a pointer to a context string, with the string itself in the read buffer
     * after it. There is no SELinux here to ask, so every sender gets the same
     * placeholder - enough for a caller that only looks at the label to run,
     * and honest that it is not a decision anyone made.
     */
    if (e->secctx && !m->is_reply) {
      static const char label[] = "u:r:untrusted_app:s0";
      uint64_t placeholder = 0;
      ep_queue_cmd(e, BR_TRANSACTION_SEC_CTX);
      ep_queue(e, &out, sizeof out);
      size_t at = e->pending_len;
      ep_queue(e, &placeholder, sizeof placeholder);
      size_t to = e->pending_len;
      ep_queue(e, label, sizeof label);
      ep_queue_fixup(e, at, to);
    } else {
      ep_queue_cmd(e, m->is_reply ? BR_REPLY : BR_TRANSACTION);
      ep_queue(e, &out, sizeof out);
    }
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
      int r = do_transaction(e, &tr, cmd == BC_REPLY, 0);
      if (r < 0)
        return r;
      break;
    }

    /*
     * The scatter-gather form: the same transaction followed by how much room
     * the objects inside it will need. Nothing else differs, which is the
     * point of it - the sender says up front what the buffer must hold so the
     * receiver's allocation is made once.
     */
    case BC_TRANSACTION_SG:
    case BC_REPLY_SG: {
      struct { struct btr tr; uint64_t buffers_size; } sg;
      void *q = guest_to_host(buf + off);
      if (q == NULL)
        return -LINUX_EFAULT;
      memcpy(&sg, q, sizeof sg);
      off += sizeof sg;
      int r = do_transaction(e, &sg.tr, cmd == BC_REPLY_SG, sg.buffers_size);
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

  /*
   * A read with nothing to read waits, which is what a binder read does: a
   * looper's whole life is one blocking read, and a caller that has just sent
   * a transaction sits in one until the reply comes back. Returning empty
   * straight away turns every such wait into a spin, and a caller that spins a
   * fixed number of times gives up before a peer that is still starting - on
   * arm64 a fork is an exec, so a freshly forked sender takes long enough to
   * lose that race every time.
   *
   * The wait is on the endpoint's wake fifo, and eps_lock is dropped for it:
   * held, it would stop every other thread in this process from touching
   * binder for as long as this one has nothing to do. Bounded, so a wakeup
   * that goes missing costs a return trip rather than the process.
   */
  bool block = (fcntl(e->fd, F_GETFL) & O_NONBLOCK) == 0;
  for (int waited = 0;
       block && e->pending_len == e->pending_off && waited < 5000;
       waited += 200) {
    struct pollfd pfd = { .fd = e->fd, .events = POLLIN };
    int wfd = e->fd;
    pthread_mutex_unlock(&eps_lock);
    poll(&pfd, 1, 200);
    pthread_mutex_lock(&eps_lock);
    if (ep_of(wfd) != e)         /* closed under us while we waited */
      return 0;
    collect_messages(e);
  }

  size_t have = e->pending_len - e->pending_off;
  if (have == 0)
    return 0;
  size_t n = have < size ? have : (size_t) size;
  void *dst = guest_to_host(buf);
  if (dst == NULL)
    return -LINUX_EFAULT;
  memcpy(dst, e->pending + e->pending_off, n);

  /* Now the buffer has an address, so the pointers into it can be filled in. */
  for (unsigned i = 0; i < e->fixup_n; ) {
    size_t at = e->fixups[i].at, to = e->fixups[i].to;
    bool in = at >= e->pending_off && at + 8 <= e->pending_off + n &&
              to >= e->pending_off && to < e->pending_off + n;
    if (in) {
      uint64_t addr = buf + (to - e->pending_off);
      memcpy((unsigned char *) dst + (at - e->pending_off), &addr, sizeof addr);
      e->fixups[i] = e->fixups[--e->fixup_n];
    } else {
      i++;
    }
  }

  e->pending_off += n;
  if (e->pending_off == e->pending_len) {
    e->pending_off = e->pending_len = 0;
    e->fixup_n = 0;
  }
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

/*
 * Where this endpoint's transaction buffers live.
 *
 * Registered two ways, because there are two kinds of caller. mSL's own
 * BINDER_MSL_SET_ARENA hands over memory the guest already has, which is what
 * the conformance probe does; a real binder client calls mmap on the device
 * and the driver gives it a mapping, which is what every process in Android
 * does - libbinder's ProcessState maps just under a megabyte before it will
 * talk to anything. Both end here.
 */
static int
arena_set(struct binder_ep *e, uint64_t addr, uint64_t size)
{
  /* Refused rather than trusted: a null or tiny arena is a caller that has not
   * really registered one, and the first transaction would write into whatever
   * is there. */
  if (addr == 0 || size < 4096)
    return -LINUX_EINVAL;
  if (guest_to_host(addr) == NULL)
    return -LINUX_EFAULT;
  /*
   * Once only. Buffers already handed out point into the arena that was
   * registered when they were allocated, so accepting a second one would leave
   * the guest holding pointers this no longer believes in - and the receiver
   * would go on reading a region nothing is delivering into.
   */
  if (e->arena_addr != 0)
    return -LINUX_EBUSY;
  e->arena_addr = addr;
  e->arena_size = size;
  e->arena_brk = 0;
  memset(e->allocs, 0, sizeof e->allocs);
  return 0;
}

/*
 * mmap of the device, which is how a real client asks for its arena. The
 * memory is the guest's own - nabi has nothing of its own to map here - so the
 * caller has already made an anonymous mapping and this only records it.
 */
int
binder_emul_mmap(int fd, uint64_t addr, uint64_t size)
{
  pthread_mutex_lock(&eps_lock);
  struct binder_ep *e = ep_of(fd);
  int r = e == NULL ? -LINUX_ENOTTY : arena_set(e, addr, size);
  pthread_mutex_unlock(&eps_lock);
  return r;
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
    /*
     * The _EXT form names the node being registered, and its flags say which
     * form of transaction that node wants. Asked for rather than assumed: a
     * manager registered without the flag is given the plain 64-byte
     * BR_TRANSACTION and would mis-read the longer one as its own fields.
     */
    e->secctx = false;
    if (cmd == LINUX_BINDER_SET_CONTEXT_MGR_EXT) {
      uint32_t fbo_flags;                     /* flat_binder_object.flags */
      unsigned char *p = guest_to_host(arg);
      if (p == NULL) { r = -LINUX_EFAULT; break; }
      memcpy(&fbo_flags, p + 4, sizeof fbo_flags);
      e->secctx = (fbo_flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX) != 0;
    }

    /* One at a time across the whole instance, not just this process - that is
     * what makes handle 0 mean one thing to everybody. */
    if (!shm_attach()) { r = -LINUX_ENOMEM; break; }
    shm_lock();
    for (int i = 0; i < BINDER_MAX_EP; i++)
      if (shm->ep[i].used && shm->ep[i].is_mgr && shm->ep[i].id != e->id &&
          strcmp(shm->ep[i].ctx, e->ctx) == 0) {
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
    r = arena_set(e, a.addr, a.size);
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
