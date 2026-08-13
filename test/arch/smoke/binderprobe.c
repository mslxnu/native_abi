/* freestanding: the binder ioctl passthrough, spoken end to end.
 *
 * NABI's fs.c sends the binder command numbers from include/linux/ioctl.h
 * to the host ioctl(2) with both direction bits set, so mSL/DevFS's driver
 * - which implements the Linux binder ABI - sees the guest's numbers and
 * the guest's argument pointers. This is that path in a guest, and it is
 * the driver's own probe (mSL-DevFS/tools/binder-probe.c) reduced to its
 * first four stages, because those are the ones a guest can reach without
 * a second process or a second vCPU:
 *
 *   version   the device answers BINDER_VERSION with protocol 8
 *   arena     BINDER_MSL_SET_ARENA accepts the registered region and
 *             refuses the null and the undersized
 *   manager   BINDER_SET_CONTEXT_MGR is a write-only command; the guest
 *             sends the Linux number, and the argument must arrive rather
 *             than be zeroed by XNU's direction-bit reading
 *   oneway    a transaction to ourselves, which is the whole engine in one
 *             thread: allocate in the arena, translate, deliver, free
 *
 * The sync/poll stages are left out because they need guest threads, which
 * binder-probe already covers on the host; the oneway stage proves the
 * ioctl numbers, the argument, and the arena all survive the NABI layer.
 *
 * twoproc is the same transaction across a fork: the client is its own
 * process with its own binder fd, arena and acquire, and the owner - the
 * context manager - receives the payload in *its* arena. That is the shape
 * the descriptor broker will build on, and the two processes are where the
 * per-process binder state is what separates them.
 *
 * fd      is the descriptor broker: the client sends a BINDER_TYPE_FD object
 * (its own /dev/binder open) in a oneway transaction and the manager, which
 * registered with FLAT_BINDER_FLAG_ACCEPTS_FDS, receives it back as a real
 * descriptor. NABI moved the fd over SCM_RIGHTS, keyed by the pid the driver
 * stamped into the cookie; the manager proves the substitution by asking the
 * received descriptor for its version.
 *
 * epoll   is the looper path: a read filter on the binder fd, which kqueue
 * refuses as a plain filter and NABI has to register with NOTE_LOWAT of one.
 * The filter must be exact both ways - silent before work, woken by it - or
 * a binder looper either spins or sleeps through a pending transaction.
 *
 * Exits 77 when /dev/binder is not present, so a host without the driver
 * loaded skips rather than fails.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_mmap 222
#define SYS_epoll_create1 20
#define SYS_epoll_ctl 21
#define SYS_epoll_pwait 22
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_clone 220
#define SYS_wait4 260
#define SIGCHLD 17
#define AT_FDCWD -100
#define O_RDWR 2
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define EPOLL_CTL_ADD 1
#define EPOLLIN 0x001u

/* Linux's own ioctl encodings; NABI rewrites the direction bits. */
#define BINDER_WRITE_READ          0xC0306201u
#define BINDER_SET_CONTEXT_MGR     0x40046207u
#define BINDER_SET_CONTEXT_MGR_EXT 0x4018620Du
#define BINDER_VERSION             0xC0046209u
#define BINDER_MSL_SET_ARENA       0xC01062E0u
#define BINDER_MSL_ABI_VERSION     0xC00462E1u

#define BC_ACQUIRE                 0x40046305u
#define BC_ENTER_LOOPER            0x0000630Cu
#define BC_FREE_BUFFER             0x40086303u
#define BC_TRANSACTION             0x40406300u
#define BR_TRANSACTION             0x80407202u
#define BR_TRANSACTION_COMPLETE    0x00007206u
#define TF_ONE_WAY                 0x01u

/* B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE) and flat_binder_object.flags, from
 * mSL-DevFS's binder.h. */
#define BINDER_TYPE_FD             0x66642a85u
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x0100u

#define ARENA_SIZE (256u * 1024u)

struct binder_write_read {
  unsigned long write_size;
  unsigned long write_consumed;
  unsigned long write_buffer;
  unsigned long read_size;
  unsigned long read_consumed;
  unsigned long read_buffer;
}; /* 48 bytes */

struct binder_version {
  int protocol_version;
}; /* 4 bytes */

struct binder_msl_arena {
  unsigned long addr;
  unsigned long size;
}; /* 16 bytes */

struct binder_transaction_data {
  union {
    unsigned long ptr;
    unsigned int handle;
  } target;
  unsigned long cookie;
  unsigned int code;
  unsigned int flags;
  int sender_pid;
  unsigned int sender_euid;
  unsigned long data_size;
  unsigned long offsets_size;
  union {
    struct {
      unsigned long buffer;
      unsigned long offsets;
    } ptr;
    unsigned char buf[8];
  } data;
}; /* 64 bytes */

typedef char assert_wr[sizeof(struct binder_write_read) == 48 ? 1 : -1];
typedef char assert_ver[sizeof(struct binder_version) == 4 ? 1 : -1];
typedef char assert_arena[sizeof(struct binder_msl_arena) == 16 ? 1 : -1];
typedef char assert_tr[sizeof(struct binder_transaction_data) == 64 ? 1 : -1];

/* A binder object in a payload: the fd sits in the low 4 bytes of the union
 * at offset 8, the cookie at 16. */
struct flat_binder_object {
  unsigned int type;
  unsigned int flags;
  unsigned int fd;
  unsigned int pad;
  unsigned long cookie;
}; /* 24 bytes */
typedef char assert_fbo[sizeof(struct flat_binder_object) == 24 ? 1 : -1];

/* Unpacked, as on aarch64: NABI's l_epoll_event is 16 bytes there (the x86-64
 * spelling is the packed 12-byte one). */
struct ep_event {
  unsigned int events;
  unsigned long long data;
}; /* 16 bytes */
typedef char assert_ep[sizeof(struct ep_event) == 16 ? 1 : -1];

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("binderprobe FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit_group, 1, 0,0,0,0,0);
}

static void mzero(void *p, unsigned long n)
{
  unsigned char *b = p;
  unsigned long i;
  for (i = 0; i < n; i++) b[i] = 0;
}

static void mcopy(void *d, const void *s, unsigned long n)
{
  unsigned char *a = d;
  const unsigned char *b = s;
  unsigned long i;
  for (i = 0; i < n; i++) a[i] = b[i];
}

static long bioctl(int fd, unsigned int cmd, void *arg)
{
  return sys6(SYS_ioctl, fd, cmd, (long)arg, 0, 0, 0);
}

static int binder_wr(int fd, void *wbuf, unsigned long wsize,
    void *rbuf, unsigned long rsize, unsigned long *consumed)
{
  struct binder_write_read bwr;
  long r;

  bwr.write_size = wsize;
  bwr.write_consumed = 0;
  bwr.write_buffer = (unsigned long)wbuf;
  bwr.read_size = rsize;
  bwr.read_consumed = 0;
  bwr.read_buffer = (unsigned long)rbuf;
  r = bioctl(fd, BINDER_WRITE_READ, &bwr);
  if (consumed != 0)
    *consumed = bwr.read_consumed;
  return (int)r;
}

static int open_binder(const char *path)
{
  return (int)sys6(SYS_openat, AT_FDCWD, (long)path, O_RDWR, 0, 0, 0);
}

static void stage_version(void)
{
  struct binder_version ver;
  unsigned int abi = 0;
  long r;
  int fd;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder", fd);
  r = bioctl(fd, BINDER_VERSION, &ver);
  if (r != 0 || ver.protocol_version != 8)
    fail("BINDER_VERSION", ver.protocol_version);
  r = bioctl(fd, BINDER_MSL_ABI_VERSION, &abi);
  if (r != 0 || abi != 1)
    fail("BINDER_MSL_ABI_VERSION", abi);
  sys6(SYS_close, fd, 0,0,0,0,0);
}

static void stage_arena(void)
{
  struct binder_msl_arena a;
  unsigned long arena;
  long r;
  int fd;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder (arena)", fd);

  a.addr = 0;
  a.size = ARENA_SIZE;
  if (bioctl(fd, BINDER_MSL_SET_ARENA, &a) >= 0)
    fail("a null arena was accepted", 0);

  a.addr = 0x100000;
  a.size = 64;
  if (bioctl(fd, BINDER_MSL_SET_ARENA, &a) >= 0)
    fail("an undersized arena was accepted", 0);

  arena = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)arena >= -4096 && (long)arena < 0)
    fail("mmap the arena", (long)arena);
  a.addr = arena;
  a.size = ARENA_SIZE;
  r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
  if (r != 0)
    fail("BINDER_MSL_SET_ARENA", r);
  if (bioctl(fd, BINDER_MSL_SET_ARENA, &a) >= 0)
    fail("a second arena was accepted", 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
}

static void stage_manager(void)
{
  int zero = 0;
  long r;
  int a, b;

  a = open_binder("/dev/binder");
  if (a < 0)
    fail("open /dev/binder (manager)", a);
  r = bioctl(a, BINDER_SET_CONTEXT_MGR, &zero);
  if (r != 0)
    fail("claim the context manager", r);
  b = open_binder("/dev/binder");
  if (b >= 0) {
    if (bioctl(b, BINDER_SET_CONTEXT_MGR, &zero) >= 0)
      fail("a second manager was accepted", 0);
    sys6(SYS_close, b, 0,0,0,0,0);
  }
  sys6(SYS_close, a, 0,0,0,0,0);
}

static void stage_oneway(void)
{
  struct binder_transaction_data tr, *got;
  unsigned char payload[16] = "binder-oneway";
  unsigned char wbuf[128], rbuf[512];
  struct binder_msl_arena a;
  unsigned long arena, consumed;
  unsigned int cmd;
  int woff, fd, spin, i;
  int zero = 0;
  long r;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder (oneway)", fd);
  r = bioctl(fd, BINDER_SET_CONTEXT_MGR, &zero);
  if (r != 0)
    fail("become the context manager", r);

  /* The arena must be registered before any transaction: it is where the
   * driver will put the payload, and the bounds check below reads it. */
  arena = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)arena >= -4096 && (long)arena < 0)
    fail("mmap the arena (oneway)", (long)arena);
  a.addr = arena;
  a.size = ARENA_SIZE;
  r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
  if (r != 0)
    fail("register the arena (oneway)", r);

  woff = 0;
  cmd = BC_ACQUIRE;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned int *)(wbuf + woff) = zero; woff += 4;
  cmd = BC_ENTER_LOOPER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_ACQUIRE on handle 0", 0);

  for (i = 0; i < (int)sizeof(tr); i++)
    ((unsigned char *)&tr)[i] = 0;
  tr.target.handle = 0;
  tr.code = 42;
  tr.flags = TF_ONE_WAY;
  tr.data_size = sizeof(payload);
  tr.data.ptr.buffer = (unsigned long)payload;
  tr.data.ptr.offsets = 0;

  woff = 0;
  cmd = BC_TRANSACTION;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  for (i = 0; i < (int)sizeof(tr); i++)
    wbuf[woff + i] = ((unsigned char *)&tr)[i];
  woff += (int)sizeof(tr);

  consumed = 0;
  if (binder_wr(fd, wbuf, woff, rbuf, sizeof(rbuf), &consumed) != 0)
    fail("BC_TRANSACTION accepted", 0);

  /* The first read may only deliver BR_TRANSACTION_COMPLETE; the delivery
   * itself is the next read, as binder-probe's comment says. */
  got = 0;
  for (spin = 0; spin < 5 && got == 0; spin++) {
    unsigned long off = 0;

    while (off + 4 <= consumed) {
      unsigned int c = *(unsigned int *)(rbuf + off);
      off += 4;
      if (c == BR_TRANSACTION) {
        got = (struct binder_transaction_data *)(rbuf + off);
        off += sizeof(tr);
        break;
      }
    }
    if (got == 0) {
      consumed = 0;
      if (binder_wr(fd, 0, 0, rbuf, sizeof(rbuf), &consumed) != 0)
        break;
    }
  }
  if (got == 0)
    fail("BR_TRANSACTION came back", 0);
  if (got->code != 42)
    fail("the transaction code survived", got->code);
  if (got->data_size != sizeof(payload))
    fail("the payload size survived", got->data_size);
  if (got->data.ptr.buffer < arena ||
      got->data.ptr.buffer >= arena + ARENA_SIZE)
    fail("the payload landed outside the arena", (long)got->data.ptr.buffer);
  for (i = 0; i < (int)sizeof(payload); i++) {
    if (((unsigned char *)got->data.ptr.buffer)[i] != payload[i])
      fail("the payload bytes survived the round trip", 0);
  }

  woff = 0;
  cmd = BC_FREE_BUFFER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned long *)(wbuf + woff) = got->data.ptr.buffer; woff += 8;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_FREE_BUFFER accepted", 0);
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) >= 0)
    fail("freeing the same buffer twice is refused", 0);

  sys6(SYS_close, fd, 0,0,0,0,0);
}

/* The looper path: epoll over the binder fd. NABI must register the read
 * filter with a NOTE_LOWAT of one, because kqueue refuses the plain filter
 * on a device without its own kqfilter; and that filter has to be exact, or
 * a looper either busy-spins or sleeps through a pending transaction. */
static void stage_epoll(void)
{
  struct binder_transaction_data tr, *got;
  unsigned char payload[16] = "binder-oneway";
  unsigned char wbuf[128], rbuf[512];
  struct binder_msl_arena a;
  struct ep_event ev;
  unsigned long arena, consumed, off;
  unsigned int cmd;
  int woff, fd, epfd, i, spin;
  int zero = 0;
  long r;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder (epoll)", fd);
  r = bioctl(fd, BINDER_SET_CONTEXT_MGR, &zero);
  if (r != 0)
    fail("become the context manager (epoll)", r);

  arena = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)arena >= -4096 && (long)arena < 0)
    fail("mmap the arena (epoll)", (long)arena);
  a.addr = arena;
  a.size = ARENA_SIZE;
  r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
  if (r != 0)
    fail("register the arena (epoll)", r);

  woff = 0;
  cmd = BC_ACQUIRE;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned int *)(wbuf + woff) = zero; woff += 4;
  cmd = BC_ENTER_LOOPER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_ACQUIRE on handle 0 (epoll)", 0);

  epfd = (int)sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
  if (epfd < 0)
    fail("epoll_create1", epfd);
  ev.events = EPOLLIN;
  ev.data = 77;
  r = sys6(SYS_epoll_ctl, epfd, EPOLL_CTL_ADD, fd, (long)&ev, 0, 0);
  if (r != 0)
    fail("epoll_ctl ADD the binder fd", r);

  /* With nothing pending the filter must be silent - the alternative, an
   * always-ready registration, is a looper that spins. */
  i = (int)sys6(SYS_epoll_pwait, epfd, (long)&ev, 1, 0, 0, 0);
  if (i != 0)
    fail("epoll before work (must sleep)", i);

  /* Deliver a oneway transaction to ourselves: the driver queues it and
   * selwakeups the process, which is what the filter is armed on. */
  for (i = 0; i < (int)sizeof(tr); i++)
    ((unsigned char *)&tr)[i] = 0;
  tr.target.handle = 0;
  tr.code = 43;
  tr.flags = TF_ONE_WAY;
  tr.data_size = sizeof(payload);
  tr.data.ptr.buffer = (unsigned long)payload;
  tr.data.ptr.offsets = 0;

  woff = 0;
  cmd = BC_TRANSACTION;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  for (i = 0; i < (int)sizeof(tr); i++)
    wbuf[woff + i] = ((unsigned char *)&tr)[i];
  woff += (int)sizeof(tr);
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_TRANSACTION accepted (epoll)", 0);

  /* And the wait must wake: the other failure mode is a looper that sleeps
   * through a transaction that is already pending. */
  i = (int)sys6(SYS_epoll_pwait, epfd, (long)&ev, 1, 5000, 0, 0);
  if (i != 1)
    fail("epoll after work (must wake)", i);
  if ((ev.events & EPOLLIN) == 0)
    fail("the woken event is EPOLLIN", ev.events);
  if (ev.data != 77)
    fail("the epoll data survived", ev.data);

  /* Drain the transaction, as stage_oneway does, and free its buffer. */
  got = 0;
  for (spin = 0; spin < 5 && got == 0; spin++) {
    consumed = 0;
    if (binder_wr(fd, 0, 0, rbuf, sizeof(rbuf), &consumed) != 0)
      break;
    off = 0;
    while (off + 4 <= consumed) {
      unsigned int c = *(unsigned int *)(rbuf + off);
      off += 4;
      if (c == BR_TRANSACTION) {
        got = (struct binder_transaction_data *)(rbuf + off);
        off += sizeof(tr);
        break;
      }
    }
  }
  if (got == 0)
    fail("BR_TRANSACTION came back (epoll)", 0);
  if (got->code != 43)
    fail("the epoll transaction code survived", got->code);
  if (got->data.ptr.buffer < arena ||
      got->data.ptr.buffer >= arena + ARENA_SIZE)
    fail("the epoll payload landed outside the arena", (long)got->data.ptr.buffer);
  for (i = 0; i < (int)sizeof(payload); i++) {
    if (((unsigned char *)got->data.ptr.buffer)[i] != payload[i])
      fail("the epoll payload bytes survived", 0);
  }

  woff = 0;
  cmd = BC_FREE_BUFFER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned long *)(wbuf + woff) = got->data.ptr.buffer; woff += 8;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_FREE_BUFFER accepted (epoll)", 0);

  /* Work drained, the filter must be silent again - it re-armed rather than
   * staying latched, or the looper would spin after every transaction. */
  i = (int)sys6(SYS_epoll_pwait, epfd, (long)&ev, 1, 0, 0, 0);
  if (i != 0)
    fail("epoll after drain (must sleep)", i);

  sys6(SYS_close, epfd, 0,0,0,0,0);
  sys6(SYS_close, fd, 0,0,0,0,0);
}

/* Two processes, the way binder is actually used: the owner is the context
 * manager, the client - a fork, its own /dev/binder open, its own arena -
 * sends it a oneway transaction. The delivery is what is on test: the client
 * acquires a handle and queues work on the owner, and the owner reads the
 * payload back out of its own arena. Each process's binder state is its own;
 * the inherited descriptors are closed rather than shared. */
static void stage_twoproc(void)
{
  struct binder_transaction_data tr, *got;
  unsigned char payload[16] = "two-proc";
  unsigned char wbuf[128], rbuf[512];
  struct binder_msl_arena a;
  unsigned long arena, consumed;
  unsigned int cmd;
  int ready[2], go[2], woff, fd, spin, i;
  int zero = 0;
  long child, status, r;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder (twoproc)", fd);
  r = bioctl(fd, BINDER_SET_CONTEXT_MGR, &zero);
  if (r != 0)
    fail("become the context manager (twoproc)", r);

  arena = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)arena >= -4096 && (long)arena < 0)
    fail("mmap the arena (twoproc)", (long)arena);
  a.addr = arena;
  a.size = ARENA_SIZE;
  r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
  if (r != 0)
    fail("register the arena (twoproc)", r);

  woff = 0;
  cmd = BC_ACQUIRE;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned int *)(wbuf + woff) = zero; woff += 4;
  cmd = BC_ENTER_LOOPER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_ACQUIRE on handle 0 (twoproc)", 0);

  if (sys6(SYS_pipe2, (long)ready, 0, 0,0,0,0) != 0)
    fail("pipe(ready) (twoproc)", 0);
  if (sys6(SYS_pipe2, (long)go, 0, 0,0,0,0) != 0)
    fail("pipe(go) (twoproc)", 0);

  child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);   /* fork */
  if (child < 0)
    fail("fork (twoproc)", child);

  if (child == 0) {
    /* The client. The binder fd that came over the fork is the owner's
     * process, not ours, and the pipe ends the owner holds would keep it
     * from seeing our half-close. */
    char c;

    sys6(SYS_close, fd, 0,0,0,0,0);
    sys6(SYS_close, ready[0], 0,0,0,0,0);
    sys6(SYS_close, go[1], 0,0,0,0,0);

    fd = open_binder("/dev/binder");
    if (fd < 0)
      sys6(SYS_exit_group, 2, 0,0,0,0,0);

    a.addr = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)a.addr >= -4096 && (long)a.addr < 0)
      sys6(SYS_exit_group, 3, 0,0,0,0,0);
    a.size = ARENA_SIZE;
    r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
    if (r != 0)
      sys6(SYS_exit_group, 3, 0,0,0,0,0);

    woff = 0;
    cmd = BC_ACQUIRE;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    *(unsigned int *)(wbuf + woff) = zero; woff += 4;
    cmd = BC_ENTER_LOOPER;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);

    /* Set up and ready; the owner releases us when it is reading. */
    if (sys6(SYS_write, ready[1], (long)"g", 1, 0,0,0) != 1)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);
    if (sys6(SYS_read, go[0], (long)&c, 1, 0,0,0) != 1)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);

    for (i = 0; i < (int)sizeof(tr); i++)
      ((unsigned char *)&tr)[i] = 0;
    tr.target.handle = 0;
    tr.code = 44;
    tr.flags = TF_ONE_WAY;
    tr.data_size = sizeof(payload);
    tr.data.ptr.buffer = (unsigned long)payload;
    tr.data.ptr.offsets = 0;

    woff = 0;
    cmd = BC_TRANSACTION;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    for (i = 0; i < (int)sizeof(tr); i++)
      wbuf[woff + i] = ((unsigned char *)&tr)[i];
    woff += (int)sizeof(tr);
    if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 5, 0,0,0,0,0);

    sys6(SYS_close, fd, 0,0,0,0,0);
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }

  /* The owner: wait for the client's setup, then release it. */
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  sys6(SYS_close, go[0], 0,0,0,0,0);
  {
    char c;

    if (sys6(SYS_read, ready[0], (long)&c, 1, 0,0,0) != 1)
      fail("the client never became ready", 0);
    if (sys6(SYS_write, go[1], (long)"g", 1, 0,0,0) != 1)
      fail("releasing the client", 0);
  }

  /* The transaction arrives in the owner's arena; read it as stage_oneway
   * does. The first read may only deliver BR_TRANSACTION_COMPLETE. */
  got = 0;
  for (spin = 0; spin < 10 && got == 0; spin++) {
    consumed = 0;
    if (binder_wr(fd, 0, 0, rbuf, sizeof(rbuf), &consumed) != 0)
      break;
    i = 0;
    while (i + 4 <= (int)consumed) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_TRANSACTION) {
        got = (struct binder_transaction_data *)(rbuf + i);
        i += sizeof(tr);
        break;
      }
    }
  }
  if (got == 0)
    fail("BR_TRANSACTION from the client", 0);
  if (got->code != 44)
    fail("the twoproc transaction code survived", got->code);
  if (got->data.ptr.buffer < arena ||
      got->data.ptr.buffer >= arena + ARENA_SIZE)
    fail("the payload landed outside the owner's arena",
         (long)got->data.ptr.buffer);
  for (i = 0; i < (int)sizeof(payload); i++) {
    if (((unsigned char *)got->data.ptr.buffer)[i] != payload[i])
      fail("the twoproc payload bytes survived", 0);
  }

  woff = 0;
  cmd = BC_FREE_BUFFER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned long *)(wbuf + woff) = got->data.ptr.buffer; woff += 8;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_FREE_BUFFER accepted (twoproc)", 0);

  status = 0;
  if (sys6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) < 0)
    fail("wait4 the client", 0);
  if (((status >> 8) & 0xff) != 0)
    fail("the client exited nonzero", status);

  sys6(SYS_close, fd, 0,0,0,0,0);
}

/* A descriptor across the boundary: the client puts a BINDER_TYPE_FD object -
 * its own /dev/binder open - in the transaction, and the manager, which
 * registered as the manager with FLAT_BINDER_FLAG_ACCEPTS_FDS, receives the
 * object with the driver's stamp (the sender's pid in the cookie) and NABI's
 * substitution (the descriptor, arrived over SCM_RIGHTS, in the fd). The
 * manager proves the descriptor is a real one by asking the received fd for
 * its version. */
static void stage_fd(void)
{
  struct binder_transaction_data tr, *got;
  struct binder_msl_arena a;
  struct flat_binder_object obj;
  unsigned char payload[64];
  unsigned char wbuf[128], rbuf[512];
  unsigned long arena, consumed, offsets[1];
  unsigned int cmd;
  int ready[2], go[2], woff, fd, spin, i;
  int zero = 0;
  long child, status, r;

  fd = open_binder("/dev/binder");
  if (fd < 0)
    fail("open /dev/binder (fd)", fd);

  /* The manager must say it accepts descriptors, or the driver refuses the
   * object (EPERM) at the transaction boundary. SET_CONTEXT_MGR_EXT is how
   * the object's flags reach the node. */
  mzero(&obj, sizeof obj);
  obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
  r = bioctl(fd, BINDER_SET_CONTEXT_MGR_EXT, &obj);
  if (r != 0)
    fail("become the context manager with ACCEPTS_FDS", r);

  arena = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if ((long)arena >= -4096 && (long)arena < 0)
    fail("mmap the arena (fd)", (long)arena);
  a.addr = arena;
  a.size = ARENA_SIZE;
  r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
  if (r != 0)
    fail("register the arena (fd)", r);

  woff = 0;
  cmd = BC_ACQUIRE;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned int *)(wbuf + woff) = zero; woff += 4;
  cmd = BC_ENTER_LOOPER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_ACQUIRE on handle 0 (fd)", 0);

  if (sys6(SYS_pipe2, (long)ready, 0, 0,0,0,0) != 0)
    fail("pipe(ready) (fd)", 0);
  if (sys6(SYS_pipe2, (long)go, 0, 0,0,0,0) != 0)
    fail("pipe(go) (fd)", 0);

  child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);   /* fork */
  if (child < 0)
    fail("fork (fd)", child);

  if (child == 0) {
    char c;

    sys6(SYS_close, fd, 0,0,0,0,0);
    sys6(SYS_close, ready[0], 0,0,0,0,0);
    sys6(SYS_close, go[1], 0,0,0,0,0);

    fd = open_binder("/dev/binder");
    if (fd < 0)
      sys6(SYS_exit_group, 2, 0,0,0,0,0);

    a.addr = (unsigned long)sys6(SYS_mmap, 0, ARENA_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)a.addr >= -4096 && (long)a.addr < 0)
      sys6(SYS_exit_group, 3, 0,0,0,0,0);
    a.size = ARENA_SIZE;
    r = bioctl(fd, BINDER_MSL_SET_ARENA, &a);
    if (r != 0)
      sys6(SYS_exit_group, 3, 0,0,0,0,0);

    woff = 0;
    cmd = BC_ACQUIRE;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    *(unsigned int *)(wbuf + woff) = zero; woff += 4;
    cmd = BC_ENTER_LOOPER;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);

    /* The parcel: the string, then the object at offset 16. The fd field
     * names the client's own /dev/binder open. */
    for (i = 0; i < (int)sizeof(payload); i++)
      payload[i] = 0;
    mcopy(payload, "fd-probe", 8);
    obj.type = BINDER_TYPE_FD;
    obj.flags = 0;
    obj.fd = (unsigned int)fd;
    obj.cookie = 0;
    mcopy(payload + 16, &obj, sizeof obj);
    offsets[0] = 16;

    if (sys6(SYS_write, ready[1], (long)"g", 1, 0,0,0) != 1)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);
    if (sys6(SYS_read, go[0], (long)&c, 1, 0,0,0) != 1)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);

    for (i = 0; i < (int)sizeof(tr); i++)
      ((unsigned char *)&tr)[i] = 0;
    tr.target.handle = 0;
    tr.code = 45;
    tr.flags = TF_ONE_WAY;
    tr.data_size = 16 + sizeof(obj);
    tr.offsets_size = sizeof(offsets);
    tr.data.ptr.buffer = (unsigned long)payload;
    tr.data.ptr.offsets = (unsigned long)offsets;

    woff = 0;
    cmd = BC_TRANSACTION;
    *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
    for (i = 0; i < (int)sizeof(tr); i++)
      wbuf[woff + i] = ((unsigned char *)&tr)[i];
    woff += (int)sizeof(tr);
    if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 5, 0,0,0,0,0);

    sys6(SYS_close, fd, 0,0,0,0,0);
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }

  sys6(SYS_close, ready[1], 0,0,0,0,0);
  sys6(SYS_close, go[0], 0,0,0,0,0);
  {
    char c;

    if (sys6(SYS_read, ready[0], (long)&c, 1, 0,0,0) != 1)
      fail("the client never became ready (fd)", 0);
    if (sys6(SYS_write, go[1], (long)"g", 1, 0,0,0) != 1)
      fail("releasing the client (fd)", 0);
  }

  got = 0;
  for (spin = 0; spin < 10 && got == 0; spin++) {
    consumed = 0;
    if (binder_wr(fd, 0, 0, rbuf, sizeof(rbuf), &consumed) != 0)
      break;
    i = 0;
    while (i + 4 <= (int)consumed) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_TRANSACTION) {
        got = (struct binder_transaction_data *)(rbuf + i);
        i += sizeof(tr);
        break;
      }
    }
  }
  if (got == 0)
    fail("BR_TRANSACTION with the descriptor (fd)", 0);
  if (got->code != 45)
    fail("the fd transaction code survived", got->code);
  if (got->data.ptr.buffer < arena ||
      got->data.ptr.buffer >= arena + ARENA_SIZE)
    fail("the fd payload landed outside the owner's arena",
         (long)got->data.ptr.buffer);

  mcopy(&obj, (void *)got->data.ptr.buffer + 16, sizeof obj);
  if (obj.type != BINDER_TYPE_FD)
    fail("the object stayed a BINDER_TYPE_FD", obj.type);
  if (obj.cookie != (unsigned long)child)
    fail("the cookie carries the sender's pid", (long)obj.cookie);

  /* The fd NABI substituted must be a real, usable descriptor: asking the
   * client's open for its version answers protocol 8, exactly as stage_version
   * checked on our own open. */
  {
    struct binder_version ver;

    if (bioctl((int)obj.fd, BINDER_VERSION, &ver) != 0)
      fail("the received descriptor answers ioctl", (long)obj.fd);
    if (ver.protocol_version != 8)
      fail("the received descriptor is the client's binder", ver.protocol_version);
  }

  woff = 0;
  cmd = BC_FREE_BUFFER;
  *(unsigned int *)(wbuf + woff) = cmd; woff += 4;
  *(unsigned long *)(wbuf + woff) = got->data.ptr.buffer; woff += 8;
  if (binder_wr(fd, wbuf, woff, 0, 0, 0) != 0)
    fail("BC_FREE_BUFFER accepted (fd)", 0);

  status = 0;
  if (sys6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) < 0)
    fail("wait4 the client (fd)", 0);
  if (((status >> 8) & 0xff) != 0)
    fail("the client exited nonzero (fd)", status);

  sys6(SYS_close, fd, 0,0,0,0,0);
}

void _start(void)
{
  int fd;

  fd = open_binder("/dev/binder");
  if (fd >= 0) {
    sys6(SYS_close, fd, 0,0,0,0,0);
    stage_version();
    stage_arena();
    stage_manager();
    stage_oneway();
    stage_epoll();
    stage_twoproc();
    stage_fd();
    put("binderprobe ok\n");
  }
  sys6(SYS_exit_group, fd < 0 ? 77 : 0, 0,0,0,0,0);
}
