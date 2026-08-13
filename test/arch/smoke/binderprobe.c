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
 * The sync/poll/twoproc stages are left out because they need threads or a
 * fork, which binder-probe already covers on the host; the oneway stage
 * proves the ioctl numbers, the argument, and the arena all survive the
 * NABI layer, which is the thing being tested here.
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
#define AT_FDCWD -100
#define O_RDWR 2
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

/* Linux's own ioctl encodings; NABI rewrites the direction bits. */
#define BINDER_WRITE_READ          0xC0306201u
#define BINDER_SET_CONTEXT_MGR     0x40046207u
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

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("binderprobe FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit_group, 1, 0,0,0,0,0);
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
    put("binderprobe ok\n");
  }
  sys6(SYS_exit_group, fd < 0 ? 77 : 0, 0,0,0,0,0);
}
