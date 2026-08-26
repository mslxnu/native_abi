/* freestanding: an object passed by reference, and called through it.
 *
 * Until this, the emulated driver knew exactly one handle: zero, the context
 * manager. That is enough to reach servicemanager and nothing else, and Android
 * is built the other way round - a service registers itself *with* the manager,
 * the manager hands it out to whoever asks, and every call after that goes to a
 * handle the driver invented. With no such handles, a client could look a
 * service up, be given a reference, and then transact into nothing: `vdc
 * checkpoint markBootAttempt` found vold, called it, and waited until init gave
 * up on post-fs. post-fs-data never ran and the zygote had no /data.
 *
 * Three things have to be true, and each fails differently:
 *
 *   - an object the sender owns arrives as a *handle*. A pointer means nothing
 *     in another address space, so a parcel that carried one unchanged would
 *     have the receiver dereference the sender's memory.
 *   - transacting to that handle reaches the process that owns the object.
 *     This is the whole point and the part that did not exist.
 *   - the same handle sent back to its owner arrives as the owner's own
 *     pointer again. A process has to recognise its own object when it comes
 *     home, or every reference it ever handed out returns as a stranger.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_mmap 222
#define SYS_pipe2 59
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define PROT_READ 1
#define MAP_PRIVATE 0x02
#define O_NONBLOCK 04000
#define SYS_nanosleep 101
#define SIGCHLD 17
#define ARENA_SIZE 0x20000

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_REPLY               0x40406301u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define BR_REPLY               0x80407203u

#define TYPE_BINDER 0x73622a85u
#define TYPE_HANDLE 0x73682a85u

/* What the owner calls its object. Arbitrary, and checked on the way back. */
#define OBJ_PTR    0x00000000cafe1000ull
#define OBJ_COOKIE 0x000000005ec0ffeeull
#define CODE_GET   1               /* "give me a reference to your object" */
#define CODE_CALL  2               /* sent to that reference */
#define CODE_HOME  3               /* the reference, sent back to its owner */

struct binder_write_read {
  unsigned long write_size, write_consumed, write_buffer;
  unsigned long read_size, read_consumed, read_buffer;
};
struct btd {
  unsigned long target, cookie;
  unsigned int code, flags;
  int sender_pid; unsigned int sender_euid;
  unsigned long data_size, offsets_size;
  unsigned long buffer, offsets;
};
struct flat { unsigned int type, flags; unsigned long binder, cookie; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void puth(unsigned long v){char b[19];int i=18;b[i--]=0;
  if(v==0)b[i--]='0';while(v>0){unsigned d=v&15;b[i--]=d<10?'0'+d:'a'+d-10;v>>=4;}
  put("0x");put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void mzero(void*p,int n){unsigned char*q=p;while(n--)*q++=0;}
static void mcopy(void*d,const void*s,int n){unsigned char*a=d;const unsigned char*b=s;while(n--)*a++=*b++;}

/*
 * Non-blocking, both sides.
 *
 * A binder read waits when there is nothing to read, which is right for a
 * service and wrong for a test: the failure this exists to catch is a
 * transaction that never arrives, and a blocking read turns that into a hang
 * instead of a message. A hang says nothing, cannot be told from slowness, and
 * takes the whole suite's timeout with it - so every read here is one that
 * comes back empty, and the spin around it is what bounds the wait.
 */
static int open_binder(void)
{
  return (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder",
                    O_RDWR|O_CLOEXEC|O_NONBLOCK, 0,0,0);
}
static long bwr(int fd, void *wb, unsigned long wn, void *rb, unsigned long rn,
                unsigned long *consumed)
{
  struct binder_write_read w;
  mzero(&w, sizeof w);
  w.write_size = wn; w.write_buffer = (unsigned long) wb;
  w.read_size = rn;  w.read_buffer = (unsigned long) rb;
  long r = sys6(SYS_ioctl, fd, BINDER_WRITE_READ, (long)&w, 0, 0, 0);
  if (consumed) *consumed = w.read_consumed;
  return r;
}
/* One BC_TRANSACTION or BC_REPLY, built into wbuf and sent. */
static long send_cmd(int fd, unsigned int cmd, unsigned long target,
                     unsigned int code, void *data, unsigned long dsize,
                     unsigned long *offs, unsigned long osize)
{
  unsigned char wbuf[256];
  struct btd tr;
  mzero(&tr, sizeof tr);
  tr.target = target;
  tr.code = code;
  tr.data_size = dsize;
  tr.buffer = (unsigned long) data;
  tr.offsets_size = osize;
  tr.offsets = (unsigned long) offs;
  *(unsigned int *)wbuf = cmd;
  mcopy(wbuf + 4, &tr, (int) sizeof tr);
  return bwr(fd, wbuf, 4 + sizeof tr, 0, 0, 0);
}
/*
 * Read until the command arrives, or give up.
 *
 * With non-blocking reads the spin must have a wait in it. Without one the two
 * hundred tries are two hundred instructions, all of them finishing before the
 * other process has even been scheduled, so the test failed for one run in
 * three - and failed with "no reply came back", which points at the driver
 * rather than at the test that did not wait for it.
 */
static struct btd *
await(int fd, unsigned char *rbuf, unsigned long rn, unsigned int wanted)
{
  unsigned long consumed;
  for (int spin = 0; spin < 200; spin++) {
    consumed = 0;
    long r = bwr(fd, 0, 0, rbuf, rn, &consumed);
    if (r != 0 && r != -11 /* EAGAIN: nothing yet */)
      return 0;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == wanted) return (struct btd *)(rbuf + i);
      if (c == BR_TRANSACTION || c == BR_REPLY) i += sizeof(struct btd);
    }
    struct { long sec, nsec; } ts = { 0, 1000000 };   /* a millisecond */
    sys6(SYS_nanosleep, (long) &ts, 0, 0, 0, 0, 0);
  }
  return 0;
}

/*
 * The owner. It is also the context manager, so the client has something to
 * reach it by before it has any handle at all - which is exactly how a real
 * service is bootstrapped.
 */
static void owner(int ready_w)
{
  unsigned char rbuf[512];
  int zero = 0;

  int fd = open_binder();
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);
  unsigned int enter = BC_ENTER_LOOPER;
  if (bwr(fd, &enter, 4, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);
  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);

  /* 1: hand out a reference to an object of its own. */
  if (await(fd, rbuf, sizeof rbuf, BR_TRANSACTION) == 0)
    sys6(SYS_exit_group, 15, 0,0,0,0,0);
  struct flat obj;
  mzero(&obj, sizeof obj);
  obj.type = TYPE_BINDER;
  obj.binder = OBJ_PTR;
  obj.cookie = OBJ_COOKIE;
  unsigned long off0 = 0;
  if (send_cmd(fd, BC_REPLY, 0, CODE_GET, &obj, sizeof obj, &off0, 8) != 0)
    sys6(SYS_exit_group, 16, 0,0,0,0,0);

  /* 2: the call that arrives through that reference rather than through 0. */
  struct btd *t = await(fd, rbuf, sizeof rbuf, BR_TRANSACTION);
  if (t == 0) sys6(SYS_exit_group, 17, 0,0,0,0,0);
  if (t->code != CODE_CALL) sys6(SYS_exit_group, 18, 0,0,0,0,0);
  if (send_cmd(fd, BC_REPLY, 0, CODE_CALL, 0, 0, 0, 0) != 0)
    sys6(SYS_exit_group, 19, 0,0,0,0,0);

  /* 3: its own reference, sent home. It must be a pointer again. */
  t = await(fd, rbuf, sizeof rbuf, BR_TRANSACTION);
  if (t == 0) sys6(SYS_exit_group, 20, 0,0,0,0,0);
  if (t->code != CODE_HOME) sys6(SYS_exit_group, 21, 0,0,0,0,0);
  if (t->data_size < sizeof(struct flat)) sys6(SYS_exit_group, 22, 0,0,0,0,0);
  struct flat *back = (struct flat *)(void *) t->buffer;
  int rc = 0;
  if (back->type != TYPE_BINDER)   rc = 23;
  else if (back->binder != OBJ_PTR) rc = 24;
  else if (back->cookie != OBJ_COOKIE) rc = 25;
  send_cmd(fd, BC_REPLY, 0, CODE_HOME, 0, 0, 0, 0);
  sys6(SYS_exit_group, rc, 0,0,0,0,0);
}

void _start(void);

void _start(void)
{
  unsigned char rbuf[512];
  int ready[2];

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); owner(ready[1]); }
  want("fork the owner", kid > 0, 1);
  if (kid <= 0) { put("binderhandle failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  char b;
  sys6(SYS_read, ready[0], (long) &b, 1, 0,0,0);

  int fd = open_binder();
  want("open /dev/binder", fd >= 0, 1);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  want("mmap the arena", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);

  /* Ask the manager for a reference to its object. */
  want("ask for the object", send_cmd(fd, BC_TRANSACTION, 0, CODE_GET, 0, 0, 0, 0), 0);
  struct btd *rep = await(fd, rbuf, sizeof rbuf, BR_REPLY);
  want("a reply comes back", rep != 0 ? 1 : 0, 1);

  unsigned int handle = 0;
  if (rep != 0 && rep->data_size >= sizeof(struct flat)) {
    struct flat *got = (struct flat *)(void *) rep->buffer;
    /*
     * A handle, not the owner's pointer. Getting this wrong is not a failed
     * call - it is the receiver being handed an address in somebody else's
     * address space, and told it is an object.
     */
    if (got->type != TYPE_HANDLE) {
      fails++;
      put("  FAIL the object arrived as type "); puth(got->type);
      put(", not a handle");
      if (got->type == TYPE_BINDER) put(" - it is the owner's own pointer");
      put("\n");
    }
    want("the handle is not zero", got->binder != 0 ? 1 : 0, 1);
    want("and is not the owner's pointer", got->binder != OBJ_PTR ? 1 : 0, 1);
    handle = (unsigned int) got->binder;
  } else {
    fails++;
    put("  FAIL the reply carried no object\n");
  }

  if (handle != 0) {
    /* The call that only works if the handle names its owner. Waiting for an
     * answer is only meaningful if the call was accepted - a refused send has
     * no answer coming, and asking for one would hang rather than fail. */
    long sent = send_cmd(fd, BC_TRANSACTION, handle, CODE_CALL, 0, 0, 0, 0);
    want("call through the handle", sent, 0);
    if (sent == 0)
      want("the owner answers it", await(fd, rbuf, sizeof rbuf, BR_REPLY) != 0 ? 1 : 0, 1);

    /* And the same reference, handed back to the process that owns it. */
    struct flat give;
    mzero(&give, sizeof give);
    give.type = TYPE_HANDLE;
    give.binder = handle;
    unsigned long off0 = 0;
    sent = send_cmd(fd, BC_TRANSACTION, handle, CODE_HOME, &give, sizeof give, &off0, 8);
    want("send the reference home", sent, 0);
    if (sent == 0)
      want("which is answered", await(fd, rbuf, sizeof rbuf, BR_REPLY) != 0 ? 1 : 0, 1);
  }

  int status = 0;
  sys6(SYS_wait4, kid, (long) &status, 0, 0, 0, 0);
  int code = (status >> 8) & 0xff;
  /* 23..25 are the owner's own checks on what came home; see owner(). */
  want("the owner is content", code, 0);

  put(fails == 0 ? "binderhandle ok\n" : "binderhandle failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
