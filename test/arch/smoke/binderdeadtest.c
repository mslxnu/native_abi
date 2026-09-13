/* freestanding: a transaction to an endpoint whose owner has gone is answered,
 * not swallowed.
 *
 * A process that dies without closing its binder descriptor - killed, rather
 * than exiting - leaves its endpoint behind: the shared slot still says it is
 * there, and the wake fifo still has its name, but nobody holds it open any
 * more. A sender then resolves the handle, puts a transaction in the queue, and
 * pokes a fifo that answers ENXIO.
 *
 * nabi threw that error away. The message stayed in the dead endpoint's queue
 * for ever, because collect_messages only ever runs from a read on that same
 * endpoint and there was nobody left to read it, and the sender waited for a
 * reply that could not come. Neither process was at fault and nothing was
 * logged: an Android boot stopping at whichever service asked a dead one for
 * something.
 *
 * Linux answers this with BR_DEAD_REPLY, which libbinder turns into
 * DEAD_OBJECT, and so does nabi now.
 *
 * The owner has to be *killed* for this to be the path under test. Exiting
 * normally closes the descriptor, which drops the last reference, frees the
 * slot and unlinks the fifo - and then the handle does not resolve at all,
 * which is a different answer arrived at a different way. The caller also opens
 * its own endpoint before the kill, because opening one afterwards reaps dead
 * slots on the way past and would take the corpse with it.
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
#define SYS_nanosleep 101
#define SYS_kill 129
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define O_NONBLOCK 04000
#define PROT_READ 1
#define MAP_PRIVATE 0x02
#define SIGCHLD 17
#define SIGKILL 9
#define ARENA_SIZE 0x20000

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define BR_REPLY               0x80407203u
#define BR_DEAD_REPLY          0x00007205u

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

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void mzero(void*p,int n){unsigned char*q=p;while(n--)*q++=0;}
static void naptime(long ms){ struct { long s, ns; } t = { ms/1000, (ms%1000)*1000000 };
  sys6(SYS_nanosleep, (long)&t, 0, 0,0,0,0); }
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
/* BR_DEAD_REPLY carries nothing, so only the two that do have to be stepped
 * over to keep the walk aligned. */
static int saw(const unsigned char *rbuf, unsigned long consumed, unsigned int cmd)
{
  for (unsigned long i = 0; i + 4 <= consumed; ) {
    unsigned int c = *(unsigned int *)(rbuf + i);
    i += 4;
    if (c == cmd) return 1;
    if (c == BR_TRANSACTION || c == BR_REPLY) i += sizeof(struct btd);
  }
  return 0;
}

/* Becomes the context manager and then stays put, so that it is still holding
 * the endpoint when it is killed. */
static void manager(int ready_w)
{
  unsigned char wbuf[64];
  int zero = 0;

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder", O_RDWR|O_CLOEXEC, 0,0,0);
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);
  *(unsigned int *)wbuf = BC_ENTER_LOOPER;
  if (bwr(fd, wbuf, 4, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);

  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);

  for (;;) naptime(1000);        /* killed from outside, never exits */
}

void _start(void)
{
  unsigned char wbuf[256], rbuf[1024];
  unsigned long consumed = 0;
  int ready[2];

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);

  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); manager(ready[1]); }
  want("fork the manager", kid > 0, 1);
  if (kid <= 0) { put("binderdead failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  char b; sys6(SYS_read, ready[0], (long)&b, 1, 0,0,0);

  /*
   * Opened before the kill on purpose: an open reaps the slots of processes
   * that have gone, and this one must still find the endpoint afterwards.
   */
  int cfd = (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder",
                       O_RDWR|O_CLOEXEC|O_NONBLOCK, 0,0,0);
  want("open /dev/binder", cfd >= 0, 1);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, cfd, 0);
  want("mmap the arena", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);

  /* Killed, not asked to leave: the descriptor is never closed, so the slot
   * and the fifo outlive the process that owned them. */
  want("kill the manager", sys6(SYS_kill, kid, SIGKILL, 0,0,0,0), 0);
  long status = 0;
  for (int i = 0; i < 100; i++) {
    if (sys6(SYS_wait4, kid, (long)&status, 1 /* WNOHANG */, 0, 0, 0) == kid)
      break;
    naptime(20);
  }
  naptime(100);                  /* let the kernel close what it holds */

  struct btd tr;
  mzero(&tr, sizeof tr);
  tr.target = 0;                 /* the context manager, which is now a corpse */
  tr.code = 1;
  static const char ask[] = "ask";
  tr.data_size = sizeof ask;
  tr.buffer = (unsigned long) ask;
  int woff = 0;
  *(unsigned int *)(wbuf + woff) = BC_TRANSACTION; woff += 4;
  for (unsigned long j = 0; j < sizeof tr; j++)
    wbuf[woff + j] = ((unsigned char *)&tr)[j];
  woff += (int) sizeof tr;

  /* Write and read in one ioctl, the way libbinder does. The answer is there
   * the moment the send gives up on the target, so this must not have to wait
   * for it - and before the fix there was no answer at all. */
  long rc = bwr(cfd, wbuf, woff, rbuf, sizeof rbuf, &consumed);
  want("the send was accepted", rc, 0);
  want("the sender was told the target is dead", saw(rbuf, consumed, BR_DEAD_REPLY), 1);

  sys6(SYS_close, cfd, 0,0,0,0,0);
  put(fails == 0 ? "binderdead ok\n" : "binderdead failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
