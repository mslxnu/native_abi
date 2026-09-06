/* freestanding: a reply goes to the thread that made the call, and to no other.
 *
 * Linux queues a reply on the todo list of the thread that made the call, and
 * frees it if that thread exits. No other thread is ever offered it.
 *
 * nabi offered it to another thread eventually - first after a count of how
 * many other threads had declined it, then after a deadline - on the reasoning
 * that a reply owed to a thread which never comes back should not sit in the
 * queue for ever. Both are wrong in the same way. libbinder handles BR_REPLY
 * only in waitForResponse, so a thread from the pool that receives one reaches
 * executeCommand, which has no case for it and answers UNKNOWN_ERROR; the reply
 * is then gone and the thread that made the call waits for it for ever. The
 * fallback only chose how long the boot took to wedge, and a process with a
 * busy thread pool runs through sixty-four polls in the time the owed thread
 * spends between two of its own.
 *
 * So: one thread calls, another polls hard while the reply is sitting there,
 * and has to come away with nothing every time.
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
#define SYS_exit 93
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define O_NONBLOCK 04000
#define PROT_READ 1
#define MAP_PRIVATE 0x02
#define SIGCHLD 17
#define ARENA_SIZE 0x20000
#define THREAD_FLAGS (0x100|0x200|0x400|0x800|0x10000|0x40000)

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_REPLY               0x40406301u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define BR_REPLY               0x80407203u

/* Comfortably more than any count the fallback ever used, and long enough in
 * wall time to outlast a deadline. */
#define OTHER_POLLS 300

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

static const char answer[] = "answered";

/* Answers one call, then goes away. */
static void manager(int ready_w)
{
  unsigned char wbuf[256], rbuf[1024];
  unsigned long consumed;
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

  for (int spin = 0; spin < 20; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    if (!saw(rbuf, consumed, BR_TRANSACTION))
      continue;
    struct btd tr;
    mzero(&tr, sizeof tr);
    tr.code = 0x5a;
    tr.data_size = sizeof answer;
    tr.buffer = (unsigned long) answer;
    int woff = 0;
    *(unsigned int *)(wbuf + woff) = BC_REPLY; woff += 4;
    for (unsigned long j = 0; j < sizeof tr; j++)
      wbuf[woff + j] = ((unsigned char *)&tr)[j];
    woff += (int) sizeof tr;
    bwr(fd, wbuf, woff, 0, 0, 0);
    break;
  }
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}

static int cfd = -1;
static int go[2], back[2];
static volatile int other_saw_reply = 0;

static void wake(int fd){ sys6(SYS_write, fd, (long) "x", 1, 0,0,0); }
static void await(int fd){ char c; sys6(SYS_read, fd, (long) &c, 1, 0,0,0); }
/*
 * The child of a clone carries on inside _start, whose prologue ran in the
 * parent - so its frame locals are addressed above the stack pointer the child
 * was given. Handing over the very top of the mapping puts those writes past
 * the end of it; the room below the top is for the frame this thread never
 * allocated.
 */
static long new_stack(void){ long s = sys6(SYS_mmap, 0, 1<<16, 3, 0x22, -1, 0);
  return s < 0 ? 0 : s + (1<<16) - 4096; }

/* The thread the reply is not for. */
__attribute__((noinline)) static void other_thread(void)
{
  unsigned char rbuf[1024];
  unsigned long consumed;

  await(go[0]);
  for (int i = 0; i < OTHER_POLLS; i++) {
    consumed = 0;
    if (bwr(cfd, 0, 0, rbuf, sizeof rbuf, &consumed) == 0 &&
        saw(rbuf, consumed, BR_REPLY)) {
      other_saw_reply = 1;
      break;
    }
    naptime(10);
  }
  wake(back[1]);
  sys6(SYS_exit, 0, 0,0,0,0,0);
}

void _start(void)
{
  unsigned char wbuf[256], rbuf[1024];
  unsigned long consumed;
  int ready[2];

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  want("pipe2 go", sys6(SYS_pipe2, (long) go, 0, 0,0,0,0), 0);
  want("pipe2 back", sys6(SYS_pipe2, (long) back, 0, 0,0,0,0), 0);

  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); manager(ready[1]); }
  want("fork the manager", kid > 0, 1);
  if (kid <= 0) { put("binderownreply failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  char b; sys6(SYS_read, ready[0], (long)&b, 1, 0,0,0);

  /* Non-blocking, because most of the polls below are meant to find nothing. */
  cfd = (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder",
                   O_RDWR|O_CLOEXEC|O_NONBLOCK, 0,0,0);
  want("open /dev/binder", cfd >= 0, 1);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, cfd, 0);
  want("mmap the arena", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);

  long sp = new_stack();
  long tid = sys6(SYS_clone, THREAD_FLAGS, sp, 0, 0, 0, 0);
  if (tid == 0) other_thread();
  want("the other thread started", tid > 0, 1);

  /* The call is made here, so the reply is owed here. */
  struct btd tr;
  mzero(&tr, sizeof tr);
  tr.target = 0;
  tr.code = 1;
  tr.data_size = 4;
  static const char ask[] = "ask";
  tr.buffer = (unsigned long) ask;
  int woff = 0;
  *(unsigned int *)(wbuf + woff) = BC_TRANSACTION; woff += 4;
  for (unsigned long j = 0; j < sizeof tr; j++)
    wbuf[woff + j] = ((unsigned char *)&tr)[j];
  woff += (int) sizeof tr;
  want("the call was sent", bwr(cfd, wbuf, woff, 0, 0, 0), 0);

  /* And the other thread looks for it, hard, while it is sitting there. */
  wake(go[1]);
  await(back[0]);
  want("no other thread was given the reply", other_saw_reply, 0);

  /* It is still here, for the thread it belongs to. */
  int mine = 0;
  for (int i = 0; i < 300 && !mine; i++) {
    consumed = 0;
    if (bwr(cfd, 0, 0, rbuf, sizeof rbuf, &consumed) == 0 &&
        saw(rbuf, consumed, BR_REPLY))
      mine = 1;
    else
      naptime(10);
  }
  want("and the thread that called got it", mine, 1);

  long status = 0, done = 0;
  for (int i = 0; i < 100 && done != kid; i++) {
    done = sys6(SYS_wait4, kid, (long)&status, 1 /* WNOHANG */, 0, 0, 0);
    if (done != kid) naptime(20);
  }
  if (done != kid) sys6(SYS_kill, kid, 9, 0,0,0,0);
  sys6(SYS_close, cfd, 0,0,0,0,0);
  put(fails == 0 ? "binderownreply ok\n" : "binderownreply failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
