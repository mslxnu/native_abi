/* freestanding: a binder reply that crosses a process boundary.
 *
 * BC_REPLY names no target. On Linux the driver knows which transaction the
 * replying thread is inside and sends the answer back to whoever made that
 * call. nabi had no record of it, so a reply could only be delivered to the
 * endpoint that sent it - which is to say a process could only answer itself,
 * and every real call hung.
 *
 * Android's boot is made of these. vdc asks vold to mark a boot attempt and
 * waits for the answer; the answer went nowhere, and init waited on the pair
 * of them until it declared the service hung and stopped starting anything
 * else.
 *
 * What is checked:
 *
 *   - a synchronous transaction to the context manager in another process
 *     comes back as BR_REPLY, not silence.
 *   - the reply carries the manager's data, in the caller's own arena.
 *   - and the code the manager replied with, so the answer is that call's
 *     answer and not some other message that happened to arrive.
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
#define SIGCHLD 17
#define ARENA_SIZE 0x20000

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_REPLY               0x40406301u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define BR_REPLY               0x80407203u

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

static int open_binder(void)
{
  return (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder", O_RDWR|O_CLOEXEC, 0,0,0);
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
#define REPLY_CODE 0x5a
static const char answer[] = "answered";

/* The manager: waits for one call and answers it. */
static void manager(int ready_w)
{
  unsigned char wbuf[256], rbuf[512];
  unsigned long consumed, p;
  int zero = 0, woff = 0;

  int fd = open_binder();
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);
  *(unsigned int *)wbuf = BC_ENTER_LOOPER;
  if (bwr(fd, wbuf, 4, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);

  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);

  int got = 0;
  for (int spin = 0; spin < 3 && !got; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_TRANSACTION) { got = 1; break; }
    }
  }
  if (!got) sys6(SYS_exit_group, 15, 0,0,0,0,0);

  /* The answer. BC_REPLY names nobody: the driver has to know. */
  struct btd tr;
  mzero(&tr, sizeof tr);
  tr.code = REPLY_CODE;
  tr.data_size = sizeof answer;
  tr.buffer = (unsigned long) answer;
  woff = 0;
  *(unsigned int *)(wbuf + woff) = BC_REPLY; woff += 4;
  for (unsigned long i = 0; i < sizeof tr; i++)
    wbuf[woff + i] = ((unsigned char *)&tr)[i];
  woff += (int) sizeof tr;
  if (bwr(fd, wbuf, woff, 0, 0, 0) != 0) sys6(SYS_exit_group, 16, 0,0,0,0,0);
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}

void _start(void)
{
  unsigned char wbuf[256], rbuf[512];
  unsigned long consumed;
  int ready[2];

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); manager(ready[1]); }
  want("fork the manager", kid > 0, 1);
  if (kid <= 0) { put("binderreply failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);

  char b;
  sys6(SYS_read, ready[0], (long) &b, 1, 0,0,0);   /* it is the manager now */

  int fd = open_binder();
  want("open /dev/binder", fd >= 0, 1);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  want("mmap the arena", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);

  /* A call, not a one-way: an answer is expected. */
  struct btd tr;
  unsigned char payload[16] = "ask";
  mzero(&tr, sizeof tr);
  tr.target = 0;
  tr.code = 11;
  tr.data_size = sizeof payload;
  tr.buffer = (unsigned long) payload;
  int woff = 0;
  *(unsigned int *)(wbuf + woff) = BC_TRANSACTION; woff += 4;
  for (unsigned long i = 0; i < sizeof tr; i++)
    wbuf[woff + i] = ((unsigned char *)&tr)[i];
  woff += (int) sizeof tr;
  want("send the call", bwr(fd, wbuf, woff, 0, 0, 0), 0);

  /* And the answer comes back. */
  struct btd *rep = 0;
  for (int spin = 0; spin < 3 && rep == 0; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_REPLY) { rep = (struct btd *)(rbuf + i); break; }
      if (c == BR_TRANSACTION) i += sizeof(struct btd);
    }
  }
  want("the reply arrives", rep != 0 ? 1 : 0, 1);
  if (rep != 0) {
    want("with the code the manager sent", rep->code, REPLY_CODE);
    want("and a buffer in our own arena",
         rep->buffer >= p && rep->buffer < p + ARENA_SIZE ? 1 : 0, 1);
    if (rep->buffer >= p && rep->buffer < p + ARENA_SIZE) {
      const char *got = (const char *) rep->buffer;
      int same = 1;
      for (unsigned long i = 0; i < sizeof answer; i++)
        if (got[i] != answer[i]) same = 0;
      want("carrying the manager's data", same, 1);
    }
  }

  long status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  want("the manager finished cleanly", (status >> 8) & 0xff, 0);

  sys6(SYS_close, fd, 0,0,0,0,0);
  put(fails == 0 ? "binderreply ok\n" : "binderreply failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
