/* freestanding: a receiver's arena is reusable.
 *
 * Every transaction is copied into a buffer in the receiver's own memory, and
 * the receiver gives that buffer back with BC_FREE_BUFFER when it is done. The
 * allocator here was a bump allocator and only a bump allocator: the mark went
 * up and never came down, and a freed record was kept for ever so that a
 * double free could be recognised.
 *
 * Both of those make the arena a one-shot. An endpoint stopped being able to
 * receive after its arena's worth of bytes had passed through it, or after
 * BINDER_MAX_ALLOCS messages, whichever came first - and stopped for good,
 * since nothing ever came back. Which is an intermittent failure by
 * construction: whether any given call gets through depends on how much
 * traffic went before it.
 *
 * What is checked: far more traffic than the arena holds, and more messages
 * than there are allocation records, through an endpoint that frees each
 * buffer as it goes. All of it has to arrive. The numbers below are chosen to
 * pass both limits several times over, because passing one of them would leave
 * the other untested.
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
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define O_NONBLOCK 04000
#define PROT_READ 1
#define MAP_PRIVATE 0x02
#define SIGCHLD 17

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_FREE_BUFFER         0x40086303u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define TF_ONE_WAY 0x01

/* Small on purpose: the arena is 16 KiB and 400 messages of 512 bytes is
 * 200 KiB through it, twelve times over - and 400 is well past the number of
 * allocation records there are. */
#define ARENA_SIZE 0x4000
#define PAYLOAD    512
#define SENDS      400

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

/* The receiver: reads, frees each buffer, and counts. */
static void receiver(int ready_w)
{
  unsigned char wbuf[64], rbuf[4096];
  unsigned long consumed, p;
  int zero = 0, seen = 0, quiet = 0;

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long)"/dev/binder",
                      O_RDWR|O_CLOEXEC|O_NONBLOCK, 0,0,0);
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);
  *(unsigned int *)wbuf = BC_ENTER_LOOPER;
  if (bwr(fd, wbuf, 4, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);
  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);

  for (int spin = 0; spin < 4000 && seen < SENDS; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    if (consumed == 0) { if (++quiet > 200) break; naptime(5); continue; }
    quiet = 0;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c != BR_TRANSACTION)
        continue;
      struct btd *tr = (struct btd *)(rbuf + i);
      i += sizeof *tr;
      seen++;
      /* Give it back at once, which is what makes the arena reusable at all. */
      int woff = 0;
      *(unsigned int *)(wbuf + woff) = BC_FREE_BUFFER; woff += 4;
      *(unsigned long *)(wbuf + woff) = tr->buffer;    woff += 8;
      if (bwr(fd, wbuf, woff, 0, 0, 0) != 0)
        sys6(SYS_exit_group, 16, 0,0,0,0,0);
    }
  }
  sys6(SYS_exit_group, seen == SENDS ? 0 : 17, 0,0,0,0,0);
}

void _start(void)
{
  unsigned char wbuf[128], payload[PAYLOAD];
  int ready[2], refused = 0;

  for (int i = 0; i < PAYLOAD; i++) payload[i] = (unsigned char) i;

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); receiver(ready[1]); }
  want("fork the receiver", kid > 0, 1);
  if (kid <= 0) { put("binderarena failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  char b; sys6(SYS_read, ready[0], (long)&b, 1, 0,0,0);

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long)"/dev/binder", O_RDWR|O_CLOEXEC, 0,0,0);
  want("open /dev/binder", fd >= 0, 1);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  want("mmap the arena", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);

  for (int i = 0; i < SENDS; i++) {
    struct btd tr;
    mzero(&tr, sizeof tr);
    tr.target = 0;
    tr.code = (unsigned) i;
    tr.flags = TF_ONE_WAY;
    tr.data_size = PAYLOAD;
    tr.buffer = (unsigned long) payload;
    int woff = 0;
    *(unsigned int *)(wbuf + woff) = BC_TRANSACTION; woff += 4;
    for (unsigned long j = 0; j < sizeof tr; j++)
      wbuf[woff + j] = ((unsigned char *)&tr)[j];
    woff += (int) sizeof tr;
    if (bwr(fd, wbuf, woff, 0, 0, 0) != 0)
      refused++;
  }
  want("no send was refused", refused, 0);

  long status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  want("and all of it arrived", (status >> 8) & 0xff, 0);

  sys6(SYS_close, fd, 0,0,0,0,0);
  put(fails == 0 ? "binderarena ok\n" : "binderarena failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
