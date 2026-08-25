/* freestanding: a sender waits for a receiver that is behind, rather than
 * being refused.
 *
 * Linux does not fail a transaction because the receiver has not caught up:
 * its queue is a list, and what bounds a receiver is the buffer it mapped. The
 * queue here lives in a fixed shared region and so has a count, and when that
 * count was reached the sender was told EAGAIN.
 *
 * Which is not a quiet failure but is an obscure one. libbinder reports that
 * the transaction failed, and what reaches the log is whatever the caller says
 * about its own work: Android's boot filled a queue of eight a hundred times
 * over, and vold's service registration was among the casualties - "Unable to
 * start VoldNativeService", from a registration refused because something else
 * was busy. It failed in about one boot in four, which is the worst rate to
 * debug.
 *
 * What is checked: a receiver that stops reading for a while, and a sender that
 * sends more than the queue holds. Every send has to succeed, because the
 * receiver does come back - and every message has to arrive, since waiting
 * would be no better than failing if the message were dropped in the process.
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
#define ARENA_SIZE 0x40000

#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BINDER_WRITE_READ      0xC0306201u
#define BC_TRANSACTION         0x40406300u
#define BC_ENTER_LOOPER        0x0000630Cu
#define BR_TRANSACTION         0x80407202u
#define TF_ONE_WAY 0x01
#define SENDS 40                  /* more than the queue holds */

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
static int open_binder(void){
  return (int) sys6(SYS_openat, AT_FDCWD, (long)"/dev/binder", O_RDWR|O_CLOEXEC, 0,0,0); }
/*
 * The receiver's own, opened non-blocking. A binder read waits when there is
 * nothing to read, and this test spends its time deliberately having nothing
 * to read - so a blocking one turns the failing case into a hang, which is a
 * worse way to report a bug than failing.
 */
static int open_binder_nb(void){
  return (int) sys6(SYS_openat, AT_FDCWD, (long)"/dev/binder",
                    O_RDWR|O_CLOEXEC|O_NONBLOCK, 0,0,0); }
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

/* The receiver: registers, then deliberately stops reading, then catches up. */
static void receiver(int ready_w)
{
  unsigned char wbuf[64], rbuf[2048];
  unsigned long consumed, p;
  int zero = 0, seen = 0;

  int fd = open_binder_nb();
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);
  *(unsigned int *)wbuf = BC_ENTER_LOOPER;
  if (bwr(fd, wbuf, 4, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);

  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);

  naptime(50);                  /* fall behind, on purpose */

  /*
   * A few turns, and out as soon as two come back empty. A binder read waits
   * when there is nothing to read, so a receiver that keeps asking for
   * messages that were never sent costs seconds a turn - and this test's whole
   * purpose is the case where they were not sent, so it must not answer that
   * by hanging.
   */
  int quiet = 0;
  for (int spin = 0; spin < 200 && seen < SENDS; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    if (consumed == 0) {
      /* Give the sender room, but not for ever: this test's whole purpose is
       * the case where the messages were never sent, and answering that by
       * hanging would be no use at all. About a second, all told. */
      if (++quiet > 50) break;
      naptime(20);
      continue;
    }
    quiet = 0;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_TRANSACTION) { seen++; i += sizeof(struct btd); }
    }
  }
  sys6(SYS_exit_group, seen == SENDS ? 0 : (seen > 99 ? 99 : seen + 100), 0,0,0,0,0);
}

void _start(void)
{
  unsigned char wbuf[128], payload[16] = "busy";
  int ready[2];
  int refused = 0;

  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); receiver(ready[1]); }
  want("fork the receiver", kid > 0, 1);
  if (kid <= 0) { put("binderbusy failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  sys6(SYS_close, ready[1], 0,0,0,0,0);
  char b; sys6(SYS_read, ready[0], (long)&b, 1, 0,0,0);

  int fd = open_binder();
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
    tr.data_size = sizeof payload;
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
  want("and every message arrived", (status >> 8) & 0xff, 0);

  sys6(SYS_close, fd, 0,0,0,0,0);
  put(fails == 0 ? "binderbusy ok\n" : "binderbusy failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
