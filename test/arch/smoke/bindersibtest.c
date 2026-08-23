/* freestanding: two processes find the same binder, when their parent never
 * opened one.
 *
 * The emulated driver keeps its registry of endpoints in a file, and every
 * process that speaks binder has to find the same one. The name was being
 * decided by whichever process wanted it first: it settled on its own pid and
 * published that in the environment for children it would then never have.
 *
 * A fork hides this completely, because the parent has already named the
 * registry by the time the child exists - which is why binderprobe's twoproc
 * stage passed throughout. Siblings do not: Android's init does not open binder
 * itself, so servicemanager, vold and every other service made a registry
 * apiece and each was the only endpoint in it. Transactions to handle 0 came
 * back ENOENT with a live servicemanager in the next process along, and vold
 * exited, and vold has reboot_on_failure.
 *
 * So this parent deliberately never touches the device. It forks two children:
 * one becomes the context manager, the other sends it a transaction. They are
 * siblings, and nothing but the instance-wide name can bring them together.
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

#define BINDER_VERSION             0xC0046209u
#define BINDER_SET_CONTEXT_MGR     0x40046207u
#define BINDER_WRITE_READ          0xC0306201u
#define BC_TRANSACTION             0x40406300u
#define BC_ENTER_LOOPER            0x0000630Cu
#define BR_TRANSACTION             0x80407202u
#define TF_ONE_WAY 0x01

struct binder_write_read {
  unsigned long write_size, write_consumed, write_buffer;
  unsigned long read_size, read_consumed, read_buffer;
};
struct binder_transaction_data {
  unsigned long target; unsigned long cookie;
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
  return (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder",
                    O_RDWR | O_CLOEXEC, 0, 0, 0);
}
static long bwr(int fd, void *wb, unsigned long wn, void *rb, unsigned long rn,
                unsigned long *consumed)
{
  struct binder_write_read w;
  mzero(&w, sizeof w);
  w.write_size = wn; w.write_buffer = (unsigned long) wb;
  w.read_size = rn;  w.read_buffer = (unsigned long) rb;
  long r = sys6(SYS_ioctl, fd, BINDER_WRITE_READ, (long) &w, 0, 0, 0);
  if (consumed) *consumed = w.read_consumed;
  return r;
}

/* The manager: register, then wait for the transaction the sibling sends. */
static void manager(int ready_w, int done_w)
{
  unsigned char wbuf[64], rbuf[512];
  unsigned long consumed;
  int zero = 0, woff = 0, ok = 0;
  unsigned long p;

  int fd = open_binder();
  if (fd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 12, 0,0,0,0,0);
  if (sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0) != 0)
    sys6(SYS_exit_group, 13, 0,0,0,0,0);

  *(unsigned int *)(wbuf + woff) = BC_ENTER_LOOPER; woff += 4;
  if (bwr(fd, wbuf, woff, 0, 0, 0) != 0) sys6(SYS_exit_group, 14, 0,0,0,0,0);

  sys6(SYS_write, ready_w, (long) "r", 1, 0,0,0);   /* registered */

  /* A few, not many: a binder read waits when there is nothing to read, so
   * each turn of this costs seconds when the two are not talking - which is
   * precisely the case this test exists to catch, and a test that catches it
   * by hanging is no better than the bug. */
  for (int spin = 0; spin < 3 && !ok; spin++) {
    consumed = 0;
    if (bwr(fd, 0, 0, rbuf, sizeof rbuf, &consumed) != 0) break;
    for (unsigned long i = 0; i + 4 <= consumed; ) {
      unsigned int c = *(unsigned int *)(rbuf + i);
      i += 4;
      if (c == BR_TRANSACTION) { ok = 1; break; }
    }
  }
  sys6(SYS_write, done_w, ok ? (long) "y" : (long) "n", 1, 0,0,0);
  sys6(SYS_exit_group, ok ? 0 : 15, 0,0,0,0,0);
}

/* The sender: a sibling, which has to find the manager the other one made. */
static void sender(int ready_r)
{
  struct binder_transaction_data tr;
  unsigned char wbuf[128], payload[16] = "sibling";
  char b;
  int woff = 0;

  sys6(SYS_read, ready_r, (long) &b, 1, 0,0,0);      /* wait for the manager */

  int fd = open_binder();
  if (fd < 0) sys6(SYS_exit_group, 21, 0,0,0,0,0);
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE, fd, 0);
  if ((long) p >= -4096 && (long) p < 0) sys6(SYS_exit_group, 22, 0,0,0,0,0);

  mzero(&tr, sizeof tr);
  tr.target = 0;                                     /* the context manager */
  tr.code = 7;
  tr.flags = TF_ONE_WAY;
  tr.data_size = sizeof payload;
  tr.buffer = (unsigned long) payload;

  *(unsigned int *)(wbuf + woff) = BC_TRANSACTION; woff += 4;
  for (unsigned long i = 0; i < sizeof tr; i++)
    wbuf[woff + i] = ((unsigned char *)&tr)[i];
  woff += (int) sizeof tr;

  long r = bwr(fd, wbuf, woff, 0, 0, 0);
  sys6(SYS_exit_group, r == 0 ? 0 : 23, 0,0,0,0,0);
}

void _start(void)
{
  int ready[2], done[2];
  long status;

  /* Deliberately not opened here: the parent must never name the registry. */
  want("pipe2", sys6(SYS_pipe2, (long) ready, 0, 0,0,0,0), 0);
  want("pipe2", sys6(SYS_pipe2, (long) done, 0, 0,0,0,0), 0);

  long a = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (a == 0) { sys6(SYS_close, ready[0],0,0,0,0,0); manager(ready[1], done[1]); }
  long b = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (b == 0) { sys6(SYS_close, ready[1],0,0,0,0,0); sender(ready[0]); }
  want("fork the manager", a > 0, 1);
  want("fork the sender", b > 0, 1);

  sys6(SYS_close, ready[0],0,0,0,0,0); sys6(SYS_close, ready[1],0,0,0,0,0);
  sys6(SYS_close, done[1],0,0,0,0,0);

  status = 0;
  sys6(SYS_wait4, b, (long)&status, 0, 0, 0, 0);
  want("the sender's transaction was accepted", (status >> 8) & 0xff, 0);
  status = 0;
  sys6(SYS_wait4, a, (long)&status, 0, 0, 0, 0);
  want("the manager received it", (status >> 8) & 0xff, 0);
  sys6(SYS_close, done[0],0,0,0,0,0);

  put(fails == 0 ? "bindersib ok\n" : "bindersib failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
