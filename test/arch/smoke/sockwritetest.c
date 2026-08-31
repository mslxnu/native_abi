/* freestanding: write(2) on a socket returns what it wrote, and no more.
 *
 * A write can return less than it was asked for - that is a short write, and
 * every caller loops. It can never return *more*. adbd's WriteFdExactly does
 * the ordinary thing with the answer:
 *
 *     while (len > 0) { r = adb_write(fd, p, len); len -= r; p += r; }
 *
 * so a count larger than the buffer walks the pointer past the end and the
 * length past zero. What reached the host was a corrupted adb stream: adbd read
 * the CNXN handshake correctly, wrote its own, and the connection died -
 * "host-320: offline", "destroying transport" - and `adb connect` answered
 * "failed to connect" for a socket that nc could open perfectly well.
 *
 * Both kinds are checked, because the accepted TCP socket is the one adbd uses
 * and the unix pair is the one that says whether it is sockets in general.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept4 242
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SIGCHLD 17

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

/* The adb message header is 24 bytes, which is the size that failed. */
static unsigned char buf[512];

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  (void) sp;
  for (unsigned i = 0; i < sizeof buf; i++) buf[i] = (unsigned char)(i + 1);

  /* A unix pair first: if this is wrong, it is not about TCP. */
  int sv[2];
  want("socketpair", sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0, 0), 0);
  long w = sys6(SYS_write, sv[0], (long) buf, 24, 0, 0, 0);
  want("write 24 to a unix pair returns 24", w, 24);
  w = sys6(SYS_write, sv[0], (long) buf, 362, 0, 0, 0);
  want("write 362 to a unix pair returns 362", w, 362);
  sys6(SYS_close, sv[0], 0,0,0,0,0); sys6(SYS_close, sv[1], 0,0,0,0,0);

  /*
   * Then an accepted TCP connection, which is the shape adbd has: it listens,
   * something connects, and it writes to what accept gave it.
   */
  int ls = (int) sys6(SYS_socket, AF_INET, SOCK_STREAM, 0, 0,0,0);
  want("socket", ls >= 0, 1);
  if (ls < 0) { put("sockwrite failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  unsigned char sa[16];
  mzero(sa, sizeof sa);
  sa[0] = AF_INET; sa[1] = 0;          /* sin_family, little-endian u16 */
  sa[2] = 0; sa[3] = 0;                /* port 0: let the host choose */
  sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;
  want("bind", sys6(SYS_bind, ls, (long) sa, 16, 0,0,0), 0);
  want("listen", sys6(SYS_listen, ls, 4, 0,0,0,0), 0);
  /* Ask which port it got, so the child can reach it. */
  int alen = 16;
  want("getsockname", sys6(SYS_getsockname, ls, (long) sa, (long) &alen, 0,0,0), 0);

  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    int cs = (int) sys6(SYS_socket, AF_INET, SOCK_STREAM, 0, 0,0,0);
    if (cs < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
    if (sys6(SYS_connect, cs, (long) sa, 16, 0,0,0) != 0)
      sys6(SYS_exit_group, 12, 0,0,0,0,0);
    /* Drain, so the writer is never blocked by a full buffer - a short write
     * would be legal and is not what this is about. */
    unsigned char in[512];
    long total = 0;
    while (total < 24 + 362) {
      long r = sys6(SYS_read, cs, (long) in, sizeof in, 0,0,0);
      if (r <= 0) break;
      total += r;
    }
    sys6(SYS_close, cs, 0,0,0,0,0);
    sys6(SYS_exit_group, total == 24 + 362 ? 0 : 13, 0,0,0,0,0);
  }
  want("fork", kid > 0, 1);

  int as = (int) sys6(SYS_accept4, ls, 0, 0, 0, 0, 0);
  want("accept4", as >= 0, 1);
  if (as >= 0) {
    w = sys6(SYS_write, as, (long) buf, 24, 0, 0, 0);
    want("write 24 to an accepted socket returns 24", w, 24);
    w = sys6(SYS_write, as, (long) buf, 362, 0, 0, 0);
    want("write 362 to an accepted socket returns 362", w, 362);
    sys6(SYS_close, as, 0,0,0,0,0);
  }
  sys6(SYS_close, ls, 0,0,0,0,0);

  int st = 0;
  sys6(SYS_wait4, kid, (long) &st, 0, 0, 0, 0);
  want("the reader got every byte", (st >> 8) & 0xff, 0);

  put(fails == 0 ? "sockwrite ok\n" : "sockwrite failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
