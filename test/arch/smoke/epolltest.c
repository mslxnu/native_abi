/* freestanding: epoll over a self-pipe, translated to kqueue underneath.
 *
 * Covers the places the two models differ: the timeout path, a level-triggered
 * readable pipe, that the guest's opaque 64-bit data comes back verbatim (a
 * packed vs unpacked struct epoll_event would shift it by four bytes), and that
 * EPOLL_CTL_DEL really unregisters. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit  93
#define SYS_pipe2 59
#define SYS_epoll_create1 20
#define SYS_epoll_ctl     21
#define SYS_epoll_pwait   22
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLLIN 0x1
#define MAGIC 0x0123456789abcdefULL

struct ep_event { unsigned int events; unsigned long long data; };  /* unpacked: aarch64 */

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int ok = 1;

void _start(void){
  int fds[2];
  if (sys6(SYS_pipe2,(long)fds,0,0,0,0,0) < 0) { put("pipe FAIL\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  long ep = sys6(SYS_epoll_create1, 0, 0,0,0,0,0);
  if (ep < 0) { put("epoll_create1 FAIL\n"); sys6(SYS_exit,2,0,0,0,0,0); }

  struct ep_event ev = { EPOLLIN, MAGIC };
  if (sys6(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, fds[0], (long)&ev, 0, 0) < 0) {
    put("epoll_ctl ADD FAIL\n"); sys6(SYS_exit,3,0,0,0,0,0);
  }

  /* nothing written yet: must time out with no events */
  struct ep_event got[4];
  long n = sys6(SYS_epoll_pwait, ep, (long)got, 4, 10 /*ms*/, 0, 0);
  if (n != 0) { put("timeout FAIL\n"); ok = 0; }

  /* now readable */
  char c = 'x'; sys6(SYS_write, fds[1], (long)&c, 1, 0,0,0);
  n = sys6(SYS_epoll_pwait, ep, (long)got, 4, 1000, 0, 0);
  if (n != 1)                       { put("ready FAIL\n"); ok = 0; }
  else if (!(got[0].events & EPOLLIN)) { put("events FAIL\n"); ok = 0; }
  else if (got[0].data != MAGIC)    { put("data FAIL\n"); ok = 0; }

  /* after DEL the descriptor must not be reported again */
  if (sys6(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, fds[0], 0, 0, 0) < 0) {
    put("epoll_ctl DEL FAIL\n"); ok = 0;
  } else {
    n = sys6(SYS_epoll_pwait, ep, (long)got, 4, 10, 0, 0);
    if (n != 0) { put("del FAIL\n"); ok = 0; }
  }

  if (ok) put("epoll ok\n");
  sys6(SYS_exit, ok ? 0 : 4, 0,0,0,0,0);
}
