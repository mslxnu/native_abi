/* freestanding: a thread waiting in accept must not stop the rest of its
 * process.
 *
 * accept is the one call in the socket layer that waits without a bound - a
 * server sits in it for as long as nobody connects, which for a listening
 * daemon is most of its life. The descriptor table's lock used to be taken
 * before it and held across it, so for all of that time no other thread in the
 * process could open a file, make a socket, or do anything else that touches
 * the table. They did not fail; they stopped, in their first call, and stayed
 * there.
 *
 * adbd is built out of exactly that shape. A thread waits in accept on the tcp
 * port while its "server socket" and "jdwp control" threads each begin with a
 * socket() call, and both stopped there before doing anything at all. adbd
 * listens, the host completes the connection, and the part of adbd that would
 * read the handshake has not finished starting up - which from the outside
 * looks like adbd accepting a connection and then ignoring it.
 *
 * The lock has to cover the accepted descriptor from existing to being
 * registered, so that no other thread can exec in between and inherit it
 * unmarked. Waiting for a connection is before any of that: there is no
 * descriptor yet to protect.
 *
 * What is checked: one thread parked in accept on a socket nobody connects to,
 * and another thread calling socket(). The second call has to return. The
 * check is in the parent, which is a different process and so cannot be caught
 * by the same lock - otherwise the failing case would hang the test rather
 * than report it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_kill 129
#define SYS_nanosleep 101
#define SYS_exit 93
#define SYS_exit_group 94

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SIGCHLD 17
#define SIGKILL 9
#define WNOHANG 1
#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define CLONE_SYSVSEM 0x40000
#define THREAD_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM)

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void naptime(long ms){ struct { long s, ns; } t = { ms/1000, (ms%1000)*1000000 };
  sys6(SYS_nanosleep, (long)&t, 0, 0,0,0,0); }
static long new_stack(void){
  long s = sys6(SYS_mmap, 0, 1<<16, 3, 0x22, -1, 0);
  return s < 0 ? 0 : s + (1<<16) - 16;
}

/* An abstract name, so nothing is left behind in the filesystem. */
static char addr[112];
static volatile int in_accept = 0;
static volatile int accept_returned = 0;
static int lfd = -1;

static void child(void)
{
  lfd = (int) sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0,0,0);
  if (lfd < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);

  addr[0] = AF_UNIX; addr[1] = 0;
  addr[2] = 0;                             /* abstract */
  const char *nm = "nabi-acceptlock";
  int n = 0; while (nm[n]) { addr[3 + n] = nm[n]; n++; }
  if (sys6(SYS_bind, lfd, (long) addr, 3 + n, 0,0,0) < 0)
    sys6(SYS_exit_group, 11, 0,0,0,0,0);
  if (sys6(SYS_listen, lfd, 4, 0,0,0,0) < 0)
    sys6(SYS_exit_group, 11, 0,0,0,0,0);

  long sp = new_stack();
  if (!sp) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  long tid = sys6(SYS_clone, THREAD_FLAGS, sp, 0, 0, 0, 0);
  if (tid < 0) sys6(SYS_exit_group, 11, 0,0,0,0,0);
  if (tid == 0) {
    in_accept = 1;
    sys6(SYS_accept, lfd, 0, 0, 0,0,0);   /* nobody ever connects */
    accept_returned = 1;
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }

  /* Let it get in there, and make sure it stayed. */
  for (int i = 0; i < 200 && !in_accept; i++) naptime(5);
  naptime(150);
  if (accept_returned)
    sys6(SYS_exit_group, 12, 0,0,0,0,0);  /* setup broken: accept did not wait */

  /* The call that used to stop here for good. */
  int s = (int) sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0,0,0);
  sys6(SYS_exit_group, s < 0 ? 10 : 0, 0,0,0,0,0);
}

void _start(void)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) child();
  want("fork", kid > 0, 1);
  if (kid <= 0) { put("acceptlock failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  /*
   * Bounded, and from another process. A child stuck behind its own fd table
   * lock is exactly what is being tested for, so waiting on it without a limit
   * would turn the failure into a hang.
   */
  long status = 0, done = 0;
  for (int i = 0; i < 120; i++) {
    done = sys6(SYS_wait4, kid, (long)&status, WNOHANG, 0, 0, 0);
    if (done == kid) break;
    naptime(50);
  }
  if (done != kid) {
    fails++;
    put("  FAIL socket() never returned while a thread waited in accept\n");
    sys6(SYS_kill, kid, SIGKILL, 0,0,0,0);
    sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  } else {
    want("the other thread got its socket", (status >> 8) & 0xff, 0);
  }

  put(fails == 0 ? "acceptlock ok\n" : "acceptlock failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
