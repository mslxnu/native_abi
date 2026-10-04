/* freestanding: SO_PEERCRED, including on things that are not sockets.
 *
 * Every failure of the peer lookup was handed to the guest as the host left it, and
 * Darwin's ENOTSOCK is 38 where Linux's is 88 - so a descriptor that is not a socket
 * came back as EPERM. Android asks this of descriptors that are not sockets, a
 * /proc/kmsg one among them, 46 times a boot, and "operation not permitted" about a
 * pipe is a different problem from the one the caller has.
 *
 * The second half is a socket with nobody on the other end. Linux answers that
 * rather than failing: no process, and the overflow ids, which is its way of
 * reporting a value it has none for. nabi failed instead.
 *
 * What must keep working is the case that already did: a connected socket reports the
 * peer's real credentials. dbus-daemon's EXTERNAL authentication is decided on them.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_openat 56
#define SYS_pipe2 59
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_getsockopt 209
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_PEERCRED 17
#define ENOTSOCK 88
#define OVERFLOW_ID 65534

struct ucred { int pid; unsigned uid, gid; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++; put("  FAIL "); put(what); put(": got "); putd(got);
  put(", want "); putd(expect); put("\n"); }

/* Asks, and reports what came back. */
static long peercred(long fd, struct ucred *uc)
{
  int len = sizeof *uc;
  uc->pid = -1; uc->uid = -1; uc->gid = -1;
  return sys6(SYS_getsockopt, fd, SOL_SOCKET, SO_PEERCRED, (long) uc, (long) &len, 0);
}

void _start(void)
{
  struct ucred uc;

  /* Not sockets. All three are ENOTSOCK and none of them is a permission problem. */
  {
    int p[2];
    if (sys6(SYS_pipe2, (long) p, 0, 0,0,0,0) != 0) { put("pipe FAIL\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    want("a pipe", peercred(p[0], &uc), -ENOTSOCK);
    sys6(SYS_close, p[0], 0,0,0,0,0); sys6(SYS_close, p[1], 0,0,0,0,0);
  }
  {
    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/stat", 0, 0,0,0);
    if (fd >= 0) {
      want("a regular file", peercred(fd, &uc), -ENOTSOCK);
      sys6(SYS_close, fd, 0,0,0,0,0);
    }
  }
  {
    /* The one Android actually asks about. */
    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/kmsg", 0, 0,0,0);
    if (fd >= 0) {
      want("/proc/kmsg", peercred(fd, &uc), -ENOTSOCK);
      sys6(SYS_close, fd, 0,0,0,0,0);
    }
  }

  /* A socket with nobody on the other end: answered, not refused. */
  {
    long s = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0,0,0);
    if (s < 0) { put("socket FAIL\n"); sys6(SYS_exit_group,2,0,0,0,0,0); }
    want("an unconnected socket is answered", peercred(s, &uc), 0);
    want("  with no process", uc.pid, 0);
    want("  and the overflow uid", uc.uid, OVERFLOW_ID);
    want("  and the overflow gid", uc.gid, OVERFLOW_ID);
    sys6(SYS_close, s, 0,0,0,0,0);
  }

  /*
   * And a connected one still names the peer. Both ends are this process, so the
   * answer has to be this process - which is the case dbus decides on, and the one
   * that was already right.
   */
  {
    int sv[2];
    if (sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0, 0) != 0) {
      put("socketpair FAIL\n");
      sys6(SYS_exit_group, 3, 0,0,0,0,0);
    }
    long me = sys6(SYS_getpid, 0,0,0,0,0,0);
    long myuid = sys6(SYS_getuid, 0,0,0,0,0,0);
    want("a connected socket is answered", peercred(sv[0], &uc), 0);
    want("  and names this process", uc.pid, me);
    want("  with this uid", uc.uid, myuid);
    sys6(SYS_close, sv[0], 0,0,0,0,0); sys6(SYS_close, sv[1], 0,0,0,0,0);
  }

  put(fails == 0 ? "peercred ok\n" : "peercred failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
