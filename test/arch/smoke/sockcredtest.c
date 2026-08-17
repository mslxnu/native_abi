/* freestanding: what a bound unix socket belongs to, and what a peer is.
 *
 * Run as a non-root uid on purpose. Both answers under test are produced by
 * mapping the *host* account, which nabi shows the guest as root, so as root
 * the wrong answer and the right one are the same number and nothing here can
 * fail. That is not hypothetical: the SO_PEERCRED check in scmtest runs as root
 * and passed throughout the window in which SO_PEERCRED was reporting root for
 * every peer alive.
 *
 *   - a socket the guest binds belongs to the guest user that bound it. It did
 *     not: every other way of creating a file stamps the creator's ownership
 *     beside it and bind did not, so the socket came out owned by root and its
 *     own creator could neither chmod nor unlink it. dbus-daemon chmods its
 *     socket at startup and that EPERM was as far as a session bus got.
 *
 *   - SO_PEERCRED names the peer in the guest's own terms. Darwin answers about
 *     the host account, which every guest process shares, so the translation
 *     gave root for every peer - and a guest that asked about its own socket
 *     was told it belonged to somebody else.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_unlinkat     35
#define SYS_newfstatat   79
#define SYS_socket      198
#define SYS_bind        200
#define SYS_socketpair  199
#define SYS_getsockopt  209
#define SYS_fchmodat     53
#define SYS_getuid      174
#define SYS_getgid      176

#define AF_UNIX          1
#define SOCK_STREAM      1
#define SOL_SOCKET       1
#define SO_PEERCRED     17
#define AT_FDCWD      (-100)

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("sockcred FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

struct sun { unsigned short family; char path[108]; };
struct ucred { int pid; unsigned uid; unsigned gid; };

/* aarch64 struct stat: uid at 24, gid at 28. */
static unsigned char stbuf[128];

void _start(void)
{
  long r;
  long uid = sys6(SYS_getuid,0,0,0,0,0,0);
  long gid = sys6(SYS_getgid,0,0,0,0,0,0);

  /* The whole point is to run as somebody; as root this proves nothing. */
  if (uid == 0)
    fail("this test must not run as root", uid, 1000);

  const char *path = "/sk";
  sys6(SYS_unlinkat, AT_FDCWD, (long) path, 0, 0, 0, 0);

  long fd = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  if (fd < 0) fail("socket", fd, 0);

  struct sun a;
  a.family = AF_UNIX;
  { int i = 0; while (path[i]) { a.path[i] = path[i]; i++; } a.path[i] = 0; }
  if ((r = sys6(SYS_bind, fd, (long) &a, 2 + 4, 0, 0, 0)) != 0)
    fail("bind", r, 0);

  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) stbuf, 0, 0, 0)) != 0)
    fail("stat of the bound socket", r, 0);
  unsigned suid = *(unsigned *)(stbuf + 24);
  unsigned sgid = *(unsigned *)(stbuf + 28);
  if (suid != (unsigned) uid) fail("the socket's owner", suid, uid);
  if (sgid != (unsigned) gid) fail("the socket's group", sgid, gid);

  /* Owning it means being able to change it; that is what the guest lost. */
  if ((r = sys6(SYS_fchmodat, AT_FDCWD, (long) path, 0777, 0, 0, 0)) != 0)
    fail("chmod of our own socket", r, 0);
  if ((r = sys6(SYS_unlinkat, AT_FDCWD, (long) path, 0, 0, 0, 0)) != 0)
    fail("unlink of our own socket", r, 0);

  /* And what a peer is. Both ends here are this process, so the answer is
   * known exactly. */
  int sv[2];
  if ((r = sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0, 0)) != 0)
    fail("socketpair", r, 0);
  struct ucred uc; uc.pid = -1; uc.uid = 0xffffffff; uc.gid = 0xffffffff;
  int len = sizeof uc;
  if ((r = sys6(SYS_getsockopt, sv[0], SOL_SOCKET, SO_PEERCRED,
                (long) &uc, (long) &len, 0)) != 0)
    fail("getsockopt SO_PEERCRED", r, 0);
  if (uc.uid != (unsigned) uid) fail("SO_PEERCRED uid", uc.uid, uid);
  if (uc.gid != (unsigned) gid) fail("SO_PEERCRED gid", uc.gid, gid);

  put("sockcred ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
