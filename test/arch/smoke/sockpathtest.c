/* freestanding: getsockname gives back the name the guest bound.
 *
 * A filesystem socket's address is a path, and nabi translates that path on the
 * way in: /dev/socket/x is inside the rootfs, not at the host's /dev. It did
 * not translate it back on the way out, so getsockname answered with the host's
 * name - an address the guest never used and cannot use.
 *
 * bionic's android_get_control_socket does exactly this comparison. init passes
 * a service its listening socket and the service checks the descriptor really
 * is /dev/socket/<name> by asking getsockname. With the host's path coming
 * back, no Android service could recognise its own socket: prng_seeder failed
 * setup and hangs on purpose ("Hanging forever because setup failed"), and
 * boringssl's self test then blocks forever reading from the socket
 * prng_seeder never served.
 *
 * What is checked:
 *
 *   - the name a bound socket reports is the one it was bound with,
 *   - the reported length is the length of that name, since it is not the
 *     length of the host's,
 *   - the same through accept, where the address comes from the other side,
 *   - and a buffer too small truncates but is still told the whole length,
 *     which is what Linux does and what a caller sizing a second buffer needs.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept4 242
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SIGCHLD 17

struct l_sockaddr_un { unsigned short sun_family; char sun_path[108]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void wants(const char *what, const char *got, const char *expect){
  const char *a = got, *b = expect;
  while (*a && *a == *b) { a++; b++; }
  if (*a == *b) return;
  fails++;
  put("  FAIL "); put(what); put(": got \""); put(got); put("\", want \"");
  put(expect); put("\"\n");
}
static int slen(const char*s){int i=0;while(s[i])i++;return i;}
static void setpath(struct l_sockaddr_un *a, const char *p){
  a->sun_family = AF_UNIX;
  int i = 0; while (p[i]) { a->sun_path[i] = p[i]; i++; }
  while (i < 108) a->sun_path[i++] = 0;
}

#define SOCKPATH "/sockdir/ctl"

void _start(void)
{
  struct l_sockaddr_un a, got;
  unsigned int len;
  long r;

  sys6(SYS_mkdirat, AT_FDCWD, (long) "/sockdir", 0755, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) SOCKPATH, 0, 0,0,0);

  int sfd = (int) sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0,0,0);
  want("socket", sfd >= 0, 1);
  if (sfd < 0) { put("sockpath failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  setpath(&a, SOCKPATH);
  want("bind", sys6(SYS_bind, sfd, (long)&a, sizeof a, 0,0,0), 0);

  /* The name it reports must be the name it was bound with. */
  for (int i = 0; i < (int) sizeof got; i++) ((char *)&got)[i] = 0;
  len = sizeof got;
  want("getsockname", sys6(SYS_getsockname, sfd, (long)&got, (long)&len, 0,0,0), 0);
  want("the family", got.sun_family, AF_UNIX);
  wants("the bound path comes back", got.sun_path, SOCKPATH);
  want("and the length is that path's",
       len, (long) (2 + slen(SOCKPATH) + 1));

  /* A buffer too small: truncated, but told the whole length. */
  {
    char small[8];
    for (int i = 0; i < 8; i++) small[i] = 0;
    unsigned int slen8 = sizeof small;
    want("getsockname into a short buffer",
         sys6(SYS_getsockname, sfd, (long)small, (long)&slen8, 0,0,0), 0);
    want("which is still told the whole length",
         slen8, (long) (2 + slen(SOCKPATH) + 1));
  }

  /* And through accept, where the address is the listening socket's. */
  want("listen", sys6(SYS_listen, sfd, 4, 0,0,0,0), 0);
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    int c = (int) sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0,0,0);
    struct l_sockaddr_un ca;
    setpath(&ca, SOCKPATH);
    long cr = sys6(SYS_connect, c, (long)&ca, sizeof ca, 0,0,0);
    sys6(SYS_close, c, 0,0,0,0,0);
    sys6(SYS_exit_group, cr == 0 ? 0 : 1, 0,0,0,0,0);
  }
  want("fork", kid > 0, 1);
  if (kid > 0) {
    for (int i = 0; i < (int) sizeof got; i++) ((char *)&got)[i] = 0;
    len = sizeof got;
    int c = (int) sys6(SYS_accept4, sfd, (long)&got, (long)&len, 0, 0, 0);
    want("accept", c >= 0, 1);
    if (c >= 0) {
      /* The accepted socket's own name is the listening path. */
      for (int i = 0; i < (int) sizeof got; i++) ((char *)&got)[i] = 0;
      len = sizeof got;
      want("getsockname on the accepted socket",
           sys6(SYS_getsockname, c, (long)&got, (long)&len, 0,0,0), 0);
      wants("which reports the guest's path too", got.sun_path, SOCKPATH);
      sys6(SYS_close, c, 0,0,0,0,0);
    }
    long status = 0;
    sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
    want("the client connected", (status >> 8) & 0xff, 0);
  }

  sys6(SYS_close, sfd, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) SOCKPATH, 0, 0,0,0);
  put(fails == 0 ? "sockpath ok\n" : "sockpath failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
