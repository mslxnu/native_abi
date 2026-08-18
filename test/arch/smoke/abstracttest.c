/* freestanding: the abstract unix socket namespace.
 *
 * A Linux abstract socket has a name beginning with a NUL and no filesystem
 * entry at all: nothing is created, nothing is looked up by path, and the name
 * is released when the last descriptor on it closes. Darwin has only pathname
 * sockets, so the name is mapped onto one somewhere of nabi's own.
 *
 * They were not translated at all before: the leading NUL was kept and Darwin
 * was asked to create a file with an empty name, which fails. Anything using
 * them - D-Bus, systemd, X11 - could not bind, and LXC could not reach a
 * container's command socket.
 *
 * What is checked:
 *
 *   - a name binds, another socket connects to it, and bytes cross.
 *   - the name is unique: a second bind is EADDRINUSE. Two callers both
 *     believing they own a name is the failure a namespace exists to prevent.
 *   - connecting to a name nobody has bound is ECONNREFUSED, not ENOENT. The
 *     two mean different things and Linux is precise: a *path* that is not
 *     there is ENOENT, an abstract name that is not bound is ECONNREFUSED,
 *     because the namespace is always present and simply empty. lxc-info reads
 *     ECONNREFUSED as "the container is not running" and anything else as a
 *     failure to ask, so it called a stopped container INVALID STATE and
 *     lxc-start then refused to start one it thought was already up.
 *   - closing the descriptor releases the name, which is what having no
 *     filesystem entry means. A name that stayed taken would make every
 *     restart of a daemon fail.
 *   - the name has no filesystem presence: the bytes after the NUL are not a
 *     path that appears anywhere.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write       64
#define SYS_exit        93
#define SYS_close       57
#define SYS_socket     198
#define SYS_bind       200
#define SYS_listen     201
#define SYS_accept     202
#define SYS_connect    203
#define SYS_sendto     206
#define SYS_recvfrom   207
#define SYS_newfstatat  79

#define AF_UNIX          1
#define SOCK_STREAM      1
#define AT_FDCWD     (-100)

#define EADDRINUSE     98
#define ECONNREFUSED  111
#define ENOENT          2

struct sun { unsigned short family; char path[108]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("abstract FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

/* The name, and the address length that carries it. An abstract name is not a
 * string: its length comes from the address length alone. */
static const char NAME[] = "nabi-abstract-smoke";
#define NAMELEN (sizeof NAME - 1)

static void
fill(struct sun *a)
{
  a->family = AF_UNIX;
  a->path[0] = '\0';
  for (unsigned i = 0; i < NAMELEN; i++)
    a->path[1 + i] = NAME[i];
}
#define ADDRLEN ((int) (2 + 1 + NAMELEN))

static unsigned char stbuf[128];
static char buf[32];

void _start(void)
{
  long r;
  struct sun a;
  fill(&a);

  /* Nobody has it yet: connecting is refused, and refused the way Linux
   * refuses it. This has to come first, while the name is certainly free. */
  { long c = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    if (c < 0) fail("socket", c, 0);
    r = sys6(SYS_connect, c, (long) &a, ADDRLEN, 0, 0, 0);
    if (r != -ECONNREFUSED)
      fail("connect to an unbound abstract name", r, -ECONNREFUSED);
    sys6(SYS_close, c, 0, 0, 0, 0, 0); }

  long srv = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  if (srv < 0) fail("socket", srv, 0);
  if ((r = sys6(SYS_bind, srv, (long) &a, ADDRLEN, 0, 0, 0)) != 0)
    fail("bind of an abstract name", r, 0);
  if ((r = sys6(SYS_listen, srv, 4, 0, 0, 0, 0)) != 0)
    fail("listen", r, 0);

  /* Taken: a second bind must not succeed. */
  { long t = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    r = sys6(SYS_bind, t, (long) &a, ADDRLEN, 0, 0, 0);
    if (r != -EADDRINUSE)
      fail("a second bind of the same abstract name", r, -EADDRINUSE);
    sys6(SYS_close, t, 0, 0, 0, 0, 0); }

  /* It is reachable, and it carries data. */
  long cli = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  if ((r = sys6(SYS_connect, cli, (long) &a, ADDRLEN, 0, 0, 0)) != 0)
    fail("connect to a bound abstract name", r, 0);
  long acc = sys6(SYS_accept, srv, 0, 0, 0, 0, 0);
  if (acc < 0) fail("accept", acc, 0);
  if ((r = sys6(SYS_sendto, cli, (long) "ping", 4, 0, 0, 0)) != 4)
    fail("send", r, 4);
  if ((r = sys6(SYS_recvfrom, acc, (long) buf, sizeof buf, 0, 0, 0)) != 4)
    fail("recv", r, 4);
  if (buf[0] != 'p' || buf[3] != 'g')
    fail("what came through", buf[0], 'p');
  sys6(SYS_close, acc, 0, 0, 0, 0, 0);
  sys6(SYS_close, cli, 0, 0, 0, 0, 0);

  /* No filesystem entry: the bytes after the NUL name nothing. */
  { char path[64];
    path[0] = '/';
    for (unsigned i = 0; i < NAMELEN; i++) path[1 + i] = NAME[i];
    path[1 + NAMELEN] = '\0';
    r = sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) stbuf, 0, 0, 0);
    if (r != -ENOENT)
      fail("an abstract name appearing in the filesystem", r, -ENOENT); }

  /* Closing it gives the name back, which is what makes a daemon restartable. */
  sys6(SYS_close, srv, 0, 0, 0, 0, 0);
  { long again = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    r = sys6(SYS_bind, again, (long) &a, ADDRLEN, 0, 0, 0);
    if (r != 0)
      fail("rebinding the name after closing it", r, 0);
    sys6(SYS_close, again, 0, 0, 0, 0, 0); }

  put("abstract ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
