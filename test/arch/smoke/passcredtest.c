/* freestanding: SCM_CREDENTIALS on a datagram socket, across a fork.
 *
 * This is logd's shape and nothing else: one process binds a datagram socket
 * and sets SO_PASSCRED on it, hands it to another process, and that process
 * receives messages from many senders and wants to know who sent each one.
 *
 * Two things were wrong and either alone is fatal to it. SO_PASSCRED was kept
 * in a table keyed by descriptor number *in the setting process*, so a process
 * that inherited the socket inherited no flag and was sent no credentials. And
 * the credentials themselves came from LOCAL_PEERCRED, a question about a
 * connected socket's single peer, which a shared datagram socket does not have.
 * Android's logd drops any message without credentials, so the guest had no
 * logging at all: every ring buffer read "0 B consumed".
 *
 * The receiver asks for *no* sender address here, deliberately, because logd
 * does not either - the credentials have to arrive without it.
 *
 * WHO DOES WHAT MATTERS. The process that sets SO_PASSCRED must not be the one
 * that receives, or the per-descriptor table would have been enough and the
 * test would pass on the broken build. So: the parent binds and sets the flag,
 * a child inherits the descriptor and does the receiving, and the parent drops
 * to another uid and sends. That is init, logd and a logging client.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_socket 198
#define SYS_bind 200
#define SYS_connect 203
#define SYS_setsockopt 208
#define SYS_recvmsg 212
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_getpid 172
#define SYS_getppid 173
#define SYS_setuid 146
#define SYS_unlinkat 35
#define AT_FDCWD -100
#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_PASSCRED 16
#define SCM_CREDENTIALS 2
#define EACCES 13
#define CHILD_UID 1234

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(const char *t, long v)
{
  char b[48]; int i = 0; put(t); put("=");
  if (v < 0) { put("-"); v = -v; }
  char q[24]; int j = 0; if (!v) q[j++] = '0';
  while (v) { q[j++] = '0' + (char)(v % 10); v /= 10; }
  while (j) b[i++] = q[--j]; b[i++] = '\n'; b[i] = 0; put(b);
}
static void fail(const char *w, long v) { putd(w, v); put("FAIL\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

struct sa { unsigned short fam; char path[108]; };
struct iov { void *base; unsigned long len; };
struct mhdr {
  void *name; unsigned int namelen; int _pad;
  struct iov *iov; unsigned long iovlen;
  void *control; unsigned long controllen;
  int flags; int _pad2;
};
struct cmsg { unsigned long len; int level; int type; };
struct ucred { int pid; unsigned uid, gid; };

static struct sa addr;
static char cbuf[128];
static char dbuf[64];

void _start(void)
{
  const char *path = "/tmp/nabi-passcred.sock";
  addr.fam = AF_UNIX;
  for (int i = 0; path[i]; i++) addr.path[i] = path[i];
  sys6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);

  long rs = sys6(SYS_socket, AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
  if (rs < 0) fail("socket", rs);
  if (sys6(SYS_bind, rs, (long)&addr, 2 + 108, 0, 0, 0) != 0) fail("bind", 0);

  int on = 1;
  if (sys6(SYS_setsockopt, rs, SOL_SOCKET, SO_PASSCRED, (long)&on, 4, 0) != 0)
    fail("SO_PASSCRED", 0);

  /*
   * The receiver is a *different process* from the one that set the flag, which
   * is the whole point: a descriptor number means nothing across a fork.
   */
  long rcv = sys6(SYS_clone, 0, 0, 0, 0, 0, 0);
  if (rcv == 0) {
    struct iov io = { dbuf, sizeof dbuf };
    struct mhdr m;
    for (unsigned i = 0; i < sizeof m; i++) ((char *)&m)[i] = 0;
    m.iov = &io; m.iovlen = 1;
    m.control = cbuf; m.controllen = sizeof cbuf;
    /* No name buffer, on purpose: logd asks for none. */
    long n = sys6(SYS_recvmsg, rs, (long)&m, 0, 0, 0, 0);
    if (n != 4) sys6(SYS_exit_group, 31, 0,0,0,0,0);

    struct ucred *uc = 0;
    for (unsigned long off = 0; off + sizeof(struct cmsg) <= m.controllen; ) {
      struct cmsg *c = (struct cmsg *)(cbuf + off);
      if (c->len < sizeof(struct cmsg)) break;
      if (c->level == SOL_SOCKET && c->type == SCM_CREDENTIALS)
        uc = (struct ucred *)(cbuf + off + sizeof(struct cmsg));
      off += (c->len + 7) & ~7UL;
    }
    if (uc == 0) sys6(SYS_exit_group, 32, 0,0,0,0,0);     /* nothing arrived */
    putd("sender pid", uc->pid);
    putd("sender uid", uc->uid);
    if (uc->pid == 0) sys6(SYS_exit_group, 33, 0,0,0,0,0);
    if (uc->pid != sys6(SYS_getppid, 0,0,0,0,0,0)) sys6(SYS_exit_group, 34, 0,0,0,0,0);
    if (uc->uid != CHILD_UID) sys6(SYS_exit_group, 35, 0,0,0,0,0);
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }
  if (rcv < 0) fail("clone receiver", rcv);

  /*
   * And the sender is this process, under a different identity taken before the
   * connect - which is when the name that carries it is fixed.
   */
  if (sys6(SYS_setuid, CHILD_UID, 0,0,0,0,0) != 0)
    fail("setuid", 0);
  long cs = sys6(SYS_socket, AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
  if (cs < 0) fail("sender socket", cs);
  if (sys6(SYS_connect, cs, (long)&addr, 2 + 108, 0, 0, 0) != 0)
    fail("sender connect", 0);
  if (sys6(SYS_write, cs, (long)"LINE", 4, 0, 0, 0) != 4)
    fail("sender write", 0);

  long st = 0;
  sys6(SYS_wait4, rcv, (long)&st, 0, 0, 0, 0);
  long code = (st >> 8) & 0xff;
  if (code == 32) fail("no SCM_CREDENTIALS arrived at the receiver", code);
  if (code == 34) fail("credentials named the wrong pid", code);
  if (code == 35) fail("credentials carried the wrong uid", code);
  if (code != 0) fail("the receiver failed at step", code);

  /*
   * Not covered here: bind refuses nabi's own autobind prefix, so a guest
   * cannot bind a name that decodes to another process's credentials. The guest
   * cannot name that directory from inside - it carries the boot tag - so the
   * guard is in the code and not in this test.
   */
  sys6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
  put("ok passcred\n");
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}
