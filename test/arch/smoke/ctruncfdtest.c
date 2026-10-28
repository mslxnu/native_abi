/* freestanding: a descriptor that fits is not reported as truncated.
 *
 * nabi does not hand the host's control data to the guest - it reads it,
 * registers the descriptors and builds the Linux form itself - so whether the
 * guest's buffer held it is nabi's question, and the host's MSG_CTRUNC is about
 * a buffer the guest never saw. Darwin sets that flag in cases that are not
 * truncation at all: measured, a message carrying one descriptor came back with
 * it set and sixteen bytes of control delivered out of a buffer of a thousand.
 *
 * Passed through, it cost netd its descriptors on every boot - libbase reads
 * MSG_CTRUNC as "some of these are missing", logs "control message was
 * truncated when receiving file descriptors" and discards the message.
 *
 * So: send one descriptor with a control buffer of exactly the size Linux says
 * one needs, and require both that it arrives and that no truncation is
 * claimed. The flag is checked as well as the descriptor, because a receiver
 * that believes the flag never looks at the descriptor.
 *
 * WHAT THIS TEST DOES NOT DO: it passes on the build without the fix. Darwin's
 * spurious MSG_CTRUNC could not be provoked from a guest - neither a socketpair
 * nor a bound datagram pair, which is netd's own shape, triggers it - so what
 * is guarded here is that descriptor passing works and that nothing claims
 * truncation for a message that fitted. The flag itself was caught on an
 * Android boot and measured there: a message carrying one descriptor, sixteen
 * bytes of control delivered, a host buffer of a thousand and twenty-four, and
 * MSG_CTRUNC set anyway.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_exit_group 94
#define SYS_socket 198
#define SYS_bind 200
#define SYS_connect 203
#define SYS_unlinkat 35
#define SYS_sendmsg 211
#define SYS_recvmsg 212
#define SYS_openat 56
#define AT_FDCWD -100
#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define MSG_CTRUNC 8

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

struct iov { void *base; unsigned long len; };
struct mhdr {
  void *name; unsigned int namelen; int _p1;
  struct iov *iov; unsigned long iovlen;
  void *control; unsigned long controllen;
  int flags; int _p2;
};
struct cmsg { unsigned long len; int level; int type; };

/* Linux: CMSG_SPACE(sizeof(int)) = align8(16) + align8(4) = 24. Exactly that,
 * so a buffer one byte short of generous cannot hide the answer. */
static char cbuf[24];
static char rbuf[24];
static int sv[2];
struct sa { unsigned short fam; char path[108]; };
static struct sa ra, sa_;
static char payload[1] = { 'x' };
static char got[8];

void _start(void)
{
  /*
   * A bound datagram pair, which is netd's shape - it receives descriptors on a
   * SOCK_DGRAM socket, not on a socketpair, and a socketpair does not reproduce
   * this at all.
   */
  const char *rp = "/tmp/nabi-ctrunc-r.sock", *sp = "/tmp/nabi-ctrunc-s.sock";
  ra.fam = sa_.fam = AF_UNIX;
  for (int i = 0; rp[i]; i++) ra.path[i] = rp[i];
  for (int i = 0; sp[i]; i++) sa_.path[i] = sp[i];
  sys6(SYS_unlinkat, AT_FDCWD, (long)rp, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)sp, 0, 0, 0, 0);
  sv[0] = (int) sys6(SYS_socket, AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
  sv[1] = (int) sys6(SYS_socket, AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
  if (sv[0] < 0 || sv[1] < 0) fail("socket", 0);
  if (sys6(SYS_bind, sv[0], (long)&ra, 2+108, 0,0,0) != 0) fail("bind receiver", 0);
  if (sys6(SYS_bind, sv[1], (long)&sa_, 2+108, 0,0,0) != 0) fail("bind sender", 0);
  if (sys6(SYS_connect, sv[1], (long)&ra, 2+108, 0,0,0) != 0) fail("connect", 0);

  /* Something recognisable to pass: /dev/zero, which reads as zeroes. */
  long z = sys6(SYS_openat, AT_FDCWD, (long)"/dev/zero", 0, 0, 0, 0);
  if (z < 0) fail("open /dev/zero", z);

  struct cmsg *c = (struct cmsg *)cbuf;
  c->len = sizeof(struct cmsg) + sizeof(int);
  c->level = SOL_SOCKET;
  c->type = SCM_RIGHTS;
  *(int *)(cbuf + sizeof(struct cmsg)) = (int) z;

  struct iov sio = { payload, 1 };
  struct mhdr sm;
  for (unsigned i = 0; i < sizeof sm; i++) ((char *)&sm)[i] = 0;
  sm.iov = &sio; sm.iovlen = 1;
  sm.control = cbuf; sm.controllen = c->len;      /* CMSG_LEN, as senders use */
  if (sys6(SYS_sendmsg, sv[1], (long)&sm, 0, 0, 0, 0) != 1)
    fail("sendmsg", 0);

  struct iov rio = { got, sizeof got };
  struct mhdr rm;
  for (unsigned i = 0; i < sizeof rm; i++) ((char *)&rm)[i] = 0;
  rm.iov = &rio; rm.iovlen = 1;
  rm.control = rbuf; rm.controllen = sizeof rbuf;  /* exactly CMSG_SPACE(int) */
  long n = sys6(SYS_recvmsg, sv[0], (long)&rm, 0, 0, 0, 0);
  if (n != 1) fail("recvmsg", n);

  if (rm.flags & MSG_CTRUNC) {
    putd("msg_flags", rm.flags);
    fail("truncation was claimed for a descriptor that fitted", rm.controllen);
  }

  struct cmsg *rc = (struct cmsg *)rbuf;
  if (rc->level != SOL_SOCKET || rc->type != SCM_RIGHTS)
    fail("no SCM_RIGHTS came back, controllen", (long) rm.controllen);
  int fd = *(int *)(rbuf + sizeof(struct cmsg));
  if (fd <= 0) fail("the descriptor is not usable", fd);

  /* And it is really the file: /dev/zero reads zeroes. */
  got[0] = 0x55;
  if (sys6(SYS_read, fd, (long)got, 1, 0, 0, 0) != 1)
    fail("read from the passed descriptor", 0);
  if (got[0] != 0) fail("the passed descriptor is not the one sent", got[0]);

  sys6(SYS_close, fd, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)rp, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)sp, 0, 0, 0, 0);
  put("ok ctruncfd\n");
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}
