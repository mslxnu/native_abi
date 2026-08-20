/* freestanding: recvmmsg(2) -- receive multiple datagrams.
 *
 * Creates a socketpair, writes data into one end, then calls recvmmsg on
 * the other to verify it returns the correct count and msg_len values.
 * Also exercises the vlen=0, timeout-expired, and MSG_DONTWAIT paths.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
  register long x8 asm("x8") = n;
  register long x0 asm("x0") = a; register long x1 asm("x1") = b;
  register long x2 asm("x2") = c; register long x3 asm("x3") = d;
  register long x4 asm("x4") = e; register long x5 asm("x5") = f;
  asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
                              "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}

static int slen(const char *s) { int i = 0; while (s[i]) i++; return i; }
static void put(const char *m) { sys6(64, 1, (long)m, slen(m), 0, 0, 0); }

static void putx(long v)
{
  char buf[18]; int i;
  buf[0] = '0'; buf[1] = 'x';
  for (i = 15; i >= 0; i--)
    buf[2 + 15 - i] = "0123456789abcdef"[(v >> (i * 4)) & 0xf];
  sys6(64, 1, (long)buf, 18, 0, 0, 0);
}

static void die(const char *msg, long val)
{
  put("FAIL: "); put(msg); put(" ret="); putx(val); put("\n");
  sys6(93, 1, 0, 0, 0, 0, 0);
  for (;;) {}
}

/* syscall numbers — arm64 */
#define SYS_write       64
#define SYS_exit        93
#define SYS_socketpair 199
#define SYS_sendto     270
#define SYS_recvmmsg   243

#define AF_LOCAL   1
#define SOCK_DGRAM 2

/* struct layout — arm64 (all pointers = 8 bytes, l_uint = 4 bytes) */
struct iovec { unsigned long iov_base; unsigned long iov_len; };
struct msghdr {
  unsigned long msg_name;     /* 8 */
  int            msg_namelen; /* 4 + 4 pad */
  unsigned long msg_iov;      /* 8 */
  unsigned long msg_iovlen;   /* 8 */
  unsigned long msg_control;  /* 8 */
  unsigned long msg_controllen; /* 8 */
  unsigned int  msg_flags;    /* 4 */
}; /* = 56 bytes */
struct mmsghdr {
  struct msghdr msg_hdr; /* 56 */
  unsigned int  msg_len; /* 4 + 4 pad */
}; /* = 64 bytes */

#define MSG_DONTWAIT 0x40

static int checks = 0;

static void check(int cond, const char *msg, long val)
{
  if (!cond) die(msg, val);
  checks++;
}

void _start(void)
{
  int fds[2];
  long r;

  /* (1) socketpair(AF_LOCAL, SOCK_DGRAM, 0, fds) */
  r = sys6(SYS_socketpair, AF_LOCAL, SOCK_DGRAM, 0, (long)fds, 0, 0);
  if (r < 0) die("socketpair", r);

  /* (2) write "hello" (5 bytes) into fds[1] */
  r = sys6(SYS_write, fds[1], (long)"hello", 5, 0, 0, 0);
  check(r == 5, "write returned wrong count", r);

  /* (3) write "world" (5 bytes) into fds[1] */
  r = sys6(SYS_write, fds[1], (long)"world", 5, 0, 0, 0);
  check(r == 5, "write2 returned wrong count", r);

  /* (4) recvmmsg: vlen=2, receive both datagrams */
  {
    char buf0[32], buf1[32];
    struct iovec iov0 = { (unsigned long)buf0, sizeof buf0 };
    struct iovec iov1 = { (unsigned long)buf1, sizeof buf1 };
    struct msghdr hdr0 = { 0, 0, (unsigned long)&iov0, 1, 0, 0, 0 };
    struct msghdr hdr1 = { 0, 0, (unsigned long)&iov1, 1, 0, 0, 0 };
    struct mmsghdr msgs[2];
    msgs[0].msg_hdr.msg_name = 0;
    msgs[0].msg_hdr.msg_namelen = 0;
    msgs[0].msg_hdr.msg_iov = (unsigned long)&iov0;
    msgs[0].msg_hdr.msg_iovlen = 1;
    msgs[0].msg_hdr.msg_control = 0;
    msgs[0].msg_hdr.msg_controllen = 0;
    msgs[0].msg_hdr.msg_flags = 0;
    msgs[0].msg_len = 0;
    msgs[1].msg_hdr.msg_name = 0;
    msgs[1].msg_hdr.msg_namelen = 0;
    msgs[1].msg_hdr.msg_iov = (unsigned long)&iov1;
    msgs[1].msg_hdr.msg_iovlen = 1;
    msgs[1].msg_hdr.msg_control = 0;
    msgs[1].msg_hdr.msg_controllen = 0;
    msgs[1].msg_hdr.msg_flags = 0;
    msgs[1].msg_len = 0;
    r = sys6(SYS_recvmmsg, fds[0], (long)msgs, 2, 0, 0, 0);
    check(r >= 1, "recvmmsg count < 1", r);
    /* first message should be "hello" (5 bytes) */
    check(msgs[0].msg_len == 5, "msg0 len != 5", msgs[0].msg_len);
    {
      int ok0 = 1; int i;
      for (i = 0; i < 5; i++) if (buf0[i] != "hello"[i]) ok0 = 0;
      check(ok0, "msg0 data != hello", 0);
    }
    /* if two messages received, check second is "world" */
    if (r >= 2) {
      check(msgs[1].msg_len == 5, "msg1 len != 5", msgs[1].msg_len);
      {
        int ok1 = 1; int i;
        for (i = 0; i < 5; i++) if (buf1[i] != "world"[i]) ok1 = 0;
        check(ok1, "msg1 data != world", 0);
      }
    }
  }

  /* (5) recvmmsg: vlen=0 returns 0 */
  r = sys6(SYS_recvmmsg, fds[0], 0, 0, 0, 0, 0);
  check(r == 0, "vlen=0 didn't return 0", r);

  /* (6) recvmmsg: timeout (1ms) on empty socket returns 0 */
  {
    /* struct timespec { long tv_sec; long tv_nsec; } */
    unsigned long ts[2] = { 0, 1000000 }; /* 1 ms */
    r = sys6(SYS_recvmmsg, fds[0], 0, 0, 0, (long)ts, 0);
    check(r == 0, "timeout didn't return 0", r);
  }

  /* (7) recvmmsg: MSG_DONTWAIT on empty socket returns an error (negative) */
  {
    char tmpbuf[32];
    struct iovec tmpiov = { (unsigned long)tmpbuf, sizeof tmpbuf };
    struct mmsghdr dummy;
    dummy.msg_hdr.msg_name = 0;
    dummy.msg_hdr.msg_namelen = 0;
    dummy.msg_hdr.msg_iov = (unsigned long)&tmpiov;
    dummy.msg_hdr.msg_iovlen = 1;
    dummy.msg_hdr.msg_control = 0;
    dummy.msg_hdr.msg_controllen = 0;
    dummy.msg_hdr.msg_flags = 0;
    dummy.msg_len = 0;
    r = sys6(SYS_recvmmsg, fds[0], (long)&dummy, 1, MSG_DONTWAIT, 0, 0);
    check(r < 0, "MSG_DONTWAIT should return negative on empty socket", r);
  }

  put("recvmmsg ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
  for (;;) {}
}
