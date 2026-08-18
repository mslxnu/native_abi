/* freestanding: AF_UNIX SOCK_SEQPACKET, which Darwin does not have.
 *
 * Linux gives local sockets a sequenced-packet mode: connection-oriented like
 * a stream, but keeping the message boundaries of a datagram. Darwin has no
 * such thing on AF_UNIX and answers EPROTONOSUPPORT, so nabi builds the
 * channel out of a connected datagram pair instead.
 *
 * This is what stopped Android's init. Second-stage init makes its channel to
 * property_service with socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC) and
 * treats a failure as fatal - "Failed to socketpair() between property_service
 * and init" - so it died there having already read its properties and run
 * restorecon.
 *
 * What is checked:
 *
 *   - the pair is created at all, which is the whole of what init needed.
 *   - boundaries survive: two sends of three bytes are two receives of three,
 *     not one of six. This is the difference between SEQPACKET and STREAM, and
 *     a caller that framed its messages this way would silently misparse.
 *   - an oversized message is truncated to the buffer and the rest dropped,
 *     rather than being left to be read as a second message.
 *   - a peer that closes is end-of-file. Darwin reports ECONNRESET here and
 *     Linux reports 0; a reader looking for the clean shutdown of a service
 *     would otherwise see an error it has no path for.
 *   - the same over recvfrom as over read, since which one a caller uses is
 *     not something the emulation gets to choose.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_read         63
#define SYS_exit         93
#define SYS_close        57
#define SYS_socketpair  199
#define SYS_sendto      206
#define SYS_recvfrom    207

#define AF_UNIX          1
#define SOCK_SEQPACKET   5
#define SOCK_CLOEXEC  0x80000

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}

static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) { put("  ok  "); put(what); put("\n"); return; }
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  int sv[2];
  long r = sys6(SYS_socketpair, AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, (long)sv, 0, 0);
  want("socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC)", r, 0);
  if (r != 0) { put("seqpackettest: FAILED\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

  char buf[64];

  /* Two messages in, two messages out - not one of six bytes. */
  sys6(SYS_write, sv[0], (long)"aaa", 3, 0,0,0);
  sys6(SYS_write, sv[0], (long)"bbb", 3, 0,0,0);
  want("read keeps the first boundary", sys6(SYS_read, sv[1], (long)buf, sizeof buf, 0,0,0), 3);
  want("first message is 'aaa'", buf[0]=='a' && buf[1]=='a' && buf[2]=='a', 1);
  want("recvfrom keeps the second", sys6(SYS_recvfrom, sv[1], (long)buf, sizeof buf, 0, 0, 0), 3);
  want("second message is 'bbb'", buf[0]=='b' && buf[1]=='b' && buf[2]=='b', 1);

  /* Oversize: truncated to the buffer, and the remainder is gone rather than
   * turning up as a message of its own. */
  sys6(SYS_write, sv[0], (long)"0123456789", 10, 0,0,0);
  want("oversize message truncates", sys6(SYS_read, sv[1], (long)buf, 4, 0,0,0), 4);
  sys6(SYS_write, sv[0], (long)"z", 1, 0,0,0);
  want("the remainder was dropped", sys6(SYS_read, sv[1], (long)buf, sizeof buf, 0,0,0), 1);
  want("and the next message is 'z'", buf[0]=='z', 1);

  /* The peer going away is end-of-file, not a reset connection. */
  sys6(SYS_close, sv[0], 0,0,0,0,0);
  want("read after peer close is EOF", sys6(SYS_read, sv[1], (long)buf, sizeof buf, 0,0,0), 0);
  want("recvfrom after peer close is EOF", sys6(SYS_recvfrom, sv[1], (long)buf, sizeof buf, 0, 0, 0), 0);
  sys6(SYS_close, sv[1], 0,0,0,0,0);

  put(fails ? "seqpackettest: FAILED\n" : "seqpackettest: ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
