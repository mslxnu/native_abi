/* freestanding: POSIX message queues, and the I/O priority pair.
 *
 * Darwin has no mq_open at all, so all of this is NABI's own. The parts worth
 * testing are the ones a working-looking implementation gets wrong:
 *
 *   - Priority ordering. A queue is not a pipe: a message sent later with a
 *     higher priority comes out first, and among equal priorities the oldest
 *     wins. Send three in one order and they must come back in another.
 *   - The size rule. A receive buffer smaller than the queue's message size is
 *     refused outright, because a message arrives whole or not at all - there
 *     is no short read to fall back on.
 *   - O_NONBLOCK in both directions: a full queue and an empty one.
 *   - mq_unlink removes the name and not the queue, so a descriptor still open
 *     keeps working afterwards.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_close             57
#define SYS_write             64
#define SYS_exit              93
#define SYS_ioprio_set        30
#define SYS_ioprio_get        31
#define SYS_mq_open          180
#define SYS_mq_unlink        181
#define SYS_mq_timedsend     182
#define SYS_mq_timedreceive  183
#define SYS_mq_notify        184
#define SYS_mq_getsetattr    185

#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    0100
#define O_EXCL     0200
#define O_NONBLOCK 04000

#define EAGAIN     11
#define EINVAL     22
#define EMSGSIZE   90
#define EEXIST     17
#define ENOENT      2
#define EACCES     13
#define EBUSY      16

#define SIGEV_SIGNAL 0
#define SIGEV_NONE   1

#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_CLASS_BE    2
#define IOPRIO_CLASS_IDLE  3
#define IOPRIO_WHO_PROCESS 1

struct mq_attr { long long flags, maxmsg, msgsize, curmsgs, reserved[4]; };
struct sigev { int val, padv, signo, notify, tid, pad[11]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("mq FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("mq FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

void _start(void)
{
  long r;

  /* A run that failed part-way could have left the queue behind. */
  sys6(SYS_mq_unlink, (long) "/nabitest", 0, 0, 0, 0, 0);

  /* ---- names Linux refuses ---- */
  if ((r = sys6(SYS_mq_open, (long) "nabitest", O_RDWR | O_CREAT, 0600, 0, 0, 0)) != -EINVAL)
    fail("a queue name with no leading slash", r, -EINVAL);
  if ((r = sys6(SYS_mq_open, (long) "/a/b", O_RDWR | O_CREAT, 0600, 0, 0, 0)) != -EACCES)
    fail("a queue name with a path in it", r, -EACCES);
  if ((r = sys6(SYS_mq_open, (long) "/nabitest", O_RDWR, 0, 0, 0, 0)) != -ENOENT)
    fail("opening a queue that does not exist", r, -ENOENT);

  /* ---- create, with attributes of our own ---- */
  struct mq_attr want; clr((char *) &want, sizeof want);
  want.maxmsg = 4;
  want.msgsize = 32;
  long q = sys6(SYS_mq_open, (long) "/nabitest", O_RDWR | O_CREAT | O_EXCL, 0600, (long) &want, 0, 0);
  if (q < 0)
    fail("creating a queue", q, 0);

  if ((r = sys6(SYS_mq_open, (long) "/nabitest", O_RDWR | O_CREAT | O_EXCL, 0600, (long) &want, 0, 0)) != -EEXIST)
    fail("creating a queue that already exists, with O_EXCL", r, -EEXIST);

  { struct mq_attr got; clr((char *) &got, sizeof got);
    if ((r = sys6(SYS_mq_getsetattr, q, 0, (long) &got, 0, 0, 0)) != 0)
      fail("mq_getsetattr", r, 0);
    if (got.maxmsg != 4)
      fail("the queue's maxmsg", (long) got.maxmsg, 4);
    if (got.msgsize != 32)
      fail("the queue's msgsize", (long) got.msgsize, 32);
    if (got.curmsgs != 0)
      fail("a new queue's message count", (long) got.curmsgs, 0); }

  /*
   * ---- priority ordering ----
   *
   * Sent low, high, low. They must come back high first, and the two lows in
   * the order they were sent - a queue that behaved like a pipe would return
   * them in the order below and look entirely reasonable doing it.
   */
  if ((r = sys6(SYS_mq_timedsend, q, (long) "first-low", 9, 1, 0, 0)) != 0)
    fail("sending the first message", r, 0);
  if ((r = sys6(SYS_mq_timedsend, q, (long) "high", 4, 9, 0, 0)) != 0)
    fail("sending a higher-priority message", r, 0);
  if ((r = sys6(SYS_mq_timedsend, q, (long) "second-low", 10, 1, 0, 0)) != 0)
    fail("sending the third message", r, 0);

  { struct mq_attr got; clr((char *) &got, sizeof got);
    sys6(SYS_mq_getsetattr, q, 0, (long) &got, 0, 0, 0);
    if (got.curmsgs != 3)
      fail("the queue's message count after three sends", (long) got.curmsgs, 3); }

  char buf[64];
  unsigned int prio;
  { clr(buf, sizeof buf); prio = 0;
    if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, (long) &prio, 0, 0)) != 4)
      fail("receiving the highest-priority message", r, 4);
    if (!eq(buf, "high"))
      fails("which message came out first", buf, "high");
    if (prio != 9)
      fail("the priority it came back with", prio, 9); }

  { clr(buf, sizeof buf); prio = 0;
    if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, (long) &prio, 0, 0)) != 9)
      fail("receiving the older of two equal priorities", r, 9);
    if (!eq(buf, "first-low"))
      fails("the older of two equal priorities", buf, "first-low");
    if (prio != 1)
      fail("its priority", prio, 1); }

  { clr(buf, sizeof buf);
    if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, 0, 0)) != 10)
      fail("receiving the last message", r, 10);
    if (!eq(buf, "second-low"))
      fails("the last message", buf, "second-low"); }

  /* ---- the size rule ---- */
  sys6(SYS_mq_timedsend, q, (long) "x", 1, 0, 0, 0);
  if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 31, 0, 0, 0)) != -EMSGSIZE)
    fail("a receive buffer smaller than the queue's message size", r, -EMSGSIZE);
  /* Still there: a refused receive must not have consumed it. */
  clr(buf, sizeof buf);
  if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, 0, 0)) != 1)
    fail("the message a refused receive left behind", r, 1);

  if ((r = sys6(SYS_mq_timedsend, q, (long) buf, 33, 0, 0, 0)) != -EMSGSIZE)
    fail("sending more than the queue's message size", r, -EMSGSIZE);

  /* ---- O_NONBLOCK, both ways ---- */
  { struct mq_attr set; clr((char *) &set, sizeof set);
    set.flags = O_NONBLOCK;
    if ((r = sys6(SYS_mq_getsetattr, q, (long) &set, 0, 0, 0, 0)) != 0)
      fail("setting O_NONBLOCK", r, 0);
    struct mq_attr got; clr((char *) &got, sizeof got);
    sys6(SYS_mq_getsetattr, q, 0, (long) &got, 0, 0, 0);
    if (!(got.flags & O_NONBLOCK))
      fail("O_NONBLOCK reading back", (long) got.flags, O_NONBLOCK);

    /* Empty: a receive returns rather than waiting. */
    if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, 0, 0)) != -EAGAIN)
      fail("a non-blocking receive on an empty queue", r, -EAGAIN);

    /* Full: four fit, the fifth does not. */
    for (int i = 0; i < 4; i++)
      if ((r = sys6(SYS_mq_timedsend, q, (long) "f", 1, 0, 0, 0)) != 0)
        fail("filling the queue", r, 0);
    if ((r = sys6(SYS_mq_timedsend, q, (long) "f", 1, 0, 0, 0)) != -EAGAIN)
      fail("a non-blocking send on a full queue", r, -EAGAIN);
    for (int i = 0; i < 4; i++)
      sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, 0, 0); }

  /* ---- a timed receive really does time out ---- */
  { struct { long long sec, nsec; } abs = { 0, 0 };
    /* An absolute deadline already in the past: it must not wait at all. */
    struct mq_attr set; clr((char *) &set, sizeof set);
    sys6(SYS_mq_getsetattr, q, (long) &set, 0, 0, 0, 0);   /* back to blocking */
    if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, (long) &abs, 0))
        != -110 /* ETIMEDOUT */)
      fail("a timed receive whose deadline has passed", r, -110); }

  /* ---- notification: what can be honoured, and what is refused ---- */
  { struct sigev ev; clr((char *) &ev, sizeof ev);
    ev.notify = SIGEV_NONE;
    if ((r = sys6(SYS_mq_notify, q, (long) &ev, 0, 0, 0, 0)) != 0)
      fail("registering for SIGEV_NONE", r, 0);
    if ((r = sys6(SYS_mq_notify, q, 0, 0, 0, 0, 0)) != 0)
      fail("cancelling a notification", r, 0);

    /* A signal NABI cannot deliver is refused rather than accepted and never
     * acted on - the caller can fall back to a blocking receive, which works. */
    ev.notify = SIGEV_SIGNAL;
    ev.signo = 34;              /* SIGRTMIN */
    if ((r = sys6(SYS_mq_notify, q, (long) &ev, 0, 0, 0, 0)) != -EINVAL)
      fail("registering for a realtime signal", r, -EINVAL); }

  /* ---- unlink removes the name, not the queue ---- */
  if ((r = sys6(SYS_mq_unlink, (long) "/nabitest", 0, 0, 0, 0, 0)) != 0)
    fail("mq_unlink", r, 0);
  if ((r = sys6(SYS_mq_open, (long) "/nabitest", O_RDWR, 0, 0, 0, 0)) != -ENOENT)
    fail("opening an unlinked queue by name", r, -ENOENT);
  /* The descriptor still works, because the file it holds still exists. */
  if ((r = sys6(SYS_mq_timedsend, q, (long) "after", 5, 0, 0, 0)) != 0)
    fail("sending on an unlinked but still-open queue", r, 0);
  clr(buf, sizeof buf);
  if ((r = sys6(SYS_mq_timedreceive, q, (long) buf, 32, 0, 0, 0)) != 5)
    fail("receiving from an unlinked but still-open queue", r, 5);
  if (!eq(buf, "after"))
    fails("what came back from the unlinked queue", buf, "after");
  if ((r = sys6(SYS_mq_unlink, (long) "/nabitest", 0, 0, 0, 0, 0)) != -ENOENT)
    fail("unlinking a queue twice", r, -ENOENT);
  sys6(SYS_close, q, 0, 0, 0, 0, 0);

  /* ---- io priority ---- */
  { int idle = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
    if ((r = sys6(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, idle, 0, 0, 0)) != 0)
      fail("ioprio_set to idle", r, 0);
    if ((r = sys6(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0, 0, 0, 0, 0)) < 0)
      fail("ioprio_get", r, 0);
    if ((r >> IOPRIO_CLASS_SHIFT) != IOPRIO_CLASS_IDLE)
      fail("the class ioprio_get read back", r >> IOPRIO_CLASS_SHIFT,
           IOPRIO_CLASS_IDLE);

    int be = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4;
    if ((r = sys6(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, be, 0, 0, 0)) != 0)
      fail("ioprio_set to best-effort", r, 0);
    if ((r = sys6(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0, 0, 0, 0, 0)) < 0)
      fail("ioprio_get after best-effort", r, 0);
    if ((r >> IOPRIO_CLASS_SHIFT) != IOPRIO_CLASS_BE)
      fail("the class after setting best-effort", r >> IOPRIO_CLASS_SHIFT,
           IOPRIO_CLASS_BE);

    /* Another process cannot be named: the host has no way to say which. */
    if ((r = sys6(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 12345, 0, 0, 0, 0)) != -1)
      { if (r >= 0) fail("asking about another process", r, -1); }
    if ((r = sys6(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, 99 << IOPRIO_CLASS_SHIFT, 0, 0, 0)) != -EINVAL)
      fail("an io priority class that does not exist", r, -EINVAL); }

  put("mq ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
