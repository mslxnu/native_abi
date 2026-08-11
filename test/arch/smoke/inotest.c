/* freestanding: inotify, on a host whose only notification is kqueue.
 *
 * The descriptor a guest gets is the read end of a pipe that a watcher thread
 * feeds, so the interesting part is not that read works - it is a pipe, it was
 * always going to - but that the events arriving through it are the ones Linux
 * would have sent, with the names attached.
 *
 * Names are the whole difficulty. kqueue says a directory changed and not what
 * changed in it, so the listing is remembered and diffed; a test that only
 * checked "something arrived" would pass against an implementation that had
 * lost every name, which is the half callers actually use.
 *
 * The last check is the one worth having. A mask asking only for events this
 * host can never produce is refused, because the alternative is a caller that
 * waits forever - and a watch that is accepted and never fires is exactly the
 * failure that is hardest to attribute to the right place.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_mkdirat  34
#define SYS_unlinkat 35
#define SYS_openat   56
#define SYS_close    57
#define SYS_read     63
#define SYS_write    64
#define SYS_exit     93
#define SYS_nanosleep 101
#define SYS_inotify_init1     26
#define SYS_inotify_add_watch 27
#define SYS_inotify_rm_watch  28

#define AT_FDCWD  -100
#define O_RDONLY  0
#define O_WRONLY  1
#define O_CREAT   0100
#define O_TRUNC   01000
#define IN_NONBLOCK 04000

#define IN_MODIFY       0x00000002
#define IN_ATTRIB       0x00000004
#define IN_CLOSE_WRITE  0x00000008
#define IN_ACCESS       0x00000001
#define IN_OPEN         0x00000020
#define IN_CREATE       0x00000100
#define IN_DELETE       0x00000200
#define IN_IGNORED      0x00008000

#define EINVAL 22
#define EAGAIN 11

struct ino_ev { int wd; unsigned mask; unsigned cookie; unsigned len; };
struct tspec { long tv_sec, tv_nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("ino FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
static void fails(const char *what)
{ put("ino FAIL: "); put(what); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* What was seen, so the checks do not depend on the order events arrive in. */
static unsigned seen_mask_a, seen_mask_b;
static int saw_create_a, saw_create_b, saw_delete_a, saw_close_b;

static void
drain(int fd)
{
  char buf[4096];
  for (;;) {
    long n = sys6(SYS_read, fd, (long) buf, sizeof buf, 0,0,0);
    if (n <= 0)
      return;
    for (long off = 0; off + (long) sizeof(struct ino_ev) <= n; ) {
      struct ino_ev *e = (struct ino_ev *) (buf + off);
      const char *name = e->len ? buf + off + sizeof *e : "";
      if (eq(name, "a")) {
        seen_mask_a |= e->mask;
        if (e->mask & IN_CREATE) saw_create_a = 1;
        if (e->mask & IN_DELETE) saw_delete_a = 1;
      } else if (eq(name, "b")) {
        seen_mask_b |= e->mask;
        if (e->mask & IN_CREATE) saw_create_b = 1;
        if (e->mask & IN_CLOSE_WRITE) saw_close_b = 1;
      }
      off += (long) sizeof *e + (long) e->len;
    }
  }
}

/* The watcher is a thread, so an event is not there the instant the change is.
 * Bounded so a failure is a failure rather than a hang. */
static void
settle(int fd)
{
  for (int i = 0; i < 40; i++) {
    struct tspec ts = { 0, 50000000 };  /* 50ms */
    sys6(SYS_nanosleep, (long) &ts, 0, 0,0,0,0);
    drain(fd);
    if (saw_create_a && saw_create_b && saw_close_b)
      return;
  }
}

void _start(void)
{
  long r;

  long fd = sys6(SYS_inotify_init1, IN_NONBLOCK, 0,0,0,0,0);
  if (fd < 0)
    fail("inotify_init1", fd, 0);

  sys6(SYS_mkdirat, AT_FDCWD, (long) "/ino-dir", 0755, 0,0,0);

  long wd = sys6(SYS_inotify_add_watch, fd, (long) "/ino-dir",
                 IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB,
                 0,0,0);
  if (wd < 0)
    fail("inotify_add_watch", wd, 0);

  /* A mask that could never fire here is refused rather than accepted, so a
   * caller relying on it fails instead of waiting. */
  if ((r = sys6(SYS_inotify_add_watch, fd, (long) "/ino-dir", IN_ACCESS, 0,0,0)) != -EINVAL)
    fail("a watch for only IN_ACCESS", r, -EINVAL);

  /* Watching the same object again updates the watch rather than making a
   * second one, which is what the descriptor being the same number means. */
  if ((r = sys6(SYS_inotify_add_watch, fd, (long) "/ino-dir",
                IN_CREATE | IN_DELETE, 0,0,0)) != wd)
    fail("re-watching the same directory", r, wd);
  /* ...and the mask that matters for the rest of this is put back. */
  sys6(SYS_inotify_add_watch, fd, (long) "/ino-dir",
       IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE, 0,0,0);

  /* Two files, one of which is written and closed. */
  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/ino-dir/a",
                  O_WRONLY | O_CREAT | O_TRUNC, 0644, 0,0);
    if (f < 0) fail("creating a", f, 0);
    sys6(SYS_close, f, 0,0,0,0,0);

    f = sys6(SYS_openat, AT_FDCWD, (long) "/ino-dir/b",
             O_WRONLY | O_CREAT | O_TRUNC, 0644, 0,0);
    if (f < 0) fail("creating b", f, 0);
    sys6(SYS_write, f, (long) "hello\n", 6, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
  }

  settle(fd);

  if (!saw_create_a)
    fails("no IN_CREATE for a, or it arrived without its name");
  if (!saw_create_b)
    fails("no IN_CREATE for b, or it arrived without its name");
  /* The one kqueue cannot see: taken from the guest's own close. */
  if (!saw_close_b)
    fails("no IN_CLOSE_WRITE for b");

  /* And a deletion, which the same directory diff has to notice. */
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/ino-dir/a", 0, 0,0,0);
  for (int i = 0; i < 40 && !saw_delete_a; i++) {
    struct tspec ts = { 0, 50000000 };
    sys6(SYS_nanosleep, (long) &ts, 0, 0,0,0,0);
    drain(fd);
  }
  if (!saw_delete_a)
    fails("no IN_DELETE for a");

  /* Removing a watch says so, and says it once. */
  if ((r = sys6(SYS_inotify_rm_watch, fd, wd, 0,0,0,0)) != 0)
    fail("inotify_rm_watch", r, 0);
  if ((r = sys6(SYS_inotify_rm_watch, fd, wd, 0,0,0,0)) != -EINVAL)
    fail("removing a watch twice", r, -EINVAL);
  {
    char buf[256];
    long n = sys6(SYS_read, fd, (long) buf, sizeof buf, 0,0,0);
    int ignored = 0;
    for (long off = 0; n > 0 && off + (long) sizeof(struct ino_ev) <= n; ) {
      struct ino_ev *e = (struct ino_ev *) (buf + off);
      if (e->mask & IN_IGNORED)
        ignored = 1;
      off += (long) sizeof *e + (long) e->len;
    }
    if (!ignored)
      fails("no IN_IGNORED after inotify_rm_watch");
  }

  sys6(SYS_unlinkat, AT_FDCWD, (long) "/ino-dir/b", 0, 0,0,0);
  sys6(SYS_close, fd, 0,0,0,0,0);

  put("ino ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
