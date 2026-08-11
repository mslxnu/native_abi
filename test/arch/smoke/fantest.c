/* freestanding: fanotify, whose whole point is seeing what OTHER processes did.
 *
 * That is what separates it from inotify here, and what made it the harder of
 * the two: nabi's processes are separate host processes, so the open happens in
 * one and the listener sits in another with no kernel between them. A test that
 * opened the file itself would pass against an implementation that could only
 * ever see its own process - which is the one process nobody uses fanotify to
 * watch - so the work is done in a forked child.
 *
 * The refusals are checked too. Permission events block the accessing process
 * until the listener answers, and a listener that died would leave every open
 * in the guest waiting on a verdict that is not coming; they are refused with
 * EINVAL, which is what Linux itself returns when built without them.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_fanotify_init 262
#define SYS_fanotify_mark 263
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define SIGCHLD 17

#define FAN_CLASS_NOTIF 0
#define FAN_NONBLOCK 2
#define FAN_CLASS_CONTENT 4
#define FAN_MARK_ADD 1
#define FAN_MARK_MOUNT 0x10
#define FAN_OPEN 0x20
#define FAN_CLOSE_WRITE 0x8
#define FAN_MODIFY 0x2
#define FAN_OPEN_PERM 0x10000
#define EINVAL 22

struct fan_md { unsigned event_len; unsigned char vers, res; unsigned short mdlen;
                unsigned long long mask; int fd; int pid; };
struct tspec { long tv_sec, tv_nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("fan FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

void _start(void){
  long r;
  long fd = sys6(SYS_fanotify_init, FAN_CLASS_NOTIF|FAN_NONBLOCK, O_RDONLY, 0,0,0,0);
  if (fd < 0)
    fail("fanotify_init", fd, 0);

  /* The class that would allow permission events is refused, not the call. */
  if ((r = sys6(SYS_fanotify_init, FAN_CLASS_CONTENT, O_RDONLY, 0,0,0,0)) != -EINVAL)
    fail("fanotify_init(FAN_CLASS_CONTENT)", r, -EINVAL);

  sys6(SYS_mkdirat, AT_FDCWD, (long)"/fan-dir", 0755, 0,0,0);
  r = sys6(SYS_fanotify_mark, fd, FAN_MARK_ADD|FAN_MARK_MOUNT,
           FAN_OPEN|FAN_CLOSE_WRITE|FAN_MODIFY, AT_FDCWD, (long)"/fan-dir", 0);
  if (r != 0)
    fail("fanotify_mark(FAN_MARK_MOUNT)", r, 0);

  /* And so is a mark that asks for one directly. */
  if ((r = sys6(SYS_fanotify_mark, fd, FAN_MARK_ADD, FAN_OPEN_PERM,
                AT_FDCWD, (long)"/fan-dir", 0)) != -EINVAL)
    fail("a mark asking for FAN_OPEN_PERM", r, -EINVAL);

  /* A DIFFERENT process touches a file under the mark. */
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) {
    long f = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/f", O_WRONLY|O_CREAT, 0644, 0,0);
    sys6(SYS_write, f, (long)"x\n", 2, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  if (pid < 0)
    fail("clone", pid, 0);
  int st=0;
  if (sys6(SYS_wait4, pid, (long)&st, 0, 0,0,0) < 0)
    fail("wait4", -1, 0);

  int opens=0, mods=0, closes=0;
  for (int i=0;i<40;i++){
    struct tspec ts={0,50000000}; sys6(SYS_nanosleep,(long)&ts,0,0,0,0,0);
    char buf[4096];
    long n = sys6(SYS_read, fd, (long)buf, sizeof buf, 0,0,0);
    for (long off=0; n>0 && off+(long)sizeof(struct fan_md)<=n; ){
      struct fan_md *m=(struct fan_md*)(buf+off);
      if(m->mask & FAN_OPEN) opens++;
      if(m->mask & FAN_MODIFY) mods++;
      if(m->mask & FAN_CLOSE_WRITE) closes++;
      if(m->fd>=0) sys6(SYS_close,m->fd,0,0,0,0,0);
      off += m->event_len;
    }
    if(opens&&mods&&closes) break;
  }
  if (!opens)
    fail("no FAN_OPEN from another process", 0, 1);
  if (!mods)
    fail("no FAN_MODIFY from another process", 0, 1);
  if (!closes)
    fail("no FAN_CLOSE_WRITE from another process", 0, 1);

  sys6(SYS_close, fd, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)"/fan-dir/f", 0, 0,0,0);
  put("fan ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
