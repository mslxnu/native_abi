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
#define SYS_exit_group 94
#define SYS_fanotify_init 262
#define SYS_fanotify_mark 263
#define SYS_name_to_handle_at 264
#define SYS_open_by_handle_at 265
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
#define FAN_ALLOW 1
#define FAN_DENY 2
#define FAN_REPORT_FID 0x200
#define FAN_NOFD (-1)
#define EOVERFLOW 75
#define EPERM 1
#define EINVAL 22

struct fan_md { unsigned event_len; unsigned char vers, res; unsigned short mdlen;
                unsigned long long mask; int fd; int pid; };
struct fid_hdr { unsigned char info_type, pad; unsigned short len; int fsid[2]; };
struct fhandle { unsigned bytes; int type; unsigned char h[32]; };
struct tspec { long tv_sec, tv_nsec; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int eqs(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void fail(const char *what, long got, long want)
{ put("fan FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

void _start(void){
  long r;
  long fd = sys6(SYS_fanotify_init, FAN_CLASS_NOTIF|FAN_NONBLOCK, O_RDONLY, 0,0,0,0);
  if (fd < 0)
    fail("fanotify_init", fd, 0);

  /* A permission mark on a notification instance has nowhere for a verdict to
   * come from, and is refused - as it is on Linux. */
  if ((r = sys6(SYS_fanotify_mark, fd, FAN_MARK_ADD, FAN_OPEN_PERM,
                AT_FDCWD, (long)"/", 0)) != -EINVAL)
    fail("FAN_OPEN_PERM on a notification instance", r, -EINVAL);

  sys6(SYS_mkdirat, AT_FDCWD, (long)"/fan-dir", 0755, 0,0,0);
  r = sys6(SYS_fanotify_mark, fd, FAN_MARK_ADD|FAN_MARK_MOUNT,
           FAN_OPEN|FAN_CLOSE_WRITE|FAN_MODIFY, AT_FDCWD, (long)"/fan-dir", 0);
  if (r != 0)
    fail("fanotify_mark(FAN_MARK_MOUNT)", r, 0);


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

  /*
   * Permission events: a listener in this process, an open in another, and the
   * open must actually fail. A guard that reported the open after allowing it
   * would pass a notification test and be worthless.
   */
  long pfd = sys6(SYS_fanotify_init, FAN_CLASS_CONTENT|FAN_NONBLOCK, O_RDONLY, 0,0,0,0);
  if (pfd < 0)
    fail("fanotify_init(FAN_CLASS_CONTENT)", pfd, 0);
  r = sys6(SYS_fanotify_mark, pfd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_OPEN_PERM,
           AT_FDCWD, (long)"/fan-dir", 0);
  if (r != 0)
    fail("marking for FAN_OPEN_PERM", r, 0);

  /* The object exists, which is what a guard is asked about; an open that
   * creates the file is covered by the release path instead. */
  { long g = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/g", O_WRONLY|O_CREAT, 0644, 0,0);
    if (g >= 0) sys6(SYS_close, g, 0,0,0,0,0); }

  long dpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (dpid < 0)
    fail("clone for the permission test", dpid, 0);
  if (dpid == 0) {
    long f = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/g", O_RDONLY, 0, 0,0);
    if (f >= 0) sys6(SYS_close, f, 0,0,0,0,0);
    /* Report what the open did, so the parent can insist it was refused. */
    sys6(SYS_exit, f < 0 ? 7 : 8, 0,0,0,0,0);
  }

  /* Answer every request with a denial until the child has finished. */
  int denied = 0;
  for (int i = 0; i < 100; i++) {
    char buf[4096];
    long n = sys6(SYS_read, pfd, (long)buf, sizeof buf, 0,0,0);
    for (long off=0; n>0 && off+(long)sizeof(struct fan_md)<=n; ){
      struct fan_md *m=(struct fan_md*)(buf+off);
      if (m->fd >= 0) {
        struct { int fd; unsigned resp; } vr = { m->fd, FAN_DENY };
        sys6(SYS_write, pfd, (long)&vr, sizeof vr, 0,0,0);
        sys6(SYS_close, m->fd, 0,0,0,0,0);
        denied++;
      }
      off += m->event_len;
    }
    int st2 = 0;
    long w = sys6(SYS_wait4, dpid, (long)&st2, 1 /*WNOHANG*/, 0,0,0);
    if (w == dpid) {
      int code = (st2 >> 8) & 0xff;
      if (code == 8)
        fail("an open that should have been denied succeeded", 8, 7);
      if (code != 7)
        fail("the permission child exited with", code, 7);
      break;
    }
    struct tspec ts={0,20000000}; sys6(SYS_nanosleep,(long)&ts,0,0,0,0,0);
    if (i == 99)
      fail("the denied open never returned", 0, 1);
  }
  if (!denied)
    fail("no permission event reached the listener", 0, 1);

  sys6(SYS_close, pfd, 0,0,0,0,0);

  /*
   * And the property this was allowed to exist on: a listener that dies without
   * answering must release whoever is waiting, not leave them.
   *
   * Linux does this in the kernel - closing the descriptor releases everything
   * pending with FAN_ALLOW - and there is no kernel here, so the listener's pid
   * is recorded with its marks and the waiting side watches it. Without that
   * check this open never returns, and a guest that ran a guard once could not
   * open a file again.
   */
  long lpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (lpid < 0)
    fail("clone for the dead-listener test", lpid, 0);
  if (lpid == 0) {
    long f2 = sys6(SYS_fanotify_init, FAN_CLASS_CONTENT|FAN_NONBLOCK, O_RDONLY, 0,0,0,0);
    if (f2 < 0)
      sys6(SYS_exit_group, 9, 0,0,0,0,0);
    sys6(SYS_fanotify_mark, f2, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_OPEN_PERM,
         AT_FDCWD, (long)"/fan-dir", 0);
    /* Gone, with the instance never closed. */
    sys6(SYS_exit_group, 0, 0,0,0,0,0);
  }
  { int st3 = 0;
    if (sys6(SYS_wait4, lpid, (long)&st3, 0, 0,0,0) < 0)
      fail("wait4 for the dying listener", -1, 0);
    if (((st3 >> 8) & 0xff) != 0)
      fail("the dying listener could not set up", (st3 >> 8) & 0xff, 0); }

  { struct tspec ts = { 0, 200000000 }; sys6(SYS_nanosleep, (long)&ts, 0,0,0,0,0); }
  { long f3 = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/g", O_RDONLY, 0, 0,0);
    if (f3 < 0)
      fail("an open guarded by a dead listener was not released", f3, 0);
    sys6(SYS_close, f3, 0,0,0,0,0); }

  /*
   * FAN_REPORT_FID: the record names the object with a handle instead of
   * handing over a descriptor. A handle that cannot be turned back into the
   * file would be a number to compare and nothing else, so the check is that it
   * opens, and opens the *right* file - which is why the content is verified
   * rather than the call's return value.
   */
  long ffd = sys6(SYS_fanotify_init, FAN_CLASS_NOTIF|FAN_NONBLOCK|FAN_REPORT_FID,
                  O_RDONLY, 0,0,0,0);
  if (ffd < 0)
    fail("fanotify_init(FAN_REPORT_FID)", ffd, 0);

  /* Handles and permission events cannot be combined, as on Linux: a verdict
   * names a descriptor, and this mode never hands one out. */
  if ((r = sys6(SYS_fanotify_init, FAN_CLASS_CONTENT|FAN_REPORT_FID,
                O_RDONLY, 0,0,0,0)) != -EINVAL)
    fail("FAN_REPORT_FID with a permission class", r, -EINVAL);

  if ((r = sys6(SYS_fanotify_mark, ffd, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_OPEN,
                AT_FDCWD, (long)"/fan-dir", 0)) != 0)
    fail("marking a FID instance", r, 0);

  /* Something for the handle to name, with content only it has. */
  { long h = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/h", O_WRONLY|O_CREAT, 0644, 0,0);
    if (h < 0) fail("creating h", h, 0);
    sys6(SYS_write, h, (long)"fid\n", 4, 0,0,0);
    sys6(SYS_close, h, 0,0,0,0,0); }

  long hpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (hpid < 0) fail("clone for the fid test", hpid, 0);
  if (hpid == 0) {
    long f4 = sys6(SYS_openat, AT_FDCWD, (long)"/fan-dir/h", O_RDONLY, 0, 0,0);
    if (f4 >= 0) sys6(SYS_close, f4, 0,0,0,0,0);
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  { int st4=0; sys6(SYS_wait4, hpid, (long)&st4, 0, 0,0,0); }

  int resolved = 0;
  for (int i=0;i<60 && !resolved;i++){
    struct tspec ts={0,20000000}; sys6(SYS_nanosleep,(long)&ts,0,0,0,0,0);
    char buf[4096];
    long n = sys6(SYS_read, ffd, (long)buf, sizeof buf, 0,0,0);
    for (long off=0; n>0 && off+(long)sizeof(struct fan_md)<=n; ){
      struct fan_md *m=(struct fan_md*)(buf+off);
      if (m->fd != FAN_NOFD)
        fail("a FID event carried a descriptor", m->fd, FAN_NOFD);
      if (m->event_len > sizeof *m) {
        /* The handle follows the metadata; hand it straight back. */
        char *info = buf + off + m->mdlen;
        struct fhandle *fh = (struct fhandle *)(info + sizeof(struct fid_hdr));
        long o = sys6(SYS_open_by_handle_at, AT_FDCWD, (long)fh, O_RDONLY, 0,0,0);
        if (o < 0)
          fail("open_by_handle_at on a reported handle", o, 0);
        char c[8] = {0};
        long got = sys6(SYS_read, o, (long)c, 4, 0,0,0);
        sys6(SYS_close, o, 0,0,0,0,0);
        if (got != 4 || !eqs(c, "fid\n"))
          fail("the handle opened the wrong file", got, 4);
        resolved = 1;
      }
      off += m->event_len;
    }
  }
  if (!resolved)
    fail("no FID event arrived", 0, 1);
  sys6(SYS_close, ffd, 0,0,0,0,0);

  /* name_to_handle_at answers the size before it answers the handle, which is
   * the whole of how a caller sizes its buffer. */
  { struct fhandle small; small.bytes = 0;
    if ((r = sys6(SYS_name_to_handle_at, AT_FDCWD, (long)"/fan-dir/h",
                  (long)&small, 0, 0, 0)) != -EOVERFLOW)
      fail("name_to_handle_at with too small a buffer", r, -EOVERFLOW);
    if (small.bytes == 0)
      fail("it did not say how much was wanted", small.bytes, 16); }

  sys6(SYS_unlinkat, AT_FDCWD, (long)"/fan-dir/f", 0, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)"/fan-dir/g", 0, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)"/fan-dir/h", 0, 0,0,0);
  put("fan ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
