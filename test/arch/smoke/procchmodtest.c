/* freestanding: chmod on a passed-through /proc, which the host refuses.
 *
 * Linux's procfs implements setattr, so root may chmod the files in it and
 * Android's first-stage init does exactly that: it tightens /proc/cmdline to
 * 0440 and calls a failure fatal, which is where it stopped - "chmod
 * ("/proc/cmdline", 0440) failed Operation not permitted", then "Init
 * encountered errors starting first stage". When /proc is passed through, the
 * files belong to the host module serving them and it has no mode to change.
 *
 * Nothing in nabi consults a mode on those paths, so the request is answered
 * rather than failed, and the bits go nowhere.
 *
 * What is checked:
 *
 *   - chmod of a /proc file succeeds, which is the whole of what init needed.
 *   - it succeeds through fchmodat too, since which entry point a caller uses
 *     is not something this gets to choose.
 *   - a chmod of a path that is genuinely not there still fails with ENOENT.
 *     A blanket "yes" on anything under /proc would hide real mistakes.
 *   - a chmod on an ordinary file still takes effect: the mode reads back as
 *     it was set, so this has not turned chmod into a no-op everywhere.
 *
 * Skipped, reporting ok, where /proc is not passed through - there is nothing
 * to refuse then, and the run is not a failure.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_close        57
#define SYS_openat       56
#define SYS_fchmodat     53
#define SYS_newfstatat   79

#define AT_FDCWD     (-100)
#define O_RDONLY         0
#define ENOENT           2

struct kstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long at, atn, mt, mtn, ct, ctn; unsigned unused[2]; };

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
  struct kstat st;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long)"/proc/cmdline", (long)&st, 0, 0, 0) < 0) {
    put("procchmodtest: no /proc passed through, skipped\n");
    put("procchmod ok\n");
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }

  /* What init does, to the file init does it to. */
  want("chmod /proc/cmdline 0440",
       sys6(SYS_fchmodat, AT_FDCWD, (long)"/proc/cmdline", 0440, 0, 0, 0), 0);
  want("chmod /proc/cmdline 0444 back",
       sys6(SYS_fchmodat, AT_FDCWD, (long)"/proc/cmdline", 0444, 0, 0, 0), 0);

  /* Relative to a directory descriptor, which is the same call underneath but
   * a different path into it. */
  long dfd = sys6(SYS_openat, AT_FDCWD, (long)"/proc", O_RDONLY, 0, 0, 0);
  if (dfd >= 0) {
    want("fchmodat(dirfd, \"cmdline\", 0440)",
         sys6(SYS_fchmodat, dfd, (long)"cmdline", 0440, 0, 0, 0), 0);
    sys6(SYS_close, dfd, 0,0,0,0,0);
  }

  /* Not a licence to say yes to anything under /proc. */
  want("chmod of a missing /proc file is ENOENT",
       sys6(SYS_fchmodat, AT_FDCWD, (long)"/proc/no-such-entry-here", 0440, 0, 0, 0), -ENOENT);

  /* And an ordinary file still really changes. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/procchmodtest", O_RDONLY, 0, 0, 0);
  want("an ordinary file opens", fd >= 0, 1);
  if (fd >= 0) {
    sys6(SYS_close, fd, 0,0,0,0,0);
    want("chmod of an ordinary file",
         sys6(SYS_fchmodat, AT_FDCWD, (long)"/procchmodtest", 0705, 0, 0, 0), 0);
    sys6(SYS_newfstatat, AT_FDCWD, (long)"/procchmodtest", (long)&st, 0, 0, 0);
    want("and the mode reads back", st.mode & 0777, 0705);
    sys6(SYS_fchmodat, AT_FDCWD, (long)"/procchmodtest", 0755, 0, 0, 0);
  }

  put(fails ? "procchmod FAILED\n" : "procchmod ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
