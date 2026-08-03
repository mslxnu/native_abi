/* freestanding: the three ways a guest asks for its writes to be durable.
 *
 * syncfs was not implemented at all, so it returned ENOSYS - which coreutils'
 * sync(1) reports as "error syncing '<file>': Function not implemented". That
 * is what stopped `apt-get install linux-image-arm64`: update-initramfs builds
 * the initrd, syncs it, and the kernel postinst treats a failure there as
 * fatal, so a 37MB kernel unpacked correctly and was then left unconfigured
 * over a flush.
 *
 * Darwin has no syncfs and the nearest thing, F_FULLFSYNC, is a stronger
 * promise about one file rather than a weaker one about a filesystem; fsync is
 * the honest approximation, and what this checks is that the call succeeds and
 * that the bytes are readable afterwards.
 *
 * All three are here rather than syncfs alone because they are one family and
 * an ENOSYS in any of them fails the same way - silently, in a postinst,
 * attributed to whatever package happened to be installing.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_unlinkat 35
#define SYS_fsync 82
#define SYS_fdatasync 83
#define SYS_syncfs 267
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("sync FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

void _start(void)
{
  static const char msg[] = "durable\n";
  long fd, r;

  sys6(SYS_unlinkat, AT_FDCWD, (long) "/synctest.tmp", 0, 0, 0, 0);

  if ((fd = sys6(SYS_openat, AT_FDCWD, (long) "/synctest.tmp",
                 O_RDWR|O_CREAT|O_TRUNC, 0644, 0, 0)) < 0)
    fail("create /synctest.tmp", fd);
  if ((r = sys6(SYS_write, fd, (long) msg, sizeof msg - 1, 0, 0, 0)) < 0)
    fail("write", r);

  if ((r = sys6(SYS_fsync, fd, 0,0,0,0,0)) < 0)
    fail("fsync", r);
  if ((r = sys6(SYS_fdatasync, fd, 0,0,0,0,0)) < 0)
    fail("fdatasync", r);
  /* The one that was missing. -ENOSYS is 38. */
  if ((r = sys6(SYS_syncfs, fd, 0,0,0,0,0)) < 0)
    fail("syncfs", r);

  sys6(SYS_close, fd, 0,0,0,0,0);

  /* Durable means readable: a flush that reported success while losing the
   * bytes would pass every check above. */
  char buf[16];
  if ((fd = sys6(SYS_openat, AT_FDCWD, (long) "/synctest.tmp", O_RDONLY, 0, 0, 0)) < 0)
    fail("reopen", fd);
  if ((r = sys6(SYS_read, fd, (long) buf, sizeof buf, 0, 0, 0)) < 0)
    fail("read back", r);
  if (r != (long) sizeof msg - 1)
    fail("read back the wrong length", r);
  for (long i = 0; i < r; i++)
    if (buf[i] != msg[i])
      fail("read back the wrong bytes at", i);

  sys6(SYS_close, fd, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/synctest.tmp", 0, 0, 0, 0);

  put("sync ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
