/* freestanding: O_DIRECTORY and O_NOFOLLOW mean what they say.
 *
 * These four flags are not common between arches. asm-generic/fcntl.h defines
 * them and x86 takes the defaults, but arch/arm64 overrides all four - and not
 * by shifting them, by permuting them:
 *
 *              x86-64     arm64
 *   O_DIRECT   00040000  0200000
 *   O_LARGEFILE 00100000 0400000
 *   O_DIRECTORY 00200000  040000
 *   O_NOFOLLOW 00400000  0100000
 *
 * NABI carried the x86 numbers unconditionally, so an arm64 guest's
 * O_DIRECTORY arrived looking like O_DIRECT and its O_NOFOLLOW like
 * O_LARGEFILE. Both are hints NABI drops, so both requests were silently
 * granted - which is the worst possible failure for a flag whose entire job is
 * to make an open fail.
 *
 * Nothing noticed for a long time because a wrongly-granted open still returns
 * a working fd. What noticed was `mv a b`: coreutils asks whether the
 * destination is a directory by opening it with O_DIRECTORY rather than by
 * calling stat, and being told yes for a regular file, it appended the source's
 * basename and went looking for "b/a". Every mv and cp onto an existing file
 * failed, which is most of what a package install does.
 *
 * So this checks the two that must *refuse*, since a flag that is being ignored
 * passes any test that only asks for success.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_symlinkat 36
#define SYS_unlinkat 35
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
/* The arm64 numbers, which is the whole point: a guest built for arm64 uses
 * these, and NABI has to read them as these. */
#define O_DIRECTORY 040000
#define O_NOFOLLOW 0100000
#define ENOTDIR 20
#define ELOOP 40

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}

static void fail(const char *what, long rc)
{
  put("oflag FAIL: "); put(what); put(" -> "); putd(rc); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

void _start(void)
{
  /* A plain regular file to aim at. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/oflag.tmp",
                 O_WRONLY|O_CREAT|O_TRUNC, 0644, 0, 0);
  if (fd < 0) fail("create /oflag.tmp", fd);
  sys6(SYS_write, fd, (long) "x\n", 2, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);

  /* O_DIRECTORY on a regular file must be ENOTDIR. Told otherwise, coreutils
   * concludes the destination of a move is a directory. */
  long r = sys6(SYS_openat, AT_FDCWD, (long) "/oflag.tmp", O_RDONLY|O_DIRECTORY, 0, 0, 0);
  if (r >= 0) {
    sys6(SYS_close, r, 0,0,0,0,0);
    fail("O_DIRECTORY opened a regular file", r);
  }
  if (r != -ENOTDIR) fail("O_DIRECTORY gave the wrong errno", r);

  /* And it must still work on an actual directory, so the fix cannot be "make
   * every O_DIRECTORY open fail". */
  r = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY|O_DIRECTORY, 0, 0, 0);
  if (r < 0) fail("O_DIRECTORY refused a real directory", r);
  sys6(SYS_close, r, 0,0,0,0,0);

  /* O_NOFOLLOW on a symlink must be ELOOP. Silently followed, a program that
   * opens a path specifically to refuse a symlink gets the symlink. */
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/oflag.link", 0, 0, 0, 0);
  r = sys6(SYS_symlinkat, (long) "/oflag.tmp", AT_FDCWD, (long) "/oflag.link", 0, 0, 0);
  if (r < 0) fail("symlink", r);

  r = sys6(SYS_openat, AT_FDCWD, (long) "/oflag.link", O_RDONLY|O_NOFOLLOW, 0, 0, 0);
  if (r >= 0) {
    sys6(SYS_close, r, 0,0,0,0,0);
    fail("O_NOFOLLOW followed a symlink", r);
  }
  if (r != -ELOOP) fail("O_NOFOLLOW gave the wrong errno", r);

  /* Without it, the same symlink opens fine. */
  r = sys6(SYS_openat, AT_FDCWD, (long) "/oflag.link", O_RDONLY, 0, 0, 0);
  if (r < 0) fail("plain open of a symlink", r);
  sys6(SYS_close, r, 0,0,0,0,0);

  sys6(SYS_unlinkat, AT_FDCWD, (long) "/oflag.link", 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/oflag.tmp", 0, 0, 0, 0);
  put("oflag ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
