/* freestanding: the guest's root has no parent.
 *
 * On Linux "/.." is "/". The kernel pins it, and a process cannot climb out of
 * its own filesystem however many times it asks. Here the host resolved the
 * component, so it climbed straight out of the rootfs: `stat /..` gave a
 * different inode from `stat /`, `stat /../..` gave a different *device*, and
 * `ls /../..` reached the host's /Volumes. Every host file was one ".." away.
 *
 * It also broke software that checks the invariant rather than the containment.
 * systemd's chaseat() returns an absolute path when the descriptor it walked
 * from is the root, and works out whether it is by asking where ".." leads.
 * Told somewhere else, it returned a relative path, which chaseat_prefix_root
 * rejects as impossible - so every rpm %sysusers scriptlet failed with "Failed
 * to prefix '...' with root '/': Invalid argument", and dnf reported a failed
 * transaction for packages that had installed perfectly.
 *
 * The descriptor case is checked too, and separately, because it is the one
 * that took a second attempt: a guest that opens "/" for itself gets an
 * ordinary descriptor, and identifying the root by descriptor *number* says no
 * about the very same directory. systemd holds its own handle on the root, so
 * it went on escaping after the path form was fixed.
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
#define SYS_getcwd 17
#define SYS_chdir 49
#define SYS_newfstatat 79
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_DIRECTORY 040000

struct lstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long times[6]; unsigned pad3[2]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int n=v<0;if(n)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(n)b[i--]='-';put(b+i+1);}
static void fail(const char *what)
{ put("root FAIL: "); put(what); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

static int same(const struct lstat *a, const struct lstat *b)
{ return a->dev == b->dev && a->ino == b->ino; }

static void stat_at(int dirfd, const char *p, struct lstat *st)
{
  long r = sys6(SYS_newfstatat, dirfd, (long) p, (long) st, 0, 0, 0);
  if (r < 0) { put("root FAIL: stat of "); put(p); put(" -> "); putd(r);
               put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
}

void _start(void)
{
  struct lstat root, up, up2;

  stat_at(AT_FDCWD, "/", &root);
  stat_at(AT_FDCWD, "/..", &up);
  if (!same(&root, &up))
    fail("\"/..\" is not \"/\" - the guest can climb out of its own filesystem");

  stat_at(AT_FDCWD, "/../..", &up2);
  if (!same(&root, &up2))
    fail("\"/../..\" is not \"/\"");

  /* Interior ".." still has to work, or the fix is worse than the bug. */
  struct lstat viaup;
  stat_at(AT_FDCWD, "/../", &viaup);
  if (!same(&root, &viaup))
    fail("\"/../\" is not \"/\"");

  /* Through a descriptor the guest opened itself, which is a different number
   * from the one nabi holds and the same directory. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY|O_DIRECTORY, 0, 0, 0);
  if (fd < 0) fail("could not open \"/\"");
  struct lstat viafd;
  stat_at((int) fd, "..", &viafd);
  if (!same(&root, &viafd))
    fail("\"..\" from the guest's own handle on \"/\" leaves the rootfs");
  sys6(SYS_close, fd, 0,0,0,0,0);

  /* The working directory is named the way the guest names things, not the
   * host's path for it. A guest used to start outside its own root entirely. */
  char cwd[512];
  long r = sys6(SYS_getcwd, (long) cwd, sizeof cwd, 0, 0, 0, 0);
  if (r < 0) { put("root FAIL: getcwd -> "); putd(r); put("\n");
               sys6(SYS_exit, 1, 0,0,0,0,0); }
  if (cwd[0] != '/')
    fail("getcwd did not answer with an absolute path");
  if (cwd[1] != '\0')
    fail("a guest does not start at its own root");

  if ((r = sys6(SYS_chdir, (long) "/..", 0, 0, 0, 0, 0)) < 0)
    { put("root FAIL: chdir /.. -> "); putd(r); put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  r = sys6(SYS_getcwd, (long) cwd, sizeof cwd, 0, 0, 0, 0);
  if (r < 0 || cwd[0] != '/' || cwd[1] != '\0')
    fail("chdir(\"/..\") left the working directory somewhere other than \"/\"");

  put("root ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
