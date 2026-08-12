/* freestanding: chroot and pivot_root.
 *
 * chroot accepted "/" and answered EACCES for everything else, and pivot_root
 * was refused outright on the grounds that it could not be more capable than
 * chroot. Both are real now, and what is worth checking is the half that makes
 * pivot_root worth having rather than a rename of chroot: the old root stays
 * reachable at put_old.
 *
 * A pivot that swapped the root and left put_old as the empty directory it was
 * would satisfy the call and lose the filesystem the guest came from - and a
 * container runtime would not find out until it tried to unmount the old root
 * through that path. So the test reads a file that only exists in the *old*
 * root, through put_old, after pivoting.
 *
 * The other half is that "/" really changed: a file that exists only in the new
 * root has to be readable at its short name, and one that exists only in the
 * old root must no longer be readable at the top.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getcwd     17
#define SYS_mkdirat    34
#define SYS_unlinkat   35
#define SYS_chdir      49
#define SYS_openat     56
#define SYS_close      57
#define SYS_read       63
#define SYS_write      64
#define SYS_exit       93
#define SYS_chroot     51
#define SYS_pivot_root 41

#define ENOENT   2
#define EPERM    1
#define ENOTDIR 20
#define EBUSY   16
#define EINVAL  22

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define AT_FDCWD (-100)

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("pivot FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

static void
makefile(const char *path, const char *text, int len)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_WRONLY|O_CREAT|O_TRUNC, 0644, 0, 0);
  if (fd < 0) fail("creating a marker file", fd, 0);
  if (sys6(SYS_write, fd, (long) text, len, 0, 0, 0) != len)
    fail("writing a marker file", -1, len);
  sys6(SYS_close, fd, 0,0,0,0,0);
}

/* Reads the first byte of `path` relative to `dirfd`, or the negative errno. */
static long
firstbyte_at(int dirfd, const char *path)
{
  char c = 0;
  long fd = sys6(SYS_openat, dirfd, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return fd;
  long n = sys6(SYS_read, fd, (long) &c, 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  return n == 1 ? c : -1;
}

static long
firstbyte(const char *path)
{
  return firstbyte_at(AT_FDCWD, path);
}

void _start(void)
{
  long r;

  /* A marker that exists only in the old root. */
  makefile("/oldmark", "O", 1);

  /*
   * Ask the ".." question once *before* anything changes the root.
   *
   * nabi caches the root's identity the first time it is asked, so without this
   * the cache is still empty when the pivot happens and gets filled with the
   * new root - correct by accident, and the later checks would pass whether or
   * not anything invalidates it. Filling it with the original root here is what
   * makes a stale one observable.
   */
  { long rfd = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY, 0, 0, 0);
    if (rfd < 0) fail("opening the root directory", rfd, 0);
    /* ".." at the root clamps to the root rather than failing, which is what
     * Linux does - so this reads the same file, and the point of asking is the
     * cache it fills rather than the answer. */
    if ((r = firstbyte_at((int) rfd, "../oldmark")) != 'O')
      fail("..  at the starting root did not clamp to it", r, 'O');
    sys6(SYS_close, rfd, 0,0,0,0,0); }

  /* The tree to pivot into, with a marker of its own and the directory the old
   * root will be found at. */
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/newroot", 0755, 0,0,0)) != 0)
    fail("mkdir /newroot", r, 0);
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/newroot/old", 0755, 0,0,0)) != 0)
    fail("mkdir /newroot/old", r, 0);
  makefile("/newroot/newmark", "N", 1);

  /* ---- what pivot_root refuses ---- */
  if ((r = sys6(SYS_pivot_root, (long) "newroot", (long) "/newroot/old", 0,0,0,0)) != -EINVAL)
    fail("pivot_root with a relative new_root", r, -EINVAL);
  /* put_old outside new_root is the check the whole call turns on. */
  if ((r = sys6(SYS_pivot_root, (long) "/newroot", (long) "/oldmark", 0,0,0,0)) != -EINVAL)
    fail("pivot_root with put_old outside new_root", r, -EINVAL);
  /* Whole components, so /newrootfoo is not inside /newroot. */
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/newrootfoo", 0755, 0,0,0)) != 0)
    fail("mkdir /newrootfoo", r, 0);
  if ((r = sys6(SYS_pivot_root, (long) "/newroot", (long) "/newrootfoo", 0,0,0,0)) != -EINVAL)
    fail("pivot_root with put_old sharing a prefix but not a component", r, -EINVAL);
  if ((r = sys6(SYS_pivot_root, (long) "/newroot", (long) "/newroot", 0,0,0,0)) != -EBUSY)
    fail("pivot_root with put_old equal to new_root", r, -EBUSY);
  if ((r = sys6(SYS_pivot_root, (long) "/", (long) "/newroot/old", 0,0,0,0)) != -EBUSY)
    fail("pivot_root onto the current root", r, -EBUSY);
  if ((r = sys6(SYS_pivot_root, (long) "/oldmark", (long) "/oldmark", 0,0,0,0)) != -ENOTDIR)
    fail("pivot_root onto something that is not a directory", r, -ENOTDIR);
  if ((r = sys6(SYS_pivot_root, (long) "/nosuchdir", (long) "/nosuchdir/x", 0,0,0,0)) != -ENOENT)
    fail("pivot_root onto a directory that does not exist", r, -ENOENT);

  /* Everything above must have left the root alone. */
  if ((r = firstbyte("/oldmark")) != 'O')
    fail("a refused pivot_root changed the root anyway", r, 'O');

  /* ---- the pivot ---- */
  if ((r = sys6(SYS_pivot_root, (long) "/newroot", (long) "/newroot/old", 0,0,0,0)) != 0)
    fail("pivot_root", r, 0);

  /* "/" is the new tree: its marker is at the top now. */
  if ((r = firstbyte("/newmark")) != 'N')
    fail("the new root's file is not at the top after pivoting", r, 'N');

  /* And the old root is gone from the top, which is what confinement means. */
  if ((r = firstbyte("/oldmark")) != -ENOENT)
    fail("the old root is still reachable at the top after pivoting", r, -ENOENT);

  /*
   * The half that matters: the old root is reachable at put_old. A pivot that
   * left this an empty directory would pass every check above.
   */
  if ((r = firstbyte("/old/oldmark")) != 'O')
    fail("the old root is not reachable at put_old", r, 'O');
  /* And the new tree is visible through it too, since it was inside the old
   * root all along. */
  if ((r = firstbyte("/old/newroot/newmark")) != 'N')
    fail("put_old does not serve the whole old root", r, 'N');

  /* ---- chroot, which is the same machinery one step simpler ---- */
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/sub", 0755, 0,0,0)) != 0)
    fail("mkdir /sub", r, 0);
  makefile("/sub/submark", "S", 1);
  if ((r = sys6(SYS_chroot, (long) "/sub", 0,0,0,0,0)) != 0)
    fail("chroot", r, 0);
  if ((r = firstbyte("/submark")) != 'S')
    fail("chroot did not change the root", r, 'S');
  if ((r = firstbyte("/newmark")) != -ENOENT)
    fail("the old tree is still reachable after chroot", r, -ENOENT);
  if ((r = sys6(SYS_chroot, (long) "/submark", 0,0,0,0,0)) != -ENOTDIR)
    fail("chroot onto something that is not a directory", r, -ENOTDIR);

  /*
   * ".." must not climb out of the root that is current *now*.
   *
   * nabi caches the root's identity to answer that, and the cache was built
   * when the root could not change. A stale one names the old root, so "/.."
   * would be let through at exactly the moment the guest was confined to a new
   * one - which is the failure that looks like nothing at all until something
   * reads a file it should not have reached.
   */
  if ((r = firstbyte("/../submark")) != 'S')
    fail("/.. did not stay inside the current root", r, 'S');
  if ((r = firstbyte("/../newmark")) != -ENOENT)
    fail("/.. climbed out of the root chroot had just set", r, -ENOENT);
  if ((r = firstbyte("/../../old/oldmark")) != -ENOENT)
    fail("a longer .. walk climbed out of the root", r, -ENOENT);

  /*
   * The same question asked through a descriptor the *guest* opened, which is
   * the case the root-identity cache exists for and the only one that
   * exercises it: a path beginning with "/" starts at nabi's own root
   * descriptor and is recognised by its number, so it never consults the cache
   * at all. This is how systemd walked ".." out of the rootfs while holding its
   * own handle on "/", and a cache still naming the *previous* root would let
   * it happen again at the moment a guest was confined to a new one.
   */
  { long rootfd = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY, 0, 0, 0);
    if (rootfd < 0) fail("opening the root directory", rootfd, 0);
    if ((r = firstbyte_at((int) rootfd, "submark")) != 'S')
      fail("a guest handle on / does not reach its own contents", r, 'S');
    if ((r = firstbyte_at((int) rootfd, "../newmark")) != -ENOENT)
      fail("a guest handle on / walked .. out of the current root", r, -ENOENT);
    if ((r = firstbyte_at((int) rootfd, "../../old/oldmark")) != -ENOENT)
      fail("a guest handle on / walked further out of the current root", r, -ENOENT);
    sys6(SYS_close, rootfd, 0,0,0,0,0); }

  put("pivot ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
