/* freestanding: extended attributes on a filesystem that has none.
 *
 * macOS's devfs has no attribute store, and says so with EPERM: listxattr on
 * /dev/null, /dev/zero and /dev/binder alike fails that way. Linux's devtmpfs
 * is tmpfs underneath and answers with an empty list, so a guest asking the
 * same question there gets "there are none" rather than "you may not ask".
 *
 * nabi passed the EPERM straight through, and `ls -l /dev/binder` printed
 * "Operation not permitted" before going on to list the node correctly on the
 * next line. Untidy on its own; the reason it matters is that a container
 * runtime setting up /dev reads that as a permission failure on the device it
 * is about to hand to Android.
 *
 * The distinction being checked is that this is about a *missing store*, not
 * about permission: a real file's attributes still round-trip, so the mapping
 * cannot have been done by making every failure succeed.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_setxattr    5
#define SYS_getxattr    8
#define SYS_listxattr  11
#define SYS_llistxattr 12
#define SYS_unlinkat   35
#define SYS_openat     56
#define SYS_close      57
#define SYS_write      64
#define SYS_exit       93

#define ENODATA   61
#define ENOENT     2
#define AT_FDCWD  (-100)
#define O_WRONLY  1
#define O_CREAT  0100
#define O_TRUNC 01000

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("xattrdev FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static char list[512];
static char val[64];

void _start(void)
{
  long r;

  /* ---- a device node: no store, so an empty listing rather than an error ---- */
  r = sys6(SYS_listxattr, (long) "/dev/null", (long) list, sizeof list, 0, 0, 0);
  if (r != 0)
    fail("listxattr on a device node", r, 0);
  r = sys6(SYS_llistxattr, (long) "/dev/zero", (long) list, sizeof list, 0, 0, 0);
  if (r != 0)
    fail("llistxattr on a device node", r, 0);

  /* An attribute that is not there is absent, not forbidden. ENODATA is what
   * SELinux-aware code checks for; EPERM sends it down an error path. */
  r = sys6(SYS_getxattr, (long) "/dev/null", (long) "security.selinux",
           (long) val, sizeof val, 0, 0);
  if (r != -ENODATA)
    fail("getxattr of a missing attribute on a device node", r, -ENODATA);

  /*
   * ---- an error that is a real error still is one ----
   *
   * The mapping above is about a filesystem with no attribute store, not about
   * making every failure look like success. A path that does not exist must
   * still be ENOENT: turning it into "no such attribute" would tell a caller
   * the file was fine and merely unlabelled.
   */
  r = sys6(SYS_getxattr, (long) "/no/such/path", (long) "user.x",
           (long) val, sizeof val, 0, 0);
  if (r != -ENOENT)
    fail("getxattr on a path that does not exist", r, -ENOENT);
  r = sys6(SYS_listxattr, (long) "/no/such/path", (long) list, sizeof list, 0, 0, 0);
  if (r != -ENOENT)
    fail("listxattr on a path that does not exist", r, -ENOENT);

  /* ---- and a real file is untouched ---- */
  {
    const char *p = "/xattrdev.tmp";
    long fd = sys6(SYS_openat, AT_FDCWD, (long) p, O_WRONLY|O_CREAT|O_TRUNC, 0644, 0, 0);
    if (fd < 0) fail("creating a file", fd, 0);
    sys6(SYS_close, fd, 0,0,0,0,0);

    if ((r = sys6(SYS_setxattr, (long) p, (long) "user.nabi", (long) "hello", 5, 0, 0)) != 0)
      fail("setxattr on a regular file", r, 0);
    /* The listing has to contain something now - a mapping that answered 0 for
     * everything would report an empty list here too. */
    r = sys6(SYS_listxattr, (long) p, (long) list, sizeof list, 0, 0, 0);
    if (r <= 0)
      fail("listxattr on a file that has one", r, 1);
    r = sys6(SYS_getxattr, (long) p, (long) "user.nabi", (long) val, sizeof val, 0, 0);
    if (r != 5)
      fail("getxattr of an attribute that exists", r, 5);
    if (val[0] != 'h' || val[4] != 'o')
      fail("getxattr returned the wrong bytes", val[0], 'h');
    /* And a missing one on a filesystem that *does* have a store is still
     * ENODATA, which is the same answer for a different reason. */
    r = sys6(SYS_getxattr, (long) p, (long) "user.absent", (long) val, sizeof val, 0, 0);
    if (r != -ENODATA)
      fail("getxattr of a missing attribute on a real file", r, -ENODATA);
    sys6(SYS_unlinkat, AT_FDCWD, (long) p, 0, 0, 0, 0);
  }

  put("xattrdev ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
