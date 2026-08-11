/* freestanding: extended attributes, and the ones the guest must not see.
 *
 * These were stubs, and setxattr was the bad kind of stub - it warned and
 * returned 0, so every attribute a guest stored was stored nowhere and reported
 * as stored. The round trip is therefore the first thing checked.
 *
 * The rest is containment. nabi keeps a file's guest ownership in
 * msl.nabi.owner, because Darwin cannot hold a uid the host account has not
 * got, and that attribute is bookkeeping rather than the guest's data. A guest
 * that could see it could also copy it: cp -a, tar --xattrs and rsync -X all
 * read every attribute from one file and write them onto another, so one
 * archive extraction would stamp a single file's owner across everything it
 * touched. It has to be absent from listings and refused by name, and the file
 * has to still be owned by whom it was afterwards.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_setxattr    5
#define SYS_getxattr    8
#define SYS_listxattr   11
#define SYS_removexattr 14
#define SYS_openat      56
#define SYS_close       57
#define SYS_write       64
#define SYS_exit        93
#define SYS_unlinkat    35
#define SYS_fchownat    54
#define SYS_newfstatat  79

#define AT_FDCWD -100
#define O_WRONLY 1
#define O_CREAT  0100
#define ENODATA  61
#define EPERM    1

struct lstat { unsigned long dev, ino; unsigned mode, nlink, uid, gid;
               unsigned long rdev, pad1; long size; char rest[64]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("xattr FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what)
{ put("xattr FAIL: "); put(what); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }

#define P "/xattr-file"

void _start(void)
{
  long r;
  sys6(SYS_unlinkat, AT_FDCWD, (long) P, 0, 0, 0, 0);
  { long f = sys6(SYS_openat, AT_FDCWD, (long) P, O_WRONLY|O_CREAT, 0644, 0, 0);
    if (f < 0) fail("creating the file", f, 0);
    sys6(SYS_close, f, 0, 0, 0, 0, 0); }

  /* An attribute the guest sets is an attribute the guest can read back. */
  if ((r = sys6(SYS_setxattr, (long) P, (long) "user.k", (long) "vv", 2, 0, 0)) != 0)
    fail("setxattr", r, 0);
  { char v[8] = {0};
    r = sys6(SYS_getxattr, (long) P, (long) "user.k", (long) v, sizeof v, 0, 0);
    if (r != 2) fail("getxattr length", r, 2);
    if (v[0] != 'v' || v[1] != 'v') fails("getxattr returned other bytes"); }

  /*
   * Ownership goes into msl.nabi.owner, and from here on that attribute must
   * be invisible, unwritable and unremovable - while the ownership it records
   * keeps working.
   */
  if ((r = sys6(SYS_fchownat, AT_FDCWD, (long) P, 4242, -1, 0, 0)) != 0)
    fail("chown", r, 0);

  { char list[512] = {0};
    r = sys6(SYS_listxattr, (long) P, (long) list, sizeof list, 0, 0, 0);
    if (r < 0) fail("listxattr", r, 0);
    int saw_ours = 0, saw_nabi = 0;
    for (long i = 0; i < r; ) {
      const char *n = list + i;
      if (eq(n, "user.k")) saw_ours = 1;
      if (n[0]=='m'&&n[1]=='s'&&n[2]=='l'&&n[3]=='.') saw_nabi = 1;
      while (list[i]) i++;
      i++;
    }
    if (!saw_ours) fails("the guest's own attribute was missing from the listing");
    if (saw_nabi)  fails("nabi's private attribute was visible in the listing"); }

  if ((r = sys6(SYS_getxattr, (long) P, (long) "msl.nabi.owner", 0, 0, 0, 0)) != -ENODATA)
    fail("reading nabi's private attribute", r, -ENODATA);
  if ((r = sys6(SYS_setxattr, (long) P, (long) "msl.nabi.owner", (long) "\0\0\0\0\0\0\0\0", 8, 0, 0)) != -EPERM)
    fail("writing nabi's private attribute", r, -EPERM);
  if ((r = sys6(SYS_removexattr, (long) P, (long) "msl.nabi.owner", 0, 0, 0, 0)) != -EPERM)
    fail("removing nabi's private attribute", r, -EPERM);

  /* ...and after all of that the file is still owned by whom it was. */
  { struct lstat sb;
    if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) P, (long) &sb, 0, 0, 0)) < 0)
      fail("stat after the attempts", r, 0);
    if (sb.uid != 4242) fail("the owner after the attempts", sb.uid, 4242); }

  if ((r = sys6(SYS_removexattr, (long) P, (long) "user.k", 0, 0, 0, 0)) != 0)
    fail("removexattr of the guest's own", r, 0);
  if ((r = sys6(SYS_getxattr, (long) P, (long) "user.k", 0, 0, 0, 0)) != -ENODATA)
    fail("reading it back after removal", r, -ENODATA);

  sys6(SYS_unlinkat, AT_FDCWD, (long) P, 0, 0, 0, 0);
  put("xattr ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
