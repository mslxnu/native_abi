/* freestanding: the guest's own credentials decide what it may touch.
 *
 * They used to decide nothing. Every access was performed by the host account,
 * which owns the whole tree, so an unprivileged guest could open anything -
 * `apt install` without sudo got all the way to dpkg before anything objected,
 * where a real Linux refuses at the lock file.
 *
 * Two things had to be true before that could be fixed, and this checks both.
 *
 * Ownership has to be real. The host cannot represent it: one account owns
 * everything and chown to anybody else needs privileges nabi has not got, so a
 * file the guest's user created came back owned by root and useradd's chown of
 * a home directory did nothing at all. Enforcing on top of that would have
 * locked every user out of their own home.
 *
 * And the rules have to apply to the *path*, not only to the file at the end of
 * it: a file may be readable by everybody inside a directory that is not, and
 * on Linux the directory decides.
 *
 * The test runs as root - nabi starts every guest as root - and drops to an
 * ordinary uid partway through, which is the transition that matters.
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
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_fchownat 54
#define SYS_fchmodat 53
#define SYS_faccessat 48
#define SYS_setresuid 147
#define SYS_setresgid 149
#define SYS_newfstatat 79
#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define EACCES 13
#define R_OK 4
#define W_OK 2

struct lstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long times[6]; unsigned pad3[2]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{
  put("perm FAIL: "); put(what); put(" -> "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static long open_at(const char *p, int flags, int mode)
{
  return sys6(SYS_openat, AT_FDCWD, (long) p, flags, mode, 0, 0);
}

int _start_c(void);

void _start(void) { sys6(SYS_exit, _start_c(), 0,0,0,0,0); }

int _start_c(void)
{
  long r, fd;

  /* Left over from a previous run, if any: the test must be repeatable on the
   * same tree, and it ends as an unprivileged user who cannot tidy up. */
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/priv/inside", 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/priv", AT_REMOVEDIR, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/mine/f", 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/mine", AT_REMOVEDIR, 0, 0, 0);

  /* Root builds the shape: a private directory holding a world-readable file,
   * and a file of the user's own. */
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/priv", 0700, 0, 0, 0)) < 0)
    fail("mkdir /priv as root", r);
  if ((fd = open_at("/priv/inside", O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0)
    fail("create /priv/inside", fd);
  sys6(SYS_close, fd, 0,0,0,0,0);

  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/mine", 0755, 0, 0, 0)) < 0)
    fail("mkdir /mine", r);
  /* Given away to uid 1000 - which the host cannot do, so this is the
   * recorded-ownership path. */
  if ((r = sys6(SYS_fchownat, AT_FDCWD, (long) "/mine", 1000, 1000, 0, 0)) < 0)
    fail("chown /mine to 1000", r);

  struct lstat st;
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/mine", (long) &st, 0, 0, 0)) < 0)
    fail("stat /mine", r);
  if (st.uid != 1000 || st.gid != 1000) {
    put("perm FAIL: chown did not stick, owner reads "); putd(st.uid);
    put(":"); putd(st.gid); put("\n");
    return 1;
  }

  /* Root may still read the private file, because root bypasses these rules. */
  if ((fd = open_at("/priv/inside", O_RDONLY, 0)) < 0)
    fail("root reading /priv/inside", fd);
  sys6(SYS_close, fd, 0,0,0,0,0);

  /* Become an ordinary user. gid first, as anything dropping privileges must. */
  if ((r = sys6(SYS_setresgid, 1000, 1000, 1000, 0, 0, 0)) < 0)
    fail("setresgid", r);
  if ((r = sys6(SYS_setresuid, 1000, 1000, 1000, 0, 0, 0)) < 0)
    fail("setresuid", r);

  /* Its own directory is writable... */
  if ((fd = open_at("/mine/f", O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0)
    fail("user writing its own directory", fd);
  sys6(SYS_close, fd, 0,0,0,0,0);

  /* ...and the file it just made is its own. */
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/mine/f", (long) &st, 0, 0, 0)) < 0)
    fail("stat /mine/f", r);
  if (st.uid != 1000)
    fail("a file the user created is not owned by the user; uid reads", st.uid);

  /* The private directory is out of reach even though the file inside it is
   * world-readable. This is the path check rather than the file check. */
  if ((fd = open_at("/priv/inside", O_RDONLY, 0)) >= 0) {
    sys6(SYS_close, fd, 0,0,0,0,0);
    fail("a 0700 directory did not stop the user reading through it", 0);
  }
  if (fd != -EACCES)
    fail("reading through a private directory gave the wrong errno", fd);

  /* Creating in a directory it does not own is refused... */
  if ((fd = open_at("/priv/new", O_WRONLY|O_CREAT, 0644)) >= 0)
    fail("the user created a file in root's private directory", fd);

  /* ...and so is removing root's things. */
  if ((r = sys6(SYS_unlinkat, AT_FDCWD, (long) "/priv", AT_REMOVEDIR, 0, 0, 0)) >= 0)
    fail("the user removed root's directory", r);

  /* access(2) must agree with what open actually does, rather than answering
   * for the host account as it used to. */
  if ((r = sys6(SYS_faccessat, AT_FDCWD, (long) "/priv/inside", R_OK, 0, 0, 0)) >= 0)
    fail("access() said a private file was readable", r);
  if ((r = sys6(SYS_faccessat, AT_FDCWD, (long) "/mine/f", W_OK, 0, 0, 0)) < 0)
    fail("access() said the user's own file was not writable", r);

  /* Changing the mode of somebody else's file is EPERM, not EACCES. */
  if ((r = sys6(SYS_fchmodat, AT_FDCWD, (long) "/priv", 0777, 0, 0, 0)) >= 0)
    fail("the user chmodded root's directory", r);

  put("perm ok\n");
  return 0;
}
