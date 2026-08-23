/* freestanding: binderfs, the filesystem that makes binders.
 *
 * A device does not have one binder. It has three - /dev/binder for the
 * framework, /dev/hwbinder for HALs, /dev/vndbinder for vendor code - and they
 * are separate on purpose: handle 0 is a different object in each, so a
 * framework call and a vendor call cannot reach one another. binderfs is how
 * they come into being now, mounted by init and told what to create, instead
 * of being nodes the kernel brings with it.
 *
 * What is checked:
 *
 *   - a fresh binderfs has a control node and nothing else.
 *   - BINDERFS_CTL_ADD makes a device, which then exists in the directory.
 *     Both halves matter: a container lists the directory to see whether what
 *     it asked for is there, so a device that works but cannot be seen reads
 *     as a failed mount.
 *   - the devices it makes are real binders - they answer BINDER_VERSION.
 *   - and separate ones. Each takes its own context manager, which is the
 *     whole point: if two names were one binder the second registration would
 *     be refused, and the two would be able to see each other's objects.
 *   - /dev/binder and /dev/hwbinder are separate in the same way.
 *   - a name that is already taken is refused, and so is one that is not a
 *     name - a device called "../x" would be a file outside the mount.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_close 57
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_ioctl 29
#define SYS_getdents64 61
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_RDWR 2
#define O_DIRECTORY 0200000
#define EEXIST 17
#define EINVAL 22

#define BINDERFS_CTL_ADD           0xC1086201u
#define BINDER_VERSION             0xC0046209u
#define BINDER_SET_CONTEXT_MGR     0x40046207u

struct binderfs_device {
  char name[255 + 1];
  unsigned int major;
  unsigned int minor;
};
typedef char assert_bfsdev[sizeof(struct binderfs_device) == 264 ? 1 : -1];

struct linux_dirent64 {
  unsigned long  d_ino;
  long           d_off;
  unsigned short d_reclen;
  unsigned char  d_type;
  char           d_name[];
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if(got==expect)return;
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}
static void wantne(const char*what,long got,long unwanted){
  if(got!=unwanted)return;
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", wanted anything else\n");}
static int eq(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void cpy(char*d,const char*s){while((*d++=*s++));}
static void mzero(void*p,int n){unsigned char*q=p;while(n--)*q++=0;}

static int open_rw(const char *path)
{
  return (int) sys6(SYS_openat, AT_FDCWD, (long) path, O_RDWR, 0, 0, 0);
}

/* Does this directory hold a file of that name? */
static int listed(const char *dir, const char *name)
{
  char buf[4096];
  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long) dir, O_RDONLY|O_DIRECTORY, 0,0,0);
  if (fd < 0)
    return -1;
  int found = 0;
  for (;;) {
    long n = sys6(SYS_getdents64, fd, (long) buf, sizeof buf, 0, 0, 0);
    if (n <= 0)
      break;
    for (long off = 0; off < n; ) {
      struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
      if (eq(de->d_name, name))
        found = 1;
      off += de->d_reclen;
    }
  }
  sys6(SYS_close, fd, 0,0,0,0,0);
  return found;
}

/* Make a device, and say what minor it was given. */
static long ctl_add(int ctl, const char *name, unsigned int *minor)
{
  struct binderfs_device d;
  mzero(&d, sizeof d);
  cpy(d.name, name);
  long r = sys6(SYS_ioctl, ctl, BINDERFS_CTL_ADD, (long) &d, 0, 0, 0);
  if (r == 0 && minor != 0)
    *minor = d.minor;
  if (r == 0)
    wantne("the device was given a major", d.major, 0);
  return r;
}

/* Is this a binder, and can it be this binder's context manager? */
static void check_binder(const char *path, const char *what)
{
  unsigned int ver = 0;
  int zero = 0;
  int fd = open_rw(path);
  if (fd < 0) {
    fails++; put("  FAIL open "); put(path); put(": "); putd(fd); put("\n");
    return;
  }
  want("BINDER_VERSION", sys6(SYS_ioctl, fd, BINDER_VERSION, (long)&ver, 0,0,0), 0);
  wantne("the version is set", ver, 0);
  /*
   * Left open deliberately. Each of these is a different binder, so each has
   * a context manager of its own to give away - and a registration is only
   * proof of that while the one before it is still standing.
   */
  want(what, sys6(SYS_ioctl, fd, BINDER_SET_CONTEXT_MGR, (long)&zero, 0,0,0), 0);
}

void _start(void)
{
  unsigned int m_alpha = 0, m_beta = 0;

  sys6(SYS_mkdirat, AT_FDCWD, (long) "/bfs", 0755, 0, 0, 0);
  long r = sys6(SYS_mount, (long) "none", (long) "/bfs", (long) "binderfs", 0, 0, 0);
  want("mount binderfs", r, 0);

  int ctl = open_rw("/bfs/binder-control");
  if (ctl < 0) {
    put("  FAIL open /bfs/binder-control: "); putd(ctl); put("\n");
    put("binderfs failed\n");
    sys6(SYS_exit_group, 1, 0,0,0,0,0);
  }
  want("a fresh binderfs has no devices", listed("/bfs", "alpha"), 0);

  want("add alpha", ctl_add(ctl, "alpha", &m_alpha), 0);
  want("add beta",  ctl_add(ctl, "beta",  &m_beta), 0);
  wantne("the two devices are different nodes", m_alpha, m_beta);

  want("alpha is in the directory", listed("/bfs", "alpha"), 1);
  want("beta is in the directory",  listed("/bfs", "beta"), 1);

  want("a name already taken is refused", ctl_add(ctl, "alpha", 0), -EEXIST);
  want("a name that is a path is refused", ctl_add(ctl, "../escape", 0), -EINVAL);
  want("an empty name is refused", ctl_add(ctl, "", 0), -EINVAL);

  check_binder("/bfs/alpha", "alpha takes its own context manager");
  check_binder("/bfs/beta",  "beta takes its own context manager");
  check_binder("/dev/binder",   "/dev/binder takes its own context manager");
  check_binder("/dev/hwbinder", "/dev/hwbinder takes its own context manager");

  sys6(SYS_close, ctl, 0,0,0,0,0);
  if (fails == 0)
    put("binderfs ok\n");
  else
    put("binderfs failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
