/* freestanding: statx and fstatat accept AT_EMPTY_PATH.
 *
 * An empty pathname with AT_EMPTY_PATH names the descriptor itself, which may
 * be any kind of file rather than a directory. It is not an obscure corner:
 * Rust's standard library stats every file it opens as
 * statx(fd, "", AT_EMPTY_PATH), so it is on the path of any Rust program that
 * reads a file.
 *
 * NABI routed both syscalls through vfs_grab_dir, which rejects an empty name
 * with ENOENT. sqv - the OpenPGP verifier apt shells out to - opened apt's
 * signature file successfully, got ENOENT from the stat that followed, and
 * reported "Reading /tmp/apt.sig.XXXXXX: No such file or directory" about a
 * descriptor it was already holding. apt read that as the Debian archive being
 * unsigned, so nothing could be installed from a signed repository at all. The
 * error named the right file and the wrong reason, which is why it lasted.
 *
 * The check is that the answer matches fstat on the same descriptor, not just
 * that the call returns 0: a stat of the wrong object would also succeed.
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
#define SYS_fstat 80
#define SYS_newfstatat 79
#define SYS_statx 291
#define SYS_unlinkat 35
#define AT_FDCWD -100
#define AT_EMPTY_PATH 0x1000
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000

/* Only the fields compared below are named; the rest is padding to the real
 * size so the kernel has somewhere to write. */
struct lstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long times[6]; unsigned pad3[2]; };
struct lstatx { unsigned mask, blksize; unsigned long attr; unsigned nlink, uid, gid;
                unsigned short mode, pad1; unsigned long ino, size, blocks, attr_mask;
                unsigned long times[8]; unsigned rdev_major, rdev_minor,
                dev_major, dev_minor; unsigned long spare[14]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long rc)
{
  put("emptypath FAIL: "); put(what); put(" -> "); putd(rc); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

void _start(void)
{
  static const char msg[] = "0123456789abcdef";
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/emptypath.tmp",
                 O_WRONLY|O_CREAT|O_TRUNC, 0644, 0, 0);
  if (fd < 0) fail("create", fd);
  sys6(SYS_write, fd, (long) msg, sizeof msg - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);

  fd = sys6(SYS_openat, AT_FDCWD, (long) "/emptypath.tmp", O_RDONLY, 0, 0, 0);
  if (fd < 0) fail("reopen", fd);

  /* The answer everything else is measured against. */
  struct lstat ref;
  long r = sys6(SYS_fstat, fd, (long) &ref, 0, 0, 0, 0);
  if (r < 0) fail("fstat", r);
  if (ref.size != sizeof msg - 1) fail("fstat reported the wrong size", (long) ref.size);

  /* statx(fd, "", AT_EMPTY_PATH) - the form Rust uses. */
  struct lstatx sx;
  for (unsigned i = 0; i < sizeof sx / sizeof(unsigned long); i++)
    ((unsigned long *) &sx)[i] = 0;
  r = sys6(SYS_statx, fd, (long) "", AT_EMPTY_PATH, 0xfff, (long) &sx, 0);
  if (r < 0) fail("statx AT_EMPTY_PATH", r);
  if (sx.ino != ref.ino) fail("statx AT_EMPTY_PATH found a different inode", (long) sx.ino);
  if (sx.size != (unsigned long) ref.size) fail("statx AT_EMPTY_PATH size", (long) sx.size);

  /* fstatat(fd, "", AT_EMPTY_PATH) - the same idea, older spelling. */
  struct lstat st;
  r = sys6(SYS_newfstatat, fd, (long) "", (long) &st, AT_EMPTY_PATH, 0, 0);
  if (r < 0) fail("fstatat AT_EMPTY_PATH", r);
  if (st.ino != ref.ino) fail("fstatat AT_EMPTY_PATH found a different inode", (long) st.ino);
  if (st.size != ref.size) fail("fstatat AT_EMPTY_PATH size", (long) st.size);

  /* Without the flag an empty path is still ENOENT, so the fix cannot be
   * "treat every empty path as the descriptor". */
  r = sys6(SYS_newfstatat, fd, (long) "", (long) &st, 0, 0, 0);
  if (r >= 0) fail("empty path without AT_EMPTY_PATH should fail", r);

  /* AT_FDCWD with an empty path is the working directory, not a descriptor. */
  r = sys6(SYS_newfstatat, AT_FDCWD, (long) "", (long) &st, AT_EMPTY_PATH, 0, 0);
  if (r < 0) fail("AT_FDCWD AT_EMPTY_PATH", r);

  sys6(SYS_close, fd, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/emptypath.tmp", 0, 0, 0, 0);
  put("emptypath ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
