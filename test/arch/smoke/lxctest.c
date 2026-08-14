/* freestanding: the LXC-facing gaps in one pass.
 *
 *   - mknodat for a character node makes a placeholder whose stat reports
 *     S_IFCHR with the right rdev, and whose open answers ENXIO - the answer
 *     Linux gives for a node with no driver present.
 *   - a devtmpfs mount is backed by the host's /dev, so a container mounting
 *     its own /dev reaches the real devices (checked with /dev/null).
 *   - a binderfs mount is a real type and answers with /dev/binderfs, whose
 *     control file opens.
 *   - writing to cgroup.subtree_control is refused with EINVAL rather than
 *     landing in the host's empty file and reporting success.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_mkdirat    34
#define SYS_unlinkat   35
#define SYS_openat     56
#define SYS_close      57
#define SYS_write      64
#define SYS_exit       93
#define SYS_mknodat    33
#define SYS_mount      40
#define SYS_umount2    39
#define SYS_fstatat    79

#define AT_FDCWD   -100
#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2

#define ENXIO     6
#define EINVAL   22
#define EEXIST   17
#define EACCES   13

#define S_IFMT   0170000
#define S_IFCHR  0020000
#define S_IFREG  0100000

#define MS_BIND  4096

struct linux_stat {
  unsigned long st_dev, st_ino;
  unsigned int  st_mode, st_nlink;
  unsigned int  st_uid, st_gid;
  unsigned long st_rdev;
  unsigned long __pad1;
  long          st_size;
  int           st_blksize;
  int           __pad2;
  long          st_blocks;
  long          st_atim_sec, st_atim_nsec;
  long          st_mtim_sec, st_mtim_nsec;
  long          st_ctim_sec, st_ctim_nsec;
  long          __unused[2];
};

#define makedev(maj, min) (((maj) << 8) | (min))
#define major(dev)        ((dev) >> 8)
#define minor(dev)        ((dev) & 0xff)

static long write_all(int fd, const char *s, long n) {
  return sys6(SYS_write, fd, (long) s, n, 0, 0, 0);
}
static long strlen(const char *s) { long n = 0; while (s[n]) n++; return n; }

static int failed;

static void fail(const char *what, long got) {
  failed = 1;
  write_all(2, what, strlen(what));
  write_all(2, " fail got=", 10);
  {
    char b[32]; int n = 0; long v = got;
    if (v < 0) { b[n++] = '-'; v = -v; }
    if (v == 0) b[n++] = '0';
    char t[32]; int m = 0;
    while (v) { t[m++] = (char)('0' + v % 10); v /= 10; }
    while (m) b[n++] = t[--m];
    b[n] = '\n';
    write_all(2, b, n);
  }
}

static long puts(const char *s) { return write_all(1, s, strlen(s)); }

static void _cleanup(void);

int main(void) {
  puts("lxctest start\n");
  /* mknod a character node and check stat reports it truthfully. */
  long r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/dn", 0700, 0, 0, 0);
  if (r < 0) fail("mkdir /dn", r);
  r = sys6(SYS_mknodat, AT_FDCWD, (long) "/dn/c", S_IFCHR | 0600, makedev(1, 3), 0, 0);
  if (r < 0) fail("mknod char", r);
  struct linux_stat st;
  long acc = 0;
  r = sys6(SYS_fstatat, AT_FDCWD, (long) "/dn/c", (long) &st, 0, 0, 0);
  if (r < 0) fail("fstatat node", r);
  if ((st.st_mode & S_IFMT) != S_IFCHR) fail("node reports S_IFCHR", st.st_mode);
  if (st.st_rdev != makedev(1, 3)) fail("node reports rdev", st.st_rdev);
  if (major(st.st_rdev) != 1 || minor(st.st_rdev) != 3) fail("node rdev split", st.st_rdev);
  r = sys6(SYS_openat, AT_FDCWD, (long) "/dn/c", O_RDWR, 0, 0, 0);
  if (r != -ENXIO) fail("open node ENXIO", r);
  if (r >= 0) sys6(SYS_close, r, 0, 0, 0, 0, 0);

  /* mknod over the same path is EEXIST, as Linux says. */
  r = sys6(SYS_mknodat, AT_FDCWD, (long) "/dn/c", S_IFCHR | 0600, makedev(1, 3), 0, 0);
  if (r != -EEXIST) fail("mknod EEXIST", r);

  /* a FIFO still works. */
  r = sys6(SYS_mknodat, AT_FDCWD, (long) "/dn/f", 0010000 | 0600, 0, 0, 0);
  if (r < 0) fail("mknod fifo", r);

  /* a devtmpfs mount reaches the host's /dev. */
  r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/devmnt", 0700, 0, 0, 0);
  if (r < 0) fail("mkdir /devmnt", r);
  r = sys6(SYS_mount, (long) "devtmpfs", (long) "/devmnt", (long) "devtmpfs", 0, 0, 0);
  if (r < 0) fail("mount devtmpfs", r);
  r = sys6(SYS_openat, AT_FDCWD, (long) "/devmnt/null", O_RDONLY, 0, 0, 0);
  if (r < 0) fail("open /devmnt/null", r);
  if (r >= 0) sys6(SYS_close, r, 0, 0, 0, 0, 0);
  r = sys6(SYS_fstatat, AT_FDCWD, (long) "/devmnt/null", (long) &st, 0, 0, 0);
  if (r < 0) fail("fstatat /devmnt/null", r);
  if ((st.st_mode & S_IFMT) != S_IFCHR) fail("/devmnt/null reports S_IFCHR", st.st_mode);

  /* binderfs is a mount type, answered with the real control files. The host
   * keeps binder-control root-only, so a guest that is not root gets EACCES -
   * which still proves the mount resolved (a broken mount would give ENOENT or
   * ENOTDIR). */
  r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/bfs", 0700, 0, 0, 0);
  if (r < 0) fail("mkdir /bfs", r);
  r = sys6(SYS_mount, (long) "none", (long) "/bfs", (long) "binderfs", 0, 0, 0);
  if (r < 0) fail("mount binderfs", r);
  r = sys6(SYS_openat, AT_FDCWD, (long) "/bfs/binder-control", O_RDWR, 0, 0, 0);
  if (r < 0 && r != -EACCES) fail("open /bfs/binder-control", r);
  if (r >= 0) sys6(SYS_close, r, 0, 0, 0, 0, 0);

  /* devpts is a mount type too; the slave rewrite needs a pty so this only
   * checks that the mount itself lands. */
  r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/pts", 0700, 0, 0, 0);
  if (r < 0) fail("mkdir /pts", r);
  r = sys6(SYS_mount, (long) "devpts", (long) "/pts", (long) "devpts", 0, 0, 0);
  if (r < 0) fail("mount devpts", r);

  /* cgroup.subtree_control refuses writes. */
  r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/cg", 0700, 0, 0, 0);
  if (r < 0) fail("mkdir /cg", r);
  r = sys6(SYS_mount, (long) "cgroup2", (long) "/cg", (long) "cgroup2", 0, 0, 0);
  if (r < 0) fail("mount cgroup2", r);
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/cg/cgroup.subtree_control", O_WRONLY, 0, 0, 0);
  if (fd < 0) fail("open subtree_control", fd);
  r = sys6(SYS_write, fd, (long) "+memory", 7, 0, 0, 0);
  if (r != -EINVAL) fail("write subtree_control EINVAL", r);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);

  if (failed) { puts("lxctest FAIL\n"); _cleanup(); return 1; }
  puts("lxctest ok\n");
  _cleanup();
  return 0;
}

/* Mounts made here live in nabi's mount namespace for the rest of the boot,
 * exactly as they would on a real kernel. Tear them down so a later run of
 * this or another guest does not inherit them. */
static void _cleanup(void) {
  static const char *t[] = { "/devmnt", "/bfs", "/pts", "/cg" };
  for (int i = 0; i < 4; i++)
    sys6(SYS_umount2, (long) t[i], 0, 0, 0, 0, 0);
}
