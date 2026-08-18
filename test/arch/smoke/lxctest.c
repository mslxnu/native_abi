/* freestanding: the LXC-facing gaps in one pass.
 *
 *   - mknodat for a character node makes a placeholder whose stat reports
 *     S_IFCHR with the right rdev, and whose open reaches the host's device
 *     when the numbers name one - a node made with 1:3 is /dev/null on Linux
 *     and has to behave like it, which is what Android's init makes and then
 *     uses. A node naming a device nothing has is still ENXIO, the answer
 *     Linux gives for a node with no driver present.
 *   - a devtmpfs mount is backed by the host's /dev, so a container mounting
 *     its own /dev reaches the real devices (checked with /dev/null).
 *   - a binderfs mount is a real type and answers with /dev/binderfs, whose
 *     control file opens.
 *   - writing to cgroup.subtree_control is refused with EINVAL rather than
 *     landing in the host's empty file and reporting success.
 *   - /proc/self/task describes the *guest's* threads, and /proc/self/status
 *     agrees with it. The host's answer is nabi's own threads, and LXC refuses
 *     to start a foreground container from a threaded process - which is what
 *     `lxc-start -F` is, and what waydroid runs.
 *   - openat2 honours the resolve restrictions it can answer and refuses the
 *     rest. LXC opens /sys/fs/cgroup with NO_MAGICLINKS|NO_SYMLINKS and pins
 *     the container rootfs with those plus NO_XDEV|BENEATH, and treats either
 *     refusal as fatal, so refusing all of them stopped every container.
 *   - /proc/<pid>/cgroup answers for a pid that is not the caller. LXC reads
 *     /proc/1/cgroup to learn the cgroup layout before it will start anything,
 *     and got ENOENT because pid 1 is somebody else.
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
#define SYS_getdents64 61
#define SYS_read       63
#define SYS_openat2   437
#define SYS_symlinkat  36

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
#define ELOOP    40
#define O_DIRECTORY 0x4000
#define O_PATH   0x200000
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_IN_ROOT       0x10
#define EXDEV    18

struct open_how { unsigned long long flags, mode, resolve; };

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
  /* 1:3 is /dev/null, and a node carrying those numbers is that device: a
   * write is swallowed whole and a read is immediately end-of-file. */
  r = sys6(SYS_openat, AT_FDCWD, (long) "/dn/c", O_RDWR, 0, 0, 0);
  if (r < 0) fail("open 1:3 node", r);
  {
    long nfd = r;
    char b1[4];
    r = sys6(SYS_write, nfd, (long) "abcd", 4, 0, 0, 0);
    if (r != 4) fail("write to 1:3 node", r);
    r = sys6(SYS_read, nfd, (long) b1, sizeof b1, 0, 0, 0);
    if (r != 0) fail("read of 1:3 node is EOF", r);
    sys6(SYS_close, nfd, 0, 0, 0, 0, 0);
  }

  /* And a node whose numbers name nothing is still ENXIO. */
  r = sys6(SYS_mknodat, AT_FDCWD, (long) "/dn/nodev", S_IFCHR | 0600,
           makedev(200, 1), 0, 0);
  if (r < 0) fail("mknod nodev", r);
  r = sys6(SYS_openat, AT_FDCWD, (long) "/dn/nodev", O_RDWR, 0, 0, 0);
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

  /*
   * The guest's own threads, not nabi's.
   *
   * Counted by reading the directory, which is what LXC's am_single_threaded
   * does; a count of anything but one here is what made it refuse to start a
   * foreground container. /proc/self/status has to agree, or two files describe
   * the same process differently - which they did, because one was nabi's and
   * one was the guest's.
   */
  {
    long d = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/task",
                  O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (d < 0) {
      fail("open /proc/self/task", d);
    } else {
      static char dbuf[4096];
      long n = sys6(SYS_getdents64, d, (long) dbuf, sizeof dbuf, 0, 0, 0);
      sys6(SYS_close, d, 0, 0, 0, 0, 0);
      int count = 0;
      for (long off = 0; off < n; ) {
        /* struct linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) name */
        unsigned short reclen = *(unsigned short *) (dbuf + off + 16);
        const char *nm = dbuf + off + 19;
        if (!(nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))))
          count++;
        if (reclen == 0) break;
        off += reclen;
      }
      if (count != 1)
        fail("threads the guest is told it has", count);
    }

    long sf = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/status", O_RDONLY, 0, 0, 0);
    if (sf < 0) {
      fail("open /proc/self/status", sf);
    } else {
      static char sbuf[8192];
      long n = sys6(SYS_read, sf, (long) sbuf, sizeof sbuf - 1, 0, 0, 0);
      sys6(SYS_close, sf, 0, 0, 0, 0, 0);
      if (n > 0) {
        sbuf[n] = '\0';
        int threads = -1;
        for (long i = 0; i + 8 < n; i++)
          if (sbuf[i] == 'T' && sbuf[i+1] == 'h' && sbuf[i+2] == 'r' &&
              sbuf[i+3] == 'e' && sbuf[i+4] == 'a' && sbuf[i+5] == 'd' &&
              sbuf[i+6] == 's' && sbuf[i+7] == ':') {
            long j = i + 8;
            while (sbuf[j] == ' ' || sbuf[j] == '\t') j++;
            threads = 0;
            while (sbuf[j] >= '0' && sbuf[j] <= '9')
              threads = threads * 10 + (sbuf[j++] - '0');
            break;
          }
        if (threads != 1)
          fail("Threads: in /proc/self/status", threads);
      }
    }
  }

  /*
   * openat2's resolve restrictions.
   *
   * The two that are questions about a path are answered; a symlink in the way
   * is ELOOP, exactly where Linux would say so. The ones that need a guarantee
   * nabi cannot make are still refused, because a caller can recover from that
   * and cannot recover from being told a restriction was applied when it was
   * not.
   */
  {
    struct open_how how;
    how.flags = O_RDONLY | O_DIRECTORY | O_PATH;
    how.mode = 0;
    how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    long f = sys6(SYS_openat2, AT_FDCWD, (long) "/cg", (long) &how, sizeof how, 0, 0);
    if (f < 0)
      fail("openat2 of a plain directory with NO_SYMLINKS", f);
    else
      sys6(SYS_close, f, 0, 0, 0, 0, 0);

    /* A symlink in the path is refused, and refused as ELOOP. */
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/cglink", 0, 0, 0, 0);
    r = sys6(SYS_symlinkat, (long) "/cg", AT_FDCWD, (long) "/cglink", 0, 0, 0);
    if (r == 0) {
      f = sys6(SYS_openat2, AT_FDCWD, (long) "/cglink", (long) &how, sizeof how, 0, 0);
      if (f != -ELOOP) {
        fail("openat2 of a symlink with NO_SYMLINKS", f);
        if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
      }
      sys6(SYS_unlinkat, AT_FDCWD, (long) "/cglink", 0, 0, 0, 0);
    }

    /*
     * BENEATH and NO_XDEV, which LXC asks for together with the other two when
     * it pins a rootfs. BENEATH is enforceable once symlinks are excluded: it
     * becomes the absence of ".." and of a leading slash.
     */
    long dir = sys6(SYS_openat, AT_FDCWD, (long) "/cg", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (dir < 0) {
      fail("open /cg as a directory", dir);
    } else {
      /* A file, so the directory flag from the check above has to go. */
      how.flags = O_RDONLY;
      how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS |
                    RESOLVE_NO_XDEV | RESOLVE_BENEATH;
      f = sys6(SYS_openat2, dir, (long) "cgroup.procs", (long) &how, sizeof how, 0, 0);
      if (f < 0)
        fail("openat2 beneath a directory with all four restrictions", f);
      else
        sys6(SYS_close, f, 0, 0, 0, 0, 0);

      /* Leaving is what BENEATH forbids, and EXDEV is what Linux says. */
      f = sys6(SYS_openat2, dir, (long) "../cg", (long) &how, sizeof how, 0, 0);
      if (f != -EXDEV) {
        fail("openat2 escaping with BENEATH", f);
        if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
      }
      f = sys6(SYS_openat2, dir, (long) "/cg", (long) &how, sizeof how, 0, 0);
      if (f != -EXDEV) {
        fail("openat2 given an absolute path with BENEATH", f);
        if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
      }

      /*
       * BENEATH on its own, which is how LXC asks. It does not need
       * NO_SYMLINKS: symlinks are followed and the result has to be inside,
       * which is what Linux does and what refusing this used to prevent - the
       * container stopped at its first mount because of it.
       */
      how.resolve = RESOLVE_BENEATH;
      f = sys6(SYS_openat2, dir, (long) "cgroup.procs", (long) &how, sizeof how, 0, 0);
      if (f < 0)
        fail("openat2 with BENEATH alone, as LXC asks", f);
      else
        sys6(SYS_close, f, 0, 0, 0, 0, 0);

      /* Escaping is still refused with it alone. */
      f = sys6(SYS_openat2, dir, (long) "../cg", (long) &how, sizeof how, 0, 0);
      if (f != -EXDEV) {
        fail("openat2 escaping with BENEATH alone", f);
        if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
      }

      /*
       * And a symlink that leads out, which is the case the string cannot
       * answer: ".." and a leading slash are visible in the path, a symlink is
       * not. It is caught by asking where the descriptor landed, so this is
       * what checks that the asking happens at all.
       */
      sys6(SYS_mkdirat, AT_FDCWD, (long) "/bdir", 0755, 0, 0, 0);
      sys6(SYS_unlinkat, AT_FDCWD, (long) "/bdir/out", 0, 0, 0, 0);
      if (sys6(SYS_symlinkat, (long) "/", AT_FDCWD, (long) "/bdir/out", 0, 0, 0) == 0) {
        long bd = sys6(SYS_openat, AT_FDCWD, (long) "/bdir", O_RDONLY | O_DIRECTORY, 0, 0, 0);
        if (bd >= 0) {
          how.flags = O_RDONLY | O_DIRECTORY;
          how.resolve = RESOLVE_BENEATH;
          f = sys6(SYS_openat2, bd, (long) "out", (long) &how, sizeof how, 0, 0);
          if (f != -EXDEV) {
            fail("openat2 following a symlink out with BENEATH", f);
            if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
          }
          sys6(SYS_close, bd, 0, 0, 0, 0, 0);
        }
        sys6(SYS_unlinkat, AT_FDCWD, (long) "/bdir/out", 0, 0, 0, 0);
      }
      sys6(SYS_unlinkat, AT_FDCWD, (long) "/bdir", 0x200 /*AT_REMOVEDIR*/, 0, 0, 0);
      sys6(SYS_close, dir, 0, 0, 0, 0, 0);
    }

    /* One that still cannot be honoured is still refused. */
    how.resolve = RESOLVE_IN_ROOT;
    f = sys6(SYS_openat2, AT_FDCWD, (long) "/cg", (long) &how, sizeof how, 0, 0);
    if (f != -EINVAL) {
      fail("openat2 with a restriction nabi cannot keep", f);
      if (f >= 0) sys6(SYS_close, f, 0, 0, 0, 0, 0);
    }
  }

  /*
   * A /proc entry reached *relative to a descriptor*, which is how LXC reads
   * it: it holds "/" open and opens "proc/self/mountinfo" against it. The
   * entries nabi serves are recognised by name, and a relative path carries no
   * name - so this used to reach the rootfs's own empty /proc and answer
   * ENOENT while the absolute spelling opened.
   */
  {
    long root = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (root < 0) {
      fail("open /", root);
    } else {
      long f = sys6(SYS_openat, root, (long) "proc/self/mountinfo", O_RDONLY, 0, 0, 0);
      if (f < 0) {
        fail("opening proc/self/mountinfo relative to /", f);
      } else {
        static char mbuf[64];
        long n = sys6(SYS_read, f, (long) mbuf, sizeof mbuf - 1, 0, 0, 0);
        sys6(SYS_close, f, 0, 0, 0, 0, 0);
        /* And it is the real thing, not an empty file that happened to open. */
        if (n <= 0)
          fail("what the relative open read", n);
      }
      /* The same path with BENEATH, which is the form LXC actually uses. */
      { struct open_how h2;
        h2.flags = O_RDONLY; h2.mode = 0; h2.resolve = RESOLVE_BENEATH;
        long g = sys6(SYS_openat2, root, (long) "proc/self/mountinfo",
                      (long) &h2, sizeof h2, 0, 0);
        if (g < 0)
          fail("openat2 of proc/self/mountinfo with BENEATH", g);
        else
          sys6(SYS_close, g, 0, 0, 0, 0, 0); }
      sys6(SYS_close, root, 0, 0, 0, 0, 0);
    }
  }

  /*
   * /proc/1/cgroup: somebody else's, which is the one LXC reads. The content
   * is checked, not merely the open - a file that exists and is empty would
   * satisfy a check that only opened it, and tells the reader nothing.
   */
  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/1/cgroup", O_RDONLY, 0, 0, 0);
    if (f < 0) {
      fail("open /proc/1/cgroup", f);
    } else {
      static char cbuf[128];
      long n = sys6(SYS_read, f, (long) cbuf, sizeof cbuf - 1, 0, 0, 0);
      sys6(SYS_close, f, 0, 0, 0, 0, 0);
      if (n < 4)
        fail("what /proc/1/cgroup says", n);
      else if (!(cbuf[0] == '0' && cbuf[1] == ':' && cbuf[2] == ':' && cbuf[3] == '/'))
        fail("the cgroup v2 line for pid 1", cbuf[0]);
    }
  }

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
