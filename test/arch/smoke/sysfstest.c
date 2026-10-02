/* freestanding: the parts of /sys nabi answers for itself.
 *
 * mSL/SysFS is on its way out and on this machine was never in, so /sys was
 * whatever the rootfs image had at that name - an empty read-only directory - and
 * every question about it was ENOENT. One Android boot asks 30,080 and is refused
 * 5,167 times, and the refusals are not equal: init opens /sys/class/udc 1,721
 * times from one thread, waiting for a USB device controller before it will set up
 * the gadget. A core spent on a question whose answer cannot change, which is the
 * shape logd's old spin on /proc/kmsg had.
 *
 * What is checked is both halves of each answer: that the entries are there, and
 * that the ones deliberately left out are still out - a trace_marker would turn
 * Android's tracing on to write into something that traces nothing, and a
 * /sys/power/state would have it believe the device had suspended.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_getdents64 61
#define SYS_newfstatat 79
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define SYS_socket 198
#define SYS_ioctl 29
#define AF_INET 2
#define SOCK_DGRAM 2
#define SIOCGIFINDEX 0x8933
#define O_DIRECTORY 0200000
#define S_IFMT  0170000
#define S_IFDIR 0040000

#define THP "/sys/kernel/mm/transparent_hugepage/enabled"

struct ltimespec { long long tv_sec; long long tv_nsec; };
struct lstat {
  unsigned long long st_dev, st_ino;
  unsigned st_mode, st_nlink, st_uid, st_gid;
  unsigned long long st_rdev, __pad1;
  long long st_size;
  int st_blksize, __pad2;
  long long st_blocks;
  struct ltimespec st_atim, st_mtim, st_ctim;
};
struct linux_dirent64 {
  unsigned long  d_ino;
  long           d_off;
  unsigned short d_reclen;
  unsigned char  d_type;
  char           d_name[];
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int fails;
static void bad(const char *what, const char *why)
{ fails++; put("  FAIL "); put(what); put(": "); put(why); put("\n"); }
static int eq(const char*a,const char*b)
{ int i=0; for(;a[i]&&b[i];i++) if(a[i]!=b[i]) return 0; return a[i]==b[i]; }
static int eqn(const char*a,const char*b,int n)
{ for(int i=0;i<n;i++) if(a[i]!=b[i]) return 0; return 1; }
static int find(const char*h,int hn,const char*nd,int nn)
{ for(int i=0;i+nn<=hn;i++) if(eqn(h+i,nd,nn)) return 1; return 0; }
static int slen(const char*s){int i=0;while(s[i])i++;return i;}

static void must_be_dir(const char *path)
{
  struct lstat st;
  long r = sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &st, 0, 0, 0);
  if (r != 0) {
    bad(path, r == -2 ? "is not there (ENOENT)"
             : r == -13 ? "is there but refused (EACCES)"
             : "is not there");
    return;
  }
  if ((st.st_mode & S_IFMT) != S_IFDIR)
    bad(path, "is not a directory");
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY | O_DIRECTORY, 0,0,0);
  if (fd < 0) bad(path, "stats as a directory but will not open as one");
  else sys6(SYS_close, fd, 0,0,0,0,0);
}

static void must_be_absent(const char *path)
{
  struct lstat st;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &st, 0, 0, 0) == 0)
    bad(path, "exists, and was meant not to");
}

/* Counts the entries of a directory, and optionally requires one by name. */
static int listing(const char *dir, const char *want)
{
  static char buf[8192];
  int n_entries = 0, found = 0;
  long fd = sys6(SYS_openat, AT_FDCWD, (long) dir, O_RDONLY | O_DIRECTORY, 0,0,0);
  if (fd < 0) return -1;
  for (;;) {
    long n = sys6(SYS_getdents64, fd, (long) buf, sizeof buf, 0, 0, 0);
    if (n <= 0) break;
    for (long off = 0; off < n; ) {
      struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
      if (de->d_name[0] != '.') {
        n_entries++;
        if (want && eq(de->d_name, want)) found = 1;
      }
      off += de->d_reclen;
    }
  }
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (want && !found) return -2;
  return n_entries;
}

static long slurp(const char *path, char *buf, int cap)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return -1;
  long n = sys6(SYS_read, fd, (long) buf, cap - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n < 0) return -1;
  buf[n] = 0;
  return n;
}

void _start(void)
{
  static char buf[4096], buf2[4096];

  /*
   * The spin. An empty directory is the whole fix: it exists, so init stops
   * asking, and it holds nothing, which is the truth about a Mac.
   */
  must_be_dir("/sys/class/udc");
  {
    int n = listing("/sys/class/udc", 0);
    if (n < 0) bad("/sys/class/udc", "will not list");
    else if (n != 0) bad("/sys/class/udc", "claims a device controller exists");
  }

  /* And /sys itself lists what is under it. A directory a guest can enter and
   * cannot see is the same disagreement /proc's stat and open used to have. */
  for (int i = 0; i < 4; i++) {
    const char *want[] = { "class", "fs", "kernel", "power" };
    if (listing("/sys", want[i]) == -2) bad("/sys", "its listing is missing an entry it serves");
  }

  must_be_dir("/sys/class");
  must_be_dir("/sys/kernel");
  must_be_dir("/sys/kernel/mm");
  must_be_dir("/sys/kernel/mm/transparent_hugepage");
  must_be_dir("/sys/power");
  /* Both spellings, because atrace probes both. */
  must_be_dir("/sys/kernel/tracing");
  must_be_dir("/sys/kernel/debug/tracing");

  /*
   * The brackets mark the setting in force, and never is in force: there are no
   * huge pages here to collapse into. Saying "always" would have a guest expect
   * its madvise(MADV_HUGEPAGE) to mean something.
   */
  if (slurp(THP, buf, sizeof buf) <= 0) {
    bad(THP, "will not read");
  } else {
    if (!find(buf, slen(buf), "[never]", 7))
      bad(THP, "does not report huge pages as off");
    /*
     * A root guest's write to it lands - it cannot be refused through a host mode,
     * and refusing it properly needs the write diverted the way /proc's writable
     * entries are. What must hold is that it does not persist, so the next reader
     * is told what is true rather than what the file was last told.
     */
    long fd = sys6(SYS_openat, AT_FDCWD, (long) THP, O_WRONLY, 0, 0, 0);
    if (fd >= 0) {
      sys6(SYS_write, fd, (long) "always\n", 7, 0, 0, 0);
      sys6(SYS_close, fd, 0,0,0,0,0);
    }
    if (slurp(THP, buf2, sizeof buf2) <= 0)
      bad(THP, "stopped reading after a write");
    else if (!find(buf2, slen(buf2), "[never]", 7))
      bad(THP, "a write to it stuck, so it now reports huge pages that do not exist");
  }

  /*
   * Deliberately absent. trace_marker would turn Android's tracing on to write
   * into something that traces nothing; /sys/power/state would have it believe
   * the device suspended, because a write would land in a real file and succeed.
   */
  must_be_absent("/sys/kernel/tracing/trace_marker");
  must_be_absent("/sys/kernel/debug/tracing/trace_marker");
  must_be_absent("/sys/power/state");

  /*
   * And the cgroup hierarchy is still the real one. /sys/fs/cgroup is a directory
   * in this tree only so that a listing of /sys/fs shows it; what is inside it
   * belongs to the hierarchy nabi keeps, and an empty placeholder served in its
   * place would take every cgroup with it.
   */
  if (listing("/sys/fs", "cgroup") == -2)
    bad("/sys/fs", "does not list cgroup");
  if (listing("/sys/fs/cgroup", "cgroup.procs") == -2)
    bad("/sys/fs/cgroup", "is the empty placeholder rather than the real hierarchy");

  /*
   * /sys/class/net: one directory per interface, and the same set netlink reports.
   *
   * Asked 40 times a boot as a directory and never as a file, because the list of
   * names is what a caller wants from it first. An empty directory would have been
   * worse than an absent one - it would say the machine has no interfaces while
   * netlink lists them - so what is checked is that the names are there and that
   * each one's ifindex is the number the rest of nabi gives for that name.
   */
  must_be_dir("/sys/class/net");
  {
    static char nbuf[8192];
    int nifs = 0;
    long dfd = sys6(SYS_openat, AT_FDCWD, (long) "/sys/class/net",
                    O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (dfd < 0) {
      bad("/sys/class/net", "will not list");
    } else {
      long sock = sys6(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
      for (;;) {
        long n = sys6(SYS_getdents64, dfd, (long) nbuf, sizeof nbuf, 0, 0, 0);
        if (n <= 0) break;
        for (long off = 0; off < n; ) {
          struct linux_dirent64 *de = (struct linux_dirent64 *)(nbuf + off);
          off += de->d_reclen;
          if (de->d_name[0] == '.') continue;
          nifs++;

          /* Every attribute Linux puts there has to be readable; a caller that
           * enumerates and then reads one must not meet an ENOENT. */
          static const char *const want[] = { "address", "addr_len", "ifindex",
                                              "mtu", "flags", "type",
                                              "operstate", "carrier" };
          char p2[160], val[64];
          long ifindex = -1;
          for (int k = 0; k < 8; k++) {
            int i2 = 0;
            const char *pre = "/sys/class/net/";
            for (int j = 0; pre[j]; j++) p2[i2++] = pre[j];
            for (int j = 0; de->d_name[j]; j++) p2[i2++] = de->d_name[j];
            p2[i2++] = '/';
            for (int j = 0; want[k][j]; j++) p2[i2++] = want[k][j];
            p2[i2] = 0;
            long r2 = slurp(p2, val, sizeof val);
            if (r2 <= 0) { bad(p2, "will not read"); continue; }
            if (k == 2) {
              ifindex = 0;
              for (int j = 0; val[j] >= '0' && val[j] <= '9'; j++)
                ifindex = ifindex * 10 + (val[j] - '0');
            }
          }

          /*
           * And the index agrees with what an ioctl says for the same name. This is
           * the invariant the whole arrangement rests on: /sys/class/net is built
           * from the same walk netlink's link dump uses, so a guest that enumerates
           * here and then asks about one of them - which is what Java's
           * NetworkInterface does - cannot be told two different stories.
           */
          if (sock >= 0 && ifindex > 0) {
            char ifr[40];
            for (int j = 0; j < 40; j++) ifr[j] = 0;
            for (int j = 0; de->d_name[j] && j < 15; j++) ifr[j] = de->d_name[j];
            if (sys6(SYS_ioctl, sock, SIOCGIFINDEX, (long) ifr, 0, 0, 0) == 0) {
              long got = *(int *)(ifr + 16);
              if (got != ifindex)
                bad(de->d_name, "its ifindex here is not the one the ioctl gives");
            }
          }
        }
      }
      if (sock >= 0) sys6(SYS_close, sock, 0,0,0,0,0);
      sys6(SYS_close, dfd, 0,0,0,0,0);
      /* There is always a loopback, so an empty listing means the walk failed
       * rather than that the machine has no interfaces. */
      if (nifs == 0)
        bad("/sys/class/net", "lists no interface at all");
    }
  }

  /*
   * And nothing in /sys may be created, which a real host directory would
   * otherwise allow. Android made /sys/power/state and
   * /sys/kernel/tracing/tracing_on inside this tree, where they persisted and
   * changed what /sys said from one boot to the next - the state file this
   * deliberately does not serve existed by the second run.
   */
  {
    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/sys/power/state",
                   O_WRONLY | 0100 /* O_CREAT */, 0644, 0, 0);
    if (fd >= 0) {
      sys6(SYS_close, fd, 0,0,0,0,0);
      bad("/sys/power/state", "could be created, so the tree is not read-only");
    }
  }

  put(fails == 0 ? "sysfs ok\n" : "sysfs failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
