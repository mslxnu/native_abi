/* freestanding: /proc's directories, and the rule that open and stat agree.
 *
 * procfs used to answer open for far more of /proc than it answered stat for -
 * deliberately, because "most of /proc is the host's" and mSL/ProcFS stat'd the
 * rest. With the kext gone that left the two halves contradicting each other
 * about the same path: /proc/self/status read perfectly while `[ -e ]` of it was
 * false, and /proc/2/status opened while a stat of /proc/2 was ENOENT. procps
 * stats before it reads, so `ps aux` died with "fatal library error, lookup
 * self" even though every file it wanted could be opened by name.
 *
 * So the invariant under test is not any file's contents - procmachinetest has
 * those - but that a path nabi will open is a path nabi admits exists, and that
 * the directories report themselves as directories.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_openat 56
#define SYS_getdents64 61
#define SYS_newfstatat 79
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_DIRECTORY 0200000
#define S_IFMT   0170000
#define S_IFDIR  0040000

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

/* The whole point: whatever opens must also stat. */
static void agree(const char *path, int wantdir)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path,
                 wantdir ? (O_RDONLY | O_DIRECTORY) : O_RDONLY, 0, 0, 0);
  if (fd < 0)
    return;                       /* not served at all here - not this test's business */
  sys6(SYS_close, fd, 0,0,0,0,0);

  struct lstat st;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &st, 0, 0, 0) != 0) {
    bad(path, "opens but does not stat");
    return;
  }
  int isdir = (st.st_mode & S_IFMT) == S_IFDIR;
  if (wantdir && !isdir)
    bad(path, "stats as something other than a directory");
  if (!wantdir && isdir)
    bad(path, "stats as a directory");
}

static int lists(const char *dir, const char *name)
{
  static char buf[8192];
  long fd = sys6(SYS_openat, AT_FDCWD, (long) dir, O_RDONLY | O_DIRECTORY, 0,0,0);
  if (fd < 0)
    return 0;
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

void _start(void)
{
  /* The directories. /proc itself was whatever the rootfs had at that name - an
   * empty directory - so nothing enumerating processes found any. */
  agree("/proc", 1);
  agree("/proc/self", 1);
  agree("/proc/self/fd", 1);
  agree("/proc/self/task", 1);
  agree("/proc/self/ns", 1);

  /* The files. Every one of these could be read before and none of them could
   * be stat'd, which is the bug this test exists for. */
  agree("/proc/self/status", 0);
  agree("/proc/self/stat", 0);
  agree("/proc/self/cmdline", 0);
  agree("/proc/self/comm", 0);
  agree("/proc/self/maps", 0);
  agree("/proc/self/mounts", 0);
  agree("/proc/self/mountinfo", 0);
  agree("/proc/self/cgroup", 0);
  agree("/proc/mounts", 0);
  agree("/proc/net/dev", 0);
  agree("/proc/sysvipc/shm", 0);
  agree("/proc/sys/kernel/ngroups_max", 0);
  agree("/proc/sys/kernel/random/uuid", 0);
  agree("/proc/self/attr/current", 0);

  /* And a listing of /proc has to contain at least this process, by the name
   * every tool reaches it with. Without this `ps` printed a header and nothing
   * under it. */
  if (!lists("/proc", "self"))
    bad("/proc", "its own listing has no self");

  put(fails == 0 ? "procdir ok\n" : "procdir failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
