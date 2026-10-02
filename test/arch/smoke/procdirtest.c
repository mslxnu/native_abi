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
#define O_WRONLY 1
#define SYS_read 63
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
static int eqn(const char*a,const char*b,int n)
{ for(int i=0;i<n;i++) if(a[i]!=b[i]) return 0; return 1; }
static int find(const char*h,int hn,const char*nd,int nn)
{ for(int i=0;i+nn<=hn;i++) if(eqn(h+i,nd,nn)) return 1; return 0; }

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

/* The first real entry of a directory, copied into `out`. The tid under
 * /proc/self/task cannot be known ahead of time and cannot be borrowed from
 * another process - every guest process here has its own task list, so a tid read
 * in one and used in another is correctly refused. */
static int first_entry(const char *dir, char *out, int cap)
{
  static char buf[8192];
  long fd = sys6(SYS_openat, AT_FDCWD, (long) dir, O_RDONLY | O_DIRECTORY, 0,0,0);
  if (fd < 0) return 0;
  int got = 0;
  for (;;) {
    long n = sys6(SYS_getdents64, fd, (long) buf, sizeof buf, 0, 0, 0);
    if (n <= 0) break;
    for (long off = 0; off < n && !got; ) {
      struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
      if (de->d_name[0] != '.') {
        int i = 0;
        for (; de->d_name[i] && i < cap - 1; i++) out[i] = de->d_name[i];
        out[i] = 0;
        got = 1;
      }
      off += de->d_reclen;
    }
    if (got) break;
  }
  sys6(SYS_close, fd, 0,0,0,0,0);
  return got;
}

/* Joins "/proc/self/task/<tid>" and `leaf` into `out`. */
static void tpath(const char *tid, const char *leaf, char *out, int cap)
{
  const char *pre = "/proc/self/task/";
  int i = 0;
  for (int j = 0; pre[j] && i < cap - 1; j++) out[i++] = pre[j];
  for (int j = 0; tid[j] && i < cap - 1; j++) out[i++] = tid[j];
  for (int j = 0; leaf[j] && i < cap - 1; j++) out[i++] = leaf[j];
  out[i] = 0;
}

/*
 * Stronger than agree(): this path must be there. agree() deliberately says
 * nothing about a path that does not open at all, so a file that is absent from
 * both halves of procfs slips past it - which is exactly the shape of the
 * /task/<tid> gap and of stat and status having no answer without the kext.
 * `must` has to appear in what it reads, so a generator that returns nothing is
 * caught too.
 */
static void require(const char *path, const char *must, int mustn)
{
  static char rbuf[8192];
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0) { bad(path, "does not open"); return; }
  long n = sys6(SYS_read, fd, (long) rbuf, sizeof rbuf - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n <= 0) { bad(path, "reads empty"); return; }
  rbuf[n] = 0;
  if (!find(rbuf, (int) n, must, mustn)) bad(path, "is missing what it must say");
  struct lstat rst;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &rst, 0, 0, 0) != 0)
    bad(path, "reads but does not stat");
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

  /*
   * stat and status must be there, not merely agree. Both were built by rewriting
   * the pid fields of the *host's* /proc, read with a plain open that the
   * passthrough probe never saw - so they quietly went on working on a machine
   * pretending to have no kext, and on one that really had none they were absent
   * while stat claimed they existed. Required here, with a field of each that a
   * caller actually parses, so the Darwin-backed answer cannot regress to nothing.
   */
  require("/proc/self/status", "Name:", 5);
  require("/proc/self/status", "VmRSS:", 6);
  require("/proc/self/status", "Threads:", 8);
  require("/proc/self/stat", ")", 1);

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

  /*
   * /proc/<pid>/task/<tid>/<file>, the per-thread view. Only the bare /task was
   * classified, so everything inside it fell through - and libselinux's fallback
   * for setting a creation context is exactly
   * /proc/self/task/<tid>/attr/fscreate, so a guest whose first spelling failed
   * had no second one.
   *
   * The tid has to be read from the directory rather than assumed: it is not the
   * pid in a threaded guest, and a tid taken from another process is correctly
   * refused, since each guest process here keeps its own task list.
   */
  char tid[32], path[128];
  struct lstat tst;
  if (!first_entry("/proc/self/task", tid, sizeof tid)) {
    bad("/proc/self/task", "lists no thread at all");
  } else {
    tpath(tid, "", path, sizeof path);
    agree(path, 1);                       /* the thread's own directory */
    if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &tst, 0, 0, 0) != 0)
      bad(path, "the thread's own directory is not there");
    tpath(tid, "/fd", path, sizeof path);     agree(path, 1);
    tpath(tid, "/ns", path, sizeof path);     agree(path, 1);
    tpath(tid, "/status", path, sizeof path); agree(path, 0);
    tpath(tid, "/stat", path, sizeof path);   agree(path, 0);
    tpath(tid, "/comm", path, sizeof path);   agree(path, 0);
    tpath(tid, "/maps", path, sizeof path);   agree(path, 0);
    tpath(tid, "/cmdline", path, sizeof path); agree(path, 0);
    tpath(tid, "/cgroup", path, sizeof path); agree(path, 0);
    tpath(tid, "/attr/current", path, sizeof path); agree(path, 0);

    /* The one that sent libselinux away empty-handed, and it has to be writable
     * rather than merely present. */
    tpath(tid, "/attr/fscreate", path, sizeof path);
    long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_WRONLY, 0, 0, 0);
    if (fd < 0) bad(path, "cannot be opened for writing");
    else sys6(SYS_close, fd, 0,0,0,0,0);

    /* And they really read, rather than merely opening: these are generated on
     * open, so an empty answer means the generator declined. */
    tpath(tid, "/status", path, sizeof path);  require(path, "Name:", 5);
    tpath(tid, "/stat", path, sizeof path);    require(path, ")", 1);
    tpath(tid, "/comm", path, sizeof path);    require(path, "", 0);
  }

  /* A tid that is not one of ours is not ours to answer for. */
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) "/proc/self/task/999999/status",
           (long) &tst, 0, 0, 0) == 0)
    bad("/proc/self/task/999999/status", "answered for a thread we do not have");

  put(fails == 0 ? "procdir ok\n" : "procdir failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
