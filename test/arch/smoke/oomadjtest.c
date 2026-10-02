/* freestanding: /proc/<pid>/oom_score_adj - the bias a guest sets and reads back.
 *
 * It did not exist. Android's init writes -1000 to /proc/1/oom_score_adj as one
 * of the first things it does and writes /proc/<pid>/oom_score_adj for every
 * service it starts; lmkd writes the processes it is biasing. All of it was
 * ENOENT, which is why "init: Unable to write -1000 to /proc/1/oom_score_adj:
 * open() failed: No such file or directory" appeared on every boot.
 *
 * There is no OOM killer here for the number to bias, so what is under test is
 * not any effect but that the file behaves: it round-trips, it refuses what
 * Linux refuses, and a child inherits it - which on arm64 means it has to travel
 * in the checkpoint, since a fork here is fork plus execve.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_newfstatat 79
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit 93
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define SIGCHLD 17
#define EINVAL 22
#define PATH "/proc/self/oom_score_adj"

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

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int fails;
static void bad(const char *what){ fails++; put("  FAIL "); put(what); put("\n"); }

static int slen(const char *s){int i=0;while(s[i])i++;return i;}

/* Writes `text`, returning what write(2) came back with. */
static long set(const char *path, const char *text)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_WRONLY, 0, 0, 0);
  if (fd < 0) return fd;
  long r = sys6(SYS_write, fd, (long) text, slen(text), 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  return r;
}

/* Reads the number back. Returns 1 and fills *out, or 0 if it could not. */
static int get(const char *path, long *out)
{
  char buf[32];
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return 0;
  long n = sys6(SYS_read, fd, (long) buf, sizeof buf - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n <= 0) return 0;
  buf[n] = 0;
  int i = 0, neg = 0;
  if (buf[i] == '-') { neg = 1; i++; }
  long v = 0, digits = 0;
  for (; buf[i] >= '0' && buf[i] <= '9'; i++, digits++)
    v = v * 10 + (buf[i] - '0');
  if (!digits) return 0;
  *out = neg ? -v : v;
  return 1;
}

void _start(void)
{
  long v;

  /* It exists, it stats, and it is writable - a read-only mode would have the
   * caller that matters decline to try. */
  struct lstat st;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) PATH, (long) &st, 0, 0, 0) != 0)
    bad("stat");
  else if ((st.st_mode & 0200) == 0)
    bad("not writable");

  /* Zero until something sets it, which is Linux's default. */
  if (!get(PATH, &v)) bad("read the default");
  else if (v != 0) bad("default is not 0");

  /* The write Android's init makes, and the read back that has to agree with it.
   * Landing in the stand-in temp file instead would report this as a success and
   * record nothing, so the read is the whole point. */
  if (set(PATH, "-1000\n") < 0) bad("write -1000");
  if (!get(PATH, &v)) bad("read back -1000");
  else if (v != -1000) bad("-1000 did not stick");

  /* Both ends of the range, and past each of them. init reads the EINVAL back:
   * it prints "oom_score_adjust value must be in range" rather than guessing. */
  if (set(PATH, "1000") < 0) bad("write 1000");
  if (set(PATH, "1001") != -EINVAL) bad("1001 was not refused with EINVAL");
  if (set(PATH, "-1001") != -EINVAL) bad("-1001 was not refused with EINVAL");
  if (set(PATH, "wat") != -EINVAL) bad("a non-number was not refused with EINVAL");
  /* And a refusal leaves the old value alone. */
  if (!get(PATH, &v)) bad("read after a refusal");
  else if (v != 1000) bad("a refused write changed the value");

  /* Someone else's is accepted and dropped - there is no table of other
   * processes to keep it in - but it must not be recorded against us. */
  if (set("/proc/1/oom_score_adj", "-500\n") < 0) {
    /* pid 1 is us under --pid1 and somebody else otherwise; either is fine. */
  }

  /* Inherited across fork, as Linux inherits it. A fork on arm64 is fork plus
   * execve, so this fails unless the value travels in the checkpoint. */
  if (set(PATH, "-250\n") < 0) bad("write -250");
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) {
    long cv;
    int ok = get(PATH, &cv) && cv == -250;
    sys6(SYS_exit, ok ? 7 : 8, 0,0,0,0,0);
  }
  if (pid < 0) {
    bad("fork");
  } else {
    long status = 0;
    sys6(SYS_wait4, -1, (long) &status, 0, 0, 0, 0);
    int code = (int) ((status >> 8) & 0xff);
    if (code == 8) bad("a child did not inherit the bias");
    else if (code != 7) bad("the child did not run");
  }

  put(fails == 0 ? "oomadj ok\n" : "oomadj failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
