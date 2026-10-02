/* freestanding: per-thread accounting in /proc/<pid>/task/<tid>/stat.
 *
 * The per-thread files used to be the process's files under another name - the
 * /task/<tid>/ path was rewritten to /proc/self/ and the tid thrown away - so
 * every thread reported the process's id, state and cpu time. That makes every
 * row of `ps -L` and `top -H` identical in the one column those commands exist to
 * show, and it is not visible in a single-threaded guest, where the process's
 * numbers happen to be the thread's.
 *
 * So this runs three threads with deliberately unequal work: one spins, one
 * sleeps in a futex, and the main thread waits. If the accounting were still the
 * process's, every thread's time would be the same number - which is exactly what
 * is asserted against.
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
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_futex 98
#define SYS_exit 93
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_DIRECTORY 0200000
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define CLONE_SYSVSEM 0x40000
#define THREAD_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM)

struct linux_dirent64 {
  unsigned long  d_ino;
  long           d_off;
  unsigned short d_reclen;
  unsigned char  d_type;
  char           d_name[];
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int fails;
static void bad(const char *what){ fails++; put("  FAIL "); put(what); put("\n"); }

static volatile long spin_go = 0;     /* released when the readings are taken */
static volatile int  sleeper = 0;
static volatile long busy_live = 0;
static volatile long lazy_live = 0;

static long new_stack(void){
  long s = sys6(SYS_mmap, 0, 1<<16, 3, 0x22, -1, 0);
  return s < 0 ? 0 : s + (1<<16) - 16;
}

/* The thread that earns some cpu time. */
static void busy(void){
  busy_live = 1;
  while (!spin_go)
    for (long i = 0; i < 200000; i++) asm volatile("" ::: "memory");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
/*
 * And the thread that earns none, so there is something to compare against.
 *
 * The wait is looped rather than taken once, because FUTEX_WAIT is allowed to
 * return without the value having changed and does. Taking it once let this thread
 * fall through and exit, which removed it from the task list - and that looked
 * exactly like nabi dropping a blocked thread, convincingly enough to be worth
 * saying here.
 */
static void lazy(void){
  lazy_live = 1;
  while (!sleeper)
    sys6(SYS_futex, (long)&sleeper, FUTEX_WAIT, 0, 0, 0, 0);
  sys6(SYS_exit, 0, 0,0,0,0,0);
}

static int slen(const char*s){int i=0;while(s[i])i++;return i;}
static long tonum(const char *s){
  long v = 0; int i = 0, neg = 0;
  if (s[i]=='-'){neg=1;i++;}
  for (; s[i] >= '0' && s[i] <= '9'; i++) v = v*10 + (s[i]-'0');
  return neg ? -v : v;
}
static void cat3(char *out, int cap, const char *a, const char *b, const char *c){
  int i = 0;
  for (int j=0; a[j] && i<cap-1; j++) out[i++]=a[j];
  for (int j=0; b[j] && i<cap-1; j++) out[i++]=b[j];
  for (int j=0; c[j] && i<cap-1; j++) out[i++]=c[j];
  out[i]=0;
}

/* Reads a whole file. Returns the length, or -1. */
static long slurp(const char *path, char *buf, int cap){
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return -1;
  long n = sys6(SYS_read, fd, (long)buf, cap-1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n < 0) return -1;
  buf[n] = 0;
  return n;
}

/*
 * Field 1 of a stat line, and the sum of utime and stime.
 *
 * Counted from the last close parenthesis, which is how this file has to be read:
 * comm can itself contain spaces and parentheses, so anything splitting the whole
 * line on spaces reads the wrong field. Returns 0 on success.
 */
static int parse_stat(const char *s, long *pid_out, long *ticks_out)
{
  *pid_out = tonum(s);
  int last = -1;
  for (int i = 0; s[i]; i++) if (s[i] == ')') last = i;
  if (last < 0) return -1;
  const char *p = s + last + 1;
  /* utime and stime are the 12th and 13th fields after the comm. */
  long vals[14];
  for (int f = 0; f < 14; f++) {
    while (*p == ' ') p++;
    if (!*p) return -1;
    vals[f] = tonum(p);
    while (*p && *p != ' ') p++;
  }
  *ticks_out = vals[11] + vals[12];
  return 0;
}

void _start(void)
{
  static char buf[8192], path[128], tids[8][24];
  long sp;

  sp = new_stack();
  if (!sp) { put("mmap FAIL\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }
  long t1 = sys6(SYS_clone, THREAD_FLAGS, sp, 0, 0, 0, 0);
  if (t1 == 0) busy();
  if (t1 < 0) { put("clone FAIL\n"); sys6(SYS_exit_group, 2, 0,0,0,0,0); }

  sp = new_stack();
  if (!sp) { put("mmap FAIL\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }
  long t2 = sys6(SYS_clone, THREAD_FLAGS, sp, 0, 0, 0, 0);
  if (t2 == 0) lazy();
  if (t2 < 0) { put("clone2 FAIL\n"); sys6(SYS_exit_group, 2, 0,0,0,0,0); }

  /*
   * Both threads must have reached their own code before the directory is read,
   * or this races them: a thread is listed once it has registered itself, and
   * waiting only on the spinner let the sleeper be missed about half the time -
   * which looked exactly like nabi dropping a blocked thread and was the test's
   * own doing.
   */
  while (!busy_live || !lazy_live) asm volatile("" ::: "memory");
  /* And the spinner needs real time to earn a measurable difference: a tick is a
   * hundredth of a second and the comparison needs more than one of them. */
  for (long i = 0; i < 400000000; i++) asm volatile("" ::: "memory");

  /* Every thread the directory lists. */
  int ntid = 0;
  {
    long fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/task",
                   O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (fd < 0) { bad("/proc/self/task will not open"); }
    else {
      for (;;) {
        long n = sys6(SYS_getdents64, fd, (long)buf, sizeof buf, 0, 0, 0);
        if (n <= 0) break;
        for (long off = 0; off < n; ) {
          struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + off);
          if (de->d_name[0] != '.' && ntid < 8) {
            int i = 0;
            for (; de->d_name[i] && i < 23; i++) tids[ntid][i] = de->d_name[i];
            tids[ntid][i] = 0;
            ntid++;
          }
          off += de->d_reclen;
        }
      }
      sys6(SYS_close, fd, 0,0,0,0,0);
    }
  }
  if (ntid < 3) bad("/proc/self/task does not list all three threads");

  /*
   * Each thread's stat must name that thread, and the times must not all be the
   * same - which they were, every one of them being the process's total.
   */
  long lo = -1, hi = -1;
  for (int i = 0; i < ntid; i++) {
    cat3(path, sizeof path, "/proc/self/task/", tids[i], "/stat");
    if (slurp(path, buf, sizeof buf) <= 0) { bad("a thread's stat will not read"); continue; }
    long pid, ticks;
    if (parse_stat(buf, &pid, &ticks) != 0) { bad("a thread's stat will not parse"); continue; }
    if (pid != tonum(tids[i]))
      bad("a thread's stat names the process rather than the thread");
    if (lo < 0 || ticks < lo) lo = ticks;
    if (ticks > hi) hi = ticks;

    /* And its status has to tell Pid from Tgid, which is the whole of how a
     * thread is distinguished from its process. */
    cat3(path, sizeof path, "/proc/self/task/", tids[i], "/status");
    if (slurp(path, buf, sizeof buf) <= 0) bad("a thread's status will not read");

    cat3(path, sizeof path, "/proc/self/task/", tids[i], "/comm");
    if (slurp(path, buf, sizeof buf) <= 0) bad("a thread's comm will not read");
  }

  if (hi <= lo)
    bad("every thread reports the same cpu time, so it is still the process's");

  /* Let them go. */
  spin_go = 1;
  sleeper = 1;
  sys6(SYS_futex, (long)&sleeper, FUTEX_WAKE, 1, 0, 0, 0);

  put(fails == 0 ? "threadstat ok\n" : "threadstat failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
