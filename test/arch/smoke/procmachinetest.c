/* freestanding: the six /proc files that describe the machine, answered by nabi.
 *
 * mSL/ProcFS used to answer these with the host Mac's values, which is the same
 * mistake as /proc/cmdline: the file exists, it parses, and what it says is about
 * the wrong machine. `free` reported the Mac's memory and `ps aux` the Mac's
 * processes. Without the kext they simply were not there, so `free` said
 * "Memory information file /proc/meminfo does not exist" and `ps` said
 * "Error, do this: mount -t proc proc /proc".
 *
 * Checked for shape rather than value: the numbers are the host's where the
 * host's number is also the guest's, and asserting on them would be asserting on
 * whatever this machine happens to have. /proc/version is the exception - it has
 * to agree with uname(2) or a guest that compares them is being lied to.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_uname 160
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0

struct utsn { char sys[65], node[65], rel[65], ver[65], mach[65], dom[65]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int fails;
static int eq(const char*a,const char*b,int n){for(int i=0;i<n;i++){if(a[i]!=b[i])return 0;}return 1;}
static int find(const char*h,int hn,const char*n,int nn){
  for(int i=0;i+nn<=hn;i++) if(eq(h+i,n,nn)) return 1; return 0; }
static void bad(const char *what){ fails++; put("  FAIL "); put(what); put("\n"); }

/* Reads the file and requires `must` to appear in it. */
static void expect(const char *path, const char *must, int mustn, char *buf, int cap)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0) { bad(path); return; }
  long n = sys6(SYS_read, fd, (long) buf, cap - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n <= 0) { bad(path); return; }
  buf[n] = 0;
  if (!find(buf, (int) n, must, mustn)) bad(path);
}

void _start(void)
{
  static char buf[8192];

  expect("/proc/cpuinfo", "processor", 9, buf, sizeof buf);
  expect("/proc/meminfo", "MemTotal:", 9, buf, sizeof buf);
  expect("/proc/stat",    "btime",     5, buf, sizeof buf);
  expect("/proc/uptime",  ".",         1, buf, sizeof buf);
  expect("/proc/loadavg", ".",         1, buf, sizeof buf);

  /*
   * /proc/version must carry the same release uname reports. Checked against
   * uname rather than a literal so that bumping the release in one place cannot
   * leave the two disagreeing.
   */
  struct utsn u;
  if (sys6(SYS_uname, (long)&u, 0,0,0,0,0) != 0) {
    bad("uname");
  } else {
    int rn = 0; while (u.rel[rn] && rn < 64) rn++;
    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/version", O_RDONLY, 0,0,0);
    if (fd < 0) { bad("/proc/version"); }
    else {
      long n = sys6(SYS_read, fd, (long) buf, (long) sizeof buf - 1, 0,0,0);
      sys6(SYS_close, fd, 0,0,0,0,0);
      if (n <= 0) { bad("/proc/version"); }
      else {
        buf[n] = 0;
        if (!find(buf, (int) n, "Linux version", 13)) bad("/proc/version prefix");
        if (!find(buf, (int) n, u.rel, rn)) bad("/proc/version disagrees with uname");
      }
    }
  }

  put(fails == 0 ? "procmachine ok\n" : "procmachine failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
