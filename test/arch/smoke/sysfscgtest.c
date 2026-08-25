/* freestanding: /sys/fs/cgroup is simply there.
 *
 * On Linux the cgroup subsystem creates that directory and the unified
 * hierarchy is mounted on it, so a guest that wants a cgroup finds it without
 * having asked. Here /sys is either the host's sysfs, which is read-only and
 * answers mkdir with ENOENT, or a directory inside a read-only rootfs image -
 * so the path did not exist and could not be made.
 *
 * libprocessgroup gives up there, before it tries to mount anything:
 * "mkdir() failed for /sys/fs/cgroup", then "Failed to setup cgroup2 cgroup",
 * after which Android's init put every process group at the root of the
 * hierarchy and complained about it for the rest of the boot.
 *
 * What is checked, having mounted nothing at all:
 *
 *   - the directory is there, and mkdir says so rather than failing.
 *   - it is the cgroup hierarchy: the files a cgroup has are in it.
 *   - a cgroup made under it is a real cgroup, with its own files.
 *   - and /proc/mounts says it is mounted, because on Linux it is - a guest
 *     that reads the table to find out where cgroups are has to find it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_getpid 172
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define EEXIST 17

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static int has(const char*s,const char*n){
  for(int i=0;s[i];i++){int j=0;while(n[j]&&s[i+j]==n[j])j++;if(!n[j])return 1;}return 0;}

/* Openable? 1 if so, else the negative errno. */
static long can_open(const char *p)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) p, O_RDONLY, 0, 0, 0);
  if (fd < 0) return fd;
  sys6(SYS_close, fd, 0,0,0,0,0);
  return 1;
}

/* A name of this run's own: the hierarchy is a real directory that outlives
 * the guest, so a fixed name is already there the second time. */
static char mine[64], mine_procs[80];
static void paths(long pid)
{
  const char *pre = "/sys/fs/cgroup/t";
  int k = 0;
  while (pre[k]) { mine[k] = pre[k]; k++; }
  char t[16]; int ti = 0;
  if (pid == 0) t[ti++] = '0';
  while (pid > 0) { t[ti++] = (char)('0' + pid % 10); pid /= 10; }
  while (ti > 0) mine[k++] = t[--ti];
  mine[k] = '\0';
  int i = 0; while (mine[i]) { mine_procs[i] = mine[i]; i++; }
  const char *tail = "/cgroup.procs";
  int j = 0; while (tail[j]) { mine_procs[i + j] = tail[j]; j++; }
  mine_procs[i + j] = '\0';
}

void _start(void)
{
  paths(sys6(SYS_getpid, 0,0,0,0,0,0));

  /* Nothing has been mounted. It is there anyway. */
  want("/sys/fs/cgroup is already there",
       sys6(SYS_mkdirat, AT_FDCWD, (long) "/sys/fs/cgroup", 0755, 0,0,0), -EEXIST);
  want("and it is the hierarchy",
       can_open("/sys/fs/cgroup/cgroup.controllers"), 1);
  want("with the rest of a cgroup's files",
       can_open("/sys/fs/cgroup/cgroup.procs"), 1);

  /* A cgroup made in it is a cgroup. */
  want("mkdir a cgroup under it",
       sys6(SYS_mkdirat, AT_FDCWD, (long) mine, 0755, 0,0,0), 0);
  want("which has its own files", can_open(mine_procs), 1);

  /* And the table says it is mounted, because on Linux it is. */
  {
    char buf[4096];
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/mounts", O_RDONLY, 0,0,0);
    want("open /proc/mounts", f >= 0, 1);
    if (f >= 0) {
      long n = sys6(SYS_read, f, (long) buf, sizeof buf - 1, 0,0,0);
      sys6(SYS_close, f, 0,0,0,0,0);
      buf[n > 0 ? n : 0] = '\0';
      want("/proc/mounts names it", has(buf, "/sys/fs/cgroup"), 1);
    }
  }

  put(fails == 0 ? "sysfscg ok\n" : "sysfscg failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
