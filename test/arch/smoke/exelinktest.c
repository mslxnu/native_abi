/* freestanding: /proc/self/exe, which must name the guest's program.
 *
 * From the host's side the executable of every one of nabi's processes is
 * nabi. The guest's own program is something only nabi knows, so this is one
 * of the /proc entries it has to answer itself - and answering only half of it
 * is worse than not answering, because the two halves are used by different
 * callers.
 *
 * Android's apexd is what found it missing. It stats /proc/self/exe while
 * starting up; the stat fell through to the host's procfs, which has no such
 * file for this process, and apexd aborted. init reports that as
 * "reboot,bootloader,bootstrap-apexd-failed" and reboots the machine - three
 * steps from the cause, and nothing in between mentions /proc.
 *
 * What is checked:
 *
 *   - readlink gives the path the guest was exec'd with. This half already
 *     worked, and is checked so that a fix for the other half cannot quietly
 *     break it: resolution now rewrites the name, and readlink must still be
 *     served before that happens or it would read back the file rather than
 *     the link.
 *   - stat follows it and finds a regular file, which is the half that was
 *     missing.
 *   - lstat does not follow it and finds a symlink, so the two disagree in
 *     exactly the way a symlink makes them disagree.
 *   - it can be opened and read, since following it is what open does.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_exit_group 94
#define SYS_readlinkat 78
#define SYS_newfstatat 79
#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDONLY 0
#define S_IFMT   0170000
#define S_IFREG  0100000
#define S_IFLNK  0120000

/* struct stat's st_mode sits at offset 16 on arm64. */
#define ST_MODE(buf) (*(unsigned int *)((char *)(buf) + 16))

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static int eq(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}

void _start(void)
{
  char link[512];
  unsigned char st[256];

  long n = sys6(SYS_readlinkat, AT_FDCWD, (long) "/proc/self/exe",
                (long) link, sizeof link - 1, 0, 0);
  want("readlink /proc/self/exe succeeds", n > 0, 1);
  if (n > 0) {
    link[n] = '\0';
    /* The name this was started with, which run.sh puts at the root. */
    want("and it names this program", eq(link, "/exelinktest"), 1);
  }

  long r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/proc/self/exe", (long) st, 0, 0, 0);
  want("stat follows it", r, 0);
  if (r == 0)
    want("to a regular file", (ST_MODE(st) & S_IFMT) == S_IFREG, 1);

  r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/proc/self/exe", (long) st,
           AT_SYMLINK_NOFOLLOW, 0, 0);
  want("lstat does not follow it", r, 0);
  if (r == 0)
    want("and sees a symlink", (ST_MODE(st) & S_IFMT) == S_IFLNK, 1);

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/exe", O_RDONLY, 0, 0, 0);
  want("it can be opened", fd >= 0, 1);
  if (fd >= 0) {
    char b[4];
    long got = sys6(SYS_read, fd, (long) b, sizeof b, 0, 0, 0);
    want("and read", got, 4);
    /* What was opened is this ELF, so it starts the way an ELF does. */
    want("and it is the program", b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' &&
                                  b[3] == 'F', 1);
    sys6(SYS_close, fd, 0,0,0,0,0);
  }

  put(fails == 0 ? "exelink ok\n" : "exelink failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
