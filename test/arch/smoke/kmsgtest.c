/* freestanding: /dev/kmsg, the kernel log of a kernel that is a process.
 *
 * A guest's most important diagnostics go here and nowhere else. Android's
 * init writes every line of its boot to /dev/kmsg - every command that failed,
 * every service that would not start - and while the device was mapped onto
 * /dev/null those lines were destroyed as they were written. They could be
 * recovered only by running a syscall trace and reading them out of the
 * write() records, which is how several of this port's bugs had to be found.
 *
 * What is checked:
 *
 *   - a write comes back as a record, with the priority the writer put on the
 *     front and a sequence number, in the form Linux hands readers:
 *     <priority>,<sequence>,<microseconds>,-;<message>
 *   - one read is one record, never a piece of one and never two at once.
 *   - a reader that has caught up is told to wait rather than given nothing,
 *     because end-of-log is not end-of-file: more is coming.
 *   - a record that will not fit is EINVAL rather than a truncated record,
 *     which is Linux's answer and the only safe one - half a record cannot be
 *     told from a whole one.
 *   - what one process writes, another reads. That is the whole point of the
 *     device: init writes and logd reads, and they are different processes.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_exit 93
#define SYS_close 57
#define SYS_openat 56
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_clone 220
#define SYS_wait4 260
#define AT_FDCWD (-100)
#define S_IFCHR 0020000
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_NONBLOCK 04000
#define EAGAIN 11
#define EINVAL 22
#define SIGCHLD 17
#define mkdev(ma,mi) (((ma)<<8)|(mi))

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if(got==expect){put("  ok  ");put(what);put("\n");return;}
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}
static int slen(const char*s){int i=0;while(s[i])i++;return i;}
static int starts(const char*s,const char*p){while(*p)if(*s++!=*p++)return 0;return 1;}
static int has(const char*s,const char*n){
  for(int i=0;s[i];i++){int j=0;while(n[j]&&s[i+j]==n[j])j++;if(!n[j])return 1;}return 0;}

void _start(void)
{
  sys6(SYS_mkdirat,AT_FDCWD,(long)"/dev",0755,0,0,0);
  want("mount a tmpfs over /dev",
       sys6(SYS_mount,(long)"none",(long)"/dev",(long)"tmpfs",0,0,0), 0);
  sys6(SYS_mknodat,AT_FDCWD,(long)"/dev/kmsg",S_IFCHR|0600,mkdev(1,11),0,0);

  long w = sys6(SYS_openat,AT_FDCWD,(long)"/dev/kmsg",O_WRONLY,0,0,0);
  want("open for writing", w >= 0, 1);
  const char *line = "<3>init: a service would not start\n";
  want("a write is accepted whole",
       sys6(SYS_write,w,(long)line,slen(line),0,0,0), slen(line));

  long r = sys6(SYS_openat,AT_FDCWD,(long)"/dev/kmsg",O_RDONLY|O_NONBLOCK,0,0,0);
  want("open for reading", r >= 0, 1);
  static char buf[1024];
  /* Found by reading forward rather than assumed to be first: another process
   * of the same instance may have logged before this one started. */
  long n = 0, mine = 0;
  for (int i = 0; i < 64 && !mine; i++) {
    n = sys6(SYS_read,r,(long)buf,sizeof buf,0,0,0);
    if (n <= 0) break;
    buf[n] = 0;
    if (has(buf, "a service would not start")) mine = 1;
  }
  want("the record written above comes back", mine, 1);
  want("it carries the priority the writer gave", starts(buf, "3,"), 1);
  want("and ends as one record", n > 0 && buf[n-1] == '\n', 1);

  want("a reader that has caught up is told to wait",
       sys6(SYS_read,r,(long)buf,sizeof buf,0,0,0), -EAGAIN);

  /* A record that cannot fit is refused rather than cut in half. */
  sys6(SYS_write,w,(long)"<6>x\n",5,0,0,0);
  long r2 = sys6(SYS_openat,AT_FDCWD,(long)"/dev/kmsg",O_RDONLY|O_NONBLOCK,0,0,0);
  char tiny[4];
  want("a record too big for the buffer is EINVAL",
       sys6(SYS_read,r2,(long)tiny,sizeof tiny,0,0,0), -EINVAL);

  /* The shape the device exists for: one process writes, another reads. */
  long kid = sys6(SYS_clone,SIGCHLD,0,0,0,0,0);
  if (kid == 0) {
    long cw = sys6(SYS_openat,AT_FDCWD,(long)"/dev/kmsg",O_WRONLY,0,0,0);
    const char *m = "<4>child: written by another process\n";
    sys6(SYS_write,cw,(long)m,slen(m),0,0,0);
    sys6(SYS_exit,0,0,0,0,0,0);
  }
  int st=0; sys6(SYS_wait4,kid,(long)&st,0,0,0,0);

  long found = 0;
  for (int i = 0; i < 8 && !found; i++) {
    long m = sys6(SYS_read,r,(long)buf,sizeof buf,0,0,0);
    if (m <= 0) break;
    buf[m] = 0;
    if (has(buf, "written by another process")) found = 1;
  }
  want("what another process wrote is readable here", found, 1);

  put(fails ? "kmsg FAILED\n" : "kmsg ok\n");
  sys6(SYS_exit, fails?1:0, 0,0,0,0,0);
}
