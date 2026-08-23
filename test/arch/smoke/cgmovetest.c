/* freestanding: putting *another* process in a cgroup.
 *
 * Writing a pid to cgroup.procs is how a process joins a cgroup, and the pid
 * written is usually not the writer's. That is the ordinary use: a process
 * manager makes a cgroup for each thing it starts and writes that thing's pid
 * into it. Android's init does exactly this for every service.
 *
 * nabi refused any pid but the writer's, on the reasoning that membership was
 * kept in the process being moved and so could not be changed from outside.
 * That was never quite true - the procs files are the record, which is what
 * makes /proc/<pid>/cgroup answerable for a pid that is not us - and the
 * refusal meant createProcessGroup failed for every Android service, after
 * which init killed the service it had just started and rebooted.
 *
 * No pid namespace here, deliberately. cgroup.procs holds pids in the
 * numbering of whoever wrote them, so a mover and a moved process in different
 * pid namespaces do not mean the same thing by the same number - a real
 * wrinkle, and not this test's subject.
 *
 * What is checked:
 *
 *   - a parent can write its child's pid into a cgroup, and the write is
 *     accepted rather than refused.
 *   - the child then reports that cgroup as its own, so the two sides agree
 *     about where it is. The moved process is never told, so it has to be
 *     reading the record rather than remembering something.
 *   - moving it again takes it out of the first cgroup, rather than leaving it
 *     in two at once - which is not a state a cgroup hierarchy has.
 *   - a pid that names nothing is refused.
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
#define SYS_mount 40
#define SYS_pipe2 59
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define SYS_getpid 172
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define SIGCHLD 17
#define ESRCH 3

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
static int fmt(char *out, long v){
  char t[16]; int ti=0, k=0;
  if (v == 0) t[ti++]='0';
  while (v > 0) { t[ti++] = (char)('0' + v % 10); v /= 10; }
  while (ti > 0) out[k++] = t[--ti];
  out[k++]='\n';
  return k;
}

/* Write a pid into a cgroup's procs file; the errno, or the count written. */
static long join(const char *procs, long pid)
{
  char line[24];
  int li = fmt(line, pid);
  long f = sys6(SYS_openat, AT_FDCWD, (long) procs, O_WRONLY, 0,0,0);
  if (f < 0)
    return f;
  long r = sys6(SYS_write, f, (long) line, li, 0,0,0);
  sys6(SYS_close, f, 0,0,0,0,0);
  return r < 0 ? r : (r == li ? 0 : -1);
}

/* Whether a cgroup's procs file names this pid. */
static int lists(const char *procs, long pid)
{
  char body[256], want[24];
  int wl = fmt(want, pid);
  want[wl - 1] = '\0';
  long f = sys6(SYS_openat, AT_FDCWD, (long) procs, O_RDONLY, 0,0,0);
  if (f < 0) return 0;
  long n = sys6(SYS_read, f, (long) body, sizeof body - 1, 0,0,0);
  sys6(SYS_close, f, 0,0,0,0,0);
  if (n <= 0) return 0;
  body[n] = '\0';
  for (int i = 0; i < n; ) {
    int j = i;
    while (body[j] && body[j] != '\n') j++;
    char save = body[j]; body[j] = '\0';
    int hit = eq(body + i, want);
    body[j] = save;
    if (hit) return 1;
    i = j + (save ? 1 : 0);
    if (!save) break;
  }
  return 0;
}

/*
 * Cgroup names unique to this run.
 *
 * nabi's hierarchy is a real directory that outlives the guest that made it -
 * Linux's is memory and vanishes with the last reference - so a fixed name is
 * already there the second time this runs, and the mkdir that should create it
 * returns EEXIST. Naming them after this process keeps each run to itself.
 */
static char one[32], two[32], one_procs[48], two_procs[48];

static void paths(long pid)
{
  int k = 0;
  const char *pre = "/cg/m";
  while (pre[k]) { one[k] = pre[k]; two[k] = pre[k]; k++; }
  k += fmt(one + k, pid) - 1;          /* fmt ends with a newline; drop it */
  for (int i = 5; i < k; i++)
    two[i] = one[i];
  one[k] = 'a'; two[k] = 'b';
  one[k + 1] = '\0'; two[k + 1] = '\0';

  const char *tail = "/cgroup.procs";
  int i = 0;
  while (one[i]) { one_procs[i] = one[i]; two_procs[i] = two[i]; i++; }
  int j = 0;
  while (tail[j]) { one_procs[i + j] = tail[j]; two_procs[i + j] = tail[j]; j++; }
  one_procs[i + j] = '\0'; two_procs[i + j] = '\0';
}

void _start(void)
{
  long r;
  int fds[2];

  paths(sys6(SYS_getpid, 0,0,0,0,0,0));

  sys6(SYS_mkdirat, AT_FDCWD, (long) "/cg", 0755, 0,0,0);
  want("mount cgroup2",
       sys6(SYS_mount, (long) "none", (long) "/cg", (long) "cgroup2", 0, 0, 0), 0);
  want("mkdir a cgroup", sys6(SYS_mkdirat, AT_FDCWD, (long) one, 0755, 0,0,0), 0);
  want("mkdir another",  sys6(SYS_mkdirat, AT_FDCWD, (long) two, 0755, 0,0,0), 0);

  want("pipe2", sys6(SYS_pipe2, (long) fds, 0, 0,0,0,0), 0);

  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    char b, cg[64];
    sys6(SYS_close, fds[1], 0,0,0,0,0);
    sys6(SYS_read, fds[0], (long) &b, 1, 0,0,0);   /* wait to be moved */
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/cgroup", O_RDONLY, 0,0,0);
    long n = f < 0 ? -1 : sys6(SYS_read, f, (long) cg, sizeof cg - 1, 0,0,0);
    if (f >= 0) sys6(SYS_close, f, 0,0,0,0,0);
    if (n > 0 && cg[n - 1] == '\n') n--;
    cg[n > 0 ? n : 0] = '\0';
    /* "0::" then the cgroup's path in the hierarchy, which is the mount
     * path without the mount point in front of it. */
    sys6(SYS_exit_group, eq(cg + 3, two + 3) ? 0 : 1, 0,0,0,0,0);
  }
  want("fork", kid > 0, 1);
  if (kid <= 0) { put("cgmove failed\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }
  sys6(SYS_close, fds[0], 0,0,0,0,0);

  want("a parent may move its child", join(one_procs, kid), 0);
  want("and the record says so", lists(one_procs, kid), 1);

  /* Again, somewhere else: it must leave the first behind. */
  want("moving it again", join(two_procs, kid), 0);
  want("it is in the second", lists(two_procs, kid), 1);
  want("and no longer in the first", lists(one_procs, kid), 0);

  /* A pid that names nothing. */
  r = join(one_procs, 0x3fffffff);
  want("a pid that names nothing is refused", r, -ESRCH);

  sys6(SYS_write, fds[1], (long) "g", 1, 0,0,0);
  sys6(SYS_close, fds[1], 0,0,0,0,0);
  long status = 0;
  sys6(SYS_wait4, kid, (long) &status, 0, 0, 0, 0);
  want("the moved process reports its new cgroup", (status >> 8) & 0xff, 0);

  put(fails == 0 ? "cgmove ok\n" : "cgmove failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
