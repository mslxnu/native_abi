/* freestanding: namespaces - the one that works, the ones that say they do not,
 * and the identity surviving a fork.
 *
 * macOS has no namespaces at all, so nothing here is delegated: a namespace is
 * emulated in nabi's bookkeeping or it does not exist. The uts namespace can be
 * emulated completely - it is a hostname and a domainname - and the rest cannot
 * yet, so they are refused with EINVAL, which is what Linux returns for a
 * namespace its kernel was not built with. The refusal is the point: a guest
 * that asks for a network namespace and is told "yes" while nothing is isolated
 * has been lied to in a way it cannot detect.
 *
 * The fork case is the one worth having a test for. arm64's fork is fork plus
 * exec, so a child is a fresh process that rebuilds everything from a
 * checkpoint - and the namespace *identity* has to travel as well as the
 * hostname. A child sharing its parent's uts namespace must report the same
 * inode from /proc/self/ns/uts, because comparing those numbers is the main
 * thing they are for; a child given a fresh one would look isolated when it is
 * not.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_readlinkat 78
#define SYS_uname 160
#define SYS_sethostname 161
#define SYS_setdomainname 162
#define SYS_unshare 97
#define SYS_setns 268
#define SYS_clone 220
#define SYS_wait4 260
#define AT_FDCWD -100
#define O_RDONLY 0
#define SIGCHLD 17

#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUTS    0x04000000
#define CLONE_NEWIPC    0x08000000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000
#define EINVAL 22

struct utsname { char sys[65], node[65], rel[65], ver[65], mach[65], dom[65]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long wanted)
{ put("ns FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(wanted); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
static void fails(const char *what, const char *got)
{ put("ns FAIL: "); put(what); put(" -> \""); put(got); put("\"\n");
  sys6(SYS_exit, 1, 0,0,0,0,0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* The link text, e.g. "uts:[4026531836]". */
static long ns_link(const char *path, char *buf, long cap)
{
  long n = sys6(SYS_readlinkat, AT_FDCWD, (long) path, (long) buf, cap - 1, 0, 0);
  if (n < 0) return n;
  buf[n] = '\0';
  return n;
}

static void nodename(char *out)
{
  struct utsname u;
  sys6(SYS_uname, (long) &u, 0,0,0,0,0);
  int i = 0; while (u.node[i] && i < 64) { out[i] = u.node[i]; i++; }
  out[i] = '\0';
}

void _start(void)
{
  char a[80], b[80], name[80];
  long r;

  /* Every type has a link, including the ones that cannot be unshared - Linux
   * always has them, and software reads them to compare rather than to move. */
  static const char *const all[] = {
    "/proc/self/ns/mnt", "/proc/self/ns/uts", "/proc/self/ns/ipc",
    "/proc/self/ns/pid", "/proc/self/ns/net", "/proc/self/ns/user",
    "/proc/self/ns/cgroup", "/proc/self/ns/time", 0
  };
  for (int i = 0; all[i]; i++)
    if ((r = ns_link(all[i], a, sizeof a)) < 0)
      fail(all[i], r, 0);

  /* What cannot be isolated is refused, and refused before anything changes. */
  if ((r = ns_link("/proc/self/ns/net", a, sizeof a)) < 0)
    fail("reading the net link", r, 0);
  if ((r = sys6(SYS_unshare, CLONE_NEWNET, 0,0,0,0,0)) != -EINVAL)
    fail("unshare(CLONE_NEWNET)", r, -EINVAL);
  if ((r = sys6(SYS_unshare, CLONE_NEWPID, 0,0,0,0,0)) != -EINVAL)
    fail("unshare(CLONE_NEWPID)", r, -EINVAL);
  if ((r = sys6(SYS_unshare, CLONE_NEWUSER, 0,0,0,0,0)) != -EINVAL)
    fail("unshare(CLONE_NEWUSER)", r, -EINVAL);
  if ((r = ns_link("/proc/self/ns/net", b, sizeof b)) < 0)
    fail("re-reading the net link", r, 0);
  if (!eq(a, b))
    fails("a refused unshare moved the net namespace anyway", b);

  /* A refused flag alongside a workable one refuses the whole call, so nobody
   * ends up half moved. */
  if ((r = ns_link("/proc/self/ns/uts", a, sizeof a)) < 0)
    fail("reading the uts link", r, 0);
  if ((r = sys6(SYS_unshare, CLONE_NEWUTS|CLONE_NEWNET, 0,0,0,0,0)) != -EINVAL)
    fail("unshare(NEWUTS|NEWNET)", r, -EINVAL);
  if ((r = ns_link("/proc/self/ns/uts", b, sizeof b)) < 0)
    fail("re-reading the uts link", r, 0);
  if (!eq(a, b))
    fails("a partly-refused unshare moved uts anyway", b);

  /* setns onto the namespace already occupied is a no-op that must succeed. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/ns/uts", O_RDONLY, 0,0,0);
  if (fd < 0)
    fail("opening the uts link", fd, 0);
  if ((r = sys6(SYS_setns, fd, CLONE_NEWUTS, 0,0,0,0)) != 0)
    fail("setns onto the current uts namespace", r, 0);
  if ((r = sys6(SYS_setns, fd, CLONE_NEWNET, 0,0,0,0)) != -EINVAL)
    fail("setns with a type that disagrees with the descriptor", r, -EINVAL);
  sys6(SYS_close, fd, 0,0,0,0,0);

  /* Now the one that works. */
  if ((r = sys6(SYS_unshare, CLONE_NEWUTS, 0,0,0,0,0)) != 0)
    fail("unshare(CLONE_NEWUTS)", r, 0);
  if ((r = ns_link("/proc/self/ns/uts", b, sizeof b)) < 0)
    fail("uts link after unsharing", r, 0);
  if (eq(a, b))
    fails("unshare(CLONE_NEWUTS) left the namespace identity unchanged", b);

  /* The new namespace starts as a copy, as it does on Linux - unshare does not
   * blank the hostname - and then diverges. */
  if ((r = sys6(SYS_sethostname, (long) "nabi-test-host", 14, 0,0,0,0)) != 0)
    fail("sethostname", r, 0);
  nodename(name);
  if (!eq(name, "nabi-test-host"))
    fails("uname did not report the name just set", name);
  if ((r = sys6(SYS_setdomainname, (long) "nabi-test-dom", 13, 0,0,0,0)) != 0)
    fail("setdomainname", r, 0);

  /* A fork rebuilds all of this from a checkpoint. Both the name and the
   * identity have to arrive. */
  if ((r = ns_link("/proc/self/ns/uts", a, sizeof a)) < 0)
    fail("uts link before forking", r, 0);

  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid < 0)
    fail("clone", pid, 0);
  if (pid == 0) {
    char cn[80], cl[80];
    nodename(cn);
    if (!eq(cn, "nabi-test-host"))
      sys6(SYS_exit, 2, 0,0,0,0,0);       /* hostname did not survive */
    if (ns_link("/proc/self/ns/uts", cl, sizeof cl) < 0)
      sys6(SYS_exit, 3, 0,0,0,0,0);
    if (!eq(cl, a))
      sys6(SYS_exit, 4, 0,0,0,0,0);       /* identity did not survive */
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }

  int status = 0;
  if ((r = sys6(SYS_wait4, pid, (long) &status, 0, 0,0,0)) < 0)
    fail("wait4", r, 0);
  if ((status & 0x7f) != 0)
    fail("the child died on signal", status & 0x7f, 0);
  switch ((status >> 8) & 0xff) {
  case 0: break;
  case 2: fails("the child's hostname did not survive the fork", "");
  case 3: fails("the child could not read its uts link", "");
  case 4: fails("the child's uts namespace identity did not survive the fork", "");
  default: fail("the child exited with", (status >> 8) & 0xff, 0);
  }

  put("ns ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
