/* freestanding: clone with a namespace flag, and the parent left where it was.
 *
 * Namespace flags on clone had never worked. The namespaces were created - the
 * clone syscall calls nsproxy_clone before anything forks - and then do_clone
 * refused the very flags that had asked for them, so the call returned EINVAL.
 * LXC asks for five at once and could not spawn a container at all.
 *
 * The half that only becomes visible once the flags are accepted is what
 * happens to the *parent*. On arm64 a child is a fresh process rebuilt from a
 * checkpoint, so the namespace has to exist before the checkpoint is written -
 * which means it is made in the parent, and the parent is standing in a
 * namespace it never asked to join until it is put back. That is the whole
 * difference between clone and unshare, and it is what this checks: a clone
 * that leaves the parent moved would pass any test that only looked at the
 * child.
 *
 * The uts namespace is the one to test with, because it has contents a guest
 * can see - a hostname - so "a different namespace" is an observable fact
 * rather than an inode number.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_exit         93
#define SYS_clone       220
#define SYS_wait4       260
#define SYS_sethostname 161
#define SYS_uname       160
#define SYS_readlinkat   78

#define SIGCHLD          17
#define CLONE_NEWNS   0x00020000
#define CLONE_NEWUTS  0x04000000
#define CLONE_NEWIPC  0x08000000
#define CLONE_NEWPID  0x20000000
#define CLONE_NEWCGROUP 0x02000000
#define AT_FDCWD      (-100)

struct utsname { char sysname[65], nodename[65], release[65], version[65],
                 machine[65], domainname[65]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("clonens FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static int streq(const char *a, const char *b)
{ int i = 0; while (a[i] && a[i] == b[i]) i++; return a[i] == b[i]; }

static struct utsname un;
static char nsbuf[128];

static void
hostname_now(char *out)
{
  for (unsigned i = 0; i < sizeof un; i++) ((char *) &un)[i] = 0;
  if (sys6(SYS_uname, (long) &un, 0, 0, 0, 0, 0) != 0)
    fail("uname", -1, 0);
  int i = 0;
  while (un.nodename[i]) { out[i] = un.nodename[i]; i++; }
  out[i] = '\0';
}

void _start(void)
{
  long r;
  char before[128], after[128], childsaw[128];

  /* A name of our own to start from, so the check does not depend on what the
   * host happens to be called. */
  if ((r = sys6(SYS_sethostname, (long) "parent-host", 11, 0, 0, 0, 0)) != 0)
    fail("sethostname", r, 0);
  hostname_now(before);
  if (!streq(before, "parent-host"))
    fail("the name we just set", 0, 1);

  /* The clone that used to be refused outright. */
  long child = sys6(SYS_clone, SIGCHLD | CLONE_NEWUTS, 0, 0, 0, 0, 0);
  if (child < 0)
    fail("clone with CLONE_NEWUTS", child, 0);

  if (child == 0) {
    /* In the child's own namespace: renaming here must not reach the parent. */
    sys6(SYS_sethostname, (long) "child-host", 10, 0, 0, 0, 0);
    hostname_now(childsaw);
    sys6(SYS_exit, streq(childsaw, "child-host") ? 21 : 22, 0, 0, 0, 0, 0);
  }

  int st = 0;
  if ((r = sys6(SYS_wait4, child, (long) &st, 0, 0, 0, 0)) != child)
    fail("wait4", r, child);
  int code = (st >> 8) & 0xff;
  if (code == 22) fail("the child's own hostname did not take", 22, 21);
  if (code != 21) fail("the child", code, 21);

  /*
   * The parent, which is the point. Its name must be the one it set: unchanged
   * by the child, and unchanged by the namespace having been created here.
   */
  hostname_now(after);
  if (!streq(after, "parent-host"))
    fail("the parent's hostname after cloning a uts namespace", 0, 1);

  /* And the parent is in the namespace it started in, not the child's. The
   * link is what /proc reports; an unchanged one is the restore having
   * happened. */
  { long n = sys6(SYS_readlinkat, AT_FDCWD, (long) "/proc/self/ns/uts",
                  (long) nsbuf, sizeof nsbuf - 1, 0, 0);
    if (n > 0) {
      nsbuf[n] = '\0';
      /* Cloning again must report the same namespace as the first time. */
      char firstns[128];
      for (long i = 0; i <= n; i++) firstns[i] = nsbuf[i];
      long c2 = sys6(SYS_clone, SIGCHLD | CLONE_NEWUTS, 0, 0, 0, 0, 0);
      if (c2 == 0) sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
      if (c2 > 0) {
        int s2 = 0;
        sys6(SYS_wait4, c2, (long) &s2, 0, 0, 0, 0);
        long m = sys6(SYS_readlinkat, AT_FDCWD, (long) "/proc/self/ns/uts",
                      (long) nsbuf, sizeof nsbuf - 1, 0, 0);
        if (m > 0) {
          nsbuf[m] = '\0';
          if (!streq(firstns, nsbuf))
            fail("the parent's uts namespace after a second clone", 0, 1);
        }
      }
    } }

  /* The set LXC asks for, all at once. */
  { long c = sys6(SYS_clone,
                  SIGCHLD | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
                  CLONE_NEWPID | CLONE_NEWCGROUP, 0, 0, 0, 0, 0);
    if (c < 0)
      fail("clone with the five namespaces LXC asks for", c, 0);
    if (c == 0)
      sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
    int s3 = 0;
    sys6(SYS_wait4, c, (long) &s3, 0, 0, 0, 0);
    hostname_now(after);
    if (!streq(after, "parent-host"))
      fail("the parent's hostname after cloning five namespaces", 0, 1); }

  put("clonens ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
