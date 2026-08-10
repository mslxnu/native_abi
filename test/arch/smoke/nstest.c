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
#define SYS_getuid 174
#define SYS_getgid 176
#define SYS_getpid 172
#define SYS_getppid 173
#define SYS_read 63
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_connect 203
#define SYS_sethostname 161
#define SYS_setdomainname 162
#define SYS_unshare 97
#define SYS_kill 129
#define SYS_setns 268
#define SYS_clone 220
#define SYS_clock_gettime 113
#define SYS_newfstatat 79
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_umount2 39
#define SYS_fchownat 54
#define SYS_wait4 260
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT  0100
#define MS_RDONLY 1
#define MS_REMOUNT 0x20
#define MS_BIND 0x1000
#define MS_MOVE 0x2000
#define EROFS 30
#define ENOENT 2
#define SIGCHLD 17

#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUTS    0x04000000
#define CLONE_NEWIPC    0x08000000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000
#define CLONE_NEWTIME   0x00000080
#define CLONE_NEWCGROUP 0x02000000
#define NOBODY          65534
#define EINVAL 22
#define EPERM  1
#define ESRCH  3
#define ENETUNREACH   101
#define EADDRNOTAVAIL 99
#define AF_INET 2
#define AF_UNIX 1
#define SOCK_STREAM 1

struct utsname { char sys[65], node[65], rel[65], ver[65], mach[65], dom[65]; };
struct tspec { long tv_sec, tv_nsec; };

/* aarch64's struct stat, as far as the owner. */
struct lstat { unsigned long dev, ino; unsigned mode, nlink, uid, gid;
               unsigned long rdev, pad1; long size; char rest[64]; };

#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME  7
#define TIMENS_OFFSET   3600

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
    "/proc/self/ns/cgroup", "/proc/self/ns/time",
    "/proc/self/ns/time_for_children", "/proc/self/ns/pid_for_children", 0
  };
  for (int i = 0; all[i]; i++)
    if ((r = ns_link(all[i], a, sizeof a)) < 0)
      fail(all[i], r, 0);

  /*
   * There is no longer a CLONE_NEW* that unshare refuses: all eight are
   * supported, so the check that used to live here - that a refused flag
   * alongside a workable one moves nothing - has no flag left to make it with.
   * What still refuses is clone(CLONE_NEWTIME), because that flag lands inside
   * the exit-signal byte clone carries, and it is tested with the time
   * namespace below.
   *
   * The property that call refuses *before* changing anything is worth keeping
   * a check on, so: a nonsense flag is rejected and nothing moves.
   */
  if ((r = ns_link("/proc/self/ns/uts", a, sizeof a)) < 0)
    fail("reading the uts link", r, 0);
  if ((r = sys6(SYS_unshare, CLONE_NEWUTS | 0x00000004 /* CLONE_FS-ish */,
                0,0,0,0,0)) < 0) {
    /* Whether an unrelated flag is accepted is not what is being checked here;
     * what matters is that uts did not move if the call failed. */
    if ((r = ns_link("/proc/self/ns/uts", b, sizeof b)) < 0)
      fail("re-reading the uts link", r, 0);
    if (!eq(a, b))
      fails("a failed unshare moved uts anyway", b);
  }

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

  int status;
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

  status = 0;
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

  /*
   * The time namespace, which behaves unlike every other one: unshare does not
   * move the caller into it.
   *
   * A process's CLOCK_MONOTONIC cannot be shifted underneath it - that is a
   * clock jumping, which is the one thing monotonic means it will not do - so
   * the new namespace is set aside for children and /proc/self/ns/time goes on
   * naming the old one. Anything that assumed unshare moves the caller would
   * read the same inode from both links and never notice.
   */
  char tbefore[80], tafter[80], cbefore[80], cafter[80];
  if (ns_link("/proc/self/ns/time", tbefore, sizeof tbefore) < 0)
    fail("reading the time link", -1, 0);
  if (ns_link("/proc/self/ns/time_for_children", cbefore, sizeof cbefore) < 0)
    fail("reading the time_for_children link", -1, 0);
  if (!eq(tbefore, cbefore))
    fails("time and time_for_children disagreed before any unshare", cbefore);

  /* clone cannot ask for one: the flag is 0x80, which lands in the exit-signal
   * byte clone's low bits carry, so Linux offers it only through unshare. */
  if ((r = sys6(SYS_clone, CLONE_NEWTIME | SIGCHLD, 0, 0, 0, 0, 0)) != -EINVAL)
    fail("clone(CLONE_NEWTIME)", r, -EINVAL);

  if ((r = sys6(SYS_unshare, CLONE_NEWTIME, 0,0,0,0,0)) != 0)
    fail("unshare(CLONE_NEWTIME)", r, 0);
  if (ns_link("/proc/self/ns/time", tafter, sizeof tafter) < 0)
    fail("re-reading the time link", -1, 0);
  if (ns_link("/proc/self/ns/time_for_children", cafter, sizeof cafter) < 0)
    fail("re-reading the time_for_children link", -1, 0);
  if (!eq(tbefore, tafter))
    fails("unshare(CLONE_NEWTIME) moved the caller, which it must not", tafter);
  if (eq(cbefore, cafter))
    fails("unshare(CLONE_NEWTIME) left time_for_children unchanged", cafter);

  /* The offsets, which are writable only while nobody is in the namespace. */
  long ofd = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/timens_offsets",
                  O_WRONLY, 0,0,0);
  if (ofd < 0)
    fail("opening /proc/self/timens_offsets", ofd, 0);
  static const char offsets[] = "monotonic 3600 0\nboottime 7200 0\n";
  int olen = 0; while (offsets[olen]) olen++;
  if ((r = sys6(SYS_write, ofd, (long) offsets, olen, 0,0,0)) != olen)
    fail("writing the offsets", r, olen);
  sys6(SYS_close, ofd, 0,0,0,0,0);

  /* This process is not in that namespace, so its own clocks have not moved. */
  struct tspec pm, pb, pr;
  sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long) &pm, 0,0,0,0);
  sys6(SYS_clock_gettime, CLOCK_BOOTTIME, (long) &pb, 0,0,0,0);
  sys6(SYS_clock_gettime, CLOCK_REALTIME, (long) &pr, 0,0,0,0);

  long tpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (tpid < 0)
    fail("clone into the time namespace", tpid, 0);
  if (tpid == 0) {
    /* The child is in it, so its monotonic and boottime are shifted and its
     * realtime is not - a time namespace does not touch the wall clock. */
    struct tspec cm, cb, cr;
    char cl[80];
    sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long) &cm, 0,0,0,0);
    sys6(SYS_clock_gettime, CLOCK_BOOTTIME, (long) &cb, 0,0,0,0);
    sys6(SYS_clock_gettime, CLOCK_REALTIME, (long) &cr, 0,0,0,0);

    long dm = cm.tv_sec - pm.tv_sec;
    long db = cb.tv_sec - pb.tv_sec;
    long dr = cr.tv_sec - pr.tv_sec;
    if (dm < TIMENS_OFFSET - 5 || dm > TIMENS_OFFSET + 5)
      sys6(SYS_exit, 5, 0,0,0,0,0);       /* monotonic did not shift */
    if (db < 2 * TIMENS_OFFSET - 5 || db > 2 * TIMENS_OFFSET + 5)
      sys6(SYS_exit, 6, 0,0,0,0,0);       /* boottime did not shift */
    if (dr < -5 || dr > 5)
      sys6(SYS_exit, 7, 0,0,0,0,0);       /* realtime moved, and must not */
    if (ns_link("/proc/self/ns/time", cl, sizeof cl) < 0)
      sys6(SYS_exit, 8, 0,0,0,0,0);
    if (!eq(cl, cafter))
      sys6(SYS_exit, 9, 0,0,0,0,0);       /* not in the one set aside for it */
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  status = 0;
  if ((r = sys6(SYS_wait4, tpid, (long) &status, 0, 0,0,0)) < 0)
    fail("wait4 for the time child", r, 0);
  switch ((status >> 8) & 0xff) {
  case 0: break;
  case 5: fails("the child's CLOCK_MONOTONIC was not shifted", "");
  case 6: fails("the child's CLOCK_BOOTTIME was not shifted", "");
  case 7: fails("the child's CLOCK_REALTIME was shifted, and must not be", "");
  case 8: fails("the child could not read its time link", "");
  case 9: fails("the child is not in the namespace set aside for it", "");
  default: fail("the time child exited with", (status >> 8) & 0xff, 0);
  }

  /*
   * The mount namespace. There was no mount table at all before this - a rootfs
   * and a fixed list of host prefixes - so there was nothing a namespace could
   * have isolated, which is why this one waited on mount(2).
   *
   * A bind is the case worth testing because it is the one that carries the
   * whole design: it is a rewrite of one path prefix to another, applied at the
   * same point resolution already chooses between the rootfs and a passthrough.
   */
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/mnt-src", 0755, 0,0,0);
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/mnt-dst", 0755, 0,0,0);
  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-src/f",
                  O_WRONLY | O_CREAT, 0644, 0,0);
    if (f < 0)
      fail("creating the bind source's file", f, 0);
    sys6(SYS_write, f, (long) "bound\n", 6, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
  }

  char mbefore[80], mafter[80];
  if (ns_link("/proc/self/ns/mnt", mbefore, sizeof mbefore) < 0)
    fail("reading the mnt link", -1, 0);
  if ((r = sys6(SYS_unshare, CLONE_NEWNS, 0,0,0,0,0)) != 0)
    fail("unshare(CLONE_NEWNS)", r, 0);
  if (ns_link("/proc/self/ns/mnt", mafter, sizeof mafter) < 0)
    fail("re-reading the mnt link", -1, 0);
  if (eq(mbefore, mafter))
    fails("unshare(CLONE_NEWNS) left the identity unchanged", mafter);

  /* Nothing is there until it is mounted. */
  if ((r = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/f", O_RDONLY, 0,0,0)) != -ENOENT)
    fail("the target before mounting", r, -ENOENT);

  if ((r = sys6(SYS_mount, (long) "/mnt-src", (long) "/mnt-dst", 0,
                MS_BIND, 0, 0)) != 0)
    fail("mount(MS_BIND)", r, 0);

  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/f", O_RDONLY, 0,0,0);
    if (f < 0)
      fail("reading through the bind", f, 0);
    char buf[8] = {0};
    long n = sys6(63 /*read*/, f, (long) buf, 6, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    if (n != 6 || !eq(buf, "bound\n"))
      fails("what came back through the bind", buf);
  }

  /*
   * Moving it, which in a table of prefix rewrites is changing the prefix an
   * entry answers to. The host object it resolved to when it was mounted is not
   * consulted again, so a move cannot fail the way a fresh mount might - and
   * the old mount point is uncovered by it, which is the half a caller checks.
   */
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/mnt-moved", 0755, 0,0,0);
  if ((r = sys6(SYS_mount, (long) "/mnt-dst", (long) "/mnt-moved", 0,
                MS_MOVE, 0, 0)) != 0)
    fail("mount(MS_MOVE)", r, 0);
  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-moved/f", O_RDONLY, 0,0,0);
    if (f < 0)
      fail("reading through a moved mount", f, 0);
    sys6(SYS_close, f, 0,0,0,0,0);
  }
  if ((r = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/f", O_RDONLY, 0,0,0)) != -ENOENT)
    fail("the mount point a move left behind", r, -ENOENT);

  /* Somewhere that is not a mount point cannot be moved. */
  if ((r = sys6(SYS_mount, (long) "/mnt-src", (long) "/mnt-moved", 0,
                MS_MOVE, 0, 0)) != -EINVAL)
    fail("moving something that is not a mount point", r, -EINVAL);
  /* Nor into its own subtree, which would put the mount inside itself. */
  if ((r = sys6(SYS_mount, (long) "/mnt-moved", (long) "/mnt-moved/under", 0,
                MS_MOVE, 0, 0)) != -EINVAL)
    fail("moving a mount into its own subtree", r, -EINVAL);

  /* And back, so the checks below still have it where they expect. */
  if ((r = sys6(SYS_mount, (long) "/mnt-moved", (long) "/mnt-dst", 0,
                MS_MOVE, 0, 0)) != 0)
    fail("moving it back", r, 0);

  /*
   * Read-only, and honoured rather than recorded. A mount that took the flag
   * and then accepted writes would be worse than one that refused to exist,
   * since the only reason to ask for it is to be certain.
   */
  if ((r = sys6(SYS_mount, 0, (long) "/mnt-dst", 0,
                MS_REMOUNT | MS_BIND | MS_RDONLY, 0, 0)) != 0)
    fail("mount(MS_REMOUNT|MS_RDONLY)", r, 0);
  if ((r = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/new",
                O_WRONLY | O_CREAT, 0644, 0,0)) != -EROFS)
    fail("creating a file under a read-only mount", r, -EROFS);
  if ((r = sys6(SYS_mkdirat, AT_FDCWD, (long) "/mnt-dst/d", 0755, 0,0,0)) != -EROFS)
    fail("mkdir under a read-only mount", r, -EROFS);
  /* Reading through it still works, which is the other half of read-only. */
  {
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/f", O_RDONLY, 0,0,0);
    if (f < 0)
      fail("reading through a read-only mount", f, 0);
    sys6(SYS_close, f, 0,0,0,0,0);
  }

  if ((r = sys6(SYS_umount2, (long) "/mnt-dst", 0, 0,0,0,0)) != 0)
    fail("umount2", r, 0);
  if ((r = sys6(SYS_openat, AT_FDCWD, (long) "/mnt-dst/f", O_RDONLY, 0,0,0)) != -ENOENT)
    fail("the target after unmounting", r, -ENOENT);
  if ((r = sys6(SYS_umount2, (long) "/mnt-dst", 0, 0,0,0,0)) != -EINVAL)
    fail("umount2 of something that is not a mount", r, -EINVAL);

  /*
   * The pid namespace, which unshare treats as it treats time: the caller stays
   * where it is and the new namespace is for its children. A process cannot be
   * renumbered underneath itself any more than its clock can be moved, and
   * Linux says so - unshare(CLONE_NEWPID) puts the *first child* at pid 1.
   */
  char pbefore[80], pafter[80], pcbefore[80], pcafter[80];
  if (ns_link("/proc/self/ns/pid", pbefore, sizeof pbefore) < 0)
    fail("reading the pid link", -1, 0);
  if (ns_link("/proc/self/ns/pid_for_children", pcbefore, sizeof pcbefore) < 0)
    fail("reading the pid_for_children link", -1, 0);

  long mypid = sys6(SYS_getpid, 0,0,0,0,0,0);
  if ((r = sys6(SYS_unshare, CLONE_NEWPID, 0,0,0,0,0)) != 0)
    fail("unshare(CLONE_NEWPID)", r, 0);

  if (ns_link("/proc/self/ns/pid", pafter, sizeof pafter) < 0)
    fail("re-reading the pid link", -1, 0);
  if (ns_link("/proc/self/ns/pid_for_children", pcafter, sizeof pcafter) < 0)
    fail("re-reading the pid_for_children link", -1, 0);
  if (!eq(pbefore, pafter))
    fails("unshare(CLONE_NEWPID) moved the caller, which it must not", pafter);
  if (eq(pcbefore, pcafter))
    fails("unshare(CLONE_NEWPID) left pid_for_children unchanged", pcafter);
  if (sys6(SYS_getpid, 0,0,0,0,0,0) != mypid)
    fail("the caller's own pid changed", sys6(SYS_getpid,0,0,0,0,0,0), mypid);

  long ppid2 = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (ppid2 < 0)
    fail("clone into the pid namespace", ppid2, 0);
  if (ppid2 == 0) {
    /* First in, so pid 1 - and the parent is outside, which Linux reports as
     * a parent pid of 0 rather than as the number it has elsewhere. */
    if (sys6(SYS_getpid, 0,0,0,0,0,0) != 1)
      sys6(SYS_exit, 5, 0,0,0,0,0);
    if (sys6(SYS_getppid, 0,0,0,0,0,0) != 0)
      sys6(SYS_exit, 6, 0,0,0,0,0);
    /* A pid this namespace does not contain cannot be signalled, which is the
     * containment it does provide. */
    if (sys6(SYS_kill, 99999, 0, 0,0,0,0) != -ESRCH)
      sys6(SYS_exit, 7, 0,0,0,0,0);
    /* Its own link is the namespace the parent set aside. */
    {
      char cl[80];
      if (ns_link("/proc/self/ns/pid", cl, sizeof cl) < 0)
        sys6(SYS_exit, 8, 0,0,0,0,0);
      if (!eq(cl, pcafter))
        sys6(SYS_exit, 9, 0,0,0,0,0);
    }
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  status = 0;
  if ((r = sys6(SYS_wait4, ppid2, (long) &status, 0, 0,0,0)) != ppid2)
    fail("wait4 returned a different pid from clone", r, ppid2);
  switch ((status >> 8) & 0xff) {
  case 0: break;
  case 5: fails("the first child of a new pid namespace was not pid 1", "");
  case 6: fails("its parent, which is outside, was not reported as 0", "");
  case 7: fails("a pid outside the namespace was signallable", "");
  case 8: fails("the child could not read its pid link", "");
  case 9: fails("the child is not in the namespace set aside for it", "");
  default: fail("the pid child exited with", (status >> 8) & 0xff, 0);
  }

  /*
   * The cgroup namespace, which rebases the view of a hierarchy - and needed
   * the hierarchy building first, as the mount namespace needed mount(2).
   *
   * The hierarchy organises processes and controls nothing: cgroup.controllers
   * is empty and stays empty, because Darwin gives an unprivileged process no
   * cpu, memory or io control to enforce a limit with. A cgroup that accepted
   * memory.max and ignored it would be the worst thing here, so there is no
   * such file to write.
   */
  {
    char cg[64];
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/cgroup", O_RDONLY, 0,0,0);
    if (f < 0)
      fail("opening /proc/self/cgroup", f, 0);
    long n = sys6(SYS_read, f, (long) cg, sizeof cg - 1, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    if (n <= 0) fail("reading /proc/self/cgroup", n, 1);
    cg[n] = '\0';
    if (!eq(cg, "0::/\n"))
      fails("the cgroup before anything was mounted", cg);
  }

  if ((r = sys6(SYS_mount, (long) "none", (long) "/cgtest", (long) "cgroup2",
                0, 0, 0)) != 0)
    fail("mount(cgroup2)", r, 0);
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/cgtest/w", 0755, 0,0,0);

  /* A cgroup has the four files a cgroup has, and controllers is empty. */
  {
    char buf[32];
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/cgtest/w/cgroup.controllers",
                  O_RDONLY, 0,0,0);
    if (f < 0)
      fail("a new cgroup has no cgroup.controllers", f, 0);
    long n = sys6(SYS_read, f, (long) buf, sizeof buf, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    if (n != 0)
      fail("cgroup.controllers was not empty, so something claims to control", n, 0);
  }

  /* Joining it, which is what writing to cgroup.procs does. */
  {
    char line[24];
    int li = 0;
    long v = sys6(SYS_getpid, 0,0,0,0,0,0);
    char t[16]; int ti = 0;
    if (v == 0) t[ti++] = '0';
    while (v > 0) { t[ti++] = (char) ('0' + v % 10); v /= 10; }
    while (ti > 0) line[li++] = t[--ti];
    line[li++] = '\n';

    long f = sys6(SYS_openat, AT_FDCWD, (long) "/cgtest/w/cgroup.procs",
                  O_WRONLY, 0,0,0);
    if (f < 0)
      fail("opening cgroup.procs", f, 0);
    if ((r = sys6(SYS_write, f, (long) line, li, 0,0,0)) != li)
      fail("writing to cgroup.procs", r, li);
    sys6(SYS_close, f, 0,0,0,0,0);
  }

  {
    char cg[64];
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/cgroup", O_RDONLY, 0,0,0);
    long n = sys6(SYS_read, f, (long) cg, sizeof cg - 1, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    if (n <= 0) fail("re-reading /proc/self/cgroup", n, 1);
    cg[n] = '\0';
    if (!eq(cg, "0::/w\n"))
      fails("the cgroup after joining one", cg);
  }

  /* And the namespace, whose whole function is to rebase that path: a process
   * in /w that unshares is at the root of its own view, while its actual
   * cgroup has not moved. */
  {
    char gbefore[80], gafter[80], cg[64];
    if (ns_link("/proc/self/ns/cgroup", gbefore, sizeof gbefore) < 0)
      fail("reading the cgroup link", -1, 0);
    if ((r = sys6(SYS_unshare, CLONE_NEWCGROUP, 0,0,0,0,0)) != 0)
      fail("unshare(CLONE_NEWCGROUP)", r, 0);
    if (ns_link("/proc/self/ns/cgroup", gafter, sizeof gafter) < 0)
      fail("re-reading the cgroup link", -1, 0);
    if (eq(gbefore, gafter))
      fails("unshare(CLONE_NEWCGROUP) left the identity unchanged", gafter);

    long f = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/cgroup", O_RDONLY, 0,0,0);
    long n = sys6(SYS_read, f, (long) cg, sizeof cg - 1, 0,0,0);
    sys6(SYS_close, f, 0,0,0,0,0);
    if (n <= 0) fail("reading the cgroup inside the namespace", n, 1);
    cg[n] = '\0';
    if (!eq(cg, "0::/\n"))
      fails("the namespace did not rebase the cgroup path", cg);
  }

  /*
   * The network namespace, which here is an *empty* one and stays empty. A
   * fresh namespace on Linux has a loopback interface that is down, no address
   * and no route, and nothing in it can reach anything - that state needs no
   * network stack, and it is what `unshare -n` is used for.
   *
   * A bind is refused rather than allowed. Linux would let the wildcard address
   * be bound in an empty namespace, but the socket underneath is a host socket
   * and binding it would take a port on the Mac - so two namespaces would
   * collide with each other and with the host, which is the opposite of what
   * was asked for.
   */
  {
    char nbefore[80], nafter[80];
    if (ns_link("/proc/self/ns/net", nbefore, sizeof nbefore) < 0)
      fail("reading the net link", -1, 0);
    if ((r = sys6(SYS_unshare, CLONE_NEWNET, 0,0,0,0,0)) != 0)
      fail("unshare(CLONE_NEWNET)", r, 0);
    if (ns_link("/proc/self/ns/net", nafter, sizeof nafter) < 0)
      fail("re-reading the net link", -1, 0);
    if (eq(nbefore, nafter))
      fails("unshare(CLONE_NEWNET) left the identity unchanged", nafter);

    /* A socket can still be made - Linux makes one too; there is simply
     * nowhere for it to go. */
    long sk = sys6(SYS_socket, AF_INET, SOCK_STREAM, 0, 0,0,0);
    if (sk < 0)
      fail("socket(AF_INET) in a network namespace", sk, 0);

    /* sockaddr_in: family, port 9, 127.0.0.1 */
    unsigned char sin[16] = {0};
    sin[0] = AF_INET; sin[1] = 0;
    sin[2] = 0; sin[3] = 9;
    sin[4] = 127; sin[5] = 0; sin[6] = 0; sin[7] = 1;
    if ((r = sys6(SYS_connect, sk, (long) sin, 16, 0,0,0)) != -ENETUNREACH)
      fail("connect out of an empty network namespace", r, -ENETUNREACH);

    unsigned char any[16] = {0};
    any[0] = AF_INET;
    if ((r = sys6(SYS_bind, sk, (long) any, 16, 0,0,0)) != -EADDRNOTAVAIL)
      fail("bind in an empty network namespace", r, -EADDRNOTAVAIL);
    sys6(SYS_close, sk, 0,0,0,0,0);

    /* AF_UNIX is the mount namespace's business, not this one's, and goes on
     * working - which is what lets anything in here still talk locally. */
    int sv[2] = { -1, -1 };
    if ((r = sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long) sv, 0,0)) != 0)
      fail("socketpair(AF_UNIX) in a network namespace", r, 0);
    sys6(SYS_close, sv[0], 0,0,0,0,0);
    sys6(SYS_close, sv[1], 0,0,0,0,0);
  }

  /*
   * The user namespace. It is an identity here rather than an authority:
   * credentials are translated at the boundary and never rewritten, so a
   * process that maps itself to root is still, to every check nabi makes, the
   * unprivileged process it was. That is the part of Linux's behaviour worth
   * having, and it falls out of *not* implementing capabilities rather than
   * being enforced by them.
   *
   * Last, because unlike the others it changes what every subsequent id-related
   * answer means.
   */
  struct lstat sb;
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/nstest", (long) &sb, 0, 0,0)) < 0)
    fail("stat of the test binary", r, 0);
  long owner_outside = sb.uid;

  char ubefore[80], uafter[80];
  if (ns_link("/proc/self/ns/user", ubefore, sizeof ubefore) < 0)
    fail("reading the user link", -1, 0);
  if ((r = sys6(SYS_unshare, CLONE_NEWUSER, 0,0,0,0,0)) != 0)
    fail("unshare(CLONE_NEWUSER)", r, 0);
  if (ns_link("/proc/self/ns/user", uafter, sizeof uafter) < 0)
    fail("re-reading the user link", -1, 0);
  if (eq(ubefore, uafter))
    fails("unshare(CLONE_NEWUSER) left the identity unchanged", uafter);

  /* Before a map exists there is no id to report, and Linux says nobody. */
  if ((r = sys6(SYS_getuid, 0,0,0,0,0,0)) != NOBODY)
    fail("getuid in a namespace with no map", r, NOBODY);
  if ((r = sys6(SYS_getgid, 0,0,0,0,0,0)) != NOBODY)
    fail("getgid in a namespace with no map", r, NOBODY);
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/nstest", (long) &sb, 0, 0,0)) < 0)
    fail("stat before a map", r, 0);
  if (sb.uid != NOBODY)
    fail("a file's owner before a map", sb.uid, NOBODY);

  /* Map the id this process actually has onto 100. */
  {
    long fd2 = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/uid_map",
                    O_WRONLY, 0,0,0);
    if (fd2 < 0)
      fail("opening /proc/self/uid_map", fd2, 0);
    char line[64];
    int li = 0;
    const char *pfx = "100 ";
    for (int i = 0; pfx[i]; i++) line[li++] = pfx[i];
    long v = owner_outside;
    if (v == 0) line[li++] = '0';
    else { char t[16]; int ti = 0;
           while (v > 0) { t[ti++] = (char) ('0' + v % 10); v /= 10; }
           while (ti > 0) line[li++] = t[--ti]; }
    line[li++] = ' '; line[li++] = '1'; line[li++] = '\n';
    if ((r = sys6(SYS_write, fd2, (long) line, li, 0,0,0)) != li)
      fail("writing uid_map", r, li);
    sys6(SYS_close, fd2, 0,0,0,0,0);
  }

  if ((r = sys6(SYS_getuid, 0,0,0,0,0,0)) != 100)
    fail("getuid after mapping it to 100", r, 100);

  /* And the same map decides what a file's owner reads as. */
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) "/nstest", (long) &sb, 0, 0,0)) < 0)
    fail("stat after a map", r, 0);
  if (sb.uid != 100)
    fail("a mapped owner", sb.uid, 100);

  /* An id the map does not cover has no outside equivalent, so chowning to it
   * is EINVAL rather than a guess. */
  if ((r = sys6(SYS_fchownat, AT_FDCWD, (long) "/nstest", 55, -1, 0, 0)) != -EINVAL)
    fail("chown to an unmapped id", r, -EINVAL);

  /* The map is written once; a second attempt cannot reinterpret every id the
   * process has already been told. */
  {
    long fd3 = sys6(SYS_openat, AT_FDCWD, (long) "/proc/self/uid_map",
                    O_WRONLY, 0,0,0);
    if (fd3 >= 0) {
      r = sys6(SYS_write, fd3, (long) "7 0 1\n", 6, 0,0,0);
      sys6(SYS_close, fd3, 0,0,0,0,0);
      if (r != -EPERM)
        fail("a second write to uid_map", r, -EPERM);
    }
  }

  put("ns ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
