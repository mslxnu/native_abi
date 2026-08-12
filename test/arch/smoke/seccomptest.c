/* freestanding: seccomp, setreuid/setregid, setfsuid/setfsgid, set_mempolicy.
 *
 * seccomp is only worth having if it *holds*, so the checks are on syscalls
 * actually being stopped rather than on the installer returning 0. An
 * implementation that accepted a filter and enforced nothing would satisfy
 * every program that installs one and confine none of them - which is the
 * failure that cannot be seen from inside the guest, and the reason Landlock
 * was refused where this was not.
 *
 * What is worth checking:
 *
 *   - a filter that answers ERRNO for one syscall makes that syscall fail with
 *     that errno, and leaves every other syscall alone.
 *   - the filter is consulted for the *right* call, so the number in
 *     seccomp_data has to be the one being made.
 *   - a second filter cannot loosen the first. That is what makes a chain safe
 *     to inherit, and it is the property a naive "last one wins" gets wrong.
 *   - it survives a fork, because on arm64 a fork is a fork plus an exec and
 *     the child rebuilds itself from a checkpoint. A child that came back
 *     unfiltered would be a silent hole.
 *   - a filter built for another architecture must not match, or an x86 filter
 *     would pass an aarch64 program.
 *   - a program that runs off its own end, or jumps outside itself, is refused
 *     at install time rather than at some later syscall.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getcwd       17
#define SYS_write        64
#define SYS_exit         93
#define SYS_clone       220
#define SYS_wait4       260
#define SYS_prctl       167
#define SYS_seccomp     277
#define SYS_getpid      172
#define SYS_getppid     173
#define SYS_geteuid     175
#define SYS_getuid      174
#define SYS_getgid      176
#define SYS_getegid     177
#define SYS_setreuid    145
#define SYS_setregid    143
#define SYS_setfsuid    151
#define SYS_setfsgid    152
#define SYS_setresuid   147
#define SYS_set_mempolicy 237
#define SYS_set_mempolicy_home_node 450

#define EPERM   1
#define EACCES 13
#define EINVAL 22
#define ENOSYS 38

#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_GET_SECCOMP      21

#define SECCOMP_SET_MODE_FILTER  1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_RET_ERRNO 0x00050000u
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define SECCOMP_RET_LOG   0x7ffc0000u
#define SECCOMP_RET_USER_NOTIF 0x7fc00000u
#define AUDIT_ARCH_AARCH64 0xc00000b7u

struct sock_filter { unsigned short code; unsigned char jt, jf; unsigned k; };
struct sock_fprog { unsigned short len; unsigned short pad[3]; const struct sock_filter *filter; };

#define BPF_LD_W_ABS 0x20
#define BPF_JEQ_K    0x15
#define BPF_JMP_JA   0x05
#define BPF_RET_K    0x06

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("seccomp FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }

static long
install(const struct sock_filter *f, unsigned short len)
{
  struct sock_fprog p = { len, {0,0,0}, f };
  return sys6(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, (long) &p, 0, 0, 0);
}

void _start(void)
{
  long r;

  /* ---- the credential calls, before anything is filtered ---- */
  {
    /* setfsuid always returns the previous value and never fails, which is the
     * odd part of its interface: the way to know whether it took is to call
     * twice. */
    long prev = sys6(SYS_setfsuid, 4242, 0,0,0,0,0);
    if (prev != 0) fail("setfsuid did not return the previous id", prev, 0);
    long now = sys6(SYS_setfsuid, -1, 0,0,0,0,0);
    if (now != 4242) fail("setfsuid did not take", now, 4242);
    /* Back, or later file access in this test would be checked as 4242. */
    sys6(SYS_setfsuid, 0, 0,0,0,0,0);
    if ((r = sys6(SYS_setfsuid, -1, 0,0,0,0,0)) != 0)
      fail("setfsuid back to root", r, 0);

    long pg = sys6(SYS_setfsgid, 4243, 0,0,0,0,0);
    if (pg != 0) fail("setfsgid did not return the previous id", pg, 0);
    if ((r = sys6(SYS_setfsgid, -1, 0,0,0,0,0)) != 4243)
      fail("setfsgid did not take", r, 4243);
    sys6(SYS_setfsgid, 0, 0,0,0,0,0);

    /* setreuid moves the saved id when the effective id changes, which is what
     * stops a dropped privilege from being picked back up. Checked through a
     * child, so this process keeps its own. */
    long child = sys6(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (child < 0) fail("clone", child, 0);
    if (child == 0) {
      long c = sys6(SYS_setreuid, 1000, 1000, 0,0,0,0);
      if (c != 0) sys6(SYS_exit, 21, 0,0,0,0,0);
      if (sys6(SYS_getuid, 0,0,0,0,0,0) != 1000) sys6(SYS_exit, 22, 0,0,0,0,0);
      if (sys6(SYS_geteuid, 0,0,0,0,0,0) != 1000) sys6(SYS_exit, 23, 0,0,0,0,0);
      /* The saved id moved too, so root is gone for good. */
      if (sys6(SYS_setresuid, 0, 0, -1, 0,0,0) != -EPERM) sys6(SYS_exit, 24, 0,0,0,0,0);
      /* And setfsuid now follows the effective id rather than the old root. */
      if (sys6(SYS_setfsuid, -1, 0,0,0,0,0) != 1000) sys6(SYS_exit, 25, 0,0,0,0,0);
      sys6(SYS_exit, 20, 0,0,0,0,0);
    }
    int ws = 0;
    if ((r = sys6(SYS_wait4, child, (long) &ws, 0, 0, 0, 0)) != child)
      fail("wait4", r, child);
    if (((ws >> 8) & 0xff) != 20)
      fail("setreuid in a child", (ws >> 8) & 0xff, 20);
  }

  /* ---- set_mempolicy ---- */
  {
    unsigned long node0 = 1, node1 = 2;
    if ((r = sys6(SYS_set_mempolicy, 0 /* MPOL_DEFAULT */, 0, 0, 0,0,0)) != 0)
      fail("set_mempolicy(MPOL_DEFAULT)", r, 0);
    if ((r = sys6(SYS_set_mempolicy, 2 /* MPOL_BIND */, (long) &node0, 64, 0,0,0)) != 0)
      fail("set_mempolicy(MPOL_BIND) on the only node", r, 0);
    if ((r = sys6(SYS_set_mempolicy, 2, (long) &node1, 64, 0,0,0)) != -EINVAL)
      fail("set_mempolicy naming a node that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_set_mempolicy, 2, 0, 0, 0,0,0)) != -EINVAL)
      fail("set_mempolicy(MPOL_BIND) over an empty set", r, -EINVAL);
    if ((r = sys6(SYS_set_mempolicy, 99, 0, 0, 0,0,0)) != -EINVAL)
      fail("set_mempolicy with a mode that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_set_mempolicy_home_node, 0, 0, 1, 0, 0, 0)) != -EINVAL)
      fail("set_mempolicy_home_node naming node 1", r, -EINVAL);
  }

  /* ---- what seccomp refuses to install ---- */
  {
    /* Falls off its own end. */
    static const struct sock_filter runoff[] = {
      { BPF_LD_W_ABS, 0, 0, 0 },
    };
    if ((r = install(runoff, 1)) != -EINVAL)
      fail("a filter that does not end in a return", r, -EINVAL);
    /* Jumps outside itself. */
    static const struct sock_filter jumpout[] = {
      { BPF_JMP_JA, 0, 0, 99 },
      { BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW },
    };
    if ((r = install(jumpout, 2)) != -EINVAL)
      fail("a filter that jumps outside itself", r, -EINVAL);
    if ((r = install(runoff, 0)) != -EINVAL)
      fail("an empty filter", r, -EINVAL);

    /* The actions that need somebody attached are reported unavailable rather
     * than accepted and then quietly meaning something else. */
    unsigned act = SECCOMP_RET_USER_NOTIF;
    if ((r = sys6(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, (long) &act, 0,0,0)) >= 0)
      fail("SECCOMP_GET_ACTION_AVAIL for USER_NOTIF", r, -1);
    act = SECCOMP_RET_ERRNO;
    if ((r = sys6(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, (long) &act, 0,0,0)) != 0)
      fail("SECCOMP_GET_ACTION_AVAIL for ERRNO", r, 0);
  }

  /* ---- no_new_privs ---- */
  if ((r = sys6(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0,0,0,0,0)) != 0)
    fail("PR_GET_NO_NEW_PRIVS before setting it", r, 0);
  if ((r = sys6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0,0,0,0)) != 0)
    fail("PR_SET_NO_NEW_PRIVS", r, 0);
  if ((r = sys6(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0,0,0,0,0)) != 1)
    fail("PR_GET_NO_NEW_PRIVS after setting it", r, 1);

  /* ---- a filter that stops one call ---- */
  {
    /* Wrong architecture first: it must not match, so getppid stays allowed. */
    static const struct sock_filter otherarch[] = {
      { BPF_LD_W_ABS, 0, 0, 4 },                       /* A = arch */
      { BPF_JEQ_K, 0, 1, 0xc000003eu },                /* x86-64? */
      { BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 77 },
      { BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW },
    };
    if ((r = install(otherarch, 4)) != 0)
      fail("installing a filter for another architecture", r, 0);
    if ((r = sys6(SYS_getppid, 0,0,0,0,0,0)) < 0)
      fail("a filter for another architecture matched anyway", r, 0);

    /* Now one that does match, on getppid only. */
    static const struct sock_filter block[] = {
      { BPF_LD_W_ABS, 0, 0, 4 },                       /* A = arch */
      { BPF_JEQ_K, 0, 3, AUDIT_ARCH_AARCH64 },
      { BPF_LD_W_ABS, 0, 0, 0 },                       /* A = nr */
      { BPF_JEQ_K, 0, 1, SYS_getppid },
      { BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 77 },
      { BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW },
    };
    if ((r = install(block, 6)) != 0)
      fail("installing a filter", r, 0);

    if ((r = sys6(SYS_prctl, PR_GET_SECCOMP, 0,0,0,0,0)) != 2)
      fail("PR_GET_SECCOMP after installing a filter", r, 2);

    /* The filtered call fails with the filter's errno... */
    if ((r = sys6(SYS_getppid, 0,0,0,0,0,0)) != -77)
      fail("the filtered syscall", r, -77);
    /* ...and its neighbours are untouched, so the number in seccomp_data is
     * the call being made and not a constant. */
    if ((r = sys6(SYS_getpid, 0,0,0,0,0,0)) <= 0)
      fail("an unfiltered syscall beside the filtered one", r, 1);
    if ((r = sys6(SYS_getuid, 0,0,0,0,0,0)) != 0)
      fail("getuid with a filter installed", r, 0);
  }

  /* ---- a second filter cannot loosen the first ---- */
  {
    static const struct sock_filter allowall[] = {
      { BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW },
    };
    if ((r = install(allowall, 1)) != 0)
      fail("installing a second filter", r, 0);
    if ((r = sys6(SYS_getppid, 0,0,0,0,0,0)) != -77)
      fail("a permissive second filter loosened the first", r, -77);
  }

  /* ---- and it survives a fork ---- */
  {
    long child = sys6(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (child < 0) fail("clone", child, 0);
    if (child == 0) {
      long c = sys6(SYS_getppid, 0,0,0,0,0,0);
      /* 7 means the filter came across; 8 means the child was unfiltered. */
      sys6(SYS_exit, c == -77 ? 7 : 8, 0,0,0,0,0);
    }
    int ws = 0;
    if ((r = sys6(SYS_wait4, child, (long) &ws, 0, 0, 0, 0)) != child)
      fail("wait4 for the forked child", r, child);
    if (((ws >> 8) & 0xff) != 7)
      fail("the seccomp filter did not survive the fork", (ws >> 8) & 0xff, 7);
  }

  put("seccomp ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
