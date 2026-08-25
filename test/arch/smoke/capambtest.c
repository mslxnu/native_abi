/* freestanding: the ambient capability set, and that an execve carries it.
 *
 * The ambient set is how a process hands capabilities to something it is about
 * to run, when that program is not setuid and carries no file capabilities of
 * its own. It is the only way to do it, and Android's init uses nothing else:
 * it asks whether the mechanism exists before it will accept a `capabilities`
 * line at all - "capabilities requested but the kernel does not support
 * ambient capabilities" - and then raises the bits and execs.
 *
 * Without it, init had already given up its own permitted set by the time it
 * exec'd, on the understanding that ambient was holding the capabilities; so
 * logd started with none, its own capset for CAP_SYSLOG came back EPERM, and
 * it exited. init restarts it, and the restart fails differently - on a
 * read-only property the first attempt had already set - which is two failures
 * away from the cause.
 *
 * What is checked, following init's own sequence:
 *
 *   - the set can be read, raised, lowered and cleared.
 *   - raising is refused unless the capability is already both permitted and
 *     inheritable. That condition is the whole of what makes it safe: nothing
 *     can be added that the process did not already have.
 *   - keeping capabilities across a change of user, then raising ambient,
 *     then giving up the permitted set - and the exec still arrives with the
 *     capability in both permitted and effective. That is the sequence init
 *     performs, and the one that matters.
 *   - and a capability that was never raised does not arrive.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_capget 90
#define SYS_capset 91
#define SYS_prctl 167
#define SYS_setuid 146
#define SYS_execve 221
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define SIGCHLD 17
#define EPERM 1
#define EINVAL 22

#define PR_SET_SECUREBITS 28
#define PR_CAP_AMBIENT 47
#define   AMB_IS_SET 1
#define   AMB_RAISE 2
#define   AMB_LOWER 3
#define   AMB_CLEAR_ALL 4
#define SECBIT_KEEP_CAPS 0x10
#define CAPVER3 0x20080522
#define CAP_CHOWN 0
#define CAP_KILL 5

struct cap_header { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static long capset3(unsigned int eff, unsigned int perm, unsigned int inh)
{
  struct cap_header h = { CAPVER3, 0 };
  struct cap_data d[2];
  d[0].effective = eff; d[0].permitted = perm; d[0].inheritable = inh;
  d[1].effective = d[1].permitted = d[1].inheritable = 0;
  return sys6(SYS_capset, (long)&h, (long)d, 0, 0, 0, 0);
}
static long amb(long op, long cap)
{
  return sys6(SYS_prctl, PR_CAP_AMBIENT, op, cap, 0, 0, 0);
}

/* init's sequence, in a process of its own, ending in the execve whose exit
 * status says what arrived. `raise` chooses whether the capability is put in
 * the ambient set at all. */
static long run(int raise_it)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    char *argv[2]; char *envp[1];
    argv[0] = (char *) "/capambhelper"; argv[1] = 0; envp[0] = 0;

    /* Keep the capabilities across the change of user, as init does. */
    if (sys6(SYS_prctl, PR_SET_SECUREBITS, SECBIT_KEEP_CAPS, 0, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 10, 0,0,0,0,0);
    if (sys6(SYS_setuid, 1000, 0, 0, 0, 0, 0) != 0)
      sys6(SYS_exit_group, 11, 0,0,0,0,0);

    /* Permitted and inheritable, which is what raising ambient requires. */
    if (capset3(1u << CAP_CHOWN, 1u << CAP_CHOWN, 1u << CAP_CHOWN) != 0)
      sys6(SYS_exit_group, 12, 0,0,0,0,0);
    if (raise_it && amb(AMB_RAISE, CAP_CHOWN) != 0)
      sys6(SYS_exit_group, 13, 0,0,0,0,0);

    /* And now give the permitted set up, exactly as init does before the exec:
     * from here only the ambient set can carry anything across. */
    if (capset3(0, 0, 1u << CAP_CHOWN) != 0)
      sys6(SYS_exit_group, 14, 0,0,0,0,0);

    sys6(SYS_execve, (long) argv[0], (long) argv, (long) envp, 0, 0, 0);
    sys6(SYS_exit_group, 15, 0,0,0,0,0);   /* only if the exec failed */
  }
  if (kid < 0)
    return -1;
  long status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  return (status >> 8) & 0xff;
}

void _start(void)
{
  /* It exists, which is the question init asks first. */
  want("PR_CAP_AMBIENT_IS_SET is answered", amb(AMB_IS_SET, CAP_CHOWN), 0);
  want("a capability past the last one is EINVAL", amb(AMB_IS_SET, 200), -EINVAL);

  /* Raising needs the capability to be permitted *and* inheritable. As root
   * it is permitted but the inheritable set starts empty. */
  want("raising one that is not inheritable is refused",
       amb(AMB_RAISE, CAP_KILL), -EPERM);
  want("make it inheritable",
       capset3(1u << CAP_KILL, ~0u, 1u << CAP_KILL), 0);
  want("now it can be raised", amb(AMB_RAISE, CAP_KILL), 0);
  want("and it reads back set", amb(AMB_IS_SET, CAP_KILL), 1);
  want("lowering it", amb(AMB_LOWER, CAP_KILL), 0);
  want("and it is gone", amb(AMB_IS_SET, CAP_KILL), 0);
  want("raise again", amb(AMB_RAISE, CAP_KILL), 0);
  want("clear the lot", amb(AMB_CLEAR_ALL, 0), 0);
  want("and it is gone too", amb(AMB_IS_SET, CAP_KILL), 0);

  /* The sequence that matters: what an execve carries. */
  want("an exec arrives with the ambient capability", run(1), 0);
  want("and without one that was never raised", run(0), 1);

  put(fails == 0 ? "capamb ok\n" : "capamb failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
