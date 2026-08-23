/* freestanding: what a change of user does to the capabilities.
 *
 * A process that gives up the last of its root ids loses its permitted and
 * effective sets - unless it said to keep them, which is the whole purpose of
 * PR_SET_KEEPCAPS and of the securebit behind it. nabi remembered the flag and
 * reported it and changed no outcome: capget and capset answered from the euid
 * at the moment of asking, so a process that had deliberately kept its
 * capabilities was told it had none.
 *
 * That is fine for the caller the flag was added here for - a daemon dropping
 * privilege, which wants to lose them. It is exactly wrong for the other one.
 * Android's init sets the securebits, changes to the service's user, and *then*
 * installs the capabilities the service is to run with; the last step is a
 * non-root process asking for a non-empty set, and it was refused.
 * "cap_set_proc(0) failed: Operation not permitted", and init aborts rather
 * than start a service with capabilities it could not confirm.
 *
 * What is checked:
 *
 *   - the securebits round-trip, and PR_GET_SECUREBITS does not mind the
 *     uninitialised arguments a varargs prctl leaves behind it.
 *   - the bounding set can be read, and dropped from, and a drop sticks.
 *   - with keepcaps, a process that becomes another user keeps its permitted
 *     set and can still install a reduced one. This is Android's sequence.
 *   - without keepcaps, the same change of user takes the set away, and asking
 *     for it back is refused. This is the rule the keeping is an exception to,
 *     and it is checked so that the exception cannot be an accident.
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
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define SIGCHLD 17
#define EPERM 1

#define PR_SET_KEEPCAPS   8
#define PR_CAPBSET_READ  23
#define PR_CAPBSET_DROP  24
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#define SECBIT_KEEP_CAPS 0x10
#define CAP_SETPCAP  8
#define CAP_SYS_BOOT 22
#define CAP_CHOWN    0
#define CAPVER3 0x20080522

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

static long capget2(struct cap_data *d)
{
  struct cap_header h = { CAPVER3, 0 };
  d[0].effective = d[0].permitted = d[0].inheritable = 0;
  d[1].effective = d[1].permitted = d[1].inheritable = 0;
  return sys6(SYS_capget, (long)&h, (long)d, 0, 0, 0, 0);
}
static long capset2(unsigned int eff, unsigned int perm, unsigned int inh)
{
  struct cap_header h = { CAPVER3, 0 };
  struct cap_data d[2];
  d[0].effective = eff; d[0].permitted = perm; d[0].inheritable = inh;
  d[1].effective = d[1].permitted = d[1].inheritable = 0;
  return sys6(SYS_capset, (long)&h, (long)d, 0, 0, 0, 0);
}

/* Become somebody else, then try to install a reduced set. The exit status is
 * the answer: 0 for what was expected, and a number saying which step differed
 * otherwise. */
static void child(int keep)
{
  struct cap_data d[2];
  if (keep && sys6(SYS_prctl, PR_SET_KEEPCAPS, 1, 0, 0, 0, 0) != 0)
    sys6(SYS_exit_group, 1, 0,0,0,0,0);
  if (sys6(SYS_setuid, 1000, 0, 0, 0, 0, 0) != 0)
    sys6(SYS_exit_group, 2, 0,0,0,0,0);
  if (capget2(d) != 0)
    sys6(SYS_exit_group, 3, 0,0,0,0,0);

  if (keep) {
    /* Kept, so still held - and a reduced set can still be installed. */
    if (d[0].permitted == 0)
      sys6(SYS_exit_group, 4, 0,0,0,0,0);
    if (capset2(1u << CAP_CHOWN, 1u << CAP_CHOWN, 0) != 0)
      sys6(SYS_exit_group, 5, 0,0,0,0,0);
    if (capget2(d) != 0 || d[0].permitted != (1u << CAP_CHOWN))
      sys6(SYS_exit_group, 6, 0,0,0,0,0);
  } else {
    /* Not kept, so gone - and asking for one back is refused. */
    if (d[0].permitted != 0)
      sys6(SYS_exit_group, 7, 0,0,0,0,0);
    if (capset2(1u << CAP_CHOWN, 1u << CAP_CHOWN, 0) != -EPERM)
      sys6(SYS_exit_group, 8, 0,0,0,0,0);
  }
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}

static long run(int keep)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0)
    child(keep);
  if (kid < 0)
    return -1;
  long status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  return (status >> 8) & 0xff;
}

void _start(void)
{
  struct cap_data d[2];

  want("capget", capget2(d), 0);
  want("root holds capabilities", d[0].permitted != 0, 1);

  /* The securebits. The extra arguments are deliberately junk: a varargs prctl
   * leaves whatever was on the stack, and Linux does not look at them. */
  want("PR_GET_SECUREBITS ignores its other arguments",
       sys6(SYS_prctl, PR_GET_SECUREBITS, 0x1234, 0x5678, 0x9abc, 0, 0), 0);
  want("PR_SET_SECUREBITS",
       sys6(SYS_prctl, PR_SET_SECUREBITS, SECBIT_KEEP_CAPS, 0, 0, 0, 0), 0);
  want("and it reads back",
       sys6(SYS_prctl, PR_GET_SECUREBITS, 0, 0, 0, 0, 0), SECBIT_KEEP_CAPS);
  want("PR_SET_SECUREBITS back to nothing",
       sys6(SYS_prctl, PR_SET_SECUREBITS, 0, 0, 0, 0, 0), 0);

  /* The bounding set. */
  want("CAP_SETPCAP is in the bound",
       sys6(SYS_prctl, PR_CAPBSET_READ, CAP_SETPCAP, 0, 0, 0, 0), 1);
  want("a capability past the last one is EINVAL",
       sys6(SYS_prctl, PR_CAPBSET_READ, 200, 0, 0, 0, 0), -22);
  want("dropping from the bound",
       sys6(SYS_prctl, PR_CAPBSET_DROP, CAP_SYS_BOOT, 0, 0, 0, 0), 0);
  want("and the drop sticks",
       sys6(SYS_prctl, PR_CAPBSET_READ, CAP_SYS_BOOT, 0, 0, 0, 0), 0);

  /* The two halves of the setuid rule, each in its own process. */
  want("with keepcaps, the set survives becoming another user", run(1), 0);
  want("without it, the set is taken away", run(0), 0);

  put(fails == 0 ? "capuid ok\n" : "capuid failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
