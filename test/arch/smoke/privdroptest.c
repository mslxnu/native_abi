/* freestanding: prctl's shape, and dropping capabilities without holding any.
 *
 * Run under --user, because the capset half is about what a process that is not
 * root may do. captest covers capget/capset as root; this is the other side.
 *
 * The sequence libcap performs on behalf of a daemon giving up privilege is:
 * set KEEPCAPS, change uid, reduce the set, clear KEEPCAPS. Every step of it
 * failed here for a different reason, and dbus-daemon's system bus reported
 * only "Failed to drop capabilities" for all of them.
 *
 *   - prctl was declared with five arguments after the option where Linux has
 *     four, so the last one it read and checked was a register the caller never
 *     wrote. glibc's prctl is variadic and sets only what it was passed, so what
 *     that register held was whatever the previous call left there. The test
 *     puts a value in it deliberately: a correct prctl never looks.
 *
 *   - PR_SET_KEEPCAPS did not exist, and an unknown option is EINVAL.
 *
 *   - capset refused every caller that was not root, including one asking for
 *     nothing. A capability is needed to raise a set, never to drop one.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_capget  90
#define SYS_capset  91
#define SYS_prctl  167
#define SYS_getuid 174

#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define EINVAL 22
#define EPERM   1
#define CAP_VERSION_3 0x20080522u
#define CAP_CHOWN 0   /* bit 0 of the first word */

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("privdrop FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

struct caphdr { unsigned version; int pid; };
struct capdata { unsigned effective, permitted, inheritable; };

void _start(void)
{
  long r;
  if (sys6(SYS_getuid,0,0,0,0,0,0) == 0)
    fail("this test must not run as root", 0, 1000);

  /* The sixth register holds something. A prctl of the right shape never sees
   * it; one that reads it will refuse a call Linux accepts. */
  if ((r = sys6(SYS_prctl, PR_SET_KEEPCAPS, 1, 0, 0, 0, 0x5eedbead)) != 0)
    fail("PR_SET_KEEPCAPS with a dirty sixth register", r, 0);
  if ((r = sys6(SYS_prctl, PR_GET_KEEPCAPS, 0, 0, 0, 0, 0x5eedbead)) != 1)
    fail("PR_GET_KEEPCAPS after setting it", r, 1);
  if ((r = sys6(SYS_prctl, PR_SET_KEEPCAPS, 0, 0, 0, 0, 0)) != 0)
    fail("clearing PR_SET_KEEPCAPS", r, 0);
  if ((r = sys6(SYS_prctl, PR_GET_KEEPCAPS, 0, 0, 0, 0, 0)) != 0)
    fail("PR_GET_KEEPCAPS after clearing it", r, 0);

  /* The arguments Linux does check are still checked: dropping the phantom one
   * must not mean dropping the rule. */
  if ((r = sys6(SYS_prctl, PR_SET_KEEPCAPS, 2, 0, 0, 0, 0)) != -EINVAL)
    fail("PR_SET_KEEPCAPS with a value out of range", r, -EINVAL);
  if ((r = sys6(SYS_prctl, PR_SET_KEEPCAPS, 1, 1, 0, 0, 0)) != -EINVAL)
    fail("PR_SET_KEEPCAPS with a nonzero second argument", r, -EINVAL);

  /* What a non-root process holds, which is nothing. */
  struct caphdr h; h.version = CAP_VERSION_3; h.pid = 0;
  struct capdata d[2];
  if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
    fail("capget", r, 0);
  if (d[0].permitted != 0 || d[0].effective != 0)
    fail("a non-root process holding capabilities", d[0].permitted, 0);

  /*
   * Asking for one is refused - and this has to come first. Dropping to the
   * empty set lowers the ceiling to nothing, after which a request is refused
   * for that reason instead, and the check would pass whether or not a non-root
   * caller is held to holding nothing.
   */
  d[1].effective = d[1].permitted = d[1].inheritable = 0;
  d[0].inheritable = 0;
  d[0].permitted = 1u << CAP_CHOWN;
  d[0].effective = 1u << CAP_CHOWN;
  h.version = CAP_VERSION_3; h.pid = 0;
  if ((r = sys6(SYS_capset, (long) &h, (long) d, 0, 0, 0, 0)) != -EPERM)
    fail("capset asking for a capability we do not hold", r, -EPERM);

  /* Dropping to nothing is allowed; it is what the call is for. */
  d[0].effective = d[0].permitted = d[0].inheritable = 0;
  d[1].effective = d[1].permitted = d[1].inheritable = 0;
  h.version = CAP_VERSION_3; h.pid = 0;
  if ((r = sys6(SYS_capset, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
    fail("capset of the empty set as a non-root process", r, 0);

  put("privdrop ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
