/* freestanding: the guest as pid 1.
 *
 * Being pid 1 is not decoration. libprocessgroup will set up cgroups for pid 1
 * and refuses for anything else - "Cgroup setup can be done only by init
 * process" - so Android's init cannot get past its own first step unless the
 * process it runs in really is the first one in a pid namespace. It used to be
 * arranged from outside, with a helper that cloned into a namespace and exec'd
 * nabi; --pid1 is nabi doing it for itself.
 *
 * What is checked, in whichever mode nabi was started:
 *
 *   - a fork is numbered after the parent and inside the same namespace, not
 *     in a nested one. This is the part that would break if the process were
 *     put in the namespace without its children following it there: the child
 *     would come back as pid 1 of a namespace of its own.
 *   - the child agrees about who its parent is, which is the same fact read
 *     from the other side.
 *
 * The pid itself is printed rather than asserted, because what it should be
 * depends on how nabi was started - the caller checks it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_getpid 172
#define SYS_getppid 173
#define SYS_clone 220
#define SYS_wait4 260
#define SIGCHLD 17

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if(got==expect)return;
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}
static void wantgt(const char*what,long got,long floor){
  if(got>floor)return;
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want more than ");putd(floor);put("\n");}

/*
 * Fork, and bring back one number the child looked up about itself, along with
 * the pid we saw it get. An exit status is eight bits wide, so the answer is
 * the low byte of what the child read - which is enough to compare the two
 * sides against each other, and the only reason every comparison here is made
 * on low bytes rather than on whole pids.
 */
static long ask(int *bad, int want_ppid, long *child_out)
{
  long child = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (child == 0) {
    long v = sys6(want_ppid ? SYS_getppid : SYS_getpid, 0,0,0,0,0,0);
    sys6(SYS_exit_group, v & 0xff, 0,0,0,0,0);
  }
  *child_out = child;
  if (child < 0) {
    (*bad)++;
    put("  FAIL fork: "); putd(child); put("\n");
    return -1;
  }
  long status = 0;
  if (sys6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) < 0) {
    (*bad)++;
    put("  FAIL wait4\n");
    return -1;
  }
  return (status >> 8) & 0xff;
}

void _start(void)
{
  long self = sys6(SYS_getpid, 0,0,0,0,0,0);
  long ppid = sys6(SYS_getppid, 0,0,0,0,0,0);

  /*
   * Twice, because one exit status carries one number and there are two
   * questions. The first is the one that matters: the child says what pid it
   * sees itself as, and it must be the pid we saw it get. A child put in a
   * namespace *below* ours would call itself 1 while we called it something
   * else, and every check that only compares magnitudes would pass.
   */
  long kid_a = 0, kid_b = 0;
  long saw_self = ask(&fails, 0, &kid_a);
  long saw_ppid = ask(&fails, 1, &kid_b);
  wantgt("the child is numbered after us", kid_a, self);
  want("the child agrees what pid it was given", saw_self, kid_a & 0xff);
  want("the child's parent is us", saw_ppid, self & 0xff);
  wantgt("the second child is numbered after the first", kid_b, kid_a);

  if (fails == 0) {
    put("pid1 ok self="); putd(self);
    put(" ppid="); putd(ppid);
    put("\n");
  } else {
    put("pid1 failed\n");
  }
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
