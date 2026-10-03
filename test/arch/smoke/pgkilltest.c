/* freestanding: signalling a process group.
 *
 * kill(-pgid, sig) used to translate the group as a pid and hand the host its own
 * process group of that number. A host group of that number is a different thing:
 * one nabi does not own answers EPERM, which is what Android's libprocessgroup met
 * 376 times a boot - "kill(-512, 9) failed: Operation not permitted", then "Failed
 * to kill process cgroup ... 1 processes remain" - and one that does not exist
 * answers ESRCH. The quiet half was the worse one. On a machine where that number
 * happened to name a group of this account's own processes the signal would have
 * been delivered to them, and a pid namespace that lets a signal out by arithmetic
 * is not containing anything.
 *
 * It is delivered a member at a time now, to the members of the namespace whose own
 * group is the one named. So what is checked is that a group reaches *every* member
 * of itself: the leader is waited for and must die of the signal, and a pipe the
 * whole group holds open must reach end of file, which it can only do once the
 * member that was never named directly has died too.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_setpgid 154
#define SYS_getpgid 155
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_kill 129
#define SYS_nanosleep 101
#define SYS_exit 93
#define SYS_exit_group 94
#define SIGCHLD 17
#define SIGKILL 9
#define ESRCH 3

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';put(b+i+1);}
static int fails;
static void bad(const char *what){ fails++; put("  FAIL "); put(what); put("\n"); }
static void badv(const char *what, long got, long want){
  fails++; put("  FAIL "); put(what); put(": got "); putd(got);
  put(", want "); putd(want); put("\n"); }

struct tspec { long sec, nsec; };
static void nap(long ms){ struct tspec t = { ms / 1000, (ms % 1000) * 1000000 };
  sys6(SYS_nanosleep, (long) &t, 0, 0,0,0,0); }

void _start(void)
{
  int fds[2];
  if (sys6(SYS_pipe2, (long) fds, 0, 0,0,0,0) != 0) {
    put("pipe FAIL\n");
    sys6(SYS_exit_group, 1, 0,0,0,0,0);
  }

  /*
   * The leader makes the group and then has a child of its own, so the group has a
   * member nothing ever names: the only way it can be signalled is by the group
   * really being a group. Both hold the pipe's write end, so end of file is the
   * proof that both are gone.
   */
  long leader = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (leader == 0) {
    sys6(SYS_setpgid, 0, 0, 0,0,0,0);
    sys6(SYS_close, fds[0], 0,0,0,0,0);
    long second = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (second == 0) {
      sys6(SYS_write, fds[1], (long) "b", 1, 0,0,0);   /* "the second one is up" */
      for (;;) nap(1000);
    }
    sys6(SYS_write, fds[1], (long) "a", 1, 0,0,0);     /* "the leader is up" */
    for (;;) nap(1000);
  }
  if (leader < 0) {
    put("clone FAIL\n");
    sys6(SYS_exit_group, 2, 0,0,0,0,0);
  }

  /* Ours is the only copy of the write end left, so EOF means the group is gone. */
  sys6(SYS_close, fds[1], 0,0,0,0,0);

  char hello[2];
  if (sys6(SYS_read, fds[0], (long) hello, 1, 0,0,0) != 1) bad("the leader never started");
  if (sys6(SYS_read, fds[0], (long) hello, 1, 0,0,0) != 1) bad("the second member never started");

  /* A group that exists nowhere is ESRCH, rather than a signal sent somewhere. */
  long r = sys6(SYS_kill, -999999, 0, 0,0,0,0);
  if (r != -ESRCH)
    badv("a group that does not exist", r, -ESRCH);

  /* The leader made itself the leader, so the group's number is its pid. */
  if ((r = sys6(SYS_kill, -leader, SIGKILL, 0,0,0,0)) != 0)
    badv("signalling the group", r, 0);

  long status = 0;
  long w = sys6(SYS_wait4, leader, (long) &status, 0, 0, 0, 0);
  if (w != leader)
    badv("waiting for the leader", w, leader);
  else if ((status & 0x7f) != SIGKILL)
    badv("the leader died of the wrong thing", status & 0x7f, SIGKILL);

  /*
   * And the member nobody named is gone too. Without a real group it stayed alive
   * holding the pipe open, and this read would block rather than return nothing.
   */
  long n = sys6(SYS_read, fds[0], (long) hello, 1, 0,0,0);
  if (n != 0)
    badv("the whole group was not signalled; the pipe is still held open", n, 0);

  /*
   * And a group outlives its leader, which is the part that cannot be done by
   * handing the host a number.
   *
   * A process group exists on Linux while any process is in it, leader or not. The
   * old translation produced the leader's host pid and asked the host about its
   * group of that number; once the leader has exited and been reaped there is no
   * such host group, so a group with a living member in it answered ESRCH and the
   * member was never signalled. Enumerating the namespace finds it, because what
   * is compared is each member's own group.
   */
  {
    int fd2[2];
    if (sys6(SYS_pipe2, (long) fd2, 0, 0,0,0,0) != 0) {
      bad("second pipe");
    } else {
      long lead2 = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
      if (lead2 == 0) {
        sys6(SYS_setpgid, 0, 0, 0,0,0,0);
        sys6(SYS_close, fd2[0], 0,0,0,0,0);
        long sec = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (sec == 0) {
          sys6(SYS_write, fd2[1], (long) "b", 1, 0,0,0);
          for (;;) nap(1000);
        }
        /* The leader leaves at once; the group is now its child's alone. */
        sys6(SYS_exit, 0, 0,0,0,0,0);
      }
      if (lead2 < 0) {
        bad("clone for the orphaned group");
      } else {
        sys6(SYS_close, fd2[1], 0,0,0,0,0);
        char c2[2];
        if (sys6(SYS_read, fd2[0], (long) c2, 1, 0,0,0) != 1)
          bad("the orphaned group's member never started");
        long st2 = 0;
        if (sys6(SYS_wait4, lead2, (long) &st2, 0, 0, 0, 0) != lead2)
          bad("could not reap the leader");
        nap(200);

        long r2 = sys6(SYS_kill, -lead2, SIGKILL, 0,0,0,0);
        if (r2 != 0)
          badv("signalling a group whose leader has gone", r2, 0);
        long n2 = sys6(SYS_read, fd2[0], (long) c2, 1, 0,0,0);
        if (n2 != 0)
          badv("the surviving member of the group was not signalled", n2, 0);
      }
    }
  }

  put(fails == 0 ? "pgkill ok\n" : "pgkill failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
