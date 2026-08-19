/* freestanding: quotactl(2) and quotactl_fd(2) — disk quota control.
 *
 * NABI does not manage disk quotas, so both syscalls return ENOSYS for
 * every subcommand.  The test verifies this for a handful of commands:
 * Q_GETFMT (0x800004), Q_QUOTAON (0x800002), Q_SYNC (0x800001), and
 * Q_GETQUOTA (0x800007).
 *
 * quotactl_fd uses a file descriptor instead of a device path.  A
 * bogus fd (-1) must also yield ENOSYS, not EBADF — the quota check
 * comes before the fd lookup.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write       64
#define SYS_exit        93
#define SYS_quotactl    60
#define SYS_quotactl_fd 443

#define ENOSYS  38
#define EBADF   9

/* Quota commands: type (0=USRQUOTA) | subcommand. */
#define QCMD(cmd, type)  (((cmd) << 8) | ((type) & 0xff))
#define Q_GETFMT     0x800004
#define Q_QUOTAON    0x800002
#define Q_SYNC       0x800001
#define Q_GETQUOTA   0x800007
#define USRQUOTA     0

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("quota FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void want(const char *w, long got, long expect)
{ if (got != expect) fail(w, got, expect); }

/* Fake device path (doesn't matter, quotactl never reaches the path). */
static const char fake_dev[] = "/dev/sda1";

void _start(void)
{
  long r;
  char buf[64];

  /* ------------------------------------------------------------------ */
  /* quotactl: every subcommand returns ENOSYS.                         */
  /* ------------------------------------------------------------------ */

  /* (1) Q_GETFMT on a fake device: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_GETFMT, USRQUOTA), (long)fake_dev, 0, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("Q_GETFMT", r, -ENOSYS);

  /* (2) Q_QUOTAON: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_QUOTAON, USRQUOTA), (long)fake_dev, 0, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("Q_QUOTAON", r, -ENOSYS);

  /* (3) Q_SYNC: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_SYNC, USRQUOTA), (long)fake_dev, 0, 0, 0, 0);
  if (r != -ENOSYS)
    fail("Q_SYNC", r, -ENOSYS);

  /* (4) Q_GETQUOTA: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_GETQUOTA, USRQUOTA), (long)fake_dev, 1000, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("Q_GETQUOTA", r, -ENOSYS);

  /* ------------------------------------------------------------------ */
  /* quotactl_fd: same answer, fd-relative.                             */
  /* ------------------------------------------------------------------ */

  /* (5) Q_GETFMT via bogus fd (-1): ENOSYS (not EBADF). */
  r = sys6(SYS_quotactl_fd, -1, QCMD(Q_GETFMT, USRQUOTA), 0, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("fd Q_GETFMT", r, -ENOSYS);

  /* (6) Q_QUOTAON via bogus fd: ENOSYS. */
  r = sys6(SYS_quotactl_fd, -1, QCMD(Q_QUOTAON, USRQUOTA), 0, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("fd Q_QUOTAON", r, -ENOSYS);

  /* (7) Q_SYNC via bogus fd: ENOSYS. */
  r = sys6(SYS_quotactl_fd, -1, QCMD(Q_SYNC, USRQUOTA), 0, 0, 0, 0);
  if (r != -ENOSYS)
    fail("fd Q_SYNC", r, -ENOSYS);

  /* (8) Q_GETQUOTA via bogus fd: ENOSYS. */
  r = sys6(SYS_quotactl_fd, -1, QCMD(Q_GETQUOTA, USRQUOTA), 1000, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("fd Q_GETQUOTA", r, -ENOSYS);

  /* ------------------------------------------------------------------ */
  /* GRPQUOTA variant: same answer.                                     */
  /* ------------------------------------------------------------------ */

  /* (9) Q_GETFMT with GRPQUOTA type: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_GETFMT, 1), (long)fake_dev, 0, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("GRPQ Q_GETFMT", r, -ENOSYS);

  /* (10) Q_GETQUOTA with GRPQUOTA: ENOSYS. */
  r = sys6(SYS_quotactl, QCMD(Q_GETQUOTA, 1), (long)fake_dev, 100, (long)buf, 0, 0);
  if (r != -ENOSYS)
    fail("GRPQ Q_GETQUOTA", r, -ENOSYS);

  put("quota ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
