/* freestanding: a recorded guest mode the host mode contradicts.
 *
 * NABI keeps a file's guest mode in an extended attribute when the host cannot
 * carry it, and sets the host mode alongside it - always to `record | 0600`, or
 * `| 0700` for a directory, so that NABI can still read what it is holding. The
 * two are written together, so a pair that disagrees is a record NABI could not
 * have produced.
 *
 * That is not a hypothetical. A Fedora tree carried records of 0200 against
 * files the host held at 0644, left by a version of NABI since fixed. 0200
 * denies read to *everyone*, so a non-root guest could not open them - Python
 * could not import `encodings`, and every GLib program that reached one died
 * with a bare PermissionError. Nothing in the guest could diagnose it: the file
 * reports mode 0200, and there is no way from inside to know the number is
 * wrong.
 *
 * The half of this that matters as much as the repair is what must *not* be
 * repaired. "Restrictive" is not the test - /etc/shadow legitimately records
 * 0000 against a host 0600, and sudo records 04111 against a host 0711. Both
 * are what NABI writes, both are correct, and a rule that discarded records
 * denying read would discard those too. So this checks both: the contradictory
 * record is dropped, and the consistent one is obeyed.
 *
 * The two files are prepared by run.sh, which can set an extended attribute
 * where a freestanding guest cannot.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_setgid    144
#define SYS_setuid    146
#define SYS_openat     56
#define SYS_close      57
#define SYS_write      64
#define SYS_exit       93
#define SYS_newfstatat 79

#define AT_FDCWD -100
#define O_RDONLY   0
#define EACCES    13

/* struct stat's mode, at its aarch64 offset. */
#define STAT_MODE_OFF 16

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("stale FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static unsigned mode_of(const char *path)
{
  char st[256];
  for (int i = 0; i < 256; i++) st[i] = 0;
  if (sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) st, 0, 0, 0) < 0)
    fail("stat", -1, 0);
  return (*(unsigned *)(st + STAT_MODE_OFF)) & 07777;
}

void _start(void)
{
  long r;

  /*
   * As a normal user, which is the whole point: root short-circuits the
   * permission check and would never have noticed any of this. The Fedora
   * failure appeared the first time something ran as an ordinary user.
   */
  if ((r = sys6(SYS_setgid, 1000, 0, 0, 0, 0, 0)) != 0)
    fail("setgid", r, 0);
  if ((r = sys6(SYS_setuid, 1000, 0, 0, 0, 0, 0)) != 0)
    fail("setuid", r, 0);

  /*
   * The contradictory record: 0200 recorded, 0644 on the host. NABI cannot have
   * written that pair, so the record is stale and the host mode is the truth.
   */
  { unsigned m = mode_of("/stale");
    if (m == 0200)
      fail("the mode of a file whose record contradicts its host mode", m, 0644);
    if (m != 0644)
      fail("the mode a stale record should fall back to", m, 0644);

    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/stale", O_RDONLY, 0, 0, 0);
    if (fd < 0)
      fail("opening a file whose record is stale", fd, 0);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0); }

  /*
   * And the record that is consistent, which must be obeyed exactly as before -
   * this is /etc/shadow's shape, and breaking it would be worse than the bug.
   */
  { unsigned m = mode_of("/shadowlike");
    if (m != 0000)
      fail("the mode of a file whose record is consistent", m, 0000);

    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/shadowlike", O_RDONLY, 0, 0, 0);
    if (fd >= 0) {
      sys6(SYS_close, fd, 0, 0, 0, 0, 0);
      fail("opening a file recorded 0000, which nobody may read", 0, -EACCES);
    }
    if (fd != -EACCES)
      fail("what opening a file recorded 0000 reported", fd, -EACCES); }

  put("stale ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
