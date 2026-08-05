/* freestanding: the two files under /proc/sys/kernel/random that get read.
 *
 * mSL/FHS mirrors Darwin's sysctl tree under /proc/sys, so /proc/sys/kernel is
 * the kern.* namespace and random/ comes out empty - these two are Linux's own
 * and have no Darwin sysctl behind them. Arch's shell startup reads both, so a
 * login began with three copies of
 *
 *   -bash: /proc/sys/kernel/random/uuid: No such file or directory
 *
 * They are opposites and that is the whole of the test. uuid is a generator
 * with a filename: every read must produce a different value, and a cached one
 * would be worse than a missing file, because nothing would report it. boot_id
 * must not change, for as long as the machine has been up - it comes from
 * Darwin's kern.bootsessionuuid, so every guest on the host agrees on it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define AT_FDCWD -100
#define O_RDONLY 0

#define UUID_PATH "/proc/sys/kernel/random/uuid"
#define BOOT_PATH "/proc/sys/kernel/random/boot_id"

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int n=v<0;if(n)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(n)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long v)
{ put("rand FAIL: "); put(what); put(" "); putd(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0); }

/* Reads the whole file. Returns the length, or a negative errno. */
static long slurp(const char *path, char *buf, long cap)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDONLY, 0, 0, 0);
  if (fd < 0)
    return fd;
  long n = sys6(SYS_read, fd, (long) buf, cap - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n < 0)
    return n;
  buf[n] = '\0';
  return n;
}

/* A UUID and a newline: 8-4-4-4-12 hex digits with hyphens. */
static int looks_like_uuid(const char *s, long n)
{
  if (n != 37 || s[36] != '\n')
    return 0;
  for (int i = 0; i < 36; i++) {
    char c = s[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return 0;
    } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;                 /* lowercase, as Linux writes it */
    }
  }
  return 1;
}

static int same(const char *a, const char *b, long n)
{ for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0; return 1; }

void _start(void)
{
  char a[64], b[64];
  long na, nb;

  if ((na = slurp(UUID_PATH, a, sizeof a)) < 0)
    fail("opening " UUID_PATH " returned", na);
  if (!looks_like_uuid(a, na))
    fail("uuid is not a lowercase UUID and a newline; length", na);

  if ((nb = slurp(UUID_PATH, b, sizeof b)) < 0)
    fail("second read of uuid returned", nb);
  if (!looks_like_uuid(b, nb))
    fail("the second uuid is not a UUID; length", nb);
  if (same(a, b, 36))
    fail("two reads of uuid gave the same value; it is a generator, not a file", 0);

  if ((na = slurp(BOOT_PATH, a, sizeof a)) < 0)
    fail("opening " BOOT_PATH " returned", na);
  if (!looks_like_uuid(a, na))
    fail("boot_id is not a lowercase UUID and a newline; length", na);

  if ((nb = slurp(BOOT_PATH, b, sizeof b)) < 0)
    fail("second read of boot_id returned", nb);
  if (!same(a, b, 36))
    fail("boot_id changed between two reads", 0);

  put("rand ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
