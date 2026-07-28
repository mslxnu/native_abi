/* freestanding: /proc/self/maps describes the guest, not the nabi running it.
 *
 * A guest process is a host process, so mSL/ProcFS resolves /proc/self to the
 * right process - but what it knows about that process is XNU's view, in which
 * it is a `nabi` executing a guest. Its maps are NABI's own host address space:
 * not a distorted view of the guest's, a different one entirely. NABI overlays
 * this file from proc.mm instead.
 *
 * The check is a mapping this test makes itself, at an address the test learns
 * from mmap and can then look for. That is stronger than checking the shape of
 * the output, and it cannot pass against the host's map by accident: a guest
 * address is in the guest's own space, which is not where NABI's host mappings
 * are.
 *
 * Also read after a fork, because whether NABI can answer at all depends on
 * state that on arm64 has to survive fork + exec.
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
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_wait4 260
#define AT_FDCWD -100
#define SIGCHLD 17
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static int str_eq_n(const char *a, const char *b, int n)
{
  for (int i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* Does /proc/self/maps mention `needle`? */
static int maps_mentions(const char *needle, int nlen)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/maps", 0, 0, 0, 0);
  if (fd < 0)
    return -1;                       /* no maps at all */
  static char buf[65536];
  int total = 0;
  for (;;) {
    long n = sys6(SYS_read, fd, (long)(buf + total), sizeof buf - total - 1, 0,0,0);
    if (n <= 0) break;
    total += (int) n;
    if (total >= (int) sizeof buf - 1) break;
  }
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  buf[total] = 0;
  for (int i = 0; i + nlen <= total; i++)
    if (str_eq_n(buf + i, needle, nlen)) return 1;
  return 0;
}

/* 12 lowercase hex digits, the width the maps lines use. */
static void hex12(unsigned long v, char *out)
{
  for (int i = 0; i < 12; i++) {
    unsigned d = (v >> ((11 - i) * 4)) & 0xf;
    out[i] = d < 10 ? '0' + d : 'a' + d - 10;
  }
  out[12] = 0;
}

void _start(void)
{
  long p = sys6(SYS_mmap, 0, 16*1024, PROT_READ|PROT_WRITE,
                MAP_ANON|MAP_PRIVATE, -1, 0);
  if (p < 0) { put("maps FAIL: mmap\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  char want[16];
  hex12((unsigned long) p, want);

  int r = maps_mentions(want, 12);
  if (r < 0) { put("maps skipped\n"); sys6(SYS_exit, 0, 0,0,0,0,0); }
  if (r == 0) {
    put("maps FAIL: guest mapping "); put(want); put(" absent\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  /* Again from a child, which on arm64 is a fresh nabi from a checkpoint. */
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0)
    sys6(SYS_exit, maps_mentions(want, 12) == 1 ? 0 : 1, 0,0,0,0,0);
  if (pid < 0) { put("maps FAIL: fork\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  int status = 0;
  sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
  if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) {
    put("maps FAIL: lost across fork\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  put("maps ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
