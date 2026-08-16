/* freestanding: AArch64 pointer tags, in hardware and in nabi's own lookups.
 *
 * The top byte of a user pointer is not part of the address. TCR_EL1.TBI0 tells
 * the MMU so, and Linux has set it on arm64 forever - it is what makes tagged
 * pointers possible at all. Android leans on it: bionic tags every heap
 * pointer, so an ordinary malloc result looks like 0xb4000000c4e00010 and the
 * bytes it names live at 0xc4e00010.
 *
 * nabi had neither half. Without TBI0 the MMU translated the tag as address
 * bits, so the guest's first write to its own heap faulted on an address no
 * region covered - Android's sh died on a synthesised SIGSEGV before it printed
 * anything. With TBI0 set the hardware was fine and syscalls still were not,
 * because guest_to_host resolves an address in software and was still counting
 * the tag: `toybox echo hello` answered "write: Bad address" about a buffer
 * that was mapped and readable the whole time.
 *
 * So both halves are checked here, and separately, because either one alone
 * looks like it works right up until the other is needed.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getcwd     17
#define SYS_openat     56
#define SYS_close      57
#define SYS_read       63
#define SYS_write      64
#define SYS_newfstatat 79
#define SYS_exit       93
#define SYS_unlinkat   35
#define AT_FDCWD (-100)
#define O_RDWR   2
#define O_CREAT 0100
#define O_TRUNC 01000

/* A tag in the top byte, the shape bionic's allocator produces. */
#define TAG(p) ((void *)((unsigned long)(p) | (0xB4UL << 56)))

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("tag FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static char buf[8192];
static char cwd[256];

void _start(void)
{
  long r;

  /* ---- the hardware half: TCR_EL1.TBI0 ----
   *
   * A load and a store straight through a tagged pointer. Without TBI0 the
   * translation uses the tag and this faults on an address nothing maps, which
   * nabi reports as an unresolvable page fault and turns into SIGSEGV - so a
   * failure here does not reach the check below, it kills the process. */
  {
    volatile char *t = (volatile char *) TAG(buf);
    *t = 0x5A;
    if (buf[0] != 0x5A)
      fail("a store through a tagged pointer did not reach the object", buf[0], 0x5A);
    buf[1] = 0x27;
    if (t[1] != 0x27)
      fail("a load through a tagged pointer did not read the object", t[1], 0x27);
    /* A tag anywhere in the top byte, not just the one value. */
    volatile char *t2 = (volatile char *) ((unsigned long) buf | (0xFFUL << 56));
    *t2 = 0x11;
    if (buf[0] != 0x11)
      fail("a store through a 0xff tag", buf[0], 0x11);
  }

  /* ---- the software half: nabi's own address lookup ----
   *
   * The same pointers, handed to syscalls. These resolve through guest_to_host
   * rather than the MMU, so TBI0 does nothing for them. */
  {
    static const char msg[] = "tagged-write-ok\n";
    for (unsigned i = 0; i < sizeof msg; i++) buf[i] = msg[i];
    /* write() reading its buffer through a tag. */
    r = sys6(SYS_write, 1, (long) TAG(buf), sizeof msg - 1, 0, 0, 0);
    if (r != (long)(sizeof msg - 1))
      fail("write() from a tagged buffer", r, (long)(sizeof msg - 1));
  }
  {
    /* getcwd() *writing* through a tag - the other direction. */
    for (unsigned i = 0; i < sizeof cwd; i++) cwd[i] = 0;
    r = sys6(SYS_getcwd, (long) TAG(cwd), sizeof cwd, 0, 0, 0, 0);
    if (r < 0)
      fail("getcwd() into a tagged buffer", r, 0);
    if (cwd[0] != '/')
      fail("getcwd() wrote somewhere other than the tagged buffer", cwd[0], '/');
  }
  {
    /* A tagged *path* pointer, which strncpy_from_user has to walk. */
    static const char path[] = "/tagtest.tmp";
    long fd = sys6(SYS_openat, AT_FDCWD, (long) TAG(path), O_RDWR|O_CREAT|O_TRUNC, 0644, 0, 0);
    if (fd < 0)
      fail("openat() with a tagged path", fd, 0);
    static const char body[] = "roundtrip";
    if ((r = sys6(SYS_write, fd, (long) TAG(body), sizeof body - 1, 0,0,0)) != (long)(sizeof body - 1))
      fail("write() of a tagged buffer to a file", r, (long)(sizeof body - 1));
    /* And a tagged struct pointer. */
    static char st[256];
    if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) TAG(path), (long) TAG(st), 0, 0, 0)) != 0)
      fail("newfstatat() with tagged path and tagged buffer", r, 0);
    sys6(SYS_close, fd, 0,0,0,0,0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) TAG(path), 0, 0, 0, 0);
  }

  put("tag ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
