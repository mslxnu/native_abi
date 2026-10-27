/* freestanding: a non-zero addr without MAP_FIXED is a hint, and a free one is taken.
 *
 * The hint was discarded and the allocator chose every time. That is a correct
 * mmap and an unsatisfiable one for a caller that needs a particular part of the
 * address space: ART wants the low 4GiB for its compressed references, finds a
 * hole by probing with msync, asks for it by hint, gets an address above 4GiB,
 * unmaps and probes the next page - a loop with no way to end. zygote spent a
 * whole Android boot in it.
 *
 * The hint is a hint, so the other half matters just as much: a hint onto
 * something already mapped must be quietly ignored rather than honoured, or
 * mmap has become MAP_FIXED and will unmap a caller's memory under it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_munmap 215
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define PAGE 4096

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

static void puthex(unsigned long v)
{
  char b[19]; b[0]='0'; b[1]='x';
  for (int i = 0; i < 16; i++) {
    unsigned d = (v >> ((15 - i) * 4)) & 0xf;
    b[2+i] = d < 10 ? '0'+d : 'a'+d-10;
  }
  b[18] = 0;
  put(b);
}

static void fail(const char *what, unsigned long v)
{
  put("FAIL "); put(what); put(" "); puthex(v); put("\n");
  sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

static long hinted(unsigned long hint, unsigned long len)
{
  return sys6(SYS_mmap, hint, len, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANON, -1, 0);
}

void _start(void)
{
  /* 1. A free hint well inside the low 4GiB, which is the case ART needs. The
   *    address is chosen high enough to be clear of the executable and its
   *    libraries and low enough to be under the allocator's own range. */
  unsigned long want = 0x30000000UL;
  long a = hinted(want, 16 * PAGE);
  if (a <= 0)
    fail("hinted mmap", (unsigned long) a);
  if ((unsigned long) a != want) {
    put("asked "); puthex(want); put(" got "); puthex((unsigned long) a); put("\n");
    fail("free hint was not taken", (unsigned long) a);
  }
  /* It has to be real memory, not just the right number. */
  volatile unsigned char *p = (volatile unsigned char *) a;
  for (unsigned long i = 0; i < 16 * PAGE; i++)
    p[i] = (unsigned char) (i & 0xff);
  for (unsigned long i = 0; i < 16 * PAGE; i++)
    if (p[i] != (unsigned char) (i & 0xff))
      fail("hinted mapping not usable at", i);

  /* 2. The same hint again, now occupied. A hint is not MAP_FIXED: it must be
   *    ignored, and the first mapping must survive untouched. */
  long b = hinted(want, 16 * PAGE);
  if (b <= 0)
    fail("hint onto a live mapping", (unsigned long) b);
  if ((unsigned long) b == want)
    fail("occupied hint was taken anyway", (unsigned long) b);
  for (unsigned long i = 0; i < 16 * PAGE; i++)
    if (p[i] != (unsigned char) (i & 0xff))
      fail("first mapping was clobbered at", i);
  sys6(SYS_munmap, b, 16 * PAGE, 0, 0, 0, 0);

  /* 3. A hint that overlaps the live mapping only partly is still occupied. */
  long c = hinted(want + 8 * PAGE, 16 * PAGE);
  if (c <= 0)
    fail("partly overlapping hint", (unsigned long) c);
  if ((unsigned long) c == want + 8 * PAGE)
    fail("partly occupied hint was taken", (unsigned long) c);
  sys6(SYS_munmap, c, 16 * PAGE, 0, 0, 0, 0);

  /* 4. And once the range is free again, the same hint is taken again - so the
   *    bookkeeping gave the addresses back rather than remembering them. */
  sys6(SYS_munmap, a, 16 * PAGE, 0, 0, 0, 0);
  long d = hinted(want, 16 * PAGE);
  if ((unsigned long) d != want)
    fail("hint not taken after the range was freed", (unsigned long) d);
  sys6(SYS_munmap, d, 16 * PAGE, 0, 0, 0, 0);

  /* 5. A hint below mmap_min_addr is ignored, the way Linux ignores it: the
   *    lowest pages are not available by asking politely. */
  long e = hinted(PAGE, 16 * PAGE);
  if (e <= 0)
    fail("hint below mmap_min_addr", (unsigned long) e);
  if ((unsigned long) e == PAGE)
    fail("hint below mmap_min_addr was taken", (unsigned long) e);
  sys6(SYS_munmap, e, 16 * PAGE, 0, 0, 0, 0);

  /* 6. Zero still means "anywhere", which is the overwhelmingly common call. */
  long f = hinted(0, 16 * PAGE);
  if (f <= 0)
    fail("mmap with no hint", (unsigned long) f);
  sys6(SYS_munmap, f, 16 * PAGE, 0, 0, 0, 0);

  put("ok mmaphint\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
