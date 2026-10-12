/* freestanding: MADV_DONTNEED means the pages come back zero.
 *
 * madvise was a stub that printed a line and returned 0 for every advice. Most
 * of them are hints and nothing here can act on them, so 0 is the right answer
 * - but MADV_DONTNEED is not a hint. Linux drops the pages, and an anonymous
 * private mapping reads back as zero afterwards; that is the whole point of the
 * call. Android's allocator releases memory that way and then reuses it, so a
 * no-op hands it back a page still holding whatever was there before, which
 * surfaces as a garbage pointer somewhere else entirely.
 *
 * The middle of the range is dropped and the ends are not, because a length
 * that is quietly rounded to the whole region passes a test that only looks at
 * one page.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_madvise 233
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define PAGE (16*1024)
#define EINVAL 22

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

/* First byte in [from,to) that is not `want`, or -1. */
static long differs(volatile unsigned char *p, unsigned long from,
                    unsigned long to, unsigned char want)
{
  for (unsigned long i = from; i < to; i++)
    if (p[i] != want)
      return (long) i;
  return -1;
}

void _start(void)
{
  unsigned long len = 4 * PAGE;
  long r = sys6(SYS_mmap, 0, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
  if (r <= 0)
    fail("mmap", (unsigned long) r);
  volatile unsigned char *p = (volatile unsigned char *) r;

  for (unsigned long i = 0; i < len; i++)
    p[i] = 0xAB;
  long bad = differs(p, 0, len, 0xAB);
  if (bad >= 0)
    fail("fill did not take at", (unsigned long) bad);

  /* A hint. Still accepted, still nothing to do. */
  long h = sys6(SYS_madvise, r, len, MADV_WILLNEED, 0, 0, 0);
  if (h != 0)
    fail("MADV_WILLNEED refused", (unsigned long) h);
  bad = differs(p, 0, len, 0xAB);
  if (bad >= 0)
    fail("MADV_WILLNEED disturbed at", (unsigned long) bad);

  /* Not a hint: the middle two pages go. */
  long d = sys6(SYS_madvise, r + PAGE, 2 * PAGE, MADV_DONTNEED, 0, 0, 0);
  if (d != 0)
    fail("MADV_DONTNEED refused", (unsigned long) d);

  bad = differs(p, PAGE, 3 * PAGE, 0x00);
  if (bad >= 0)
    fail("dropped page not zero at", (unsigned long) bad);
  bad = differs(p, 0, PAGE, 0xAB);
  if (bad >= 0)
    fail("page below the range lost at", (unsigned long) bad);
  bad = differs(p, 3 * PAGE, len, 0xAB);
  if (bad >= 0)
    fail("page above the range lost at", (unsigned long) bad);

  /* And the mapping is still there to be used. */
  for (unsigned long i = PAGE; i < 3 * PAGE; i++)
    p[i] = 0xCD;
  bad = differs(p, PAGE, 3 * PAGE, 0xCD);
  if (bad >= 0)
    fail("refill after drop failed at", (unsigned long) bad);

  /* An unaligned address is EINVAL, not a silent success. */
  long u = sys6(SYS_madvise, r + 1, PAGE, MADV_DONTNEED, 0, 0, 0);
  if (u != -EINVAL)
    fail("unaligned addr accepted", (unsigned long) u);

  put("ok madvise\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
