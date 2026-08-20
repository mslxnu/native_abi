/* freestanding: remap_file_pages(2) -- deprecated no-op.
 *
 * remap_file_pages() was deprecated in Linux 3.16.  The kernel returns 0
 * for all callers.  This test exercises the syscall with a handful of
 * argument combinations, verifying that it always returns 0 and never faults.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
  register long x8 asm("x8") = n;
  register long x0 asm("x0") = a; register long x1 asm("x1") = b;
  register long x2 asm("x2") = c; register long x3 asm("x3") = d;
  register long x4 asm("x4") = e; register long x5 asm("x5") = f;
  asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
                              "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}

static int slen(const char *s) { int i=0; while(s[i])i++; return i; }
static void put(const char *m) { sys6(64,1,(long)m,slen(m),0,0,0); }

static void putx(long v)
{
  char buf[18]; int i;
  buf[0]='0'; buf[1]='x';
  for(i=15;i>=0;i--){buf[2+15-i]="0123456789abcdef"[(v>>(i*4))&0xf];}
  sys6(64,1,(long)buf,18,0,0,0);
}

static void die(const char *m, long val)
{
  put("FAIL: "); put(m); put(" ret="); putx(val); put("\n");
  sys6(93,1,0,0,0,0,0); for(;;){}
}

#define SYS_remap_file_pages 234

void _start(void)
{
  long r;

  /* (1) Typical call. */
  r = sys6(SYS_remap_file_pages, 0x1000, 4096, 0, 0, 0, 0);
  if (r != 0) die("basic call", r);

  /* (2) addr=0, size=0. */
  r = sys6(SYS_remap_file_pages, 0, 0, 0, 0, 0, 0);
  if (r != 0) die("zero args", r);

  /* (3) Large addr, large size. */
  r = sys6(SYS_remap_file_pages, 0x7ffffffff000UL, 0x100000, 3, 42, 1, 0);
  if (r != 0) die("large range", r);

  /* (4) prot=PROT_READ. */
  r = sys6(SYS_remap_file_pages, 0x2000, 8192, 1, 0, 0, 0);
  if (r != 0) die("prot=READ", r);

  /* (5) flags=1. */
  r = sys6(SYS_remap_file_pages, 0x3000, 4096, 0, 10, 1, 0);
  if (r != 0) die("flags=1", r);

  put("rfptest ok (5 checks)\n");
  sys6(93,0,0,0,0,0,0); for(;;){}
}
