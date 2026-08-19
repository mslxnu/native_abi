/* freestanding: readahead(2) -- prefetch hint.
 *
 * readahead(fd, offset, count) tells the kernel to prefetch data into
 * the page cache.  Darwin maintains its own read-ahead, so NABI
 * validates the fd and returns 0.  A bogus fd must yield EBADF.
 *
 * The test exercises: valid fd returns 0, bogus fd returns EBADF,
 * offset and count are ignored.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write      64
#define SYS_exit       93
#define SYS_openat     56
#define SYS_close      57
#define SYS_readahead  213

#define EBADF    9
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT  0x241
#define AT_FDCWD -100

static const char fname[] = "/ra_src";

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("rahtest FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void want(const char *w, long got, long expect)
{ if (got != expect) fail(w, got, expect); }

void _start(void)
{
  long r;

  /* Create a small source file. */
  r = sys6(SYS_openat, AT_FDCWD, (long)fname, O_CREAT|O_WRONLY, 0644, 0, 0);
  if (r < 0)
    fail("create", r, 0);
  long fd_w = r;
  /* Write some data. */
  sys6(SYS_write, fd_w, (long)fname, 6, 0, 0, 0);
  sys6(SYS_close, fd_w, 0, 0, 0, 0, 0);

  /* Open for reading. */
  r = sys6(SYS_openat, AT_FDCWD, (long)fname, O_RDONLY, 0, 0, 0);
  if (r < 0)
    fail("open", r, 0);
  long fd = r;

  /* ------------------------------------------------------------------ */
  /* readahead: valid fd.                                                */
  /* ------------------------------------------------------------------ */

  /* (1) readahead on a valid fd: returns 0. */
  r = sys6(SYS_readahead, fd, 0, 4096, 0, 0, 0);
  want("valid fd", r, 0);

  /* (2) readahead with offset: returns 0 (offset ignored). */
  r = sys6(SYS_readahead, fd, 100, 4096, 0, 0, 0);
  want("with offset", r, 0);

  /* (3) readahead with large count: returns 0. */
  r = sys6(SYS_readahead, fd, 0, 0x7fffffffffffUL, 0, 0, 0);
  want("large count", r, 0);

  /* (4) readahead with zero count: returns 0. */
  r = sys6(SYS_readahead, fd, 0, 0, 0, 0, 0);
  want("zero count", r, 0);

  /* ------------------------------------------------------------------ */
  /* readahead: bogus fd.                                                */
  /* ------------------------------------------------------------------ */

  /* (5) readahead on bogus fd (-1): EBADF. */
  r = sys6(SYS_readahead, -1, 0, 4096, 0, 0, 0);
  if (r != -EBADF)
    fail("bogus fd", r, -EBADF);

  /* (6) readahead on large bogus fd: EBADF. */
  r = sys6(SYS_readahead, 9999, 0, 4096, 0, 0, 0);
  if (r != -EBADF)
    fail("large bogus fd", r, -EBADF);

  /* ------------------------------------------------------------------ */
  /* Cleanup.                                                           */
  /* ------------------------------------------------------------------ */

  sys6(SYS_close, fd, 0, 0, 0, 0, 0);

  /* (7) readahead on closed fd: EBADF. */
  r = sys6(SYS_readahead, fd, 0, 4096, 0, 0, 0);
  if (r != -EBADF)
    fail("closed fd", r, -EBADF);

  put("rahtest ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
