/* freestanding: the stack a guest is promised is the stack it has.
 *
 * getrlimit(RLIMIT_STACK) used to report the *host* process's limit - the stack
 * nabi itself runs on - while the guest's stack was a fixed two megabytes
 * mapped at exec. So a guest was told eight and given two, and a guest acts on
 * what it is told: bionic's pthread_attr_getstack takes the top of the stack
 * from /proc/self/maps, subtracts rlim_cur, and hands the runtime a range six
 * megabytes of which was never mapped. zygote died in ART's startup with the
 * fault address equal to its own stack pointer.
 *
 * So the test is not "is the limit eight megabytes" - that is a number, and a
 * number can be changed without fixing anything. It is that the limit and the
 * mapping are the same size, and that the whole of it can actually be written.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_openat 56
#define SYS_read 63
#define SYS_close 57
#define SYS_getrlimit 163
#define SYS_prlimit64 261
#define AT_FDCWD -100
#define RLIMIT_STACK 3
#define PAGE 4096

struct rlim { unsigned long cur, max; };

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

static char maps_buf[262144];

static unsigned long hex_at(const char *p, const char **end)
{
  unsigned long v = 0;
  while (*p) {
    unsigned d;
    if (*p >= '0' && *p <= '9') d = (unsigned)(*p - '0');
    else if (*p >= 'a' && *p <= 'f') d = (unsigned)(*p - 'a') + 10;
    else break;
    v = v * 16 + d;
    p++;
  }
  *end = p;
  return v;
}

static int is_stack(const char *line, const char *eol)
{
  for (const char *q = line; q + 7 <= eol; q++)
    if (q[0]=='[' && q[1]=='s' && q[2]=='t' && q[3]=='a' &&
        q[4]=='c' && q[5]=='k' && q[6]==']')
      return 1;
  return 0;
}

/* The [stack] line's bounds. */
static void stack_bounds(unsigned long *lo_out, unsigned long *hi_out)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/maps", 0, 0, 0, 0);
  if (fd < 0)
    fail("open maps", (unsigned long) fd);
  long len = 0;
  for (;;) {
    long n = sys6(SYS_read, fd, (long)(maps_buf + len),
                  (long)(sizeof maps_buf - 1 - (unsigned long) len), 0, 0, 0);
    if (n <= 0) break;
    len += n;
  }
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  maps_buf[len] = '\0';

  *lo_out = *hi_out = 0;
  for (const char *line = maps_buf; *line; ) {
    const char *e;
    unsigned long lo = hex_at(line, &e);
    unsigned long hi = (*e == '-') ? hex_at(e + 1, &e) : 0;
    const char *eol = e;
    while (*eol && *eol != '\n') eol++;
    if (is_stack(line, eol)) {
      *lo_out = lo; *hi_out = hi;
      return;
    }
    line = *eol ? eol + 1 : eol;
  }
}

static unsigned long get_stack_limit(void)
{
  struct rlim rl = { 0, 0 };
  long r = sys6(SYS_getrlimit, RLIMIT_STACK, (long)&rl, 0, 0, 0, 0);
  if (r != 0)
    fail("getrlimit", (unsigned long) r);
  return rl.cur;
}

void _start(void)
{
  unsigned long limit = get_stack_limit();
  if (limit == 0)
    fail("RLIMIT_STACK is zero", 0);

  unsigned long lo = 0, hi = 0;
  stack_bounds(&lo, &hi);
  if (hi == 0)
    fail("no [stack] line in maps", 0);

  /* The promise and the mapping, which is the whole point. */
  if (hi - lo != limit) {
    put("limit "); puthex(limit);
    put(" mapping "); puthex(hi - lo); put("\n");
    fail("RLIMIT_STACK is not the size of the stack", hi - lo);
  }

  /*
   * And every page of it is really there. The low end first, because that is
   * the part that was missing: a guest told it has eight megabytes walks down
   * from the top, and the fault comes where the old mapping stopped. Far below
   * this frame, so nothing being used is touched.
   */
  volatile unsigned char *p = (volatile unsigned char *) lo;
  for (unsigned long off = 0; off + PAGE <= (hi - lo) / 2; off += PAGE)
    p[off] = (unsigned char) ((off / PAGE) & 0xff);
  for (unsigned long off = 0; off + PAGE <= (hi - lo) / 2; off += PAGE)
    if (p[off] != (unsigned char) ((off / PAGE) & 0xff))
      fail("promised stack page is not writable at", lo + off);

  /* A raise is clamped to what exists rather than believed. */
  struct rlim bigger = { 64UL << 20, 64UL << 20 };
  long r = sys6(SYS_prlimit64, 0, RLIMIT_STACK, (long)&bigger, 0, 0, 0);
  if (r != 0)
    fail("prlimit64 raise", (unsigned long) r);
  if (get_stack_limit() != limit)
    fail("a raise above the real stack was believed", get_stack_limit());

  /* A lower is a smaller promise, and is kept. */
  struct rlim smaller = { 1UL << 20, 1UL << 20 };
  r = sys6(SYS_prlimit64, 0, RLIMIT_STACK, (long)&smaller, 0, 0, 0);
  if (r != 0)
    fail("prlimit64 lower", (unsigned long) r);
  if (get_stack_limit() != (1UL << 20))
    fail("a lower was not kept", get_stack_limit());

  put("ok stacklimit\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
