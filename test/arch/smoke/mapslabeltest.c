/* freestanding: /proc/self/stat's startstack names a range in /proc/self/maps.
 *
 * This is the pair bionic's pthread_attr_getstack walks for the main thread:
 * field 28 of stat is where the stack started, and the mapping containing it is
 * the stack. Field 28 was a literal zero - nothing in the tail of stat was
 * filled - so the hunt through maps found no line and bionic called
 * async_safe_fatal("stack not found in /proc/self/maps"). That is what aborted
 * zygote.
 *
 * Checked as a pair rather than separately, because either file alone can look
 * right while the two disagree: a plausible address that no mapping covers
 * fails exactly the same way as a zero.
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
#define SYS_brk 214
#define AT_FDCWD -100

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

static long slurp(const char *path, char *buf, long cap)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long) path, 0, 0, 0, 0);
  if (fd < 0)
    fail("open", (unsigned long) fd);
  long len = 0;
  for (;;) {
    long n = sys6(SYS_read, fd, (long)(buf + len), cap - 1 - len, 0, 0, 0);
    if (n <= 0)
      break;
    len += n;
    if (len >= cap - 1)
      break;
  }
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  buf[len] = '\0';
  return len;
}

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

static int streq_n(const char *a, const char *b, int n)
{
  for (int i = 0; i < n; i++)
    if (a[i] != b[i])
      return 0;
  return 1;
}

static char stat_buf[8192];
static char maps_buf[262144];

void _start(void)
{
  /* Give brk something to cover, so [heap] is a range and not empty. */
  long base = sys6(SYS_brk, 0, 0, 0, 0, 0, 0);
  long grown = sys6(SYS_brk, base + 0x20000, 0, 0, 0, 0, 0);
  if (grown != base + 0x20000)
    fail("brk did not grow", (unsigned long) grown);

  slurp("/proc/self/stat", stat_buf, sizeof stat_buf);

  /* Field 2 is the comm in parentheses and may hold spaces, so start counting
   * after the last ')' - which is how every reader of this file does it. */
  const char *p = stat_buf;
  const char *rp = 0;
  for (const char *q = stat_buf; *q; q++)
    if (*q == ')')
      rp = q;
  if (!rp)
    fail("stat has no comm", 0);
  p = rp + 1;

  /* p is now at field 3. Walk to field 28. */
  unsigned long startstack = 0;
  for (int field = 3; field <= 28; field++) {
    while (*p == ' ') p++;
    if (!*p)
      fail("stat ended at field", (unsigned long) field);
    if (field == 28) {
      unsigned long v = 0;
      while (*p >= '0' && *p <= '9') { v = v * 10 + (unsigned)(*p - '0'); p++; }
      startstack = v;
      break;
    }
    while (*p && *p != ' ') p++;
  }
  if (startstack == 0)
    fail("stat field 28 (startstack) is zero", 0);

  slurp("/proc/self/maps", maps_buf, sizeof maps_buf);

  /* The line whose range contains it, and it must be the one called [stack]. */
  int found = 0, labelled = 0, saw_heap = 0;
  for (const char *line = maps_buf; *line; ) {
    const char *e;
    unsigned long lo = hex_at(line, &e);
    unsigned long hi = 0;
    if (*e == '-')
      hi = hex_at(e + 1, &e);
    const char *eol = e;
    while (*eol && *eol != '\n') eol++;

    /* Bound by the shorter of the two labels; the longer one is checked only
     * where there is room for it. A single q + 7 bound silently never reaches a
     * "[heap]" sitting at the end of a line, which is where it always sits. */
    for (const char *q = line; q + 6 <= eol; q++) {
      if (q + 7 <= eol && streq_n(q, "[stack]", 7)) {
        labelled++;
        if (lo <= startstack && startstack < hi)
          found = 1;
      }
      if (streq_n(q, "[heap]", 6))
        saw_heap = 1;
    }
    line = *eol ? eol + 1 : eol;
  }

  if (labelled == 0)
    fail("no [stack] line in maps, startstack", startstack);
  if (labelled != 1)
    fail("more than one [stack] line", (unsigned long) labelled);
  if (!found)
    fail("the [stack] line does not contain startstack", startstack);
  if (!saw_heap)
    fail("no [heap] line after brk grew", (unsigned long) base);

  put("ok mapslabel\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
