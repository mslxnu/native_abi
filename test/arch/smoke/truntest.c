/* freestanding: truncate(2) -- shrink, expand, and error paths.
 *
 * Creates a file with known content, truncates it shorter (must zero the
 * tail), truncates it longer (must read back zero), tries a nonexistent
 * path, and truncates to zero.  File size is verified through fstatat.
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

/* syscall numbers — arm64 */
#define SYS_openat     56
#define SYS_close      57
#define SYS_read       63
#define SYS_write      64
#define SYS_fstatat    79
#define SYS_truncate   45
#define SYS_unlinkat   35

#define AT_FDCWD       (-100)
#define O_WRONLY       1
#define O_CREAT        64     /* 0x40 */
#define O_TRUNC        512    /* 0x200 */

/* arm64 stat: st_size is at byte offset 48 */
#define ST_SIZE_OFF    48

static int checks = 0;

static void check(int cond, const char *msg, long val)
{
  if (!cond) die(msg, val);
  checks++;
}

/* Read file size via fstatat(AT_FDCWD, path, &buf, 0) */
static long filesize(const char *path)
{
  char buf[256];
  long r = sys6(SYS_fstatat, AT_FDCWD, (long)path, (long)buf, 0, 0, 0);
  if (r < 0) return r;
  long sz = 0;
  unsigned char *p = (unsigned char *)buf + ST_SIZE_OFF;
  for (int i = 0; i < 8; i++) sz |= ((long)p[i]) << (i * 8);
  return sz;
}

void _start(void)
{
  long r;
  const char *path = "truntest_file";

  /* (1) Create a 16-byte file with "AAAAAAAAAAAAAAAA" */
  {
    int fd = sys6(SYS_openat, AT_FDCWD, (long)path,
                  O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
    check(fd >= 0, "openat create", fd);
    char buf[16];
    for (int i = 0; i < 16; i++) buf[i] = 'A';
    r = sys6(SYS_write, fd, (long)buf, 16, 0, 0, 0);
    check(r == 16, "write 16 bytes", r);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  }

  /* (2) Verify size is 16 */
  {
    long sz = filesize(path);
    check(sz == 16, "initial size 16", sz);
  }

  /* (3) Truncate to 8 — must shrink */
  r = sys6(SYS_truncate, (long)path, 8, 0, 0, 0, 0);
  check(r == 0, "truncate to 8", r);
  {
    long sz = filesize(path);
    check(sz == 8, "size after shrink", sz);
  }

  /* (4) Read back after shrink — first 8 bytes must be 'A' */
  {
    char buf[8] = {0};
    int fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    check(fd >= 0, "openat read-only", fd);
    r = sys6(SYS_read, fd, (long)buf, 8, 0, 0, 0);
    check(r == 8, "read after shrink", r);
    int ok = 1;
    for (int i = 0; i < 8; i++) if (buf[i] != 'A') ok = 0;
    check(ok, "shrink preserved head", 0);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  }

  /* (5) Truncate to 32 — must expand with zeros */
  r = sys6(SYS_truncate, (long)path, 32, 0, 0, 0, 0);
  check(r == 0, "truncate to 32", r);
  {
    long sz = filesize(path);
    check(sz == 32, "size after expand", sz);
  }

  /* Read back: first 8 bytes 'A', bytes 8..31 must be 0 */
  {
    char buf[32] = {0};
    int fd = sys6(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    check(fd >= 0, "openat read expand", fd);
    r = sys6(SYS_read, fd, (long)buf, 32, 0, 0, 0);
    check(r == 32, "read after expand", r);
    int ok = 1;
    for (int i = 0; i < 8; i++) if (buf[i] != 'A') ok = 0;
    for (int i = 8; i < 32; i++) if (buf[i] != 0) ok = 0;
    check(ok, "expand zeroed hole", 0);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  }

  /* (6) Truncate to 0 */
  r = sys6(SYS_truncate, (long)path, 0, 0, 0, 0, 0);
  check(r == 0, "truncate to 0", r);
  {
    long sz = filesize(path);
    check(sz == 0, "size after truncate-0", sz);
  }

  /* (7) Nonexistent path must return ENOENT (2) */
  r = sys6(SYS_truncate, (long)"no_such_file", 0, 0, 0, 0, 0);
  check(r == -2, "ENOENT on missing path", r);

  /* (8) Truncate a regular file to itself (length = current size = 0) — no-op */
  r = sys6(SYS_truncate, (long)path, 0, 0, 0, 0, 0);
  check(r == 0, "truncate no-op", r);

  /* cleanup */
  sys6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);

  put("truntest ok\n");
  sys6(93,0,0,0,0,0,0); for(;;){}
}
