/* freestanding: sendfile(2) and copy_file_range(2).
 *
 * The copying is the easy part. What these get wrong is the bookkeeping, and
 * the case that matters is a short write.
 *
 * An implementation that reads with read(2) and writes what it read has already
 * moved the source's file position by the time it finds out the destination
 * would only take part of it. The rest is consumed, undelivered and unreported
 * - a silent hole in the middle of a copy, and one that only appears when the
 * destination is slow, which is never the case in a small test. So the test
 * below sends a 200K file into a *non-blocking pipe*, which cannot take it all,
 * and then checks the source's position: it must be exactly what the call said
 * it moved. Reading ahead of the write shows up here as a position that has run
 * past the returned count.
 *
 * The offset arguments are checked the same way as splice's, for the same
 * reason: an offset means the file's own position must not move.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_unlinkat        35
#define SYS_fcntl           25
#define SYS_openat          56
#define SYS_close           57
#define SYS_pipe2           59
#define SYS_lseek           62
#define SYS_read            63
#define SYS_write           64
#define SYS_sendfile        71
#define SYS_exit            93
#define SYS_copy_file_range 285

#define AT_FDCWD   -100
#define O_RDONLY    0
#define O_WRONLY    1
#define O_RDWR      2
#define O_CREAT     0100
#define O_TRUNC     01000
#define O_NONBLOCK  04000
#define F_SETFL     4
#define SEEK_SET    0
#define SEEK_CUR    1
#define EBADF       9
#define EINVAL     22
#define EISDIR     21

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("copy FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
static void fails(const char *what, const char *got, const char *want)
{ put("copy FAIL: "); put(what); put(" -> \""); put(got); put("\", wanted \"");
  put(want); put("\"\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void clr(char *b, int n){ for (int i = 0; i < n; i++) b[i] = 0; }

static long mkfile(const char *path, const char *data, int len)
{
  long f = sys6(SYS_openat, AT_FDCWD, (long) path,
                O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
  if (f < 0)
    fail("creating a file", f, 0);
  if (len && sys6(SYS_write, f, (long) data, len, 0, 0, 0) != len)
    fail("writing a file", -1, len);
  sys6(SYS_lseek, f, 0, SEEK_SET, 0, 0, 0);
  return f;
}

void _start(void)
{
  long r;
  char buf[64];

  long src = mkfile("/copysrc", "hello world", 11);
  long dst = mkfile("/copydst", 0, 0);

  /* ---- sendfile, file to file, no offset: the position follows ---- */
  if ((r = sys6(SYS_sendfile, dst, src, 0, 11, 0, 0)) != 11)
    fail("sendfile of eleven bytes", r, 11);
  if ((r = sys6(SYS_lseek, src, 0, SEEK_CUR, 0, 0, 0)) != 11)
    fail("the source position after a sendfile with no offset", r, 11);

  sys6(SYS_lseek, dst, 0, SEEK_SET, 0, 0, 0);
  clr(buf, sizeof buf);
  if ((r = sys6(SYS_read, dst, (long) buf, sizeof buf, 0, 0, 0)) != 11)
    fail("what reached the destination", r, 11);
  if (!eq(buf, "hello world"))
    fails("what sendfile delivered", buf, "hello world");

  /* ---- sendfile with an offset: the offset moves, the position does not ---- */
  { long long off = 6;
    sys6(SYS_lseek, src, 0, SEEK_SET, 0, 0, 0);
    sys6(SYS_lseek, dst, 0, SEEK_SET, 0, 0, 0);
    if ((r = sys6(SYS_sendfile, dst, src, (long) &off, 5, 0, 0)) != 5)
      fail("sendfile from an offset", r, 5);
    if (off != 11)
      fail("the caller's offset afterwards", (long) off, 11);
    if ((r = sys6(SYS_lseek, src, 0, SEEK_CUR, 0, 0, 0)) != 0)
      fail("the source position after an offset sendfile", r, 0);

    sys6(SYS_lseek, dst, 0, SEEK_SET, 0, 0, 0);
    clr(buf, sizeof buf);
    sys6(SYS_read, dst, (long) buf, 5, 0, 0, 0);
    if (!eq(buf, "world"))
      fails("sendfile from an offset", buf, "world"); }

  /* A count past the end returns what is there, not an error. */
  sys6(SYS_lseek, src, 0, SEEK_SET, 0, 0, 0);
  sys6(SYS_lseek, dst, 0, SEEK_SET, 0, 0, 0);
  if ((r = sys6(SYS_sendfile, dst, src, 0, 1000, 0, 0)) != 11)
    fail("sendfile of more than the file holds", r, 11);

  /*
   * ---- the short write ----
   *
   * 200K into a non-blocking pipe, which holds far less. Whatever comes back,
   * the source must be positioned at exactly that - anything further means
   * bytes were taken out of the file and dropped.
   */
  { char block[4096];
    for (int i = 0; i < 4096; i++)
      block[i] = 'a' + (i % 26);
    long big = mkfile("/copybig", 0, 0);
    for (int i = 0; i < 50; i++)
      if (sys6(SYS_write, big, (long) block, 4096, 0, 0, 0) != 4096)
        fail("filling the big file", -1, 4096);
    sys6(SYS_lseek, big, 0, SEEK_SET, 0, 0, 0);

    int p[2];
    if (sys6(SYS_pipe2, (long) p, 0, 0, 0, 0, 0) != 0)
      fail("pipe2", -1, 0);
    if ((r = sys6(SYS_fcntl, p[1], F_SETFL, O_NONBLOCK, 0, 0, 0)) < 0)
      fail("making the pipe non-blocking", r, 0);

    long sent = sys6(SYS_sendfile, p[1], big, 0, 50 * 4096, 0, 0);
    if (sent <= 0)
      fail("sendfile into a non-blocking pipe", sent, 1);
    if (sent >= 50 * 4096)
      fail("the pipe took the whole file; the test proves nothing",
           sent, 50 * 4096 - 1);

    long pos = sys6(SYS_lseek, big, 0, SEEK_CUR, 0, 0, 0);
    if (pos != sent)
      fail("the source position after a short write; bytes were dropped",
           pos, sent);

    sys6(SYS_close, p[0], 0, 0, 0, 0, 0);
    sys6(SYS_close, p[1], 0, 0, 0, 0, 0);
    sys6(SYS_close, big, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/copybig", 0, 0, 0, 0); }

  /* ---- copy_file_range ---- */
  sys6(SYS_lseek, src, 0, SEEK_SET, 0, 0, 0);
  { long f2 = mkfile("/copyout", 0, 0);
    long long oi = 0, oo = 0;
    if ((r = sys6(SYS_copy_file_range, src, (long) &oi, f2, (long) &oo, 11, 0)) != 11)
      fail("copy_file_range of eleven bytes", r, 11);
    if (oi != 11 || oo != 11)
      fail("the offsets afterwards", (long) oi, 11);
    if ((r = sys6(SYS_lseek, src, 0, SEEK_CUR, 0, 0, 0)) != 0)
      fail("the source position after an offset copy", r, 0);

    sys6(SYS_lseek, f2, 0, SEEK_SET, 0, 0, 0);
    clr(buf, sizeof buf);
    sys6(SYS_read, f2, (long) buf, 11, 0, 0, 0);
    if (!eq(buf, "hello world"))
      fails("what copy_file_range delivered", buf, "hello world");

    /* Overlapping ranges of one file have no defined answer. Two separate
     * opens of the same file are the case that must not slip through. */
    { long g = sys6(SYS_openat, AT_FDCWD, (long) "/copysrc", O_RDWR, 0, 0, 0);
      long long a = 0, b = 4;
      if ((r = sys6(SYS_copy_file_range, src, (long) &a, g, (long) &b, 8, 0)) != -EINVAL)
        fail("an overlapping copy within one file", r, -EINVAL);
      /* Non-overlapping in the same file is allowed. */
      a = 0; b = 32;
      if ((r = sys6(SYS_copy_file_range, src, (long) &a, g, (long) &b, 4, 0)) != 4)
        fail("a non-overlapping copy within one file", r, 4);
      sys6(SYS_close, g, 0, 0, 0, 0, 0); }

    sys6(SYS_close, f2, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/copyout", 0, 0, 0, 0); }

  /* ---- what these refuse ---- */
  { int p[2];
    sys6(SYS_pipe2, (long) p, 0, 0, 0, 0, 0);
    if ((r = sys6(SYS_sendfile, dst, p[0], 0, 4, 0, 0)) != -EINVAL)
      fail("sendfile from a pipe", r, -EINVAL);
    if ((r = sys6(SYS_copy_file_range, p[0], 0, dst, 0, 4, 0)) != -EINVAL)
      fail("copy_file_range from a pipe", r, -EINVAL);
    sys6(SYS_close, p[0], 0, 0, 0, 0, 0);
    sys6(SYS_close, p[1], 0, 0, 0, 0, 0); }

  if ((r = sys6(SYS_copy_file_range, src, 0, dst, 0, 4, 1)) != -EINVAL)
    fail("copy_file_range with a flag set", r, -EINVAL);

  { long d = sys6(SYS_openat, AT_FDCWD, (long) "/", O_RDONLY, 0, 0, 0);
    if (d >= 0) {
      if ((r = sys6(SYS_copy_file_range, d, 0, dst, 0, 4, 0)) != -EISDIR)
        fail("copy_file_range from a directory", r, -EISDIR);
      sys6(SYS_close, d, 0, 0, 0, 0, 0);
    } }

  sys6(SYS_close, src, 0, 0, 0, 0, 0);
  sys6(SYS_close, dst, 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/copysrc", 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/copydst", 0, 0, 0, 0);

  put("copy ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
