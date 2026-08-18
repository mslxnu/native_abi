/* freestanding: renameat2, which is renameat with the flags Linux added.
 *
 * The only unimplemented syscall waydroid's container reaches - LXC renames
 * with RENAME_NOREPLACE, and unimplemented meant ENOSYS where a rename was
 * expected.
 *
 * Darwin has the two that matter under other names: RENAME_EXCL refuses to
 * clobber and RENAME_SWAP is the atomic exchange. What is checked is that they
 * do the thing rather than merely return 0 - a NOREPLACE that quietly replaced,
 * or an EXCHANGE that renamed one way, would both satisfy a check on the return
 * value alone, and both are what the flags exist to prevent.
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
#define SYS_read       63
#define SYS_unlinkat   35
#define SYS_renameat2 276

#define AT_FDCWD  (-100)
#define O_WRONLY   1
#define O_CREAT   64
#define O_TRUNC  512
#define EEXIST    17
#define EINVAL    22

#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE  2
#define RENAME_WHITEOUT  4

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("rename FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static char buf[16];

static void
writefile(const char *path, const char *text, int n)
{
  long f = sys6(SYS_openat, AT_FDCWD, (long) path, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
  if (f < 0) fail("creating a file", f, 0);
  sys6(SYS_write, f, (long) text, n, 0, 0, 0);
  sys6(SYS_close, f, 0, 0, 0, 0, 0);
}

/* The first byte of a file, or -1. */
static int
firstbyte(const char *path)
{
  long f = sys6(SYS_openat, AT_FDCWD, (long) path, 0, 0, 0, 0);
  if (f < 0) return -1;
  long n = sys6(SYS_read, f, (long) buf, 1, 0, 0, 0);
  sys6(SYS_close, f, 0, 0, 0, 0, 0);
  return n == 1 ? (unsigned char) buf[0] : -1;
}

void _start(void)
{
  long r;
  const char *A = "/ra", *B = "/rb", *C = "/rc";

  sys6(SYS_unlinkat, AT_FDCWD, (long) A, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) B, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) C, 0, 0, 0, 0);
  writefile(A, "A", 1);
  writefile(B, "B", 1);

  /* NOREPLACE onto a name that exists must refuse, and must not have moved
   * anything: the refusal is the whole point of the flag. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) A, AT_FDCWD, (long) B, RENAME_NOREPLACE, 0);
  if (r != -EEXIST) fail("NOREPLACE onto an existing name", r, -EEXIST);
  if (firstbyte(A) != 'A') fail("the source after a refused NOREPLACE", firstbyte(A), 'A');
  if (firstbyte(B) != 'B') fail("the target after a refused NOREPLACE", firstbyte(B), 'B');

  /* EXCHANGE swaps them, both ways at once. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) A, AT_FDCWD, (long) B, RENAME_EXCHANGE, 0);
  if (r != 0) fail("EXCHANGE", r, 0);
  if (firstbyte(A) != 'B') fail("the first name after EXCHANGE", firstbyte(A), 'B');
  if (firstbyte(B) != 'A') fail("the second name after EXCHANGE", firstbyte(B), 'A');

  /* NOREPLACE onto a free name is an ordinary rename. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) A, AT_FDCWD, (long) C, RENAME_NOREPLACE, 0);
  if (r != 0) fail("NOREPLACE onto a free name", r, 0);
  if (firstbyte(C) != 'B') fail("what arrived at the new name", firstbyte(C), 'B');
  if (firstbyte(A) != -1) fail("the old name after a rename", firstbyte(A), -1);

  /* No flags is a plain rename. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) C, AT_FDCWD, (long) A, 0, 0);
  if (r != 0) fail("renameat2 with no flags", r, 0);
  if (firstbyte(A) != 'B') fail("what arrived with no flags", firstbyte(A), 'B');

  /* The pair contradict each other and Linux refuses them together. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) A, AT_FDCWD, (long) B,
           RENAME_NOREPLACE | RENAME_EXCHANGE, 0);
  if (r != -EINVAL) fail("NOREPLACE with EXCHANGE", r, -EINVAL);

  /* WHITEOUT belongs to overlayfs and is refused rather than pretended. */
  r = sys6(SYS_renameat2, AT_FDCWD, (long) A, AT_FDCWD, (long) B, RENAME_WHITEOUT, 0);
  if (r != -EINVAL) fail("WHITEOUT", r, -EINVAL);

  sys6(SYS_unlinkat, AT_FDCWD, (long) A, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) B, 0, 0, 0, 0);
  put("rename ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
