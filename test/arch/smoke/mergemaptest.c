/* freestanding: a mapping that was split and made whole again is whole again.
 *
 * mprotect on part of a region splits it, and nothing ever put the halves back
 * together - so a guest that protects a page and then restores the protection
 * is left with two regions where Linux, which merges in mprotect_fixup, has
 * one. Nothing notices until something asks about the whole mapping again, and
 * then mremap says EFAULT because the region it finds at old_addr is shorter
 * than old_size. That is what Android's CFI shadow does: flip one page's
 * protection hundreds of times and then grow the buffer.
 *
 * Checked through mremap rather than by counting regions, because mremap is
 * where the guest feels it.
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
#define SYS_mprotect 226
#define SYS_mremap 216
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define MREMAP_MAYMOVE 1
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

static long take(unsigned long len)
{
  long r = sys6(SYS_mmap, 0, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
  if (r <= 0)
    fail("mmap", (unsigned long) r);
  return r;
}

void _start(void)
{
  /* 1. A grow of an untouched two-page mapping. The control: if this fails the
   *    test is about something else entirely. */
  long a = take(2 * PAGE);
  long g = sys6(SYS_mremap, a, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0, 0);
  if (g <= 0)
    fail("grow of an untouched mapping", (unsigned long) g);
  sys6(SYS_munmap, g, 4 * PAGE, 0, 0, 0, 0);

  /* 2. The same grow, after the first page's protection has been taken away and
   *    given back. Same mapping, same permissions, one region on Linux. */
  long b = take(2 * PAGE);
  if (sys6(SYS_mprotect, b, PAGE, PROT_READ, 0, 0, 0) != 0)
    fail("mprotect to read-only", (unsigned long) b);
  if (sys6(SYS_mprotect, b, PAGE, PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
    fail("mprotect back to read-write", (unsigned long) b);
  long h = sys6(SYS_mremap, b, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0, 0);
  if (h <= 0)
    fail("grow after split and restore", (unsigned long) h);

  /* The bytes have to survive the move, whether it moved or grew in place. */
  volatile unsigned char *p = (volatile unsigned char *) h;
  for (unsigned long i = 0; i < 4 * PAGE; i++)
    p[i] = (unsigned char) (i & 0xff);
  for (unsigned long i = 0; i < 4 * PAGE; i++)
    if (p[i] != (unsigned char) (i & 0xff))
      fail("grown mapping not writable at", i);
  sys6(SYS_munmap, h, 4 * PAGE, 0, 0, 0, 0);

  /* 3. The middle page, protected and restored, with the grow spanning it. A
   *    split at both ends rather than one. */
  long c = take(3 * PAGE);
  if (sys6(SYS_mprotect, c + PAGE, PAGE, PROT_READ, 0, 0, 0) != 0)
    fail("mprotect middle page", (unsigned long) c);
  if (sys6(SYS_mprotect, c + PAGE, PAGE, PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
    fail("mprotect middle page back", (unsigned long) c);
  long k = sys6(SYS_mremap, c, 3 * PAGE, 6 * PAGE, MREMAP_MAYMOVE, 0, 0);
  if (k <= 0)
    fail("grow across a restored middle page", (unsigned long) k);
  sys6(SYS_munmap, k, 6 * PAGE, 0, 0, 0, 0);

  /* 4. A genuinely mixed mapping must still be refused: old_size runs past the
   *    end of the region that starts at old_addr, which is EFAULT on Linux too.
   *    Merging must not become "merge regardless of permission". */
  long d = take(2 * PAGE);
  if (sys6(SYS_mprotect, d, PAGE, PROT_READ, 0, 0, 0) != 0)
    fail("mprotect for the mixed case", (unsigned long) d);
  long m = sys6(SYS_mremap, d, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0, 0);
  if (m != -14)                 /* EFAULT */
    fail("grow across differing permissions was not EFAULT", (unsigned long) m);

  put("ok mergemap\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
