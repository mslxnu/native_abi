/* freestanding: mremap with MREMAP_FIXED lands at the pinned address.
 *
 * The CFI shadow-rewrite flow works like this: a page the guest wants to write
 * through is made read-only, a temporary page is allocated, and mremap is then
 * asked to move that page onto the protected one - MREMAP_FIXED | MREMAP_MAYMOVE
 * with old_size == new_size. That is a *move*, not a shrink, and an
 * implementation that only shrank in place returned the temporary page's
 * address, which the caller detected and turned into EFAULT - killing the
 * instrumented binary.
 *
 * The sequence here mirrors the traced flow: reserve a region and make one of
 * its interior pages read-only (the destination, deliberately not aligned to
 * the host's 16KiB stage-2 block), allocate a temporary page, fill it, make it
 * read-only too, then mremap it onto the destination. What must hold:
 *
 *   - mremap answers with the pinned destination, not the temporary address;
 *   - the bytes written to the temporary page are present at the destination
 *     (mremap copies on the way);
 *   - the moved page can be mprotected writable and written to, which is what
 *     the shadow-writer does next.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_mremap 216
#define SYS_mprotect 226
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void puthex(unsigned long v){char b[19];b[0]='0';b[1]='x';
  for(int i=0;i<16;i++){unsigned d=(v>>((15-i)*4))&0xf;b[2+i]=d<10?'0'+d:'a'+d-10;}b[18]=0;put(b);}

static void fail(const char*m, long v)
{
  put("mremapfixed FAIL: "); put(m); put(" (");
  puthex((unsigned long)v); put(")\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

void _start(void)
{
  /* A region to hold the destination page. The interior page at +0x2000 is
   * 4KiB-aligned but not 16KiB-aligned, exactly like the traced CFI target. */
  unsigned long res = sys6(SYS_mmap, 0, 0x100000, PROT_NONE,
                           MAP_ANON|MAP_PRIVATE, -1, 0);
  if (res < 0) fail("reserve", res);

  unsigned long dst = res + 0x2000;
  if (sys6(SYS_mprotect, dst, 0x1000, PROT_READ, 0, 0, 0) < 0)
    fail("mprotect dst", res);

  /* The temporary page, filled with a pattern and then made read-only, as the
   * shadow flow does before the move. */
  unsigned long tmp = sys6(SYS_mmap, 0, 0x1000, PROT_READ|PROT_WRITE,
                           MAP_ANON|MAP_PRIVATE, -1, 0);
  if (tmp < 0) fail("mmap temp", tmp);
  for (int i = 0; i < 4096; i++)
    ((unsigned char *) tmp)[i] = (unsigned char)(i ^ 0xa5);
  if (sys6(SYS_mprotect, tmp, 0x1000, PROT_READ, 0, 0, 0) < 0)
    fail("mprotect temp", tmp);

  /* The move. Must answer dst, and the pattern must arrive with it. */
  long r = sys6(SYS_mremap, tmp, 0x1000, 0x1000,
                MREMAP_FIXED|MREMAP_MAYMOVE, dst, 0);
  if (r < 0) fail("mremap", r);
  if (r != (long) dst) {
    put("mremapfixed FAIL: mremap returned "); puthex((unsigned long)r);
    put(" want "); puthex(dst); put("\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }
  for (int i = 0; i < 4096; i += 3) {
    if (((unsigned char *) dst)[i] != (unsigned char)(i ^ 0xa5))
      fail("copy to dst", i);
  }

  /* Make the moved page writable and write through it, which is what the
   * shadow-writer does after the move. */
  if (sys6(SYS_mprotect, dst, 0x1000, PROT_READ|PROT_WRITE, 0, 0, 0) < 0)
    fail("mprotect dst rw", dst);
  ((unsigned char *) dst)[0] = 0x7e;
  if (((unsigned char *) dst)[0] != 0x7e)
    fail("write dst", 0);

  put("mremapfixed ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
