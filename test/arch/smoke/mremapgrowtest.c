/* freestanding: growing a mapping, repeatedly, the way realloc does.
 *
 * A large buffer that grows in steps is the shape that matters. Linux extends
 * the mapping where it stands when the space above it is free, so each step
 * costs the pages it adds; nabi allocated the whole new size, copied the old
 * bytes across, and rebuilt the mapping a page at a time, which costs the whole
 * region every time. dnf's download buffer went from 1.7MB upwards in 64KiB
 * steps, 2199 times in one process - and `dnf check-update` took 8m55s, of
 * which 3m39s was nabi re-mapping some ten gigabytes of pages to move two
 * megabytes of data. It also abandoned each old allocation, so the arena grew
 * with the square of the buffer until it could not be extended at all.
 *
 * Speed is not what this checks - a timing test would be a flaky one. What it
 * checks is what has to remain true for the fast path to be allowed to run:
 *
 *   - the bytes survive every grow, including the ones written before it;
 *   - a mapping made *after* a grow does not land inside the grown region.
 *     That is the failure the first attempt actually produced: alloc_region is
 *     a bump allocator that never consults the region tree, so growing into
 *     the space it was about to hand out put one region on top of another and
 *     panicked "recording overlapping regions" some hundreds of allocations
 *     later, nowhere near the mremap that caused it.
 *   - and the region can still be unmapped as one, which is what a caller that
 *     grew it will eventually do.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_mremap 216
#define SYS_exit_group 94
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MREMAP_MAYMOVE 1

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void puth(unsigned long v){char b[19];int i=18;b[i--]=0;
  if(v==0)b[i--]='0';while(v>0){unsigned d=v&15;b[i--]=d<10?'0'+d:'a'+d-10;v>>=4;}
  put("0x");put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

/* Keyed to the offset, not the address: the region may legitimately move, and
 * the bytes have to arrive with it either way. */
static unsigned long pat(unsigned long off){ return off * 0x9E3779B97F4A7C15UL ^ 0xA5A5UL; }
static void fill(unsigned long base, unsigned long from, unsigned long to){
  for (unsigned long o = from; o + 8 <= to; o += 8)
    *(volatile unsigned long *)(base + o) = pat(o);
}
static int check(const char *what, unsigned long base, unsigned long len){
  int bad = 0;
  for (unsigned long o = 0; o + 8 <= len; o += 8) {
    unsigned long got = *(volatile unsigned long *)(base + o);
    if (got == pat(o)) continue;
    if (bad < 3) {
      put("  FAIL "); put(what); put(" at offset "); puth(o);
      put(": got "); puth(got); put(", want "); puth(pat(o));
      if (got == 0) put(" [zeroed - something was mapped over it]");
      put("\n");
    }
    bad++;
  }
  return bad;
}

#define START 0x40000
#define STEP  0x10000
#define GROWS 24

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  (void) sp;
  unsigned long size = START;
  long a = sys6(SYS_mmap, 0, (long) size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (a >= -4096 && a < 0) { put("mmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  unsigned long base = (unsigned long) a;
  fill(base, 0, size);

  for (int i = 0; i < GROWS; i++) {
    unsigned long want_size = size + STEP;
    long r = sys6(SYS_mremap, (long) base, (long) size, (long) want_size,
                  MREMAP_MAYMOVE, 0, 0);
    if (r >= -4096 && r < 0) {
      fails++;
      put("  FAIL mremap grow "); putd(i); put(" -> "); putd(r); put("\n");
      break;
    }
    base = (unsigned long) r;
    fails += check("the bytes after a grow", base, size);
    fill(base, size, want_size);      /* and the new tail is usable */
    size = want_size;

    /*
     * A fresh mapping between grows. If growing in place took space the
     * allocator still thinks is free, this is what lands on top of it - and
     * the damage shows up in the region above, not here.
     */
    long other = sys6(SYS_mmap, 0, 0x8000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (other >= -4096 && other < 0) { fails++; put("  FAIL interleaved mmap\n"); break; }
    /* Write all over it, so an overlap cannot go unnoticed. */
    for (unsigned long o = 0; o + 8 <= 0x8000; o += 8)
      *(volatile unsigned long *)((unsigned long) other + o) = 0;
    if ((unsigned long) other < base + size &&
        (unsigned long) other + 0x8000 > base) {
      fails++;
      put("  FAIL a later mmap landed inside the grown region: ");
      puth((unsigned long) other); put(" is within ["); puth(base);
      put(", "); puth(base + size); put(")\n");
    }
    fails += check("the bytes after an interleaved mmap", base, size);
  }

  want("grew to the size asked for", (long) size, START + (long) GROWS * STEP);
  fails += check("the bytes at the end", base, size);
  want("and it unmaps as one", sys6(SYS_munmap, (long) base, (long) size, 0,0,0,0), 0);

  put(fails == 0 ? "mremapgrow ok\n" : "mremapgrow failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
