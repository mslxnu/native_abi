/* freestanding: msync on a page that is not the first one.
 *
 * The range has to lie inside the mapping it starts in, and that is the whole
 * of the test. There used to be another clause beside it comparing the offset
 * of the address within its region against the number of bytes being synced -
 * two quantities with nothing to do with each other. What it amounted to was
 * that a page could be synced only if it lay within the first len bytes of its
 * mapping: syncing a whole region worked, syncing its first page worked, and
 * syncing any page after that returned ENOMEM.
 *
 * ART walks its heap exactly that way, a page at a time, so the zygote retried
 * its way through the whole heap one 4KiB call at a time - three quarters of a
 * gigabyte of strace for one boot, and enough load to starve the rest of the
 * machine. adb went from a working shell to "device offline" with adbd itself
 * sitting idle.
 *
 * So the sizes here matter more than the return values: a single page, synced
 * far enough into a mapping that the offset is larger than the length. A test
 * that synced the whole region, or only its first page, passed throughout.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_msync 227
#define SYS_exit_group 94
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MS_SYNC 4
#define MS_ASYNC 1
#define PAGE 4096
#define PAGES 64
#define ENOMEM 12

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  long p = sys6(SYS_mmap, 0, PAGE * PAGES, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  want("mmap", p > 0 || p < -4096, 1);
  if (p <= 0 && p >= -4096) { put("msync failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  /* Touched, so the pages really exist. */
  for (long i = 0; i < PAGE * PAGES; i += PAGE)
    *(volatile char *)(p + i) = 1;

  /* The whole mapping, which always worked. */
  want("the whole mapping", sys6(SYS_msync, p, PAGE * PAGES, MS_SYNC, 0,0,0), 0);

  /* The first page, which always worked because its offset is zero. */
  want("the first page", sys6(SYS_msync, p, PAGE, MS_SYNC, 0,0,0), 0);

  /*
   * And every page after it, one at a time, which is the case that failed. The
   * second page already has an offset of 4096 against a length of 4096.
   */
  for (long i = 1; i < PAGES; i++) {
    long r = sys6(SYS_msync, p + i * PAGE, PAGE, MS_SYNC, 0,0,0);
    if (r != 0) {
      fails++;
      put("  FAIL page "); putd(i); put(" of the mapping: got "); putd(r);
      put(", want 0\n");
      break;                    /* they all fail the same way */
    }
  }

  /* MS_ASYNC takes the same path. */
  want("async, mid-mapping", sys6(SYS_msync, p + 8 * PAGE, PAGE, MS_ASYNC, 0,0,0), 0);

  /* Two pages from the middle, so length and offset differ. */
  want("two pages, mid-mapping",
       sys6(SYS_msync, p + 30 * PAGE, 2 * PAGE, MS_SYNC, 0,0,0), 0);

  /* Past the end is still ENOMEM, which is what the bounds test is for. */
  want("running off the end",
       sys6(SYS_msync, p + (PAGES - 1) * PAGE, 4 * PAGE, MS_SYNC, 0,0,0), -ENOMEM);

  sys6(SYS_munmap, p, PAGE * PAGES, 0,0,0,0);
  put(fails == 0 ? "msync ok\n" : "msync failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
