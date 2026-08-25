/* freestanding: AT_PAGESZ is the granule mmap actually uses.
 *
 * A guest computes with the page size it is given. glibc's allocator serves
 * anything past its mmap threshold with a mapping of its own, and when freeing
 * one it checks that the address and the length are page-aligned - by that
 * number. So a guest told its pages are larger than they are aborts on the
 * first large free, with a message about the heap:
 *
 *     munmap_chunk(): invalid pointer
 *
 * which is not heap corruption and says nothing about where to look. On Apple
 * Silicon AT_PAGESZ said 16KiB, the stage-2 block size, while guest mappings
 * had been 4KiB-granular since the two were separated - so `sudo apt install`
 * and `sudo dnf install` both died on both distributions, and anything else
 * that allocated past the threshold with them.
 *
 * What is checked: every address mmap returns is aligned to AT_PAGESZ. Several
 * of them, of awkward sizes, because a mapping that happens to land on a
 * coarser boundary proves nothing - under the bug about one in four did.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_exit_group 94
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define AT_PAGESZ 6

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  /* argc, then argv and its terminator, then envp and its terminator, then the
   * auxiliary vector - which is where the kernel says how big a page is. */
  unsigned long argc = sp[0];
  unsigned long *p = &sp[1 + argc + 1];
  while (*p) p++;
  p++;

  unsigned long pagesz = 0;
  for (; p[0] != 0; p += 2)
    if (p[0] == AT_PAGESZ)
      pagesz = p[1];

  want("the auxv says how big a page is", pagesz != 0, 1);
  if (pagesz == 0) { put("pagesz failed\n"); sys6(SYS_exit_group, 1, 0,0,0,0,0); }
  want("and it is a power of two", (pagesz & (pagesz - 1)) == 0, 1);
  want("and at least 4096", pagesz >= 4096, 1);

  /*
   * Awkward sizes on purpose: a mapping the size of a page, or of several,
   * would be laid out the same either way. What has to hold is that whatever
   * mmap hands back can be freed by something that believes in pagesz.
   */
  static const unsigned long sizes[] = {
    1, 4095, 4097, 8192 + 1, 65536 - 8, 131072 + 4096, 3, 262144 + 1,
  };
  for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
    unsigned long a = (unsigned long) sys6(SYS_mmap, 0, (long) sizes[i],
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long) a >= -4096 && (long) a < 0) {
      fails++;
      put("  FAIL mmap of "); putd((long) sizes[i]); put(" -> ");
      putd((long) a); put("\n");
      continue;
    }
    if ((a & (pagesz - 1)) != 0) {
      fails++;
      put("  FAIL mmap of "); putd((long) sizes[i]);
      put(" is not aligned to the page size the guest was told (");
      putd((long) pagesz); put(")\n");
    }
    /* Usable, so this is a real mapping and not a number. */
    *(volatile unsigned char *) a = 0x5a;
    want("and readable back", *(volatile unsigned char *) a, 0x5a);
    sys6(SYS_munmap, (long) a, (long) sizes[i], 0, 0, 0, 0);
  }

  put(fails == 0 ? "pagesz ok\n" : "pagesz failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
