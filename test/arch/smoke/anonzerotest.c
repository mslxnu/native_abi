/* freestanding: MAP_ANONYMOUS memory is zero, including the second time round.
 *
 * Anonymous guest pages come out of the arena, and a munmap hands the range
 * back by punching a hole in the arena's backing file - which reads as zeros
 * again. That punch is best-effort and its result is discarded, so if it ever
 * fails the next guest to be given that offset is handed the previous one's
 * bytes. A stale pointer in supposedly fresh memory is almost impossible to
 * trace back from where it faults, so it is checked here instead.
 *
 * Fill, free, take the same size again, and look. Several rounds, because
 * whether an offset is reused at all depends on the allocator.
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
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define PAGE (16*1024)
#define ROUNDS 8

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

void _start(void)
{
  unsigned long len = 8 * PAGE;

  for (int round = 0; round < ROUNDS; round++) {
    long r = sys6(SYS_mmap, 0, len, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (r <= 0)
      fail("mmap", (unsigned long) r);
    volatile unsigned char *p = (volatile unsigned char *) r;

    /* Anything handed out must be zero, whoever had it before. */
    for (unsigned long i = 0; i < len; i++)
      if (p[i] != 0) {
        put("round "); puthex((unsigned long) round);
        put(" byte "); puthex(i); put(" = "); puthex(p[i]); put("\n");
        fail("fresh anon page not zero at", (unsigned long) r + i);
      }

    /* Leave something behind that the next round would notice. A pointer-shaped
     * value, because that is the shape that does the damage. */
    for (unsigned long i = 0; i < len; i += 8)
      *(volatile unsigned long *)(p + i) = 0x4f6399b000000000UL | i;

    if (sys6(SYS_munmap, r, len, 0, 0, 0, 0) != 0)
      fail("munmap", (unsigned long) r);
  }

  put("ok anonzero\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
