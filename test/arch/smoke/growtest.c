/* freestanding: every page of a large region is writable, including the last.
 *
 * A dpkg install hung on a write near the end of an 8MiB anonymous region that
 * mremap had grown: NABI's stage-1 leaf was valid, writable and EL0-accessible,
 * stage-2 mapped the IPA it named, and the hardware still reported a level-3
 * translation fault - forever, at full CPU.
 *
 * The tail is the suspicious part. vmm_mmap maps stage 2 over
 * roundup(size, 16KiB) but walks stage 1 in 4KiB steps over `size`; arena_alloc
 * rounds to its own granule; and the arena file grows in 4MiB steps. Those four
 * only have to disagree at the very end for the final block of a big region to
 * be the one page that is not really there - and until an 8MiB mremap came
 * along, nothing in the suite was large enough to notice.
 *
 * So: touch first, middle and last page of a fresh mapping, then grow it and
 * touch the new last page. Reading back what was written is the check, because
 * a store that lands somewhere unmapped is exactly the failure being hunted.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_clone 220
#define SYS_wait4 260
#define SIGCHLD 17
#define SYS_mmap 222
#define SYS_mremap 216
#define SYS_mprotect 226
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define MREMAP_MAYMOVE 1

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void puthex(unsigned long v){char b[19];b[0]='0';b[1]='x';
  for(int i=0;i<16;i++){unsigned d=(v>>((15-i)*4))&0xf;b[2+i]=d<10?'0'+d:'a'+d-10;}b[18]=0;put(b);}

/* Write a byte derived from the offset and read it straight back. A mapping
 * that is not really there fails here rather than somewhere later. */
static int touch(unsigned char *p, unsigned long off)
{
  volatile unsigned char *q = p + off;
  *q = (unsigned char)(off ^ 0xa5);
  return *q == (unsigned char)(off ^ 0xa5);
}

static int sweep(unsigned char *p, unsigned long size, const char *what)
{
  /* first, middle, last page, and the very last byte */
  unsigned long spots[] = { 0, size / 2, size - 4096, size - 1 };
  for (unsigned i = 0; i < 4; i++) {
    if (!touch(p, spots[i])) {
      put("grow FAIL: "); put(what); put(" at +"); puthex(spots[i]); put("\n");
      return 0;
    }
  }
  return 1;
}

void _start(void)
{
  /*
   * First the case that actually broke: a large PROT_NONE reservation with a
   * piece mprotected writable, which is how malloc manages an arena and how
   * dpkg's buffer was built. Stage 2 is established at mmap time with the
   * region's permission - none - and mprotect used to rewrite only stage 1, so
   * the guest faulted forever on memory both of NABI's tables called writable.
   */
  unsigned long size = 0x7fc000;
  long res = sys6(SYS_mmap, 0, size, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (res < 0) { put("grow FAIL: reserve\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  if (sys6(SYS_mprotect, res + 0x4000, size - 0x8000,
           PROT_READ|PROT_WRITE, 0, 0, 0) < 0) {
    put("grow FAIL: mprotect\n"); sys6(SYS_exit,1,0,0,0,0,0);
  }
  {
    unsigned char *p = (unsigned char *) res;
    unsigned long spots[] = { 0x4000, size / 2, size - 0x8000 - 1 };
    for (unsigned i = 0; i < 3; i++)
      if (!touch(p, spots[i])) {
        put("grow FAIL: mprotected reservation at +"); puthex(spots[i]);
        put("\n"); sys6(SYS_exit,1,0,0,0,0,0);
      }
  }


  long p = sys6(SYS_mmap, 0, size, PROT_READ|PROT_WRITE,
                MAP_ANON|MAP_PRIVATE, -1, 0);
  if (p < 0) { put("grow FAIL: mmap\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  if (!sweep((unsigned char *) p, size, "fresh mapping"))
    sys6(SYS_exit, 1, 0,0,0,0,0);

  /* Grow it, which is what moved dpkg's buffer to the range that faulted. */
  unsigned long bigger = size + 0x200000;
  long q = sys6(SYS_mremap, p, size, bigger, MREMAP_MAYMOVE, 0, 0);
  if (q < 0) { put("grow FAIL: mremap\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  if (!sweep((unsigned char *) q, bigger, "after mremap"))
    sys6(SYS_exit, 1, 0,0,0,0,0);

  /* And again, since dpkg grows its buffer repeatedly. */
  unsigned long biggest = bigger + 0x400000;
  long r = sys6(SYS_mremap, q, bigger, biggest, MREMAP_MAYMOVE, 0, 0);
  if (r < 0) { put("grow FAIL: mremap 2\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  if (!sweep((unsigned char *) r, biggest, "after second mremap"))
    sys6(SYS_exit, 1, 0,0,0,0,0);

  /*
   * And once more from a child, which is where dpkg actually faulted. On arm64
   * a fork is fork + exec: the child is a fresh nabi that rebuilds every
   * mapping from the checkpoint, so a region that survives in the parent says
   * nothing about whether the child can still reach all of it.
   */
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid == 0) {
    /* Reading what the parent already had is the easy half. The hard half is a
     * mapping the child makes for itself *after* resuming, which is the order
     * dpkg works in: it forks, and the child then grows its own buffer. */
    if (!sweep((unsigned char *) r, biggest, "in child"))
      sys6(SYS_exit, 1, 0,0,0,0,0);

    long c = sys6(SYS_mmap, 0, size, PROT_READ|PROT_WRITE,
                  MAP_ANON|MAP_PRIVATE, -1, 0);
    if (c < 0) { put("grow FAIL: child mmap\n"); sys6(SYS_exit,1,0,0,0,0,0); }
    if (!sweep((unsigned char *) c, size, "child's own mapping"))
      sys6(SYS_exit, 1, 0,0,0,0,0);

    long c2 = sys6(SYS_mremap, c, size, size + 0x200000, MREMAP_MAYMOVE, 0, 0);
    if (c2 < 0) { put("grow FAIL: child mremap\n"); sys6(SYS_exit,1,0,0,0,0,0); }
    sys6(SYS_exit,
         sweep((unsigned char *) c2, size + 0x200000, "child's grown mapping")
           ? 0 : 1, 0,0,0,0,0);
  }
  if (pid < 0) { put("grow FAIL: fork\n"); sys6(SYS_exit,1,0,0,0,0,0); }

  int status = 0;
  sys6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
  if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) {
    put("grow FAIL: unreachable from a child\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  put("grow ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
