/* freestanding: the dynamic linker's over-align-then-trim sequence, at size.
 *
 * When a shared object's p_align exceeds the page size - and every Debian
 * aarch64 library is built with p_align 64K while NABI reports 16K pages -
 * glibc cannot just mmap the file where it likes. It reserves maplength+align
 * anonymously, maps the file at the aligned address inside that reservation,
 * then munmaps the slack at each end, and finally mprotects the inter-segment
 * hole to PROT_NONE. So a library load is not one mapping but a reservation
 * carved into three, and the two carve-outs are partial munmaps of a live
 * file-backed region.
 *
 * The sizes here are libcrypto.so.3's, because that is where it first broke:
 * smaller libraries in the same chain loaded fine, so the reproducer has to be
 * large enough to span more than one of whatever internal unit is running out.
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
#define SYS_openat 56
#define SYS_close 57
#define AT_FDCWD -100
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANON 0x20
#define PAGE (16*1024)

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

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((unsigned long)(a) - 1))

void _start(void)
{
  const unsigned long maplength = 0x6055a8;   /* libcrypto's total span */
  const unsigned long mapalign  = 0x10000;    /* its p_align */
  const unsigned long maplen    = maplength + mapalign;

  /* 1. the anonymous reservation */
  long r = sys6(SYS_mmap, 0, maplen, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
  if (r < 0)
    fail("reserve", (unsigned long) r);
  unsigned long start = (unsigned long) r;

  /* 2. the real mapping, at the aligned address inside it - from a file, and a
   *    file shorter than the mapping, which is the normal case for a library:
   *    the last segment's memsz exceeds its filesz, so the mapping runs past
   *    end-of-file and those bytes must read as zero.
   *
   *    The +0x8000 is not decoration. Where the reservation lands is the
   *    allocator's business, and if it happens to be aligned already there is
   *    no head to trim and the interesting case never runs - which is exactly
   *    how this went unnoticed. Offsetting by hand makes the head trim
   *    unconditional; 0x8000 is what libcrypto's own load came out to. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long) "/bigmapfile", 0, 0, 0, 0);
  if (fd < 0)
    fail("open", (unsigned long) fd);

  unsigned long aligned = ALIGN_UP(start, mapalign) + 0x8000;
  r = sys6(SYS_mmap, aligned, maplength, PROT_READ|PROT_EXEC,
           MAP_PRIVATE|MAP_FIXED, fd, 0);
  if (r < 0 || (unsigned long) r != aligned)
    fail("fixed", (unsigned long) r);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);

  /* 3. trim the head */
  unsigned long delta = aligned - start;
  if (delta) {
    r = sys6(SYS_munmap, start, delta, 0, 0, 0, 0);
    if (r < 0)
      fail("trim-head", (unsigned long) r);
  }

  /* 4. trim the tail */
  unsigned long end = ALIGN_UP(aligned + maplength, PAGE);
  delta = start + maplen - end;
  if (delta) {
    r = sys6(SYS_munmap, end, delta, 0, 0, 0, 0);
    if (r < 0)
      fail("trim-tail", (unsigned long) r);
  }

  /* 5. the hole between the two LOAD segments goes to PROT_NONE */
  r = sys6(SYS_mprotect, aligned + 0x580000, 0x4000, PROT_NONE, 0, 0, 0);
  if (r < 0)
    fail("hole", (unsigned long) r);

  /* 6. what survives must still be readable, at both ends and in the middle -
   *    in particular at 0x584000, the byte immediately after the PROT_NONE
   *    hole, which is where an mprotect that over-reaches shows up. A fault
   *    here kills the guest, so reaching the end is the assertion. */
  volatile const unsigned char *p = (const unsigned char *) aligned;
  static const unsigned long probe[] = {
    0, 0x4000, 0x100000, 0x300000, 0x57f000,
    0x584000,                         /* first byte past the hole */
    0x600000, maplength - 1
  };
  unsigned long sum = 0;
  for (unsigned i = 0; i < sizeof probe / sizeof *probe; i++)
    sum += p[probe[i]];
  (void) sum;

  /* The file is shorter than the mapping, so its last byte must read as zero
   * rather than fault or return whatever was in the page. */
  if (p[maplength - 1] != 0)
    fail("past-eof", p[maplength - 1]);

  put("OK\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
