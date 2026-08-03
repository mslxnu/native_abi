/* freestanding: brk(0) must answer with the break as it stands.
 *
 * brk(0) is how every libc asks where the break *is* - the value is below any
 * floor, so it cannot be a request to move it. NABI answered with start_brk,
 * the address the heap began at, which is only the same thing until something
 * has already grown it.
 *
 * Static glibc grows it before anything else: __libc_setup_tls takes the thread
 * block with sbrk during startup. So by the time the program asks, the answer
 * was already a lie, and glibc recorded a break below memory it had been given.
 * The next allocation was handed the same bytes a second time, on top of the
 * thread pointer.
 *
 * ldconfig died on it, and only when LANG was set: a C-locale process does not
 * allocate again after TLS, so it never finds out. The fault address was
 * 0x6e756f46206572a7 - ASCII text, a pointer with a string written through it -
 * which says corruption rather than a missing mapping, and says nothing at all
 * about brk.
 *
 * Checked here directly, because the distance between this call and that
 * symptom is the whole reason it survived so long.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_brk 214

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void puth(unsigned long v){char b[19];int i=18;b[i--]=0;
  if(v==0)b[i--]='0';while(v){int d=v&15;b[i--]="0123456789abcdef"[d];v>>=4;}
  put("0x");put(b+i+1);}
static void fail(const char *what, unsigned long a, unsigned long b)
{
  put("brk FAIL: "); put(what); put(" "); puth(a); put(" vs "); puth(b); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

static unsigned long brk_call(unsigned long addr)
{ return (unsigned long) sys6(SYS_brk, (long) addr, 0,0,0,0,0); }

void _start(void)
{
  unsigned long start = brk_call(0);
  if (start == 0)
    fail("brk(0) at startup returned nothing", start, 0);

  /* Ask for a break well above the current one. What comes back may be rounded
   * up - the mapping behind it has a granule - but it must not be below what
   * was asked for. */
  unsigned long want = start + 0x10000;
  unsigned long got = brk_call(want);
  if (got < want)
    fail("raising the break returned less than requested", got, want);

  /* The query has to agree with what the move just reported. This is the whole
   * bug: it answered `start` here, so a libc that had already taken memory
   * between start and got would hand that same memory out again. */
  unsigned long now = brk_call(0);
  if (now != got)
    fail("brk(0) disagrees with the break just set; query said", now, got);
  if (now == start)
    fail("brk(0) answered the original break after it had moved", now, start);

  /* The memory between the two is writable, which is what having moved the
   * break is supposed to mean. */
  for (unsigned long p = start; p < want; p += 0x1000)
    *(volatile unsigned char *) p = 0xa5;
  for (unsigned long p = start; p < want; p += 0x1000)
    if (*(volatile unsigned char *) p != 0xa5)
      fail("memory below the break did not hold what was written at", p, 0);

  /* Lowering it again is reflected too, so the query is not merely a
   * high-water mark. */
  unsigned long lowered = brk_call(start);
  if (brk_call(0) != lowered)
    fail("brk(0) disagrees after lowering; query said", brk_call(0), lowered);

  put("brk ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
