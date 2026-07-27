/* freestanding: no value in x0 may stop a syscall from reaching the host.
 *
 * The EL1 trampoline reaches the host with `hvc`, and it deliberately clobbers
 * no register - a real `svc` must preserve x0-x30 - so the guest's x0 is still
 * live when the `hvc` executes. x0 is also where SMCCC puts a function ID, and
 * Apple's hypervisor answers some of that space itself: an `hvc #0` whose x0
 * looks like a call it owns is completed in firmware, returning
 * SMCCC_RET_NOT_SUPPORTED (-1) in x0, and never becomes a VM exit at all. The
 * guest's syscall then quietly does not happen and comes back as 0xffffffff.
 *
 * Measured, that was every x0 in [0xc1000000, 0xc2000000) - fast call, SMC64,
 * owning entity 1 ("CPU service calls"). Which x0 values reach it is not ours
 * to choose: the first argument of any syscall is a guest address, and a guest
 * whose mappings land in that band loses mmap and mprotect. Using a non-zero
 * `hvc` immediate is what keeps the call ours.
 *
 * The sweep is over the whole top byte rather than the one band that was seen
 * to break, because the point is that no function-ID-shaped value is special.
 * munmap of an address that was never mapped is the probe: the kernel owes
 * -ENOMEM, while an untouched x0 comes back as the address itself.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define ENOMEM 12

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

void _start(void)
{
  int bad = 0;
  for (unsigned b = 0; b < 256; b++) {
    unsigned long addr = ((unsigned long) b << 24) | 0x008000UL;
    if (addr == 0x8000UL)
      continue;                       /* b == 0 is the guest's own low memory */
    long r = sys6(SYS_munmap, (long) addr, 0x4000, 0, 0, 0, 0);
    if (r != -ENOMEM) {
      bad = 1;
      put("BAD x0="); puthex(addr); put(" -> "); puthex((unsigned long) r);
      put("\n");
    }
  }
  put(bad ? "FAIL\n" : "hvc ok\n");
  sys6(SYS_exit, bad, 0, 0, 0, 0, 0);
}
