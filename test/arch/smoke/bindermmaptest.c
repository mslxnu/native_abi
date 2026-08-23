/* freestanding: mmap of the binder device, which is how a real client asks for
 * its arena.
 *
 * binderprobe registers memory the caller already has, through mSL's own
 * BINDER_MSL_SET_ARENA. Nothing in Android does that. libbinder's ProcessState
 * maps just under a megabyte of /dev/binder and lets the driver say where the
 * buffer went, and a driver that cannot answer mmap is one it refuses to use:
 * "Binder driver could not be opened. Terminating." - which is fatal to vold,
 * and vold has reboot_on_failure.
 *
 * Its own test rather than a stage of binderprobe, because the probe is the
 * oracle for the kext's driver as well and that one answers mmap with ENODEV.
 * This is about what nabi's emulation does, so it is run only against that.
 *
 * What is checked:
 *
 *   - the mapping succeeds, with the protection and flags ProcessState uses.
 *   - it *is* the arena: registering another one is refused, which is the only
 *     way from out here to tell the mapping was recorded rather than merely
 *     handed back.
 *   - the memory is real - it can be read - since a driver that returned an
 *     address to nothing would satisfy the two checks above and fail the first
 *     time anything was delivered into it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_mmap 222
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define PROT_READ 1
#define MAP_PRIVATE 0x02
#define MAP_NORESERVE 0x4000
#define EBUSY 16
#define ARENA_SIZE 0xfe000            /* what ProcessState asks for */

#define BINDER_MSL_SET_ARENA 0xC01062E0u
#define BINDER_VERSION       0xC0046209
struct binder_msl_arena { unsigned long addr, size; };

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
  struct binder_msl_arena a;
  unsigned int ver = 0;

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long) "/dev/binder",
                      O_RDWR | O_CLOEXEC, 0, 0, 0);
  want("open /dev/binder", fd >= 0, 1);
  if (fd < 0) { put("bindermmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  want("BINDER_VERSION", sys6(SYS_ioctl, fd, BINDER_VERSION, (long)&ver, 0,0,0), 0);

  /* Exactly what ProcessState asks for. */
  unsigned long p = (unsigned long) sys6(SYS_mmap, 0, ARENA_SIZE, PROT_READ,
                                         MAP_PRIVATE | MAP_NORESERVE, fd, 0);
  want("mmap the device", (long) p >= -4096 && (long) p < 0 ? 0 : 1, 1);
  if ((long) p >= -4096 && (long) p < 0) {
    put("  (mmap said "); putd((long) p); put(")\n");
    put("bindermmap failed\n");
    sys6(SYS_exit_group, 1, 0,0,0,0,0);
  }
  want("which is an address", p != 0, 1);

  /* Real memory: readable through its whole length, and zeroed the way fresh
   * memory is. Reaching the check at all is half the point - a fault on the
   * way would take the process with it. */
  {
    volatile unsigned char *m = (volatile unsigned char *) p;
    unsigned long nonzero = 0;
    for (unsigned long i = 0; i < ARENA_SIZE; i += 4096)
      if (m[i] != 0)
        nonzero++;
    want("and readable end to end, and zeroed", (long) nonzero, 0);
  }

  /* It is the arena, so another one is refused. */
  a.addr = p;
  a.size = ARENA_SIZE;
  want("a second arena is refused",
       sys6(SYS_ioctl, fd, BINDER_MSL_SET_ARENA, (long)&a, 0,0,0), -EBUSY);

  sys6(SYS_close, fd, 0,0,0,0,0);
  put(fails == 0 ? "bindermmap ok\n" : "bindermmap failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
