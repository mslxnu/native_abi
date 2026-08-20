/* freestanding: userfaultfd(2) -- on-demand page resolution.
 *
 * Exercises the userfaultfd lifecycle: create, API negotiation,
 * range register/unregister, non-blocking read, and close.
 * No actual page faults are triggered (that needs multi-threading).
 *
 * 15 checks total.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}

#define SYS_write       64
#define SYS_exit        93
#define SYS_ioctl       29
#define SYS_mmap       222
#define SYS_userfaultfd 282
#define SYS_read        63
#define SYS_close       57

#define EBADF      9
#define EINVAL    22
#define EAGAIN    11
#define O_NONBLOCK 0x800
#define O_CLOEXEC  0x80000

/* PROT_NONE / MAP_ANON / MAP_PRIVATE */
#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANON    0x20

/* UFFD API */
#define UFFD_API          0xAAULL

/* ioctl command numbers — same encoding as the kernel */
#define UFFDIO_API        0xC018AA3FULL
#define UFFDIO_REGISTER   0xC018AA00ULL
#define UFFDIO_UNREGISTER 0x8010AA01ULL
#define UFFDIO_WAKE       0x8010AA02ULL
#define UFFDIO_COPY       0xC020AA03ULL
#define UFFDIO_ZEROPAGE   0xC020AA04ULL

#define UFFDIO_REGISTER_MODE_MISSING 1ULL

struct uffdio_api   { unsigned long long api, features, ioctls; };
struct uffdio_range { unsigned long long start, len; };
struct uffdio_register { struct uffdio_range range; unsigned long long mode, ioctls; };
struct uffd_msg {
  unsigned char event, reserved1;
  unsigned short reserved2;
  unsigned int reserved3;
  union { struct { unsigned long long flags, address; } pagefault;
          struct { unsigned long long r1,r2,r3; } reserved; } arg;
} __attribute__((packed));

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void putx(unsigned long v){char b[24];int i=23;b[i--]=0;
  if(v==0)b[i--]='0';while(v>0){int d=v&0xf;b[i--]=d<10?'0'+d:'a'+d-10;v>>=4;}put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("uffdtest FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void failx(const char *w, long got, unsigned long want)
{ put("uffdtest FAIL: "); put(w); put(" -> "); putx(got); put(", wanted 0x"); putx(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }
static void want(const char *w, long got, long expect)
{ if (got != expect) fail(w, got, expect); }

void _start(void)
{
  long r;
  int nchecks = 0;

  /* ================================================================== */
  /* Basic creation                                                      */
  /* ================================================================== */

  /* (1) userfaultfd(0) → valid fd. */
  r = sys6(SYS_userfaultfd, 0, 0, 0, 0, 0, 0);
  if (r < 0) fail("create", r, 0);
  long fd1 = r;
  nchecks++;

  /* (2) userfaultfd(O_NONBLOCK|O_CLOEXEC) → valid fd. */
  r = sys6(SYS_userfaultfd, O_NONBLOCK|O_CLOEXEC, 0, 0, 0, 0, 0);
  if (r < 0) fail("create flags", r, 0);
  long fd2 = r;
  nchecks++;

  /* (3) userfaultfd with unknown bit → EINVAL. */
  r = sys6(SYS_userfaultfd, 0x80000000, 0, 0, 0, 0, 0);
  want("bad flags", r, -EINVAL);
  nchecks++;

  /* ================================================================== */
  /* UFFDIO_API negotiation                                              */
  /* ================================================================== */

  struct uffdio_api api_in;
  api_in.api = UFFD_API;
  api_in.features = 0;
  api_in.ioctls = 0;

  /* (4) UFFDIO_API → 0, api echoed back. */
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_API, (long)&api_in, 0, 0, 0);
  want("api", r, 0);
  nchecks++;

  /* (5) api version echoed back. */
  if ((unsigned long long)api_in.api != UFFD_API)
    failx("api echo", api_in.api, UFFD_API);
  nchecks++;

  /* (6) features = 0 (none supported). */
  if (api_in.features != 0)
    failx("features", api_in.features, 0);
  nchecks++;

  /* (7) ioctls bitmask has REGISTER, UNREGISTER, COPY, ZEROPAGE, WAKE. */
  unsigned long long expected_ioctls =
    (1ULL<<0) | (1ULL<<1) | (1ULL<<2) | (1ULL<<3) | (1ULL<<4);
  if (api_in.ioctls != expected_ioctls)
    failx("ioctls", api_in.ioctls, expected_ioctls);
  nchecks++;

  /* (8) UFFDIO_API with wrong version → EINVAL. */
  struct uffdio_api bad_api;
  bad_api.api = 0x42;
  bad_api.features = 0;
  bad_api.ioctls = 0;
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_API, (long)&bad_api, 0, 0, 0);
  want("bad api ver", r, -EINVAL);
  nchecks++;

  /* ================================================================== */
  /* Range register / unregister                                         */
  /* ================================================================== */

  /* mmap a PROT_NONE region for registration. */
  long pagesize = 4096;
  long mapsz = pagesize * 2;
  long addr = sys6(SYS_mmap, 0, mapsz, PROT_NONE,
                    MAP_PRIVATE|MAP_ANON, -1, 0);
  if (addr < 0) fail("mmap", addr, 0);

  struct uffdio_register reg;
  reg.range.start = (unsigned long long)addr;
  reg.range.len   = (unsigned long long)mapsz;
  reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
  reg.ioctls      = 0;

  /* (9) UFFDIO_REGISTER → 0. */
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_REGISTER, (long)&reg, 0, 0, 0);
  want("register", r, 0);
  nchecks++;

  /* (10) range ioctls filled in (WAKE|COPY|ZEROPAGE = 0xc). */
  unsigned long long expected_range_ioctls = (1ULL<<2)|(1ULL<<3)|(1ULL<<4);
  if (reg.ioctls != expected_range_ioctls)
    failx("register ioctls", reg.ioctls, expected_range_ioctls);
  nchecks++;

  /* (11) duplicate register → EINVAL (overlap). */
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_REGISTER, (long)&reg, 0, 0, 0);
  want("dup register", r, -EINVAL);
  nchecks++;

  /* (12) UFFDIO_UNREGISTER → 0. */
  struct uffdio_range unreg;
  unreg.start = (unsigned long long)addr;
  unreg.len   = (unsigned long long)mapsz;
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_UNREGISTER, (long)&unreg, 0, 0, 0);
  want("unregister", r, 0);
  nchecks++;

  /* (13) unregister again → EINVAL. */
  r = sys6(SYS_ioctl, fd1, (long)UFFDIO_UNREGISTER, (long)&unreg, 0, 0, 0);
  want("unreg again", r, -EINVAL);
  nchecks++;

  /* ================================================================== */
  /* Non-blocking read (no faults pending → EAGAIN).                     */
  /* ================================================================== */

  /* (14) non-blocking read on uffd with no pending events → EAGAIN. */
  r = sys6(SYS_read, fd2, (long)&api_in, sizeof(struct uffd_msg), 0, 0, 0);
  want("read eagain", r, -EAGAIN);
  nchecks++;

  /* ================================================================== */
  /* Cleanup.                                                           */
  /* ================================================================== */

  sys6(SYS_close, fd1, 0, 0, 0, 0, 0);
  sys6(SYS_close, fd2, 0, 0, 0, 0, 0);

  /* (15) read on closed fd → EBADF. */
  r = sys6(SYS_read, fd1, (long)&api_in, sizeof(struct uffd_msg), 0, 0, 0);
  want("closed fd read", r, -EBADF);
  nchecks++;

  put("uffdtest ok (");
  putd(nchecks);
  put(" checks)\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
