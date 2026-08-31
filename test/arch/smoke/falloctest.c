/* freestanding: how a Wayland client gets a buffer, and the two ways it failed.
 *
 * wl_shm is the shape: make a memfd, size it with posix_fallocate, map it
 * MAP_SHARED, draw into it, and pass the descriptor to the compositor. Two
 * things on that path were wrong, and neither announced itself as an error.
 *
 * fallocate reported success and did not change the file's size. macOS's
 * F_PREALLOCATE reserves blocks and leaves st_size alone, which is not what
 * Linux's fallocate does. mmap does not check a file's size, so the mapping
 * succeeded too - and the first store past the end of a zero-length file is
 * SIGBUS, in the *host* process. weston-simple-shm ended as "Bus error: 10"
 * with nothing in any log, because a host memory fault is not a guest one.
 *
 * And mmap of zero bytes panicked. Linux answers EINVAL; this reached the arena
 * allocator, which asked the host to map nothing, got EINVAL and brought the
 * guest down. A compositor with no keymap to publish sends a size of zero and
 * xkbcommon maps what it is told, so `wayland-info` hit it on connect.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_fstat 80
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_fallocate 47
#define SYS_memfd_create 279
#define SYS_exit_group 94
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
/* Linux/arm64 struct stat: st_size is at 48. */
static long fsize(int fd){
  unsigned char st[144];
  for (unsigned i = 0; i < sizeof st; i++) st[i] = 0;
  if (sys6(SYS_fstat, fd, (long) st, 0,0,0,0) < 0) return -1;
  long sz; __builtin_memcpy(&sz, st + 48, 8); return sz;
}

#define BUFSZ 0x3d090          /* what weston-simple-shm asks for */

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  (void) sp;

  /*
   * First, because the check below it can end the process rather than fail it:
   * a wrong size turns into SIGBUS on the store, and a test that dies takes its
   * remaining checks with it.
   */
  long z = sys6(SYS_mmap, 0, 0, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  want("mmap of zero bytes is EINVAL", z, -22);

  int fd = (int) sys6(SYS_memfd_create, (long) "shmtest", 0, 0,0,0,0);
  want("memfd_create", fd >= 0, 1);
  if (fd < 0) { put("falloc failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  want("a fresh memfd is empty", fsize(fd), 0);

  want("fallocate succeeds", sys6(SYS_fallocate, fd, 0, 0, BUFSZ, 0, 0), 0);
  /*
   * The whole point. Reserving blocks without setting the size is a success
   * the caller cannot see and cannot act on.
   */
  want("and the file is now that size", fsize(fd), BUFSZ);

  /* Mapped shared and written through, which is where the wrong size turns
   * into a fault rather than an error - first page, last page, and the byte
   * before the end. */
  long a = sys6(SYS_mmap, 0, BUFSZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  want("mmap the buffer", a >= -4096 && a < 0 ? 0 : 1, 1);
  if (!(a >= -4096 && a < 0)) {
    volatile unsigned char *p = (volatile unsigned char *) a;
    p[0] = 0xa5;
    p[BUFSZ / 2] = 0x5a;
    p[BUFSZ - 1] = 0x3c;
    want("the first byte reads back", p[0], 0xa5);
    want("the middle byte reads back", p[BUFSZ / 2], 0x5a);
    want("the last byte reads back", p[BUFSZ - 1], 0x3c);
    sys6(SYS_munmap, a, BUFSZ, 0,0,0,0);
  }

  /* Never shrinks: Linux's fallocate only ever extends. */
  want("a smaller fallocate is not a truncate",
       sys6(SYS_fallocate, fd, 0, 0, BUFSZ / 2, 0, 0), 0);
  want("so the size is unchanged", fsize(fd), BUFSZ);

  /* And extending from an offset rather than from zero. */
  want("fallocate past the end", sys6(SYS_fallocate, fd, 0, BUFSZ, 0x1000, 0, 0), 0);
  want("extends to offset plus length", fsize(fd), BUFSZ + 0x1000);

  sys6(SYS_close, fd, 0,0,0,0,0);

  put(fails == 0 ? "falloc ok\n" : "falloc failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
