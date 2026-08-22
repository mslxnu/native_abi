/* freestanding: a read-only descriptor on a writable file still maps shared.
 *
 * A descriptor that cannot write is not the same thing as a file that cannot
 * be written, and mmap's MAP_SHARED is about the file. The ordinary shape of a
 * reader is exactly this: Android's property area is a 0644 file that init
 * writes through its own descriptor while every other process opens it
 * O_RDONLY and maps it MAP_SHARED. nabi gave those readers a private copy, so
 * every property froze at the moment it was mapped - silently, and properties
 * are what sequence the rest of Android's boot.
 *
 * What is checked:
 *
 *   - a write through a separate descriptor is visible through the mapping.
 *     This is the case that was wrong.
 *   - the same across a fork, which is the real shape: one process changes the
 *     file, another is holding the mapping. On arm64 that also means the
 *     mapping has to survive being re-established in a resumed child.
 *   - a file that genuinely cannot be written still maps. A private copy is
 *     the right answer there - nothing can change it - and it must not become
 *     a failure, because ld.so maps every library that way on a read-only
 *     rootfs.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_openat 56
#define SYS_pwrite 68
#define SYS_mmap 222
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_fchmodat 53
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define PROT_READ 1
#define MAP_SHARED 1
#define SIGCHLD 17

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if(got==expect){put("  ok  ");put(what);put("\n");return;}
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}

void _start(void)
{
  /* A writable file, mapped through a read-only descriptor. */
  long w = sys6(SYS_openat,AT_FDCWD,(long)"/prop",O_RDWR|O_CREAT,0644,0,0);
  sys6(SYS_pwrite,w,(long)"AAAA",4,0,0,0);
  long r = sys6(SYS_openat,AT_FDCWD,(long)"/prop",O_RDONLY,0,0,0);
  long m = sys6(SYS_mmap,0,4096,PROT_READ,MAP_SHARED,r,0);
  want("mmap(MAP_SHARED) of a read-only descriptor", m > 0, 1);
  volatile char *p = (volatile char *) m;
  want("it starts with what the file holds", p[0], 'A');

  sys6(SYS_pwrite,w,(long)"BBBB",4,0,0,0);
  want("a write through another descriptor is visible", p[0], 'B');

  /* The real shape: the writer is another process. */
  long kid = sys6(SYS_clone,SIGCHLD,0,0,0,0,0);
  if (kid == 0) {
    long cw = sys6(SYS_openat,AT_FDCWD,(long)"/prop",O_RDWR,0,0,0);
    sys6(SYS_pwrite,cw,(long)"CCCC",4,0,0,0);
    sys6(SYS_exit,0,0,0,0,0,0);
  }
  int st=0; sys6(SYS_wait4,kid,(long)&st,0,0,0,0);
  want("a write by another process is visible too", p[0], 'C');

  /* A file that truly cannot be written still maps, privately. */
  long ro = sys6(SYS_openat,AT_FDCWD,(long)"/ro",O_RDWR|O_CREAT,0644,0,0);
  sys6(SYS_pwrite,ro,(long)"ZZZZ",4,0,0,0);
  sys6(SYS_close,ro,0,0,0,0,0);
  sys6(SYS_fchmodat,AT_FDCWD,(long)"/ro",0444,0,0,0);
  long ror = sys6(SYS_openat,AT_FDCWD,(long)"/ro",O_RDONLY,0,0,0);
  long rom = sys6(SYS_mmap,0,4096,PROT_READ,MAP_SHARED,ror,0);
  want("a read-only file still maps", rom > 0, 1);
  if (rom > 0) want("and reads correctly", *(volatile char *)rom, 'Z');

  put(fails ? "shmapd FAILED\n" : "shmapd ok\n");
  sys6(SYS_exit, fails?1:0, 0,0,0,0,0);
}
