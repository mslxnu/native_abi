/* freestanding: a guest path that merely starts with a host-passthrough name.
 *
 * NABI deliberately lets a few absolute paths - /Users, /Volumes, /dev, /tmp,
 * /private - resolve on the host rather than in the rootfs, which is how a guest
 * sees the Mac's files. Those names have to be matched a whole component at a
 * time: a plain prefix test also catches /tmpmark, /devices or /private-key,
 * which are ordinary guest paths. The guest's own file then becomes invisible
 * and a host file of that name is exposed in its place.
 *
 * /tmpmark exists in the rootfs and not on the host, so opening it succeeds only
 * if the guest path was resolved where it belongs. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_openat 56
#define AT_FDCWD -100
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
void _start(void){
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/tmpmark", 0, 0,0,0);
  if (fd >= 0) put("path ok\n"); else put("path MISROUTED\n");
  sys6(SYS_exit, fd >= 0 ? 0 : 1, 0,0,0,0,0);
}
