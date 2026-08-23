/* freestanding: the devices nabi answers for, once the guest owns /dev.
 *
 * A node the guest makes with mknod is a placeholder - there is no driver
 * behind it - so opening it has to be turned into something real or refused.
 * Linux names devices two ways and both have to work.
 *
 * By number, for the ones whose major and minor Linux fixes. That is exact
 * where it applies, and it is why /dev/null kept working after a guest mounted
 * its own /dev over the passthrough.
 *
 * By name, for the ones whose numbers Linux assigns dynamically. Binder is the
 * reason: its numbers are whatever was free when the device was made, so they
 * identify nothing, while the name is fixed by every client that opens it.
 * Without this, /dev/binder answered ENXIO the moment Android's init mounted a
 * tmpfs on /dev - which it always does - while /dev/null carried on working,
 * purely because one is found by number and the other is not.
 *
 * What is checked:
 *
 *   - a numbered device still resolves inside a guest-owned /dev.
 *   - a device with no driver anywhere is ENXIO, which is what Linux answers
 *     for a node whose driver is not loaded. Not ENOENT: the guest just made
 *     the node and it is plainly there.
 *   - a name is only a device *in /dev*. A character node called "binder"
 *     somewhere else is a node with no driver, and must not be quietly wired
 *     to the binder device.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_openat 56
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_mount 40
#define AT_FDCWD (-100)
#define S_IFCHR 0020000
#define O_RDWR 2
#define ENXIO 6
#define mkdev(ma,mi) (((ma)<<8)|(mi))

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if(got==expect){put("  ok  ");put(what);put("\n");return;}
  fails++;put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}

/* mknod then open; 1 if it opened, else the negative errno. */
static long mk_open(const char*p,int maj,int min){
  sys6(SYS_mknodat,AT_FDCWD,(long)p,S_IFCHR|0666,mkdev(maj,min),0,0);
  long fd=sys6(SYS_openat,AT_FDCWD,(long)p,O_RDWR,0,0,0);
  if (fd>=0){ sys6(SYS_close,fd,0,0,0,0,0); return 1; }
  return fd;
}

void _start(void)
{
  sys6(SYS_mkdirat,AT_FDCWD,(long)"/dev",0755,0,0,0);
  want("mount a tmpfs over /dev",
       sys6(SYS_mount,(long)"none",(long)"/dev",(long)"tmpfs",0,0,0), 0);

  want("a numbered device still resolves", mk_open("/dev/null",1,3), 1);
  want("and another one", mk_open("/dev/zero",1,5), 1);
  /* The pty multiplexer, which is a device like any other once the guest owns
   * /dev - and is how init gives a command it runs somewhere to write to. */
  want("the pty multiplexer resolves", mk_open("/dev/ptmx",5,2), 1);
  want("a device nothing provides is ENXIO", mk_open("/dev/nosuchthing",99,99), -ENXIO);

  /* A name is a device only in /dev. */
  sys6(SYS_mkdirat,AT_FDCWD,(long)"/elsewhere",0755,0,0,0);
  want("a node named binder outside /dev is not the binder device",
       mk_open("/elsewhere/binder",99,98), -ENXIO);

  /* Informational: whether this host provides binder at all depends on the
   * kext being loaded, so it is reported rather than asserted. */
  long b = mk_open("/dev/binder",10,50);
  put("binder-open="); putd(b); put("\n");

  put(fails ? "devnode FAILED\n" : "devnode ok\n");
  sys6(SYS_exit, fails?1:0, 0,0,0,0,0);
}
