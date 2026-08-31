/* freestanding: a directory whose mode denies its own owner, and chown on it.
 *
 * Ownership is recorded in an extended attribute, because the host has one
 * account and no way to give a file to another. Writing an extended attribute
 * needs write permission on the object - and chown on Linux needs no such
 * thing, which is the whole mismatch: a mode-0 directory can be chowned on
 * Linux and could not be here.
 *
 * dpkg unpacks in exactly that order: mkdir with mode 0, chown to the package's
 * user, chmod to the real mode. So `mkdirat("/var/cache/man.dpkg-new", 0)`
 * succeeded and the chown after it came back EACCES, man-db failed to unpack,
 * and everything depending on it - x11-apps, wayland-utils, weston - stopped
 * behind an unmet dependency.
 *
 * mkdir now splits the mode the way chmod already did: the host gets one it can
 * work with, the guest's own mode is recorded beside it. Both have to hold
 * afterwards - the guest still sees mode 0, and the owner took.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_fchownat 54
#define SYS_newfstatat 79
#define SYS_fchmodat 53
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
/* Linux/arm64 struct stat: mode at 16, uid at 24, gid at 28. */
static int statat(const char *p, unsigned *mode, unsigned *uid, unsigned *gid){
  unsigned char st[144];
  for (unsigned i = 0; i < sizeof st; i++) st[i] = 0;
  long r = sys6(SYS_newfstatat, AT_FDCWD, (long) p, (long) st, 0, 0, 0);
  if (r < 0) return (int) r;
  __builtin_memcpy(mode, st + 16, 4);
  __builtin_memcpy(uid,  st + 24, 4);
  __builtin_memcpy(gid,  st + 28, 4);
  return 0;
}

#define DIR "/tmp/nabi-mode0-test"

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  (void) sp;
  sys6(SYS_unlinkat, AT_FDCWD, (long) DIR, AT_REMOVEDIR, 0,0,0);

  want("mkdir with mode 0", sys6(SYS_mkdirat, AT_FDCWD, (long) DIR, 0, 0,0,0), 0);

  unsigned mode = 0, uid = 0, gid = 0;
  want("stat it", statat(DIR, &mode, &uid, &gid), 0);
  want("the guest sees mode 0", mode & 07777, 0);

  /* The call that used to be EACCES. 6/12 is man:man, which is the pair dpkg
   * uses for the directory this was found on. */
  want("chown a directory the owner cannot write",
       sys6(SYS_fchownat, AT_FDCWD, (long) DIR, 6, 12, 0, 0), 0);

  want("re-stat", statat(DIR, &mode, &uid, &gid), 0);
  want("the owner took", uid, 6);
  want("and the group", gid, 12);
  want("and the mode is still 0", mode & 07777, 0);

  /* And it can still be given a real mode afterwards, which is dpkg's next
   * step and needs the host side to remain workable. */
  want("chmod to 0755", sys6(SYS_fchmodat, AT_FDCWD, (long) DIR, 0755, 0,0,0), 0);
  want("re-stat again", statat(DIR, &mode, &uid, &gid), 0);
  want("the new mode holds", mode & 07777, 0755);
  want("and the owner survived it", uid, 6);

  sys6(SYS_unlinkat, AT_FDCWD, (long) DIR, AT_REMOVEDIR, 0,0,0);
  put(fails == 0 ? "mkdirmode ok\n" : "mkdirmode failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
