/* freestanding: O_NOFOLLOW is about the file, not about the path to it.
 *
 * Linux follows every symlink on the way to a file and refuses only if the
 * *last* component is one. That is what makes the flag mean "give me this
 * file, not whatever it points at" rather than "fail on any symlink anywhere
 * in this name".
 *
 * nabi refused them all, which is a very quiet difference: a path that plainly
 * exists returns ENOENT, and only for callers that pass the flag - so a shell
 * and every test could open it while the one caller that mattered could not.
 * libprocessgroup opens /etc/cgroups.json with O_NOFOLLOW|O_CLOEXEC and
 * Android ships /etc as a symlink to /system/etc, so Android's cgroup setup
 * failed with "Failed to load cgroup description file" and init then repeated
 * "cpuset cgroup controller is not mounted!" for the rest of its life.
 *
 * What is checked, on a tree the runner builds: dir/ holds file, link_to_dir
 * points at dir and link_to_file at dir/file.
 *
 *   - a symlink in the middle of the path is followed even with O_NOFOLLOW,
 *     which is the case that was broken.
 *   - a symlink as the last component is refused with ELOOP, which is what the
 *     flag is for and must keep working.
 *   - without the flag, the same last component opens.
 *   - a path with no symlinks in it is unaffected either way.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_openat 56
#define AT_FDCWD (-100)
#define O_NOFOLLOW 0x8000
#define O_CLOEXEC  0x80000
#define ELOOP 40

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char*what,long got,long expect){
  if (got==expect){put("  ok  ");put(what);put("\n");return;}
  fails++; put("  FAIL ");put(what);put(": got ");putd(got);put(", want ");putd(expect);put("\n");}
static long op(const char*p,int fl){ long fd=sys6(SYS_openat,AT_FDCWD,(long)p,fl,0,0,0);
  if (fd>=0){ sys6(SYS_close,fd,0,0,0,0,0); return 1; } return fd; }

void _start(void)
{
  /* The case Android needed: the symlink is not the thing being opened. */
  want("intermediate symlink is followed with O_NOFOLLOW",
       op("/link_to_dir/file", O_NOFOLLOW), 1);
  want("...and with O_NOFOLLOW|O_CLOEXEC, as libprocessgroup asks",
       op("/link_to_dir/file", O_NOFOLLOW|O_CLOEXEC), 1);
  want("...and without the flag at all",
       op("/link_to_dir/file", 0), 1);

  /* The case the flag exists for, which must not have been broken to fix it. */
  want("a final-component symlink is refused with O_NOFOLLOW",
       op("/link_to_file", O_NOFOLLOW), -ELOOP);
  want("the same symlink opens without the flag",
       op("/link_to_file", 0), 1);
  want("a symlinked directory as the last component is refused too",
       op("/link_to_dir", O_NOFOLLOW), -ELOOP);

  /* And a path with no symlink in it is untouched. */
  want("a plain path with O_NOFOLLOW", op("/dir/file", O_NOFOLLOW), 1);
  want("a plain path without it", op("/dir/file", 0), 1);

  put(fails ? "nofollow FAILED\n" : "nofollow ok\n");
  sys6(SYS_exit, fails?1:0, 0,0,0,0,0);
}
