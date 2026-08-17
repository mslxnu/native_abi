/* freestanding: mounting a filesystem image, which the host is asked to do.
 *
 * nabi has no block layer and no filesystem of its own - every file the guest
 * sees is a host file reached by rewriting a path - so `mount` on a regular
 * file had nothing to do and answered ENODEV. Android ships as ext4 images and
 * `waydroid session start` mounts system.img before anything else.
 *
 * The image beside this file is 1MiB of ext4 holding two known files. It is
 * built without the 64bit feature on purpose: the host driver refuses one that
 * has it, with an error about devices that says nothing about why.
 *
 * What is checked:
 *
 *   - the mount succeeds and the files inside it are readable *through the
 *     guest's mountpoint*. A mount that returned 0 and left the mountpoint
 *     empty would pass any check that only looked at the return value, and
 *     that is the failure this is most likely to have.
 *   - a nested path resolves too, so what is mounted is a tree and not one
 *     directory.
 *   - a writable mount is refused. Read-only is all this can do, and a guest
 *     told otherwise would find out at its first write, somewhere else.
 *   - a file that is not an image is refused, rather than attached and left to
 *     fail as something else.
 *   - unmounting works, and the mountpoint is empty afterwards - an unmount
 *     that detached nothing would leave the files readable.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write    64
#define SYS_exit     93
#define SYS_mount    40
#define SYS_umount2  39
#define SYS_openat   56
#define SYS_read     63
#define SYS_close    57
#define SYS_mkdirat  34

#define MS_RDONLY  1
#define EROFS     30
#define EINVAL    22
#define ENOENT     2

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("imagemount FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static char buf[128];

/* Read a file whole; -errno, or the length. */
static long slurp(const char *path)
{
  long fd = sys6(SYS_openat, -100, (long) path, 0, 0, 0, 0);
  if (fd < 0) return fd;
  long n = sys6(SYS_read, fd, (long) buf, sizeof buf - 1, 0, 0, 0);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  if (n >= 0) buf[n] = '\0';
  return n;
}

static int streq(const char *a, const char *b)
{ int i = 0; while (a[i] && a[i] == b[i]) i++; return a[i] == b[i]; }

void _start(void)
{
  long r;
  sys6(SYS_mkdirat, -100, (long) "/mnt", 0755, 0, 0, 0);

  /* Writable is refused, and refused *before* anything is attached. */
  r = sys6(SYS_mount, (long) "/tiny.ext4", (long) "/mnt", (long) "ext4", 0, 0, 0);
  if (r != -EROFS)
    fail("a writable mount of an image", r, -EROFS);

  /* So is a file that is not one. */
  r = sys6(SYS_mount, (long) "/imagemounttest", (long) "/mnt", (long) "ext4",
           MS_RDONLY, 0, 0);
  if (r != -EINVAL)
    fail("mounting a file that is not an image", r, -EINVAL);

  /* And one that is not there at all. */
  r = sys6(SYS_mount, (long) "/nosuch.ext4", (long) "/mnt", (long) "ext4",
           MS_RDONLY, 0, 0);
  if (r != -ENOENT)
    fail("mounting an image that does not exist", r, -ENOENT);

  /* The real thing. */
  r = sys6(SYS_mount, (long) "/tiny.ext4", (long) "/mnt", (long) "ext4",
           MS_RDONLY, 0, 0);
  if (r != 0)
    fail("mounting the image", r, 0);

  long n = slurp("/mnt/marker.txt");
  if (n < 0) fail("opening a file inside the image", n, 1);
  if (!streq(buf, "nabi image mount works\n"))
    fail("the contents of that file", n, 23);

  n = slurp("/mnt/sub/deep.txt");
  if (n < 0) fail("opening a nested file inside the image", n, 1);
  if (!streq(buf, "nested\n"))
    fail("the contents of the nested file", n, 7);

  if ((r = sys6(SYS_umount2, (long) "/mnt", 0, 0, 0, 0, 0)) != 0)
    fail("unmounting", r, 0);

  /* Gone afterwards, or the unmount detached nothing. */
  n = slurp("/mnt/marker.txt");
  if (n >= 0)
    fail("a file still readable after unmounting", n, -ENOENT);

  put("imagemount ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
