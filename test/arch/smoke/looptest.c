/* freestanding: loop devices, which is how anything actually mounts an image.
 *
 * nabi can mount an image - the host is asked to do it - but nothing reached
 * that, because util-linux's `mount` never calls mount(2) on a regular file.
 * It sets up a loop device first, in userspace, and gives up when it cannot:
 * "failed to setup loop device". waydroid mounts its images with that mount.
 *
 * There is no block layer under these. A loop device here is a name for a
 * backing file, and the descriptor reads as that file - which is not a
 * decoration: util-linux probes the device the moment it is bound, to identify
 * the filesystem before it will mount it. Backed by nothing, that probe read
 * zero bytes and asked again, for ever.
 *
 * What is checked:
 *
 *   - /dev/loop-control exists and hands out a number. /dev is a host
 *     passthrough with no such node in it, so both the stat and the open are
 *     answered by nabi; util-linux stats before it opens and calls a missing
 *     one a setup failure.
 *   - /dev/loopN stats as a block device with Linux's major, which is what
 *     anything asking "is this a loop device" compares against.
 *   - once bound, the descriptor reads the *backing file* - checked on the ext4
 *     superblock magic at offset 0x438, which is the same check blkid makes and
 *     the one that was failing.
 *   - mounting the device mounts the file behind it.
 *   - unbinding frees the number again, so the devices are not one-shot.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write      64
#define SYS_exit       93
#define SYS_openat     56
#define SYS_close      57
#define SYS_read       63
#define SYS_lseek      62
#define SYS_ioctl      29
#define SYS_mount      40
#define SYS_umount2    39
#define SYS_mkdirat    34
#define SYS_newfstatat 79

#define AT_FDCWD    (-100)
#define O_RDONLY      0
#define O_RDWR        2
#define MS_RDONLY     1

#define LOOP_SET_FD       0x4C00
#define LOOP_CLR_FD       0x4C01
#define LOOP_GET_STATUS64 0x4C05
#define LOOP_CTL_GET_FREE 0x4C82

#define LOOP_MAJOR 7

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *w, long got, long want)
{ put("loop FAIL: "); put(w); put(" -> "); putd(got); put(", wanted "); putd(want);
  put("\n"); sys6(SYS_exit,1,0,0,0,0,0); }

static unsigned char stbuf[128];
static unsigned char buf[2048];
static char devname[24];

/* "/dev/loopN" for a single-digit N, which is all LOOP_MAX allows. */
static void
make_name(int n)
{
  const char *p = "/dev/loop";
  int i = 0;
  while (p[i]) { devname[i] = p[i]; i++; }
  devname[i++] = (char) ('0' + n);
  devname[i] = '\0';
}

void _start(void)
{
  long r;

  /* The control device, which has to be there before anything else. */
  long ctl = sys6(SYS_openat, AT_FDCWD, (long) "/dev/loop-control", O_RDWR, 0, 0, 0);
  if (ctl < 0) fail("opening /dev/loop-control", ctl, 0);

  long n = sys6(SYS_ioctl, ctl, LOOP_CTL_GET_FREE, 0, 0, 0, 0);
  if (n < 0) fail("LOOP_CTL_GET_FREE", n, 0);
  make_name((int) n);

  /* It stats as a block device, with the major that says what it is. */
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) devname, (long) stbuf, 0, 0, 0)) != 0)
    fail("stat of the loop device", r, 0);
  {
    unsigned mode = *(unsigned *)(stbuf + 16);
    unsigned long long rdev = *(unsigned long long *)(stbuf + 32);
    if ((mode & 0170000) != 0060000)
      fail("the loop device is not a block device", mode & 0170000, 0060000);
    if ((rdev >> 8) != LOOP_MAJOR)
      fail("the loop device's major", (long) (rdev >> 8), LOOP_MAJOR);
  }

  long dev = sys6(SYS_openat, AT_FDCWD, (long) devname, O_RDWR, 0, 0, 0);
  if (dev < 0) fail("opening the loop device", dev, 0);

  long img = sys6(SYS_openat, AT_FDCWD, (long) "/tiny.ext4", O_RDONLY, 0, 0, 0);
  if (img < 0) fail("opening the image", img, 0);

  if ((r = sys6(SYS_ioctl, dev, LOOP_SET_FD, img, 0, 0, 0)) != 0)
    fail("LOOP_SET_FD", r, 0);

  /*
   * Now it reads as the file. The ext4 superblock magic is 0xef53 at 0x438,
   * and finding it is exactly what a filesystem probe does before mounting -
   * a device backed by nothing read zero bytes here without ever stopping.
   */
  if ((r = sys6(SYS_lseek, dev, 0x400, 0 /* SEEK_SET */, 0, 0, 0)) != 0x400)
    fail("seeking to the superblock", r, 0x400);
  r = sys6(SYS_read, dev, (long) buf, 128, 0, 0, 0);
  if (r < 0x40) fail("reading the superblock through the device", r, 0x40);
  if (buf[0x38] != 0x53 || buf[0x39] != 0xef)
    fail("the ext4 magic read through the device", buf[0x38], 0x53);

  /* It knows its own number. */
  { unsigned char info[232];
    for (unsigned i = 0; i < sizeof info; i++) info[i] = 0;
    if ((r = sys6(SYS_ioctl, dev, LOOP_GET_STATUS64, (long) info, 0, 0, 0)) != 0)
      fail("LOOP_GET_STATUS64", r, 0);
    unsigned num = *(unsigned *)(info + 40);
    if (num != (unsigned) n) fail("the number it reports", num, n); }

  /* And mounting the device mounts the file behind it. */
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/lmnt", 0755, 0, 0, 0);
  if ((r = sys6(SYS_mount, (long) devname, (long) "/lmnt", (long) "ext4",
                MS_RDONLY, 0, 0)) != 0)
    fail("mounting the loop device", r, 0);
  { long f = sys6(SYS_openat, AT_FDCWD, (long) "/lmnt/marker.txt", O_RDONLY, 0, 0, 0);
    if (f < 0) fail("a file inside the mounted device", f, 0);
    long got = sys6(SYS_read, f, (long) buf, 32, 0, 0, 0);
    if (got <= 0) fail("reading it", got, 1);
    sys6(SYS_close, f, 0, 0, 0, 0, 0); }
  if ((r = sys6(SYS_umount2, (long) "/lmnt", 0, 0, 0, 0, 0)) != 0)
    fail("unmounting it", r, 0);

  /* Unbinding gives the number back, or the devices run out. */
  if ((r = sys6(SYS_ioctl, dev, LOOP_CLR_FD, 0, 0, 0, 0)) != 0)
    fail("LOOP_CLR_FD", r, 0);
  { long again = sys6(SYS_ioctl, ctl, LOOP_CTL_GET_FREE, 0, 0, 0, 0);
    if (again != n) fail("the number after unbinding", again, n); }

  sys6(SYS_close, dev, 0, 0, 0, 0, 0);
  sys6(SYS_close, img, 0, 0, 0, 0, 0);
  sys6(SYS_close, ctl, 0, 0, 0, 0, 0);
  put("loop ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
