/* freestanding: a mount table belongs to one image, not to one boot.
 *
 * The table is keyed by the mount namespace it belongs to, which is an inode
 * number - and the *initial* mount namespace has the same inode number in
 * every guest. So two guests of different images, sharing nothing but a boot
 * tag, shared a mount table.
 *
 * That is not a theoretical collision. Mounting a tmpfs on /dev while bringing
 * up an Android image put that tmpfs, and every other mount Android made, into
 * an unrelated Fedora guest: its login shell found /dev/null had become a
 * regular file it had no permission to write, and said so on every redirect.
 *
 * This reports whether /mnt is already a mount and then mounts a tmpfs there,
 * which lets run.sh check both halves of the property with one binary:
 *
 *   - run twice in the same rootfs, the second run must see the first one's
 *     mount. That is what the table is *for* - nabi's processes are separate
 *     host processes, so a mount made in one has to be visible in the next -
 *     and a fix that isolated by accident would break it.
 *   - run in a second rootfs, it must see nothing. Different images share no
 *     mounts, whatever their namespace inodes happen to be.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write      64
#define SYS_read       63
#define SYS_exit       93
#define SYS_close      57
#define SYS_openat     56
#define SYS_mount     40
#define SYS_mkdirat   34
#define AT_FDCWD    (-100)
#define O_RDONLY       0

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}

/* Is there a mount at /mnt? Read from the guest's own view of its mounts. */
static int mnt_is_mounted(void)
{
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/mounts", O_RDONLY, 0, 0, 0);
  if (fd < 0)
    return -1;
  static char buf[65536];
  long total = 0, r;
  while ((r = sys6(SYS_read, fd, (long)(buf + total), sizeof buf - 1 - total, 0,0,0)) > 0) {
    total += r;
    if ((unsigned long) total >= sizeof buf - 1)
      break;
  }
  sys6(SYS_close, fd, 0,0,0,0,0);
  buf[total] = 0;
  /* look for " /mnt " as a mount point field */
  for (long i = 0; i + 6 < total; i++)
    if (buf[i]==' ' && buf[i+1]=='/' && buf[i+2]=='m' && buf[i+3]=='n' &&
        buf[i+4]=='t' && buf[i+5]==' ')
      return 1;
  return 0;
}

void _start(void)
{
  sys6(SYS_mkdirat, AT_FDCWD, (long)"/mnt", 0755, 0, 0, 0);

  int before = mnt_is_mounted();
  if (before < 0) {
    put("mntkey: no /proc/self/mounts, skipped\n");
    put("mntkey ok\n");
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  put(before ? "mntkey: /mnt present\n" : "mntkey: /mnt absent\n");

  if (!before) {
    long r = sys6(SYS_mount, (long)"none", (long)"/mnt", (long)"tmpfs", 0, 0, 0);
    if (r < 0) {
      put("mntkey FAILED: could not mount tmpfs on /mnt\n");
      sys6(SYS_exit, 1, 0,0,0,0,0);
    }
    if (mnt_is_mounted() != 1) {
      put("mntkey FAILED: mounted, but /mnt still reads as absent\n");
      sys6(SYS_exit, 1, 0,0,0,0,0);
    }
  }
  put("mntkey ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
