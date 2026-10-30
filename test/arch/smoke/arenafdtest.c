/* freestanding: NABI's own descriptors are not the guest's.
 *
 * The guest memory arena is a file, and the file is reached through a
 * descriptor that has to survive exec - so it is created before the guest's
 * descriptor table is seeded and lands on the lowest free number, 3, every
 * time. The seeding loop adopted every open host descriptor except the rootfs
 * handle, so the arena was adopted too: a guest descriptor no guest ever
 * opened, listed in /proc/self/fd, and readlink-able to the host path of
 * NABI's own memory.
 *
 * Zygote is what makes this fatal rather than untidy. Before forking the
 * system server it audits every open descriptor, because one inherited into
 * an app is a sandbox escape, and anything it cannot account for aborts the
 * fork: "JNI FatalError called: (system_server) Not allowlisted (3):
 * /tmp/nabi-arena-XXXXXX". Android got as far as ZygoteInit.forkSystemServer
 * and died there.
 *
 * WHICH ASSERTION DOES THE WORK: the readlink of a descriptor the guest does
 * not hold, and it is asked before anything is opened on purpose - the first
 * open takes number 3 itself, so after that the question is about the
 * directory. That one assertion fails on either half of the fix reverted: the
 * adoption put the arena in the table, and the range check that used to guard
 * /proc/self/fd/<n> admitted every low host descriptor whether the guest held
 * it or not. Both were checked by reverting each alone.
 *
 * The listing scan is narrower - it fails only on the adoption - but it is
 * what zygote actually does, so it is worth having in the shape zygote has it.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_openat 56
#define SYS_getdents64 61
#define SYS_readlinkat 78
#define AT_FDCWD -100
#define O_DIRECTORY 0x4000

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putn(const char*m,int n){sys6(SYS_write,1,(long)m,n,0,0,0);}

static void fail(const char *what)
{
  put("FAIL "); put(what); put("\n");
  sys6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

/* Whether `hay` contains `needle`. No libc here. */
static int has(const char *hay, int haylen, const char *needle)
{
  int nl = 0; while (needle[nl]) nl++;
  for (int i = 0; i + nl <= haylen; i++) {
    int j = 0;
    while (j < nl && hay[i + j] == needle[j]) j++;
    if (j == nl) return 1;
  }
  return 0;
}

struct d64 { unsigned long ino, off; unsigned short reclen; unsigned char type; char name[]; };

static char buf[8192];
static char link[1024];

int main(void)
{
  /*
   * First, before anything is opened: 0, 1 and 2 are the only descriptors this
   * process holds, so 3 names nothing and Linux answers ENOENT. Asking after
   * the open below would ask about the directory itself, since that open is
   * what takes 3.
   */
  long r = sys6(SYS_readlinkat, AT_FDCWD, (long)"/proc/self/fd/3",
                (long)link, sizeof link - 1, 0, 0);
  if (r >= 0) {
    put("fd 3 reads back as: "); putn(link, (int) r); put("\n");
    fail("readlink of a descriptor the guest does not hold succeeded");
  }

  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long)"/proc/self/fd", O_DIRECTORY, 0, 0, 0);
  if (fd < 0)
    fail("could not open /proc/self/fd");

  int seen = 0;
  for (;;) {
    long n = sys6(SYS_getdents64, fd, (long)buf, sizeof buf, 0, 0, 0);
    if (n <= 0) break;
    for (long off = 0; off < n; ) {
      struct d64 *e = (struct d64 *)(buf + off);
      if (e->reclen == 0) break;
      off += e->reclen;
      if (e->name[0] == '.') continue;
      seen++;
      char path[64]; int i = 0;
      for (const char *p = "/proc/self/fd/"; *p; p++) path[i++] = *p;
      for (int j = 0; e->name[j]; j++) path[i++] = e->name[j];
      path[i] = 0;
      long len = sys6(SYS_readlinkat, AT_FDCWD, (long)path,
                      (long)link, sizeof link - 1, 0, 0);
      if (len <= 0) continue;   /* a pipe or socket has no path; not our worry */
      if (has(link, (int) len, "nabi-arena")) {
        put("fd "); put(e->name); put(" -> "); putn(link, (int) len); put("\n");
        fail("the arena is listed as one of the guest's descriptors");
      }
    }
  }

  /* The scan proves nothing if the listing was empty. */
  if (seen == 0)
    fail("/proc/self/fd listed nothing at all");

  put("arenafdtest ok\n");
  return 0;
}
void _start(void){ sys6(SYS_exit, main(), 0,0,0,0,0); }
