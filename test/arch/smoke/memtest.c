/* freestanding: memfd_create, the mlock family, migrate_pages, membarrier,
 * and the six that answer ENOSYS.
 *
 * What is worth checking:
 *
 *   - a memfd is a *file*: it can be written, read back, grown with ftruncate
 *     and mapped, and it has no name anywhere. Anything less than a round trip
 *     through the contents would pass against a descriptor that is merely open.
 *   - MFD_CLOEXEC has to reach the descriptor flag, not only nabi's bitmap -
 *     the same trap close_range fell into.
 *   - mlock was a stub returning 0. The check is that it *fails* where a real
 *     lock must fail: a range that is not mapped is ENOMEM, and a stub returns
 *     0 for it. There is no way for a guest to observe a successful lock, so
 *     the failure is the whole discriminator.
 *   - mlock2's MLOCK_ONFAULT and mlockall's MCL_FUTURE are refused rather than
 *     quietly treated as the other thing.
 *   - migrate_pages accepts the only node there is and refuses one that does
 *     not exist. An implementation returning 0 for everything passes the first
 *     half and fails the second.
 *   - membarrier's query reports no commands, and every command then says so.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_fcntl                 25
#define SYS_ftruncate             46
#define SYS_close                 57
#define SYS_lseek                 62
#define SYS_read                  63
#define SYS_write                 64
#define SYS_fstat                 80
#define SYS_exit                  93
#define SYS_munmap               215
#define SYS_mmap                 222
#define SYS_mlock                228
#define SYS_munlock              229
#define SYS_mlockall             230
#define SYS_munlockall           231
#define SYS_mlock2               284
#define SYS_migrate_pages        238
#define SYS_membarrier           283
#define SYS_memfd_create         279
#define SYS_memfd_secret         447
#define SYS_map_shadow_stack     453
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule       445
#define SYS_landlock_restrict_self  446

#define ENOENT        2
#define EBADF         9
#define ENOMEM       12
#define EINVAL       22
#define ENOSYS       38

#define F_GETFD        1
#define FD_CLOEXEC     1
#define MFD_CLOEXEC        1
#define MFD_ALLOW_SEALING  2
#define MFD_HUGETLB        4

#define MLOCK_ONFAULT  1
#define MCL_CURRENT    1
#define MCL_FUTURE     2

#define PROT_READ    1
#define PROT_WRITE   2
#define MAP_SHARED   1
#define MAP_PRIVATE  2
#define MAP_ANON  0x20

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("mem FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static char scratch[8192];

void _start(void)
{
  long r;

  /* ================= memfd_create ================= */
  {
    if ((r = sys6(SYS_memfd_create, (long) "probe", 0x1000, 0, 0, 0, 0)) != -EINVAL)
      fail("memfd_create with a flag that does not exist", r, -EINVAL);
    /* Huge pages are a backing guarantee, not a hint, so they are refused. */
    if ((r = sys6(SYS_memfd_create, (long) "probe", MFD_HUGETLB, 0, 0, 0, 0)) != -EINVAL)
      fail("memfd_create with MFD_HUGETLB", r, -EINVAL);

    long fd = sys6(SYS_memfd_create, (long) "buffer", MFD_CLOEXEC | MFD_ALLOW_SEALING, 0, 0, 0, 0);
    if (fd < 0)
      fail("memfd_create", fd, 0);

    /* The flag has to reach the descriptor, not only nabi's own bitmap. */
    if ((r = sys6(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0)) < 0 || !(r & FD_CLOEXEC))
      fail("memfd_create did not set close-on-exec", r, FD_CLOEXEC);

    /* It is a file: it grows, it holds what is written, and it reads back. */
    for (int i = 0; i < 4096; i++)
      scratch[i] = (char) (i * 7 + 3);
    if ((r = sys6(SYS_write, fd, (long) scratch, 4096, 0, 0, 0)) != 4096)
      fail("writing to a memfd", r, 4096);
    if ((r = sys6(SYS_lseek, fd, 0, 0 /* SEEK_SET */, 0, 0, 0)) != 0)
      fail("seeking a memfd", r, 0);
    for (int i = 0; i < 4096; i++)
      scratch[i] = 0;
    if ((r = sys6(SYS_read, fd, (long) scratch, 4096, 0, 0, 0)) != 4096)
      fail("reading a memfd back", r, 4096);
    for (int i = 0; i < 4096; i++)
      if (scratch[i] != (char) (i * 7 + 3))
        fail("a memfd did not hold what was written to it", i, -1);

    /*
     * And it can be mapped shared, which is the whole reason wl_shm and dbus
     * want one - a descriptor whose contents two processes can see.
     */
    if ((r = sys6(SYS_ftruncate, fd, 65536, 0, 0, 0, 0)) != 0)
      fail("growing a memfd", r, 0);
    long p = sys6(SYS_mmap, 0, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p < 0 && p > -4096)
      fail("mapping a memfd shared", p, 0);
    *(volatile char *) p = 0x5a;
    if ((r = sys6(SYS_lseek, fd, 0, 0, 0, 0, 0)) != 0)
      fail("seeking after the map", r, 0);
    scratch[0] = 0;
    if ((r = sys6(SYS_read, fd, (long) scratch, 1, 0, 0, 0)) != 1)
      fail("reading what was written through the mapping", r, 1);
    if (scratch[0] != 0x5a)
      fail("a shared mapping of a memfd is not shared with the file",
           scratch[0], 0x5a);
    sys6(SYS_munmap, p, 65536, 0, 0, 0, 0);

    /* Sealing is what this cannot do, and it says so at the seal rather than
     * at the creation - which is where a caller can still decide not to trust
     * the buffer. 1033 is F_ADD_SEALS. */
    if ((r = sys6(SYS_fcntl, fd, 1033, 0x8 /* F_SEAL_WRITE */, 0, 0, 0)) >= 0)
      fail("fcntl reported that a memfd was sealed", r, -EINVAL);

    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  }

  /* ================= the mlock family ================= */
  {
    long p = sys6(SYS_mmap, 0, 65536, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p < 0 && p > -4096)
      fail("mmap for the lock tests", p, 0);

    if ((r = sys6(SYS_mlock, p, 65536, 0, 0, 0, 0)) != 0)
      fail("mlock over a mapping that exists", r, 0);
    if ((r = sys6(SYS_munlock, p, 65536, 0, 0, 0, 0)) != 0)
      fail("munlock", r, 0);

    /*
     * The discriminator. A guest cannot observe that a lock took effect, so
     * what is checked is that it fails where a real one must: this address is
     * not mapped, and Linux answers ENOMEM. The stub this replaces returned 0
     * for every address in the machine.
     */
    if ((r = sys6(SYS_mlock, 0x40000000000ULL, 4096, 0, 0, 0, 0)) != -ENOMEM)
      fail("mlock over memory that is not mapped", r, -ENOMEM);
    if ((r = sys6(SYS_munlock, 0x40000000000ULL, 4096, 0, 0, 0, 0)) != -ENOMEM)
      fail("munlock over memory that is not mapped", r, -ENOMEM);

    /* A range that starts inside a mapping and runs off its end is not all
     * mapped either, which is the case a per-region walk has to get right. */
    if ((r = sys6(SYS_mlock, p + 61440, 1 << 20, 0, 0, 0, 0)) != -ENOMEM)
      fail("mlock over a range that runs past the mapping", r, -ENOMEM);

    /* mlock2 without flags is mlock; with the flag it is refused rather than
     * silently being mlock. */
    if ((r = sys6(SYS_mlock2, p, 65536, 0, 0, 0, 0)) != 0)
      fail("mlock2 with no flags", r, 0);
    if ((r = sys6(SYS_mlock2, p, 65536, MLOCK_ONFAULT, 0, 0, 0)) != -EINVAL)
      fail("mlock2 with MLOCK_ONFAULT", r, -EINVAL);
    if ((r = sys6(SYS_mlock2, p, 65536, 0x40, 0, 0, 0)) != -EINVAL)
      fail("mlock2 with a flag that does not exist", r, -EINVAL);
    sys6(SYS_munlock, p, 65536, 0, 0, 0, 0);

    if ((r = sys6(SYS_mlockall, 0, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("mlockall with no flags at all", r, -EINVAL);
    if ((r = sys6(SYS_mlockall, MCL_FUTURE, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("mlockall with MCL_FUTURE", r, -EINVAL);
    if ((r = sys6(SYS_mlockall, 0x40, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("mlockall with a flag that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_mlockall, MCL_CURRENT, 0, 0, 0, 0, 0)) != 0)
      fail("mlockall with MCL_CURRENT", r, 0);
    if ((r = sys6(SYS_munlockall, 0, 0, 0, 0, 0, 0)) != 0)
      fail("munlockall", r, 0);

    sys6(SYS_munmap, p, 65536, 0, 0, 0, 0);
  }

  /* ================= migrate_pages ================= */
  {
    unsigned long node0 = 1, node1 = 2, none = 0;

    if ((r = sys6(SYS_migrate_pages, 0, 64, (long) &node0, (long) &node0, 0, 0)) != 0)
      fail("migrate_pages between the only node and itself", r, 0);
    if ((r = sys6(SYS_migrate_pages, 0, 64, (long) &none, (long) &node0, 0, 0)) != 0)
      fail("migrate_pages from an empty set", r, 0);

    /* A node that does not exist is refused rather than confirmed. This is the
     * check an implementation returning 0 for everything fails. */
    if ((r = sys6(SYS_migrate_pages, 0, 64, (long) &node0, (long) &node1, 0, 0)) != -EINVAL)
      fail("migrate_pages to a node this machine does not have", r, -EINVAL);
    if ((r = sys6(SYS_migrate_pages, 0, 64, (long) &node1, (long) &node0, 0, 0)) != -EINVAL)
      fail("migrate_pages from a node this machine does not have", r, -EINVAL);

    /* Another process is out of reach, and that is not the same as absent. */
    if ((r = sys6(SYS_migrate_pages, 0x7ffffff, 64, (long) &node0, (long) &node0, 0, 0)) != -3 /* ESRCH */)
      fail("migrate_pages naming a process that does not exist", r, -3);
  }

  /* ================= membarrier ================= */
  {
    if ((r = sys6(SYS_membarrier, 0 /* QUERY */, 0, 0, 0, 0, 0)) != 0)
      fail("membarrier query reported commands that do not work", r, 0);
    if ((r = sys6(SYS_membarrier, 0, 1, 0, 0, 0, 0)) != -EINVAL)
      fail("membarrier query with a flag", r, -EINVAL);
    /* PRIVATE_EXPEDITED, which the query just said was unavailable. */
    if ((r = sys6(SYS_membarrier, 8, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("membarrier command the query did not offer", r, -EINVAL);
  }

  /* ================= the ones that cannot exist ================= */
  if ((r = sys6(SYS_landlock_create_ruleset, 0, 0, 1 /* _VERSION */, 0, 0, 0)) != -ENOSYS)
    fail("landlock_create_ruleset version probe", r, -ENOSYS);
  if ((r = sys6(SYS_landlock_add_rule, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("landlock_add_rule", r, -ENOSYS);
  if ((r = sys6(SYS_landlock_restrict_self, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("landlock_restrict_self", r, -ENOSYS);
  if ((r = sys6(SYS_memfd_secret, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("memfd_secret", r, -ENOSYS);
  if ((r = sys6(SYS_map_shadow_stack, 0, 65536, 0, 0, 0, 0)) != -ENOSYS)
    fail("map_shadow_stack", r, -ENOSYS);

  put("mem ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
