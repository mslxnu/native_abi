/* freestanding: cachestat, capget/capset, futimesat, getcpu and the LSM three.
 *
 * What is worth checking:
 *
 *   - cachestat's nr_cache has to *move*. A file written and then read back is
 *     cached; a range past the end of it is not. An implementation returning
 *     zeros, or returning the page count of the range whatever is resident,
 *     passes any check that only looks at one file.
 *   - capget used to return 0 and write nothing, so a caller read back its own
 *     uninitialised buffer. The check is therefore that the buffer *changed*
 *     from a value nothing would naturally produce.
 *   - the capability version protocol: an unknown version is corrected in the
 *     header and the call fails, which is how libcap discovers what to use. A
 *     kernel that just accepted anything would break that discovery silently.
 *   - capset drops and capget sees the drop, and a capability that was dropped
 *     cannot be picked back up.
 *   - futimesat carries microseconds and utimensat carries nanoseconds. The
 *     check is that a half-second lands as half a second, which is exactly what
 *     a missing x1000 gets wrong - and only in the fractional part, which is
 *     why it went unnoticed.
 *   - getcpu must answer inside the CPU set this guest was given, which is one
 *     CPU. The host's real core number is not that.
 *   - lsm_list_modules reports none, which is a count and not an error.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_getcwd            17
#define SYS_epoll_create1     20
#define SYS_openat            56
#define SYS_close             57
#define SYS_pipe2             59
#define SYS_read              63
#define SYS_write             64
#define SYS_fstat             80
#define SYS_newfstatat        79
#define SYS_utimensat         88
#define SYS_capget            90
#define SYS_capset            91
#define SYS_exit              93
#define SYS_unlinkat          35
#define SYS_lseek             62
#define SYS_ftruncate         46
#define SYS_getcpu           168
#define SYS_getpid           172
#define SYS_sched_getaffinity 123
#define SYS_delete_module    106
#define SYS_finit_module     273
#define SYS_cachestat        451
#define SYS_lsm_get_self_attr 459
#define SYS_lsm_set_self_attr 460
#define SYS_lsm_list_modules 461

#define EPERM         1
#define EBADF         9
#define EINVAL       22
#define ENOSYS       38
#define EOPNOTSUPP   95

#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT   0100
#define O_TRUNC  01000
#define AT_FDCWD  (-100)

/* 64MiB: big enough that counting the range instead of its residency is
 * unmistakable, small enough to extend instantly as a hole. */
#define SPARSE_SIZE  (64 << 20)

#define CAP_VERSION_1  0x19980330
#define CAP_VERSION_3  0x20080522
#define CAP_LAST_CAP   40
#define CAP_SYS_ADMIN  21

struct caphdr { unsigned version; int pid; };
struct capdata { unsigned effective, permitted, inheritable; };
struct csrange { unsigned long long off, count; };
struct cstat { unsigned long long nr_cache, nr_dirty, nr_writeback,
                                  nr_evicted, nr_recently_evicted; };
struct ltimespec { long sec, nsec; };
struct ltimeval  { long sec, usec; };

/* struct stat as aarch64 Linux lays it out, far enough to reach mtime. */
struct lstat {
  unsigned long long st_dev, st_ino;
  unsigned st_mode, st_nlink, st_uid, st_gid;
  unsigned long long st_rdev, __pad1;
  long long st_size;
  int st_blksize, __pad2;
  long long st_blocks;
  struct ltimespec st_atim, st_mtim, st_ctim;
};

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("cap FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static char buf[512 * 1024];

void _start(void)
{
  long r;

  /* ================= cachestat ================= */
  {
    const char *path = "/cache.dat";
    long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDWR | O_CREAT | O_TRUNC, 0644, 0, 0);
    if (fd < 0)
      fail("creating a file to measure", fd, 0);
    for (unsigned i = 0; i < sizeof buf; i++)
      buf[i] = (char) i;
    if ((r = sys6(SYS_write, fd, (long) buf, sizeof buf, 0, 0, 0)) != (long) sizeof buf)
      fail("writing it", r, (long) sizeof buf);

    struct csrange rg; struct cstat cs;

    /* Flags that do not exist, and a descriptor that is not open. */
    rg.off = 0; rg.count = sizeof buf;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 1, 0, 0)) != -EINVAL)
      fail("cachestat with a flag that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_cachestat, 999, (long) &rg, (long) &cs, 0, 0, 0)) != -EBADF)
      fail("cachestat on a descriptor that is not open", r, -EBADF);

    /*
     * The whole file, which was just written and so is cached.
     */
    cs.nr_cache = 0xdead;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 0, 0, 0)) != 0)
      fail("cachestat over the whole file", r, 0);
    if (cs.nr_cache == 0)
      fail("cachestat says a file just written is not cached", (long) cs.nr_cache, 1);
    if (cs.nr_cache > sizeof buf / 4096)
      fail("cachestat reports more pages than the range holds", (long) cs.nr_cache, 0);
    unsigned long long whole = cs.nr_cache;

    /*
     * ---- the part that has to be *partly* resident ----
     *
     * Everything above is satisfied by an implementation that reports the whole
     * range cached without consulting anything, because the whole range really
     * is cached - which is how the first version of this test passed while
     * measuring nothing. A sparse file is the discriminator: it is extended
     * without being written, so almost none of it exists in memory, and only
     * the prefix that gets written afterwards does.
     */
    if ((r = sys6(SYS_ftruncate, fd, SPARSE_SIZE, 0, 0, 0, 0)) != 0)
      fail("ftruncate to make a sparse file", r, 0);

    rg.off = 0; rg.count = SPARSE_SIZE;
    cs.nr_cache = 0xdead;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 0, 0, 0)) != 0)
      fail("cachestat over a sparse file", r, 0);
    /*
     * The prefix written before the truncate may still be resident; the rest of
     * the file was never written and cannot be. So this is far below the page
     * count of the range, which is what an implementation counting the range
     * rather than its residency would report.
     */
    if (cs.nr_cache > SPARSE_SIZE / 4096 / 8)
      fail("cachestat counted a sparse file's holes as cached",
           (long) cs.nr_cache, (long) (SPARSE_SIZE / 4096 / 8));
    unsigned long long sparse = cs.nr_cache;

    /* Writing at the far end makes those pages, and only those, resident. */
    if ((r = sys6(SYS_lseek, fd, SPARSE_SIZE - (long) sizeof buf, 0 /* SEEK_SET */, 0, 0, 0))
        != SPARSE_SIZE - (long) sizeof buf)
      fail("seeking to the end of the sparse file", r, 0);
    if ((r = sys6(SYS_write, fd, (long) buf, sizeof buf, 0, 0, 0)) != (long) sizeof buf)
      fail("writing the far end of the sparse file", r, (long) sizeof buf);

    cs.nr_cache = 0xdead;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 0, 0, 0)) != 0)
      fail("cachestat after writing the far end", r, 0);
    if (cs.nr_cache <= sparse)
      fail("cachestat did not notice pages that were just written",
           (long) cs.nr_cache, (long) sparse + 1);
    if (cs.nr_cache > SPARSE_SIZE / 4096 / 8)
      fail("cachestat still counts the holes", (long) cs.nr_cache,
           (long) (SPARSE_SIZE / 4096 / 8));

    /* Put the file back to the size the rest of this block expects. */
    if ((r = sys6(SYS_ftruncate, fd, sizeof buf, 0, 0, 0, 0)) != 0)
      fail("ftruncate back", r, 0);

    /* A range that starts past the end of the file holds nothing. This is the
     * one that catches "return the size of the range". */
    rg.off = sizeof buf * 4; rg.count = sizeof buf;
    cs.nr_cache = 0xdead;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 0, 0, 0)) != 0)
      fail("cachestat past the end of the file", r, 0);
    if (cs.nr_cache != 0)
      fail("cachestat found pages past the end of the file", (long) cs.nr_cache, 0);

    /* Half the file is at most as many pages as all of it, and more than none. */
    rg.off = 0; rg.count = sizeof buf / 2;
    if ((r = sys6(SYS_cachestat, fd, (long) &rg, (long) &cs, 0, 0, 0)) != 0)
      fail("cachestat over half the file", r, 0);
    if (cs.nr_cache == 0 || cs.nr_cache > whole)
      fail("cachestat over half the file", (long) cs.nr_cache, (long) whole);

    /* A pipe holds no pages, and saying so is not an error. */
    { int p[2];
      if ((r = sys6(SYS_pipe2, (long) p, 0, 0, 0, 0, 0)) != 0)
        fail("pipe2", r, 0);
      rg.off = 0; rg.count = 4096; cs.nr_cache = 0xdead;
      if ((r = sys6(SYS_cachestat, p[0], (long) &rg, (long) &cs, 0, 0, 0)) != 0)
        fail("cachestat on a pipe", r, 0);
      if (cs.nr_cache != 0)
        fail("cachestat found pages in a pipe", (long) cs.nr_cache, 0);
      sys6(SYS_close, p[0], 0, 0, 0, 0, 0);
      sys6(SYS_close, p[1], 0, 0, 0, 0, 0); }

    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) path, 0, 0, 0, 0);
  }

  /* ================= capget / capset ================= */
  {
    struct caphdr h; struct capdata d[2];

    /* The version probe: an unknown version is corrected and refused. */
    h.version = 0; h.pid = 0;
    if ((r = sys6(SYS_capget, (long) &h, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("capget with a version that does not exist", r, -EINVAL);
    if (h.version != CAP_VERSION_3)
      fail("capget did not report the version to use", (long) h.version, CAP_VERSION_3);

    /* A pid that is not this process cannot be read. */
    h.version = CAP_VERSION_3; h.pid = 0x7ffffff;
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != -3 /* ESRCH */)
      fail("capget of another process", r, -3);

    /*
     * The real read. The buffer is poisoned first, because the fault this
     * replaces was a capget that returned 0 and wrote nothing at all - a check
     * that only looked at the return value could not tell the difference.
     */
    h.version = CAP_VERSION_3; h.pid = 0;
    d[0].effective = d[0].permitted = d[0].inheritable = 0xa5a5a5a5;
    d[1].effective = d[1].permitted = d[1].inheritable = 0xa5a5a5a5;
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capget", r, 0);
    if (d[0].effective == 0xa5a5a5a5 || d[1].effective == 0xa5a5a5a5)
      fail("capget returned success without writing anything", (long) d[0].effective, 0);

    /* This guest starts as root, so it holds every capability that exists and
     * none that does not. */
    if (d[0].effective != 0xffffffffu)
      fail("capget: the low word of root's effective set", (long) d[0].effective, -1);
    if (d[1].effective != (1u << (CAP_LAST_CAP - 32 + 1)) - 1)
      fail("capget: the high word, bounded by the last capability",
           (long) d[1].effective, (long) ((1u << (CAP_LAST_CAP - 32 + 1)) - 1));

    /* The old one-word ABI writes one word and must not touch the second. */
    h.version = CAP_VERSION_1; h.pid = 0;
    d[1].effective = 0xa5a5a5a5;
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capget with the version 1 ABI", r, 0);
    if (d[1].effective != 0xa5a5a5a5)
      fail("capget with the one-word ABI wrote a second word", (long) d[1].effective, 0);

    /* ---- dropping ---- */
    h.version = CAP_VERSION_3; h.pid = 0;
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capget before the drop", r, 0);

    unsigned full0 = d[0].effective;
    d[0].effective &= ~(1u << CAP_SYS_ADMIN);
    d[0].permitted &= ~(1u << CAP_SYS_ADMIN);
    if ((r = sys6(SYS_capset, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capset dropping CAP_SYS_ADMIN", r, 0);

    d[0].effective = d[0].permitted = 0xa5a5a5a5;
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capget after the drop", r, 0);
    if (d[0].permitted & (1u << CAP_SYS_ADMIN))
      fail("capget did not see the dropped capability", (long) d[0].permitted, 0);

    /* And it cannot be picked back up: a set is a thing you lower. */
    d[0].permitted = full0;
    d[0].effective = full0;
    if ((r = sys6(SYS_capset, (long) &h, (long) d, 0, 0, 0, 0)) != -EPERM)
      fail("capset raising a capability that was dropped", r, -EPERM);

    /* Effective may not exceed permitted, either. */
    if ((r = sys6(SYS_capget, (long) &h, (long) d, 0, 0, 0, 0)) != 0)
      fail("capget", r, 0);
    d[0].effective |= 1u << CAP_SYS_ADMIN;
    if ((r = sys6(SYS_capset, (long) &h, (long) d, 0, 0, 0, 0)) != -EPERM)
      fail("capset with effective exceeding permitted", r, -EPERM);
  }

  /* ================= what futimesat writes into =================
   *
   * futimesat itself cannot be called from here: it is an x86-only number, as
   * utimes is, and aarch64 has neither - every timestamp on this architecture
   * goes through utimensat. So what is checked is the half that *is* reachable,
   * which is the sink both of them feed: do_utimensat has to record the
   * fractional part it is given rather than round it away. If that were lossy
   * the microsecond conversion in futimesat would be pointless, and this is
   * what proves it is not.
   *
   * The conversion itself - the multiply by 1000 - is exercised only by an
   * x86_64 guest, which this host cannot run.
   */
  {
    const char *path = "/times.dat";
    long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDWR | O_CREAT | O_TRUNC, 0644, 0, 0);
    if (fd < 0)
      fail("creating a file to stamp", fd, 0);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    struct ltimespec ts[2] = { { 1000000000, 500000000 }, { 1000000000, 500000000 } };
    if ((r = sys6(SYS_utimensat, AT_FDCWD, (long) path, (long) ts, 0, 0, 0)) != 0)
      fail("utimensat", r, 0);

    struct lstat st;
    if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) path, (long) &st, 0, 0, 0)) != 0)
      fail("stat after utimensat", r, 0);
    if (st.st_mtim.sec != 1000000000)
      fail("utimensat set the wrong second", st.st_mtim.sec, 1000000000);
    if (st.st_mtim.nsec != 500000000)
      fail("utimensat lost the fractional second", st.st_mtim.nsec, 500000000);

    sys6(SYS_unlinkat, AT_FDCWD, (long) path, 0, 0, 0, 0);
  }

  /* ================= getcpu ================= */
  {
    unsigned cpu = 0xdead, node = 0xdead;
    if ((r = sys6(SYS_getcpu, (long) &cpu, (long) &node, 0, 0, 0, 0)) != 0)
      fail("getcpu", r, 0);

    /*
     * It has to be inside the affinity mask this guest was given, which offers
     * one CPU. Passing the host's real core number through would land outside
     * it - and a program sizing a per-CPU array from the mask would index off
     * the end of it.
     */
    unsigned char mask[32] = { 0 };
    if ((r = sys6(SYS_sched_getaffinity, 0, sizeof mask, (long) mask, 0, 0, 0)) < 0)
      fail("sched_getaffinity", r, 0);
    if (cpu >= 8 * sizeof mask || !(mask[cpu / 8] & (1u << (cpu % 8))))
      fail("getcpu named a CPU outside this guest's affinity mask", (long) cpu, 0);
    if (node != 0)
      fail("getcpu named a memory node other than the only one", (long) node, 0);

    /* Both pointers are optional. */
    if ((r = sys6(SYS_getcpu, 0, 0, 0, 0, 0, 0)) != 0)
      fail("getcpu with no pointers at all", r, 0);
  }

  /* ================= the LSM three ================= */
  {
    unsigned size = 64;
    unsigned long long ids[8];
    if ((r = sys6(SYS_lsm_list_modules, (long) ids, (long) &size, 1, 0, 0, 0)) != -EINVAL)
      fail("lsm_list_modules with a flag that does not exist", r, -EINVAL);

    size = 64;
    if ((r = sys6(SYS_lsm_list_modules, (long) ids, (long) &size, 0, 0, 0, 0)) != 0)
      fail("lsm_list_modules", r, 0);
    if (size != 0)
      fail("lsm_list_modules wants room for modules there are none of", (long) size, 0);

    size = 64;
    if ((r = sys6(SYS_lsm_get_self_attr, 100 /* LSM_ATTR_CURRENT */, (long) ids,
                  (long) &size, 0, 0, 0)) != -EOPNOTSUPP)
      fail("lsm_get_self_attr", r, -EOPNOTSUPP);
    if ((r = sys6(SYS_lsm_get_self_attr, 0, (long) ids, (long) &size, 0, 0, 0)) != -EINVAL)
      fail("lsm_get_self_attr with LSM_ATTR_UNDEF", r, -EINVAL);
    if ((r = sys6(SYS_lsm_set_self_attr, 100, (long) ids, 16, 0, 0, 0)) != -EOPNOTSUPP)
      fail("lsm_set_self_attr", r, -EOPNOTSUPP);
  }

  /* ================= the module family ================= */
  if ((r = sys6(SYS_finit_module, 0, (long) "", 0, 0, 0, 0)) != -ENOSYS)
    fail("finit_module", r, -ENOSYS);
  if ((r = sys6(SYS_delete_module, (long) "nothing", 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("delete_module", r, -ENOSYS);

  put("cap ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
