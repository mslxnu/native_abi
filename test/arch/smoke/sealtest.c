/* freestanding: mseal, mincore, move_pages, preadv/pwritev and friends,
 * pause, personality, pkey_mprotect, and the five that answer ENOSYS.
 *
 * What is worth checking:
 *
 *   - mseal is only worth having if it *holds*. So every gate is tried against
 *     a sealed page: munmap, mprotect, mremap, and a MAP_FIXED mmap over it.
 *     An implementation that records the seal and enforces nothing passes any
 *     test that only calls mseal and looks at the return value.
 *   - and it must not over-reach: the page beside a sealed one is still an
 *     ordinary page, which is what catches a check written against the whole
 *     region instead of the sealed range.
 *   - mincore has to *discriminate*. A fresh anonymous mapping is not resident
 *     until it is touched, so the answer must change when it is touched - the
 *     same trap cachestat fell into, where a fully resident file could not tell
 *     a real answer from a constant one.
 *   - preadv must not disturb the file position, and preadv2 with an offset of
 *     -1 must. That pair is the whole difference between them.
 *   - the offset arrives in two halves and only the low one carries it here.
 *     A read at a large offset is what catches an implementation folding in the
 *     high half, since glibc leaves garbage there on a 64-bit machine.
 *   - personality answers the query without changing anything, and refuses the
 *     bits nabi cannot honour rather than recording them.
 *   - pkey_mprotect(-1) is mprotect; any real key is invalid, because none can
 *     have been allocated.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_unlinkat        35
#define SYS_ftruncate       46
#define SYS_openat          56
#define SYS_close           57
#define SYS_lseek           62
#define SYS_read            63
#define SYS_write           64
#define SYS_pread64         67
#define SYS_preadv          69
#define SYS_pwritev         70
#define SYS_exit            93
#define SYS_getpid         172
#define SYS_clone          220
#define SYS_wait4          260
#define SYS_personality     92
#define SYS_mincore        232
#define SYS_madvise        233
#define SYS_mprotect       226
#define SYS_munmap         215
#define SYS_mremap         216
#define SYS_mmap           222
#define SYS_move_pages     239
#define SYS_preadv2        286
#define SYS_pwritev2       287
#define SYS_pkey_mprotect  288
#define SYS_pkey_alloc     289
#define SYS_pkey_free      290
#define SYS_mseal          462
#define SYS_perf_event_open 241
#define SYS_pivot_root      41

#define EPERM         1
#define ENOENT        2
#define EBADF         9
#define ENOMEM       12
#define EINVAL       22
#define ENOSYS       38
#define EOPNOTSUPP   95

#define PROT_NONE    0
#define PROT_READ    1
#define PROT_WRITE   2
#define MAP_SHARED   1
#define MAP_PRIVATE  2
#define MAP_FIXED   0x10
#define MAP_ANON    0x20
#define MREMAP_MAYMOVE 1

#define O_RDONLY   0
#define O_RDWR     2
#define O_CREAT   0100
#define O_TRUNC  01000
#define AT_FDCWD  (-100)

/* Apple Silicon's page, which is also the guest's. */
#define PAGE  16384

struct iov { void *base; unsigned long len; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("seal FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

static char buf[8192];
static char vec[64];

void _start(void)
{
  long r;

  /* ================= mseal ================= */
  {
    /* Four pages, so that a seal on the second can be checked against the
     * first and third staying ordinary. */
    long p = sys6(SYS_mmap, 0, 4 * PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p < 0 && p > -4096)
      fail("mmap for the seal tests", p, 0);

    if ((r = sys6(SYS_mseal, p + PAGE, PAGE, 1, 0, 0, 0)) != -EINVAL)
      fail("mseal with a flag, of which there are none", r, -EINVAL);
    if ((r = sys6(SYS_mseal, p + 1, PAGE, 0, 0, 0, 0)) != -EINVAL)
      fail("mseal at an address that is not page aligned", r, -EINVAL);
    if ((r = sys6(SYS_mseal, 0x40000000000ULL, PAGE, 0, 0, 0, 0)) != -ENOMEM)
      fail("mseal over memory that is not mapped", r, -ENOMEM);

    if ((r = sys6(SYS_mseal, p + PAGE, PAGE, 0, 0, 0, 0)) != 0)
      fail("mseal", r, 0);

    /* ---- every gate, against the sealed page ---- */
    if ((r = sys6(SYS_munmap, p + PAGE, PAGE, 0, 0, 0, 0)) != -EPERM)
      fail("munmap of a sealed page", r, -EPERM);
    if ((r = sys6(SYS_mprotect, p + PAGE, PAGE, PROT_READ, 0, 0, 0)) != -EPERM)
      fail("mprotect of a sealed page", r, -EPERM);
    if ((r = sys6(SYS_mremap, p + PAGE, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0, 0)) != -EPERM)
      fail("mremap of a sealed page", r, -EPERM);
    r = sys6(SYS_mmap, p + PAGE, PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (r != -EPERM)
      fail("mapping over a sealed page", r, -EPERM);
    /* pkey_mprotect delegates to mprotect, so the seal has to reach it too. */
    if ((r = sys6(SYS_pkey_mprotect, p + PAGE, PAGE, PROT_READ, -1, 0, 0)) != -EPERM)
      fail("pkey_mprotect of a sealed page", r, -EPERM);

    /* A range that only overlaps the sealed page is refused as a whole. */
    if ((r = sys6(SYS_munmap, p, 2 * PAGE, 0, 0, 0, 0)) != -EPERM)
      fail("munmap of a range that reaches into a sealed page", r, -EPERM);

    /* ---- and the neighbours are untouched ---- */
    if ((r = sys6(SYS_mprotect, p, PAGE, PROT_READ, 0, 0, 0)) != 0)
      fail("mprotect of the page before the sealed one", r, 0);
    if ((r = sys6(SYS_mprotect, p + 2 * PAGE, PAGE, PROT_READ, 0, 0, 0)) != 0)
      fail("mprotect of the page after the sealed one", r, 0);
    if ((r = sys6(SYS_munmap, p + 3 * PAGE, PAGE, 0, 0, 0, 0)) != 0)
      fail("munmap of an unsealed page in the same mapping", r, 0);

    /* The sealed page is still there and still readable and writable, which is
     * the point: sealing froze the layout, not the contents. */
    *(volatile char *) (p + PAGE) = 0x27;
    if (*(volatile char *) (p + PAGE) != 0x27)
      fail("a sealed page stopped working", 0, 0x27);

    /*
     * ---- and it survives a fork ----
     *
     * A fork on arm64 is a fork plus an exec: the child rebuilds its address
     * space from the checkpoint. So a seal that is not carried in the
     * checkpoint record comes back cleared, and the child is quietly less
     * protected than the parent with nothing in either of them saying so.
     * The child reports back through its exit code.
     */
    { long child = sys6(SYS_clone, 17 /* SIGCHLD */, 0, 0, 0, 0, 0);
      if (child < 0)
        fail("clone", child, 0);
      if (child == 0) {
        long c = sys6(SYS_munmap, p + PAGE, PAGE, 0, 0, 0, 0);
        /* 7 means the seal held; 8 means it did not. */
        sys6(SYS_exit, c == -EPERM ? 7 : 8, 0, 0, 0, 0, 0);
      }
      int wstatus = 0;
      if ((r = sys6(SYS_wait4, child, (long) &wstatus, 0, 0, 0, 0)) != child)
        fail("wait4 for the forked child", r, child);
      int code = (wstatus >> 8) & 0xff;
      if (code != 7)
        fail("the seal did not survive the fork", code, 7);
    }
  }

  /* ================= mincore ================= */
  {
    long p = sys6(SYS_mmap, 0, 8 * PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p < 0 && p > -4096)
      fail("mmap for mincore", p, 0);

    if ((r = sys6(SYS_mincore, p + 1, PAGE, (long) vec, 0, 0, 0)) != -EINVAL)
      fail("mincore at an address that is not page aligned", r, -EINVAL);
    if ((r = sys6(SYS_mincore, 0x40000000000ULL, PAGE, (long) vec, 0, 0, 0)) != -ENOMEM)
      fail("mincore over memory that is not mapped", r, -ENOMEM);

    /*
     * Untouched, so not resident. This is the half that catches an
     * implementation reporting everything resident, and the touched pass below
     * is the half that catches one reporting nothing.
     */
    for (int i = 0; i < 8; i++) vec[i] = 0x7f;
    if ((r = sys6(SYS_mincore, p, 8 * PAGE, (long) vec, 0, 0, 0)) != 0)
      fail("mincore over a fresh mapping", r, 0);
    int before = 0;
    for (int i = 0; i < 8; i++) {
      if (vec[i] & ~1)
        fail("mincore wrote bits Linux calls reserved", vec[i], 0);
      before += vec[i] & 1;
    }
    if (before != 0)
      fail("mincore says an untouched mapping is resident", before, 0);

    /* Touch four of the eight. */
    for (int i = 0; i < 4; i++)
      *(volatile char *) (p + (long) i * PAGE) = 1;
    if ((r = sys6(SYS_mincore, p, 8 * PAGE, (long) vec, 0, 0, 0)) != 0)
      fail("mincore after touching", r, 0);
    int after = 0;
    for (int i = 0; i < 8; i++)
      after += vec[i] & 1;
    if (after < 4)
      fail("mincore did not notice pages that were touched", after, 4);
    if (after == 8)
      fail("mincore reports pages resident that were never touched", after, 4);

    sys6(SYS_munmap, p, 8 * PAGE, 0, 0, 0, 0);
  }

  /* ================= move_pages ================= */
  {
    long p = sys6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    unsigned long pages[3] = { (unsigned long) p, (unsigned long) p + PAGE,
                               0x40000000000ULL };
    int nodes[3] = { 0, 0, 0 };
    int status[3] = { 9, 9, 9 };

    /* The query form: every page that exists is on the only node, and one that
     * does not is ENOENT in its own slot rather than a failed call. */
    if ((r = sys6(SYS_move_pages, 0, 3, (long) pages, 0, (long) status, 0)) != 0)
      fail("move_pages asking where the pages are", r, 0);
    if (status[0] != 0 || status[1] != 0)
      fail("move_pages put a mapped page somewhere other than node 0", status[0], 0);
    if (status[2] != -ENOENT)
      fail("move_pages on a page that is not mapped", status[2], -ENOENT);

    /* A move to the only node is already done; to any other it is refused per
     * page, which is what an implementation returning 0 for all of it fails. */
    if ((r = sys6(SYS_move_pages, 0, 2, (long) pages, (long) nodes, (long) status, 0)) != 0)
      fail("move_pages to node 0", r, 0);
    if (status[0] != 0)
      fail("move_pages to the node the page is already on", status[0], 0);
    nodes[0] = 1;
    if ((r = sys6(SYS_move_pages, 0, 2, (long) pages, (long) nodes, (long) status, 0)) != 0)
      fail("move_pages with one bad node", r, 0);
    if (status[0] != -EINVAL)
      fail("move_pages to a node this machine does not have", status[0], -EINVAL);
    if (status[1] != 0)
      fail("move_pages refused a good page beside a bad one", status[1], 0);

    sys6(SYS_munmap, p, 2 * PAGE, 0, 0, 0, 0);
  }

  /* ================= preadv / pwritev / v2 ================= */
  {
    const char *path = "/iov.dat";
    long fd = sys6(SYS_openat, AT_FDCWD, (long) path, O_RDWR | O_CREAT | O_TRUNC, 0644, 0, 0);
    if (fd < 0)
      fail("creating a file for the iov tests", fd, 0);

    for (int i = 0; i < 4096; i++)
      buf[i] = (char) (i * 5 + 1);
    if ((r = sys6(SYS_write, fd, (long) buf, 4096, 0, 0, 0)) != 4096)
      fail("filling it", r, 4096);

    /* Two vectors, read at an offset. The position must not move. */
    if ((r = sys6(SYS_lseek, fd, 100, 0 /* SEEK_SET */, 0, 0, 0)) != 100)
      fail("seeking", r, 100);
    char a[64], b[64];
    struct iov v[2] = { { a, sizeof a }, { b, sizeof b } };
    for (unsigned i = 0; i < sizeof a; i++) a[i] = b[i] = 0;
    if ((r = sys6(SYS_preadv, fd, (long) v, 2, 1000, 0, 0)) != 128)
      fail("preadv over two vectors", r, 128);
    for (int i = 0; i < 64; i++)
      if (a[i] != (char) ((1000 + i) * 5 + 1))
        fail("preadv read the wrong bytes into the first vector", i, -1);
    for (int i = 0; i < 64; i++)
      if (b[i] != (char) ((1064 + i) * 5 + 1))
        fail("preadv read the wrong bytes into the second vector", i, -1);
    if ((r = sys6(SYS_lseek, fd, 0, 1 /* SEEK_CUR */, 0, 0, 0)) != 100)
      fail("preadv moved the file position", r, 100);

    /*
     * The two-halves trap. glibc leaves the high word holding whatever was in
     * that register, so an implementation folding it in reads from a wild
     * offset. Passing an obviously wrong high half must change nothing.
     */
    for (unsigned i = 0; i < sizeof a; i++) a[i] = 0;
    struct iov one[1] = { { a, sizeof a } };
    if ((r = sys6(SYS_preadv, fd, (long) one, 1, 1000, 0x5a5a5a5a, 0)) != 64)
      fail("preadv with garbage in the high half of the offset", r, 64);
    if (a[0] != (char) (1000 * 5 + 1))
      fail("preadv folded in the high half of the offset", a[0], (char) (1000 * 5 + 1));

    /* pwritev at an offset, read back with pread. */
    for (int i = 0; i < 32; i++) a[i] = (char) (0x40 + i);
    struct iov w[1] = { { a, 32 } };
    if ((r = sys6(SYS_pwritev, fd, (long) w, 1, 2000, 0, 0)) != 32)
      fail("pwritev", r, 32);
    if ((r = sys6(SYS_pread64, fd, (long) b, 32, 2000, 0, 0)) != 32)
      fail("pread after pwritev", r, 32);
    for (int i = 0; i < 32; i++)
      if (b[i] != (char) (0x40 + i))
        fail("pwritev wrote the wrong bytes", i, -1);
    if ((r = sys6(SYS_lseek, fd, 0, 1, 0, 0, 0)) != 100)
      fail("pwritev moved the file position", r, 100);

    /* ---- v2 ---- */
    if ((r = sys6(SYS_preadv2, fd, (long) one, 1, 0, 0, 0x40)) != -EINVAL)
      fail("preadv2 with a flag that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_preadv2, fd, (long) one, 1, 0, 0, 1 /* HIPRI */)) != -EOPNOTSUPP)
      fail("preadv2 with RWF_HIPRI", r, -EOPNOTSUPP);
    if ((r = sys6(SYS_preadv2, fd, (long) one, 1, 0, 0, 8 /* NOWAIT */)) != -EOPNOTSUPP)
      fail("preadv2 with RWF_NOWAIT", r, -EOPNOTSUPP);

    /*
     * An offset of -1 is the stream form, so unlike preadv it *does* move the
     * position. That difference is the whole reason both exist.
     */
    if ((r = sys6(SYS_lseek, fd, 200, 0, 0, 0, 0)) != 200)
      fail("seeking before the stream read", r, 200);
    for (unsigned i = 0; i < sizeof a; i++) a[i] = 0;
    if ((r = sys6(SYS_preadv2, fd, (long) one, 1, -1, -1, 0)) != 64)
      fail("preadv2 with an offset of -1", r, 64);
    if (a[0] != (char) (200 * 5 + 1))
      fail("preadv2(-1) did not read from the file position", a[0], (char) (200 * 5 + 1));
    if ((r = sys6(SYS_lseek, fd, 0, 1, 0, 0, 0)) != 264)
      fail("preadv2(-1) did not advance the file position", r, 264);

    /* RWF_APPEND goes to the end whatever offset was passed. */
    if ((r = sys6(SYS_ftruncate, fd, 4096, 0, 0, 0, 0)) != 0)
      fail("ftruncate before the append", r, 0);
    for (int i = 0; i < 16; i++) a[i] = (char) (0x70 + i);
    struct iov ap[1] = { { a, 16 } };
    if ((r = sys6(SYS_pwritev2, fd, (long) ap, 1, 0, 0, 0x10 /* APPEND */)) != 16)
      fail("pwritev2 with RWF_APPEND", r, 16);
    if ((r = sys6(SYS_pread64, fd, (long) b, 16, 4096, 0, 0)) != 16)
      fail("reading what RWF_APPEND wrote", r, 16);
    for (int i = 0; i < 16; i++)
      if (b[i] != (char) (0x70 + i))
        fail("RWF_APPEND wrote somewhere other than the end", i, -1);

    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) path, 0, 0, 0, 0);
  }

  /* ================= personality ================= */
  {
    long start = sys6(SYS_personality, 0xffffffff, 0, 0, 0, 0, 0);
    if (start < 0)
      fail("personality query", start, 0);
    /* The query must not have changed anything. */
    if (sys6(SYS_personality, 0xffffffff, 0, 0, 0, 0, 0) != start)
      fail("personality query changed the value", 0, start);

    /* nabi does not randomize, so asking for no randomization is asking for
     * what is already true - and it returns the previous value. */
    if ((r = sys6(SYS_personality, 0x0040000, 0, 0, 0, 0, 0)) != start)
      fail("personality(ADDR_NO_RANDOMIZE) did not return the old value", r, start);
    if ((r = sys6(SYS_personality, 0xffffffff, 0, 0, 0, 0, 0)) != 0x0040000)
      fail("personality did not record ADDR_NO_RANDOMIZE", r, 0x0040000);

    /* Bits nabi cannot honour are refused rather than stored. */
    if ((r = sys6(SYS_personality, 0x0400000 /* READ_IMPLIES_EXEC */, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("personality(READ_IMPLIES_EXEC)", r, -EINVAL);
    if ((r = sys6(SYS_personality, 0x0020000 /* UNAME26 */, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("personality(UNAME26)", r, -EINVAL);
    if ((r = sys6(SYS_personality, 0xffffffff, 0, 0, 0, 0, 0)) != 0x0040000)
      fail("a refused personality was recorded anyway", r, 0x0040000);
    /* A domain that is not PER_LINUX. */
    if ((r = sys6(SYS_personality, 0x0001, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("personality with a foreign execution domain", r, -EINVAL);

    sys6(SYS_personality, 0, 0, 0, 0, 0, 0);
  }

  /* ================= pkeys ================= */
  {
    long p = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    /* -1 means "no key", and is defined to be exactly mprotect. */
    if ((r = sys6(SYS_pkey_mprotect, p, PAGE, PROT_READ, -1, 0, 0)) != 0)
      fail("pkey_mprotect with no key", r, 0);
    /* No key can have been allocated, so any key is an invalid one. */
    if ((r = sys6(SYS_pkey_alloc, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
      fail("pkey_alloc", r, -ENOSYS);
    if ((r = sys6(SYS_pkey_free, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
      fail("pkey_free", r, -ENOSYS);
    if ((r = sys6(SYS_pkey_mprotect, p, PAGE, PROT_READ, 3, 0, 0)) != -EINVAL)
      fail("pkey_mprotect with a key that was never allocated", r, -EINVAL);
    sys6(SYS_munmap, p, PAGE, 0, 0, 0, 0);
  }

  /* ================= the ones that cannot exist ================= */
  if ((r = sys6(SYS_perf_event_open, 0, 0, -1, -1, 0, 0)) != -ENOSYS)
    fail("perf_event_open", r, -ENOSYS);
  if ((r = sys6(SYS_pivot_root, (long) "/", (long) "/", 0, 0, 0, 0)) != -ENOSYS)
    fail("pivot_root", r, -ENOSYS);

  /*
   * pause is not called from here: like futimesat it is an x86-only number and
   * aarch64 has none, so every wait for a signal on this architecture goes
   * through ppoll or rt_sigsuspend. It is the same wait loop rt_sigsuspend uses
   * and that one is reachable, but the call itself is unexercised on this host.
   */

  put("seal ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
