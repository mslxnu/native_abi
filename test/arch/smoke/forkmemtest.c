/* freestanding: a forked child sees exactly the memory its parent had.
 *
 * fork on Apple Silicon cannot copy an address space in place - the child is a
 * fresh `nabi --resume` that maps the parent's arena privately - so "the child
 * sees the parent's memory" is a thing that has to be arranged rather than a
 * thing that happens. When it goes wrong it does not announce itself: the
 * child's heap is simply not what its allocator remembers, and glibc reports it
 * as whatever it happens to walk into next - "malloc_consolidate(): unaligned
 * fastbin chunk detected", "malloc(): unaligned fastbin chunk detected 3",
 * an assertion in sysmalloc. All of them name the allocator, none of them name
 * fork.
 *
 * The sizes here are 4KiB multiples that are deliberately *not* 16KiB
 * multiples, so that several of them share one stage-2 block. That is the case
 * that matters: a whole-block mapping survives a handover that a partial one
 * does not, and guest mappings became 4KiB-granular while the block behind them
 * stayed at 16KiB.
 */
asm(".globl _start\n_start:\n  mov x0, sp\n  b start_c\n");

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_openat 56
#define SYS_read 63
#define SYS_write 64
#define SYS_pipe2 59
#define SYS_munmap 215
#define SYS_close 57
#define SYS_mmap 222
#define SYS_brk 214
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit_group 94
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define SIGCHLD 17
#define AT_FDCWD -100
#define O_RDONLY 0

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void puth(unsigned long v){char b[19];int i=18;b[i--]=0;
  if(v==0)b[i--]='0';while(v>0){unsigned d=v&15;b[i--]=d<10?'0'+d:'a'+d-10;v>>=4;}
  put("0x");put(b+i+1);}

/* A value that depends on the address, so a page that came from the wrong
 * place is wrong in a way that says where it came from. */
static unsigned long pat(unsigned long a){ return a * 0x9E3779B97F4A7C15UL ^ 0x5A5A5A5A5A5A5A5AUL; }

/*
 * A different pattern from fill's, for a descendant to write.
 *
 * Writing the *same* bytes a page already held would prove nothing: two
 * copy-on-write copies of one page start out identical, so a check that reads
 * back what was already there passes through either of them. The two views only
 * separate once someone stores something new.
 */
static void fill_alt(unsigned long base, unsigned long len){
  for (unsigned long o = 0; o + 8 <= len; o += 8)
    *(volatile unsigned long *)(base + o) = ~pat(base + o);
}

static void fill(unsigned long base, unsigned long len){
  for (unsigned long o = 0; o + 8 <= len; o += 8)
    *(volatile unsigned long *)(base + o) = pat(base + o);
}

/* Returns the number of words that did not survive, and reports the first few. */
static int check(const char *what, unsigned long base, unsigned long len){
  int bad = 0;
  for (unsigned long o = 0; o + 8 <= len; o += 8) {
    unsigned long got = *(volatile unsigned long *)(base + o);
    unsigned long want = pat(base + o);
    if (got == want) continue;
    if (bad < 4) {
      put("  FAIL "); put(what); put(" at "); puth(base + o);
      put(" (offset "); putd((long) o); put("): got "); puth(got);
      put(", want "); puth(want);
      /* Where it *would* have been right tells us what got aliased over it. */
      if (got == 0) put(" [zero - never copied]");
      put("\n");
    }
    bad++;
  }
  return bad;
}

#define NREG 6
static const unsigned long sizes[NREG] = {
  0x1000, 0x2000, 0x3000, 0x1000, 0x5000, 0x1000,
};
static unsigned long regs[NREG];
static unsigned long brk_base, brk_len;
static unsigned long filemap;
#define FILEMAP_LEN 0x3000
/*
 * A mapping with a hole punched in it, which is how two regions come to be
 * slices of one arena allocation: the mm layer splits a region when part of it
 * is unmapped, and the halves keep the offset of the allocation they came from.
 * Below a 16KiB block that makes them interior slices of one block, which is
 * the shape the handover used to get wrong.
 */
static unsigned long split;
#define SPLIT_LEN 0x8000
#define HOLE_AT   0x1000               /* inside the first block, not on its edge */
#define PIECE_A   0x1000               /* [split, +0x1000) - one block's worth */
#define PIECE_B_AT 0x2000
#define PIECE_B   0x6000               /* [split+0x2000, +0x6000) - spans two */
static unsigned long readback;

/* Everything a descendant must still be able to see. Taken as a function
 * because it has to be asked at every generation, not just the first: the
 * handover a child gets is built out of memory that child is itself only
 * borrowing, and the level that breaks is the second one. */
static int
verify_inherited(const char *who)
{
  int bad = 0;
  static const char *names[NREG] = {"region 0","region 1","region 2",
                                    "region 3","region 4","region 5"};
  (void) who;
  for (int i = 0; i < NREG; i++)
    bad += check(names[i], regs[i], sizes[i]);
  bad += check("the break", brk_base, brk_len);
  bad += check("the file-backed mapping", filemap, FILEMAP_LEN);
  bad += check("the piece before the hole", split, PIECE_A);
  bad += check("the piece after the hole", split + PIECE_B_AT, PIECE_B);
  {
    unsigned long cbrk = (unsigned long) sys6(SYS_brk, 0, 0,0,0,0,0);
    if (cbrk != brk_base + brk_len) {
      put("  FAIL the break is "); puth(cbrk);
      put(", the parent's was "); puth(brk_base + brk_len); put("\n");
      bad++;
    }
  }
  return bad;
}

/*
 * The bytes the guest wrote, read back through the kernel.
 *
 * Writing memory and reading it again proves only that the guest is consistent
 * with itself. It is the *kernel's* view that can differ: NABI reaches a
 * region through its own host pointer, and if that names a second private copy
 * of the same memory rather than the one stage 2 gave the guest, then the store
 * the guest made is not the store NABI reads. Both copies start out identical,
 * so nothing shows until someone writes - and then each side sees the other
 * frozen at the moment of the fork.
 *
 * A pipe is enough to ask: write(2) copies out of guest memory and read(2)
 * copies back in, so the bytes make the round trip through the same pointer the
 * kernel would use for any other syscall.
 */
static int
kernel_sees(const char *what, unsigned long base, unsigned long len)
{
  int fds[2];
  if (sys6(SYS_pipe2, (long) fds, 0, 0,0,0,0) < 0) {
    put("  FAIL pipe\n"); return 1;
  }
  int bad = 0;
  for (unsigned long done = 0; done < len; ) {
    unsigned long want = len - done > 0x1000 ? 0x1000 : len - done;
    long w = sys6(SYS_write, fds[1], (long)(base + done), (long) want, 0,0,0);
    if (w <= 0) { put("  FAIL write\n"); bad++; break; }
    long r = sys6(SYS_read, fds[0], (long)(readback + done), w, 0,0,0);
    if (r != w) { put("  FAIL read\n"); bad++; break; }
    done += (unsigned long) w;
  }
  for (unsigned long o = 0; o + 8 <= len; o += 8) {
    unsigned long mine = *(volatile unsigned long *)(base + o);
    unsigned long theirs = *(volatile unsigned long *)(readback + o);
    if (mine == theirs) continue;
    if (bad < 4) {
      put("  FAIL "); put(what); put(" at "); puth(base + o);
      put(": the guest wrote "); puth(mine);
      put(" but the kernel read "); puth(theirs);
      put(" - two copies of one page\n");
    }
    bad++;
  }
  sys6(SYS_close, fds[0], 0, 0, 0,0,0);
  sys6(SYS_close, fds[1], 0, 0, 0,0,0);
  return bad;
}

void start_c(unsigned long *sp);

void start_c(unsigned long *sp)
{
  (void) sp;

  for (int i = 0; i < NREG; i++) {
    long a = sys6(SYS_mmap, 0, (long) sizes[i], PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a >= -4096 && a < 0) { put("mmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    regs[i] = (unsigned long) a;
    fill(regs[i], sizes[i]);
  }

  /*
   * A private file-backed mapping, dirtied. This is where a real program keeps
   * the state that matters most across a fork: glibc's main_arena - every
   * bin, every fastbin pointer - lives in libc.so's data segment, which is
   * exactly this. Anonymous memory surviving the handover is not enough if the
   * pages a library wrote to its own data do not.
   */
  {
    long fd = sys6(SYS_openat, AT_FDCWD, (long) "/forkmemtest", O_RDONLY, 0, 0, 0);
    if (fd < 0) { put("open failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    long a = sys6(SYS_mmap, 0, FILEMAP_LEN, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE, fd, 0);
    if (a >= -4096 && a < 0) { put("file mmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    filemap = (unsigned long) a;
    fill(filemap, FILEMAP_LEN);
  }

  {
    long a = sys6(SYS_mmap, 0, SPLIT_LEN, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a >= -4096 && a < 0) { put("split mmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    split = (unsigned long) a;
    sys6(SYS_munmap, (long)(split + HOLE_AT), 0x1000, 0, 0, 0, 0);
    fill(split, PIECE_A);
    fill(split + PIECE_B_AT, PIECE_B);

    long r = sys6(SYS_mmap, 0, 0x8000, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r >= -4096 && r < 0) { put("readback mmap failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    readback = (unsigned long) r;
  }

  /* And the break, which is where a libc's main arena actually lives. */
  brk_base = (unsigned long) sys6(SYS_brk, 0, 0,0,0,0,0);
  brk_len = 0x5000;
  if ((unsigned long) sys6(SYS_brk, (long)(brk_base + brk_len), 0,0,0,0,0)
      < brk_base + brk_len) {
    put("brk failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0);
  }
  fill(brk_base, brk_len);

  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid < 0) { put("clone failed\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }

  if (pid == 0) {
    int bad = verify_inherited("the child");

    /*
     * Then fork again, and ask the same of the grandchild. This is the
     * generation that matters: the first child is built from a parent that
     * started normally, the second from a parent that was itself rebuilt, and
     * a shell reaches it constantly - `x=$(y=$(cmd))`, or any subshell that
     * runs a command.
     */
    long gpid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (gpid < 0) { put("  FAIL second clone\n"); bad++; }
    else if (gpid == 0) {
      int gbad = verify_inherited("the grandchild");
      /*
       * Then write, and ask the kernel what it sees. This is the generation and
       * the shape that used to fail: a resumed process forking again, with
       * regions that are 4KiB slices of one 16KiB arena block.
       */
      fill_alt(split, PIECE_A);
      fill_alt(split + PIECE_B_AT, PIECE_B);
      gbad += kernel_sees("the piece before the hole", split, PIECE_A);
      gbad += kernel_sees("the piece after the hole", split + PIECE_B_AT, PIECE_B);
      if (gbad) { put("  ("); putd(gbad); put(" wrong in the grandchild)\n"); }
      sys6(SYS_exit_group, gbad ? 1 : 0, 0,0,0,0,0);
    } else {
      int gst = 0;
      sys6(SYS_wait4, gpid, (long) &gst, 0, 0, 0, 0);
      if ((gst >> 8) & 0xff) bad++;
      /* And the child's own memory must have survived being forked from. */
      bad += verify_inherited("the child after forking");
    }

    /*
     * Then allocate, and look again. A child that is handed memory correctly
     * can still be handed an *allocator* that thinks those pages are free, and
     * the second mapping lands on top of the first. Nothing about the first
     * check would catch that.
     */
    for (int i = 0; i < NREG; i++) {
      long a = sys6(SYS_mmap, 0, (long) sizes[i], PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (a >= -4096 && a < 0) { put("  FAIL child mmap\n"); bad++; continue; }
      fill((unsigned long) a, sizes[i]);
    }
    unsigned long cb = (unsigned long) sys6(SYS_brk, 0, 0,0,0,0,0);
    sys6(SYS_brk, (long)(cb + 0x9000), 0,0,0,0,0);
    fill(cb, 0x9000);

    for (int i = 0; i < NREG; i++)
      bad += check("region after the child allocated", regs[i], sizes[i]);
    bad += check("the break after the child allocated", brk_base, brk_len);
    bad += check("the file-backed mapping after the child allocated",
                 filemap, FILEMAP_LEN);

    if (bad) { put("  ("); putd(bad); put(" words wrong in the child)\n"); }
    sys6(SYS_exit_group, bad ? 1 : 0, 0,0,0,0,0);
  }

  int status = 0;
  sys6(SYS_wait4, pid, (long) &status, 0, 0, 0, 0);
  int code = (status >> 8) & 0xff;

  /* The parent's own memory has to be intact too - a handover that reached back
   * into it would be just as wrong, and only the parent can see that. */
  int pbad = 0;
  for (int i = 0; i < NREG; i++) pbad += check("the parent's region", regs[i], sizes[i]);
  pbad += check("the parent's break", brk_base, brk_len);
  pbad += check("the parent's file-backed mapping", filemap, FILEMAP_LEN);

  put(code == 0 && pbad == 0 ? "forkmem ok\n" : "forkmem failed\n");
  sys6(SYS_exit_group, (code || pbad) ? 1 : 0, 0,0,0,0,0);
}
