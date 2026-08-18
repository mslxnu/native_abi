/* freestanding: unmapping part of a stage-2 block.
 *
 * Guest mappings are 4KiB-granular; the stage-2 blocks underneath them are
 * 16KiB, because that is all hv_vm_map will take. So a guest unmapping one
 * page splits a block: three of its pages must go on working and the fourth
 * must fault, and the block itself must stay mapped until the last page in it
 * has gone.
 *
 * This is the case that had no test, and it cost a whole session to find out.
 * Rounding every guest mapping up to 16KiB hid it - nothing could ever split a
 * block - and the entire suite passed while the memory model was wrong in a way
 * that made Android's linker and allocator corrupt themselves. When the
 * rounding was removed the suite still passed, and Android panicked on its
 * first partial unmap with a bare HV_ERROR out of hv_vm_map.
 *
 * What is checked:
 *
 *   - the survivors keep their contents. A block is re-established rather than
 *     released while anything still points into it, and re-establishing it must
 *     not disturb what it holds.
 *   - the unmapped page faults. It is the same 16KiB block as its neighbours,
 *     so the only thing making it fault is its own stage-1 descriptor being
 *     gone - and HVF's combined stage-1+2 TLB entries do not notice a guest
 *     TLBI, so a stale translation would leave freed memory reachable.
 *   - the survivors are still writable afterwards, since a flush that left the
 *     block read-only would be just as wrong and much quieter.
 *   - unmapping the rest releases the block without taking anything else with
 *     it, checked by mapping again afterwards and finding fresh zeroed memory.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_mmap   222
#define SYS_munmap 215
#define SYS_clone  220
#define SYS_wait4  260
#define PROT_RW      3
#define MAP_PRIVATE  2
#define MAP_ANON    32
#define SIGCHLD     17
#define PAGE      0x1000

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}

static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) { put("  ok  "); put(what); put("\n"); return; }
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

/* Touch an address in a child, so a fault costs a process and not the test.
 * Returns 1 if the access succeeded, 0 if it died. */
static int touchable(long addr, int write)
{
  long kid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (kid == 0) {
    if (write) *(volatile char *)addr = 'w';
    else       (void) *(volatile char *)addr;
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  int status = 0;
  sys6(SYS_wait4, kid, (long)&status, 0, 0, 0, 0);
  return (status & 0x7f) == 0;
}

void _start(void)
{
  /* One whole 16KiB block's worth, as four guest pages. */
  long a = sys6(SYS_mmap, 0, 4 * PAGE, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0);
  want("mmap four pages", a > 0, 1);
  for (int i = 0; i < 4; i++)
    *(volatile char *)(a + i * PAGE) = 'A' + i;

  /* Split the block: drop the second page only. */
  want("munmap one page in the middle",
       sys6(SYS_munmap, a + PAGE, PAGE, 0, 0, 0, 0), 0);

  want("page 0 survived",  *(volatile char *)(a + 0 * PAGE), 'A');
  want("page 2 survived",  *(volatile char *)(a + 2 * PAGE), 'C');
  want("page 3 survived",  *(volatile char *)(a + 3 * PAGE), 'D');

  want("the unmapped page faults", touchable(a + PAGE, 0), 0);
  want("a survivor is still readable", touchable(a + 2 * PAGE, 0), 1);
  want("a survivor is still writable", touchable(a + 2 * PAGE, 1), 1);

  /* Drop the rest: the block has no descriptors left and must be released. */
  want("munmap page 0", sys6(SYS_munmap, a, PAGE, 0, 0, 0, 0), 0);
  want("munmap pages 2-3", sys6(SYS_munmap, a + 2 * PAGE, 2 * PAGE, 0,0,0,0), 0);
  want("the whole range now faults", touchable(a + 2 * PAGE, 0), 0);

  /* And the space is reusable, with none of the old contents showing through. */
  long b = sys6(SYS_mmap, 0, 4 * PAGE, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0);
  want("mmap again", b > 0, 1);
  int clean = 1;
  for (int i = 0; i < 4; i++)
    if (*(volatile char *)(b + i * PAGE) != 0)
      clean = 0;
  want("the new mapping reads as zero", clean, 1);

  put(fails ? "splitblock FAILED\n" : "splitblock ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
