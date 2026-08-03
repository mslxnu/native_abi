/* freestanding: a mode that denies its own owner, and the setuid bit on it.
 *
 * Every distribution ships sudo as `---s--x--x`: executable by anyone, readable
 * by no one, set-user-ID root. Nothing about that works by itself here. NABI
 * performs every access as the ordinary host account that owns the tree, and
 * loading an ELF means *reading* it - so a mode with no owner read is a mode
 * nabi cannot open, however entitled the guest is to run it. Fedora's sudo
 * installed correctly and then answered "Permission denied".
 *
 * It cannot be fixed by relaxing the mode, because the mode is also what the
 * guest sees and what the permission checks are made of. So the guest's mode is
 * recorded beside the file the way its owner already was, and the host keeps
 * one nabi can work with. Three things have to hold at once, and this checks
 * all three because any two without the third is a plausible-looking hole:
 *
 *   - the guest still *sees* 4111, so `ls -l` and every check are unchanged;
 *   - the file can be executed, which is what the whole exercise is for;
 *   - the set-user-ID bit elevates, which needs the recorded mode rather than
 *     the host's - the host file deliberately does not carry that bit.
 *
 * run.sh sets the mode from the host side, so this also covers the repair path
 * for trees that already existed: nothing is recorded, the first open fails,
 * and the mode found there becomes the mode the guest sees.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_execve 221
#define SYS_newfstatat 79
#define SYS_fchmodat 53
#define SYS_setresuid 147
#define SYS_setresgid 149
#define AT_FDCWD -100

struct lstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long times[6]; unsigned pad3[2]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void puto(unsigned long v){char b[24];int i=23;b[i--]=0;
  if(v==0)b[i--]='0';while(v){b[i--]='0'+(v&7);v>>=3;}put("0");put(b+i+1);}
static void fail(const char *what, unsigned long v)
{
  put("suid FAIL: "); put(what); put(" "); puto(v); put("\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}

#define HELPER "/suidhelper"

void _start(void)
{
  struct lstat st;
  long r;

  /* What the guest sees has to be the mode that was set, not whatever the host
   * had to be given so that the file could be opened at all. */
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) HELPER, (long) &st, 0, 0, 0)) < 0)
    fail("stat of the helper returned", (unsigned long) -r);
  if ((st.mode & 07777) != 04111)
    fail("the guest sees a mode of", st.mode & 07777);

  /* Set it again from inside, which is the path a package manager takes -
   * rpm creates the file and chmods it - and must land in the same place. */
  if ((r = sys6(SYS_fchmodat, AT_FDCWD, (long) HELPER, 04111, 0, 0, 0)) < 0)
    fail("chmod 4111 from the guest returned", (unsigned long) -r);
  if ((r = sys6(SYS_newfstatat, AT_FDCWD, (long) HELPER, (long) &st, 0, 0, 0)) < 0)
    fail("stat after chmod returned", (unsigned long) -r);
  if ((st.mode & 07777) != 04111)
    fail("after chmod the guest sees", st.mode & 07777);

  /* Become an ordinary user. Only `other` has execute here, so this is a guest
   * that may run the file and may not read it - exactly sudo's case. */
  if ((r = sys6(SYS_setresgid, 1000, 1000, 1000, 0, 0, 0)) < 0)
    fail("setresgid returned", (unsigned long) -r);
  if ((r = sys6(SYS_setresuid, 1000, 1000, 1000, 0, 0, 0)) < 0)
    fail("setresuid returned", (unsigned long) -r);

  /* From here the helper speaks: it prints whether it was elevated. */
  static char *const argv[] = { (char *) HELPER, 0 };
  static char *const envp[] = { 0 };
  sys6(SYS_execve, (long) HELPER, (long) argv, (long) envp, 0, 0, 0);

  put("suid FAIL: could not execute a file the guest may execute\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}
