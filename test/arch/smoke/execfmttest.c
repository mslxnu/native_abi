/* freestanding: execve of something that cannot be run leaves the caller alive.
 *
 * execve has a point of no return: past it the old program is gone and there is
 * no caller left to give an error to. Linux puts that point *after* the format
 * has been accepted, which is why a binary the kernel cannot run comes back as
 * ENOEXEC and the process carries on. nabi tore the address space down first
 * and looked at the file afterwards, so ENOEXEC returned into a process with no
 * program: the caller took SIGSEGV instead of an error.
 *
 * Android's init exec_starts /vendor/bin/boringssl_self_test32, an EM_ARM ELF32
 * that Apple Silicon cannot execute a single instruction of. The service died
 * of a segmentation fault where it should have failed to start - and a
 * segmentation fault says nothing about why.
 *
 * What is checked, for each kind of file nothing here can run:
 *
 *   - execve returns ENOEXEC rather than killing the caller,
 *   - and the caller is still running afterwards, which is the half that was
 *     broken. Proved by doing more work after each attempt and reporting at the
 *     end: a process that died on the first one never gets here to say so.
 *
 * The kinds: an ELF for another machine, a 32-bit ELF, a file too short to hold
 * an ELF header, and a file that is not an executable at all.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_close 57
#define SYS_openat 56
#define SYS_unlinkat 35
#define SYS_execve 221
#define SYS_getpid 172
#define SYS_exit_group 94
#define AT_FDCWD (-100)
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define ENOEXEC 8

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

/* Write a file and make it executable. */
static int put_file(const char *path, const unsigned char *body, int n)
{
  int fd = (int) sys6(SYS_openat, AT_FDCWD, (long) path,
                      O_WRONLY | O_CREAT | O_TRUNC, 0755, 0, 0);
  if (fd < 0)
    return fd;
  long w = sys6(SYS_write, fd, (long) body, n, 0,0,0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  return w == n ? 0 : -1;
}

/* An ELF64 header, with the machine and class left to the caller. */
static void elf_header(unsigned char *h, int cls, unsigned short machine)
{
  for (int i = 0; i < 64; i++)
    h[i] = 0;
  h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
  h[4] = (unsigned char) cls;    /* EI_CLASS: 1 = 32-bit, 2 = 64-bit */
  h[5] = 1;                      /* little-endian */
  h[6] = 1;                      /* version */
  h[16] = 2;                     /* e_type = ET_EXEC */
  h[18] = (unsigned char) (machine & 0xff);
  h[19] = (unsigned char) (machine >> 8);
  h[20] = 1;                     /* e_version */
}

/* Try to exec it, and say what came back. */
static long try_exec(const char *path)
{
  char *argv[2]; char *envp[1];
  argv[0] = (char *) path; argv[1] = 0; envp[0] = 0;
  return sys6(SYS_execve, (long) path, (long) argv, (long) envp, 0, 0, 0);
}

void _start(void)
{
  unsigned char h[64];
  long before = sys6(SYS_getpid, 0,0,0,0,0,0);

  /* An ELF64 for a machine that does not exist. */
  elf_header(h, 2, 0xfffe);
  want("write the alien-machine ELF", put_file("/badmachine", h, 64), 0);
  want("execve an ELF for another machine", try_exec("/badmachine"), -ENOEXEC);
  want("still alive after it", sys6(SYS_getpid, 0,0,0,0,0,0), before);

  /* A 32-bit ELF, which is what Android's boringssl_self_test32 is. */
  elf_header(h, 1, 0x28 /* EM_ARM */);
  want("write the 32-bit ELF", put_file("/badclass", h, 64), 0);
  want("execve a 32-bit ELF", try_exec("/badclass"), -ENOEXEC);
  want("still alive after it", sys6(SYS_getpid, 0,0,0,0,0,0), before);

  /* ELF magic, but too short to hold a header. */
  elf_header(h, 2, 0xfffe);
  want("write the stub", put_file("/shortelf", h, 8), 0);
  want("execve a truncated ELF", try_exec("/shortelf"), -ENOEXEC);
  want("still alive after it", sys6(SYS_getpid, 0,0,0,0,0,0), before);

  /* Not an executable at all. */
  want("write the plain file",
       put_file("/notelf", (const unsigned char *) "hello, world\n", 13), 0);
  want("execve a plain file", try_exec("/notelf"), -ENOEXEC);
  want("still alive after it", sys6(SYS_getpid, 0,0,0,0,0,0), before);

  sys6(SYS_unlinkat, AT_FDCWD, (long) "/badmachine", 0, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/badclass", 0, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/shortelf", 0, 0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/notelf", 0, 0,0,0);

  put(fails == 0 ? "execfmt ok\n" : "execfmt failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
