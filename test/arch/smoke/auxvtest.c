/* freestanding: the auxiliary vector a process starts with.
 *
 * What is in the auxv is not only a question of what a program might find
 * useful, because of how it is read. getauxval() sets errno to ENOENT for an
 * entry that is absent, and callers do not all treat that as "no answer":
 * GLib's g_check_setuid() asks for AT_SECURE and calls g_error() if errno is
 * set, which aborts. So a missing entry is not a feature a program does
 * without, it is a program that dies.
 *
 * That is not hypothetical. Without AT_SECURE, dconf's RPM scriptlet ended in a
 * trap during a Fedora install - "GLib-ERROR: getauxval () failed" - and with it
 * every other GLib program.
 *
 * This walks the vector off its own stack rather than calling getauxval, which
 * is the point: it checks what NABI actually put there, with no libc in between
 * to paper over a gap.
 */
#define AT_NULL    0
#define AT_PHDR    3
#define AT_PHENT   4
#define AT_PHNUM   5
#define AT_PAGESZ  6
#define AT_BASE    7
#define AT_ENTRY   9
#define AT_UID    11
#define AT_EUID   12
#define AT_GID    13
#define AT_EGID   14
#define AT_HWCAP  16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_PLATFORM 15
#define AT_EXECFN   31

#define SYS_write 64
#define SYS_exit  93

static long sys3(long n, long a, long b, long c){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a;
  register long x1 asm("x1")=b; register long x2 asm("x2")=c;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2):"memory"); return x0;
}
static void put(const char*m){int i=0;while(m[i])i++;sys3(SYS_write, 1, (long)m, i);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("auxv FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys3(SYS_exit, 1, 0, 0); }

/* The whole vector, as found on the stack. */
static unsigned long seen[64], val[64];
static int nseen;

static int
have(unsigned long type, unsigned long *out)
{
  for (int i = 0; i < nseen; i++)
    if (seen[i] == type) {
      if (out) *out = val[i];
      return 1;
    }
  return 0;
}

static void
must(const char *name, unsigned long type)
{
  if (!have(type, 0))
    fail(name, 0, (long) type);
}

void
start_c(unsigned long *sp)
{
  /* sp points at argc; then argv[], NULL, envp[], NULL, then the auxv. */
  long argc = (long) sp[0];
  unsigned long *p = sp + 1 + argc + 1;   /* past argv and its terminator */
  while (*p) p++;                          /* past envp */
  p++;

  for (; *p != AT_NULL && nseen < 64; p += 2) {
    seen[nseen] = p[0];
    val[nseen] = p[1];
    nseen++;
  }

  if (nseen == 0)
    fail("an auxiliary vector with anything in it", 0, 1);

  /*
   * AT_SECURE is the one this test exists for. It is absent on no Linux, and a
   * program that asks for it and finds it missing gets errno set - which GLib
   * turns into an abort.
   */
  must("AT_SECURE", AT_SECURE);
  { unsigned long v = 1;
    have(AT_SECURE, &v);
    /* Not a setuid exec, so this must say so - and it must say so with a value
     * rather than by being absent. */
    if (v != 0)
      fail("AT_SECURE for an exec that crossed no privilege boundary", (long) v, 0); }

  /* The rest Linux always supplies, each of which some program asks for. */
  must("AT_PHDR",   AT_PHDR);
  must("AT_PHENT",  AT_PHENT);
  must("AT_PHNUM",  AT_PHNUM);
  must("AT_PAGESZ", AT_PAGESZ);
  must("AT_ENTRY",  AT_ENTRY);
  must("AT_RANDOM", AT_RANDOM);
  must("AT_UID",    AT_UID);
  must("AT_EUID",   AT_EUID);
  must("AT_GID",    AT_GID);
  must("AT_EGID",   AT_EGID);
  must("AT_CLKTCK", AT_CLKTCK);
  must("AT_HWCAP",  AT_HWCAP);
  must("AT_HWCAP2", AT_HWCAP2);

  { unsigned long v = 0;
    have(AT_CLKTCK, &v);
    if (v != 100)
      fail("AT_CLKTCK, which sysconf(_SC_CLK_TCK) reports", (long) v, 100); }

  { unsigned long v = 0;
    have(AT_PAGESZ, &v);
    if (v == 0)
      fail("AT_PAGESZ", (long) v, 1); }

  /*
   * AT_RANDOM points at sixteen bytes glibc builds its stack canary and pointer
   * guard out of, so an unreadable pointer is a crash before main - and bytes
   * that are not random are a canary that can be guessed, which is worse than a
   * crash because nothing reports it.
   *
   * A single run cannot show that sixteen bytes are random. What it can show is
   * that they are not obviously *not*: all-zero is what an unwritten buffer
   * looks like when the stack beneath happened to be clean, and all-identical
   * covers the rest of that family. Whether they differ between runs is the
   * real question, and only something outside one run can ask it - see the
   * --random mode below, which run.sh uses for exactly that.
   */
  { unsigned long v = 0;
    have(AT_RANDOM, &v);
    if (v == 0)
      fail("AT_RANDOM's pointer", (long) v, 1);
    const unsigned char *r = (const unsigned char *) v;
    int zero = 1, same = 1;
    for (int i = 0; i < 16; i++) {
      if (r[i] != 0) zero = 0;
      if (r[i] != r[0]) same = 0;
    }
    if (zero)
      fail("AT_RANDOM's sixteen bytes, which are all zero", 0, 1);
    if (same)
      fail("AT_RANDOM's sixteen bytes, which are all the same", r[0], -1);

    /*
     * Dump them instead of the usual line when asked. run.sh runs this twice
     * and requires the two to differ, which is the only way to catch bytes that
     * are stable across execs - an uninitialised buffer reached by the same
     * code path every time looks perfectly random within any one run.
     */
    if (argc > 1) {
      const char *hex = "0123456789abcdef";
      char out[33];
      for (int i = 0; i < 16; i++) {
        out[i * 2] = hex[r[i] >> 4];
        out[i * 2 + 1] = hex[r[i] & 15];
      }
      out[32] = 0;
      put(out); put("\n");
      sys3(SYS_exit, 0, 0, 0);
    } }

  must("AT_EXECFN",  AT_EXECFN);
  must("AT_PLATFORM", AT_PLATFORM);

  /*
   * Both are pointers to strings, so being present is only half of it - a
   * pointer into memory the guest cannot read, or at a string that was never
   * written, passes a presence check and fails everything after it.
   */
  { unsigned long v = 0;
    have(AT_EXECFN, &v);
    if (v == 0)
      fail("AT_EXECFN's pointer", (long) v, 1);
    const char *fn = (const char *) v;
    /* The path execve was given, so it starts at the root and names this
     * program. argv[0] would do too here, which is why the check is that it is
     * a path rather than that it equals argv[0]. */
    if (fn[0] != '/')
      fail("AT_EXECFN, which should be the path execve was given", fn[0], '/');
    int n = 0;
    while (fn[n] && n < 256) n++;
    if (n == 0 || n >= 256)
      fail("the length of AT_EXECFN's string", n, 1); }

  { unsigned long v = 0;
    have(AT_PLATFORM, &v);
    if (v == 0)
      fail("AT_PLATFORM's pointer", (long) v, 1);
    const char *pl = (const char *) v;
    /* This binary is aarch64, so the platform it is told about must be. */
    const char *want = "aarch64";
    for (int i = 0; want[i] || pl[i]; i++)
      if (pl[i] != want[i])
        fail("AT_PLATFORM's string", pl[i], want[i]); }

  put("auxv ok\n");
  sys3(SYS_exit, 0, 0, 0);
}

/* The stack pointer as the kernel left it, before anything has touched it. */
__attribute__((naked)) void _start(void)
{
  asm volatile("mov x0, sp\n\t"
               "b start_c");
}
