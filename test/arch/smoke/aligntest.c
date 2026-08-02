/* freestanding: the stack is 16-byte aligned when the process starts.
 *
 * Both ABIs require it, and NABI's push() rounds to 8 - so the block of argv
 * and envp strings, whose length is whatever the caller happened to pass, left
 * the stack 8-aligned about half the time. Every push after it is a multiple of
 * 8, so the parity was decided by the length of the environment and never
 * recovered.
 *
 * Nothing faults. The guest runs for thousands of syscalls and then glibc says
 * "free(): invalid pointer" from somewhere with no connection to the stack,
 * because an allocator that assumes 16-byte alignment and gets 8 produces a
 * heap that is subtly wrong rather than obviously broken. It surfaced as sqv,
 * the OpenPGP verifier apt shells out to, aborting for some user names and not
 * others - the name travels in the environment, and the environment set the
 * alignment.
 *
 * Testing one environment would only catch it half the time, so this re-execs
 * itself sixteen times, adding a byte of environment each round. One of those
 * lengths is guaranteed to be the bad parity.
 */
#define ROUNDS 16

static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit 93
#define SYS_execve 221

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;if(v==0)b[i--]='0';
  while(v>0){b[i--]='0'+(v%10);v/=10;}put(b+i+1);}

static int streq_n(const char *a, const char *b, int n)
{
  for (int i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* The entry point has to see SP exactly as the kernel left it, so it does
 * nothing but hand SP to C. A normal function would adjust SP in its prologue
 * first and measure its own frame instead. */
__attribute__((naked, used)) void _start(void)
{
  asm volatile("mov x0, sp\n\t" "b start_c");
}

void start_c(unsigned long sp);

void start_c(unsigned long sp)
{
  if (sp % 16 != 0) {
    put("align FAIL: entry sp is not 16-byte aligned, sp%16 = ");
    putd((long) (sp % 16));
    put("\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  /* Walk the block the kernel laid down: argc, argv[], NULL, envp[], NULL. */
  long argc = *(long *) sp;
  char **argv = (char **) (sp + 8);
  char **envp = argv + argc + 1;

  if (argc < 1 || argv[0] == 0) {
    put("align FAIL: argv is not well formed\n");
    sys6(SYS_exit, 1, 0,0,0,0,0);
  }

  /* How many rounds so far, counted by the length of our own marker. */
  int pad = -1;
  for (char **e = envp; *e; ++e) {
    if (streq_n(*e, "ALIGNPAD=", 9)) {
      pad = 0;
      for (const char *p = *e + 9; *p; p++)
        pad++;
      break;
    }
  }

  if (pad >= ROUNDS) {
    put("align ok\n");
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }

  /* One more byte of environment, then start again. Each round shifts the
   * string block by one, so the sixteen of them cover every alignment. */
  static char marker[9 + ROUNDS + 1];
  static char *newenv[2];
  int n = 0;
  for (const char *s = "ALIGNPAD="; *s; s++)
    marker[n++] = *s;
  for (int i = 0; i <= pad; i++)      /* pad == -1 on the first round */
    marker[n++] = 'A';
  marker[n] = '\0';
  newenv[0] = marker;
  newenv[1] = 0;

  sys6(SYS_execve, (long) argv[0], (long) argv, (long) newenv, 0, 0, 0);

  put("align FAIL: execve of ");
  put(argv[0]);
  put(" failed\n");
  sys6(SYS_exit, 1, 0,0,0,0,0);
}
