/* freestanding: execve with a null environment, and with a null argv.
 *
 * Linux reads nothing when argv or envp is NULL and starts the program with an
 * empty array. nabi read from guest address 0 and answered EFAULT, refusing
 * something the kernel allows.
 *
 * bionic's crash handler is the caller that showed it: having forked, the child
 * execs crash_dump64 with arguments and a *null environment*, and that exec came
 * back EFAULT - so the child never became the dumper, it stayed a copy of the
 * crashing process and exited, and Android produced no tombstone for anything.
 *
 * The exec'd program is this same binary, which looks at its own argc to say
 * which case ran. Checked by exit status rather than by output, since a program
 * started with no environment and no arguments has little else to say.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_exit_group 94
#define SYS_clone 220
#define SYS_execve 221
#define SYS_wait4 260

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(const char *t, long v)
{
  char b[40]; int i = 0; put(t); put("=");
  if (v < 0) { put("-"); v = -v; }
  char q[24]; int j = 0; if (!v) q[j++] = '0';
  while (v) { q[j++] = '0' + (char)(v % 10); v /= 10; }
  while (j) b[i++] = q[--j]; b[i++] = '\n'; b[i] = 0; put(b);
}

static const char self[] = "/execnullenvtest";
/* argv for the re-exec: the marker tells the child which case it is. */
static char a0[] = "execnullenvtest";
static char a1_env[] = "nullenv";
static char a1_argv[] = "nullargv";

static long run(long argvp, long envp)
{
  long pid = sys6(SYS_clone, 0, 0, 0, 0, 0, 0);
  if (pid == 0) {
    sys6(SYS_execve, (long) self, argvp, envp, 0, 0, 0);
    /* Only reached if the exec was refused. */
    sys6(SYS_exit_group, 99, 0, 0, 0, 0, 0);
  }
  long s = 0;
  sys6(SYS_wait4, pid, (long)&s, 0, 0, 0, 0);
  return (s >> 8) & 0xff;
}

void _start(void)
{
  /* _start has no argc here, so the marker is read from the stack: the kernel
   * puts argc at the stack pointer on entry. Read it before anything else. */
  long argc;
  asm volatile("ldr %0, [sp]" : "=r"(argc));

  if (argc == 0) {
    /* Re-exec'd with a null argv: nothing to say, just succeed distinctly. */
    sys6(SYS_exit_group, 44, 0, 0, 0, 0, 0);
  }
  if (argc == 2) {
    /* Re-exec'd with a null environment. */
    sys6(SYS_exit_group, 43, 0, 0, 0, 0, 0);
  }

  static char *argv_env[3];
  argv_env[0] = a0; argv_env[1] = a1_env; argv_env[2] = 0;
  long r = run((long) argv_env, 0);
  if (r != 43) { putd("null envp exec gave", r); put("FAIL\n");
                 sys6(SYS_exit_group, 1, 0,0,0,0,0); }

  /* And a null argv, which Linux also accepts - argc comes out zero. */
  r = run(0, 0);
  if (r != 44) { putd("null argv exec gave", r); put("FAIL\n");
                 sys6(SYS_exit_group, 1, 0,0,0,0,0); }

  (void) a1_argv;
  put("ok execnullenv\n");
  sys6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
}
