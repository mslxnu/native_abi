/* freestanding: prctl(PR_GET_NAME) reads back what PR_SET_NAME wrote.
 *
 * PR_SET_NAME was implemented and PR_GET_NAME was not - it fell through to the
 * default and came back EINVAL with "unkown prctl cmd: 16" in the log, so a
 * thread could name itself and then never be told its own name.
 *
 * The name has three readers that must give one answer: the getter, the
 * process's /proc/self/comm, and the thread's /proc/self/task/<tid>/comm. Only
 * one of them used to be right - comm was built from the executable's basename
 * and ignored the rename entirely - so all three are checked against the same
 * string here. Checked twice over, because a getter that returns a stale name
 * looks correct against a single set.
 *
 * And an unwritable buffer must be EFAULT rather than a fault in the guest.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_openat 56
#define SYS_prctl 167
#define SYS_gettid 178
#define SYS_exit 93
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define EFAULT 14

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int fails;
static void bad(const char *what,const char *got){
  fails++; put("  FAIL "); put(what); put(": \""); put(got); put("\"\n");
}

static int same(const char*a,const char*b){
  int i=0;
  while (a[i] && a[i]==b[i])
    i++;
  return a[i]==b[i];
}
static void cat3(char *out,int cap,const char*a,const char*b,const char*c){
  int i=0;
  for(int j=0;a[j]&&i<cap-1;j++) out[i++]=a[j];
  for(int j=0;b[j]&&i<cap-1;j++) out[i++]=b[j];
  for(int j=0;c[j]&&i<cap-1;j++) out[i++]=c[j];
  out[i]=0;
}
static void dec(char *out,long v){
  char t[24]; int n=0;
  if(!v) t[n++]='0';
  while(v){ t[n++]='0'+(int)(v%10); v/=10; }
  int i=0; while(n) out[i++]=t[--n];
  out[i]=0;
}

/* A whole file with its trailing newline stripped, which is how comm carries it. */
static int slurp_line(const char *path,char *buf,int cap){
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return -1;
  long n = sys6(SYS_read, fd, (long)buf, cap-1, 0, 0, 0);
  sys6(SYS_close, fd, 0,0,0,0,0);
  if (n < 0) return -1;
  while (n > 0 && (buf[n-1]=='\n' || buf[n-1]=='\r')) n--;
  buf[n] = 0;
  return (int) n;
}

/* Set the name, then demand it back from all three readers. */
static void check(const char *want, const char *tidpath)
{
  char got[64], path[128];

  long r = sys6(SYS_prctl, PR_SET_NAME, (long)want, 0, 0, 0, 0);
  if (r != 0) { char n[24]; dec(n, r); bad("PR_SET_NAME refused", n); return; }

  for (int i = 0; i < (int)sizeof got; i++) got[i] = 0x7f;
  r = sys6(SYS_prctl, PR_GET_NAME, (long)got, 0, 0, 0, 0);
  if (r != 0) { char n[24]; dec(n, r); bad("PR_GET_NAME refused", n); return; }
  /* Linux writes all sixteen bytes and terminates inside them; byte fifteen is
   * the one a caller treating the buffer as a string depends on. */
  if (got[15] != 0) bad("PR_GET_NAME left byte 15 unterminated", want);
  if (!same(got, want)) bad("PR_GET_NAME disagrees with PR_SET_NAME", got);

  if (slurp_line("/proc/self/comm", got, sizeof got) < 0)
    bad("/proc/self/comm will not open", want);
  else if (!same(got, want))
    bad("/proc/self/comm disagrees", got);

  cat3(path, sizeof path, "/proc/self/task/", tidpath, "/comm");
  if (slurp_line(path, got, sizeof got) < 0)
    bad("task comm will not open", path);
  else if (!same(got, want))
    bad("task comm disagrees", got);
}

void _start(void)
{
  char tid[24];
  dec(tid, sys6(SYS_gettid, 0,0,0,0,0,0));

  check("namedthread", tid);
  /* Again, so a getter answering from a stale copy has somewhere to be wrong.
   * Fifteen characters, which is the longest name that survives whole. */
  check("abcdefghijklmno", tid);

  /* An address with nothing mapped at it is EFAULT, not a fault. */
  long f = sys6(SYS_prctl, PR_GET_NAME, 0, 0, 0, 0, 0);
  if (f != -EFAULT) { char n[24]; dec(n, f); bad("PR_GET_NAME null buffer", n); }

  if (fails) { put("prctlname FAIL\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
  put("prctlname ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
