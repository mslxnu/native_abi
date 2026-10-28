/* freestanding: SOCK_SEQPACKET keeps its message boundaries through
 * bind/listen/accept.
 *
 * Darwin has no AF_UNIX SOCK_SEQPACKET at all - socket and socketpair both
 * answer "Protocol not supported" - so nabi builds one out of what Darwin has.
 * A socketpair becomes a datagram pair and keeps boundaries for free; a socket
 * that will be listened on cannot, because datagrams do not listen, so it
 * becomes a stream. A stream has no boundaries, and three messages written one
 * after another were read as one run of bytes.
 *
 * Android's logging is where that showed. logd writes each entry as one message
 * on /dev/socket/logdr, and logcat read three of them together and said
 * "Unexpected length" - the length in the first entry's header did not describe
 * what followed it - so the guest's log was unreadable even once logd was
 * storing it.
 *
 * Three messages of distinct lengths, read one at a time. The first read is
 * checked on its own and the test gives up there if it is wrong, because a lost
 * boundary means the second read has nothing coming and the test would hang
 * rather than fail.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write 64
#define SYS_read 63
#define SYS_exit_group 94
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept4 242
#define SYS_connect 203
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_sched_yield 124
#define SYS_unlinkat 35
#define AT_FDCWD -100
#define AF_UNIX 1
#define SOCK_SEQPACKET 5
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANON 0x20
#define CLONE_VM 0x100
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define STACK 65536
static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(const char*t,long v){char b[40];int i=0;put(t);put("=");if(v<0){put("-");v=-v;}
  char q[24];int j=0;if(!v)q[j++]='0';while(v){q[j++]='0'+(char)(v%10);v/=10;}
  while(j)b[i++]=q[--j];b[i++]='\n';b[i]=0;put(b);}
struct sa { unsigned short fam; char path[108]; };
static struct sa addr;
static volatile int ready = 0;
static char buf[256];
void _start(void)
{
  const char *p = "/tmp/nabi-seqbound.sock";
  addr.fam = AF_UNIX;
  for (int i = 0; p[i]; i++) addr.path[i] = p[i];
  sys6(SYS_unlinkat, AT_FDCWD, (long)p, 0, 0, 0, 0);
  long ls = sys6(SYS_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, 0);
  if (sys6(SYS_bind, ls, (long)&addr, 2+108, 0,0,0) != 0) { put("FAIL bind\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  if (sys6(SYS_listen, ls, 4, 0,0,0,0) != 0) { put("FAIL listen\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  long st = sys6(SYS_mmap, 0, STACK, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  long t = sys6(SYS_clone, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, st+STACK-512, 0, 0, 0, 0);
  if (t == 0) {
    long cs = sys6(SYS_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, 0);
    if (sys6(SYS_connect, cs, (long)&addr, 2+108, 0,0,0) != 0) { put("FAIL connect\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
    /* three messages of distinct lengths, written as three sends */
    sys6(SYS_write, cs, (long)"AAA", 3, 0, 0, 0);
    sys6(SYS_write, cs, (long)"BBBBBBB", 7, 0, 0, 0);
    sys6(SYS_write, cs, (long)"CC", 2, 0, 0, 0);
    ready = 1;
    for(;;) sys6(SYS_sched_yield,0,0,0,0,0,0);
  }
  long as = sys6(SYS_accept4, ls, 0, 0, 0, 0, 0);
  if (as < 0) { put("FAIL accept\n"); sys6(SYS_exit_group,1,0,0,0,0,0); }
  for (long i = 0; i < 500000 && !ready; i++) sys6(SYS_sched_yield,0,0,0,0,0,0);
  int want[3] = { 3, 7, 2 };
  for (int k = 0; k < 3; k++) {
    long n = sys6(SYS_read, as, (long)buf, sizeof buf, 0, 0, 0);
    putd("read", n);
    if (n != want[k]) {
      /* Stop here rather than read again: if this read swallowed the messages
       * that follow, the next one blocks for ever and a hang is a worse way to
       * report a wrong answer than a failure is. */
      sys6(SYS_unlinkat, AT_FDCWD, (long)p, 0, 0, 0, 0);
      put("FAIL a read did not return one whole message\n");
      sys6(SYS_exit_group, 1, 0,0,0,0,0);
    }
  }
  sys6(SYS_unlinkat, AT_FDCWD, (long)p, 0, 0, 0, 0);
  put("ok seqbound\n");
  sys6(SYS_exit_group, 0, 0,0,0,0,0);
}
