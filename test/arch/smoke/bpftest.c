/* freestanding: bpf(2), for the one thing iptables asks it.
 *
 * There is no eBPF in nabi and no prospect of one: nothing runs a program in a
 * kernel context, and no packet passes through a place a filter could be
 * attached to. Every command here answers ENOSYS, deliberately - a caller told
 * otherwise would attach a probe that never fires.
 *
 * BPF_OBJ_GET is the exception, and it is an exception about descriptors rather
 * than about programs. iptables looks a pinned object up, keeps the descriptor
 * in the rule's match data, and hands the rule to IPT_SO_SET_REPLACE, which
 * stores it as an opaque blob. Nobody dereferences it on either side, so an
 * inert descriptor carries the rule as well as a real one would.
 *
 * Answering ENOSYS instead is what the boot used to do, and iptables answers
 * that by failing the rule: `bpf: failed to get bpf object`. That fails the
 * batch, which ends iptables-restore - netd's persistent child - so netd's next
 * write is EPIPE and SIGPIPE, init answers a dead netd by restarting zygote,
 * and zygote's onrestart kills surfaceflinger, audioserver, cameraserver and
 * media. Measured over one boot, 46 of 48 iptables-restore children died on
 * this and none died on anything else.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_read 63
#define SYS_close 57
#define SYS_bpf 280
#define SYS_exit_group 94

#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD  5
#define BPF_OBJ_PIN    6
#define BPF_OBJ_GET    7

#define ENOENT 2
#define EINVAL 22
#define ENOSYS 38

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) return;
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}
static void mzero(void*p,long n){unsigned char*q=p;while(n--)*q++=0;}

/* The anonymous struct the BPF_OBJ_* commands use, at the head of the union
 * every bpf command shares. iptables sends exactly these sixteen bytes. */
struct bpf_obj_attr {
  unsigned long pathname;
  unsigned int  bpf_fd;
  unsigned int  file_flags;
};

static char pinned[] = "/sys/fs/bpf/netd_shared/prog_netd_skfilter_ingress_xtbpf";
static char elsewhere[] = "/data/local/tmp/notapin";
static char buf[8];

static long obj_get(char *path, unsigned int size)
{
  struct bpf_obj_attr attr;
  mzero(&attr, sizeof attr);
  attr.pathname = (unsigned long) path;
  return sys6(SYS_bpf, BPF_OBJ_GET, (long) &attr, size, 0, 0, 0);
}

void _start(void)
{
  /* A pinned object under the bpf filesystem is a descriptor. */
  long fd = obj_get(pinned, sizeof(struct bpf_obj_attr));
  want("BPF_OBJ_GET on a pinned path returns a descriptor", fd >= 0, 1);

  if (fd >= 0) {
    /*
     * Readable and empty, so anything treating it as a file rather than as a
     * token gets an empty one rather than an error.
     */
    want("and the descriptor reads as empty",
         sys6(SYS_read, fd, (long) buf, sizeof buf, 0,0,0), 0);
    want("and closes", sys6(SYS_close, fd, 0,0,0,0,0), 0);
  }

  /* Two of them are two descriptors, since iptables holds one per rule. */
  long a = obj_get(pinned, sizeof(struct bpf_obj_attr));
  long b = obj_get(pinned, sizeof(struct bpf_obj_attr));
  want("a second lookup is a second descriptor", a >= 0 && b >= 0 && a != b, 1);
  if (a >= 0) sys6(SYS_close, a, 0,0,0,0,0);
  if (b >= 0) sys6(SYS_close, b, 0,0,0,0,0);

  /* libbpf sends the whole union rather than the sixteen bytes it needs. */
  long big = obj_get(pinned, 0x90);
  want("a caller sending the whole union is served too", big >= 0, 1);
  if (big >= 0) sys6(SYS_close, big, 0,0,0,0,0);

  /* Somewhere a pin cannot be. */
  want("a path outside the bpf filesystem", obj_get(elsewhere, sizeof(struct bpf_obj_attr)),
       -ENOENT);

  /* Too small to hold the pathname it claims to carry. */
  want("an attr too small", obj_get(pinned, 4), -EINVAL);

  /*
   * And everything else stays unimplemented. netd's TrafficController decides
   * at startup what it can do, and it decides that with these failing; making
   * them appear to work moves it onto a path that then needs maps to hold real
   * counters, which nabi has nowhere to keep.
   */
  struct bpf_obj_attr attr;
  mzero(&attr, sizeof attr);
  want("BPF_MAP_CREATE", sys6(SYS_bpf, BPF_MAP_CREATE, (long) &attr, 0x90, 0,0,0), -ENOSYS);
  want("BPF_PROG_LOAD",  sys6(SYS_bpf, BPF_PROG_LOAD,  (long) &attr, 0x90, 0,0,0), -ENOSYS);
  want("BPF_OBJ_PIN",    sys6(SYS_bpf, BPF_OBJ_PIN,    (long) &attr, 0x90, 0,0,0), -ENOSYS);

  put(fails == 0 ? "bpf ok\n" : "bpf failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
