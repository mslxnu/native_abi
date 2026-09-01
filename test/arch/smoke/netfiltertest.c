/* freestanding: netfilter's tables, as far as iptables can tell.
 *
 * iptables does not reach the kernel through netlink. It opens a raw socket and
 * reads and writes whole tables through four socket options, and libiptc walks
 * the entry blob by the offsets written inside it - so a structure a few bytes
 * out is not a wrong answer, it is a parse that runs off the end.
 *
 * Nothing here filters a packet; there is no path through nabi for a packet to
 * be filtered on. What it provides is the conversation, and the conversation is
 * what Android needs. netd keeps a persistent iptables-restore child and
 * streams rule batches to it; with no table to talk to, iptables-restore says
 * "unable to initialize table 'filter'" and exits, netd's next write to it is
 * EPIPE and SIGPIPE, and netd dies. init answers a dead netd by restarting
 * zygote, and zygote's onrestart by killing surfaceflinger, audioserver,
 * cameraserver and media - so the boot spends itself restarting, several times
 * a minute, and adb goes from a working shell to "device offline" from the load.
 *
 * Every size and offset below is written out as a number rather than taken from
 * a struct, because the numbers are the thing being checked: they are Linux's,
 * on aarch64, and a layout that drifted from them would agree with itself and
 * with nothing else.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;}
#define SYS_write 64
#define SYS_socket 198
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_close 57
#define SYS_exit_group 94

#define AF_INET 2
#define AF_INET6 10
#define SOCK_RAW 3
#define IPPROTO_RAW 255
#define IPPROTO_IP 0
#define IPPROTO_IPV6 41

#define SO_SET_REPLACE       64
#define SO_SET_ADD_COUNTERS  65
#define SO_GET_INFO          64
#define SO_GET_ENTRIES       65
/* The revision probes are the two option numbers that differ by family: IPv4
 * asks at BASE+2 and BASE+3, IPv6 at BASE+4 and BASE+5. Answering ENOPROTOOPT
 * is not a refusal iptables reports - it uses an older revision instead, which
 * has fewer options, so netd's `-j MARK --or-mark` came back as
 * `unknown option "--or-mark"` with nothing to say where it came from. */
#define V4_REVISION_MATCH  66
#define V4_REVISION_TARGET 67
#define V6_REVISION_MATCH  68
#define V6_REVISION_TARGET 69

#define ENOENT 2
#define ENOPROTOOPT 92

/* Linux/aarch64, and the reason this test exists. */
#define V4_ENTRY  112
#define V6_ENTRY  168
#define STD_TGT    40
#define ERR_TGT    64
/* struct ipt_getinfo */
#define GI_VALID   32
#define GI_HOOK    36
#define GI_UNDER   56
#define GI_NUM     76
#define GI_SIZE    80
#define GI_LEN     84
/* struct ipt_get_entries. 40, not 36: it ends in a
 * "struct ipt_entry entrytable[0]", and an entry is eight-byte aligned because
 * it ends in two 64-bit counters, so the header is padded. Writing the blob at
 * 36 puts every offset in the table four bytes from where libiptc reads it,
 * and libiptc walks the blob by those offsets - it reads the first entry, fails
 * to recognise it as anything an entry can be, and aborts with "0 not a valid
 * target)". */
#define GE_SIZE    32
#define GE_LEN     40
/* struct ipt_replace */
#define RP_VALID   32
#define RP_NUM     36
#define RP_SIZE    40
#define RP_HOOK    44
#define RP_UNDER   64
#define RP_NCTR    84
#define RP_CTRS    88
#define RP_LEN     96
/* inside an entry */
#define E_TARGET_OFF 88
#define E_NEXT_OFF   90
#define E6_TARGET_OFF 140
#define E6_NEXT_OFF   142

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
static void setname(unsigned char *p, const char *n){
  int i = 0; while (n[i]) { p[i] = (unsigned char) n[i]; i++; }
  p[i] = 0;
}
static int nameis(const unsigned char *p, const char *n){
  int i = 0; while (n[i]) { if (p[i] != (unsigned char) n[i]) return 0; i++; }
  return p[i] == 0;
}
static unsigned u32at(const unsigned char *p, long off){
  unsigned v; const unsigned char *s = p + off;
  v = (unsigned) s[0] | ((unsigned) s[1] << 8) | ((unsigned) s[2] << 16) | ((unsigned) s[3] << 24);
  return v;
}
static unsigned u16at(const unsigned char *p, long off){
  const unsigned char *s = p + off;
  return (unsigned) s[0] | ((unsigned) s[1] << 8);
}

static unsigned char info[GI_LEN];
static unsigned char ents[4096];
static unsigned char rep[4096];

/*
 * One family's filter table, read and written back.
 *
 * entry is the size of that family's entry header, which is the only thing
 * that differs between them - the targets and the table structures are shared.
 */
static void
check_family(const char *what, int family, int level, long entry,
             int rev_match, int rev_target)
{
  int fd = (int) sys6(SYS_socket, family, SOCK_RAW, IPPROTO_RAW, 0,0,0);
  put(what); put(":\n");
  want("  raw socket for the tables", fd >= 0, 1);
  if (fd < 0) return;

  /* Three built-in chains, each an empty chain with a policy, and the error
   * entry that ends the table. */
  long want_size = 3 * (entry + STD_TGT) + (entry + ERR_TGT);

  mzero(info, sizeof info);
  setname(info, "filter");
  unsigned len = GI_LEN;
  long r = sys6(SYS_getsockopt, fd, level, SO_GET_INFO, (long) info, (long) &len, 0);
  want("  GET_INFO on filter", r, 0);
  want("  valid_hooks (INPUT|FORWARD|OUTPUT)", u32at(info, GI_VALID), 0x0e);
  want("  num_entries", u32at(info, GI_NUM), 4);
  want("  table size", u32at(info, GI_SIZE), want_size);
  want("  hook_entry[INPUT]", u32at(info, GI_HOOK + 4), 0);
  want("  hook_entry[FORWARD]", u32at(info, GI_HOOK + 8), entry + STD_TGT);
  want("  hook_entry[OUTPUT]", u32at(info, GI_HOOK + 12), 2 * (entry + STD_TGT));
  /* An empty chain's first rule and its policy are the same entry. */
  want("  underflow[INPUT] is the policy", u32at(info, GI_UNDER + 4), 0);

  unsigned size = u32at(info, GI_SIZE);
  mzero(ents, sizeof ents);
  setname(ents, "filter");
  ents[GE_SIZE] = (unsigned char)(size & 0xff);
  ents[GE_SIZE+1] = (unsigned char)((size >> 8) & 0xff);
  len = (unsigned)(GE_LEN + size);
  r = sys6(SYS_getsockopt, fd, level, SO_GET_ENTRIES, (long) ents, (long) &len, 0);
  want("  GET_ENTRIES", r, 0);

  const unsigned char *e = ents + GE_LEN;
  long toff = family == AF_INET6 ? E6_TARGET_OFF : E_TARGET_OFF;
  long noff = family == AF_INET6 ? E6_NEXT_OFF : E_NEXT_OFF;

  want("  first entry target_offset", u16at(e, toff), entry);
  want("  first entry next_offset", u16at(e, noff), entry + STD_TGT);
  want("  its target is a standard target", u16at(e + entry, 0), STD_TGT);
  want("  with no name, which is what standard means", e[entry + 2], 0);
  /* -NF_ACCEPT - 1, which is how a policy of ACCEPT is written. */
  want("  and a verdict of ACCEPT", (int) u32at(e + entry, 32), -2);

  const unsigned char *last = ents + GE_LEN + 3 * (entry + STD_TGT);
  want("  last entry next_offset", u16at(last, noff), entry + ERR_TGT);
  want("  last entry is an error target", u16at(last + entry, 0), ERR_TGT);
  want("  named ERROR", nameis(last + entry + 2, "ERROR"), 1);
  want("  with errorname ERROR", nameis(last + entry + 32, "ERROR"), 1);

  /* Write the table back, which is what iptables-restore does to commit. */
  mzero(rep, sizeof rep);
  setname(rep, "filter");
  for (long i = 0; i < 4; i++) {
    rep[RP_VALID + i] = info[GI_VALID + i];
    rep[RP_NUM + i]   = info[GI_NUM + i];
    rep[RP_SIZE + i]  = info[GI_SIZE + i];
  }
  for (long i = 0; i < 20; i++) {
    rep[RP_HOOK + i]  = info[GI_HOOK + i];
    rep[RP_UNDER + i] = info[GI_UNDER + i];
  }
  for (unsigned i = 0; i < size; i++)
    rep[RP_LEN + i] = ents[GE_LEN + i];
  r = sys6(SYS_setsockopt, fd, level, SO_SET_REPLACE, (long) rep, RP_LEN + size, 0);
  want("  SET_REPLACE", r, 0);

  /* And it is still there afterwards. */
  mzero(info, sizeof info);
  setname(info, "filter");
  len = GI_LEN;
  r = sys6(SYS_getsockopt, fd, level, SO_GET_INFO, (long) info, (long) &len, 0);
  want("  GET_INFO after the replace", r, 0);
  want("  and the same size came back", u32at(info, GI_SIZE), want_size);

  /* Counters are accepted; nothing ever counts. */
  r = sys6(SYS_setsockopt, fd, level, SO_SET_ADD_COUNTERS, (long) rep, RP_LEN, 0);
  want("  SET_ADD_COUNTERS", r, 0);

  /* Every revision is understood, because no extension's data is ever read. */
  unsigned char rev[30];
  mzero(rev, sizeof rev);
  setname(rev, "standard");
  rev[29] = 1;
  len = sizeof rev;
  want("  GET_REVISION_TARGET",
       sys6(SYS_getsockopt, fd, level, rev_target, (long) rev, (long) &len, 0), 0);
  want("  GET_REVISION_MATCH",
       sys6(SYS_getsockopt, fd, level, rev_match, (long) rev, (long) &len, 0), 0);
  /* And the other family's numbers are not this family's. */
  want("  the other family's revision option is not ours",
       sys6(SYS_getsockopt, fd, level,
            family == AF_INET6 ? V4_REVISION_TARGET : V6_REVISION_TARGET,
            (long) rev, (long) &len, 0), -ENOPROTOOPT);

  /* A table no kernel has. */
  mzero(info, sizeof info);
  setname(info, "nosuchtable");
  len = GI_LEN;
  want("  GET_INFO on a table that does not exist",
       sys6(SYS_getsockopt, fd, level, SO_GET_INFO, (long) info, (long) &len, 0), -ENOENT);

  sys6(SYS_close, fd, 0,0,0,0,0);
}

void _start(void)
{
  check_family("IPv4", AF_INET, IPPROTO_IP, V4_ENTRY,
               V4_REVISION_MATCH, V4_REVISION_TARGET);
  check_family("IPv6", AF_INET6, IPPROTO_IPV6, V6_ENTRY,
               V6_REVISION_MATCH, V6_REVISION_TARGET);

  /* The other tables netd asks for, with the hooks each is built with. */
  int fd = (int) sys6(SYS_socket, AF_INET, SOCK_RAW, IPPROTO_RAW, 0,0,0);
  if (fd >= 0) {
    static const struct { const char *name; unsigned hooks; } t[] = {
      { "nat",    (1u<<0)|(1u<<1)|(1u<<3)|(1u<<4) },
      { "mangle", (1u<<0)|(1u<<1)|(1u<<2)|(1u<<3)|(1u<<4) },
      { "raw",    (1u<<0)|(1u<<3) },
    };
    for (unsigned i = 0; i < 3; i++) {
      mzero(info, sizeof info);
      setname(info, t[i].name);
      unsigned len = GI_LEN;
      want(t[i].name,
           sys6(SYS_getsockopt, fd, IPPROTO_IP, SO_GET_INFO, (long) info, (long) &len, 0), 0);
      want("  its valid_hooks", u32at(info, GI_VALID), t[i].hooks);
    }
    sys6(SYS_close, fd, 0,0,0,0,0);
  }

  put(fails == 0 ? "netfilter ok\n" : "netfilter failed\n");
  sys6(SYS_exit_group, fails ? 1 : 0, 0,0,0,0,0);
}
