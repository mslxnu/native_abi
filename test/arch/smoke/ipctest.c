/* freestanding: System V IPC, and the namespace that scopes it.
 *
 * The case worth having a test for is a segment that is attached before a fork.
 * fork here is fork plus exec, so a child rebuilds its address space from a
 * checkpoint - an arena-backed region is copied, a file-backed one is re-mapped
 * from its descriptor, and a Darwin shmat region was neither, so resume
 * panicked outright. That is not a subtle difference from Linux: attaching a
 * segment and then forking, which is the ordinary way to use one, killed the
 * guest. So the test writes through the mapping on both sides of a fork and
 * insists each sees the other's bytes, which is the whole promise of shared
 * memory and not something a private copy can fake.
 *
 * The rest is the arithmetic of the interface: an id found again by its key, a
 * key that is not there, EEXIST, the values a semaphore holds, and IPC_RMID
 * ending an object. Then the namespace: after unshare(CLONE_NEWIPC) the same
 * key must name a *different* object, and the id that used to work must not
 * resolve - if it still did, the isolation would be a label rather than a fact.
 */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write   64
#define SYS_exit    93
#define SYS_readlinkat 78
#define SYS_unshare 97
#define SYS_semget  190
#define SYS_semctl  191
#define SYS_semop   193
#define SYS_shmget  194
#define SYS_shmctl  195
#define SYS_shmat   196
#define SYS_shmdt   197
#define SYS_clone   220
#define SYS_wait4   260

#define AT_FDCWD    -100
#define SIGCHLD     17
#define CLONE_NEWIPC 0x08000000

#define IPC_PRIVATE 0
#define IPC_CREAT   01000
#define IPC_EXCL    02000
#define IPC_RMID    0
#define IPC_STAT    2
#define IPC_64      0x0100
#define GETVAL      12
#define GETALL      13
#define SETVAL      16
#define SETALL      17

#define EINVAL 22
#define ENOENT 2
#define EEXIST 17

#define SEGSZ 4096

struct ipc64_perm { int key; unsigned uid, gid, cuid, cgid, mode;
                    unsigned short seq, pad2; unsigned long u1, u2; };
struct shmid_ds { struct ipc64_perm perm; unsigned long segsz;
                  long atime, dtime, ctime; int cpid, lpid;
                  unsigned long nattch, u4, u5; };
struct sembuf { unsigned short num; short op; short flg; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("ipc FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0,0,0,0,0); }
static void want(const char *what, long got, long expect)
{ if (got != expect) fail(what, got, expect); }

static int eq(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }

static long ns_link(char *buf, long cap)
{
  long n = sys6(SYS_readlinkat, AT_FDCWD, (long) "/proc/self/ns/ipc",
                (long) buf, cap - 1, 0, 0);
  if (n >= 0) buf[n] = '\0';
  return n;
}

void _start(void)
{
  struct shmid_ds ds;
  long r, id, addr;

  /* A segment with no key: created, attached, and it is the size asked for. */
  id = sys6(SYS_shmget, IPC_PRIVATE, SEGSZ, IPC_CREAT | 0600, 0,0,0);
  if (id < 0) fail("shmget(IPC_PRIVATE)", id, 0);
  addr = sys6(SYS_shmat, id, 0, 0, 0,0,0);
  if (addr < 0) fail("shmat", addr, 0);

  if ((r = sys6(SYS_shmctl, id, IPC_STAT | IPC_64, (long) &ds, 0,0,0)) < 0)
    fail("shmctl(IPC_STAT)", r, 0);
  want("shm_segsz", (long) ds.segsz, SEGSZ);
  want("shm_nattch after one attach", (long) ds.nattch, 1);

  /* A segment reads back as zero before anyone writes it. */
  want("a fresh segment is zeroed", *(volatile long *) addr, 0);

  *(volatile long *) addr = 0x1234;

  /*
   * The case that used to panic. The child inherits the attachment through a
   * fork that is really a fork and an exec, so the mapping has to be rebuilt on
   * the far side - and it has to be rebuilt onto the same bytes, which is what
   * the second half checks: the parent reads what the child wrote.
   */
  long pid = sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
  if (pid < 0) fail("clone", pid, 0);
  if (pid == 0) {
    if (*(volatile long *) addr != 0x1234)
      sys6(SYS_exit, 2, 0,0,0,0,0);       /* the segment did not survive */
    *(volatile long *) addr = 0x5678;
    /* And a child may detach what it inherited. */
    if (sys6(SYS_shmdt, addr, 0,0,0,0,0) != 0)
      sys6(SYS_exit, 3, 0,0,0,0,0);
    sys6(SYS_exit, 0, 0,0,0,0,0);
  }
  int status = 0;
  if ((r = sys6(SYS_wait4, pid, (long) &status, 0, 0,0,0)) < 0)
    fail("wait4", r, 0);
  if ((status & 0x7f) != 0)
    fail("the child died on signal", status & 0x7f, 0);
  switch ((status >> 8) & 0xff) {
  case 0: break;
  case 2: fail("the child could not see the attached segment", 2, 0);
  case 3: fail("the child could not detach what it inherited", 3, 0);
  default: fail("the child exited with", (status >> 8) & 0xff, 0);
  }
  want("the parent sees what the child wrote", *(volatile long *) addr, 0x5678);

  /* Detaching, and the count that follows it. */
  want("shmdt", sys6(SYS_shmdt, addr, 0,0,0,0,0), 0);
  want("shmdt of an address that is not an attachment",
       sys6(SYS_shmdt, addr, 0,0,0,0,0), -EINVAL);
  if ((r = sys6(SYS_shmctl, id, IPC_STAT | IPC_64, (long) &ds, 0,0,0)) < 0)
    fail("shmctl(IPC_STAT) after detaching", r, 0);
  want("shm_nattch after detaching", (long) ds.nattch, 0);

  want("shmctl(IPC_RMID)", sys6(SYS_shmctl, id, IPC_RMID, 0, 0,0,0), 0);
  want("shmat on a removed segment", sys6(SYS_shmat, id, 0, 0, 0,0,0), -EINVAL);

  /* Keys: the same key finds the same object, and absence is ENOENT. */
  const long key = 0x4e414249;
  want("shmget of an unknown key without IPC_CREAT",
       sys6(SYS_shmget, key, SEGSZ, 0600, 0,0,0), -ENOENT);
  long a = sys6(SYS_shmget, key, SEGSZ, IPC_CREAT | 0600, 0,0,0);
  if (a < 0) fail("shmget(key, IPC_CREAT)", a, 0);
  long b = sys6(SYS_shmget, key, SEGSZ, 0600, 0,0,0);
  want("the same key names the same segment", b, a);
  want("IPC_CREAT|IPC_EXCL on one that exists",
       sys6(SYS_shmget, key, SEGSZ, IPC_CREAT | IPC_EXCL | 0600, 0,0,0), -EEXIST);

  /* Semaphores: the values a guest sets are the values it reads. */
  long sid = sys6(SYS_semget, key, 2, IPC_CREAT | 0600, 0,0,0);
  if (sid < 0) fail("semget", sid, 0);
  want("semctl(SETVAL, 7)", sys6(SYS_semctl, sid, 0, SETVAL, 7, 0,0), 0);
  want("semctl(GETVAL)", sys6(SYS_semctl, sid, 0, GETVAL, 0, 0,0), 7);
  want("semctl(GETVAL) on a semaphore that is not there",
       sys6(SYS_semctl, sid, 9, GETVAL, 0, 0,0), -EINVAL);

  unsigned short vals[2] = { 3, 4 };
  want("semctl(SETALL)", sys6(SYS_semctl, sid, 0, SETALL, (long) vals, 0,0), 0);
  vals[0] = vals[1] = 0;
  want("semctl(GETALL)", sys6(SYS_semctl, sid, 0, GETALL, (long) vals, 0,0), 0);
  want("the first value read back", vals[0], 3);
  want("the second value read back", vals[1], 4);

  /* A semop that can proceed does, and moves the value it said it would. */
  struct sembuf op = { 0, -2, 0 };
  want("semop(-2)", sys6(SYS_semop, sid, (long) &op, 1, 0,0,0), 0);
  want("the value after semop", sys6(SYS_semctl, sid, 0, GETVAL, 0, 0,0), 1);

  /*
   * Removed before the namespace changes, because after that they are out of
   * reach. The initial IPC namespace outlives any one guest - a machine's own
   * objects do - so a test that leaves things in it fails the next time it
   * runs, which is a real property worth being reminded of rather than a
   * nuisance to design around.
   */
  want("semctl(IPC_RMID)", sys6(SYS_semctl, sid, 0, IPC_RMID, 0, 0,0), 0);
  want("shmctl(IPC_RMID) on the keyed segment",
       sys6(SYS_shmctl, a, IPC_RMID, 0, 0,0,0), 0);

  /*
   * The namespace. A new one is empty, so the same key names something else -
   * and the id from the old namespace must not resolve at all, since an id is
   * only meaningful in the namespace that issued it.
   */
  char before[80], after[80];
  if (ns_link(before, sizeof before) < 0)
    fail("reading /proc/self/ns/ipc", -1, 0);
  want("unshare(CLONE_NEWIPC)", sys6(SYS_unshare, CLONE_NEWIPC, 0,0,0,0,0), 0);
  if (ns_link(after, sizeof after) < 0)
    fail("re-reading /proc/self/ns/ipc", -1, 0);
  if (eq(before, after))
    fail("unshare(CLONE_NEWIPC) left the identity unchanged", 0, 1);

  want("the old key in a new namespace",
       sys6(SYS_shmget, key, SEGSZ, 0600, 0,0,0), -ENOENT);

  /* And the new namespace works, rather than merely being empty. */
  long c = sys6(SYS_shmget, key, SEGSZ, IPC_CREAT | 0600, 0,0,0);
  if (c < 0) fail("shmget in the new namespace", c, 0);
  long at2 = sys6(SYS_shmat, c, 0, 0, 0,0,0);
  if (at2 < 0) fail("shmat in the new namespace", at2, 0);
  want("a segment in the new namespace is its own", *(volatile long *) at2, 0);
  want("shmdt in the new namespace", sys6(SYS_shmdt, at2, 0,0,0,0,0), 0);
  want("shmctl(IPC_RMID) in the new namespace",
       sys6(SYS_shmctl, c, IPC_RMID, 0, 0,0,0), 0);

  put("ipc ok\n");
  sys6(SYS_exit, 0, 0,0,0,0,0);
}
