/* freestanding: O_PATH on a socket, which the host will not open at all.
 *
 * Linux's O_PATH opens the *name* rather than the object behind it. The
 * descriptor cannot be read or written; it exists to be handed to fstat and to
 * the *at() calls, and it works on anything a name can point at - including a
 * socket, which nothing can open in the ordinary sense.
 *
 * Darwin has no equivalent and refuses a socket outright: O_RDONLY, O_SYMLINK,
 * O_EVTONLY and O_NONBLOCK were each tried against a bound one and every one
 * answers EOPNOTSUPP. So nabi invents the descriptor and answers from the name.
 *
 * Android's init is what needed it. Having bound /dev/socket/property_service
 * it reopens it O_PATH|O_NOFOLLOW to set the mode without a window in which the
 * name could come to mean something else, and treats a failure as fatal -
 * "start_property_service socket creation failed" ended second-stage init with
 * the socket itself bound and working.
 *
 * What is checked:
 *
 *   - the open succeeds, which is what init needed.
 *   - fchmod through it changes the socket's mode, and fstat reads it back.
 *     That is the entire point of holding the descriptor.
 *   - fstat says it is a socket, so the descriptor names the right object and
 *     not, say, the directory it lives in.
 *   - a read is EBADF. An O_PATH descriptor is not a way to read a file, and
 *     one that silently read something else would be worse than no descriptor.
 *   - O_PATH on an ordinary file still gives a working descriptor, so this has
 *     not become a special case that only sockets take.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write        64
#define SYS_read         63
#define SYS_exit         93
#define SYS_close        57
#define SYS_openat       56
#define SYS_fchmod       52
#define SYS_newfstatat   79
#define SYS_socket      198
#define SYS_bind        200
#define SYS_unlinkat     35

#define AT_FDCWD     (-100)
#define AF_UNIX          1
#define SOCK_STREAM      1
#define O_RDONLY         0
#define O_NOFOLLOW  0x08000
#define O_CLOEXEC   0x80000
#define O_PATH     0x200000
#define EBADF            9
#define S_IFMT      0170000
#define S_IFSOCK    0140000

struct sun { unsigned short family; char path[108]; };
struct kstat { unsigned long dev, ino; unsigned int mode, nlink, uid, gid;
               unsigned long rdev, pad; long size; int blksize, pad2;
               long blocks; long at, atn, mt, mtn, ct, ctn; unsigned unused[2]; };

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}

static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) { put("  ok  "); put(what); put("\n"); return; }
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

void _start(void)
{
  static const char name[] = "/opathsock";
  sys6(SYS_unlinkat, AT_FDCWD, (long)name, 0, 0, 0, 0);

  long s = sys6(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
  want("socket(AF_UNIX, SOCK_STREAM)", s >= 0, 1);
  struct sun a; a.family = AF_UNIX;
  for (int i = 0; i < 108; i++) a.path[i] = 0;
  for (int i = 0; name[i]; i++) a.path[i] = name[i];
  want("bind", sys6(SYS_bind, s, (long)&a, sizeof a, 0, 0, 0), 0);

  /* Exactly what init opens, with exactly init's flags. */
  long fd = sys6(SYS_openat, AT_FDCWD, (long)name,
                 O_PATH|O_NOFOLLOW|O_CLOEXEC, 0, 0, 0);
  want("openat(socket, O_PATH|O_NOFOLLOW|O_CLOEXEC)", fd >= 0, 1);

  if (fd >= 0) {
    want("fchmod through it", sys6(SYS_fchmod, fd, 0660, 0, 0, 0, 0), 0);
    struct kstat st;
    want("fstat through it",
         sys6(SYS_newfstatat, fd, (long)"", (long)&st, 0x1000 /* AT_EMPTY_PATH */, 0, 0), 0);
    want("it names a socket", (st.mode & S_IFMT) == S_IFSOCK, 1);
    want("and carries the mode just set", st.mode & 0777, 0660);

    char buf[8];
    want("a read of it is EBADF", sys6(SYS_read, fd, (long)buf, sizeof buf, 0, 0, 0), -EBADF);
    sys6(SYS_close, fd, 0,0,0,0,0);
  }
  sys6(SYS_close, s, 0,0,0,0,0);
  sys6(SYS_unlinkat, AT_FDCWD, (long)name, 0, 0, 0, 0);

  /* Not a socket-only path: an ordinary file opened O_PATH still works. */
  long ofd = sys6(SYS_openat, AT_FDCWD, (long)"/opathsocktest",
                  O_PATH|O_CLOEXEC, 0, 0, 0);
  want("O_PATH on an ordinary file", ofd >= 0, 1);
  if (ofd >= 0) {
    struct kstat st2;
    want("and fstat works through that too",
         sys6(SYS_newfstatat, ofd, (long)"", (long)&st2, 0x1000, 0, 0), 0);
    sys6(SYS_close, ofd, 0,0,0,0,0);
  }

  put(fails ? "opathsock FAILED\n" : "opathsock ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
