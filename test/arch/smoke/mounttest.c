/* freestanding: mount_setattr, listmount, mbind - and the two kexec calls.
 *
 * The three that do something all lean on the same fact: a mount here is a row
 * in a table, so changing one is a masked update and listing them is a walk.
 *
 *   - mount_setattr must *take effect*, not be recorded. MS_RDONLY is honoured
 *     by path resolution, so a bind made read-only this way has to start
 *     refusing writes - which is the only check that can tell an implementation
 *     that applied the attribute from one that stored it.
 *   - and it must clear as precisely as it sets, since saying which attributes
 *     to change rather than handing over a whole flag word is the reason the
 *     call exists.
 *   - listmount must report the mount that was just made.
 *   - mbind has one node to work with, so what is testable is the validation:
 *     a nodemask naming a node that does not exist is refused rather than
 *     accepted and quietly ignored.
 *
 * kexec_load and kexec_file_load answer ENOSYS. There is no kernel here to boot
 * into, and a caller needs to be able to find that out.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_mkdirat          34
#define SYS_unlinkat         35
#define SYS_openat           56
#define SYS_close            57
#define SYS_write            64
#define SYS_exit             93
#define SYS_kexec_load      104
#define SYS_mount            40
#define SYS_umount2          39
#define SYS_mbind           235
#define SYS_kexec_file_load 294
#define SYS_mount_setattr   442
#define SYS_listmount       458
#define SYS_open_tree       428
#define SYS_move_mount      429
#define SYS_fsopen          430
#define SYS_fsconfig        431
#define SYS_fsmount         432
#define SYS_statmount       457

#define AT_FDCWD    -100
#define AT_REMOVEDIR 0x200
#define AT_RECURSIVE 0x8000
#define O_RDONLY     0
#define O_WRONLY     1
#define O_RDWR       2
#define O_CREAT      0100

#define MS_BIND      4096
#define MS_RDONLY       1

#define ENOSYS       38
#define EINVAL       22
#define EROFS        30
#define EACCES       13
#define EPERM         1

#define MOUNT_ATTR_RDONLY 0x00000001
#define MOUNT_ATTR_NOSUID 0x00000002
#define MOUNT_ATTR_IDMAP  0x00100000

#define OPEN_TREE_CLONE          1
#define MOVE_MOUNT_F_EMPTY_PATH  4
#define FSCONFIG_SET_STRING      1
#define FSCONFIG_CMD_CREATE      6
#define STATMOUNT_SB_BASIC       0x01
#define STATMOUNT_MNT_BASIC      0x02
#define STATMOUNT_MNT_ROOT       0x08
#define STATMOUNT_MNT_POINT      0x10
#define STATMOUNT_FS_TYPE        0x20
#define ENODEV                  19
#define EOVERFLOW               75
#define ENOENT                   2

#define MPOL_DEFAULT    0
#define MPOL_PREFERRED  1
#define MPOL_BIND       2
#define LSMT_ROOT       0xffffffffffffffffULL

struct mount_attr { unsigned long long attr_set, attr_clr, propagation, userns_fd; };
struct mnt_id_req { unsigned size, spare; unsigned long long mnt_id, param; };
/* struct statmount's fixed part and the offsets used below, measured rather
 * than assumed - the string offsets are relative to the end of it. */
#define sizeof_statmount   512
#define STATMOUNT_OFF_MASK       8
#define STATMOUNT_OFF_MNT_ID    40
#define STATMOUNT_OFF_MNT_POINT 108

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write, 1, (long)m, i, 0, 0, 0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}
static void fail(const char *what, long got, long want)
{ put("mount FAIL: "); put(what); put(" -> "); putd(got); put(", wanted ");
  putd(want); put("\n"); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }

void _start(void)
{
  long r;

  /* ---- kexec: absent, and says so ---- */
  if ((r = sys6(SYS_kexec_load, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("kexec_load", r, -ENOSYS);
  if ((r = sys6(SYS_kexec_file_load, 0, 0, 0, 0, 0, 0)) != -ENOSYS)
    fail("kexec_file_load", r, -ENOSYS);

  /* ---- mbind: one node, so the validation is the implementation ---- */
  { unsigned long long mask;

    /* No policy and no mask: satisfied by the only node there is. */
    if ((r = sys6(SYS_mbind, 0, 4096, MPOL_DEFAULT, 0, 0, 0)) != 0)
      fail("mbind with no policy", r, 0);

    /* Bound to node 0, which exists. */
    mask = 1;
    if ((r = sys6(SYS_mbind, 0, 4096, MPOL_BIND, (long) &mask, 8, 0)) != 0)
      fail("mbind to the node this machine has", r, 0);

    /* Bound to node 1, which does not. Accepting this would leave a caller
     * believing its memory is somewhere it cannot be. */
    mask = 2;
    if ((r = sys6(SYS_mbind, 0, 4096, MPOL_BIND, (long) &mask, 8, 0)) != -EINVAL)
      fail("mbind to a node this machine does not have", r, -EINVAL);

    /* Bound to nothing at all cannot be satisfied either. */
    mask = 0;
    if ((r = sys6(SYS_mbind, 0, 4096, MPOL_BIND, (long) &mask, 8, 0)) != -EINVAL)
      fail("mbind to an empty set of nodes", r, -EINVAL);

    /* "No policy" with a mask contradicts itself. */
    mask = 1;
    if ((r = sys6(SYS_mbind, 0, 4096, MPOL_DEFAULT, (long) &mask, 8, 0)) != -EINVAL)
      fail("mbind with no policy but a nodemask", r, -EINVAL);

    if ((r = sys6(SYS_mbind, 0, 4096, 99, 0, 0, 0)) != -EINVAL)
      fail("mbind with a policy that does not exist", r, -EINVAL);
    if ((r = sys6(SYS_mbind, 1, 4096, MPOL_DEFAULT, 0, 0, 0)) != -EINVAL)
      fail("mbind on an address that is not page aligned", r, -EINVAL); }

  /* ---- a bind mount to change the attributes of ---- */
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/msrc", 0755, 0, 0, 0);
  sys6(SYS_mkdirat, AT_FDCWD, (long) "/mdst", 0755, 0, 0, 0);
  if ((r = sys6(SYS_mount, (long) "/msrc", (long) "/mdst", 0, MS_BIND, 0, 0)) != 0)
    fail("a bind mount to work on", r, 0);

  /* Writable to begin with. */
  { long f = sys6(SYS_openat, AT_FDCWD, (long) "/mdst/f", O_RDWR | O_CREAT, 0644, 0, 0);
    if (f < 0)
      fail("creating a file on the bind mount", f, 0);
    sys6(SYS_close, f, 0, 0, 0, 0, 0); }

  /* ---- mount_setattr, and whether it took effect ---- */
  { struct mount_attr a = { MOUNT_ATTR_RDONLY, 0, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, sizeof a, 0)) != 0)
      fail("mount_setattr making a mount read-only", r, 0);

    /* The check that matters: an attribute that was applied refuses the write,
     * where one that was merely recorded does not. */
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mdst/f2", O_RDWR | O_CREAT, 0644, 0, 0);
    if (f >= 0) {
      sys6(SYS_close, f, 0, 0, 0, 0, 0);
      fail("a write to a mount just made read-only", f, -EROFS);
    } }

  /* And cleared as precisely as it was set. */
  { struct mount_attr a = { 0, MOUNT_ATTR_RDONLY, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, sizeof a, 0)) != 0)
      fail("mount_setattr clearing read-only", r, 0);
    long f = sys6(SYS_openat, AT_FDCWD, (long) "/mdst/f2", O_RDWR | O_CREAT, 0644, 0, 0);
    if (f < 0)
      fail("a write after read-only was cleared", f, 0);
    sys6(SYS_close, f, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/mdst/f2", 0, 0, 0, 0); }

  /* ---- what mount_setattr refuses ---- */
  { struct mount_attr a = { MOUNT_ATTR_RDONLY, MOUNT_ATTR_RDONLY, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, sizeof a, 0)) != -EINVAL)
      fail("setting and clearing the same attribute", r, -EINVAL); }
  { struct mount_attr a = { MOUNT_ATTR_IDMAP, 0, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, sizeof a, 0)) != -EINVAL)
      fail("an idmapped mount, which cannot be honoured here", r, -EINVAL); }
  { struct mount_attr a = { 1ULL << 40, 0, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, sizeof a, 0)) != -EINVAL)
      fail("an attribute that does not exist", r, -EINVAL); }
  { struct mount_attr a = { MOUNT_ATTR_NOSUID, 0, 0, 0 };
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/nowhere", 0,
                  (long) &a, sizeof a, 0)) != -EINVAL)
      fail("a path that is not a mount point", r, -EINVAL);
    if ((r = sys6(SYS_mount_setattr, AT_FDCWD, (long) "/mdst", 0,
                  (long) &a, 8, 0)) != -EINVAL)
      fail("a mount_attr smaller than the struct", r, -EINVAL); }

  /* ---- listmount ---- */
  { struct mnt_id_req req;
    unsigned long long ids[16];
    for (int i = 0; i < 16; i++) ids[i] = 0;
    req.size = sizeof req; req.spare = 0;
    req.mnt_id = LSMT_ROOT; req.param = 0;

    r = sys6(SYS_listmount, (long) &req, (long) ids, 16, 0, 0, 0);
    if (r < 1)
      fail("listmount finding the mount just made", r, 1);
    /* Every id it reported must be a real one. */
    for (long i = 0; i < r; i++)
      if (ids[i] == 0)
        fail("a mount id of zero in the list", (long) ids[i], 1);

    if ((r = sys6(SYS_listmount, (long) &req, (long) ids, 16, 1, 0, 0)) != -EINVAL)
      fail("listmount with a flag that does not exist", r, -EINVAL);
    req.size = 4;
    if ((r = sys6(SYS_listmount, (long) &req, (long) ids, 16, 0, 0, 0)) != -EINVAL)
      fail("listmount with a request smaller than the struct", r, -EINVAL); }

  /*
   * ---- statmount ----
   *
   * The partner of listmount: that one says which mounts exist, this describes
   * one. The strings come back as offsets into a run after the fixed part, so
   * an implementation that reported the wrong offset would still return
   * success - which is why the point is compared rather than counted.
   */
  { struct mnt_id_req req;
    unsigned long long ids[16];
    req.size = sizeof req; req.spare = 0;
    req.mnt_id = LSMT_ROOT; req.param = 0;
    r = sys6(SYS_listmount, (long) &req, (long) ids, 16, 0, 0, 0);
    if (r < 1)
      fail("listmount before statmount", r, 1);

    char buf[1024];
    for (int i = 0; i < 1024; i++) buf[i] = 0;
    req.mnt_id = ids[0];
    req.param = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT |
                STATMOUNT_FS_TYPE | STATMOUNT_SB_BASIC;
    if ((r = sys6(SYS_statmount, (long) &req, (long) buf, sizeof buf, 0, 0, 0)) != 0)
      fail("statmount of the mount listmount reported", r, 0);

    unsigned mask_lo = *(unsigned *)(buf + STATMOUNT_OFF_MASK);
    unsigned mnt_point_off = *(unsigned *)(buf + STATMOUNT_OFF_MNT_POINT);
    unsigned long long got_id =
        *(unsigned long long *)(buf + STATMOUNT_OFF_MNT_ID);
    if (!(mask_lo & STATMOUNT_MNT_BASIC))
      fail("statmount reporting what it filled in", mask_lo, STATMOUNT_MNT_BASIC);
    if (got_id != ids[0])
      fail("the id statmount reported", (long) got_id, (long) ids[0]);
    /* The mount point string, at the offset it said. */
    { const char *pt = buf + sizeof_statmount + mnt_point_off;
      if (pt[0] != '/')
        fail("the mount point statmount pointed at", pt[0], '/'); }

    req.mnt_id = 999999;
    if ((r = sys6(SYS_statmount, (long) &req, (long) buf, sizeof buf, 0, 0, 0)) != -ENOENT)
      fail("statmount of a mount that does not exist", r, -ENOENT);
    req.mnt_id = ids[0];
    if ((r = sys6(SYS_statmount, (long) &req, (long) buf, 16, 0, 0, 0)) != -EOVERFLOW)
      fail("statmount into a buffer too small for it", r, -EOVERFLOW); }

  /*
   * ---- the new mount API, end to end ----
   *
   * fsopen names a type, fsconfig creates it, fsmount makes a mount that is
   * attached nowhere, and move_mount attaches it. The chain is the point: each
   * step is useless alone, so what is tested is that a tmpfs mounted this way
   * is a tmpfs that is really there.
   */
  { long ctx = sys6(SYS_fsopen, (long) "tmpfs", 0, 0, 0, 0, 0);
    if (ctx < 0)
      fail("fsopen of tmpfs", ctx, 0);

    /* A filesystem this cannot provide is refused by the call that named it,
     * rather than three calls later - which is why the API is split. */
    { long bad = sys6(SYS_fsopen, (long) "ext4", 0, 0, 0, 0, 0);
      if (bad != -ENODEV)
        fail("fsopen of a filesystem there is no block layer for", bad, -ENODEV); }

    /* fsmount before the context is created has nothing to mount. */
    if ((r = sys6(SYS_fsmount, ctx, 0, 0, 0, 0, 0)) != -EINVAL)
      fail("fsmount of a context that was never created", r, -EINVAL);

    sys6(SYS_fsconfig, ctx, FSCONFIG_SET_STRING, (long) "source",
         (long) "mysrc", 0, 0);
    if ((r = sys6(SYS_fsconfig, ctx, FSCONFIG_CMD_CREATE, 0, 0, 0, 0)) != 0)
      fail("fsconfig creating the context", r, 0);

    long mfd = sys6(SYS_fsmount, ctx, 0, 0, 0, 0, 0);
    if (mfd < 0)
      fail("fsmount", mfd, 0);

    sys6(SYS_mkdirat, AT_FDCWD, (long) "/newapi", 0755, 0, 0, 0);
    /*
     * A marker underneath, so the mount can be shown to have happened. Writing
     * to /newapi afterwards would succeed whether or not anything was mounted -
     * it is a real directory either way - but a tmpfs over it hides what was
     * there, and only a mount can do that.
     */
    { long f = sys6(SYS_openat, AT_FDCWD, (long) "/newapi/under",
                    O_RDWR | O_CREAT, 0644, 0, 0);
      if (f < 0)
        fail("a marker under the mount point", f, 0);
      sys6(SYS_close, f, 0, 0, 0, 0, 0); }

    if ((r = sys6(SYS_move_mount, mfd, (long) "", AT_FDCWD, (long) "/newapi",
                  MOVE_MOUNT_F_EMPTY_PATH, 0)) != 0)
      fail("move_mount attaching the detached mount", r, 0);

    /* The marker is hidden, which is what says a mount is there. */
    { long f = sys6(SYS_openat, AT_FDCWD, (long) "/newapi/under", O_RDONLY, 0, 0, 0);
      if (f >= 0) {
        sys6(SYS_close, f, 0, 0, 0, 0, 0);
        fail("what was under the mount point is still visible", 0, -ENOENT);
      } }
    /* And the tmpfs itself works. */
    { long f = sys6(SYS_openat, AT_FDCWD, (long) "/newapi/x", O_RDWR | O_CREAT, 0644, 0, 0);
      if (f < 0)
        fail("writing to the tmpfs mounted through the new API", f, 0);
      sys6(SYS_close, f, 0, 0, 0, 0, 0); }

    /* A detached mount is used once. */
    if ((r = sys6(SYS_move_mount, mfd, (long) "", AT_FDCWD, (long) "/newapi",
                  MOVE_MOUNT_F_EMPTY_PATH, 0)) != -EINVAL)
      fail("attaching the same detached mount twice", r, -EINVAL);

    sys6(SYS_close, mfd, 0, 0, 0, 0, 0);
    sys6(SYS_close, ctx, 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/newapi/x", 0, 0, 0, 0);
    sys6(SYS_umount2, (long) "/newapi", 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/newapi/under", 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/newapi", AT_REMOVEDIR, 0, 0, 0); }

  /* ---- open_tree, the other way to get a detached mount ---- */
  { long tfd = sys6(SYS_open_tree, AT_FDCWD, (long) "/mdst", OPEN_TREE_CLONE, 0, 0, 0);
    if (tfd < 0)
      fail("open_tree cloning an existing mount", tfd, 0);
    sys6(SYS_mkdirat, AT_FDCWD, (long) "/mclone", 0755, 0, 0, 0);
    if ((r = sys6(SYS_move_mount, tfd, (long) "", AT_FDCWD, (long) "/mclone",
                  MOVE_MOUNT_F_EMPTY_PATH, 0)) != 0)
      fail("move_mount attaching the cloned tree", r, 0);
    /* The clone shows the same thing the original does. */
    { long f = sys6(SYS_openat, AT_FDCWD, (long) "/mclone/f", O_RDONLY, 0, 0, 0);
      if (f < 0)
        fail("a file visible through the cloned mount", f, 0);
      sys6(SYS_close, f, 0, 0, 0, 0, 0); }
    sys6(SYS_close, tfd, 0, 0, 0, 0, 0);
    sys6(SYS_umount2, (long) "/mclone", 0, 0, 0, 0, 0);
    sys6(SYS_unlinkat, AT_FDCWD, (long) "/mclone", AT_REMOVEDIR, 0, 0, 0);

    if ((r = sys6(SYS_open_tree, AT_FDCWD, (long) "/nowhere", OPEN_TREE_CLONE, 0, 0, 0)) != -EINVAL)
      fail("open_tree of something that is not a mount", r, -EINVAL); }

  sys6(SYS_umount2, (long) "/mdst", 0, 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/msrc/f", 0, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/msrc", AT_REMOVEDIR, 0, 0, 0);
  sys6(SYS_unlinkat, AT_FDCWD, (long) "/mdst", AT_REMOVEDIR, 0, 0, 0);

  put("mount ok\n");
  sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
