/*
 * The parts of /proc only NABI can answer.
 *
 * mSL/ProcFS supplies /proc, and NABI passes it through (src/fs/fs.c), so a
 * guest gets a real procfs describing real processes - and correctly so, since
 * a guest process *is* a host process and its pid is the host's. What XNU
 * cannot know is what that process is running: from the outside it is a `nabi`
 * executing a guest, and every per-process file describes the emulator rather
 * than the program. /proc/self/maps is the sharp end of that. It comes back as
 * NABI's own host address space, which is not a distorted view of the guest's -
 * it is a different address space entirely, and anything reading it to find out
 * where the guest's own code and heap live is comprehensively misled.
 *
 * The guest's memory map is in proc.mm, so that one NABI can answer, and this
 * file answers it. The other identity files - cmdline, exe, comm - would need
 * the guest's argv and binary path kept across fork, which on arm64 is fork +
 * exec and so means the checkpoint's wire format; they are still the emulator's
 * for now.
 *
 * Serving it as an unlinked temp file rather than a pipe is what keeps the
 * descriptor an ordinary file: seekable, stat-able, readable more than once.
 * The content is a snapshot taken at open, which is what procfs does with these
 * files anyway - each open gets the state as it was, and nothing promises a
 * reader that it changes underneath them.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslimits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <ctype.h>

/* Declared rather than included: <sys/sysctl.h> drags in a roundup() macro that
 * collides with the inline of the same name in util/misc.h. One prototype is
 * cheaper than an include-order rule nobody will remember. */
int sysctlbyname(const char *, void *, size_t *, void *, size_t);
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "namespace.h"
#include "sysv.h"
#include <sys/stat.h>

#include "page.h"

#include "linux/common.h"
#include "linux/errno.h"
#include "linux/time.h"
#include "linux/fs.h"
#include "linux/mman.h"

/*
 * Record what this process is running, at exec.
 *
 * argv is flattened here rather than kept as a vector because that is the shape
 * /proc/<pid>/cmdline has - one NUL-terminated string per argument, run
 * together - and the shape the checkpoint carries. Doing it once at exec means
 * neither the reader nor the handover has to walk a pointer array that belongs
 * to a guest address space.
 */
void
proc_set_ident(const char *exe, int argc, char *argv[])
{
  free(proc.ident.exe);
  free(proc.ident.cmdline);
  proc.ident.exe = exe ? strdup(exe) : NULL;

  size_t len = 0;
  for (int i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;

  char *flat = malloc(len ? len : 1);
  if (!flat) {
    proc.ident.cmdline = NULL;
    proc.ident.cmdline_len = 0;
    return;
  }
  size_t off = 0;
  for (int i = 0; i < argc; i++) {
    size_t n = strlen(argv[i]) + 1;
    memcpy(flat + off, argv[i], n);
    off += n;
  }
  proc.ident.cmdline = flat;
  proc.ident.cmdline_len = len;
}

/*
 * The guest's address space in Linux's /proc/<pid>/maps format:
 *
 *   start-end perms offset dev inode path
 *
 * dev, inode and the path are all left empty, and the path deliberately so.
 * mm_region keeps the guest fd a mapping was made from, but the guest closes
 * that descriptor as soon as ld.so has mapped a segment, and the number is
 * promptly reused - asking the host what it names now answers for whatever
 * holds it today, which is how every library in a shell's map came out as
 * /dev/urandom. A wrong path is worse than an absent one: a reader can see that
 * nothing is claimed, but cannot see that something claimed is a lie.
 *
 * Naming them properly means the region remembering its own file at mmap time,
 * which is a field in mm_region and so a change to the checkpoint's wire
 * format - the same thing cmdline and exe need. Until then the ranges and
 * permissions are right, which is the part that was actively wrong before.
 */
static char *
build_maps(size_t *len_out)
{
  size_t cap = 8192, len = 0;
  char *buf = malloc(cap);
  if (!buf)
    return NULL;

  pthread_rwlock_rdlock(&proc.mm->alloc_lock);
  struct mm_region *r;
  list_for_each_entry(r, &proc.mm->mm_regions, list) {
    char line[128];
    int n = snprintf(line, sizeof line,
                     "%012llx-%012llx %c%c%c%c %08llx 00:00 0 \n",
                     (unsigned long long) r->gaddr,
                     (unsigned long long) (r->gaddr + r->size),
                     (r->prot & LINUX_PROT_READ)  ? 'r' : '-',
                     (r->prot & LINUX_PROT_WRITE) ? 'w' : '-',
                     (r->prot & LINUX_PROT_EXEC)  ? 'x' : '-',
                     (r->mm_flags & LINUX_MAP_SHARED) ? 's' : 'p',
                     (unsigned long long) r->pgoff * PAGE_SIZEOF(PAGE_4KB));
    if (n < 0)
      continue;
    if (len + (size_t) n + 1 > cap) {
      size_t want = (len + (size_t) n + 1) * 2;
      char *bigger = realloc(buf, want);
      if (!bigger)
        break;
      buf = bigger;
      cap = want;
    }
    memcpy(buf + len, line, (size_t) n);
    len += (size_t) n;
  }
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  buf[len] = '\0';
  *len_out = len;
  return buf;
}

/*
 * Which of this process's own /proc files is being asked for, if any.
 *
 * /proc/self and /proc/thread-self are the guest asking about itself, and so is
 * its own pid spelled out - a guest pid is the host pid, so the number a guest
 * reads from getpid() is the one procfs knows it by. Another process's pid is
 * not ours to answer for: it may be an ordinary macOS process, and even if it
 * is another guest, its state lives in a different nabi.
 */
enum procfs_file { PROCFS_NONE, PROCFS_MAPS, PROCFS_CMDLINE, PROCFS_COMM,
                   PROCFS_EXE, PROCFS_FD, PROCFS_MOUNTS, PROCFS_FDDIR,
                   PROCFS_RANDOM_UUID, PROCFS_RANDOM_BOOT_ID, PROCFS_NS, PROCFS_NSDIR,
                   PROCFS_SYSVIPC_SHM, PROCFS_SYSVIPC_SEM, PROCFS_SYSVIPC_MSG };

/* For PROCFS_FD, the number after /fd/. Meaningless for the others. */
static enum procfs_file
own_procfs_file_n(const char *path, int *fd_out)
{
  if (strncmp(path, "/proc/", 6) != 0)
    return PROCFS_NONE;
  const char *rest = path + 6;

  /* /proc/mounts, with no pid component. The usual spelling of it - /etc/mtab
   * is a symlink to /proc/self/mounts on every distribution now, but plenty of
   * software still opens the short name directly. */
  if (strcmp(rest, "mounts") == 0)
    return PROCFS_MOUNTS;

  /*
   * The two files under /proc/sys/kernel/random that are read rather than
   * tuned. mSL/FHS mirrors Darwin's sysctl tree under /proc/sys, so
   * /proc/sys/kernel is the kern.* namespace and random/ comes out empty -
   * these are Linux's own and have no Darwin sysctl behind them.
   *
   * Arch's shell startup reads both, so a login began with
   * "-bash: /proc/sys/kernel/random/uuid: No such file or directory" three
   * times over.
   */
  /*
   * /proc/sysvipc, which is how ipcs and everything like it lists these
   * objects - it reads the files first and only falls back to shmctl(SHM_STAT)
   * if they are missing.
   *
   * mSL/ProcFS does provide them, and that is exactly the problem: it fills
   * them from the *host Mac's* System V tables, which is where these objects
   * used to live and no longer do. So the files existed, parsed, and reported
   * nothing, and ipcs showed an empty list next to a segment the guest had just
   * created - the one failure mode a fallback cannot rescue, because nothing
   * looks broken. They are answered here now, from the namespace the caller is
   * actually in.
   */
  if (strcmp(rest, "sysvipc/shm") == 0)
    return PROCFS_SYSVIPC_SHM;
  if (strcmp(rest, "sysvipc/sem") == 0)
    return PROCFS_SYSVIPC_SEM;
  if (strcmp(rest, "sysvipc/msg") == 0)
    return PROCFS_SYSVIPC_MSG;
  if (strcmp(rest, "sys/kernel/random/uuid") == 0)
    return PROCFS_RANDOM_UUID;
  if (strcmp(rest, "sys/kernel/random/boot_id") == 0)
    return PROCFS_RANDOM_BOOT_ID;

  const char *slash = strchr(rest, '/');
  if (!slash)
    return PROCFS_NONE;

  size_t n = (size_t) (slash - rest);
  bool mine = (n == 4 && strncmp(rest, "self", 4) == 0) ||
              (n == 11 && strncmp(rest, "thread-self", 11) == 0);
  if (!mine) {
    char pid[16];
    int m = snprintf(pid, sizeof pid, "%d", getpid());
    mine = m > 0 && (size_t) m == n && strncmp(rest, pid, n) == 0;
  }
  if (!mine)
    return PROCFS_NONE;

  if (strcmp(slash, "/mounts") == 0)  return PROCFS_MOUNTS;
  if (strcmp(slash, "/maps") == 0)    return PROCFS_MAPS;
  if (strcmp(slash, "/cmdline") == 0) return PROCFS_CMDLINE;
  if (strcmp(slash, "/comm") == 0)    return PROCFS_COMM;
  if (strcmp(slash, "/exe") == 0)     return PROCFS_EXE;

  /* /proc/self/fd/<n>. The host's procfs cannot answer this even when it is
   * mounted: the fds it would describe are nabi's, and a guest fd number means
   * nothing there. Worse, what it does serve are directories rather than
   * symlinks, so readlink on one comes back EINVAL - which is how systemd's
   * fsync_directory_of_file, which finds a file's directory by reading
   * /proc/self/fd/<n>, reported "Failed to flush /etc/.#group...: Invalid
   * argument" and stopped systemd, udev and cron from configuring. */
  /* The directory itself, which is what anything closing its inherited
   * descriptors reads. Handled before the /fd/<n> form below, which needs a
   * number and would decline this.
   *
   * A trailing slash is the same directory. Spelling it "/proc/self/fd/" is
   * what libassuan does, and missing that sent the open to the host's /proc -
   * where it found nabi's descriptors and never finished reading them. */
  if (strcmp(slash, "/fd") == 0 || strcmp(slash, "/fd/") == 0 ||
      strcmp(slash, "/fd/.") == 0)
    return PROCFS_FDDIR;

  /* The directory itself, which `ls /proc/self/ns` reads and which anything
   * enumerating a process's namespaces starts from. */
  if (strcmp(slash, "/ns") == 0 || strcmp(slash, "/ns/") == 0)
    return PROCFS_NSDIR;

  /* /proc/<pid>/ns/<type>. A symlink on Linux, reading "uts:[4026531838]", and
   * the thing setns is handed. */
  if (strncmp(slash, "/ns/", 4) == 0) {
    enum ns_type t;
    if (!ns_type_from_name(slash + 4, &t))
      return PROCFS_NONE;
    if (fd_out)
      *fd_out = (int) t;        /* which one, for the caller */
    return PROCFS_NS;
  }

  if (strncmp(slash, "/fd/", 4) == 0) {
    const char *p = slash + 4;
    if (*p < '0' || *p > '9')
      return PROCFS_NONE;
    int n = 0;
    for (; *p >= '0' && *p <= '9'; p++) {
      n = n * 10 + (*p - '0');
      if (n > 1 << 24)
        return PROCFS_NONE;
    }
    if (*p != '\0')
      return PROCFS_NONE;
    if (fd_out)
      *fd_out = n;
    return PROCFS_FD;
  }
  return PROCFS_NONE;
}


/*
 * The guest's mount table, in Linux's /proc/mounts format.
 *
 * There is no mount table to report. The guest's filesystem is one host
 * directory that nabi resolves paths against, and the host's own mounts are
 * neither what the guest sees nor expressible in this format. What software
 * reads this file for, though, is rarely the mounts themselves: it is which
 * filesystem a path belongs to, so it can ask how much room is left.
 *
 * pacman does exactly that, and until this existed it stopped before unpacking
 * anything with "could not open file: /etc/mtab: No such file or directory"
 * followed by "could not determine filesystem mount points" - /etc/mtab being a
 * symlink to /proc/self/mounts, which nabi did not serve. A single root entry
 * answers the question truthfully: everything the guest can reach really is on
 * one filesystem as far as it can tell.
 *
 * The passthrough prefixes are listed too, because those genuinely are a
 * different filesystem from the guest's point of view - a write to /dev or /tmp
 * lands somewhere the rootfs does not - and something sizing a download into
 * /tmp should not be told it shares the root's free space.
 */
static char *
build_mounts(size_t *len_out)
{
  static const char text[] =
    "rootfs / rootfs rw 0 0\n"
    "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
    "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n";

  size_t len = sizeof text - 1;
  char *out = malloc(len);
  if (!out)
    return NULL;
  memcpy(out, text, len);
  *len_out = len;
  return out;
}

/*
 * /proc/sysvipc/{shm,sem,msg}, in the kernel's own column layout because that
 * is what util-linux parses. The ids are the guest's, and the objects are those
 * of the IPC namespace this process is in - which is the whole point of
 * answering it here rather than letting the host's empty tables answer.
 */
static char *
build_sysvipc(enum procfs_file which, size_t *len_out)
{
  static const char shm_hdr[] =
    "       key      shmid perms       size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime        rss       swap\n";
  static const char sem_hdr[] =
    "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";
  static const char msg_hdr[] =
    "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";

  const char *hdr = which == PROCFS_SYSVIPC_SHM ? shm_hdr
                  : which == PROCFS_SYSVIPC_SEM ? sem_hdr : msg_hdr;

  size_t cap = 4096, len = strlen(hdr);
  char *out = malloc(cap);
  if (!out)
    return NULL;
  memcpy(out, hdr, len);

  /* Message queues do not exist here, so the file is its header and nothing
   * else - which is also what Linux shows when there are none. */
  if (which != PROCFS_SYSVIPC_MSG) {
    enum sysv_kind kind =
        which == PROCFS_SYSVIPC_SHM ? SYSV_SHM : SYSV_SEM;
    struct sysv_meta *all = calloc(SYSV_MAX_ID, sizeof *all);
    if (all) {
      int n = sysv_list(kind, all, SYSV_MAX_ID);
      if (n > SYSV_MAX_ID)
        n = SYSV_MAX_ID;
      for (int i = 0; i < n; i++) {
        char row[512];
        int rn;
        if (kind == SYSV_SHM)
          rn = snprintf(row, sizeof row,
                        "%10d %10d  %4o %21llu %5u %5u  %5lu %5u %5u %5u %5u %10lld %10lld %10lld %21llu %21llu\n",
                        all[i].key, all[i].host_id, all[i].mode,
                        (unsigned long long) all[i].size,
                        (unsigned) all[i].cpid, (unsigned) all[i].lpid,
                        (unsigned long) (all[i].nattch < 0 ? 0 : all[i].nattch),
                        all[i].uid, all[i].gid, all[i].cuid, all[i].cgid,
                        (long long) all[i].atime, (long long) all[i].dtime,
                        (long long) all[i].ctime,
                        (unsigned long long) all[i].size, 0ULL);
        else
          rn = snprintf(row, sizeof row,
                        "%10d %10d  %4o %10llu %5u %5u %5u %5u %10lld %10lld\n",
                        all[i].key, all[i].host_id, all[i].mode,
                        (unsigned long long) all[i].size,
                        all[i].uid, all[i].gid, all[i].cuid, all[i].cgid,
                        (long long) all[i].otime, (long long) all[i].ctime);
        if (rn < 0)
          continue;
        if (len + (size_t) rn + 1 > cap) {
          cap = (len + (size_t) rn + 1) * 2;
          char *bigger = realloc(out, cap);
          if (!bigger)
            break;
          out = bigger;
        }
        memcpy(out + len, row, (size_t) rn);
        len += (size_t) rn;
      }
      free(all);
    }
  }
  *len_out = len;
  return out;
}

/*
 * /proc/sys/kernel/random/uuid: a fresh random UUID, every time it is read.
 *
 * That is the whole of its behaviour on Linux - it is a UUID generator with a
 * filename, not a value that is stored anywhere - so two reads must not agree.
 */
static char *
build_random_uuid(size_t *len_out)
{
  uuid_t u;
  uuid_string_t text;

  uuid_generate_random(u);
  uuid_unparse_lower(u, text);

  size_t n = strlen(text);
  char *out = malloc(n + 2);
  if (!out)
    return NULL;
  memcpy(out, text, n);
  out[n] = '\n';
  *len_out = n + 1;
  return out;
}

/*
 * /proc/sys/kernel/random/boot_id: one value for as long as the machine has
 * been up, which is what anything reading it depends on.
 *
 * Darwin has exactly that in kern.bootsessionuuid, so this is a translation
 * rather than an invention - and it keeps the guest's answer agreeing with the
 * host's across every guest on the machine, which a per-process random value
 * would not. Uppercase there, lowercase here, as Linux writes it.
 */
static char *
build_boot_id(size_t *len_out)
{
  char sys[64];
  size_t syslen = sizeof sys;

  if (sysctlbyname("kern.bootsessionuuid", sys, &syslen, NULL, 0) < 0)
    return NULL;

  size_t n = strnlen(sys, sizeof sys - 1);
  char *out = malloc(n + 2);
  if (!out)
    return NULL;
  for (size_t i = 0; i < n; i++)
    out[i] = (char) tolower((unsigned char) sys[i]);
  out[n] = '\n';
  *len_out = n + 1;
  return out;
}

/* comm is the executable's basename and a newline - Linux truncates it to 15
 * characters, and something reading it to compare against a process name will
 * expect that truncation rather than the full one. */
static char *
build_comm(size_t *len_out)
{
  const char *exe = proc.ident.exe;
  if (!exe)
    return NULL;
  const char *base = strrchr(exe, '/');
  base = base ? base + 1 : exe;

  char *out = malloc(18);
  if (!out)
    return NULL;
  *len_out = (size_t) snprintf(out, 18, "%.15s\n", base);
  return out;
}

/*
 * Open a synthesised /proc file, or return -1 to mean "not ours" so the caller
 * carries on with the ordinary lookup.
 *
 * Errors from here are deliberately not fatal: if the temp file cannot be made,
 * the caller falls back to the host's own answer, which is wrong in the way
 * described at the top of this file but no worse than it was.
 */
/*
 * Staging directories handed out for /proc/self/fd, by the descriptor that
 * names one. Small and short-lived: a program reads its own fd list once,
 * closes it, and the directory goes with it.
 */
KHASH_MAP_INIT_INT(fddir, char *)
static khash_t(fddir) *fddir_tmp;

/* Remove a directory of symlinks and the directory itself. */
static void
procfs_rmtree(const char *dir)
{
  DIR *d = opendir(dir);
  if (d != NULL) {
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
        continue;
      char p[PATH_MAX];
      snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
      unlink(p);
    }
    closedir(d);
  }
  rmdir(dir);
}

/*
 * Fill a staging directory with one symlink per open guest descriptor,
 * replacing whatever was there.
 *
 * Rebuilt rather than written once because /proc/self/fd is *live*: a program
 * closing its inherited descriptors reads the directory, closes what it found,
 * and reads again to see what is left. Against a snapshot that never changes,
 * that second read returns the same list as the first and the program never
 * finishes - which is exactly where `pacman -S` stopped, rewinding one
 * descriptor forever while libassuan waited for the list to shrink.
 */
static void
procfs_fill_fddir(const char *dir)
{
  DIR *d = opendir(dir);
  if (d != NULL) {
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] == '.')
        continue;
      char p[PATH_MAX];
      snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
      unlink(p);
    }
    closedir(d);
  }

  int nfds = fdtable_open_fds(NULL, 0);
  int *fds = nfds > 0 ? malloc((size_t) nfds * sizeof *fds) : NULL;
  if (fds == NULL)
    return;
  nfds = fdtable_open_fds(fds, nfds);

  for (int i = 0; i < nfds; i++) {
    char name[PATH_MAX], target[64];
    snprintf(name, sizeof name, "%s/%d", dir, fds[i]);
    snprintf(target, sizeof target, "/proc/self/fd/%d", fds[i]);
    (void) symlink(target, name);
  }
  free(fds);
}

/* Refresh the listing behind a descriptor, if it is one of ours. Returns
 * whether it was. */
bool
procfs_refresh_fddir(int fd)
{
  if (fddir_tmp == NULL)
    return false;
  khiter_t k = kh_get(fddir, fddir_tmp, fd);
  if (k == kh_end(fddir_tmp))
    return false;
  procfs_fill_fddir(kh_value(fddir_tmp, k));
  return true;
}

/* Which namespace a descriptor from /proc/<pid>/ns/<type> names. The file
 * behind it is a stand-in, so this is where the answer actually lives. */
struct ns_note { int type; uint64_t ino; };
KHASH_MAP_INIT_INT(nsfd, struct ns_note)
static khash_t(nsfd) *nsfd_notes;

static void
procfs_remember_ns(int fd, enum ns_type type, uint64_t ino)
{
  int ret;
  if (nsfd_notes == NULL)
    nsfd_notes = kh_init(nsfd);
  khiter_t k = kh_put(nsfd, nsfd_notes, fd, &ret);
  kh_value(nsfd_notes, k) = (struct ns_note){ (int) type, ino };
}

bool
procfs_ns_of_fd(int fd, enum ns_type *type, uint64_t *ino)
{
  if (nsfd_notes == NULL)
    return false;
  khiter_t k = kh_get(nsfd, nsfd_notes, fd);
  if (k == kh_end(nsfd_notes))
    return false;
  if (type) *type = (enum ns_type) kh_value(nsfd_notes, k).type;
  if (ino)  *ino  = kh_value(nsfd_notes, k).ino;
  return true;
}

static void
procfs_remember_tmpdir(int fd, const char *dir)
{
  int ret;
  if (fddir_tmp == NULL)
    fddir_tmp = kh_init(fddir);
  khiter_t k = kh_put(fddir, fddir_tmp, fd, &ret);
  kh_value(fddir_tmp, k) = strdup(dir);
}

/* Called when a descriptor is closed; a no-op for anything that is not one of
 * these. */
void
procfs_close_fd(int fd)
{
  if (nsfd_notes != NULL) {
    khiter_t nk = kh_get(nsfd, nsfd_notes, fd);
    if (nk != kh_end(nsfd_notes))
      kh_del(nsfd, nsfd_notes, nk);
  }
  if (fddir_tmp == NULL)
    return;
  khiter_t k = kh_get(fddir, fddir_tmp, fd);
  if (k == kh_end(fddir_tmp))
    return;
  char *dir = kh_value(fddir_tmp, k);
  procfs_rmtree(dir);
  free(dir);
  kh_del(fddir, fddir_tmp, k);
}

/*
 * The descriptor number in "/proc/self/fd/<n>", or -1 for anything else.
 *
 * Opening that path is answered elsewhere; this is for every *other* operation
 * on it. systemd changes the mode of an O_PATH descriptor by chmod'ing
 * /proc/self/fd/<n>, because fchmod on an O_PATH handle is not allowed - and
 * that arrived here as an ordinary path, went to the host's /proc, and came
 * back EACCES. So `dnf install` reported a failed transaction, from
 * "Failed to copy permissions from /etc/group to /etc/.#group...".
 */
int
procfs_fd_number(const char *path)
{
  int fd = -1;
  return own_procfs_file_n(path, &fd) == PROCFS_FD ? fd : -1;
}

/*
 * stat for the entries nabi serves itself.
 *
 * Most of /proc is the host's - mSL/ProcFS provides maps, cmdline, fd and the
 * rest - so a stat of those falls through and is answered there. The namespace
 * entries have no host counterpart at all, and without this `ls /proc/self/ns`
 * stops at the directory it cannot stat, however well the links inside it read.
 *
 * Returns false for anything not ours, which is the ordinary case.
 */
bool
procfs_stat(const char *path, uint32_t *mode, uint64_t *size, uint64_t *ino)
{
  int which = -1;
  enum procfs_file kind = own_procfs_file_n(path, &which);

  switch (kind) {
  case PROCFS_NSDIR:
    *mode = 0500 | 0040000;                 /* dr-x------, as Linux has it */
    *size = 0;
    *ino  = 1;
    return true;
  case PROCFS_NS:
    /* A symlink, and the length is the text it resolves to - which is what
     * anything sizing a readlink buffer will ask for. */
    {
      char text[64];
      int n = snprintf(text, sizeof text, "%s:[%llu]",
                       ns_type_name((enum ns_type) which),
                       (unsigned long long) ns_ino_of((enum ns_type) which));
      *mode = 0777 | 0120000;               /* lrwxrwxrwx */
      *size = n < 0 ? 0 : (uint64_t) n;
      *ino  = ns_ino_of((enum ns_type) which);
    }
    return true;
  default:
    return false;
  }
}

int
procfs_open(const char *path, int *out_fd)
{
  size_t len = 0;
  char *content = NULL;
  int fdno = -1;

  switch (own_procfs_file_n(path, &fdno)) {
  case PROCFS_FDDIR: {
    /*
     * /proc/self/fd as a directory, which is how a program finds out what it
     * has open so it can close the rest. libassuan does it before starting
     * gpg-agent, and pacman's "checking keyring" step is where that happens.
     *
     * The host cannot answer this, for the same reason it cannot answer
     * /proc/self/fd/<n> below and rather more sharply. Its /proc/<pid>/fd lists
     * *nabi's* descriptors - the arena, the checkpoint files, the rootfs handle
     * - which are not the guest's and whose numbers mean nothing to it. Worse,
     * the set changes while it is being read, because serving the read itself
     * opens descriptors: the guest never saw a stable listing and never
     * finished, which is what left `pacman -S` spinning in getdents64 forever
     * on a machine where mSL/ProcFS is mounted and /proc is passed through.
     *
     * A directory of symlinks is built to answer with, because that is what the
     * caller is about to readdir. The names are what matter and the names are
     * exact - one per open guest descriptor. The targets are the guest's own
     * /proc/self/fd/<n>, which resolves properly through the case below.
     */
    char dirtpl[PATH_MAX];
    const char *tmpd = getenv("TMPDIR");
    snprintf(dirtpl, sizeof dirtpl, "%s/nabi-fddir-XXXXXX",
             tmpd && *tmpd ? tmpd : "/tmp");
    if (mkdtemp(dirtpl) == NULL)
      return -1;

    procfs_fill_fddir(dirtpl);

    int dfd = open(dirtpl, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
      procfs_rmtree(dirtpl);
      return -1;
    }
    /* Unlike the temp *files* below, this cannot be unlinked the moment it is
     * open: removing a directory removes what readdir would have found in it.
     * So it is remembered against the descriptor and swept when the guest
     * closes that - and if the guest never does, the process exiting takes the
     * whole of TMPDIR's business with it either way. */
    procfs_remember_tmpdir(dfd, dirtpl);
    *out_fd = dfd;
    return 0;
  }
  case PROCFS_NSDIR: {
    /* Built the same way /proc/self/fd is: a directory of symlinks, standing in
     * for something the host has no equivalent of. The targets are the link
     * text Linux uses, so `ls -l` reads as it does anywhere else. */
    char dirtpl[PATH_MAX];
    const char *tmpd2 = getenv("TMPDIR");
    snprintf(dirtpl, sizeof dirtpl, "%s/nabi-nsdir-XXXXXX",
             tmpd2 && *tmpd2 ? tmpd2 : "/tmp");
    if (mkdtemp(dirtpl) == NULL)
      return -1;

    for (int t = 0; t < NS_COUNT; t++) {
      char name[PATH_MAX], target[64];
      snprintf(name, sizeof name, "%s/%s", dirtpl, ns_type_name((enum ns_type) t));
      snprintf(target, sizeof target, "%s:[%llu]",
               ns_type_name((enum ns_type) t),
               (unsigned long long) ns_ino_of((enum ns_type) t));
      (void) symlink(target, name);
    }

    int dfd = open(dirtpl, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { procfs_rmtree(dirtpl); return -1; }
    procfs_remember_tmpdir(dfd, dirtpl);
    *out_fd = dfd;
    return 0;
  }
  case PROCFS_NS: {
    /*
     * Opening a namespace link.
     *
     * On Linux this is an nsfs file that carries the namespace itself; here it
     * is an ordinary temporary file holding the text the link resolves to, and
     * what makes it a namespace is the note kept beside the descriptor. setns
     * asks for that note rather than reading the file, because the file is
     * only a stand-in.
     */
    char text[64];
    int n = snprintf(text, sizeof text, "%s:[%llu]\n",
                     ns_type_name((enum ns_type) fdno),
                     (unsigned long long) ns_ino_of((enum ns_type) fdno));
    if (n < 0)
      return -1;
    len = (size_t) n;
    content = malloc(len);
    if (content)
      memcpy(content, text, len);
    if (!content)
      return -1;

    const char *tmpd = getenv("TMPDIR");
    char tpl2[PATH_MAX];
    snprintf(tpl2, sizeof tpl2, "%s/nabi-ns-XXXXXX", tmpd && *tmpd ? tmpd : "/tmp");
    int nsfd = mkstemp(tpl2);
    if (nsfd < 0) { free(content); return -1; }
    unlink(tpl2);
    bool ok2 = write(nsfd, content, len) == (ssize_t) len;
    free(content);
    if (!ok2 || lseek(nsfd, 0, SEEK_SET) < 0) { close(nsfd); return -1; }

    procfs_remember_ns(nsfd, (enum ns_type) fdno,
                       ns_ino_of((enum ns_type) fdno));
    *out_fd = nsfd;
    return 0;
  }
  case PROCFS_FD: {
    /*
     * Opening /proc/self/fd/<n> reaches the *file*, not the name - which is
     * the whole point of it, and why apt uses it: it writes a signature to a
     * temp file, unlinks the name immediately, and hands sqv "/proc/self/fd/N"
     * to read instead. Passed through to the host, that path finds nabi's own
     * procfs entry, which is a directory, and apt reports the unlinked name it
     * remembers - "Reading /tmp/apt.sig.XXXXXX: No such file or directory" -
     * naming a file that was never meant to still be there.
     *
     * Darwin has no way to reopen an unlinked file, so a regular one is copied
     * into a fresh unlinked temp file: an independent description starting at
     * offset zero, which is what a real open would give and what dup() would
     * not. The read is by pread so the guest's own offset is left where it was.
     */
    if (fdno < 0 || fdno >= proc.fileinfo.vkern_fdtable.start)
      return -1;
    struct stat st;
    if (fstat(fdno, &st) < 0)
      return -1;
    if (!S_ISREG(st.st_mode)) {
      /* A pipe, socket or tty has no contents to copy and no offset to get
       * wrong; sharing the description is the closest thing to Linux here. */
      int dupped = dup(fdno);
      if (dupped < 0)
        return -1;
      *out_fd = dupped;
      return 0;
    }
    len = (size_t) st.st_size;
    content = malloc(len ? len : 1);
    if (!content)
      return -1;
    if (len && pread(fdno, content, len, 0) != (ssize_t) len) {
      free(content);
      return -1;
    }
    break;
  }
  case PROCFS_MAPS:
    content = build_maps(&len);
    break;
  case PROCFS_CMDLINE:
    /* Handed back as-is: it is already the NUL-separated form the file has. */
    if (!proc.ident.cmdline)
      return -1;
    len = proc.ident.cmdline_len;
    content = malloc(len ? len : 1);
    if (content)
      memcpy(content, proc.ident.cmdline, len);
    break;
  case PROCFS_COMM:
    content = build_comm(&len);
    break;
  case PROCFS_MOUNTS:
    content = build_mounts(&len);
    break;
  case PROCFS_RANDOM_UUID:
    content = build_random_uuid(&len);
    break;
  case PROCFS_RANDOM_BOOT_ID:
    content = build_boot_id(&len);
    break;
  case PROCFS_SYSVIPC_SHM:
  case PROCFS_SYSVIPC_SEM:
  case PROCFS_SYSVIPC_MSG:
    content = build_sysvipc(own_procfs_file_n(path, &fdno), &len);
    break;
  default:
    return -1;      /* not ours; the caller does the ordinary lookup */
  }
  if (!content)
    return -1;

  const char *tmp = getenv("TMPDIR");
  char tpl[PATH_MAX];
  snprintf(tpl, sizeof tpl, "%s/nabi-procfs-XXXXXX", tmp && *tmp ? tmp : "/tmp");
  int fd = mkstemp(tpl);
  if (fd < 0) {
    free(content);
    return -1;
  }
  unlink(tpl);      /* reachable only through the descriptor from here on */

  bool ok = len == 0 || write(fd, content, len) == (ssize_t) len;
  free(content);
  if (!ok || lseek(fd, 0, SEEK_SET) < 0) {
    close(fd);
    return -1;
  }

  *out_fd = fd;
  return 0;
}

/*
 * /proc/<pid>/exe, which is a symlink rather than a file and so arrives through
 * readlink instead of open.
 *
 * Returns the length written, or -1 for "not ours". Not NUL-terminated: readlink
 * does not terminate, and a caller that adds one would overrun the guest's
 * buffer by a byte.
 */
int
procfs_readlink(const char *path, char *buf, size_t bufsize)
{
  int fd = -1;
  const char *link;
  char fdpath[PATH_MAX];

  switch (own_procfs_file_n(path, &fd)) {
  case PROCFS_NS: {
    int n = snprintf(fdpath, sizeof fdpath, "%s:[%llu]",
                     ns_type_name((enum ns_type) fd),
                     (unsigned long long) ns_ino_of((enum ns_type) fd));
    if (n < 0 || (size_t) n > bufsize)
      return -1;
    memcpy(buf, fdpath, (size_t) n);
    return n;
  }
  case PROCFS_EXE:
    if (!proc.ident.exe)
      return -1;
    link = proc.ident.exe;
    break;
  case PROCFS_FD:
    /* The fd is open right now, by definition - the guest just named it - so
     * F_GETPATH describes the file it actually refers to. That is not true of
     * a number remembered from earlier, where the fd may have been closed and
     * the number reused, and it is why /proc/self/maps does not carry paths. */
    /* Guest fds only. NABI keeps its own descriptors at the top of the table,
     * and those are not the guest's to look at - without this bound a guest
     * could read the path of the arena, the checkpoint, or the debug sinks. */
    if (fd < 0 || fd >= proc.fileinfo.vkern_fdtable.start ||
        fcntl(fd, F_GETPATH, fdpath) < 0 || fdpath[0] == '\0')
      return -1;
    /* F_GETPATH answers in the host's terms, and the guest cannot use that
     * answer: what it reads here it will turn around and open. systemd's
     * fsync_directory_of_file opens the parent of whatever this returns, and
     * a rootfs path handed back whole sends it to /Volumes/... - a name that
     * only means something on the far side of the boundary.
     *
     * A passthrough prefix needs no translation and gets none: /Users and
     * /tmp are the same name on both sides, and none of them is under the
     * root, so the prefix test leaves them alone by construction. */
    {
      char rootpath[PATH_MAX];
      size_t rn;
      if (fcntl(proc.fileinfo.rootfd, F_GETPATH, rootpath) == 0 &&
          (rn = strlen(rootpath)) > 0) {
        while (rn > 1 && rootpath[rn - 1] == '/')
          rn--;
        if (rn > 1 && strncmp(fdpath, rootpath, rn) == 0 &&
            (fdpath[rn] == '/' || fdpath[rn] == '\0')) {
          link = fdpath[rn] ? fdpath + rn : "/";
          break;
        }
      }
    }
    link = fdpath;
    break;
  default:
    return -1;
  }

  size_t n = strlen(link);
  if (n > bufsize)
    n = bufsize;
  memcpy(buf, link, n);
  return (int) n;
}
