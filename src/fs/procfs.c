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
#include "mount.h"
#include "cgroup.h"
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
                   PROCFS_EXE, PROCFS_FD, PROCFS_MOUNTS, PROCFS_FDDIR, PROCFS_TASKDIR,
                   PROCFS_RANDOM_UUID, PROCFS_RANDOM_BOOT_ID, PROCFS_NGROUPS_MAX,
                   PROCFS_NS, PROCFS_NSDIR,
                   PROCFS_SYSVIPC_SHM, PROCFS_SYSVIPC_SEM, PROCFS_SYSVIPC_MSG,
                   PROCFS_NS_FORCHILDREN, PROCFS_TIMENS_OFFSETS,
                   PROCFS_UID_MAP, PROCFS_GID_MAP, PROCFS_SETGROUPS,
                   PROCFS_MOUNTINFO, PROCFS_STAT, PROCFS_STATUS, PROCFS_CGROUP,
                   PROCFS_ATTR,
                   PROCFS_NET_DEV };

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
  /*
   * /proc/net/dev inside a network namespace, which has one interface and it
   * is down. The host's answer would list the Mac's - and by their Darwin
   * names, lo0 and en0 - which is exactly the thing a process asked to be
   * isolated from. Outside a namespace this is not ours and mSL/ProcFS answers
   * it as before.
   */
  if (netns_active() && strcmp(rest, "net/dev") == 0)
    return PROCFS_NET_DEV;

  if (strcmp(rest, "sysvipc/shm") == 0)
    return PROCFS_SYSVIPC_SHM;
  if (strcmp(rest, "sysvipc/sem") == 0)
    return PROCFS_SYSVIPC_SEM;
  if (strcmp(rest, "sysvipc/msg") == 0)
    return PROCFS_SYSVIPC_MSG;
  /*
   * The largest number of supplementary groups a process may have. Linux's own
   * number, with no Darwin sysctl behind it, so mSL/FHS's mirror of the kern.*
   * tree does not have it either.
   *
   * glibc reads it before it will size a group list, and anything that asks who
   * a user is - sudo, on every run - goes through that path. A guest that finds
   * the file missing falls back to a guess, which is survivable; it is still a
   * file every Linux has and cheaper to answer than to explain.
   */
  if (strcmp(rest, "sys/kernel/ngroups_max") == 0)
    return PROCFS_NGROUPS_MAX;
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

    /*
     * And by the number this namespace uses. Inside a pid namespace a process
     * asks about itself as /proc/1, which is not its host pid, so a comparison
     * against getpid() alone would decide the guest was asking about somebody
     * else and hand the question to the host's /proc - where pid 1 is launchd.
     */
    if (!mine && pidns_active()) {
      int m2 = snprintf(pid, sizeof pid, "%d", (int) pidns_to_ns(getpid()));
      mine = m2 > 0 && (size_t) m2 == n && strncmp(rest, pid, n) == 0;
    }
  }
  /*
   * stat and status are answered for *any* member of the namespace, not only
   * for the caller. /proc/1 is the process a container asks about most, and an
   * init whose own /proc/self/stat says 1 while everyone else's view of it says
   * its host pid would be consistent only from the inside.
   */
  if (!mine && pidns_active() && n > 0 && rest[0] >= '0' && rest[0] <= '9' &&
      (strcmp(slash, "/stat") == 0 || strcmp(slash, "/status") == 0)) {
    char numbuf[16];
    if (n < sizeof numbuf) {
      memcpy(numbuf, rest, n);
      numbuf[n] = '\0';
      int32_t host = pidns_to_host(atoi(numbuf));
      if (host >= 0) {
        if (fd_out)
          *fd_out = (int) host;
        return strcmp(slash, "/stat") == 0 ? PROCFS_STAT : PROCFS_STATUS;
      }
    }
  }

  /*
   * cgroup is answered for any pid, not only our own. Membership is recorded in
   * the procs files rather than in this process, so another process's cgroup is
   * a thing that can be looked up - and the caller that matters asks about
   * somebody else: LXC reads /proc/1/cgroup to learn the layout before it will
   * start a container, and got ENOENT because pid 1 is not us.
   */
  if (strcmp(slash, "/cgroup") == 0) {
    if (fd_out) {
      int32_t ns;
      if (mine) {
        ns = pidns_to_ns((int32_t) getpid());
      } else {
        char numbuf[16];
        ns = 1;
        if (n > 0 && n < sizeof numbuf) {
          memcpy(numbuf, rest, n);
          numbuf[n] = '\0';
          ns = (int32_t) atoi(numbuf);
        }
      }
      *fd_out = (int) ns;
    }
    return PROCFS_CGROUP;
  }

  if (!mine)
    return PROCFS_NONE;

  /*
   * stat and status carry pids in their text, and inside a pid namespace the
   * host's answer would contradict getpid() - the process would be told it is
   * pid 1 by one interface and its host pid by another, which is exactly the
   * inconsistency a renumbering has to avoid to be worth having. Outside a pid
   * namespace these are not ours and the host answers them as before.
   */
  if (pidns_active() && strcmp(slash, "/stat") == 0) {
    if (fd_out) *fd_out = (int) getpid();
    return PROCFS_STAT;
  }
  /*
   * status is ours whether or not a pid namespace is active, which stat is not.
   * The pid lines are the reason for the namespace test and they rewrite to
   * themselves outside one - pidns_to_ns is the identity there - but Threads:
   * is wrong in either case, because the host counts nabi's threads and not the
   * guest's. Leaving it to the host meant /proc/self/task and
   * /proc/self/status disagreed about the same process.
   */
  if (strcmp(slash, "/status") == 0) {
    if (fd_out) *fd_out = (int) getpid();
    return PROCFS_STATUS;
  }

  /* Which control group this process is in, as its cgroup namespace sees it.
   * Absent before there was a hierarchy, so anything asking got ENOENT. */
  if (strcmp(slash, "/mounts") == 0)  return PROCFS_MOUNTS;
  /* mountinfo is what systemd and every container runtime actually read; it
   * carries the mount id and the propagation that /proc/mounts has no room
   * for. */
  if (strcmp(slash, "/mountinfo") == 0) return PROCFS_MOUNTINFO;
  if (strcmp(slash, "/maps") == 0)    return PROCFS_MAPS;
  if (strcmp(slash, "/cmdline") == 0) return PROCFS_CMDLINE;
  if (strcmp(slash, "/comm") == 0)    return PROCFS_COMM;
  /*
   * /proc/<pid>/attr/<name>: the security contexts an LSM would keep for the
   * process. There is no LSM here and no context to keep, but the files have
   * to exist, because a caller that cannot open one cannot proceed.
   *
   * libselinux sets the context new files are created with by writing
   * /proc/thread-self/attr/fscreate, falling back to
   * /proc/self/task/<tid>/attr/fscreate. Android's init does that before
   * creating each cgroup directory, and both opens returning ENOENT is why
   * "Command 'SetupCgroups' ... failed: Failed to setup cgroups: No such file
   * or directory" - after which no controller is mounted, every process group
   * lands at /uid_0/... off the root, and init says "cpuset cgroup controller
   * is not mounted!" for the rest of its life.
   *
   * Empty, which is what Linux reads back for a process with no context, and
   * writable, which is what the caller needs. The write goes nowhere: nabi has
   * no security model to apply it to, and saying so by refusing the write
   * would fail exactly the callers this exists for.
   */
  if (strncmp(slash, "/attr/", 6) == 0 && slash[6] != '\0' &&
      strchr(slash + 6, '/') == NULL)
    return PROCFS_ATTR;
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

  /*
   * /proc/<pid>/task, which is how a program counts its own threads.
   *
   * The host's answer describes nabi: its threads are the ones running the
   * guest's vcpu and its own machinery, and the guest has never heard of them.
   * A single-threaded guest was told it had two.
   *
   * That is not cosmetic. LXC refuses to start a container in the foreground
   * from a threaded process - it counts the entries here - so `lxc-start -F`,
   * which is what waydroid runs, reported "Cannot start non-daemonized
   * container when threaded" and stopped.
   */
  if (strcmp(slash, "/task") == 0 || strcmp(slash, "/task/") == 0 ||
      strcmp(slash, "/task/.") == 0)
    return PROCFS_TASKDIR;

  /* The directory itself, which `ls /proc/self/ns` reads and which anything
   * enumerating a process's namespaces starts from. */
  if (strcmp(slash, "/ns") == 0 || strcmp(slash, "/ns/") == 0)
    return PROCFS_NSDIR;

  /*
   * /proc/<pid>/timens_offsets: what a time namespace's offsets are, and the
   * only way to set them. It describes the namespace this process's *children*
   * will be in, never the one it is in - which is why writing it is useful only
   * between an unshare and the fork that follows.
   */
  if (strcmp(slash, "/timens_offsets") == 0)
    return PROCFS_TIMENS_OFFSETS;

  /*
   * The user namespace's maps. Writing uid_map is how a process in a new user
   * namespace stops being nobody and becomes an id - there is no syscall for
   * it, so these files are the whole interface.
   */
  if (strcmp(slash, "/uid_map") == 0)   return PROCFS_UID_MAP;
  if (strcmp(slash, "/gid_map") == 0)   return PROCFS_GID_MAP;
  if (strcmp(slash, "/setgroups") == 0) return PROCFS_SETGROUPS;

  /*
   * The _for_children links, both of which can now differ from the plain one.
   * unshare leaves the caller in its own time and pid namespaces - neither a
   * clock nor a pid can be changed underneath a running process - and points
   * these at the new one instead, so this is where the effect of that unshare
   * is visible at all.
   */
  if (strcmp(slash, "/ns/time_for_children") == 0) {
    if (fd_out)
      *fd_out = NS_TIME;
    return PROCFS_NS_FORCHILDREN;
  }
  if (strcmp(slash, "/ns/pid_for_children") == 0) {
    if (fd_out)
      *fd_out = NS_PID;
    return PROCFS_NS_FORCHILDREN;
  }

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
  /* From the mount table now rather than a fixed string, which could only ever
   * describe the day it was written and never a mount the guest had made. */
  char buf[8192];
  int n = mount_build_mounts(buf, sizeof buf);
  if (n < 0)
    return NULL;
  char *out = malloc((size_t) n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, (size_t) n);
  *len_out = (size_t) n;
  return out;
}

static char *
build_mountinfo(size_t *len_out)
{
  char buf[8192];
  int n = mount_build_mountinfo(buf, sizeof buf);
  if (n < 0)
    return NULL;
  char *out = malloc((size_t) n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, (size_t) n);
  *len_out = (size_t) n;
  return out;
}

/*
 * Which namespace a link names: the one this process is in, or - for the
 * _for_children forms - the one its children will be. Only time can differ,
 * and only between an unshare(CLONE_NEWTIME) and the fork that follows it.
 */
static uint64_t
ns_link_ino(enum procfs_file kind, enum ns_type t)
{
  if (kind == PROCFS_NS_FORCHILDREN) {
    if (t == NS_TIME)
      return ns_ino_time_for_children();
    if (t == NS_PID)
      return ns_ino_pid_for_children();
  }
  return ns_ino_of(t);
}

/* Read a file of the host's /proc for this process. */
static char *
slurp_host_proc(int host_pid, const char *leaf, size_t *len_out)
{
  char path[PATH_MAX];
  snprintf(path, sizeof path, "/proc/%d/%s", host_pid, leaf);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return NULL;
  size_t cap = 8192, len = 0;
  char *buf = malloc(cap);
  if (!buf) {
    close(fd);
    return NULL;
  }
  ssize_t n;
  while ((n = read(fd, buf + len, cap - len - 1)) > 0) {
    len += (size_t) n;
    if (len + 1 >= cap) {
      char *bigger = realloc(buf, cap *= 2);
      if (!bigger)
        break;
      buf = bigger;
    }
  }
  close(fd);
  buf[len] = '\0';
  *len_out = len;
  return buf;
}

/*
 * /proc/<pid>/stat with its pid fields put through the namespace.
 *
 * The host's line is taken and four numbers in it are rewritten - pid, ppid,
 * process group and session - rather than the whole thing being invented here.
 * Everything else in those 52 fields is true of this process and nabi has no
 * better answer for any of it; rewriting only what the namespace changes keeps
 * the rest honest.
 *
 * Field 2 is the command in parentheses and may contain spaces, so the parse
 * starts after the last ')' - which is how everything that reads this file
 * does it, and for the same reason.
 */
static char *
build_stat(int host_pid, size_t *len_out)
{
  size_t hlen;
  char *host = slurp_host_proc(host_pid, "stat", &hlen);
  if (!host)
    return NULL;

  char *rp = strrchr(host, ')');
  if (!rp) {
    free(host);
    return NULL;
  }

  /* The fields after the comm: state, ppid, pgrp, session, then the rest. */
  char state[8] = "S";
  long ppid = 0, pgrp = 0, sess = 0;
  const char *rest = "";
  {
    char *p = rp + 1;
    while (*p == ' ') p++;
    int i = 0;
    while (*p && *p != ' ' && i < (int) sizeof state - 1) state[i++] = *p++;
    state[i] = '\0';
    char *end;
    ppid = strtol(p, &end, 10); p = end;
    pgrp = strtol(p, &end, 10); p = end;
    sess = strtol(p, &end, 10); p = end;
    while (*p == ' ') p++;
    rest = p;
  }

  /* comm, with its parentheses, exactly as the host gave it. */
  char *lp = strchr(host, '(');
  char comm[64] = "(nabi)";
  if (lp && rp > lp) {
    size_t n = (size_t) (rp - lp) + 1;
    if (n >= sizeof comm) n = sizeof comm - 1;
    memcpy(comm, lp, n);
    comm[n] = '\0';
  }

  char *out = malloc(hlen + 128);
  if (!out) {
    free(host);
    return NULL;
  }
  int n = snprintf(out, hlen + 128, "%d %s %s %d %d %d %s",
                   (int) pidns_to_ns(host_pid), comm, state,
                   (int) pidns_to_ns((int32_t) ppid),
                   (int) pidns_to_ns((int32_t) pgrp),
                   (int) pidns_to_ns((int32_t) sess), rest);
  free(host);
  if (n < 0) {
    free(out);
    return NULL;
  }
  *len_out = (size_t) n;
  return out;
}

/* The same idea for status, which carries the pids as labelled lines. */
static char *
build_status(int host_pid, size_t *len_out)
{
  size_t hlen;
  char *host = slurp_host_proc(host_pid, "status", &hlen);
  if (!host)
    return NULL;

  size_t cap = hlen + 256;
  char *out = malloc(cap);
  if (!out) {
    free(host);
    return NULL;
  }
  size_t len = 0;
  char *line = host;
  while (*line) {
    char *nl = strchr(line, '\n');
    size_t llen = nl ? (size_t) (nl - line) : strlen(line);

    int written = -1;
    if (strncmp(line, "Pid:", 4) == 0)
      written = snprintf(out + len, cap - len, "Pid:\t%d\n",
                         (int) pidns_to_ns(host_pid));
    else if (strncmp(line, "Tgid:", 5) == 0)
      written = snprintf(out + len, cap - len, "Tgid:\t%d\n",
                         (int) pidns_to_ns(host_pid));
    else if (strncmp(line, "Threads:", 8) == 0) {
      /*
       * The host's count is nabi's threads, not the guest's - the same
       * mismatch /proc/<pid>/task carries, and read by the same programs.
       *
       * Counted from the task list rather than taken from proc.nr_tasks,
       * because the two disagree: nr_tasks is not reset along the resume path,
       * so a freshly exec'd child reported three threads while its list held
       * one. The list is what /proc/<pid>/task is built from, and the two files
       * describing the same thing differently is worse than either being wrong.
       */
      int n = 0;
      struct list_head *tp;
      list_for_each (tp, &proc.tasks)
        n++;
      written = snprintf(out + len, cap - len, "Threads:\t%d\n", n > 0 ? n : 1);
    }
    else if (strncmp(line, "PPid:", 5) == 0)
      /* Translate the parent the host reported, rather than assuming it is
       * ours - this file is served for any member of the namespace. A parent
       * outside it has no pid in it, and 0 is what Linux shows for that. */
      written = snprintf(out + len, cap - len, "PPid:\t%d\n",
                         (int) pidns_to_ns((int32_t) atoi(line + 5)));
    if (written < 0) {
      if (len + llen + 2 > cap)
        break;
      memcpy(out + len, line, llen);
      len += llen;
      out[len++] = '\n';
    } else {
      len += (size_t) written;
    }
    if (!nl)
      break;
    line = nl + 1;
  }
  free(host);
  *len_out = len;
  return out;
}

/* One interface, no traffic: what a namespace nobody has configured contains. */
static char *
build_net_dev(size_t *len_out)
{
  static const char text[] =
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n";
  size_t len = sizeof text - 1;
  char *out = malloc(len);
  if (!out)
    return NULL;
  memcpy(out, text, len);
  *len_out = len;
  return out;
}

static char *
build_cgroup(int32_t nspid, size_t *len_out)
{
  char buf[CGROUP_PATH_MAX + 16];
  int n = cgroup_proc_text_for(nspid, buf, sizeof buf);
  if (n < 0)
    return NULL;
  char *out = malloc((size_t) n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, (size_t) n);
  *len_out = (size_t) n;
  return out;
}

static char *
build_userns(enum procfs_file which, size_t *len_out)
{
  char buf[256];
  int n = which == PROCFS_SETGROUPS ? userns_setgroups_read(buf, sizeof buf)
                                    : userns_map_read(which == PROCFS_GID_MAP,
                                                      buf, sizeof buf);
  if (n < 0)
    return NULL;
  if ((size_t) n > sizeof buf)
    n = (int) sizeof buf;
  char *out = malloc((size_t) n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, (size_t) n);
  *len_out = (size_t) n;
  return out;
}

static char *
build_timens_offsets(size_t *len_out)
{
  char buf[128];
  int n = timens_offsets_read(buf, sizeof buf);
  if (n < 0)
    return NULL;
  char *out = malloc((size_t) n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, (size_t) n);
  *len_out = (size_t) n;
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

  {
    enum sysv_kind kind = which == PROCFS_SYSVIPC_SHM ? SYSV_SHM
                        : which == PROCFS_SYSVIPC_SEM ? SYSV_SEM : SYSV_MSG;
    struct sysv_meta *all = calloc(SYSV_MAX_ID, sizeof *all);
    if (all) {
      int n = sysv_list(kind, all, SYSV_MAX_ID);
      if (n > SYSV_MAX_ID)
        n = SYSV_MAX_ID;
      for (int i = 0; i < n; i++) {
        char row[512];
        int rn;
        if (kind == SYSV_MSG) {
          uint64_t qnum, cbytes;
          sysv_msg_stats(all[i].host_id, &qnum, &cbytes);
          rn = snprintf(row, sizeof row,
                        "%10d %10d  %4o %10llu %10llu %5u %5u %5u %5u %5u %5u %10lld %10lld %10lld\n",
                        all[i].key, all[i].host_id, all[i].mode,
                        (unsigned long long) cbytes,
                        (unsigned long long) qnum,
                        (unsigned) all[i].lpid, (unsigned) all[i].lpid,
                        all[i].uid, all[i].gid, all[i].cuid, all[i].cgid,
                        (long long) all[i].atime, (long long) all[i].dtime,
                        (long long) all[i].ctime);
        } else if (kind == SYSV_SHM)
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
 * Linux's NGROUPS_MAX, which is what the kernel would let a process have. The
 * number is Linux's own and has been 65536 since 2.6.4; nothing here enforces
 * it, so reporting anything else would only mislead a caller sizing an array.
 */
static char *
build_ngroups_max(size_t *len)
{
  char *out = malloc(16);
  if (out == NULL)
    return NULL;
  *len = (size_t) snprintf(out, 16, "65536\n");
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

/*
 * Descriptors on /proc/<pid>/timens_offsets, which is the one file here a guest
 * writes rather than reads.
 *
 * The file it was handed is a temporary stand-in holding the current text, so a
 * write that landed in it would be recorded nowhere and reported as a success -
 * the guest would set an offset, read it back from its own copy, and find the
 * clocks unmoved. The descriptor is noted instead and write(2) is diverted to
 * the namespace itself.
 */
KHASH_MAP_INIT_INT(timensfd, int)
static khash_t(timensfd) *timens_fds;

static void
procfs_remember_writable(int fd, enum procfs_file which)
{
  int ret;
  if (timens_fds == NULL)
    timens_fds = kh_init(timensfd);
  khiter_t k = kh_put(timensfd, timens_fds, fd, &ret);
  kh_value(timens_fds, k) = (int) which;
}

/* Whether a write to this descriptor is really a write to a time namespace,
 * and if so what came of it. */
bool
procfs_write_timens(int fd, const char *buf, size_t size, int *out)
{
  if (timens_fds == NULL)
    return false;
  khiter_t k = kh_get(timensfd, timens_fds, fd);
  if (k == kh_end(timens_fds))
    return false;

  char text[512];
  size_t n = size < sizeof text - 1 ? size : sizeof text - 1;
  memcpy(text, buf, n);
  text[n] = '\0';

  int r;
  switch ((enum procfs_file) kh_value(timens_fds, k)) {
  case PROCFS_UID_MAP:    r = userns_map_write(false, text); break;
  case PROCFS_GID_MAP:    r = userns_map_write(true, text);  break;
  case PROCFS_SETGROUPS:  r = userns_setgroups_write(text);  break;
  default:                r = timens_offsets_write(text);    break;
  }
  *out = r < 0 ? r : (int) size;
  return true;
}

/*
 * Carry these notes across a dup.
 *
 * They are keyed by descriptor number, and a descriptor number is exactly what
 * dup changes. `echo > /proc/self/timens_offsets` opens the file, dup2s it onto
 * stdout and closes the original, so the write arrived on a descriptor with no
 * note against it and went to the stand-in file instead of the namespace - the
 * shell reported success and nothing had happened, which is the worst of the
 * available outcomes. The same applies to a namespace descriptor handed to
 * setns after being dup'd.
 */
void
procfs_dup_fd(int oldfd, int newfd)
{
  int ret;

  if (oldfd == newfd)
    return;                     /* dup2(fd, fd) changes nothing */

  /*
   * The destination is overwritten, so whatever it used to be it is not that
   * any more. Clearing first is not tidiness: a shell redirect ends by dup2ing
   * the saved stdout back over descriptor 1, and without this the note stayed
   * on 1 and every subsequent `echo` in that shell was diverted into the
   * namespace parser - the first write worked and the whole session broke
   * afterwards.
   */
  procfs_close_fd(newfd);

  if (nsfd_notes != NULL) {
    khiter_t k = kh_get(nsfd, nsfd_notes, oldfd);
    if (k != kh_end(nsfd_notes)) {
      struct ns_note note = kh_value(nsfd_notes, k);
      khiter_t n = kh_put(nsfd, nsfd_notes, newfd, &ret);
      kh_value(nsfd_notes, n) = note;
    }
  }
  if (timens_fds != NULL) {
    khiter_t k = kh_get(timensfd, timens_fds, oldfd);
    if (k != kh_end(timens_fds)) {
      /* The value as well as the key: it says *which* file this is, and a copy
       * that carried only the key had every map write arriving at the time
       * namespace's parser instead, which refused it. */
      int which = kh_value(timens_fds, k);
      khiter_t n = kh_put(timensfd, timens_fds, newfd, &ret);
      kh_value(timens_fds, n) = which;
    }
  }
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
  if (timens_fds != NULL) {
    khiter_t tk = kh_get(timensfd, timens_fds, fd);
    if (tk != kh_end(timens_fds))
      kh_del(timensfd, timens_fds, tk);
  }
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
procfs_stat(const char *path, bool nofollow, uint32_t *mode, uint64_t *size,
            uint64_t *ino)
{
  int which = -1;
  enum procfs_file kind = own_procfs_file_n(path, &which);

  switch (kind) {
  case PROCFS_EXE:
    /*
     * Only for a caller that asked not to follow. Following it reaches the
     * program itself, and resolution has already rewritten the path to get
     * there, so this is the lstat case alone - where the answer is the link.
     */
    if (!nofollow || proc.ident.exe == NULL)
      return false;
    *mode = 0777 | 0120000;                 /* lrwxrwxrwx */
    *size = strlen(proc.ident.exe);
    *ino  = 3;
    return true;
  case PROCFS_NSDIR:
    *mode = 0500 | 0040000;                 /* dr-x------, as Linux has it */
    *size = 0;
    *ino  = 1;
    return true;
  case PROCFS_NS_FORCHILDREN:
  case PROCFS_NS:
    /* A symlink, and the length is the text it resolves to - which is what
     * anything sizing a readlink buffer will ask for. */
    {
      uint64_t nsino = ns_link_ino(kind, (enum ns_type) which);
      char text[64];
      int n = snprintf(text, sizeof text, "%s:[%llu]",
                       ns_type_name((enum ns_type) which),
                       (unsigned long long) nsino);
      *mode = 0777 | 0120000;               /* lrwxrwxrwx */
      *size = n < 0 ? 0 : (uint64_t) n;
      *ino  = nsino;
    }
    return true;
  case PROCFS_TIMENS_OFFSETS:
  case PROCFS_UID_MAP:
  case PROCFS_GID_MAP:
  case PROCFS_SETGROUPS:
    /* Writable, and that is not decoration: writing these is the only way to
     * set a time namespace's offsets or a user namespace's maps. */
    *mode = 0644 | 0100000;
    *size = 0;
    *ino  = 2;
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
  case PROCFS_TASKDIR: {
    /*
     * One entry per guest task, named by its thread id, as directories -
     * which is what they are on Linux, and what anything walking into
     * /proc/self/task/<tid> expects to find.
     */
    char dirtpl[PATH_MAX];
    const char *tmpd = getenv("TMPDIR");
    snprintf(dirtpl, sizeof dirtpl, "%s/nabi-taskdir-XXXXXX",
             tmpd && *tmpd ? tmpd : "/tmp");
    if (mkdtemp(dirtpl) == NULL)
      return -1;

    struct list_head *p;
    list_for_each (p, &proc.tasks) {
      struct task *t = list_entry(p, struct task, head);
      char name[PATH_MAX];
      snprintf(name, sizeof name, "%s/%d", dirtpl,
               (int) pidns_to_ns((int32_t) t->tid));
      (void) mkdir(name, 0555);
    }

    int dfd = open(dirtpl, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
      procfs_rmtree(dirtpl);
      return -1;
    }
    procfs_remember_tmpdir(dfd, dirtpl);
    *out_fd = dfd;
    return 0;
  }

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
    /* Linux lists these beside the plain ones, and software walking the
     * directory expects to find them. */
    for (int k = 0; k < 2; k++) {
      enum ns_type t = k == 0 ? NS_PID : NS_TIME;
      char name[PATH_MAX], target[64];
      snprintf(name, sizeof name, "%s/%s_for_children", dirtpl, ns_type_name(t));
      snprintf(target, sizeof target, "%s:[%llu]", ns_type_name(t),
               (unsigned long long) ns_link_ino(PROCFS_NS_FORCHILDREN, t));
      (void) symlink(target, name);
    }

    int dfd = open(dirtpl, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { procfs_rmtree(dirtpl); return -1; }
    procfs_remember_tmpdir(dfd, dirtpl);
    *out_fd = dfd;
    return 0;
  }
  case PROCFS_NS_FORCHILDREN:
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
    uint64_t ino = ns_link_ino(own_procfs_file_n(path, &fdno),
                               (enum ns_type) fdno);
    char text[64];
    int n = snprintf(text, sizeof text, "%s:[%llu]\n",
                     ns_type_name((enum ns_type) fdno),
                     (unsigned long long) ino);
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

    procfs_remember_ns(nsfd, (enum ns_type) fdno, ino);
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
  case PROCFS_ATTR:
    /* No context to report. The descriptor is a writable temporary file like
     * every other entry here, so a write lands somewhere harmless. */
    content = strdup("");
    len = 0;
    break;
  case PROCFS_MOUNTS:
    content = build_mounts(&len);
    break;
  case PROCFS_MOUNTINFO:
    content = build_mountinfo(&len);
    break;
  case PROCFS_CGROUP:
    content = build_cgroup(fdno, &len);
    break;
  case PROCFS_NET_DEV:
    content = build_net_dev(&len);
    break;
  case PROCFS_STAT:
    content = build_stat(fdno, &len);
    break;
  case PROCFS_STATUS:
    content = build_status(fdno, &len);
    break;
  case PROCFS_NGROUPS_MAX:
    content = build_ngroups_max(&len);
    break;
  case PROCFS_RANDOM_UUID:
    content = build_random_uuid(&len);
    break;
  case PROCFS_RANDOM_BOOT_ID:
    content = build_boot_id(&len);
    break;
  case PROCFS_TIMENS_OFFSETS:
    content = build_timens_offsets(&len);
    break;
  case PROCFS_UID_MAP:
  case PROCFS_GID_MAP:
  case PROCFS_SETGROUPS:
    content = build_userns(own_procfs_file_n(path, &fdno), &len);
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

  {
    enum procfs_file w = own_procfs_file_n(path, &fdno);
    if (w == PROCFS_TIMENS_OFFSETS || w == PROCFS_UID_MAP ||
        w == PROCFS_GID_MAP || w == PROCFS_SETGROUPS)
      procfs_remember_writable(fd, w);
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

  enum procfs_file kind = own_procfs_file_n(path, &fd);
  switch (kind) {
  case PROCFS_NS_FORCHILDREN:
  case PROCFS_NS: {
    int n = snprintf(fdpath, sizeof fdpath, "%s:[%llu]",
                     ns_type_name((enum ns_type) fd),
                     (unsigned long long) ns_link_ino(kind, (enum ns_type) fd));
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
    /*
     * F_GETPATH answers in the host's terms, and the guest cannot use that
     * answer: what it reads here it will turn around and open. systemd's
     * fsync_directory_of_file opens the parent of whatever this returns, and
     * a rootfs path handed back whole sends it to /Volumes/... - a name that
     * only means something on the far side of the boundary.
     *
     * A mount is asked about first, and that is not a detail. A file reached
     * through a bind mount has two names, and the one the guest opened it by
     * is the mount's - stripping the rootfs prefix instead gives the name
     * underneath, which is a different place as far as anything checking
     * paths is concerned. Android mounts every APEX that way, and bionic's
     * linker reads this link to learn where a library really came from: it saw
     * /system/apex/com.android.runtime/lib64/bionic/libc.so where its own
     * configuration permits /apex/com.android.runtime/lib64/bionic, decided
     * libc was outside the namespace, and refused to link anything at all.
     *
     * A passthrough prefix needs no translation and gets none: /Users and
     * /tmp are the same name on both sides.
     */
    {
      static char gbuf[LINUX_PATH_MAX];
      if (guest_path_of_host(fdpath, gbuf, sizeof gbuf)) {
        link = gbuf;
        break;
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

/*
 * The executable /proc/<pid>/exe names, as a guest path.
 *
 * Answered during path resolution so that the name behaves like the symlink it
 * is: stat, access and open all reach the program, which is what they reach on
 * Linux. readlink is served before resolution, so the link itself still reads
 * back as a link rather than as whatever it points at.
 *
 * Only ever this process's own, because own_procfs_file_n refuses a pid that is
 * not ours - another process's executable is not something nabi knows. The
 * host's procfs cannot answer any of this: from its side the executable of
 * every one of these processes is the emulator.
 *
 * Android's apexd is what found it missing. It stats /proc/self/exe during
 * start-up, got ENOENT, and aborted - which init reports as
 * "reboot,bootloader,bootstrap-apexd-failed", three steps from the cause.
 */
bool
procfs_exe_path(const char *name, char *out, size_t outsz)
{
  int which = -1;
  if (own_procfs_file_n(name, &which) != PROCFS_EXE)
    return false;
  if (proc.ident.exe == NULL || proc.ident.exe[0] == '\0')
    return false;
  return strlcpy(out, proc.ident.exe, outsz) < outsz;
}

/*
 * Rewrite /proc/<pid>/... from this namespace's numbering into the host's.
 *
 * Without it, a container asking about /proc/1 reaches the host's pid 1, which
 * is launchd - a confusing answer rather than a wrong one, but confusing in the
 * direction that matters, since pid 1 is precisely the process a container
 * cares about. A number that names no member of the namespace is refused, which
 * is the containment half: the host's processes stay visible in the listing,
 * which is not nabi's to hide, but they cannot be *asked about* by number.
 *
 * Returns false for a path this has nothing to say about, which is every path
 * outside a pid namespace.
 */
bool
procfs_pidns_path(const char *name, char *out, size_t outsz, bool *denied)
{
  *denied = false;
  if (!pidns_active())
    return false;
  if (strncmp(name, "/proc/", 6) != 0)
    return false;

  const char *p = name + 6;
  if (*p < '0' || *p > '9')
    return false;               /* /proc/self and the rest are not ours here */

  char *end;
  long nspid = strtol(p, &end, 10);
  if (end == p || (*end != '\0' && *end != '/'))
    return false;

  int32_t host = pidns_to_host((int32_t) nspid);
  if (host < 0) {
    *denied = true;             /* not a member: it does not exist here */
    return true;
  }
  snprintf(out, outsz, "/proc/%d%s", (int) host, end);
  return true;
}
