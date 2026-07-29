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
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
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
                   PROCFS_EXE, PROCFS_FD };

/* For PROCFS_FD, the number after /fd/. Meaningless for the others. */
static enum procfs_file
own_procfs_file_n(const char *path, int *fd_out)
{
  if (strncmp(path, "/proc/", 6) != 0)
    return PROCFS_NONE;
  const char *rest = path + 6;

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
int
procfs_open(const char *path, int *out_fd)
{
  size_t len = 0;
  char *content = NULL;
  int fdno = -1;

  switch (own_procfs_file_n(path, &fdno)) {
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
