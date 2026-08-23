/*
 * Control groups, and the namespace that rebases the view of them.
 *
 * Every previous note in this series said the same thing about this one:
 * "nothing to isolate; there are no cgroups". That was true, and the way to
 * make the namespace mean something is to give it a hierarchy - as the mount
 * namespace needed mount(2) and the IPC namespace needed objects of its own.
 *
 * What is provided, and what deliberately is not:
 *
 *   The hierarchy is real. Cgroups are directories, a process is a member of
 *   exactly one, membership is inherited across fork, and /proc/<pid>/cgroup
 *   answers with it. All of that is bookkeeping nabi can keep honestly.
 *
 *   The controllers are not, and there are none. `cgroup.controllers` is empty
 *   and a write to `cgroup.subtree_control` is refused, so there is no
 *   memory.max, no cpu.max, no pids.max - not as files that accept a number and
 *   ignore it, but absent. Darwin gives an unprivileged process no CPU
 *   bandwidth control, no memory accounting it could enforce and no io control,
 *   so a limit written here could never be applied. A cgroup that took the
 *   number and did nothing would be the worst thing in this file: the caller
 *   would believe it was bounded and nothing would ever say otherwise.
 *
 * A hierarchy with no controllers enabled is an ordinary cgroup v2
 * configuration, not an invention - it is what a machine looks like when
 * cgroups are used to organise processes rather than to constrain them, which
 * is exactly and only what this can do.
 *
 * The namespace itself is then what it is on Linux, and is exact: it rebases
 * paths. A process in /foo that unshares sees itself in "/", and everything
 * below /foo relative to that, while its actual cgroup is unchanged. That is
 * the whole of what a cgroup namespace does, and none of it needs a controller.
 */
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "cgroup.h"

#include "linux/common.h"
#include "linux/errno.h"

/* Where this process is. Inherited across fork through the checkpoint. */
static char current_cgroup[CGROUP_PATH_MAX] = "/";

/*
 * The hierarchy's directory, by its canonical path.
 *
 * realpath rather than TMPDIR as it stands, because the two differ: TMPDIR is
 * /var/folders/... and /var is a symlink, so F_GETPATH - which is how a write
 * to cgroup.procs is recognised as one - answers /private/var/folders/....
 * Compared against the unresolved form nothing ever matched, and joining a
 * cgroup wrote the pid into an ordinary file and moved no one.
 */
void
cgroup_root_dir(char *out, size_t n)
{
  static char base[PATH_MAX];
  if (base[0] == '\0') {
    const char *tmp = getenv("TMPDIR");
    const char *want = tmp && *tmp ? tmp : "/tmp";
    if (realpath(want, base) == NULL)
      snprintf(base, sizeof base, "%s", want);
    /* realpath keeps no trailing slash, but TMPDIR often has one. */
    size_t bl = strlen(base);
    while (bl > 1 && base[bl - 1] == '/')
      base[--bl] = '\0';
  }
  snprintf(out, n, "%s/nabi-cgroup-%s", base, nabi_boot_tag());
}

const char *
cgroup_current(void)
{
  return current_cgroup;
}

void
cgroup_set_current(const char *path)
{
  snprintf(current_cgroup, sizeof current_cgroup, "%s",
           path && *path ? path : "/");
}

/*
 * The three files every cgroup has, and only those three.
 *
 * cgroup.controllers is empty and is the honest part: it is how a caller asks
 * what this hierarchy can do, and the answer is "organise processes". Anything
 * that would go on to write memory.max reads this first and finds nothing to
 * enable.
 */
void
cgroup_populate(const char *dir)
{
  static const struct { const char *name, *body; } files[] = {
    { "cgroup.controllers",     "" },
    { "cgroup.subtree_control", "" },
    { "cgroup.procs",           "" },
    { "cgroup.type",            "domain\n" },
  };
  char path[PATH_MAX];
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(path, sizeof path, "%s/%s", dir, files[i].name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
      continue;
    size_t n = strlen(files[i].body);
    if (n)
      (void) !write(fd, files[i].body, n);
    close(fd);
  }
}

/* Make the hierarchy if it is not there, and return its host directory. */
int
cgroup_hierarchy(char *out, size_t n)
{
  cgroup_root_dir(out, n);
  if (mkdir(out, 0755) < 0 && errno != EEXIST)
    return -darwin_to_linux_errno(errno);
  cgroup_populate(out);
  return 0;
}

/* Whether `dir` is inside the hierarchy, so that a mkdir there is a new cgroup
 * rather than an ordinary directory. */
bool
cgroup_is_hierarchy_path(const char *hostpath)
{
  char root[PATH_MAX];
  cgroup_root_dir(root, sizeof root);
  size_t n = strlen(root);
  return strncmp(hostpath, root, n) == 0 &&
         (hostpath[n] == '\0' || hostpath[n] == '/');
}

/*
 * What /proc/<pid>/cgroup says: the cgroup this process is in, as seen from the
 * namespace it is in.
 *
 * Rebasing is the entire function of a cgroup namespace. A process whose cgroup
 * is /foo/bar, in a namespace rooted at /foo, is in /bar - and one whose cgroup
 * has escaped the namespace root (which cannot happen by moving, only by the
 * root being removed) falls back to "/", as Linux does.
 */
static bool find_in_tree(const char *dir, const char *rel, int32_t nspid,
                         char *out, size_t n);

int
cgroup_proc_text(char *out, size_t n)
{
  /*
   * The files first, and the shortcut only when they have nothing to say.
   *
   * A process can be moved by another one - init moves every service it
   * starts - and the process being moved is not told. Reading current_cgroup
   * would have it report where it used to be, and disagree with what
   * /proc/<its own pid>/cgroup says about it from anywhere else. The fallback
   * is for a process that has never been written into a procs file at all: a
   * forked child, which is in its parent's cgroup by inheritance.
   */
  char found[CGROUP_PATH_MAX];
  char hroot[PATH_MAX];
  cgroup_root_dir(hroot, sizeof hroot);
  const char *mine = current_cgroup;
  if (find_in_tree(hroot, "", pidns_to_ns((int32_t) getpid()),
                   found, sizeof found))
    mine = found;

  const char *root = cgroup_ns_root();

  const char *shown = mine;
  size_t rlen = strlen(root);
  if (rlen > 1 && strncmp(mine, root, rlen) == 0 &&
      (mine[rlen] == '\0' || mine[rlen] == '/'))
    shown = mine[rlen] == '\0' ? "/" : mine + rlen;
  else if (rlen > 1)
    shown = "/";

  /* One line, hierarchy id 0 and no controller name: the cgroup v2 form. */
  return snprintf(out, n, "0::%s\n", shown);
}

/*
 * The cgroup a *given* pid is in, for /proc/<pid>/cgroup.
 *
 * Membership lives in the procs files rather than in this process, which is
 * what makes another process's cgroup answerable at all: current_cgroup is only
 * the shortcut this one keeps for itself, and nabi's processes do not share
 * memory. So the hierarchy is walked and the files are read - they are the
 * record, and procs_file_update above is what writes them.
 *
 * A pid found nowhere is at the root, which is where a process that has never
 * been moved is. That is also the answer for pid 1: there is no init here to
 * have been moved, and LXC reads /proc/1/cgroup to learn the layout rather than
 * to learn about init.
 */
static bool
find_in_tree(const char *dir, const char *rel, int32_t nspid,
             char *out, size_t n)
{
  char procs[PATH_MAX];
  snprintf(procs, sizeof procs, "%s/cgroup.procs", dir);
  int fd = open(procs, O_RDONLY);
  if (fd >= 0) {
    char body[4096];
    ssize_t got = read(fd, body, sizeof body - 1);
    close(fd);
    if (got > 0) {
      body[got] = '\0';
      for (char *line = body; *line; ) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (*line && atoi(line) == nspid) {
          snprintf(out, n, "%s", rel[0] ? rel : "/");
          return true;
        }
        if (!nl) break;
        line = nl + 1;
      }
    }
  }

  DIR *d = opendir(dir);
  if (d == NULL)
    return false;
  struct dirent *e;
  bool found = false;
  while (!found && (e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.')
      continue;
    char sub[PATH_MAX], subrel[CGROUP_PATH_MAX];
    snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name);
    struct stat st;
    if (stat(sub, &st) < 0 || !S_ISDIR(st.st_mode))
      continue;
    snprintf(subrel, sizeof subrel, "%s/%s", rel, e->d_name);
    found = find_in_tree(sub, subrel, nspid, out, n);
  }
  closedir(d);
  return found;
}

int
cgroup_proc_text_for(int32_t nspid, char *out, size_t n)
{
  if (nspid == pidns_to_ns((int32_t) getpid()))
    return cgroup_proc_text(out, n);

  char root[PATH_MAX];
  cgroup_root_dir(root, sizeof root);

  char path[CGROUP_PATH_MAX] = "/";
  (void) find_in_tree(root, "", nspid, path, sizeof path);

  /* Reported the same way as our own: relative to the namespace's root. */
  const char *nsroot = cgroup_ns_root();
  const char *shown = path;
  size_t rlen = strlen(nsroot);
  if (rlen > 1 && strncmp(path, nsroot, rlen) == 0 &&
      (path[rlen] == '\0' || path[rlen] == '/'))
    shown = path[rlen] == '\0' ? "/" : path + rlen;
  else if (rlen > 1)
    shown = "/";

  return snprintf(out, n, "0::%s\n", shown);
}

/*
 * Moving a process, which is what writing to cgroup.procs does.
 *
 * Any process, not only this one. Moving another was refused for a while on the
 * grounds that membership lived in the process being moved, and that was never
 * quite true: the procs files are the record - it is what makes
 * /proc/<pid>/cgroup answerable for a pid that is not us - and a file can be
 * written on any process's behalf. current_cgroup is a shortcut this process
 * keeps for itself, not the thing being changed.
 *
 * Refusing it stopped Android before it started. init puts each service it
 * forks into a cgroup of its own by writing the child's pid, which is what
 * every process manager does and the ordinary use of the file; with the write
 * refused, createProcessGroup failed for every service and init rebooted.
 */
/* Add or remove a pid in a cgroup's procs file, so that reading it back shows
 * what joining it did. The file is the record; current_cgroup is the shortcut
 * this process keeps for itself. */
static void
procs_file_update(const char *cgroup_path, int32_t nspid, bool add)
{
  char root[PATH_MAX], path[PATH_MAX];
  cgroup_root_dir(root, sizeof root);
  snprintf(path, sizeof path, "%s%s/cgroup.procs", root,
           strcmp(cgroup_path, "/") == 0 ? "" : cgroup_path);

  char body[4096] = "";
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, body, sizeof body - 1);
    close(fd);
    if (n > 0)
      body[n] = '\0';
  }

  char out[4096];
  size_t len = 0;
  char want[16];
  snprintf(want, sizeof want, "%d", (int) nspid);
  for (char *line = body; *line; ) {
    char *nl = strchr(line, '\n');
    size_t llen = nl ? (size_t) (nl - line) : strlen(line);
    if (llen && !(llen == strlen(want) && strncmp(line, want, llen) == 0) &&
        len + llen + 2 < sizeof out) {
      memcpy(out + len, line, llen);
      len += llen;
      out[len++] = '\n';
    }
    if (!nl)
      break;
    line = nl + 1;
  }
  if (add && len + strlen(want) + 2 < sizeof out)
    len += (size_t) snprintf(out + len, sizeof out - len, "%s\n", want);

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return;
  if (len)
    (void) !write(fd, out, len);
  close(fd);
}

/*
 * Whether a write is really a move between control groups.
 *
 * Recognised by the file's path rather than by a note kept against the
 * descriptor: cgroup.procs is an ordinary file that stays where it is, so
 * F_GETPATH answers reliably and a dup carries it for free - which is the part
 * that had to be fixed twice when the note was keyed by descriptor number.
 */
/*
 * Reading cgroup.procs, with the dead left out.
 *
 * Linux takes a process out of its cgroup when it exits; nothing here does,
 * because membership is a line in a file and a process that dies writes
 * nothing. So the file went on naming processes that were gone, and a caller
 * that believes it is the one thing that cannot make progress: libprocessgroup
 * kills a cgroup by reading this file and signalling what it finds, and a pid
 * that answers ESRCH for ever is a loop it never leaves - "getpgid(30) failed:
 * No such process" over and over, then "Failed to kill process cgroup, 1
 * processes remain".
 *
 * Filtered on the way out rather than cleaned up on the way in, because a
 * process does not always get to say it is leaving: one killed outright runs
 * no exit path at all, and its line would stay for as long as the cgroup did.
 * The file is small and read rarely.
 */
bool
cgroup_read_procs(int fd, char *out, size_t size, int *ret)
{
  char path[PATH_MAX];
  if (fcntl(fd, F_GETPATH, path) < 0)
    return false;
  if (!cgroup_is_hierarchy_path(path))
    return false;
  const char *base = strrchr(path, '/');
  if (base == NULL || strcmp(base, "/cgroup.procs") != 0)
    return false;

  char body[4096] = "";
  int rfd = open(path, O_RDONLY);
  if (rfd >= 0) {
    ssize_t n = read(rfd, body, sizeof body - 1);
    close(rfd);
    if (n > 0)
      body[n] = '\0';
  }

  char live[4096];
  size_t len = 0;
  for (char *line = body; *line; ) {
    char *nl = strchr(line, '\n');
    if (nl != NULL)
      *nl = '\0';
    if (*line != '\0') {
      int32_t nspid = (int32_t) atoi(line);
      int32_t host = pidns_to_host(nspid);
      /*
       * getpgid rather than kill(pid, 0), because a zombie answers the two
       * differently and the zombie is the case this is for. Linux takes a task
       * out of its cgroup in do_exit, before anyone reaps it, so a process
       * waiting to be reaped is already gone from here - and kill(pid, 0)
       * succeeds for one, which left libprocessgroup signalling something that
       * could never answer.
       */
      bool alive = host >= 0 && getpgid((pid_t) host) >= 0;
      size_t llen = strlen(line);
      if (alive && len + llen + 2 < sizeof live) {
        memcpy(live + len, line, llen);
        len += llen;
        live[len++] = '\n';
      }
    }
    if (nl == NULL)
      break;
    line = nl + 1;
  }

  /* Served from the descriptor's own offset, so a second read ends the file
   * rather than repeating it. */
  off_t off = lseek(fd, 0, SEEK_CUR);
  if (off < 0)
    off = 0;
  if ((size_t) off >= len) {
    *ret = 0;
    return true;
  }
  size_t give = len - (size_t) off;
  if (give > size)
    give = size;
  memcpy(out, live + off, give);
  lseek(fd, off + (off_t) give, SEEK_SET);
  *ret = (int) give;
  return true;
}

bool
cgroup_write_procs(int fd, const char *buf, size_t size, int *out)
{
  char path[PATH_MAX], root[PATH_MAX];
  if (fcntl(fd, F_GETPATH, path) < 0)
    return false;
  if (!cgroup_is_hierarchy_path(path))
    return false;

  char *base = strrchr(path, '/');
  if (!base || strcmp(base, "/cgroup.procs") != 0)
    return false;

  cgroup_root_dir(root, sizeof root);
  *base = '\0';                 /* the directory is the cgroup */
  const char *rel = path + strlen(root);
  if (*rel == '\0')
    rel = "/";

  char text[32];
  size_t n = size < sizeof text - 1 ? size : sizeof text - 1;
  memcpy(text, buf, n);
  text[n] = '\0';

  char *end;
  long pid = strtol(text, &end, 10);
  if (end == text) {
    *out = -LINUX_EINVAL;
    return true;
  }

  int r = cgroup_move(rel, (int32_t) pid);
  *out = r < 0 ? r : (int) size;
  return true;
}

/*
 * Whether a write is a request to enable controllers, which is refused.
 *
 * cgroup.subtree_control is an ordinary empty file on the host, so a write
 * would land in it and be reported as a success - the caller would believe
 * controllers were enabled and nothing would ever say otherwise. The file's
 * contract is that it cannot be made non-empty (see the header), so the
 * request is answered the way Linux answers for a controller that does not
 * exist: EINVAL. lxc-start reads the failure, logs it and continues.
 */
bool
cgroup_write_control(int fd, const char *buf, size_t size, int *out)
{
  (void) buf;
  (void) size;
  char path[PATH_MAX];
  if (fcntl(fd, F_GETPATH, path) < 0)
    return false;
  if (!cgroup_is_hierarchy_path(path))
    return false;

  char *base = strrchr(path, '/');
  if (!base || strcmp(base, "/cgroup.subtree_control") != 0)
    return false;

  *out = -LINUX_EINVAL;
  return true;
}

int
cgroup_move(const char *cgroup_path, int32_t nspid)
{
  char host[PATH_MAX], root[PATH_MAX];
  cgroup_root_dir(root, sizeof root);
  snprintf(host, sizeof host, "%s%s", root,
           strcmp(cgroup_path, "/") == 0 ? "" : cgroup_path);

  struct stat st;
  if (stat(host, &st) < 0 || !S_ISDIR(st.st_mode))
    return -LINUX_ENOENT;

  /* Zero means the writer, which is how a process joins a cgroup itself. */
  int32_t self = pidns_to_ns((int32_t) getpid());
  int32_t who = nspid == 0 ? self : nspid;

  /*
   * A pid that names no process cannot be moved, and saying so is better than
   * writing a number into a file that will never name anything. Two ways to
   * fail: outside this namespace, or not alive. The namespace test alone was
   * not enough - outside a pid namespace the translation is the identity, so
   * every number looked like a process and any of them was accepted.
   */
  if (who != self) {
    int32_t host = pidns_to_host(who);
    if (host < 0)
      return -LINUX_ESRCH;
    if (kill((pid_t) host, 0) < 0 && errno == ESRCH)
      return -LINUX_ESRCH;
  }

  /*
   * Taken out of wherever it is before being put where it is going, or it
   * would be in two cgroups at once - which is not a state Linux has. Our own
   * is known without looking; another process's is found in the files, since
   * that is where it is written down.
   */
  char from[CGROUP_PATH_MAX] = "/";
  if (who == self)
    snprintf(from, sizeof from, "%s", current_cgroup);
  else
    (void) find_in_tree(root, "", who, from, sizeof from);

  procs_file_update(from, who, false);
  if (who == self)
    cgroup_set_current(cgroup_path);
  procs_file_update(cgroup_path, who, true);
  return 0;
}
