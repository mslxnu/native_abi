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
int
cgroup_proc_text(char *out, size_t n)
{
  const char *mine = current_cgroup;
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
 * Only this process can be moved, because membership is kept in the process
 * itself rather than in a table something else could reach - the same reason
 * every other piece of per-process state here lives where it does. Asking to
 * move another one is refused rather than silently ignored.
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
  if (nspid != 0 && nspid != pidns_to_ns((int32_t) getpid()))
    return -LINUX_EPERM;

  char host[PATH_MAX], root[PATH_MAX];
  cgroup_root_dir(root, sizeof root);
  snprintf(host, sizeof host, "%s%s", root,
           strcmp(cgroup_path, "/") == 0 ? "" : cgroup_path);

  struct stat st;
  if (stat(host, &st) < 0 || !S_ISDIR(st.st_mode))
    return -LINUX_ENOENT;

  procs_file_update(current_cgroup, pidns_to_ns((int32_t) getpid()), false);
  cgroup_set_current(cgroup_path);
  procs_file_update(cgroup_path, pidns_to_ns((int32_t) getpid()), true);
  return 0;
}
