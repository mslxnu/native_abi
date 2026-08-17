/*
 * Mounting a filesystem image, by asking the host to do it.
 *
 * NABI has no block layer and no filesystem of its own: every file the guest
 * sees is a host file reached by rewriting a path. A disk image breaks that,
 * because the files inside one are not host files until something mounts it -
 * and `mount` on a regular file is how Android is shipped. waydroid's
 * system.img and vendor.img are ext4 images, and `waydroid session start`
 * mounts them before it does anything else.
 *
 * Implementing ext4 here would mean a block layer and a filesystem driver, for
 * a job the host can already do: hdiutil attaches the image as a device and the
 * ext2fs driver mounts it. That is the same division of labour as everything
 * else - the host holds the real objects, nabi rewrites paths onto them - so
 * the mount goes on the host and the guest's mountpoint is backed by the host's
 * directory, exactly as tmpfs and cgroup2 already are.
 *
 * Read-only, and only read-only. A writable mount is refused rather than
 * quietly downgraded: the guest would be told its mount succeeded, and discover
 * otherwise at the first write, which is worse than being told no. waydroid
 * mounts both images read-only and keeps its writable state in an overlay, so
 * this is the whole of what it needs.
 *
 * Subprocesses go through posix_spawn rather than fork. A plain fork here is the
 * hazard the arm64 port documents at length: this process holds Hypervisor
 * framework state, and forking it is what fork-by-exec exists to avoid.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/errno.h"

extern char **environ;

/*
 * Run a host program, with its standard output collected.
 *
 * Returns the exit status, or -1 if it could not be run at all. The output is
 * always NUL-terminated.
 */
static int
run_host(char *const argv[], char *out, size_t outsz)
{
  if (out != NULL && outsz > 0)
    out[0] = '\0';

  int pipefd[2];
  if (pipe(pipefd) < 0)
    return -1;

  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }
  posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
  /* Diagnostics go with it, so a failure has something to report. */
  posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&fa, pipefd[0]);

  pid_t pid;
  int rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  close(pipefd[1]);
  if (rc != 0) {
    close(pipefd[0]);
    return -1;
  }

  size_t at = 0;
  for (;;) {
    char buf[512];
    ssize_t n = read(pipefd[0], buf, sizeof buf);
    if (n <= 0)
      break;
    if (out != NULL && at + 1 < outsz) {
      size_t room = outsz - at - 1;
      size_t take = (size_t) n < room ? (size_t) n : room;
      memcpy(out + at, buf, take);
      at += take;
      out[at] = '\0';
    }
  }
  close(pipefd[0]);

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
    ;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Whether a file is an ext2/3/4 image.
 *
 * The superblock's magic sits at offset 0x438 and is 0xef53. Checked before
 * anything is attached, so a guest that mounts a file that is not an image is
 * told so - rather than having a device built for it and the mount fail later
 * with something that describes neither the file nor the reason.
 */
bool
image_is_ext(const char *host_path)
{
  int fd = open(host_path, O_RDONLY);
  if (fd < 0)
    return false;
  unsigned char magic[2] = { 0, 0 };
  ssize_t n = pread(fd, magic, sizeof magic, 0x438);
  close(fd);
  return n == (ssize_t) sizeof magic && magic[0] == 0x53 && magic[1] == 0xef;
}

/* The /dev/diskN hdiutil reported, which is the first such word it prints. */
static bool
parse_device(const char *text, char *dev, size_t devsz)
{
  const char *p = strstr(text, "/dev/disk");
  if (p == NULL)
    return false;
  size_t i = 0;
  while (p[i] != '\0' && p[i] != ' ' && p[i] != '\t' && p[i] != '\n' &&
         i + 1 < devsz) {
    dev[i] = p[i];
    i++;
  }
  dev[i] = '\0';
  return i > strlen("/dev/disk");
}

/*
 * Attach an image and mount it, both read-only.
 *
 * On success `dev` names the device to detach and `dir` the host directory the
 * guest's mountpoint is backed by; both are needed to undo it.
 */
int
image_mount_ro(const char *host_path, char *dev, size_t devsz,
               char *dir, size_t dirsz)
{
  struct stat st;
  if (stat(host_path, &st) < 0)
    return -darwin_to_linux_errno(errno);
  if (!S_ISREG(st.st_mode))
    return -LINUX_ENOTBLK;
  if (!image_is_ext(host_path))
    return -LINUX_EINVAL;       /* not a filesystem this can mount */

  char out[1024];
  /*
   * The image class is stated rather than left to be guessed. hdiutil probes a
   * raw image by its *name*: system.img is recognised and the same bytes called
   * system.ext4 are "not recognized". A guest names whatever it names, so the
   * extension is not something to depend on.
   */
  char *const attach[] = {
    (char *) "/usr/bin/hdiutil", (char *) "attach", (char *) "-readonly",
    (char *) "-nomount", (char *) "-imagekey",
    (char *) "diskimage-class=CRawDiskImage", (char *) host_path, NULL
  };
  if (run_host(attach, out, sizeof out) != 0)
    return -LINUX_EIO;
  if (!parse_device(out, dev, devsz)) {
    return -LINUX_EIO;
  }

  const char *tmp = getenv("TMPDIR");
  snprintf(dir, dirsz, "%s/nabi-img-XXXXXX", tmp && *tmp ? tmp : "/tmp");
  if (mkdtemp(dir) == NULL) {
    int e = errno;
    char *const detach[] = {
      (char *) "/usr/bin/hdiutil", (char *) "detach", dev, NULL
    };
    run_host(detach, NULL, 0);
    return -darwin_to_linux_errno(e);
  }

  /*
   * noowners, which is what makes the contents reachable at all.
   *
   * An image built for another system carries that system's ownership, and
   * Android's is root with modes to match - /system/build.prop is 0600 root.
   * nabi runs as an ordinary account, so without this the files are present,
   * traversable and unreadable, and the guest is told EACCES for the whole
   * tree. noowners is macOS's own answer to a volume whose uids mean nothing
   * here: everything is attributed to the mounting user. That is also the right
   * answer for nabi in particular, because the account it runs as is precisely
   * what the guest sees as root.
   */
  char *const mnt[] = {
    (char *) "/sbin/mount", (char *) "-t", (char *) "ext2fs",
    (char *) "-o", (char *) "rdonly,noowners", dev, dir, NULL
  };
  if (run_host(mnt, out, sizeof out) != 0) {
    char *const detach[] = {
      (char *) "/usr/bin/hdiutil", (char *) "detach", dev, NULL
    };
    run_host(detach, NULL, 0);
    rmdir(dir);
    /*
     * The driver is a separate piece - see the ext2fs project beside this one -
     * and its absence is the common reason to be here. ENODEV is what mount(2)
     * answers for a filesystem type the kernel does not have, which is what
     * this amounts to.
     */
    warnk("image mount failed for %s: %s\n", host_path, out);
    return -LINUX_ENODEV;
  }
  return 0;
}

/*
 * Undo it, reporting whether the filesystem actually went away.
 *
 * A mount with a file still open on it cannot be unmounted, and that is not a
 * detail to swallow: Linux answers EBUSY and the caller is expected to close
 * what it is holding. Reporting success and dropping the record would leave the
 * host mount and its device attached for as long as the machine is up, with
 * nothing left that knows they are there.
 *
 * The detach only happens once the unmount has, for the same reason - detaching
 * a device out from under a live mount is worse than leaving both.
 */
bool
image_unmount(const char *dev, const char *dir)
{
  if (dir != NULL && dir[0] != '\0') {
    char *const um[] = { (char *) "/sbin/umount", (char *) dir, NULL };
    if (run_host(um, NULL, 0) != 0)
      return false;
  }
  if (dev != NULL && dev[0] != '\0') {
    char *const detach[] = {
      (char *) "/usr/bin/hdiutil", (char *) "detach", (char *) dev, NULL
    };
    run_host(detach, NULL, 0);
  }
  if (dir != NULL && dir[0] != '\0')
    rmdir(dir);
  return true;
}
