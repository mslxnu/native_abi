/*
 * fanotify, which fits this host better than inotify did and is harder in a
 * different place.
 *
 * inotify asks what happened to a *file*, and the only thing here that knows is
 * Darwin, so it had to be derived from kqueue. fanotify asks what a *process*
 * did - opened, read, wrote, closed - and for a guest the thing that knows is
 * nabi, which sees every one of those calls as it makes them. So the events are
 * observed directly rather than inferred, which is more faithful than anything
 * in inotify.c.
 *
 * The difficulty moves to delivery. A fanotify listener exists to watch *other*
 * processes, and nabi's processes are separate host processes: the open happens
 * in one and the listener sits in another, with no kernel between them. So the
 * marks live in a file every process maps, and the events go down a FIFO named
 * after the instance. That is the machinery inotify.c deferred, and here it is
 * not optional - a fanotify that saw only its own process would be watching the
 * one process nobody uses fanotify to watch.
 *
 * The cost of the mark table is paid only by guests that use it. It is a shared
 * mapping with a count at the front, so the question every open and close asks -
 * "is anything marked?" - is a memory read, not a syscall.
 *
 * Permission events work, and the hazard in them is worth naming because it is
 * the reason they were refused at first. FAN_OPEN_PERM stops the process that
 * opened the file until the listener writes a verdict, so a listener that dies
 * mid-decision would leave every open in the guest waiting for an answer that
 * is not coming.
 *
 * Linux has the same hazard and answers it in one place: when the fanotify
 * descriptor goes - including because the listener died - the kernel releases
 * everything pending with FAN_ALLOW. There is no kernel here to notice that, so
 * the listener's pid is recorded with its marks and a waiting process checks it
 * is still there. A listener that goes away releases the guest, in the same
 * direction Linux releases it. A listener that is alive and simply slow is
 * waited for indefinitely, exactly as on Linux - a timeout would be this port
 * inventing a policy, and "allow after a while" is not a decision a guard would
 * thank us for making on its behalf.
 *
 * An instance is never sent a permission event caused by the process holding it.
 * On Linux that is a listener's own footgun to avoid; here it would be a
 * deadlock against itself with the answer in the same thread, and refusing to
 * build it costs nothing that a real listener wanted.
 *
 * The descriptor an event carries is opened by the *listener's* nabi from the
 * path in the record, rather than passed from the process that caused the
 * event. Linux guarantees that descriptor refers to the object as it was; here
 * it is a fresh open of the same name, so an object renamed between the event
 * and the read comes back as whatever holds the name now. For FAN_OPEN and the
 * closes - which is what fanotify is used for - the window is not reachable in
 * practice, and saying so is better than passing descriptors between processes
 * to close a gap nobody is standing in.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/fanotify.h"

#define FAN_MARKS_MAX 256
#define FAN_PATH      400
#define FAN_WIRE      512       /* PIPE_BUF on Darwin: a write this size is atomic */

/*
 * One mark, in the table every process maps. `inst` says which FIFO an event
 * goes down, so a process that never created an instance can still deliver to
 * one.
 */
struct fan_mark {
  uint64_t mask;
  uint32_t flags;
  uint32_t inst;
  int32_t  listener;            /* the host pid holding the instance */
  uint32_t _pad;
  char     path[FAN_PATH];
};

struct fan_registry {
  uint32_t magic;
  uint32_t nmarks;
  uint32_t next_inst;
  uint32_t next_req;
  struct fan_mark m[FAN_MARKS_MAX];
};

#define FAN_MAGIC 0x6e616661u   /* "afan" */

/* What travels down the FIFO. Fixed size so that two processes writing at once
 * cannot interleave into a record neither of them sent. */
struct fan_wire {
  uint64_t mask;
  int32_t  pid;
  uint32_t pathlen;
  uint32_t reqid;               /* non-zero: a verdict is being waited for */
  uint32_t _pad;
  char     path[FAN_WIRE - 24];
};

static struct fan_registry *registry;
static pthread_mutex_t reg_lock = PTHREAD_MUTEX_INITIALIZER;

/* The guest's fanotify descriptors, so read can be recognised as a fanotify
 * read. Small and linear: a guest has one or two of these, never many. */
static struct { int fd; uint32_t inst; unsigned cls; } inst_fds[16];
static int n_inst_fds;

/*
 * Which request each descriptor handed to the listener belongs to.
 *
 * A verdict names the descriptor it is answering, because that is the only
 * handle the listener was given - so the way back to the process that is
 * waiting runs through this.
 */
static struct { int fd; uint32_t reqid; } pending[64];
static int n_pending;

static void
registry_path(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-fanmarks-%s",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag());
}

/* Where the verdict for one request comes back. One per request, so two
 * processes waiting at once cannot read each other's answer. */
static void
reply_path(uint32_t reqid, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-fanp-%s-%u",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(), reqid);
}

static void
queue_path(uint32_t inst, char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-fanq-%s-%u",
           tmp && *tmp ? tmp : "/tmp", nabi_boot_tag(), inst);
}

/*
 * Map the mark table, making it if this is the first use.
 *
 * Mapped rather than read because every open and close consults it: a guest
 * with no marks - which is nearly every guest - must not pay a syscall to find
 * that out, and a shared mapping turns the question into a load.
 */
static struct fan_registry *
registry_map(bool create)
{
  if (registry)
    return registry;

  pthread_mutex_lock(&reg_lock);
  if (registry) {
    pthread_mutex_unlock(&reg_lock);
    return registry;
  }

  char path[PATH_MAX];
  registry_path(path, sizeof path);
  int fd = open(path, create ? (O_RDWR | O_CREAT) : O_RDWR, 0600);
  if (fd < 0) {
    pthread_mutex_unlock(&reg_lock);
    return NULL;
  }
  if (ftruncate(fd, sizeof(struct fan_registry)) < 0 && errno != EINVAL) {
    close(fd);
    pthread_mutex_unlock(&reg_lock);
    return NULL;
  }
  void *p = mmap(NULL, sizeof(struct fan_registry), PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
  close(fd);
  if (p == MAP_FAILED) {
    pthread_mutex_unlock(&reg_lock);
    return NULL;
  }
  struct fan_registry *r = p;
  if (r->magic != FAN_MAGIC) {
    r->magic = FAN_MAGIC;
    r->next_inst = 1;
  }
  registry = r;
  pthread_mutex_unlock(&reg_lock);
  return registry;
}

/* Whether anything at all is marked. One load when nothing is. */
bool
fanotify_watching(void)
{
  struct fan_registry *r = registry ? registry : registry_map(false);
  return r != NULL && r->nmarks != 0;
}

/* ------------------------------------------------------------- delivering */

static bool
mark_covers(const struct fan_mark *m, const char *hostpath)
{
  if (strcmp(m->path, hostpath) == 0)
    return true;
  /*
   * A mount mark watches everything under it, which here is a prefix - a mount
   * being a prefix rewrite in this port anyway (include/mount.h). A directory
   * mark without FAN_EVENT_ON_CHILD watches only the directory itself, which is
   * why the plain case above is not enough and this one is not always.
   */
  if (m->flags & (LINUX_FAN_MARK_MOUNT | LINUX_FAN_MARK_FILESYSTEM)) {
    size_t n = strlen(m->path);
    return strncmp(hostpath, m->path, n) == 0 &&
           (hostpath[n] == '\0' || hostpath[n] == '/' ||
            (n == 1 && m->path[0] == '/'));
  }
  if (m->mask & LINUX_FAN_EVENT_ON_CHILD) {
    size_t n = strlen(m->path);
    return strncmp(hostpath, m->path, n) == 0 && hostpath[n] == '/' &&
           !strchr(hostpath + n + 1, '/');
  }
  return false;
}

/* Send one record to one instance. Returns whether it went. */
static bool
send_wire(uint32_t inst, const char *hostpath, uint64_t mask, uint32_t reqid)
{
  char qpath[PATH_MAX];
  queue_path(inst, qpath, sizeof qpath);
  /*
   * Non-blocking, so a listener that has stopped reading costs the process
   * that caused the event nothing. Linux drops events and marks the queue
   * overflowed; the listener here sees a gap, which is the same loss.
   */
  int q = open(qpath, O_WRONLY | O_NONBLOCK);
  if (q < 0)
    return false;

  struct fan_wire w;
  memset(&w, 0, sizeof w);
  w.mask = mask;
  w.pid = (int32_t) pidns_to_ns((int32_t) getpid());
  w.reqid = reqid;
  size_t pl = strlen(hostpath);
  if (pl >= sizeof w.path)
    pl = sizeof w.path - 1;
  memcpy(w.path, hostpath, pl);
  w.pathlen = (uint32_t) pl;
  bool ok = write(q, &w, sizeof w) == (ssize_t) sizeof w;
  close(q);
  return ok;
}

/*
 * Ask, and wait for the answer.
 *
 * The wait is unbounded on purpose - Linux's is - and is made survivable by
 * watching the listener rather than the clock. If the process holding the
 * instance goes away, the request is released the way Linux releases everything
 * pending when the descriptor closes: allowed.
 */
static bool
ask_permission(uint32_t inst, int32_t listener, const char *hostpath,
               uint64_t mask)
{
  struct fan_registry *r = registry;
  if (!r)
    return true;

  /* A listener is never asked about its own access; see the top of the file. */
  if (listener == (int32_t) getpid())
    return true;

  uint32_t reqid = __sync_fetch_and_add(&r->next_req, 1);
  if (reqid == 0)
    reqid = __sync_fetch_and_add(&r->next_req, 1);

  char rpath[PATH_MAX];
  reply_path(reqid, rpath, sizeof rpath);
  unlink(rpath);
  if (mkfifo(rpath, 0600) < 0)
    return true;                /* cannot ask, so cannot refuse */

  int rfd = open(rpath, O_RDWR | O_NONBLOCK);
  if (rfd < 0) {
    unlink(rpath);
    return true;
  }

  if (!send_wire(inst, hostpath, mask, reqid)) {
    close(rfd);
    unlink(rpath);
    return true;                /* nobody listening: nothing is denying it */
  }

  bool allow = true;
  for (;;) {
    uint32_t verdict;
    ssize_t n = read(rfd, &verdict, sizeof verdict);
    if (n == (ssize_t) sizeof verdict) {
      allow = (verdict & LINUX_FAN_DENY) == 0;
      break;
    }
    /* The listener is gone, so there is no verdict coming and nothing to
     * enforce. Linux allows in the same situation. */
    if (listener > 0 && kill((pid_t) listener, 0) < 0 && errno == ESRCH)
      break;
    /* A signal for the guest is the guest's; do not swallow it in a wait it
     * did not ask for. */
    if (has_sigpending())
      break;
    struct timespec nap = { 0, 20 * 1000 * 1000 };
    nanosleep(&nap, NULL);
  }

  close(rfd);
  unlink(rpath);
  return allow;
}

/*
 * Tell every instance that asked. Called from the syscall paths, in whichever
 * process made the call - which is the point of the table being shared.
 *
 * Returns false only when a permission event was denied, which is the one case
 * where the caller must not go on with what it was doing.
 */
bool
fanotify_permit(const char *hostpath, uint64_t mask)
{
  struct fan_registry *r = registry;
  if (!r || r->nmarks == 0 || !hostpath)
    return true;

  bool allow = true;
  for (uint32_t i = 0; i < r->nmarks && i < FAN_MARKS_MAX; i++) {
    const struct fan_mark *m = &r->m[i];
    if (m->inst == 0 || !(m->mask & mask))
      continue;
    if (!mark_covers(m, hostpath))
      continue;
    if (!ask_permission(m->inst, m->listener, hostpath, mask))
      allow = false;
  }
  return allow;
}

void
fanotify_note(const char *hostpath, uint64_t mask)
{
  struct fan_registry *r = registry;
  if (!r || r->nmarks == 0 || !hostpath)
    return;

  for (uint32_t i = 0; i < r->nmarks && i < FAN_MARKS_MAX; i++) {
    const struct fan_mark *m = &r->m[i];
    if (m->inst == 0 || !(m->mask & mask))
      continue;
    if (!mark_covers(m, hostpath))
      continue;

    (void) send_wire(m->inst, hostpath, mask, 0);
  }
}

/* The same, for a descriptor rather than a path - which is what read and write
 * have to hand, and turning one into the other is a syscall, so it is asked
 * only when something is marked. */
void
fanotify_note_fd(int hostfd, uint64_t mask)
{
  struct fan_registry *r = registry;
  if (!r || r->nmarks == 0)
    return;
  char path[PATH_MAX];
  if (fcntl(hostfd, F_GETPATH, path) == 0)
    fanotify_note(path, mask);
}

/* ---------------------------------------------------------------- syscalls */

static bool
may_fanotify(void)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  bool ok = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ok;
}

DEFINE_SYSCALL(fanotify_init, unsigned int, flags, unsigned int, event_f_flags)
{
  /* CAP_SYS_ADMIN on Linux; guest root here, as mounting is. */
  if (!may_fanotify())
    return -LINUX_EPERM;

  unsigned cls = flags & LINUX_FAN_CLASS_BITS;
  if (cls != LINUX_FAN_CLASS_NOTIF && cls != LINUX_FAN_CLASS_CONTENT &&
      cls != LINUX_FAN_CLASS_PRE_CONTENT)
    return -LINUX_EINVAL;

  /*
   * The reporting flags change the record format into one carrying file
   * handles instead of descriptors. Refused rather than ignored: a listener
   * given the wrong shape would parse whatever the bytes happened to be.
   */
  if (flags & (LINUX_FAN_REPORT_FID | LINUX_FAN_REPORT_DIR_FID |
               LINUX_FAN_REPORT_NAME))
    return -LINUX_EINVAL;
  if (flags & ~(unsigned) (LINUX_FAN_CLOEXEC | LINUX_FAN_NONBLOCK |
                           LINUX_FAN_CLASS_BITS | LINUX_FAN_UNLIMITED_QUEUE |
                           LINUX_FAN_UNLIMITED_MARKS | LINUX_FAN_REPORT_TID))
    return -LINUX_EINVAL;

  struct fan_registry *r = registry_map(true);
  if (!r)
    return -LINUX_ENOMEM;

  if (n_inst_fds == (int) (sizeof inst_fds / sizeof inst_fds[0]))
    return -LINUX_EMFILE;

  uint32_t inst = __sync_fetch_and_add(&r->next_inst, 1);

  char qpath[PATH_MAX];
  queue_path(inst, qpath, sizeof qpath);
  unlink(qpath);
  if (mkfifo(qpath, 0600) < 0)
    return -darwin_to_linux_errno(errno);

  /*
   * Opened read-write rather than read-only. A FIFO with no writer reports
   * end-of-file to its reader, and a listener that saw EOF would conclude the
   * queue had been closed the moment it drained - holding a writer of our own
   * keeps it open, which is what a kernel queue is.
   */
  int fd = open(qpath, O_RDWR | O_NONBLOCK);
  if (fd < 0) {
    int e = errno;
    unlink(qpath);
    return -darwin_to_linux_errno(e);
  }
  if (!(flags & LINUX_FAN_NONBLOCK)) {
    /* The guest asked for a blocking queue, but the descriptor must stay
     * non-blocking underneath: read is served from here, not by the host. */
  }
  if (flags & LINUX_FAN_CLOEXEC)
    fcntl(fd, F_SETFD, FD_CLOEXEC);

  int err = register_fd(fd, (flags & LINUX_FAN_CLOEXEC) != 0);
  if (err < 0) {
    close(fd);
    unlink(qpath);
    return err;
  }

  inst_fds[n_inst_fds].fd = fd;
  inst_fds[n_inst_fds].inst = inst;
  inst_fds[n_inst_fds].cls = cls;
  n_inst_fds++;
  return fd;
}

static int
inst_of_fd(int fd)
{
  for (int i = 0; i < n_inst_fds; i++)
    if (inst_fds[i].fd == fd)
      return (int) inst_fds[i].inst;
  return -1;
}

DEFINE_SYSCALL(fanotify_mark, int, fanotify_fd, unsigned int, flags,
               uint64_t, mask, int, dirfd, gstr_t, path_ptr)
{
  int inst = inst_of_fd(fanotify_fd);
  if (inst < 0)
    return -LINUX_EBADF;

  struct fan_registry *r = registry_map(true);
  if (!r)
    return -LINUX_ENOMEM;

  if (flags & LINUX_FAN_MARK_FLUSH) {
    pthread_mutex_lock(&reg_lock);
    uint32_t k = 0;
    for (uint32_t i = 0; i < r->nmarks; i++)
      if (r->m[i].inst != (uint32_t) inst)
        r->m[k++] = r->m[i];
    r->nmarks = k;
    pthread_mutex_unlock(&reg_lock);
    return 0;
  }

  /*
   * A permission event on a notification instance has nowhere for the verdict
   * to come from, and Linux refuses that pairing too.
   */
  unsigned cls = LINUX_FAN_CLASS_NOTIF;
  for (int i = 0; i < n_inst_fds; i++)
    if (inst_fds[i].fd == fanotify_fd)
      cls = inst_fds[i].cls;
  if ((mask & (LINUX_FAN_OPEN_PERM | LINUX_FAN_ACCESS_PERM |
               LINUX_FAN_OPEN_EXEC_PERM)) && cls == LINUX_FAN_CLASS_NOTIF)
    return -LINUX_EINVAL;

  if ((mask & (LINUX_FAN_ACCESS | LINUX_FAN_MODIFY | LINUX_FAN_CLOSE_WRITE |
               LINUX_FAN_CLOSE_NOWRITE | LINUX_FAN_OPEN |
               LINUX_FAN_OPEN_EXEC | LINUX_FAN_OPEN_PERM |
               LINUX_FAN_ACCESS_PERM | LINUX_FAN_OPEN_EXEC_PERM)) == 0)
    return -LINUX_EINVAL;       /* nothing in it can be observed here */

  char guestpath[LINUX_PATH_MAX];
  if (path_ptr != 0) {
    if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0)
      return -LINUX_EFAULT;
  } else {
    strcpy(guestpath, "/");
  }

  char host[PATH_MAX];
  int gr = guest_to_host_path(guestpath, host, sizeof host);
  if (gr < 0)
    return gr;

  struct stat st;
  if (stat(host, &st) < 0)
    return -darwin_to_linux_errno(errno);
  if ((flags & LINUX_FAN_MARK_ONLYDIR) && !S_ISDIR(st.st_mode))
    return -LINUX_ENOTDIR;
  if (strlen(host) >= FAN_PATH)
    return -LINUX_ENAMETOOLONG;

  pthread_mutex_lock(&reg_lock);

  int at = -1;
  for (uint32_t i = 0; i < r->nmarks; i++)
    if (r->m[i].inst == (uint32_t) inst && strcmp(r->m[i].path, host) == 0)
      at = (int) i;

  if (flags & LINUX_FAN_MARK_REMOVE) {
    if (at < 0) {
      pthread_mutex_unlock(&reg_lock);
      return -LINUX_ENOENT;
    }
    r->m[at].mask &= ~mask;
    if (r->m[at].mask == 0) {
      for (uint32_t i = (uint32_t) at; i + 1 < r->nmarks; i++)
        r->m[i] = r->m[i + 1];
      r->nmarks--;
    }
    pthread_mutex_unlock(&reg_lock);
    return 0;
  }

  if (!(flags & LINUX_FAN_MARK_ADD)) {
    pthread_mutex_unlock(&reg_lock);
    return -LINUX_EINVAL;
  }

  if (at >= 0) {
    r->m[at].mask |= mask;
    r->m[at].flags = flags;
    pthread_mutex_unlock(&reg_lock);
    return 0;
  }
  if (r->nmarks == FAN_MARKS_MAX) {
    pthread_mutex_unlock(&reg_lock);
    return -LINUX_ENOSPC;
  }

  struct fan_mark *m = &r->m[r->nmarks];
  memset(m, 0, sizeof *m);
  m->mask = mask;
  m->flags = flags;
  m->inst = (uint32_t) inst;
  m->listener = (int32_t) getpid();
  snprintf(m->path, sizeof m->path, "%s", host);
  r->nmarks++;
  pthread_mutex_unlock(&reg_lock);
  return 0;
}

/* Answer a request without presenting it, when there is nothing to present. */
static void
release(uint32_t reqid, uint32_t verdict)
{
  if (reqid == 0)
    return;
  char rpath[PATH_MAX];
  reply_path(reqid, rpath, sizeof rpath);
  int rfd = open(rpath, O_WRONLY | O_NONBLOCK);
  if (rfd < 0)
    return;
  (void) !write(rfd, &verdict, sizeof verdict);
  close(rfd);
}

/*
 * Serving a read on a fanotify descriptor.
 *
 * The record the guest gets carries a descriptor, so it has to be built here
 * rather than handed through: the path comes down the FIFO and this process
 * opens it, which is the only way the number in the record means anything to
 * the process that will use it.
 */
bool
fanotify_read(int fd, char *out, size_t size, int *ret)
{
  int inst = inst_of_fd(fd);
  if (inst < 0)
    return false;

  size_t produced = 0;
  for (;;) {
    if (size - produced < sizeof(struct l_fanotify_event_metadata))
      break;

    struct fan_wire w;
    ssize_t n = read(fd, &w, sizeof w);
    if (n != (ssize_t) sizeof w) {
      if (produced == 0) {
        *ret = (n < 0 && errno == EAGAIN) ? -LINUX_EAGAIN
             : (n < 0) ? -darwin_to_linux_errno(errno) : 0;
        return true;
      }
      break;
    }
    w.path[sizeof w.path - 1] = '\0';

    /*
     * A request that cannot be presented has to be answered anyway.
     *
     * The record carries a descriptor to the object, so one has to be opened -
     * and an object that is being *created* does not exist yet, which is
     * exactly what an O_CREAT open asks permission for. Dropping the event
     * there left the process that asked waiting for a verdict nobody could send
     * it, and it never returned from open. Nothing was presented, so nothing is
     * denied.
     */
    int objfd = open(w.path, O_RDONLY);
    if (objfd < 0) {
      release(w.reqid, LINUX_FAN_ALLOW);
      continue;
    }
    if (register_fd(objfd, false) < 0) {
      close(objfd);
      release(w.reqid, LINUX_FAN_ALLOW);
      continue;
    }

    struct l_fanotify_event_metadata md;
    memset(&md, 0, sizeof md);
    md.event_len = sizeof md;
    md.vers = LINUX_FANOTIFY_METADATA_VERSION;
    md.metadata_len = sizeof md;
    md.mask = w.mask;
    md.fd = objfd;
    md.pid = w.pid;
    if (w.reqid != 0 && n_pending < (int) (sizeof pending / sizeof pending[0])) {
      pending[n_pending].fd = objfd;
      pending[n_pending].reqid = w.reqid;
      n_pending++;
    }
    memcpy(out + produced, &md, sizeof md);
    produced += sizeof md;
  }

  *ret = (int) produced;
  return true;
}

/*
 * The listener answering.
 *
 * A write to a fanotify descriptor is a verdict, not data - and it must be
 * recognised, because the descriptor underneath is the queue's own FIFO and an
 * unrecognised write would inject the verdict into the event stream as though
 * something had reported it.
 */
bool
fanotify_write(int fd, const char *buf, size_t size, int *ret)
{
  if (inst_of_fd(fd) < 0)
    return false;

  size_t used = 0;
  while (size - used >= sizeof(struct l_fanotify_response)) {
    struct l_fanotify_response resp;
    memcpy(&resp, buf + used, sizeof resp);
    used += sizeof resp;

    for (int i = 0; i < n_pending; i++) {
      if (pending[i].fd != resp.fd)
        continue;
      char rpath[PATH_MAX];
      reply_path(pending[i].reqid, rpath, sizeof rpath);
      int rfd = open(rpath, O_WRONLY | O_NONBLOCK);
      if (rfd >= 0) {
        uint32_t v = resp.response;
        (void) !write(rfd, &v, sizeof v);
        close(rfd);
      }
      pending[i] = pending[--n_pending];
      break;
    }
  }
  *ret = (int) used;
  return true;
}

/* A guest closing its fanotify descriptor takes its marks and its queue. */
void
fanotify_close(int fd)
{
  int inst = inst_of_fd(fd);
  if (inst < 0)
    return;

  struct fan_registry *r = registry;
  if (r) {
    pthread_mutex_lock(&reg_lock);
    uint32_t k = 0;
    for (uint32_t i = 0; i < r->nmarks; i++)
      if (r->m[i].inst != (uint32_t) inst)
        r->m[k++] = r->m[i];
    r->nmarks = k;
    pthread_mutex_unlock(&reg_lock);
  }

  /* Anything still waiting on this listener is released, which is what Linux
   * does when the descriptor goes: allowed, not left. */
  for (int i = 0; i < n_pending; i++)
    release(pending[i].reqid, LINUX_FAN_ALLOW);
  n_pending = 0;

  char qpath[PATH_MAX];
  queue_path((uint32_t) inst, qpath, sizeof qpath);
  unlink(qpath);

  for (int i = 0; i < n_inst_fds; i++)
    if (inst_fds[i].fd == fd) {
      inst_fds[i] = inst_fds[--n_inst_fds];
      break;
    }
}
