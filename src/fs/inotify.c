/*
 * inotify, on a host that has kqueue.
 *
 * The shape is the useful part and it comes almost free: the descriptor a guest
 * gets back is the read end of a pipe, so read, poll, select and epoll all work
 * on it without anything further being taught about inotify. A thread per
 * instance waits on a kqueue and writes inotify_event records into the other
 * end. What the guest does with the descriptor is then ordinary file reading,
 * which is exactly what it is on Linux.
 *
 * What kqueue can and cannot say is the whole of the fidelity question here.
 *
 *   It reports that a *file* changed, was renamed, had its attributes touched
 *   or was deleted. Those map onto IN_MODIFY, IN_MOVE_SELF, IN_ATTRIB and
 *   IN_DELETE_SELF exactly.
 *
 *   It reports that a *directory* changed, and not what changed in it. inotify
 *   callers need the name - IN_CREATE and IN_DELETE carry one - so the listing
 *   is remembered and diffed when the directory fires. That gives the right
 *   names and the right events; what it cannot give is the order of two changes
 *   inside one notification, or a rename's cookie pairing IN_MOVED_FROM with
 *   IN_MOVED_TO, so a rename within a watched directory arrives as a delete and
 *   a create. Linux says the same thing when the two ends are in different
 *   watched directories, so callers already handle it.
 *
 *   It has no notion of a file being opened, read or closed. IN_OPEN,
 *   IN_CLOSE_WRITE and IN_CLOSE_NOWRITE cannot come from the host at all, so
 *   they are synthesised from the guest's own open and close - and only within
 *   the process that holds the inotify instance, because that is the only
 *   process that can reach the pipe. A file closed by a forked child, which is
 *   what a shell's `echo x > f` is, produces nothing. Making these work
 *   generally needs the instance reachable by name rather than by descriptor -
 *   a FIFO and a registry of watches - which is a larger change than the rest
 *   of this file and has not been made.
 *
 *   IN_ACCESS is not delivered at all: it would mean a hook on every read, for
 *   an event almost nothing waits on.
 *
 * A watch whose mask asks *only* for things that can never arrive is refused
 * with EINVAL rather than accepted. That is the difference between a caller
 * that fails and one that waits forever, and waiting forever is the failure
 * this port keeps refusing to hand anybody.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/inotify.h"

#include "util/khash.h"

#define INO_MAX_WATCH 512

struct ino_watch {
  int       wd;
  int       fd;                 /* O_EVTONLY, what the kqueue watches */
  uint32_t  mask;
  bool      isdir;
  bool      live;
  char      path[PATH_MAX];
  char    **names;              /* the listing, for telling what changed */
  size_t    nnames;
};

struct ino_inst {
  int              rd, wr;      /* the guest holds rd */
  int              kq;
  pthread_t        thread;
  pthread_mutex_t  lock;
  bool             running;
  int              next_wd;
  struct ino_watch w[INO_MAX_WATCH];
  size_t           nw;
};

KHASH_MAP_INIT_INT(inst, struct ino_inst *)
static khash_t(inst) *instances;
static pthread_mutex_t instances_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Whether any watch exists at all, read without a lock on the hot path.
 *
 * open and close consult inotify on every call, and almost every guest has no
 * watches - so the question has to be answerable without taking a lock, or the
 * cost of a feature nobody is using is paid by everybody.
 */
static volatile int any_watches;

/* ------------------------------------------------------------------ events */

/* Linux pads a name so the next record starts aligned; the unit is the size of
 * the header itself. */
static size_t
name_field(const char *name)
{
  if (!name || !*name)
    return 0;
  size_t n = strlen(name) + 1;
  return roundup(n, sizeof(struct l_inotify_event));
}

static void
emit(struct ino_inst *in, int wd, uint32_t mask, const char *name)
{
  struct l_inotify_event ev;
  size_t nl = name_field(name);
  char buf[sizeof ev + NAME_MAX + 32];

  ev.wd = wd;
  ev.mask = mask;
  ev.cookie = 0;
  ev.len = (uint32_t) nl;
  if (sizeof ev + nl > sizeof buf)
    return;
  memcpy(buf, &ev, sizeof ev);
  if (nl) {
    memset(buf + sizeof ev, 0, nl);
    memcpy(buf + sizeof ev, name, strlen(name));
  }
  /*
   * A short or failed write means the reader is not keeping up and the pipe is
   * full. Linux answers that with IN_Q_OVERFLOW and drops events; dropping them
   * here without the marker would be the same loss told to nobody.
   */
  ssize_t n = write(in->wr, buf, sizeof ev + nl);
  if (n != (ssize_t) (sizeof ev + nl)) {
    struct l_inotify_event ovf = { .wd = -1, .mask = LINUX_IN_Q_OVERFLOW,
                                   .cookie = 0, .len = 0 };
    (void) !write(in->wr, &ovf, sizeof ovf);
  }
}

/* --------------------------------------------------------------- listings */

static void
names_free(struct ino_watch *w)
{
  for (size_t i = 0; i < w->nnames; i++)
    free(w->names[i]);
  free(w->names);
  w->names = NULL;
  w->nnames = 0;
}

static void
names_read(const char *path, char ***out, size_t *nout)
{
  *out = NULL;
  *nout = 0;
  DIR *d = opendir(path);
  if (!d)
    return;
  size_t cap = 16, n = 0;
  char **v = malloc(cap * sizeof *v);
  if (!v) {
    closedir(d);
    return;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    if (n == cap) {
      char **bigger = realloc(v, (cap *= 2) * sizeof *v);
      if (!bigger)
        break;
      v = bigger;
    }
    v[n] = strdup(e->d_name);
    if (!v[n])
      break;
    n++;
  }
  closedir(d);
  *out = v;
  *nout = n;
}

static bool
names_has(char **v, size_t n, const char *name)
{
  for (size_t i = 0; i < n; i++)
    if (strcmp(v[i], name) == 0)
      return true;
  return false;
}

static bool
is_dir_at(const char *dir, const char *name)
{
  char path[PATH_MAX];
  struct stat st;
  snprintf(path, sizeof path, "%s/%s", dir, name);
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/*
 * What changed in a watched directory, by comparing what is there now with what
 * was there before. kqueue says only that the directory changed.
 */
static void
diff_dir(struct ino_inst *in, struct ino_watch *w)
{
  char **now;
  size_t nnow;
  names_read(w->path, &now, &nnow);

  for (size_t i = 0; i < nnow; i++)
    if (!names_has(w->names, w->nnames, now[i])) {
      uint32_t m = LINUX_IN_CREATE;
      if (is_dir_at(w->path, now[i]))
        m |= LINUX_IN_ISDIR;
      if (w->mask & LINUX_IN_CREATE)
        emit(in, w->wd, m, now[i]);
    }
  for (size_t i = 0; i < w->nnames; i++)
    if (!names_has(now, nnow, w->names[i])) {
      if (w->mask & LINUX_IN_DELETE)
        emit(in, w->wd, LINUX_IN_DELETE, w->names[i]);
    }

  names_free(w);
  w->names = now;
  w->nnames = nnow;
}

/* ---------------------------------------------------------------- watcher */

/* Woken to stop; kqueue has no other way to interrupt a blocked kevent. */
#define WAKE_IDENT 1

static void *
watcher(void *arg)
{
  struct ino_inst *in = arg;

  for (;;) {
    struct kevent ev[16];
    int n = kevent(in->kq, NULL, 0, ev, 16, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    pthread_mutex_lock(&in->lock);
    if (!in->running) {
      pthread_mutex_unlock(&in->lock);
      break;
    }
    for (int i = 0; i < n; i++) {
      if (ev[i].filter == EVFILT_USER)
        continue;

      struct ino_watch *w = NULL;
      for (size_t k = 0; k < in->nw; k++)
        if (in->w[k].live && in->w[k].fd == (int) ev[i].ident)
          w = &in->w[k];
      if (!w)
        continue;

      unsigned f = (unsigned) ev[i].fflags;
      if (w->isdir) {
        if (f & (NOTE_WRITE | NOTE_LINK))
          diff_dir(in, w);
      } else if ((f & (NOTE_WRITE | NOTE_EXTEND)) && (w->mask & LINUX_IN_MODIFY)) {
        emit(in, w->wd, LINUX_IN_MODIFY, NULL);
      }
      if ((f & NOTE_ATTRIB) && (w->mask & LINUX_IN_ATTRIB))
        emit(in, w->wd, LINUX_IN_ATTRIB, NULL);
      if ((f & NOTE_RENAME) && (w->mask & LINUX_IN_MOVE_SELF))
        emit(in, w->wd, LINUX_IN_MOVE_SELF, NULL);
      if (f & NOTE_REVOKE)
        emit(in, w->wd, LINUX_IN_UNMOUNT, NULL);
      if (f & NOTE_DELETE) {
        if (w->mask & LINUX_IN_DELETE_SELF)
          emit(in, w->wd, LINUX_IN_DELETE_SELF, NULL);
        /* The watch goes with the file, and Linux says so before it does. */
        emit(in, w->wd, LINUX_IN_IGNORED, NULL);
        w->live = false;
        close(w->fd);
        names_free(w);
      }
      if (w->live && (w->mask & LINUX_IN_ONESHOT)) {
        emit(in, w->wd, LINUX_IN_IGNORED, NULL);
        w->live = false;
        close(w->fd);
        names_free(w);
      }
    }
    pthread_mutex_unlock(&in->lock);
  }
  return NULL;
}

/* ------------------------------------------------------------- the syscalls */

static struct ino_inst *
inst_of(int fd)
{
  if (!instances)
    return NULL;
  pthread_mutex_lock(&instances_lock);
  khiter_t k = kh_get(inst, instances, fd);
  struct ino_inst *in = k == kh_end(instances) ? NULL : kh_value(instances, k);
  pthread_mutex_unlock(&instances_lock);
  return in;
}

DEFINE_SYSCALL(inotify_init1, int, flags)
{
  if (flags & ~(LINUX_IN_NONBLOCK | LINUX_IN_CLOEXEC))
    return -LINUX_EINVAL;

  int p[2];
  if (pipe(p) < 0)
    return -darwin_to_linux_errno(errno);

  struct ino_inst *in = calloc(1, sizeof *in);
  if (!in) {
    close(p[0]);
    close(p[1]);
    return -LINUX_ENOMEM;
  }
  in->rd = p[0];
  in->wr = p[1];
  in->next_wd = 1;
  in->running = true;
  pthread_mutex_init(&in->lock, NULL);

  if ((in->kq = kqueue()) < 0) {
    int e = errno;
    close(p[0]); close(p[1]); free(in);
    return -darwin_to_linux_errno(e);
  }
  struct kevent wake;
  EV_SET(&wake, WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  kevent(in->kq, &wake, 1, NULL, 0, NULL);

  if (flags & LINUX_IN_NONBLOCK)
    fcntl(in->rd, F_SETFL, O_NONBLOCK);
  if (flags & LINUX_IN_CLOEXEC)
    fcntl(in->rd, F_SETFD, FD_CLOEXEC);

  if (pthread_create(&in->thread, NULL, watcher, in) != 0) {
    close(in->kq); close(p[0]); close(p[1]); free(in);
    return -LINUX_ENOMEM;
  }

  int err = register_fd(in->rd, (flags & LINUX_IN_CLOEXEC) != 0);
  if (err < 0) {
    pthread_mutex_lock(&in->lock);
    in->running = false;
    pthread_mutex_unlock(&in->lock);
    EV_SET(&wake, WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(in->kq, &wake, 1, NULL, 0, NULL);
    pthread_join(in->thread, NULL);
    close(in->kq); close(p[0]); close(p[1]); free(in);
    return err;
  }

  pthread_mutex_lock(&instances_lock);
  if (!instances)
    instances = kh_init(inst);
  int ret;
  khiter_t k = kh_put(inst, instances, in->rd, &ret);
  kh_value(instances, k) = in;
  pthread_mutex_unlock(&instances_lock);

  return in->rd;
}

/* Only x86-64 has the flagless form; the asm-generic table arm64 uses dropped
 * it and kept inotify_init1 alone. */
#if defined(__x86_64__)
DEFINE_SYSCALL(inotify_init)
{
  return sys_inotify_init1(0);
}
#endif

/*
 * The events that can arrive from anywhere. A watch asking for nothing outside
 * this set would never fire and is refused rather than left to wait.
 *
 * IN_OPEN and the closes are deliberately *not* here even though they are
 * sometimes produced, because "sometimes" is the problem: they are synthesised
 * from the guest's own calls, and only in the process holding the instance. A
 * shell's `echo x > watched/f` forks, so the close happens somewhere with no
 * instance to tell - and `inotifywait -e close_write` on a directory other
 * processes write to would wait forever. Refusing a mask made only of them
 * turns that silence into an error; a mask that also asks for something real is
 * accepted, and gets the real part.
 */
#define INO_DELIVERABLE                                                       \
  (LINUX_IN_MODIFY | LINUX_IN_ATTRIB | LINUX_IN_MOVED_FROM |                  \
   LINUX_IN_MOVED_TO | LINUX_IN_CREATE | LINUX_IN_DELETE |                    \
   LINUX_IN_DELETE_SELF | LINUX_IN_MOVE_SELF)

DEFINE_SYSCALL(inotify_add_watch, int, fd, gstr_t, path_ptr, uint32_t, mask)
{
  char guestpath[LINUX_PATH_MAX];
  if (strncpy_from_user(guestpath, path_ptr, sizeof guestpath) < 0)
    return -LINUX_EFAULT;

  struct ino_inst *in = inst_of(fd);
  if (!in)
    return -LINUX_EBADF;
  if ((mask & LINUX_IN_ALL_EVENTS) == 0)
    return -LINUX_EINVAL;
  if ((mask & INO_DELIVERABLE) == 0)
    return -LINUX_EINVAL;       /* nothing in it could ever arrive */

  char host[PATH_MAX];
  int r = guest_to_host_path(guestpath, host, sizeof host);
  if (r < 0)
    return r;

  struct stat st;
  if (stat(host, &st) < 0)
    return -darwin_to_linux_errno(errno);
  if ((mask & LINUX_IN_ONLYDIR) && !S_ISDIR(st.st_mode))
    return -LINUX_ENOTDIR;

  pthread_mutex_lock(&in->lock);

  /* An existing watch on the same object is updated, not duplicated. */
  for (size_t i = 0; i < in->nw; i++) {
    if (!in->w[i].live || strcmp(in->w[i].path, host) != 0)
      continue;
    if (mask & LINUX_IN_MASK_CREATE) {
      pthread_mutex_unlock(&in->lock);
      return -LINUX_EEXIST;
    }
    in->w[i].mask = (mask & LINUX_IN_MASK_ADD) ? in->w[i].mask | mask : mask;
    int wd = in->w[i].wd;
    pthread_mutex_unlock(&in->lock);
    return wd;
  }

  if (in->nw == INO_MAX_WATCH) {
    pthread_mutex_unlock(&in->lock);
    return -LINUX_ENOSPC;
  }

  int wfd = open(host, O_EVTONLY | ((mask & LINUX_IN_DONT_FOLLOW) ? O_SYMLINK : 0));
  if (wfd < 0) {
    int e = errno;
    pthread_mutex_unlock(&in->lock);
    return -darwin_to_linux_errno(e);
  }

  struct ino_watch *w = &in->w[in->nw];
  memset(w, 0, sizeof *w);
  w->wd = in->next_wd++;
  w->fd = wfd;
  w->mask = mask;
  w->isdir = S_ISDIR(st.st_mode);
  w->live = true;
  snprintf(w->path, sizeof w->path, "%s", host);
  if (w->isdir)
    names_read(w->path, &w->names, &w->nnames);

  struct kevent kev;
  EV_SET(&kev, wfd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
         NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_DELETE |
         NOTE_RENAME | NOTE_REVOKE, 0, NULL);
  if (kevent(in->kq, &kev, 1, NULL, 0, NULL) < 0) {
    int e = errno;
    close(wfd);
    names_free(w);
    pthread_mutex_unlock(&in->lock);
    return -darwin_to_linux_errno(e);
  }

  in->nw++;
  any_watches = 1;
  int wd = w->wd;
  pthread_mutex_unlock(&in->lock);
  return wd;
}

DEFINE_SYSCALL(inotify_rm_watch, int, fd, int, wd)
{
  struct ino_inst *in = inst_of(fd);
  if (!in)
    return -LINUX_EBADF;

  pthread_mutex_lock(&in->lock);
  for (size_t i = 0; i < in->nw; i++) {
    if (in->w[i].wd != wd || !in->w[i].live)
      continue;
    /* Linux tells the reader the watch is gone before it is. */
    emit(in, wd, LINUX_IN_IGNORED, NULL);
    in->w[i].live = false;
    close(in->w[i].fd);
    names_free(&in->w[i]);
    pthread_mutex_unlock(&in->lock);
    return 0;
  }
  pthread_mutex_unlock(&in->lock);
  return -LINUX_EINVAL;
}

/*
 * IN_OPEN and the two closes, which the host cannot see.
 *
 * kqueue has no notion of a file being opened or closed, so these are taken
 * from the guest's own calls. That covers a guest watching work it is doing
 * itself, which is what almost every use of them is; it cannot see a macOS
 * program touching the same file, and nothing here pretends otherwise.
 */
/* Whether anything is watching at all. Asked before a caller goes to the
 * trouble of finding a descriptor's path, so that a guest with no watches -
 * which is nearly every guest - pays a load and a branch per close. */
bool
inotify_watching(void)
{
  return any_watches != 0;
}

void
inotify_note_open(const char *hostpath, bool isdir)
{
  if (!any_watches || !instances || !hostpath)
    return;
  pthread_mutex_lock(&instances_lock);
  for (khiter_t k = kh_begin(instances); k != kh_end(instances); ++k) {
    if (!kh_exist(instances, k))
      continue;
    struct ino_inst *in = kh_value(instances, k);
    pthread_mutex_lock(&in->lock);
    for (size_t i = 0; i < in->nw; i++) {
      struct ino_watch *w = &in->w[i];
      if (!w->live || !(w->mask & LINUX_IN_OPEN))
        continue;
      if (strcmp(w->path, hostpath) == 0)
        emit(in, w->wd, LINUX_IN_OPEN | (isdir ? LINUX_IN_ISDIR : 0), NULL);
      else if (w->isdir) {
        size_t n = strlen(w->path);
        if (strncmp(hostpath, w->path, n) == 0 && hostpath[n] == '/' &&
            !strchr(hostpath + n + 1, '/'))
          emit(in, w->wd, LINUX_IN_OPEN | (isdir ? LINUX_IN_ISDIR : 0),
               hostpath + n + 1);
      }
    }
    pthread_mutex_unlock(&in->lock);
  }
  pthread_mutex_unlock(&instances_lock);
}

void
inotify_note_close(const char *hostpath, bool written)
{
  if (!any_watches || !instances || !hostpath)
    return;
  uint32_t want = written ? LINUX_IN_CLOSE_WRITE : LINUX_IN_CLOSE_NOWRITE;
  pthread_mutex_lock(&instances_lock);
  for (khiter_t k = kh_begin(instances); k != kh_end(instances); ++k) {
    if (!kh_exist(instances, k))
      continue;
    struct ino_inst *in = kh_value(instances, k);
    pthread_mutex_lock(&in->lock);
    for (size_t i = 0; i < in->nw; i++) {
      struct ino_watch *w = &in->w[i];
      if (!w->live || !(w->mask & want))
        continue;
      if (strcmp(w->path, hostpath) == 0)
        emit(in, w->wd, want, NULL);
      else if (w->isdir) {
        size_t n = strlen(w->path);
        if (strncmp(hostpath, w->path, n) == 0 && hostpath[n] == '/' &&
            !strchr(hostpath + n + 1, '/'))
          emit(in, w->wd, want, hostpath + n + 1);
      }
    }
    pthread_mutex_unlock(&in->lock);
  }
  pthread_mutex_unlock(&instances_lock);
}

/* The guest closed an inotify descriptor: stop the thread and let it go. */
void
inotify_close(int fd)
{
  if (!instances)
    return;
  pthread_mutex_lock(&instances_lock);
  khiter_t k = kh_get(inst, instances, fd);
  if (k == kh_end(instances)) {
    pthread_mutex_unlock(&instances_lock);
    return;
  }
  struct ino_inst *in = kh_value(instances, k);
  kh_del(inst, instances, k);
  pthread_mutex_unlock(&instances_lock);

  pthread_mutex_lock(&in->lock);
  in->running = false;
  pthread_mutex_unlock(&in->lock);

  struct kevent wake;
  EV_SET(&wake, WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  kevent(in->kq, &wake, 1, NULL, 0, NULL);
  pthread_join(in->thread, NULL);

  for (size_t i = 0; i < in->nw; i++)
    if (in->w[i].live) {
      close(in->w[i].fd);
      names_free(&in->w[i]);
    }
  close(in->kq);
  close(in->wr);
  free(in);
}
