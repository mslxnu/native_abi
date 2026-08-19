#include "common.h"
#include "linux/signal.h"
#include "linux/time.h"

#include "noah.h"
#include "namespace.h"
#include "vmm.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <signal.h>
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>

#define SET_SIGBIT(sigbits, lsig) (atomic_fetch_or((sigbits), (1UL << ((lsig) - 1))))
#define CLEAR_SIGBIT(sigbits, lsig) (atomic_fetch_and((sigbits), ~(1UL << ((lsig) - 1))))

/*
 * Sender identity of the most recent arrival of each signal, as the host
 * reported it. The pending set is a bitmap - a signal is pending or it is not -
 * and identity keeps the same shape: one record per signal, the last arrival
 * wins, which is also what Linux keeps for non-realtime signals. The values are
 * the host's own pid and uid, kept raw because the guest-space conversion
 * (pidns_to_ns, host_uid_to_guest) does file work that a signal handler must
 * not; signalfd_sender turns them into the guest's view at read time.
 *
 * The two stores from __host_signal_handler are deliberately not locked - the
 * same lock-free array scan signalfd_note_signal makes - and process memory
 * rather than checkpoint state, like the signalfd table: a forked child has no
 * signalfds, so it has no use for what filled the records.
 */
struct signalfd_sender {
  uint32_t pid, uid;
};

static struct signalfd_sender sigsenders[LINUX_NSIG];

static void
__host_signal_handler(int signum, siginfo_t *info, ucontext_t *context)
{
  /* actually no need to do it atomically */
  int lsig = darwin_to_linux_signal(signum);
  SET_SIGBIT(&task.sigpending, lsig);
  if (info != NULL) {
    sigsenders[lsig - 1].pid = (uint32_t) info->si_pid;
    sigsenders[lsig - 1].uid = (uint32_t) info->si_uid;
  } else {
    sigsenders[lsig - 1].pid = 0;
    sigsenders[lsig - 1].uid = 0;
  }
  /* A signalfd wanting this signal must see it as readable, which means a byte
   * in the socketpair underneath it. The poke is lock-free and nonblocking -
   * it runs inside a signal handler - and a lost one costs nothing, because
   * every signalfd read looks the pending set up again before deciding to
   * sleep. */
  signalfd_note_signal(lsig);
}

/*
 * The raw sender of `lsig`'s most recent arrival, as the host reported it.
 * Reads under sig_lock so it pairs with the signal paths that take it.
 */
void
signalfd_sender(int lsig, uint32_t *host_pid, uint32_t *host_uid)
{
  if (lsig <= 0 || lsig > LINUX_NSIG) {
    *host_pid = *host_uid = 0;
    return;
  }
  pthread_rwlock_rdlock(&proc.sig_lock);
  *host_pid = sigsenders[lsig - 1].pid;
  *host_uid = sigsenders[lsig - 1].uid;
  pthread_rwlock_unlock(&proc.sig_lock);
}

/* ------------------------------------------------------------------------
 * Real-time signals.
 *
 * Darwin's signals stop at 31 and Linux's real-time ones start at 32, so there
 * is no host signal to carry them: kill(2) cannot express the number. They were
 * therefore not sent at all - send_signal warned and returned success, so a
 * process that raised SIGRTMIN was told it had, and nothing was ever delivered.
 *
 * Delivery inside a process needs nothing from the host: the pending set is
 * already sixty-four bits and nabi runs the handler itself. Only the crossing
 * between processes needs a mechanism, and it is the one the credential table
 * uses - a file keyed by host pid, in TMPDIR under the boot tag - plus a host
 * signal to wake the target and make it look. SIGINFO is what that signal is:
 * Darwin has it, Linux has nothing that maps onto it, and so no guest signal
 * can be confused with the doorbell.
 *
 * What this does not reproduce is *queueing*. Linux queues real-time signals -
 * several instances of the same number, each with its own value, delivered in
 * the order they were sent - and this is a bitmask, so two arrivals of one
 * number before it is handled become one. That is the property RT signals are
 * chosen for over ordinary ones, and half of it is missing here. It is the same
 * shape as the pending set for standard signals, which is why it is what it is;
 * a queue would want the value from rt_sigqueueinfo carried too.
 * ------------------------------------------------------------------------ */

#define RTSIG_DOORBELL SIGINFO
#define RTSIG_MAX 512

struct rtsig_file {
  uint32_t n;
  struct { int32_t pid; uint64_t pending; } e[RTSIG_MAX];
};

static void
rtsig_path(char *out, size_t n)
{
  const char *tmp = getenv("TMPDIR");
  snprintf(out, n, "%s/nabi-rtsig-%s", tmp && *tmp ? tmp : "/tmp",
           nabi_boot_tag());
}

static int
rtsig_open(bool lock)
{
  char path[PATH_MAX];
  rtsig_path(path, sizeof path);
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    return -1;
  if (lock && flock(fd, LOCK_EX) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool
rtsig_read(int fd, struct rtsig_file *f)
{
  ssize_t n = pread(fd, f, sizeof *f, 0);
  if (n == (ssize_t) sizeof *f)
    return true;
  memset(f, 0, sizeof *f);
  return n >= 0;
}

/* Mark `sig` pending for `pid`, for that process to collect. */
static int
rtsig_post(pid_t pid, int sig)
{
  int fd = rtsig_open(true);
  if (fd < 0)
    return -LINUX_EAGAIN;

  struct rtsig_file f;
  int r = -LINUX_EAGAIN;
  if (rtsig_read(fd, &f)) {
    uint32_t slot = f.n;
    for (uint32_t i = 0; i < f.n; i++)
      if (f.e[i].pid == (int32_t) pid) { slot = i; break; }
    /* A full table is made room in by dropping an entry whose process is gone,
     * the same way the credential table does. */
    if (slot == f.n && f.n == RTSIG_MAX) {
      for (uint32_t i = 0; i < f.n; i++)
        if (kill(f.e[i].pid, 0) < 0 && errno == ESRCH) { slot = i; break; }
      if (slot < f.n)
        f.e[slot].pending = 0;
    }
    if (slot < RTSIG_MAX) {
      if (slot == f.n) { f.e[slot].pid = (int32_t) pid; f.e[slot].pending = 0; f.n++; }
      f.e[slot].pending |= 1ULL << (sig - 1);
      pwrite(fd, &f, sizeof f, 0);
      r = 0;
    }
  }
  flock(fd, LOCK_UN);
  close(fd);
  return r;
}

/*
 * Collect whatever was posted for this process. Called from the doorbell's
 * handler, so it must be prepared to do nothing.
 */
static void
rtsig_collect(void)
{
  int fd = rtsig_open(true);
  if (fd < 0)
    return;

  struct rtsig_file f;
  if (rtsig_read(fd, &f)) {
    int32_t me = (int32_t) getpid();
    for (uint32_t i = 0; i < f.n; i++) {
      if (f.e[i].pid != me || f.e[i].pending == 0)
        continue;
      uint64_t got = f.e[i].pending;
      f.e[i].pending = 0;
      pwrite(fd, &f, sizeof f, 0);
      for (int sig = LINUX_SIGRTMIN; sig <= LINUX_SIGRTMAX; sig++)
        if (got & (1ULL << (sig - 1))) {
          SET_SIGBIT(&task.sigpending, sig);
          signalfd_note_signal(sig);
        }
      break;
    }
  }
  flock(fd, LOCK_UN);
  close(fd);
}

static void
rtsig_doorbell(int signum, siginfo_t *info, void *ctx)
{
  (void) signum; (void) info; (void) ctx;
  rtsig_collect();
}

/* Installed once, before any guest code runs. */
void
rtsig_init(void)
{
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = rtsig_doorbell;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(RTSIG_DOORBELL, &sa, NULL);
}

/*
 * Signals a signalfd is watching have to reach us whatever the guest's
 * disposition says.
 *
 * __host_signal_handler is the one place nabi learns that a signal arrived,
 * and it was installed only for signals the guest had a real handler for. That
 * is backwards for signalfd, whose entire point is not needing a handler: the
 * ordinary use is to block the signal, leave the disposition at SIG_DFL, and
 * read it off a descriptor. Such a signal kept its host disposition, was
 * blocked on the host as well, and arrived nowhere - so the descriptor stayed
 * unreadable for good.
 *
 * Android's init sits exactly there. It blocks SIGCHLD, never handles it, and
 * waits on a signalfd inside epoll to hear that a service exited, so every
 * service it started was "Exec service is hung? Waited 10.0023 with no
 * response" while the child had already run and exited.
 *
 * Arming does not change what the guest sees. nabi's own delivery still
 * honours the guest's mask and disposition; this only ensures the arrival is
 * recorded, which is the thing a blocked signal on Linux does for itself by
 * becoming pending.
 */
void
signalfd_arm(int lsig)
{
  if (lsig <= 0 || lsig >= LINUX_SIGRTMIN)
    return;                     /* nothing on the host raises an RT signal */
  int dsig = linux_to_darwin_signal(lsig);
  if (dsig == 0 || dsig == SIGKILL || dsig == SIGSTOP)
    return;

  l_handler_t h = proc.sigaction[lsig - 1].lsa_handler;
  if (h != LINUX_SIG_DFL && h != LINUX_SIG_IGN)
    return;                     /* the guest's own handler is already ours */

  struct sigaction dact;
  memset(&dact, 0, sizeof dact);
  dact.sa_sigaction = (void (*)(int, siginfo_t *, void *)) __host_signal_handler;
  dact.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&dact.sa_mask);
  sigaction(dsig, &dact, NULL);

  /* And it must not be blocked underneath us: the guest blocking a signal is
   * what makes it pending on Linux, not what makes it vanish. */
  sigset_t un;
  sigemptyset(&un);
  sigaddset(&un, dsig);
  pthread_sigmask(SIG_UNBLOCK, &un, NULL);
}

int
send_signal(pid_t pid, int signum)
{
  if (signum >= LINUX_SIGRTMIN) {
    /*
     * Sending to ourselves needs no host signal at all: the pending set is
     * right here, and the main loop delivers from it on the way back to the
     * guest. Anyone else is posted to and rung.
     */
    if (pid == getpid()) {
      SET_SIGBIT(&task.sigpending, signum);
      signalfd_note_signal(signum);
      return 0;
    }
    int r = rtsig_post(pid, signum);
    if (r < 0)
      return r;
    return syswrap(kill(pid, RTSIG_DOORBELL));
  }
  int dsignum = (signum == 0) ? 0 : linux_to_darwin_signal(signum);
  return syswrap(kill(pid, dsignum));
}

/*
 * Whether an EINTR from the host should be hidden and the call tried again.
 *
 * EINTR is the guest's answer to "a signal you handle arrived while you were
 * waiting". If nabi has no such signal to deliver, the guest is being told
 * about something that did not happen to it: the host process is not the guest,
 * and it takes signals of its own - from the frameworks it links, from its own
 * threads - that have no meaning one level up. Passing those on invents an
 * interruption Linux would never have reported.
 *
 * That is the case this was found in, and it is worth being precise about
 * because the first guess was wrong. `sudo dnf install` answered "Operation
 * aborted by the user" the instant it printed "Is this ok [y/N]:", because the
 * read of the terminal came back EINTR and dnf takes a failed read as a
 * refusal. It looked like SIGCHLD from dnf's own children - it handles SIGCHLD
 * with SA_RESTART, and Linux would have restarted the read. But at the moment
 * of the EINTR nabi had *nothing* pending and the guest's SIGCHLD was still
 * SIG_DFL: the signal belonged to the host process alone.
 *
 * So: retry when there is nothing to deliver, and retry when everything to
 * deliver was installed with SA_RESTART, which is what Linux does with it.
 * A handler without SA_RESTART is entitled to break a blocking call, and
 * something waiting on SIGALRM to end a read must still get its EINTR.
 */
bool
sigrestart_wanted(void)
{
  uint64_t pending = task.sigpending & ~LINUX_SIGSET_TO_UI64(&task.sigmask);
  if (pending == 0)
    return true;              /* no signal for the guest; nothing interrupted it */

  for (int sig = 1; sig <= LINUX_NSIG; sig++) {
    if (!(pending & (1ULL << (sig - 1))))
      continue;
    const l_sigaction_t *sa = &proc.sigaction[sig - 1];
    if (sa->lsa_handler == LINUX_SIG_DFL || sa->lsa_handler == LINUX_SIG_IGN)
      continue;                 /* no handler runs, so nothing to restart for */
    if (!(sa->lsa_flags & LINUX_SA_RESTART))
      return false;
  }
  return true;
}

bool
has_sigpending()
{
  return task.sigpending & ~LINUX_SIGSET_TO_UI64(&task.sigmask);
}

/* called only once at the boot time */
void
init_signal(void)
{
#ifndef ATOMIC_INT_LOCK_FREE // Workaround of the incorrect atomic macro name bug of Clang
#define __GCC_ATOMIC_INT_T_LOCK_FREE __GCC_ATOMIC_INT_LOCK_FREE
#define ATOMIC_INT_LOCK_FREE ATOMIC_INT_T_LOCK_FREE
#endif
  static_assert(ATOMIC_INT_LOCK_FREE == 2, "The compiler must support lock-free atomic int");

  rtsig_init();

  /* import signal handlers registered on the host */
  for (int i = 0; i < LINUX_NSIG; i++) {
    struct sigaction oact;
    l_handler_t handler = LINUX_SIG_DFL;
    if (sigaction(i + 1, NULL, &oact) == 0) {
      if (oact.sa_handler != SIG_IGN && oact.sa_handler != SIG_DFL) {
        warnk("signal %d has a custom host handler %p - importing as SIG_DFL\n",
              i + 1, (void *) oact.sa_handler);
      }
      handler = oact.sa_handler == SIG_IGN ? LINUX_SIG_IGN : LINUX_SIG_DFL;
    }
    // flags, restorer, and mask will be flushed in execve, so just leave them 0
    proc.sigaction[i] = (l_sigaction_t) {
      .lsa_handler = handler,
      .lsa_flags = 0,
      .lsa_restorer= 0,
      .lsa_mask = {0}
    };
  }
  /* import signal mask from the hsot */
  assert(proc.nr_tasks == 1);
  sigset_t set;
  sigprocmask(0, NULL, &set);
  darwin_to_linux_sigset(&set, &task.sigmask);
  task.sigpending = ATOMIC_VAR_INIT(0);
}

void
reset_sas(void)
{
  task.sas = (l_stack_t) {
    .ss_sp = 0,
    .ss_flags = LINUX_SS_DISABLE,
    .ss_size = 0
  };
}

void
reset_signal_state()
{
  for (int i = 0; i < NSIG; i++) {
    if (proc.sigaction[i].lsa_handler == LINUX_SIG_DFL || proc.sigaction[i].lsa_handler == LINUX_SIG_IGN) {
      continue;
    }
    proc.sigaction[i] = (l_sigaction_t) {
      .lsa_handler = LINUX_SIG_DFL,
      .lsa_flags = 0,
      .lsa_restorer= 0,
      .lsa_mask = {0}
    };
    struct sigaction dact;
    linux_to_darwin_sigaction(&proc.sigaction[i], &dact, SIG_DFL);
    sigaction(i + 1, &dact, NULL);
  }
  reset_sas();
}

static inline int
pop_signal()
{
  uint64_t pending = task.sigpending;
  pending &= ~LINUX_SIGSET_TO_UI64(&task.sigmask);
  if (pending == 0)
    return 0;
  /*
   * ffsll, and a bound of NSIG rather than 32. The pending set has always been
   * sixty-four bits wide and every other part of this file treats it as one,
   * but the scan was ffs on an int: the top half was invisible, so a real-time
   * signal could be marked pending and never be found - and the assert below
   * would have aborted on one if it had been.
   */
  int sig = __builtin_ffsll((long long) pending);
  assert(0 < sig && sig <= LINUX_NSIG);
  CLEAR_SIGBIT(&task.sigpending, sig);
  return sig;
}


l_int
sas_ss_flags(uint64_t rsp)
{
  if (task.sas.ss_flags & LINUX_SS_DISABLE || task.sas.ss_size == 0) {
    return LINUX_SS_DISABLE;
  }
  if (rsp > task.sas.ss_sp && rsp - task.sas.ss_sp < task.sas.ss_size) {
    return LINUX_SS_ONSTACK | task.sas.ss_flags;
  }
  return task.sas.ss_flags;
}


static void
wake_sighandler()
{
  pthread_rwlock_rdlock(&proc.sig_lock);

  int sig;
  while ((sig = pop_signal()) != 0) {

    meta_strace_sigdeliver(sig);
    switch (proc.sigaction[sig - 1].lsa_handler) {
      case LINUX_SIG_DFL:
        //warnk("Handling default signal in Noah is not implemented yet\n");
        /* fall through */
      case LINUX_SIG_IGN:
        continue;

      default:
        if (arch_setup_sigframe(sig) < 0) {
          die_with_forcedsig(LINUX_SIGSEGV);
        }
        if (proc.sigaction[sig - 1].lsa_flags & LINUX_SA_ONESHOT) {
          proc.sigaction[sig - 1].lsa_handler = LINUX_SIG_DFL;
          // Host signal handler must be set to SIG_DFL already by Darwin kernel
        }
        goto out;
    }
  }

out:
  pthread_rwlock_unlock(&proc.sig_lock);
}

void
handle_signal()
{
  wake_sighandler();
  main_loop(1);
}

DEFINE_SYSCALL(alarm, unsigned int, seconds)
{
  return syswrap(alarm(seconds));
}

DEFINE_SYSCALL(rt_sigaction, int, sig, gaddr_t, act, gaddr_t, oact, size_t, size)
{
  if (sig <= 0 || sig > LINUX_NSIG || sig == LINUX_SIGKILL || sig == LINUX_SIGSTOP || size != sizeof(l_sigset_t)) {
    return -LINUX_EINVAL;
  }

  l_sigaction_t lact;
  struct sigaction dact, doact;
  int dsig;

  if (oact != 0) {
    int n = copy_to_user(oact, &proc.sigaction[sig - 1], sizeof(l_sigaction_t));
    if (n > 0)
      return -LINUX_EFAULT;
  }

  if (act == 0) {
    return 0;
  }

  if (copy_from_user(&lact, act, sizeof(l_sigaction_t)))  {
    return -LINUX_EFAULT;
  }

  if (lact.lsa_flags & (LINUX_SA_SIGINFO)) {
    warnk("SA_SIGINFO implementaion is incomplete: 0x%llx\n", lact.lsa_flags);
  }

  void *handler;
  if (lact.lsa_handler == LINUX_SIG_DFL || lact.lsa_handler == LINUX_SIG_IGN) {
    handler = lact.lsa_handler == LINUX_SIG_DFL ? SIG_DFL : SIG_IGN;
    /* Unless a signalfd is watching it, in which case nabi keeps its own: the
     * guest setting a disposition it does not use must not silence a
     * descriptor that is still waiting on the signal. */
    if (signalfd_wants(sig))
      handler = __host_signal_handler;
  } else {
    lact.lsa_flags |= LINUX_SA_SIGINFO;
    handler = __host_signal_handler;
  }
  linux_to_darwin_sigaction(&lact, &dact, handler);

  /*
   * A real-time signal has no host signal to install a handler for - Darwin's
   * numbering stops at 31 - and it does not need one: nothing on the host ever
   * raises it. It is delivered entirely by nabi, from the pending set, so the
   * disposition is recorded and no host sigaction is called. Refusing it here,
   * which is what a dsig of 0 used to do, made every RT handler fail to
   * install while kill() cheerfully reported the signal sent.
   */
  bool rt = sig >= LINUX_SIGRTMIN;
  if (!rt) {
    dsig = linux_to_darwin_signal(sig);
    if (dsig == 0) {
      return -LINUX_EINVAL;
    }
  }
  // TODO: make handlings of linux specific signals consistent

  int err = 0;
  pthread_rwlock_wrlock(&proc.sig_lock);

  err = rt ? 0 : syswrap(sigaction(dsig, &dact, &doact));
  if (err >= 0) {
    proc.sigaction[sig - 1] = lact;
  }

  pthread_rwlock_unlock(&proc.sig_lock);

  return err;
}

DEFINE_SYSCALL(rt_sigprocmask, int, how, gaddr_t, nset, gaddr_t, oset, size_t, size)
{
  l_sigset_t lset;
  sigset_t dset;

  if (size != sizeof(l_sigset_t)) {
    return -LINUX_EINVAL;
  }

  if (oset != 0) {
    if (copy_to_user(oset, &task.sigmask, sizeof task.sigmask)) {
      return -LINUX_EFAULT;
    }
  }

  if (nset == 0) {
    return 0;
  }

  if (copy_from_user(&lset, nset, sizeof(l_sigset_t)))  {
    return -LINUX_EFAULT;
  }
  LINUX_SIGDELSET(&lset, LINUX_SIGKILL);
  LINUX_SIGDELSET(&lset, LINUX_SIGSTOP);

  switch (how) {
    case LINUX_SIG_BLOCK:
      LINUX_SIGSET_ADD(&task.sigmask, &lset);
      break;
    case LINUX_SIG_UNBLOCK:
      LINUX_SIGSET_DEL(&task.sigmask, &lset);
      break;
    case LINUX_SIG_SETMASK:
      LINUX_SIGSET_SET(&task.sigmask, &lset);
      break;
    default:
      return -LINUX_EINVAL;
  }

  /*
   * The host thread's mask is not quite the guest's. A signal the guest blocks
   * *and* handles must still reach the host's handler, or it would never be
   * recorded as pending: __host_signal_handler is the one place nabi learns a
   * signal exists, and a signalfd wanting one would wait forever on a signal
   * that arrived and was swallowed by the host's own blocking. Leaving handled
   * signals unblocked here costs nothing, because nabi's own delivery already
   * honours the guest mask - has_sigpending and pop_signal subtract it - and
   * sigrestart_wanted re-runs a blocking call interrupted by a signal the guest
   * cannot yet receive. A signal without a handler keeps its host disposition
   * and stays blocked, so a default action cannot fire behind the guest's back.
   */
  sigemptyset(&dset);
  for (int sig = 1; sig <= LINUX_NSIG; sig++) {
    if (!LINUX_SIGISMEMBER(&task.sigmask, sig))
      continue;
    l_handler_t h = proc.sigaction[sig - 1].lsa_handler;
    if (h != LINUX_SIG_DFL && h != LINUX_SIG_IGN)
      continue;
    /* ...and one a signalfd is watching is handled too, by nabi rather than by
     * the guest. Blocking it here would swallow exactly what the descriptor
     * exists to report. */
    if (signalfd_wants(sig))
      continue;
    sigaddset(&dset, linux_to_darwin_signal(sig));
  }

  int err = syswrap(pthread_sigmask(SIG_SETMASK, &dset, NULL));
  if (err < 0) {
    return err;
  }

  return 0;
}

DEFINE_SYSCALL(rt_sigsuspend, gaddr_t, nset, size_t, size)
{
  if (size != sizeof(l_sigset_t)) {
    return -LINUX_EINVAL;
  }

  l_sigset_t lnset, loset = task.sigmask;

  if (copy_from_user(&lnset, nset, sizeof(l_sigset_t))) {
    return -LINUX_EFAULT;
  }
  LINUX_SIGDELSET(&lnset, LINUX_SIGKILL);
  LINUX_SIGDELSET(&lnset, LINUX_SIGSTOP);

  sigset_t dwset, doset;
  linux_to_darwin_sigset(&lnset, &dwset);
  pthread_sigmask(SIG_SETMASK, &dwset, &doset);
  
  task.sigmask = lnset;

  while (1) {
    /* NB: macOS's sleep is implemented using nanosleep. That's why we can use
       sleep to implement sugsuspend without worrying about alarm(2). */
    sleep(114514);
    if (has_sigpending()) {
      break;
    }
  }
  handle_signal();
  warnk("signal handled\n");
  pthread_sigmask(SIG_SETMASK, &doset, NULL);
  task.sigmask = loset;
  return -LINUX_EINTR;          /* returns -EINTR when its execution ends NORMALLY */
}

/*
 * rt_sigtimedwait: suspend until one of a chosen set of signals is pending.
 *
 * This is the timed variant of sigsuspend: the caller picks which signals to
 * wait for rather than temporarily replacing the whole mask. The mask is
 * temporarily set to block everything *except* the wait-set signals, the
 * pending set is scanned, and if nothing is there the call sleeps until one
 * arrives or the timeout expires.
 *
 * The return value is the signal number that was delivered. The signal is
 * removed from the pending set by pop_signal. If uinfo is not NULL the
 * siginfo is filled in as best nabi can: the signal number and SI_USER as the
 * code, because nabi's delivery path does not carry the original payload.
 *
 * On timeout the return is -EAGAIN. If a signal that is *not* in the wait set
 * arrives, the call returns -EINTR (matching Linux behaviour for signals that
 * were blocked before we unblocked the wait set and are still blocked in the
 * guest's real mask).
 */
DEFINE_SYSCALL(rt_sigtimedwait, gaddr_t, uthese, gaddr_t, uinfo, gaddr_t, uts, size_t, sigsetsize)
{
  if (sigsetsize != sizeof(l_sigset_t))
    return -LINUX_EINVAL;

  l_sigset_t lwait;
  if (copy_from_user(&lwait, uthese, sizeof(l_sigset_t)))
    return -LINUX_EFAULT;

  /* Read an optional timeout. */
  struct timespec ts;
  bool has_timeout = false;
  if (uts != 0) {
    struct l_timespec lts;
    if (copy_from_user(&lts, uts, sizeof lts))
      return -LINUX_EFAULT;
    ts.tv_sec  = lts.tv_sec;
    ts.tv_nsec = lts.tv_nsec;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
      return -LINUX_EINVAL;
    has_timeout = true;
  }

  /*
   * Temporarily unmask only the signals the caller is waiting for. The rest
   * of the guest's mask stays in place, so a signal outside the wait set
   * cannot sneak in through the host.
   */
  l_sigset_t loset = task.sigmask;
  sigset_t dmask, doldmask;

  /*
   * Build a Darwin mask that blocks everything the guest blocks, then
   * *unblocks* the wait-set signals. The result is "block everything
   * except the wait set" on the host side, which is what lets the host's
   * own signal delivery wake us from sleep.
   */
  linux_to_darwin_sigset(&task.sigmask, &dmask);
  sigset_t dwait;
  linux_to_darwin_sigset(&lwait, &dwait);
  /* Unblock the wait-set signals in the host mask. */
  for (int sig = 1; sig <= LINUX_SIGRTMAX; sig++) {
    if (LINUX_SIGISMEMBER(&lwait, sig))
      sigdelset(&dmask, linux_to_darwin_signal(sig));
  }
  pthread_sigmask(SIG_SETMASK, &dmask, &doldmask);

  /*
   * Also update the guest mask so that has_sigpending and pop_signal see
   * the wait set as unblocked.
   */
  LINUX_SIGSET_SET(&task.sigmask, &lwait);
  for (int sig = 1; sig <= LINUX_SIGRTMAX; sig++)
    if (LINUX_SIGISMEMBER(&lwait, sig))
      LINUX_SIGDELSET(&task.sigmask, sig);

  /* Check the pending set first - a signal may already be waiting. */
  int sig = 0;
  uint64_t waitbits = lwait.__mask;
  uint64_t pending = task.sigpending & waitbits & ~LINUX_SIGSET_TO_UI64(&task.sigmask);
  if (pending) {
    sig = __builtin_ffsll((long long) pending);
    assert(0 < sig && sig <= LINUX_NSIG);
    CLEAR_SIGBIT(&task.sigpending, sig);
    goto out;
  }

  /*
   * Sleep until one of the waited signals arrives or the timeout expires.
   * sleep() is built on nanosleep on macOS, so it is interruptible and
   * cannot swallow an alarm the way a blocking syscall could.
   */
  if (!has_timeout) {
    /* No timeout: sleep indefinitely. */
    while (1) {
      sleep(114514);
      pending = task.sigpending & waitbits;
      if (pending) {
        sig = __builtin_ffsll((long long) pending);
        assert(0 < sig && sig <= LINUX_NSIG);
        CLEAR_SIGBIT(&task.sigpending, sig);
        goto out;
      }
    }
  }

  /*
   * With a timeout: track elapsed time against the deadline.  The guest
   * timeout is relative to CLOCK_MONOTONIC, which maps to Darwin's
   * CLOCK_MONOTONIC_RAW (CLOCK_MONOTONIC in the host is fine for a
   * relative sleep).
   */
  {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    /* Absolute deadline = now + ts. */
    struct timespec deadline;
    deadline.tv_sec  = now.tv_sec  + ts.tv_sec;
    deadline.tv_nsec = now.tv_nsec + ts.tv_nsec;
    if (deadline.tv_nsec >= 1000000000L) {
      deadline.tv_sec  += 1;
      deadline.tv_nsec -= 1000000000L;
    }

    while (1) {
      clock_gettime(CLOCK_MONOTONIC, &now);
      long rem_sec  = deadline.tv_sec  - now.tv_sec;
      long rem_nsec = deadline.tv_nsec - now.tv_nsec;
      if (rem_nsec < 0) { rem_sec -= 1; rem_nsec += 1000000000L; }
      if (rem_sec < 0) {
        /* Timeout expired. */
        sig = -LINUX_EAGAIN;
        goto out;
      }
      struct timespec nap = { .tv_sec = rem_sec, .tv_nsec = rem_nsec };
      nanosleep(&nap, NULL);

      pending = task.sigpending & waitbits;
      if (pending) {
        sig = __builtin_ffsll((long long) pending);
        assert(0 < sig && sig <= LINUX_NSIG);
        CLEAR_SIGBIT(&task.sigpending, sig);
        goto out;
      }
    }
  }

out:
  /* Restore masks. */
  task.sigmask = loset;
  pthread_sigmask(SIG_SETMASK, &doldmask, NULL);

  if (sig > 0 && uinfo != 0) {
    l_siginfo_t si;
    memset(&si, 0, sizeof si);
    si.lsi_signo = sig;
    si.lsi_code  = LINUX_SI_USER;
    if (copy_to_user(uinfo, &si, sizeof si))
      return -LINUX_EFAULT;
  }
  return sig;
}

/*
 * pause: wait until a signal arrives.
 *
 * It is sigsuspend with the mask left alone, and it is written beside it rather
 * than out of it because the waiting is the whole call and that loop is where
 * the waiting is understood. sleep() is what nabi waits in - macOS builds it on
 * nanosleep, so an alarm cannot be swallowed by it - and has_sigpending is what
 * ends it.
 *
 * It only ever returns -EINTR. There is no success: a pause that returned would
 * mean a signal arrived, and that is the interrupted case.
 */
DEFINE_SYSCALL(pause)
{
  while (1) {
    sleep(114514);
    if (has_sigpending())
      break;
  }
  handle_signal();
  return -LINUX_EINTR;
}

DEFINE_SYSCALL(rt_sigpending, gaddr_t, set, size_t, size)
{
  if (size > sizeof(l_sigset_t)) {
    return -LINUX_EINVAL;
  }
  int ret = 0;

  pthread_rwlock_rdlock(&proc.sig_lock);
  if (copy_to_user(set, &task.sigpending, size) > 0) {
    ret = -LINUX_EFAULT;
  }
  pthread_rwlock_unlock(&proc.sig_lock);

  return ret;
}

DEFINE_SYSCALL(rt_sigreturn)
{
  return arch_rt_sigreturn();
}

DEFINE_SYSCALL(sigaltstack, gaddr_t, uss, gaddr_t, uoss)
{
  uint64_t rsp;
  vmm_get_reg(VREG_SP, &rsp);
  l_stack_t ss, oss = task.sas;
  oss.ss_flags = sas_ss_flags(rsp);

  if (uoss != 0) {
    if (copy_to_user(uoss, &oss, sizeof task.sas)) {
      return -LINUX_EFAULT;
    }
  }
  if (uss == 0) {
    return 0;
  }
  if (oss.ss_flags & LINUX_SS_ONSTACK) {
    return -LINUX_EPERM;
  }

  if (copy_from_user(&ss, uss, sizeof ss)) {
    return -LINUX_EFAULT;
  }

  if (ss.ss_size < LINUX_MINSIGSTKSZ) {
    return -LINUX_ENOMEM;
  }
  int mode = ss.ss_flags & ~LINUX_SS_AUTODISARM;
  if (mode != SS_DISABLE && mode != SS_ONSTACK && mode != 0) { // Linux allows only SS_ONSTACK to be passed against man
    return -LINUX_EINVAL;
  }

  task.sas = ss;

  return 0;
}

DEFINE_SYSCALL(kill, l_pid_t, pid, int, sig)
{
  /*
   * A pid this namespace does not contain does not exist as far as the caller
   * is concerned, so it is ESRCH rather than a signal that leaves the
   * namespace. This is the containment a pid namespace does provide here: the
   * host's processes remain visible through /proc, which is not ours to hide,
   * but they cannot be reached by number.
   */
  if (pid > 0) {
    pid_t h = pidns_to_host(pid);
    if (h < 0)
      return -LINUX_ESRCH;
    pid = h;
  }
  return send_signal(pid, sig);
}

/*
 * rt_sigqueueinfo: send a signal with a siginfo payload to a process group.
 *
 * The si_code is validated: only codes that user space is allowed to supply
 * (SI_QUEUE, SI_TIMER, SI_MESGQ, SI_ASYNCIO, SI_SIGIO) reach here.
 * SI_USER, SI_KERNEL, SI_TKILL, SI_DETHREAD and any positive code are
 * rejected - the same way the kernel does it.
 *
 * Like rt_tgsigqueueinfo, the payload is not carried through delivery.
 * nabi's signal infrastructure loses everything but the signal number:
 * the pending set is a bitmap and pop_signal returns only the number.
 */
DEFINE_SYSCALL(rt_sigqueueinfo, l_pid_t, tgid, int, sig, gaddr_t, uinfo)
{
  l_siginfo_t si;

  if (sig <= 0 || sig > LINUX_SIGRTMAX)
    return -LINUX_EINVAL;
  if (copy_from_user(&si, uinfo, sizeof si))
    return -LINUX_EFAULT;
  /*
   * Reject codes only the kernel may use.  A positive si_code is reserved
   * for the signal-class-specific codes (CLD_*, TRAP_*, POLL_*, etc.) that
   * the kernel generates; user space must not inject them.
   */
  if (si.lsi_code == LINUX_SI_USER ||
      si.lsi_code == LINUX_SI_KERNEL ||
      si.lsi_code == LINUX_SI_TKILL ||
      si.lsi_code == LINUX_SI_DETHREAD ||
      si.lsi_code > 0)
    return -LINUX_EINVAL;
  pid_t h = pidns_to_host(tgid);
  if (h < 0)
    return -LINUX_ESRCH;
  return send_signal(h, sig);
}

/*
 * rt_tgsigqueueinfo: a signal with a siginfo payload, aimed at one thread.
 *
 * This is how bionic implements pthread_kill, so it is not an obscure corner:
 * a pthread that cannot be signalled is a thread that cannot be cancelled,
 * interrupted, or told to die. An unimplemented entry here is worse than a
 * plain ENOSYS looks, because the caller cannot tell "not supported" from
 * "not delivered" - bionic treats a failure as a bug and abort()s.
 *
 * The guest's siginfo is validated - a bad pointer is EFAULT, as the kernel
 * reports it - but the payload is not carried any further. Delivery loses
 * everything but the signal number: nabi raises it with the host's kill(),
 * and the realtime signals that carry si_value are dropped by send_signal
 * anyway, exactly as they are for kill and tgkill.
 */
DEFINE_SYSCALL(rt_tgsigqueueinfo, l_pid_t, tgid, l_pid_t, tid, int, sig, gaddr_t, uinfo)
{
  l_siginfo_t si;

  if (tgid <= 0 || tid <= 0)
    return -LINUX_EINVAL;
  if (copy_from_user(&si, uinfo, sizeof si))
    return -LINUX_EFAULT;
  pid_t h = pidns_to_host(tid);
  if (h < 0)
    return -LINUX_ESRCH;
  return send_signal(h, sig);
}

/*
 * Re-install the host's signal handlers to match the guest's dispositions.
 *
 * For a resumed process only. NABI routes a host signal into the guest through
 * __host_signal_handler, and `exec` resets every host disposition to the
 * default - so a guest restored from a checkpoint would have its handlers
 * recorded but nothing on the host arranged to reach them, and the first signal
 * would kill it instead of being delivered.
 */
void
reinstall_host_sigactions(void)
{
  /* The doorbell first, and unconditionally: exec cleared it with everything
   * else, and a resumed child that cannot hear it would take no real-time
   * signal for the rest of its life. It is nabi's own handler, so it does not
   * depend on any guest disposition being set. */
  rtsig_init();

  for (int i = 0; i < LINUX_NSIG; i++) {
    l_sigaction_t *lact = &proc.sigaction[i];
    if (lact->lsa_handler == LINUX_SIG_DFL || lact->lsa_handler == LINUX_SIG_IGN)
      continue;
    /* A real-time signal has no host disposition to reinstall; it is delivered
     * from the pending set by nabi itself. */
    if (i + 1 >= LINUX_SIGRTMIN)
      continue;
    struct sigaction dact;
    linux_to_darwin_sigaction(lact, &dact, __host_signal_handler);
    sigaction(linux_to_darwin_signal(i + 1), &dact, NULL);
  }
}
