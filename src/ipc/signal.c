#include "common.h"
#include "linux/signal.h"

#include "noah.h"
#include "namespace.h"
#include "vmm.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
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

int
send_signal(pid_t pid, int signum)
{
  if (signum >= LINUX_SIGRTMIN) {
    warnk("RT signal is raised: %d\n", signum);
    return 0;
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

  /* import signal handlers registered on the host */
  for (int i = 0; i < LINUX_NSIG; i++) {
    struct sigaction oact;
    sigaction(i + 1, NULL, &oact);
    if (!(oact.sa_handler == SIG_IGN || oact.sa_handler == SIG_DFL)) {
      /* Printed as a pointer: the old (int) cast truncated the handler
       * address on a 64-bit host, so this diagnostic - which fires just
       * before the assert below - reported a value that was not the
       * handler. */
      warnk("sa_handler:%p\n", (void *) oact.sa_handler);
    }
    assert(oact.sa_handler == SIG_IGN || oact.sa_handler == SIG_DFL);
    // flags, restorer, and mask will be flushed in execve, so just leave them 0
    proc.sigaction[i] = (l_sigaction_t) {
      .lsa_handler = oact.sa_handler == SIG_IGN ? LINUX_SIG_IGN : LINUX_SIG_DFL,
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
  int sig = __builtin_ffs(pending);
  assert(0 < sig && sig < 32);
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
  } else {
    lact.lsa_flags |= LINUX_SA_SIGINFO;
    handler = __host_signal_handler;
  }
  linux_to_darwin_sigaction(&lact, &dact, handler);
  dsig = linux_to_darwin_signal(sig);
  // TODO: make handlings of linux specific signals consistent

  int err = 0;
  pthread_rwlock_wrlock(&proc.sig_lock);

  err = syswrap(sigaction(dsig, &dact, &doact));
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
  for (int i = 0; i < LINUX_NSIG; i++) {
    l_sigaction_t *lact = &proc.sigaction[i];
    if (lact->lsa_handler == LINUX_SIG_DFL || lact->lsa_handler == LINUX_SIG_IGN)
      continue;
    struct sigaction dact;
    linux_to_darwin_sigaction(lact, &dact, __host_signal_handler);
    sigaction(linux_to_darwin_signal(i + 1), &dact, NULL);
  }
}
