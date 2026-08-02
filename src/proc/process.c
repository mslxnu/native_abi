#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>
#include <assert.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/errno.h"
#include "linux/futex.h"

#include <sys/sysctl.h>

#define _GNU_SOURCE
#include <sys/syscall.h>

struct proc proc;
_Thread_local struct task task;

/*
 * Stopping every thread but this one, for execve.
 *
 * execve replaces the whole program, so POSIX requires the other threads to be
 * gone before the new image starts - they are running code that is about to stop
 * existing, on stacks that are about to be unmapped.
 *
 * A thread inside guest code is inside hv_vcpu_run and cannot see this flag, and
 * a guest loop containing no syscalls never comes out on its own, so setting the
 * flag is paired with kicking the vCPUs (vmm_kick_other_vcpus). Each thread then
 * returns from its run, sees the flag at the top of its loop, and tears itself
 * down. Only threads that reach that check observe it, and the caller is inside a
 * syscall rather than in the loop, so it cannot stop itself by mistake.
 */
static atomic_int stop_others_requested;

bool
task_should_stop(void)
{
  return atomic_load(&stop_others_requested) != 0;
}

/* The dying side: give up the vCPU and leave the process's task list. */
noreturn void
task_stop_self(void)
{
  vmm_destroy_vcpu();
  pthread_rwlock_wrlock(&proc.lock);
  proc.nr_tasks--;
  list_del(&task.head);
  pthread_rwlock_unlock(&proc.lock);
  pthread_exit(NULL);
}

bool
stop_other_tasks(void)
{
  pthread_rwlock_rdlock(&proc.lock);
  int others = proc.nr_tasks - 1;
  pthread_rwlock_unlock(&proc.lock);
  if (others <= 0)
    return true;

  atomic_store(&stop_others_requested, 1);
  vmm_kick_other_vcpus();

  /*
   * Wait for them. Bounded rather than forever: a thread wedged somewhere that
   * never reaches the check would otherwise hang the execve with no explanation,
   * and reporting failure lets the guest see an error instead.
   */
  bool done = false;
  for (int i = 0; i < 10000; i++) {
    pthread_rwlock_rdlock(&proc.lock);
    done = proc.nr_tasks <= 1;
    pthread_rwlock_unlock(&proc.lock);
    if (done)
      break;
    usleep(200);
  }

  atomic_store(&stop_others_requested, 0);
  if (!done)
    warnk("execve: %d thread(s) did not stop\n", proc.nr_tasks - 1);
  return done;
}

DEFINE_SYSCALL(sched_yield)
{
  sleep(0);
  return 0;
}

DEFINE_SYSCALL(getpid)
{
  /* syscall(2) has been deprecated since macOS 10.12. getpid() is equivalent
   * here: Darwin's libc does not cache the pid across fork, so it is a real
   * syscall every time (verified, not assumed). */
  return syswrap(getpid());
}

DEFINE_SYSCALL(getuid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = proc.cred.uid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

uid_t nabi_host_uid;
gid_t nabi_host_gid;

/*
 * Remember which host account the guest sees as root.
 *
 * Called from both entry points on purpose. These are a property of the host
 * process, identical across a fork, and are not carried in the checkpoint - so
 * a resumed child that never sets them leaves both at zero, and every mapping
 * silently becomes the identity: files owned by the account NABI runs as stop
 * reading back as root. Since a fork on arm64 is a fork plus an exec, that was
 * every guest process except the first, and sudo said so - "/etc/sudo.conf is
 * owned by uid 501, should be 0" - about a file the first process had been
 * reading as root's all along.
 */
void
init_host_ids(void)
{
  nabi_host_uid = getuid();
  nabi_host_gid = getgid();
}

/*
 * The account NABI runs as is the guest's root; anything else keeps the id it
 * really has. One mapping applied both ways, so a file the guest chowns to root
 * lands on the account that can actually own it and reads back as root.
 */
l_uid_t host_uid_to_guest(uid_t u) { return u == nabi_host_uid ? 0 : (l_uid_t) u; }
l_gid_t host_gid_to_guest(gid_t g) { return g == nabi_host_gid ? 0 : (l_gid_t) g; }
uid_t   guest_uid_to_host(l_uid_t u) { return u == 0 ? nabi_host_uid : (uid_t) u; }
gid_t   guest_gid_to_host(l_gid_t g) { return g == 0 ? nabi_host_gid : (gid_t) g; }

DEFINE_SYSCALL(getgid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = proc.cred.gid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

/*
 * Changing the guest's credentials, in software.
 *
 * Linux lets an unprivileged caller set each of the three only to one it
 * already holds; root may set any. That rule is enforced here and nowhere else,
 * because the host process keeps the account it started with whatever the guest
 * believes. A guest dropping to a service account and back is bookkeeping.
 *
 * Which is exactly what makes it work: apt drops to _apt to check a signature
 * and then reads a file it wrote as root, and both happen as the one account
 * that owns them. The old model tried to mirror each change onto the host with
 * setruid/seteuid, which needs to be setuid root to work at all, and panicked
 * outright on the transitions Darwin cannot express.
 */
static bool
may_become(l_uid_t want)
{
  return want == (l_uid_t) -1 || proc.cred.euid == 0 ||
         want == proc.cred.uid || want == proc.cred.euid ||
         want == proc.cred.suid;
}

static bool
may_become_gid(l_gid_t want)
{
  return want == (l_gid_t) -1 || proc.cred.euid == 0 ||
         want == proc.cred.gid || want == proc.cred.egid ||
         want == proc.cred.sgid;
}

int
do_setresuid(l_uid_t ruid, l_uid_t euid, l_uid_t suid)
{
  if (!may_become(ruid) || !may_become(euid) || !may_become(suid))
    return -LINUX_EPERM;
  if (ruid != (l_uid_t) -1) proc.cred.uid  = ruid;
  if (euid != (l_uid_t) -1) proc.cred.euid = euid;
  if (suid != (l_uid_t) -1) proc.cred.suid = suid;
  return 0;
}

static int
do_setresgid(l_gid_t rgid, l_gid_t egid, l_gid_t sgid)
{
  if (!may_become_gid(rgid) || !may_become_gid(egid) || !may_become_gid(sgid))
    return -LINUX_EPERM;
  if (rgid != (l_gid_t) -1) proc.cred.gid  = rgid;
  if (egid != (l_gid_t) -1) proc.cred.egid = egid;
  if (sgid != (l_gid_t) -1) proc.cred.sgid = sgid;
  return 0;
}

DEFINE_SYSCALL(setresuid, l_uid_t, ruid, l_uid_t, euid, l_uid_t, suid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  int ret = do_setresuid(ruid, euid, suid);
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(getresuid, gaddr_t, ruid, gaddr_t, euid, gaddr_t, suid)
{
  int ret = 0;
  pthread_rwlock_rdlock(&proc.cred.lock);
  if (copy_to_user(ruid, &proc.cred.uid, sizeof proc.cred.uid)) {
    ret = -LINUX_EFAULT;
    goto out;
  }
  if (copy_to_user(euid, &proc.cred.euid, sizeof proc.cred.euid)) {
    ret = -LINUX_EFAULT;
    goto out;
  }
  if (copy_to_user(suid, &proc.cred.suid, sizeof proc.cred.suid)) {
    ret = -LINUX_EFAULT;
    goto out;
  }
  
out:
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

// Linux's setuid is not compatible with POSIX.1-2001.
// It does not set real uid and saved-uid unless the current uid is capable of CAP_SETUID (that means root in Noah now)
DEFINE_SYSCALL(setuid, l_uid_t, uid)
{
  if (uid == (l_uid_t) -1) {
    return -LINUX_EINVAL;
  }
  int ret = 0;
  pthread_rwlock_wrlock(&proc.cred.lock);
  l_uid_t new_ruid = -1, new_euid = -1, new_suid = -1;
  if (proc.cred.euid == 0) {
    new_suid = new_ruid = uid;
  } else if (proc.cred.uid != uid && proc.cred.suid != uid) {
    ret = -LINUX_EPERM;
    goto out;
  }
  new_euid = uid;
  ret = do_setresuid(new_ruid, new_euid, new_suid);
out:
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(setgid, l_gid_t, gid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  int ret = proc.cred.euid == 0 ? do_setresgid(gid, gid, gid)
                                : do_setresgid(-1, gid, -1);
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(geteuid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = proc.cred.euid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(getegid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(setresgid, l_gid_t, rgid, l_gid_t, egid, l_gid_t, sgid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  int ret = do_setresgid(rgid, egid, sgid);
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(getresgid, gaddr_t, rgid, gaddr_t, egid, gaddr_t, sgid)
{
  int n;
  pthread_rwlock_rdlock(&proc.cred.lock);
  n = proc.cred.gid;
  if (copy_to_user(rgid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  n = proc.cred.egid;
  if (copy_to_user(egid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  n = proc.cred.sgid;
  if (copy_to_user(sgid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  pthread_rwlock_unlock(&proc.cred.lock);
  return 0;
}

DEFINE_SYSCALL(setsid)
{
  return syswrap(setsid());
}

DEFINE_SYSCALL(setpgid, pid_t, pid, pid_t, pgid)
{
  return syswrap(setpgid(pid, pgid));
}

DEFINE_SYSCALL(getppid)
{
  return syswrap(getppid());
}

DEFINE_SYSCALL(getpgrp)
{
  return syswrap(getpgrp());
}

DEFINE_SYSCALL(getpgid, l_pid_t, pid)
{
  return syswrap(getpgid(pid));
}

DEFINE_SYSCALL(getsid, l_pid_t, pid)
{
  return syswrap(getsid(pid));
}

/*
 * The supplementary groups, like the rest of the guest's credentials, are the
 * guest's own rather than the host's.
 *
 * The host list is the account NABI runs as and says nothing about the guest -
 * it was leaking macOS's staff/admin/_lpoperator into a Debian process's id
 * output. And setgroups is a privileged call on Darwin, so passing it on failed
 * with EPERM: apt's sandbox drops its groups before fetching, took the error as
 * fatal, and killed its own http method. The guest is root here, so the answer
 * to "may I set my groups" is yes.
 */
static l_gid_t guest_groups[LINUX_NGROUPS_MAX];
static int nr_guest_groups;

/* Whether the guest's credentials put it in this group - the primary one or
 * any supplementary. Used by the permission checks, which is why it lives
 * beside the list rather than exporting the array. */
bool
guest_in_group(l_gid_t gid)
{
  l_gid_t egid;
  pthread_rwlock_rdlock(&proc.cred.lock);
  egid = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (gid == egid)
    return true;
  for (int i = 0; i < nr_guest_groups; i++)
    if (guest_groups[i] == gid)
      return true;
  return false;
}

/* For the checkpoint, which has to carry these across a fork like everything
 * else in struct cred. Kept here so the array stays file-local. */
int
guest_groups_get(l_gid_t *out)
{
  if (out && nr_guest_groups > 0)
    memcpy(out, guest_groups, nr_guest_groups * sizeof guest_groups[0]);
  return nr_guest_groups;
}

const l_gid_t *
guest_groups_ptr(void)
{
  return guest_groups;
}

void
guest_groups_set(const l_gid_t *g, int n)
{
  if (n < 0 || n > LINUX_NGROUPS_MAX)
    return;
  if (n > 0)
    memcpy(guest_groups, g, n * sizeof guest_groups[0]);
  nr_guest_groups = n;
}

DEFINE_SYSCALL(getgroups, int, gidsetsize, gaddr_t, grouplist_ptr)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int n = nr_guest_groups;
  if (gidsetsize == 0) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return n;                       /* asking how many, not for the list */
  }
  if (gidsetsize < n) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EINVAL;
  }
  int r = n;
  if (n > 0 && copy_to_user(grouplist_ptr, guest_groups, n * sizeof guest_groups[0]))
    r = -LINUX_EFAULT;
  pthread_rwlock_unlock(&proc.cred.lock);
  return r;
}

DEFINE_SYSCALL(setgroups, int, gidsetsize, gaddr_t, grouplist_ptr)
{
  if (gidsetsize < 0 || gidsetsize > LINUX_NGROUPS_MAX)
    return -LINUX_EINVAL;

  pthread_rwlock_wrlock(&proc.cred.lock);
  int r = 0;
  if (proc.cred.euid != 0) {
    r = -LINUX_EPERM;
  } else if (gidsetsize > 0 &&
             copy_from_user(guest_groups, grouplist_ptr,
                            gidsetsize * sizeof guest_groups[0])) {
    r = -LINUX_EFAULT;
  } else {
    nr_guest_groups = gidsetsize;
  }
  pthread_rwlock_unlock(&proc.cred.lock);
  return r;
}

uint64_t do_gettid()
{
  return task.tid;
}

DEFINE_SYSCALL(gettid)
{
  return do_gettid();
}

/*
 * A Linux resource as a Darwin one, or -1 when Darwin has no such thing.
 *
 * -1 rather than a silent 0: the old default aliased every unknown resource
 * onto RLIMIT_CPU, which would have set a CPU-time limit for a guest asking
 * about something else entirely.
 */
/*
 * The resources Darwin does not have, kept here instead.
 *
 * Linux's own defaults, so a guest reading them sees what it would see on
 * Linux; a guest writing them is remembered rather than refused. Nothing in
 * NABI enforces any of these - there is no realtime scheduling to bound and no
 * message queues to fill - so this is bookkeeping, and honest bookkeeping is
 * better than the EINVAL that used to come back.
 */
static struct l_rlimit emulated_rlimits[LINUX_RLIM_NLIMITS];
static bool emulated_rlimits_ready;

static struct l_rlimit *
emulated_rlimit(unsigned int l_resource)
{
  if (!emulated_rlimits_ready) {
    for (int i = 0; i < LINUX_RLIM_NLIMITS; i++)
      emulated_rlimits[i] = (struct l_rlimit) { LINUX_RLIM_INFINITY,
                                                LINUX_RLIM_INFINITY };
    emulated_rlimits[LINUX_RLIMIT_SIGPENDING] = (struct l_rlimit) { 15738, 15738 };
    emulated_rlimits[LINUX_RLIMIT_MSGQUEUE]   = (struct l_rlimit) { 819200, 819200 };
    emulated_rlimits[LINUX_RLIMIT_NICE]       = (struct l_rlimit) { 0, 0 };
    emulated_rlimits[LINUX_RLIMIT_RTPRIO]     = (struct l_rlimit) { 0, 0 };
    emulated_rlimits_ready = true;
  }
  return &emulated_rlimits[l_resource];
}

int linux_to_darwin_rlimopts(int l_resource) {
  int resource = -1;
  switch (l_resource) {
  case LINUX_RLIMIT_CPU: resource = RLIMIT_CPU; break;
  case LINUX_RLIMIT_FSIZE: resource = RLIMIT_FSIZE; break;
  case LINUX_RLIMIT_DATA: resource = RLIMIT_DATA; break;
  case LINUX_RLIMIT_STACK: resource = RLIMIT_STACK; break;
  case LINUX_RLIMIT_CORE: resource = RLIMIT_CORE; break;
  case LINUX_RLIMIT_RSS: resource = RLIMIT_RSS; break;
  case LINUX_RLIMIT_NPROC: resource = RLIMIT_NPROC; break;
  case LINUX_RLIMIT_NOFILE: resource = RLIMIT_NOFILE; break;
  case LINUX_RLIMIT_MEMLOCK: resource = RLIMIT_MEMLOCK; break;
  case LINUX_RLIMIT_AS: resource = RLIMIT_AS; break;
  }
  return resource;
}

DEFINE_SYSCALL(getrlimit, int, l_resource, gaddr_t, rl_ptr)
{
  struct rlimit rl;
  struct l_rlimit l_rl;

  if (l_resource >= LINUX_RLIM_NLIMITS) {
    return -LINUX_EINVAL;
  }

  int resource = linux_to_darwin_rlimopts(l_resource);

  /* The ones Darwin has no equivalent for are kept by NABI; see
   * emulated_rlimit. */
  if (resource < 0) {
    if (copy_to_user(rl_ptr, emulated_rlimit(l_resource), sizeof l_rl))
      return -LINUX_EFAULT;
    return 0;
  }

  int r = syswrap(getrlimit(resource, &rl));
  if (r < 0)
    return r;

  darwin_to_linux_rlimit(resource, &rl, &l_rl);
  if (copy_to_user(rl_ptr, &l_rl, sizeof l_rl))
    return -LINUX_EFAULT;

  return r;
}

DEFINE_SYSCALL(setrlimit, unsigned int, resource, gaddr_t, rlim)
{
  warnk("setrlimit is not implemented\n");
  return -LINUX_ENOSYS;
}

/*
 * prlimit64 is how modern glibc/musl both query and set resource limits (plain
 * getrlimit/setrlimit are routed through it). Only the calling process is
 * supported - pid 0 or our own pid - since targeting another process would need
 * a handle we do not keep; glibc passes 0. The old limit, if requested, is the
 * value before the new one is applied. struct l_rlimit is already the 64-bit
 * rlimit64 shape, so no separate conversion is needed.
 */
DEFINE_SYSCALL(prlimit64, int, pid, unsigned int, l_resource, gaddr_t, new_ptr, gaddr_t, old_ptr)
{
  if (pid != 0 && pid != (int) getpid())
    return -LINUX_EPERM;
  if (l_resource >= LINUX_RLIM_NLIMITS)
    return -LINUX_EINVAL;

  int resource = linux_to_darwin_rlimopts(l_resource);

  if (resource < 0) {
    struct l_rlimit *e = emulated_rlimit(l_resource);
    if (old_ptr && copy_to_user(old_ptr, e, sizeof *e))
      return -LINUX_EFAULT;
    if (new_ptr && copy_from_user(e, new_ptr, sizeof *e))
      return -LINUX_EFAULT;
    return 0;
  }

  struct rlimit rl;
  int r = syswrap(getrlimit(resource, &rl));
  if (r < 0)
    return r;

  if (old_ptr) {
    struct l_rlimit old;
    darwin_to_linux_rlimit(resource, &rl, &old);
    if (copy_to_user(old_ptr, &old, sizeof old))
      return -LINUX_EFAULT;
  }

  if (new_ptr) {
    struct l_rlimit newl;
    if (copy_from_user(&newl, new_ptr, sizeof newl))
      return -LINUX_EFAULT;
    struct rlimit drl;
    if (resource == RLIMIT_NOFILE) {
      /* The inverse of what getrlimit reported, so a read-then-write round
       * trip is a no-op rather than a steady erosion of the host's limit. */
      linux_to_darwin_rlimit_nofile(&newl, &drl);
      /* And never below the descriptors NABI is holding, whatever the guest
       * asks for: they are already open, and losing the ability to address
       * them breaks the emulator rather than the guest. */
      if (drl.rlim_cur != RLIM_INFINITY &&
          drl.rlim_cur < (rlim_t) vkern_fd_floor())
        drl.rlim_cur = vkern_fd_floor();
      if (drl.rlim_max != RLIM_INFINITY &&
          drl.rlim_max < (rlim_t) vkern_fd_floor())
        drl.rlim_max = vkern_fd_floor();
    } else {
      drl.rlim_cur = newl.rlim_cur == LINUX_RLIM_INFINITY ? RLIM_INFINITY : newl.rlim_cur;
      drl.rlim_max = newl.rlim_max == LINUX_RLIM_INFINITY ? RLIM_INFINITY : newl.rlim_max;
    }
    r = syswrap(setrlimit(resource, &drl));
    if (r < 0 && r == -LINUX_EPERM) {
      /*
       * The guest believes it is root and that raising its own hard limit is
       * allowed; the host process is an ordinary account and it is not. Rather
       * than fail - sudo calls this on every invocation and stops when it
       * fails - the request is clamped to what the host will actually grant.
       *
       * The guest is told this succeeded, which is a small lie of the same
       * kind as chown being a no-op: the limit it asked for is not one NABI
       * can hand out, and refusing only breaks programs that had no way to
       * ask for less.
       */
      struct rlimit host;
      if (getrlimit(resource, &host) == 0) {
        if (drl.rlim_cur == RLIM_INFINITY || drl.rlim_cur > host.rlim_max)
          drl.rlim_cur = host.rlim_max;
        drl.rlim_max = host.rlim_max;
        r = syswrap(setrlimit(resource, &drl));
      }
      if (r < 0) {
        warnk("prlimit: resource %u could not be set, reporting success\n",
              l_resource);
        r = 0;
      }
    }
    if (r < 0)
      return r;
  }

  return 0;
}

DEFINE_SYSCALL(exit, int, reason)
{
  if (task.clear_child_tid) {
    int zero = 0;
    if (copy_to_user(task.clear_child_tid, &zero, sizeof zero))
      return -LINUX_EFAULT;
    do_futex_wake(task.clear_child_tid, 1);
  }
  vmm_destroy_vcpu();
  pthread_rwlock_wrlock(&proc.lock);
  if (proc.nr_tasks == 1) {
    _exit(reason);
  } else {
    proc.nr_tasks--;
    list_del(&task.head);
    pthread_rwlock_unlock(&proc.lock);
    pthread_exit(&reason);
  }
}

DEFINE_SYSCALL(exit_group, int, reason)
{
  if (task.clear_child_tid) {
    int zero = 0;
    if (copy_to_user(task.clear_child_tid, &zero, sizeof zero))
      return -LINUX_EFAULT;
    do_futex_wake(task.clear_child_tid, 1);
  }
  _exit(reason);
}

/*
 * tgkill and tkill: a signal aimed at one thread.
 *
 * Unimplemented, these returned ENOSYS - and that is much worse than it sounds,
 * because tgkill is how glibc's abort() delivers SIGABRT to itself. A process
 * that decides to die and cannot then does not die: it carries on with the
 * signal never raised, and anything waiting for it to exit waits forever. That
 * is what deadlocked apt. Its download method aborted after dropping privileges
 * to _apt, could not, and never closed its end of the pipe; apt sat in pselect6
 * waiting for a greeting or an EOF that were both never coming, and
 * `apt-get update` printed nothing at all.
 *
 * The delivery is per-process rather than per-thread. NABI runs a guest's
 * threads as pthreads inside one host process and keeps no pthread_t to aim
 * at, so the signal goes to the process. For the single-threaded case - abort,
 * raise, assert, every caller that was hanging - that is exact. For a guest
 * aiming at a specific sibling thread it is an approximation: the signal
 * arrives, but possibly on another thread. Worth knowing, and still a great
 * deal better than telling the caller the operation does not exist.
 */
DEFINE_SYSCALL(tgkill, l_pid_t, tgid, l_pid_t, tid, int, sig)
{
  if (tgid <= 0 || tid <= 0)
    return -LINUX_EINVAL;
  return send_signal(tgid, sig);
}

/* The older form, without the thread-group check. Same delivery. */
DEFINE_SYSCALL(tkill, l_pid_t, tid, int, sig)
{
  if (tid <= 0)
    return -LINUX_EINVAL;
  return send_signal(tid, sig);
}

DEFINE_SYSCALL(capget, gaddr_t, header_ptr, gaddr_t, data_ptr)
{
  printk("capget is unimplemented\n");
  return 0;
}

struct utsname {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

DEFINE_SYSCALL(uname, gaddr_t, buf_ptr)
{
  struct utsname buf;

  strncpy(buf.sysname, "Linux", sizeof buf.sysname - 1);
  strncpy(buf.release, LINUX_RELEASE, sizeof buf.release - 1);
  strncpy(buf.version, LINUX_VERSION, sizeof buf.version - 1);
  /* The guest architecture, not the host's - a guest that reads this picks its
   * library paths and JIT backend from it. */
#if defined(__aarch64__) || defined(__arm64__)
  strncpy(buf.machine, "aarch64", sizeof buf.machine - 1);
#else
  strncpy(buf.machine, "x86_64", sizeof buf.machine - 1);
#endif
  strncpy(buf.domainname, "GNU/Linux", sizeof buf.domainname - 1);

  int err = syswrap(gethostname(buf.nodename, sizeof buf.nodename - 1));
  if (err < 0) {
    return err;
  }

  if (copy_to_user(buf_ptr, &buf, sizeof(struct utsname))) {
    return -LINUX_EFAULT;
  }

  return 0;
}

DEFINE_SYSCALL(prctl, int, option, unsigned long, arg1, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5)
{
  switch (option) {
  case LINUX_PR_SET_NAME: {
    char buf[16];
    if (copy_from_user(buf, (gaddr_t)arg1, sizeof(buf))) {
      return -LINUX_EFAULT;
    }
    // trancate if the legnth of arg1 exceeds 16byte.
    buf[15] = '\0';
    pthread_setname_np(buf);
    return 0;
  }
  default:
    warnk("unkown prctl cmd: %d\n", option);
    return -LINUX_EINVAL;
  }
}

DEFINE_SYSCALL(arch_prctl, int, code, gaddr_t, addr)
{
  uint64_t t;

  /*
   * arch_prctl is an x86-64 syscall with no aarch64 number - the generic
   * unistd table has no such entry, so on aarch64 this handler is compiled but
   * never dispatched. The FS base is the thread pointer, so it goes through the
   * arch-neutral TLS accessor (TPIDR_EL0 on aarch64). The GS base has no
   * aarch64 counterpart at all and stays behind __x86_64__.
   */
  switch (code) {
  case LINUX_ARCH_SET_FS:
    vmm_set_tls(addr);
    return 0;
  case LINUX_ARCH_GET_FS:
    vmm_get_tls(&t);
    if (copy_to_user(addr, &t, sizeof t))
      return -LINUX_EFAULT;
    return 0;
#ifdef __x86_64__
  case LINUX_ARCH_SET_GS:
    vmm_write_vmcs(VMCS_GUEST_GS_BASE, addr);
    return 0;
  case LINUX_ARCH_GET_GS:
    vmm_read_vmcs(VMCS_GUEST_GS_BASE, &t);
    if (copy_to_user(addr, &t, sizeof t))
      return -LINUX_EFAULT;
    return 0;
#endif
  default:
    return -LINUX_EINVAL;
  }
}

DEFINE_SYSCALL(set_tid_address, gaddr_t, tidptr)
{
  task.clear_child_tid = tidptr;
  return do_gettid();
}

DEFINE_SYSCALL(set_robust_list, gaddr_t, head, size_t, len)
{
  if (len != sizeof(struct linux_robust_list_head))
    return -EINVAL;
  task.robust_list = head;
  return 0;
}

int linux_to_darwin_waitopts(int options)
{
  int opts = 0;
  if (options & LINUX_WNOHANG) {
    opts |= WNOHANG;
    options &= ~LINUX_WNOHANG;
  }
  if (options & LINUX_WUNTRACED) {
    opts |= WUNTRACED;
    options &= ~LINUX_WUNTRACED;
  }
  if (options & LINUX_WCONTINUED) {
    opts |= WCONTINUED;
    options &= ~LINUX_WCONTINUED;
  }
  if (options & LINUX_WEXITED) {
    opts |= WEXITED;
    options &= ~LINUX_WEXITED;
  }
  if (options != 0) {
    warnk("unknown options given to wait4: 0x%x\n", options);
  }
  return opts;
}

DEFINE_SYSCALL(wait4, int, pid, gaddr_t, status_ptr, int, options, gaddr_t, rusage_ptr)
{
  int status;
  struct rusage rusage;

  int ret = syswrap(wait4(pid, &status, linux_to_darwin_waitopts(options), &rusage));
  if (ret < 0) {
    return ret;
  }

  if (rusage_ptr != 0) {
    if (copy_to_user(rusage_ptr, &rusage, sizeof rusage)) {
      return -LINUX_EFAULT;
    }
  }

  if (status_ptr != 0) {
    /*
     *  SSSS SSSS -000 0000 -> exited. S is return status
     *  .... .... CYYY YYYY -> signaled if Y != 0. Y is the signal number
     *  SSSS SSSS 0111 1111 -> stopped. S is the sigal number
     */
    int st = 0;
    if (WIFEXITED(status)) {
      st = WEXITSTATUS(status) << 8;
    } else if (WIFSIGNALED(status)) {
      st = darwin_to_linux_signal(WTERMSIG(status));
      if (WCOREDUMP(status))
        st |= 0x80;
    } else if (WIFSTOPPED(status)) {
      st = (darwin_to_linux_signal(WSTOPSIG(status)) << 8) | 0x7f;
    }
    if (copy_to_user(status_ptr, &st, sizeof st)) {
      return -LINUX_EFAULT;
    }
  }

  return ret;
}

static void
darwin_to_linux_rusage(struct rusage *ru, struct l_rusage *lru)
{
  lru->ru_utime.tv_sec = ru->ru_utime.tv_sec;
  lru->ru_utime.tv_usec = ru->ru_utime.tv_usec;
  lru->ru_stime.tv_sec = ru->ru_stime.tv_sec;
  lru->ru_stime.tv_usec = ru->ru_stime.tv_usec;
  lru->ru_maxrss = ru->ru_maxrss;
  lru->ru_ixrss = ru->ru_ixrss;
  lru->ru_idrss = ru->ru_idrss;
  lru->ru_isrss = ru->ru_isrss;
  lru->ru_minflt = ru->ru_minflt;
  lru->ru_majflt = ru->ru_majflt;
  lru->ru_nswap = ru->ru_nswap;
  lru->ru_inblock = ru->ru_inblock;
  lru->ru_oublock = ru->ru_oublock;
  lru->ru_msgsnd = ru->ru_msgsnd;
  lru->ru_msgrcv = ru->ru_msgrcv;
  lru->ru_nsignals = ru->ru_nsignals;
  lru->ru_nvcsw = ru->ru_nvcsw;
  lru->ru_nivcsw = ru->ru_nivcsw;
}

DEFINE_SYSCALL(getrusage, int, who, gaddr_t, rusage_ptr)
{
  struct rusage h_rusage;
  int r;
  if ((r = syswrap(getrusage(who, &h_rusage))) < 0) {
    return r;
  }

  struct l_rusage l_rusage;
  darwin_to_linux_rusage(&h_rusage, &l_rusage);

  if (copy_to_user(rusage_ptr, &l_rusage, sizeof l_rusage)) {
    return -LINUX_EFAULT;
  }
  return 0;
}

DEFINE_SYSCALL(getpriority, int, which, int, who)
{
  return syswrap(getpriority(which, who));
}

DEFINE_SYSCALL(setpriority, int, which, int, who, int, niceval)
{
  return syswrap(setpriority(which, who, niceval));
}

DEFINE_SYSCALL(sched_getaffinity, l_pid_t, pid, unsigned int, len, gaddr_t, user_mask_ptr)
{
  /* enum, not `static const unsigned`: a const object is not a constant
   * expression in C, so buf[] below was a variable-length array that clang
   * folded to a fixed one as an extension. */
  enum { sizeof_cpumask_t = 32 }; /* FIXME */
  if (len < sizeof_cpumask_t)
    return -LINUX_EINVAL;
  unsigned char buf[sizeof_cpumask_t] = {0};
  buf[0] = 0x1;
  if (copy_to_user(user_mask_ptr, buf, sizeof buf))
    return -LINUX_EFAULT;
  return sizeof_cpumask_t;
}
