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
#include <sys/event.h>   /* kqueue, for PR_SET_PDEATHSIG */
#include <assert.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/time.h"
#include "namespace.h"
#include "linux/errno.h"
#include "linux/futex.h"
#include "linux/capability.h"

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
   * syscall every time (verified, not assumed).
   *
   * Then through the pid namespace, which for a process that never unshared is
   * the identity and costs a comparison. */
  return pidns_to_ns(getpid());
}

/*
 * The id the guest is told, which is not the id it has.
 *
 * A user namespace translates only here, at the boundary. struct cred keeps the
 * ids the process really carries, so every permission check nabi makes goes on
 * seeing the unprivileged user it started as - which is how "root inside the
 * namespace" comes out meaning what it does on Linux without a capability model
 * underneath it.
 */
DEFINE_SYSCALL(getuid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = (int) userns_uid_inward(proc.cred.uid);
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
  int ret = (int) userns_gid_inward(proc.cred.gid);
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
static void cap_after_setresuid(bool was_priv, bool now_unpriv,
                                l_uid_t old_euid, l_uid_t new_euid);


int
do_setresuid(l_uid_t ruid, l_uid_t euid, l_uid_t suid)
{
  if (!may_become(ruid) || !may_become(euid) || !may_become(suid))
    return -LINUX_EPERM;
  l_uid_t was_uid = proc.cred.uid, was_euid = proc.cred.euid,
          was_suid = proc.cred.suid;
  if (ruid != (l_uid_t) -1) proc.cred.uid  = ruid;
  if (euid != (l_uid_t) -1) proc.cred.euid = euid;
  if (suid != (l_uid_t) -1) proc.cred.suid = suid;
  cap_after_setresuid(was_uid == 0 || was_euid == 0 || was_suid == 0,
                      proc.cred.uid != 0 && proc.cred.euid != 0 &&
                          proc.cred.suid != 0,
                      was_euid, proc.cred.euid);
  /* Every change to the effective id carries the filesystem id with it. Linux
   * does this so that setfsuid is the only way the two can differ, which is
   * what makes it safe for the filesystem checks to consult fsuid alone. */
  proc.cred.fsuid = proc.cred.euid;
  /* Republished so a peer asking about this process after it changed ids is
   * told what it is now rather than what it started as. */
  cred_publish(proc.cred.euid, proc.cred.egid);
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
  proc.cred.fsgid = proc.cred.egid;
  cred_publish(proc.cred.euid, proc.cred.egid);
  return 0;
}

DEFINE_SYSCALL(setresuid, l_uid_t, ruid, l_uid_t, euid, l_uid_t, suid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  int ret = do_setresuid(ruid, euid, suid);
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

/*
 * setreuid and setregid: the older pair, with the rule that is easy to get
 * wrong.
 *
 * Setting the real id to something other than what it was, or setting the
 * effective id to something other than the old *real* id, also moves the saved
 * id to the new effective one. That is what stops a program from dropping
 * privilege and then picking it back up: without it, the saved id still holds
 * the old value and a later setuid restores it. Linux has the rule and so does
 * POSIX, and it is the whole reason setreuid is not just two assignments.
 */
DEFINE_SYSCALL(setreuid, l_uid_t, ruid, l_uid_t, euid)
{
  int ret;
  pthread_rwlock_wrlock(&proc.cred.lock);
  l_uid_t old_ruid = proc.cred.uid;

  if (!may_become(ruid) || !may_become(euid)) {
    ret = -LINUX_EPERM;
    goto out;
  }
  /* An unprivileged caller may set the real id only to the one it already has
   * as real or effective - narrower than may_become, which allows the saved
   * one too. */
  if (ruid != (l_uid_t) -1 && proc.cred.euid != 0 &&
      ruid != proc.cred.uid && ruid != proc.cred.euid) {
    ret = -LINUX_EPERM;
    goto out;
  }

  l_uid_t new_suid = (l_uid_t) -1;
  if (ruid != (l_uid_t) -1 || (euid != (l_uid_t) -1 && euid != old_ruid))
    new_suid = euid != (l_uid_t) -1 ? euid : proc.cred.euid;

  ret = do_setresuid(ruid, euid, new_suid);
out:
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(setregid, l_gid_t, rgid, l_gid_t, egid)
{
  int ret;
  pthread_rwlock_wrlock(&proc.cred.lock);
  l_gid_t old_rgid = proc.cred.gid;

  if (!may_become_gid(rgid) || !may_become_gid(egid)) {
    ret = -LINUX_EPERM;
    goto out;
  }
  if (rgid != (l_gid_t) -1 && proc.cred.euid != 0 &&
      rgid != proc.cred.gid && rgid != proc.cred.egid) {
    ret = -LINUX_EPERM;
    goto out;
  }

  l_gid_t new_sgid = (l_gid_t) -1;
  if (rgid != (l_gid_t) -1 || (egid != (l_gid_t) -1 && egid != old_rgid))
    new_sgid = egid != (l_gid_t) -1 ? egid : proc.cred.egid;

  ret = do_setresgid(rgid, egid, new_sgid);
out:
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

/*
 * setfsuid and setfsgid: the id the filesystem checks use, and nothing else.
 *
 * They exist because an NFS server, or Samba, wants to act as a user for one
 * file access without becoming that user - which would let a signal from
 * outside reach it, and would change what a later getuid reports. Splitting the
 * filesystem id off keeps the change to exactly the checks that read it.
 *
 * The odd part of the interface is that they cannot fail. Both return the
 * *previous* value whether or not the change was allowed, so the way to find
 * out whether it took is to call twice and compare - which is what libc's
 * wrappers document and what callers do. Returning an error instead would be a
 * kinder interface and the wrong one.
 *
 * Here they are real rather than recorded: cred_may consults fsuid for the
 * effective case, so a process that lowers its filesystem id genuinely loses
 * access to files it could read a moment earlier. The rest of the credentials
 * keep fsuid in step, so nothing that does not call these can tell.
 */
DEFINE_SYSCALL(setfsuid, l_uid_t, fsuid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  l_uid_t old = proc.cred.fsuid;
  if (fsuid != (l_uid_t) -1 &&
      (proc.cred.euid == 0 || fsuid == proc.cred.uid || fsuid == proc.cred.euid ||
       fsuid == proc.cred.suid || fsuid == proc.cred.fsuid))
    proc.cred.fsuid = fsuid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return (int) old;             /* never an error; see above */
}

DEFINE_SYSCALL(setfsgid, l_gid_t, fsgid)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  l_gid_t old = proc.cred.fsgid;
  if (fsgid != (l_gid_t) -1 &&
      (proc.cred.euid == 0 || fsgid == proc.cred.gid || fsgid == proc.cred.egid ||
       fsgid == proc.cred.sgid || fsgid == proc.cred.fsgid))
    proc.cred.fsgid = fsgid;
  pthread_rwlock_unlock(&proc.cred.lock);
  return (int) old;
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
  int ret = (int) userns_uid_inward(proc.cred.euid);
  pthread_rwlock_unlock(&proc.cred.lock);
  return ret;
}

DEFINE_SYSCALL(getegid)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  int ret = (int) userns_gid_inward(proc.cred.egid);
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
  n = (int) userns_gid_inward(proc.cred.gid);
  if (copy_to_user(rgid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  n = (int) userns_gid_inward(proc.cred.egid);
  if (copy_to_user(egid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  n = (int) userns_gid_inward(proc.cred.sgid);
  if (copy_to_user(sgid, &n, sizeof n)) {
    pthread_rwlock_unlock(&proc.cred.lock);
    return -LINUX_EFAULT;
  }
  pthread_rwlock_unlock(&proc.cred.lock);
  return 0;
}

DEFINE_SYSCALL(setsid)
{
  int r = syswrap(setsid());
  return r < 0 ? r : pidns_to_ns(r);
}

DEFINE_SYSCALL(setpgid, pid_t, pid, pid_t, pgid)
{
  pid_t hpid = pid == 0 ? 0 : pidns_to_host(pid);
  pid_t hpgid = pgid == 0 ? 0 : pidns_to_host(pgid);
  if (hpid < 0 || hpgid < 0)
    return -LINUX_ESRCH;
  return syswrap(setpgid(hpid, hpgid));
}

DEFINE_SYSCALL(getppid)
{
  /* A parent outside this namespace has no pid in it, and Linux reports 0 -
   * which is also what pidns_to_ns says about a process it does not know. */
  return pidns_to_ns(getppid());
}

DEFINE_SYSCALL(getpgrp)
{
  return pidns_to_ns(getpgrp());
}

DEFINE_SYSCALL(getpgid, l_pid_t, pid)
{
  pid_t hpid = pid == 0 ? 0 : pidns_to_host(pid);
  if (hpid < 0)
    return -LINUX_ESRCH;
  int r = syswrap(getpgid(hpid));
  return r < 0 ? r : pidns_to_ns(r);
}

DEFINE_SYSCALL(getsid, l_pid_t, pid)
{
  pid_t hpid = pid == 0 ? 0 : pidns_to_host(pid);
  if (hpid < 0)
    return -LINUX_ESRCH;
  int r = syswrap(getsid(hpid));
  return r < 0 ? r : pidns_to_ns(r);
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

/*
 * The thread id as the guest knows it, which is what has to be written into
 * guest memory.
 *
 * do_gettid answers with the host's number. Everywhere the guest can see that
 * number it has to go through the pid namespace first - gettid(2) does, getpid
 * does - and CLONE_CHILD_SETTID is one of those places, because the word it
 * stores is read back as a tid by whatever asked for it.
 *
 * It was stored raw, which was invisible until a guest actually had a pid
 * namespace, since without one the translation is the identity. Under --pid1 it
 * is not: Android's init forks a service, bionic keeps the word clone wrote as
 * its cached id, and the child's very next act is setpgid(0, that) - which names
 * a process that does not exist in the namespace, so every service start
 * reported "cannot set attribute for <name>: setpgid failed: No such process".
 */
int32_t
guest_tid(void)
{
  uint64_t r = do_gettid();
  return (int32_t) pidns_to_ns((int32_t) r);
}

DEFINE_SYSCALL(gettid)
{
  /* A guest thread is a host thread and nabi reports the process for it, so a
   * tid translates exactly as a pid does. */
  int r = do_gettid();
  return r < 0 ? r : pidns_to_ns(r);
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

/*
 * setrlimit, which is prlimit64 on this process with no old value wanted.
 *
 * It answered ENOSYS, on the reasoning that a modern libc routes setrlimit
 * through prlimit64 and nothing would call this. Android's init calls it: its
 * `setrlimit` command in init.rc goes straight to the syscall, so `setrlimit
 * nice 40 40` and `setrlimit nofile 32768 32768` both failed at early-init with
 * "Function not implemented" before it had started a single service.
 *
 * Delegating rather than reimplementing is the point - the resources Darwin
 * does not have are emulated, and a hard limit the host will not grant is
 * clamped instead of refused, and both of those belong to one place.
 */
DEFINE_SYSCALL(setrlimit, unsigned int, l_resource, gaddr_t, rlim)
{
  return sys_prlimit64(0, l_resource, rlim, 0);
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
    nsproxy_release();
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
  nsproxy_release();
  _exit(reason);
}

/*
 * reboot: stopping the machine, where the machine is this process.
 *
 * There is no firmware here to hand control back to, so a restart cannot be a
 * restart. What there is, and what the guest is actually asking for, is for
 * everything running under this kernel to stop - and nabi's guest is exactly
 * that set. So the halting commands end the guest, which is the same thing
 * reboot means to an init in a namespace of its own: the namespace goes, and
 * whoever started it decides whether anything comes back.
 *
 * kexec is the one command refused rather than emulated, for the reason
 * kexec_load is refused: it names a kernel image to be entered, and there is
 * nothing here that could enter one.
 *
 * The magic numbers are checked because they are the whole of what stops a
 * stray call from stopping the machine - that is what they are in Linux for,
 * and a guest that gets them wrong wants EINVAL rather than a shutdown.
 * Android's init calls this at the end of its shutdown path and reports what
 * came back, so ENOSYS there was a visible loose end even though the guest was
 * on its way out anyway.
 */
DEFINE_SYSCALL(reboot, int, magic1, int, magic2, unsigned int, cmd, gaddr_t, arg)
{
  if ((unsigned int) magic1 != LINUX_REBOOT_MAGIC1)
    return -LINUX_EINVAL;
  switch ((unsigned int) magic2) {
  case LINUX_REBOOT_MAGIC2:
  case LINUX_REBOOT_MAGIC2A:
  case LINUX_REBOOT_MAGIC2B:
  case LINUX_REBOOT_MAGIC2C:
    break;
  default:
    return -LINUX_EINVAL;
  }

  pthread_rwlock_rdlock(&proc.cred.lock);
  bool root = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (!root)
    return -LINUX_EPERM;

  switch (cmd) {
  case LINUX_REBOOT_CMD_CAD_ON:
  case LINUX_REBOOT_CMD_CAD_OFF:
    /* Whether ctrl-alt-del reboots or signals init. There is no keyboard on
     * this machine to press it on, so the setting is recorded nowhere and the
     * call succeeds, which is what a caller toggling it needs. */
    return 0;

  case LINUX_REBOOT_CMD_RESTART:
  case LINUX_REBOOT_CMD_RESTART2:
  case LINUX_REBOOT_CMD_HALT:
  case LINUX_REBOOT_CMD_POWER_OFF:
    (void) arg;                 /* RESTART2's message has nowhere to go */
    nsproxy_release();
    _exit(0);                   /* asked for, so not a failure */

  case LINUX_REBOOT_CMD_SW_SUSPEND:
    /* Suspend-to-disk needs a kernel to write the image and firmware to resume
     * it. Neither exists here, and there is no partial version worth doing. */
    return -LINUX_ENOSYS;

  case LINUX_REBOOT_CMD_KEXEC:
    return -LINUX_ENOSYS;

  default:
    return -LINUX_EINVAL;
  }
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
  pid_t h = pidns_to_host(tgid);
  if (h < 0)
    return -LINUX_ESRCH;
  return send_signal(h, sig);
}

/* The older form, without the thread-group check. Same delivery. */
DEFINE_SYSCALL(tkill, l_pid_t, tid, int, sig)
{
  if (tid <= 0)
    return -LINUX_EINVAL;
  pid_t h = pidns_to_host(tid);
  if (h < 0)
    return -LINUX_ESRCH;
  return send_signal(h, sig);
}

/*
 * Capabilities: reported from the credentials, recorded when set, and not
 * separately enforced.
 *
 * What was here before returned 0 and wrote nothing, so a caller read back
 * whatever its own buffer happened to hold and believed it was the capability
 * set. That is the same fault AT_RANDOM had - a security-relevant answer made
 * out of uninitialised memory - and it is worse than saying nothing, because
 * every caller checks the return value and none of them checks that the kernel
 * bothered.
 *
 * The model is the one nabi actually implements everywhere else: privilege here
 * is `euid == 0`, so guest root holds every capability and nobody else holds
 * any. That is not an approximation of the credentials, it *is* them, and it
 * makes capget agree with what a caller will find when it tries the operation.
 *
 * capset records what it is given rather than enforcing it, and that gap is
 * worth stating plainly: a daemon that drops CAP_SYS_ADMIN and stays uid 0 will
 * see the drop in capget, and will still be allowed to mount. Enforcing it
 * would mean every privileged check in nabi consulting a capability set instead
 * of the uid, which is a larger change than this. Recording is still better
 * than refusing - a program that drops privileges and verifies the drop gets a
 * consistent answer instead of an error it treats as fatal - and better than
 * ignoring, which is how the round trip silently lies.
 */
static uint64_t cap_effective   = ~0ULL;
static uint64_t cap_permitted   = ~0ULL;
static uint64_t cap_inheritable = 0;
/*
 * The bounding set: the ceiling on what this process, or anything it execs,
 * can ever hold. It only shrinks, which is the whole of its contract.
 */
static uint64_t cap_bounding    = ~0ULL;
/*
 * The ambient set: the capabilities that survive an execve into a program with
 * none of its own. It is how a process hands power to something it is about to
 * run without that program being setuid or carrying file capabilities, and it
 * is the only way to do so.
 */
static uint64_t cap_ambient     = 0;
static pthread_mutex_t cap_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * PR_SET_KEEPCAPS, which says whether the permitted set survives a transition
 * to all-non-zero uids.
 *
 * Held and reported, and that is the whole of it, because there is nothing here
 * for it to change: capget answers from the euid at the moment it is asked - not
 * root, not capable - so no stored set is carried across a uid change for the
 * flag to protect. What the flag is actually used for is the sequence libcap
 * performs on behalf of a daemon dropping privilege: set it, change uid, set the
 * reduced set, clear it. Refusing the first step failed the whole sequence, and
 * dbus-daemon's system bus stopped at "Failed to drop capabilities" - a
 * capability model it would have been satisfied by either way.
 */
static int cap_keepcaps = 0;

/*
 * What a change of user does to the capabilities, which is Linux's rule and not
 * an approximation of it.
 *
 * A process that gives up the last of its root ids loses its permitted and
 * effective sets - unless it said to keep them, which is the whole purpose of
 * PR_SET_KEEPCAPS and of the securebit behind it. Giving up an effective root
 * id alone clears the effective set; taking one back restores it from the
 * permitted one. SECBIT_NO_SETUID_FIXUP turns all of it off, for a caller that
 * would rather manage its own.
 *
 * This used to be nothing at all: keepcaps was remembered and reported and
 * changed no outcome, because capget and capset answered from the euid instead
 * of from a set carried across the change. That is fine for a process dropping
 * privilege and giving up its capabilities with it, which is what the flag was
 * added for here. It is exactly wrong for the other caller: Android's init sets
 * the securebits, changes to the service's user, and *then* installs the
 * capabilities that service is to run with - and the last step is a non-root
 * process asking for a non-empty set, which was refused. "cap_set_proc(0)
 * failed: Operation not permitted", and init aborts rather than start a service
 * without the capabilities it asked for.
 */
static void
cap_after_setresuid(bool was_priv, bool now_unpriv, l_uid_t old_euid,
                    l_uid_t new_euid)
{
  if (proc.securebits & SECBIT_NO_SETUID_FIXUP)
    return;
  bool keep = cap_keepcaps || (proc.securebits & SECBIT_KEEP_CAPS);
  pthread_mutex_lock(&cap_lock);
  if (was_priv && now_unpriv) {
    if (!keep) {
      cap_permitted = 0;
      cap_effective = 0;
    }
    /* The ambient set goes whatever keepcaps says, unless the process asked
     * for it to stay - Linux keeps these two decisions apart. */
    if (!(proc.securebits & SECBIT_NO_CAP_AMBIENT_RAISE))
      cap_ambient = 0;
  }
  if (old_euid == 0 && new_euid != 0)
    cap_effective = 0;
  if (old_euid != 0 && new_euid == 0)
    cap_effective = cap_permitted;
  pthread_mutex_unlock(&cap_lock);
}

/*
 * A guest told to start as somebody other than root never had capabilities to
 * lose, so it starts without them. Without this the sets would keep the full
 * value they are initialised with and be reported to a process that has no
 * claim on them - which mattered only once the sets were believed rather than
 * gated on the euid.
 */
/*
 * What an execve does to the capabilities.
 *
 * For a program with none of its own - which is every program here, since
 * nothing carries file capabilities - Linux gives the new image the ambient
 * set in both its permitted and effective sets, and keeps the ambient set
 * itself. That is the whole mechanism by which a process hands capabilities to
 * something it runs, and Android's init relies on nothing else: it raises the
 * ambient bits and execs, having already given up its own.
 */
void
cap_after_exec(void)
{
  pthread_mutex_lock(&cap_lock);
  cap_permitted |= cap_ambient;
  cap_effective |= cap_ambient;
  pthread_mutex_unlock(&cap_lock);
}

void
cap_start_unprivileged(void)
{
  pthread_mutex_lock(&cap_lock);
  cap_effective = cap_permitted = cap_inheritable = 0;
  pthread_mutex_unlock(&cap_lock);
}

/*
 * PR_SET_DUMPABLE, which says whether this process may be core-dumped and
 * inspected.
 *
 * It was answered with a flat 0 - "not dumpable" - for a process that had never
 * said so, and Linux's default is 1. A program reading it back to decide
 * whether it had already hardened itself was told it had.
 *
 * Held and reported, and that is all it can be here. What the flag gates on
 * Linux is the core dump, and the ownership of /proc/<pid>, and who may ptrace
 * it. There is no core dump to suppress - nabi is the process the host would
 * dump - and nothing here consults it for the rest, so the honest description
 * is that this remembers an answer rather than enforcing one.
 */
static int proc_dumpable = 1;

/*
 * PR_SET_THP_DISABLE: do not back this process's memory with huge pages.
 *
 * Held and reported for the same reason and with less regret, because there is
 * nothing to disable: guest memory here is an mmap of a file the host manages,
 * and transparent huge pages are a Linux memory-manager behaviour that has no
 * counterpart in it. A program that sets this is asking not to be given
 * something it was never going to be given, and telling it EINVAL would send it
 * down a path meant for kernels too old to have the option.
 */
static int thp_disabled = 0;

/*
 * PR_SET_PDEATHSIG: the signal this process wants when its parent dies.
 *
 * Darwin has nothing like it, so it is watched for. kqueue can say when a
 * process exits - EVFILT_PROC with NOTE_EXIT - and a thread waiting on that is
 * the whole mechanism; when it fires the signal is raised here, through the
 * same path anything else would raise one.
 *
 * Not storing-and-forgetting, which for this flag would be worse than refusing
 * it: what asks for it is asking to be killed if it is orphaned. LXC sets
 * SIGKILL on the container's first process precisely so that a container cannot
 * outlive the lxc-start that owns it, and a container left running with nothing
 * holding it is the failure the flag exists to prevent.
 *
 * What this does not reproduce is Linux's exactness about *which* death counts.
 * There it is the thread that created this process, not the process; here it is
 * the parent process, because that is what nabi's children have and what kqueue
 * can watch.
 */
static int pdeath_sig = 0;
static bool pdeath_watching = false;
static pthread_mutex_t pdeath_lock = PTHREAD_MUTEX_INITIALIZER;

static void *
pdeath_watch(void *arg)
{
  pid_t parent = (pid_t) (intptr_t) arg;

  int kq = kqueue();
  if (kq < 0)
    return NULL;

  struct kevent ev;
  EV_SET(&ev, (uintptr_t) parent, EVFILT_PROC, EV_ADD | EV_ONESHOT,
         NOTE_EXIT, 0, NULL);
  bool gone = false;
  if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
    /* ESRCH: it died between getppid and here, which is exactly the case the
     * flag is for - so it counts as the death rather than as a failure. */
    gone = errno == ESRCH;
    if (!gone) {
      close(kq);
      return NULL;
    }
  }

  while (!gone) {
    struct kevent out;
    int n = kevent(kq, NULL, 0, &out, 1, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (n > 0) {
      gone = true;
      break;
    }
  }
  close(kq);

  if (!gone)
    return NULL;

  pthread_mutex_lock(&pdeath_lock);
  int sig = pdeath_sig;
  pdeath_watching = false;
  pthread_mutex_unlock(&pdeath_lock);

  if (sig > 0)
    send_signal(getpid(), sig);
  return NULL;
}

/*
 * Forget it, which is what Linux does in a child: the flag is about *this*
 * process's parent, and a child's parent is somebody else. The watcher thread
 * does not survive a fork either, so a child that kept the setting would be
 * waiting on a death nothing was watching for.
 */
void
pdeathsig_clear(void)
{
  pthread_mutex_lock(&pdeath_lock);
  pdeath_sig = 0;
  pdeath_watching = false;
  pthread_mutex_unlock(&pdeath_lock);
}

/* The whole set, bounded by the last capability that exists. */
#define CAP_FULL_SET  ((LINUX_CAP_LAST_CAP >= 63) ? ~0ULL \
                       : ((1ULL << (LINUX_CAP_LAST_CAP + 1)) - 1))

/*
 * Which ABI version the header names, or 0.
 *
 * A version this cannot serve is corrected in place and the call fails, which
 * is the probe libcap performs before it does anything else: capget with
 * version 0 is how it learns which one to use.
 */
static int
cap_version(gaddr_t header_ptr, struct l_user_cap_header *hdr, int *nwords)
{
  if (copy_from_user(hdr, header_ptr, sizeof *hdr))
    return -LINUX_EFAULT;

  switch (hdr->version) {
  case LINUX_CAPABILITY_VERSION_1:
    *nwords = LINUX_CAPABILITY_U32S_1;
    return 0;
  case LINUX_CAPABILITY_VERSION_2:
  case LINUX_CAPABILITY_VERSION_3:
    *nwords = LINUX_CAPABILITY_U32S_3;
    return 0;
  default:
    hdr->version = LINUX_CAPABILITY_VERSION_3;
    if (copy_to_user(header_ptr, hdr, sizeof *hdr))
      return -LINUX_EFAULT;
    return -LINUX_EINVAL;
  }
}

/*
 * Only this process, its threads, or 0 meaning the caller.
 *
 * Linux allows reading another process's capabilities and refuses to set them
 * from outside; here there is nothing to read, for the reason process_vm_readv
 * documents, so both are ESRCH rather than a set belonging to nobody.
 */
static int
cap_check_pid(int32_t pid)
{
  if (pid < 0)
    return -LINUX_EINVAL;
  if (pid == 0)
    return 0;
  pid_t h = pidns_to_host(pid);
  if (h < 0 || h != getpid())
    return -LINUX_ESRCH;
  return 0;
}

DEFINE_SYSCALL(capget, gaddr_t, header_ptr, gaddr_t, data_ptr)
{
  struct l_user_cap_header hdr;
  int nwords, r;
  if ((r = cap_version(header_ptr, &hdr, &nwords)) < 0)
    return r;
  if ((r = cap_check_pid(hdr.pid)) < 0)
    return r;

  /* A null data pointer is the version probe, and it has already been served. */
  if (data_ptr == 0)
    return 0;

  uint64_t eff, perm, inh;
  pthread_mutex_lock(&cap_lock);
  /*
   * The sets as they stand. They are carried across a change of user by the
   * rule Linux uses - see cap_after_setresuid - rather than being gated on the
   * euid at the moment of asking, which reported nothing for a process that
   * had deliberately kept them.
   */
  eff  = cap_effective   & CAP_FULL_SET;
  perm = cap_permitted   & CAP_FULL_SET;
  inh  = cap_inheritable & CAP_FULL_SET;
  pthread_mutex_unlock(&cap_lock);

  struct l_user_cap_data data[LINUX_CAPABILITY_U32S_3] = {{0, 0, 0}, {0, 0, 0}};
  data[0].effective   = (uint32_t) eff;
  data[0].permitted   = (uint32_t) perm;
  data[0].inheritable = (uint32_t) inh;
  if (nwords > 1) {
    data[1].effective   = (uint32_t) (eff  >> 32);
    data[1].permitted   = (uint32_t) (perm >> 32);
    data[1].inheritable = (uint32_t) (inh  >> 32);
  }
  if (copy_to_user(data_ptr, data, sizeof data[0] * nwords))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(capset, gaddr_t, header_ptr, gaddr_t, data_ptr)
{
  struct l_user_cap_header hdr;
  int nwords, r;
  if ((r = cap_version(header_ptr, &hdr, &nwords)) < 0)
    return r;
  /* Setting another process's capabilities has never been allowed. */
  if (hdr.pid != 0 && (r = cap_check_pid(hdr.pid)) < 0)
    return r;
  if (data_ptr == 0)
    return -LINUX_EFAULT;

  struct l_user_cap_data data[LINUX_CAPABILITY_U32S_3] = {{0, 0, 0}, {0, 0, 0}};
  if (copy_from_user(data, data_ptr, sizeof data[0] * nwords))
    return -LINUX_EFAULT;

  uint64_t eff  = data[0].effective;
  uint64_t perm = data[0].permitted;
  uint64_t inh  = data[0].inheritable;
  if (nwords > 1) {
    eff  |= (uint64_t) data[1].effective   << 32;
    perm |= (uint64_t) data[1].permitted   << 32;
    inh  |= (uint64_t) data[1].inheritable << 32;
  }

  pthread_mutex_lock(&cap_lock);
  /*
   * The two rules Linux enforces and a caller can be wrong about: the effective
   * set cannot exceed the permitted one, and neither may gain a capability the
   * process does not already hold. A set is a thing you drop.
   *
   * Held is what capget would report, which for anyone but root is nothing -
   * so a process that is not root may still call this, and the only call that
   * succeeds is one asking for nothing. Refusing it outright was wrong: Linux
   * needs a capability only to *raise* a set, and dropping is what the call is
   * for. libcap drops privilege by setting KEEPCAPS, changing uid, and only
   * then reducing the set; that last step arrives as a non-root caller asking
   * for the empty set, and dbus-daemon's system bus got EPERM for it.
   */
  uint64_t held = cap_permitted;
  int ret = 0;
  if ((eff & ~perm) || (perm & ~held) || (inh & ~held)) {
    ret = -LINUX_EPERM;
  } else {
    cap_permitted   = perm & CAP_FULL_SET;
    cap_effective   = eff  & CAP_FULL_SET;
    cap_inheritable = inh  & CAP_FULL_SET;
  }
  pthread_mutex_unlock(&cap_lock);
  return ret;
}

/*
 * The LSM calls, answered rather than refused, because "no module is loaded" is
 * a true and useful thing to be told.
 *
 * These arrived in 6.8 so a program could ask which security modules are active
 * without parsing /sys/kernel/security. Here the answer is none: there is no
 * kernel to load one into, so nothing labels a process and nothing has an
 * attribute to read or set. ENOSYS would say the *calls* are missing, which
 * would send a caller off to the older per-module interfaces - /proc/self/attr
 * and the rest - to ask the same question again and get the same nothing.
 *
 * lsm_list_modules reporting zero is what a caller checking for SELinux or
 * AppArmor needs, and it is not an approximation. The other two answer
 * EOPNOTSUPP, which is what Linux itself answers when no loaded module handles
 * the attribute - here that is all of them.
 */
DEFINE_SYSCALL(lsm_list_modules, gaddr_t, ids_ptr, gaddr_t, size_ptr, uint32_t, flags)
{
  if (flags != 0)
    return -LINUX_EINVAL;
  if (size_ptr == 0)
    return -LINUX_EFAULT;

  uint32_t size;
  if (copy_from_user(&size, size_ptr, sizeof size))
    return -LINUX_EFAULT;
  /* Nothing to list, so nothing is needed to list it into. Written back
   * whatever was asked for, because that is the caller's answer. */
  size = 0;
  if (copy_to_user(size_ptr, &size, sizeof size))
    return -LINUX_EFAULT;
  (void) ids_ptr;
  return 0;             /* the number of modules, which is the point */
}

DEFINE_SYSCALL(lsm_get_self_attr, uint32_t, attr, gaddr_t, ctx_ptr,
               gaddr_t, size_ptr, uint32_t, flags)
{
  if (attr == 0)                /* LSM_ATTR_UNDEF names nothing */
    return -LINUX_EINVAL;
  if (size_ptr == 0)
    return -LINUX_EFAULT;
  uint32_t size;
  if (copy_from_user(&size, size_ptr, sizeof size))
    return -LINUX_EFAULT;
  (void) ctx_ptr; (void) flags;
  return -LINUX_EOPNOTSUPP;     /* no module supplies it, because there is none */
}

DEFINE_SYSCALL(lsm_set_self_attr, uint32_t, attr, gaddr_t, ctx_ptr,
               uint32_t, size, uint32_t, flags)
{
  if (attr == 0 || flags != 0)
    return -LINUX_EINVAL;
  if (ctx_ptr == 0 || size == 0)
    return -LINUX_EINVAL;
  return -LINUX_EOPNOTSUPP;
}

/*
 * personality: which execution domain, and which of the quirk bits.
 *
 * The domain part is easy and almost always PER_LINUX: the others named
 * SVr4, BSD, SunOS and the rest were for running foreign binaries under
 * emulation layers Linux dropped long ago, and a guest asking for one is asking
 * for something no current kernel provides either.
 *
 * The bits are the part still in use, and they are treated differently
 * depending on whether nabi can honour them.
 *
 * ADDR_NO_RANDOMIZE is accepted, and this is not a courtesy: nabi does not
 * randomize the layout it builds. current_mmap_top walks down from a fixed
 * address and the ELF loader places segments where the file says. A guest that
 * asks for a predictable address space is asking for what it already has, which
 * is why `setarch -R` works here - and why AT_RANDOM had to be fixed
 * separately, since that is entropy for a canary rather than for placement.
 *
 * The rest are refused rather than recorded and ignored. READ_IMPLIES_EXEC
 * would have to reach do_mmap and change what PROT_READ produces; UNAME26 would
 * have to reach uname and make it lie about the version; MMAP_PAGE_ZERO would
 * have to map a page at address zero. Recording any of them would let a caller
 * read its own request back and conclude it took effect - which is exactly what
 * a query is for, and the reason the value is stored at all.
 */
static uint32_t personality_bits;   /* what was last accepted, for the query */

DEFINE_SYSCALL(personality, unsigned int, persona)
{
  enum {
    PER_LINUX          = 0x0000,
    PER_MASK           = 0x00ff,
    UNAME26            = 0x0020000,
    ADDR_NO_RANDOMIZE  = 0x0040000,
    FDPIC_FUNCPTRS     = 0x0080000,
    MMAP_PAGE_ZERO     = 0x0100000,
    ADDR_COMPAT_LAYOUT = 0x0200000,
    READ_IMPLIES_EXEC  = 0x0400000,
    ADDR_LIMIT_32BIT   = 0x0800000,
    SHORT_INODE        = 0x1000000,
    WHOLE_SECONDS      = 0x2000000,
    STICKY_TIMEOUTS    = 0x4000000,
    ADDR_LIMIT_3GB     = 0x8000000,
  };

  uint32_t old = personality_bits;

  /* 0xffffffff is the query, and is documented as leaving the value alone. */
  if (persona == 0xffffffffU)
    return (int) old;

  if ((persona & PER_MASK) != PER_LINUX)
    return -LINUX_EINVAL;       /* a domain no kernel still provides */

  uint32_t bits = persona & ~(uint32_t) PER_MASK;
  /*
   * What can be honoured, plus the ones that ask for nothing here.
   * ADDR_COMPAT_LAYOUT and ADDR_LIMIT_* describe where mmap places things in a
   * 32-bit address space, and this guest is 64-bit with a fixed layout;
   * STICKY_TIMEOUTS and WHOLE_SECONDS are select() quirks from the SVr4 days
   * that Linux itself no longer varies.
   */
  uint32_t honoured = ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT |
                      ADDR_LIMIT_32BIT | ADDR_LIMIT_3GB |
                      STICKY_TIMEOUTS | WHOLE_SECONDS | SHORT_INODE;
  if (bits & ~honoured)
    return -LINUX_EINVAL;       /* see above: not recorded and then ignored */

  personality_bits = bits;
  return (int) old;
}

/*
 * membarrier: implemented as far as it can be answered, which is the query.
 *
 * membarrier moves a barrier out of a program's fast path and into a syscall on
 * its slow path: after it returns, every other thread of the process must have
 * executed a full memory barrier. liburcu, Go's runtime and .NET all use it,
 * and all of them ask MEMBARRIER_CMD_QUERY first and fall back when a command
 * is absent - which is the protocol this uses.
 *
 * The query is answered exactly: no command is available, so the mask is zero
 * and every command is EINVAL, which is what Linux says for a command its
 * kernel does not support. A caller reads that and takes its fallback, which is
 * the correct outcome and one it already has code for.
 *
 * The expedited commands are the ones that could be built. nabi already has the
 * mechanism - vmm_kick_other_vcpus forces every other thread out of
 * hv_vcpu_run, and leaving and re-entering the hypervisor is a full barrier on
 * that core - but it is fire-and-forget, and membarrier may not return until
 * the barrier has actually happened everywhere. That needs a per-vCPU
 * acknowledgement in the run loop of both backends, and a decision about
 * threads that are inside a nabi syscall rather than inside guest code at the
 * moment of the kick. It is exactly the kind of change whose bugs are rare,
 * silent and about memory ordering, so it is not being tacked onto the end of a
 * batch. Reporting nothing until then is the answer that cannot mislead: a
 * membarrier that returns 0 without ordering anything is undebuggable from
 * inside the guest.
 */
DEFINE_SYSCALL(membarrier, int, cmd, unsigned int, flags, int, cpu_id)
{
  enum { MEMBARRIER_CMD_QUERY = 0 };

  if (cmd == MEMBARRIER_CMD_QUERY) {
    if (flags != 0)
      return -LINUX_EINVAL;
    return 0;                   /* the set of commands available, which is none */
  }
  if (cmd < 0)
    return -LINUX_EINVAL;
  (void) cpu_id;
  return -LINUX_EINVAL;         /* not supported, and QUERY said so */
}

/*
 * getcpu: which CPU, in the guest's numbering rather than the host's.
 *
 * The host will answer this - pthread_cpu_number_np is real and returns a real
 * core - and that answer would be wrong to pass on. sched_getaffinity offers
 * this guest exactly one CPU, and sched_setaffinity rejects a mask without CPU
 * 0 for that reason; a program that sizes a per-CPU array from its affinity
 * mask and then indexes it by getcpu would be handed a 4 by a machine that told
 * it there was one CPU. Zero is not a fudge here, it is the truthful answer in
 * the only numbering the guest has been given.
 *
 * The node is zero for the same kind of reason and with none of the doubt:
 * there is one memory node, and it is node 0.
 *
 * Both pointers are optional, and the third argument has been ignored by Linux
 * since 2.6.24 - it was a per-thread cache that no longer exists.
 */
DEFINE_SYSCALL(getcpu, gaddr_t, cpu_ptr, gaddr_t, node_ptr, gaddr_t, tcache)
{
  uint32_t zero = 0;
  if (cpu_ptr != 0 && copy_to_user(cpu_ptr, &zero, sizeof zero))
    return -LINUX_EFAULT;
  if (node_ptr != 0 && copy_to_user(node_ptr, &zero, sizeof zero))
    return -LINUX_EFAULT;
  (void) tcache;
  return 0;
}

/*
 * The uts pair. Neither existed, so a guest could not name itself at all -
 * `hostname foo` reported "Function not implemented" and every guest answered
 * to whatever the Mac is called.
 *
 * They write to the namespace rather than to the host, which is the whole point
 * of the exercise: two guests in different uts namespaces disagree about the
 * hostname, and neither renames the Mac. Setting one requires being root, as it
 * does on Linux, and root here is the guest's own - see struct cred.
 */
static int
uts_set(gaddr_t ptr, size_t len, char *dst, size_t dstsz)
{
  if (len > dstsz - 1)
    return -LINUX_EINVAL;
  bool is_root;
  pthread_rwlock_rdlock(&proc.cred.lock);
  is_root = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (!is_root)
    return -LINUX_EPERM;

  char buf[128];
  if (len >= sizeof buf)
    return -LINUX_EINVAL;
  if (copy_from_user(buf, ptr, len))
    return -LINUX_EFAULT;
  buf[len] = '\0';

  memcpy(dst, buf, len);
  dst[len] = '\0';
  current_uts_commit();         /* so every process in the namespace sees it */
  return 0;
}

DEFINE_SYSCALL(sethostname, gaddr_t, name_ptr, size_t, len)
{
  struct uts_namespace *uts = current_uts();   /* reloads, so the domainname
                                                * beside it is not stale */
  return uts_set(name_ptr, len, uts->nodename, sizeof uts->nodename);
}

DEFINE_SYSCALL(setdomainname, gaddr_t, name_ptr, size_t, len)
{
  struct uts_namespace *uts = current_uts();
  return uts_set(name_ptr, len, uts->domainname, sizeof uts->domainname);
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
  /*
   * The name and domain come from the uts namespace, not from the host.
   *
   * Before there were namespaces here this asked the Mac directly, so every
   * guest reported the Mac's name and sethostname did not exist to change it.
   * The initial namespace is still seeded from the host, so a guest that never
   * touches it sees exactly what it saw before.
   */
  struct uts_namespace *uts = current_uts();
  strncpy(buf.nodename, uts->nodename, sizeof buf.nodename - 1);
  buf.nodename[sizeof buf.nodename - 1] = '\0';
  strncpy(buf.domainname, uts->domainname, sizeof buf.domainname - 1);
  buf.domainname[sizeof buf.domainname - 1] = '\0';

  if (copy_to_user(buf_ptr, &buf, sizeof(struct utsname))) {
    return -LINUX_EFAULT;
  }

  return 0;
}

/*
 * prctl takes an option and four arguments, not five.
 *
 * Linux declares it SYSCALL_DEFINE5 - option plus arg2..arg5 - so the last
 * register a caller sets is the fourth argument. This read one more, and then
 * checked it: every option that requires its unused arguments to be zero, as
 * Linux does, was testing a register nobody had written. glibc's prctl is
 * variadic and sets only what it was given, so the value there is whatever the
 * last call left behind, and the checks failed or passed by luck.
 *
 * PR_SET_KEEPCAPS is where that showed. libcap sets it as the first step of
 * dropping privilege, the garbage in the sixth register failed the check, and
 * dbus-daemon's system bus refused to start.
 */
DEFINE_SYSCALL(prctl, int, option, unsigned long, arg1, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4)
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
  case LINUX_PR_SET_VMA: {
    char name[64] = {0};
    if (arg1 != 0) {
      if (copy_from_user(name, (gaddr_t)arg1, sizeof(name) - 1)) {
        return -LINUX_EFAULT;
      }
      name[sizeof(name) - 1] = '\0';
    }
    warnk("prctl PR_SET_VMA: addr=%#lx len=%#lx name=%s\n", arg2, arg3, name);
    return 0;
  }
  case LINUX_PR_SET_PDEATHSIG: {
    if (arg1 > LINUX_NSIG || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    pthread_mutex_lock(&pdeath_lock);
    pdeath_sig = (int) arg1;
    bool start = pdeath_sig > 0 && !pdeath_watching;
    if (start)
      pdeath_watching = true;
    pthread_mutex_unlock(&pdeath_lock);

    if (start) {
      pthread_t t;
      if (pthread_create(&t, NULL, pdeath_watch,
                         (void *) (intptr_t) getppid()) != 0) {
        pthread_mutex_lock(&pdeath_lock);
        pdeath_watching = false;
        pthread_mutex_unlock(&pdeath_lock);
        return -LINUX_EAGAIN;
      }
      pthread_detach(t);
    }
    return 0;
  }
  case LINUX_PR_GET_PDEATHSIG: {
    if (arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    pthread_mutex_lock(&pdeath_lock);
    int sig = pdeath_sig;
    pthread_mutex_unlock(&pdeath_lock);
    if (copy_to_user((gaddr_t) arg1, &sig, sizeof sig))
      return -LINUX_EFAULT;
    return 0;
  }
  case LINUX_PR_GET_DUMPABLE:
    if (arg1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    return proc_dumpable;
  case LINUX_PR_SET_DUMPABLE:
    /* 0 and 1 are the only values a process may set. 2 exists - dumpable only
     * for root - but Linux reserves it to the fs.suid_dumpable sysctl and
     * refuses it here, so refusing it is what a caller is prepared for. */
    if (arg1 > 1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    proc_dumpable = (int) arg1;
    return 0;
  case LINIX_PR_SET_THP_DISABLE:
    /* arg2 carries flags in newer kernels; none are defined that this could
     * honour, so a request for one is refused rather than ignored. */
    if (arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    thp_disabled = arg1 != 0;
    return 0;
  case LINIX_PR_GET_THP_DISABLE:
    if (arg1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    return thp_disabled;
  case LINUX_PR_SET_KEEPCAPS:
    if (arg1 > 1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    pthread_mutex_lock(&cap_lock);
    cap_keepcaps = (int) arg1;
    pthread_mutex_unlock(&cap_lock);
    return 0;
  case LINUX_PR_GET_KEEPCAPS: {
    if (arg1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    pthread_mutex_lock(&cap_lock);
    int keep = cap_keepcaps;
    pthread_mutex_unlock(&cap_lock);
    return keep;
  }
  case 55:
    return 0;
  /*
   * The seccomp options, which are prctl's older door into the same thing.
   * PR_SET_SECCOMP predates the seccomp syscall and is still what a program
   * built against older headers emits, so it goes to the same place rather than
   * to a second implementation that could drift from it.
   */
  case LINIX_PR_SET_NO_NEW_PRIVS:
    if (arg1 != 1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;     /* it can only be set, and only to one */
    return seccomp_no_new_privs_set();
  case LINIX_PR_GET_NO_NEW_PRIVS:
    if (arg1 || arg2 || arg3 || arg4)
      return -LINUX_EINVAL;
    return seccomp_no_new_privs_get();
  case LINIX_PR_SET_SECCOMP:
    return seccomp_prctl_set(arg1, (gaddr_t) arg2);
  case LINIX_PR_GET_SECCOMP:
    return seccomp_mode_get();

  /*
   * The securebits, which are the rules a process wants applied to its own
   * transitions across uid 0 - keep capabilities across a setuid, do not grant
   * them for being root, and the locks that make each of those irreversible.
   *
   * There is no capability model here for them to change, so they change
   * nothing; they are remembered and handed back so that a caller reading its
   * own settings is told what it set. Refusing the pair is what could not
   * stand: Android's init reads them for every service it starts and treats
   * the failure as fatal - "prctl(PR_GET_SECUREBITS) failed for logd: Invalid
   * argument" - so logd never started and init aborted.
   *
   * The locking bits are honoured to the extent that anything here can: once a
   * lock bit is set, the bit it locks cannot be changed again, which is the
   * whole of what a lock does and is checkable without a capability model.
   */
  /*
   * The capability bounding set. Reading it is unprivileged; dropping from it
   * needs CAP_SETPCAP, and drops are all that can be done - Linux has no way
   * to put a capability back, which is what makes the set a bound rather than
   * a setting.
   *
   * Refusing the pair stopped Android before any service ran. init drops every
   * capability a service is not to have from the bound before it execs it, one
   * prctl per capability, and reports the first refusal as "cap_drop_bound(0)
   * failed: Operation not permitted" - then aborts rather than start a service
   * with more power than it asked for. Which is the right instinct, and the
   * reason answering this honestly matters more than it looks.
   */
  /*
   * The ambient set. Android's init asks whether it exists before it will
   * accept a `capabilities` line at all - "capabilities requested but the
   * kernel does not support ambient capabilities" - and then hands a service
   * its capabilities by raising them here and letting the execve carry them.
   *
   * Without it init dropped its own permitted set to nothing before the exec,
   * because ambient was supposed to be holding the capabilities by then, and
   * logd's own capset for CAP_SYSLOG came back EPERM against an empty
   * permitted set. logd exits, init restarts it, and the restart fails on a
   * read-only property the first attempt had already set.
   *
   * Linux's conditions for raising, and they are the whole of what makes an
   * ambient capability safe: it must already be both permitted and
   * inheritable, so nothing can be added that the process did not have, and
   * SECBIT_NO_CAP_AMBIENT_RAISE refuses it outright.
   */
  case LINIX_PR_CAP_AMBIENT: {
    switch (arg1) {
    case 1:                                   /* PR_CAP_AMBIENT_IS_SET */
      if (arg2 > LINUX_CAP_LAST_CAP)
        return -LINUX_EINVAL;
      return (int) ((cap_ambient >> arg2) & 1);
    case 2: {                                 /* PR_CAP_AMBIENT_RAISE */
      if (arg2 > LINUX_CAP_LAST_CAP)
        return -LINUX_EINVAL;
      uint64_t bit = 1ULL << arg2;
      pthread_mutex_lock(&cap_lock);
      bool may = (cap_permitted & bit) && (cap_inheritable & bit) &&
                 !(proc.securebits & SECBIT_NO_CAP_AMBIENT_RAISE);
      if (may)
        cap_ambient |= bit;
      pthread_mutex_unlock(&cap_lock);
      return may ? 0 : -LINUX_EPERM;
    }
    case 3:                                   /* PR_CAP_AMBIENT_LOWER */
      if (arg2 > LINUX_CAP_LAST_CAP)
        return -LINUX_EINVAL;
      pthread_mutex_lock(&cap_lock);
      cap_ambient &= ~(1ULL << arg2);
      pthread_mutex_unlock(&cap_lock);
      return 0;
    case 4:                                   /* PR_CAP_AMBIENT_CLEAR_ALL */
      if (arg2)
        return -LINUX_EINVAL;
      pthread_mutex_lock(&cap_lock);
      cap_ambient = 0;
      pthread_mutex_unlock(&cap_lock);
      return 0;
    default:
      return -LINUX_EINVAL;
    }
  }

  case LINIX_PR_CAPBSET_READ:
    if (arg1 > LINUX_CAP_LAST_CAP)
      return -LINUX_EINVAL;
    return (int) ((cap_bounding >> arg1) & 1);
  case LINIX_PR_CAPBSET_DROP: {
    if (arg1 > LINUX_CAP_LAST_CAP)
      return -LINUX_EINVAL;
    pthread_mutex_lock(&cap_lock);
    bool may = (cap_effective & (1ULL << LINUX_CAP_SETPCAP)) != 0;
    if (may)
      cap_bounding &= ~(1ULL << arg1);
    pthread_mutex_unlock(&cap_lock);
    return may ? 0 : -LINUX_EPERM;
  }

  case LINIX_PR_GET_SECUREBITS:
    /* No argument checking, because Linux does none: the remaining arguments
     * of a prctl are whatever the caller's varargs left on the stack, and
     * Android's reads them uninitialised. Refusing on their account is how
     * this came back EINVAL for a call that had asked for nothing. */
    return (int) proc.securebits;
  case LINIX_PR_SET_SECUREBITS: {
    uint32_t want = (uint32_t) arg1;
    uint32_t have = proc.securebits;
    uint32_t locks = have & SECUREBITS_LOCKS;
    /* Linux's three refusals, in its order: a locked rule may not change, a
     * lock may not be cleared, and no bit outside the set may be named. */
    if (((locks >> 1) & (have ^ want)) || (locks & ~want) ||
        (want & ~(uint32_t) SECUREBITS_KNOWN))
      return -LINUX_EPERM;
    proc.securebits = want;
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

/*
 * waitid: the same wait, said precisely.
 *
 * wait4 encodes the outcome in a status word the caller picks apart with
 * macros; waitid states it - exited, killed, stopped, continued - in a siginfo,
 * and can look at a child *without* reaping it. That last part is why lxc-start
 * uses it, and why this is served by Darwin's own waitid rather than built out
 * of wait4: WNOWAIT has no expression in wait4 at all.
 *
 * Both directions of the pid namespace are translated, as wait4 does: the id
 * asked about is this namespace's, and the pid reported back has to be too.
 */
DEFINE_SYSCALL(waitid, int, idtype, int, id, gaddr_t, infop, int, options,
               gaddr_t, rusage_ptr)
{
  /* Linux insists the caller says which states it wants to hear about. */
  if (!(options & (LINUX_WEXITED | LINUX_WSTOPPED | LINUX_WCONTINUED)))
    return -LINUX_EINVAL;
  if (options & ~(LINUX_WNOHANG | LINUX_WEXITED | LINUX_WSTOPPED |
                  LINUX_WCONTINUED | LINUX_WNOWAIT))
    return -LINUX_EINVAL;

  idtype_t did;
  id_t hid = (id_t) id;
  switch (idtype) {
  case LINUX_P_ALL:
    did = P_ALL;
    hid = 0;
    break;
  case LINUX_P_PID: {
    did = P_PID;
    int32_t h = pidns_to_host(id);
    if (h < 0)
      return -LINUX_ECHILD;
    hid = (id_t) h;
    break;
  }
  case LINUX_P_PGID: {
    did = P_PGID;
    /* A process group is named by its leader, so it translates as a pid. */
    int32_t h = pidns_to_host(id);
    if (h < 0)
      return -LINUX_ECHILD;
    hid = (id_t) h;
    break;
  }
  default:
    /* P_PIDFD wants a descriptor rather than a number, and nothing here can
     * turn one into the other yet. */
    return -LINUX_EINVAL;
  }

  int dopts = 0;
  if (options & LINUX_WNOHANG)    dopts |= WNOHANG;
  if (options & LINUX_WEXITED)    dopts |= WEXITED;
  if (options & LINUX_WSTOPPED)   dopts |= WSTOPPED;
  if (options & LINUX_WCONTINUED) dopts |= WCONTINUED;
  if (options & LINUX_WNOWAIT)    dopts |= WNOWAIT;

  siginfo_t info;
  memset(&info, 0, sizeof info);
  int r = syswrap(waitid(did, hid, &info, dopts));
  if (r < 0)
    return r;

  /*
   * WNOHANG with nothing to report is success with an empty siginfo, and si_pid
   * of zero is how the caller is told so - not an error, which is what makes
   * the zeroing above load-bearing.
   */
  if (infop != 0) {
    l_siginfo_t li;
    memset(&li, 0, sizeof li);
    if (info.si_pid != 0) {
      li.lsi_signo = LINUX_SIGCHLD;
      li.lsi_code = info.si_code;   /* CLD_* agree on both systems */
      li.lsi_pid = (l_pid_t) pidns_to_ns((int32_t) info.si_pid);
      li.lsi_uid = (l_uid_t) host_uid_to_guest(info.si_uid);
      li.lsi_status = info.si_status;
    }
    if (copy_to_user(infop, &li, sizeof li))
      return -LINUX_EFAULT;
  }

  /* Linux's waitid takes a fifth argument for rusage, which glibc does not
   * pass; it is filled only when asked for. */
  if (rusage_ptr != 0) {
    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    if (copy_to_user(rusage_ptr, &ru, sizeof ru))
      return -LINUX_EFAULT;
  }
  return 0;
}

DEFINE_SYSCALL(wait4, int, pid, gaddr_t, status_ptr, int, options, gaddr_t, rusage_ptr)
{
  int status;
  struct rusage rusage;

  /*
   * Both directions. A positive pid names a process in this namespace and has
   * to be turned into the host's before waiting; the pid that comes back has to
   * be turned into this namespace's before it is returned, or a caller that
   * waits for the child clone told it about gets a different number back.
   * -1 and the process-group forms pass through, since they name a set rather
   * than a process.
   */
  pid_t hpid = pid;
  if (pid > 0) {
    hpid = pidns_to_host(pid);
    if (hpid < 0)
      return -LINUX_ECHILD;
  }

  int ret = syswrap(wait4(hpid, &status, linux_to_darwin_waitopts(options), &rusage));
  if (ret < 0) {
    return ret;
  }
  ret = pidns_to_ns(ret);

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

/* The nice this process asked for, when the host would not take it; see
 * setpriority below. */
static int nice_wanted = 0;
static bool nice_pretended = false;

DEFINE_SYSCALL(getpriority, int, which, int, who)
{
  /*
   * Linux's getpriority syscall does not return the nice value. It returns
   * 20 - nice, so that the result is 1..40 and can never be mistaken for an
   * error, and glibc's wrapper converts it back. Darwin's getpriority(3)
   * returns the nice value itself, so handing it straight over means the guest
   * computes 20 - nice a second time.
   *
   * At the usual nice of 0 that reads as 20 - the lowest priority there is -
   * and the guest believes it. pam_limits then applies what it thinks it
   * found, so `setpriority(20)` really did drop the host process to nice 20;
   * the attempt to put it back to 0 was then a *raise* in priority, which
   * Darwin refuses to an unprivileged process with EACCES. pam_limits is
   * `required` in sudo's session stack, so sudo stopped with
   * "pam_open_session: Permission denied" - about a nice value.
   *
   * -1 is a legitimate nice value, so failure is distinguished by errno rather
   * than by the return, which is the whole reason the Linux encoding exists.
   */
  errno = 0;
  int nice = getpriority(which, who);
  if (nice == -1 && errno != 0)
    return -darwin_to_linux_errno(errno);
  /* What this process asked for, if the host would not take it - see
   * setpriority. Answering with the host's value would contradict the success
   * this already reported. */
  if (nice_pretended && which == PRIO_PROCESS && (who == 0 || who == getpid()))
    nice = nice_wanted;
  return 20 - nice;
}

/*
 * Whether the *guest* may raise a process's priority, which is not the same
 * question the host answers.
 *
 * Lowering the nice value needs CAP_SYS_NICE on Linux. The guest that asks may
 * well have it - Android's init is root and holds it - while the account nabi
 * runs as does not, so the host refuses a request the guest was entitled to
 * make. Asked here with the guest's own credentials, as file access is.
 */
static bool
may_renice(void)
{
  bool root;
  pthread_rwlock_rdlock(&proc.cred.lock);
  root = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);
  if (root)
    return true;
  pthread_mutex_lock(&cap_lock);
  bool cap = (cap_effective & (1ULL << LINUX_CAP_SYS_NICE)) != 0;
  pthread_mutex_unlock(&cap_lock);
  return cap;
}

/*
 * setpriority, answered with the guest's credentials.
 *
 * The host is asked first and its answer stands whenever it is not about
 * privilege: a value out of range is still EINVAL, a process that does not
 * exist is still ESRCH. What cannot stand is EPERM for a guest that holds
 * CAP_SYS_NICE, because that is nabi's own unprivileged account speaking and
 * not anything about the guest.
 *
 * The value is then remembered rather than applied, and getpriority reports it
 * back. That is a real gap and worth stating plainly: the guest's scheduling
 * request has no effect, and only the answer to "what did I ask for" is
 * truthful. Failing instead is worse and not more honest - Android's init sets
 * the zygote's priority before exec'ing it and treats the refusal as fatal
 * ("cannot set attribute for zygote"), so the whole framework never starts
 * over a nice value nothing here could have honoured either way.
 */
DEFINE_SYSCALL(setpriority, int, which, int, who, int, niceval)
{
  errno = 0;
  int r = setpriority(which, who, niceval);
  if (r == 0) {
    /* The host took it, so it is the truth again and any value remembered
     * from a request it would not take is stale. */
    if (which == PRIO_PROCESS && (who == 0 || who == getpid()))
      nice_pretended = false;
    return 0;
  }
  int e = errno;
  if ((e == EPERM || e == EACCES) && may_renice()) {
    if (which == PRIO_PROCESS && (who == 0 || who == getpid())) {
      nice_wanted = niceval;
      nice_pretended = true;
    }
    return 0;
  }
  errno = e;
  return syswrap(-1);
}

/* ------------------------------------------------------------- scheduling
 *
 * A guest thread is an ordinary host thread, and it stays one.
 *
 * Darwin has real-time scheduling, but not through POSIX: it is Mach's
 * thread_policy_set with a time-constraint policy, which needs a port and a
 * privilege nabi has not got. There is no honest way to put a guest thread on
 * SCHED_FIFO, so the guest is SCHED_OTHER and these say so consistently -
 * getscheduler agrees with what setscheduler accepted, and getparam agrees with
 * both.
 *
 * The refusal is the one Linux already gives. An unprivileged process asking
 * for SCHED_FIFO gets EPERM there too, so every caller that asks for real-time
 * scheduling already has a path for being told no; that is a far better answer
 * than accepting the request and not honouring it, which nothing can detect.
 *
 * The priority *ranges*, though, are reported as Linux reports them. Asking
 * what a policy's range is is a question about the interface rather than a
 * request to be scheduled under it, and a guest comparing a number against the
 * maximum should get the number it would get anywhere else.
 */

/* The task exists, or ESRCH. pid 0 is the caller, which always does. Guest pids
 * are host pids, so this is a real question with a real answer. */
static int
sched_check_pid(l_pid_t pid)
{
  if (pid < 0)
    return -LINUX_EINVAL;
  if (pid == 0)
    return 0;
  return syswrap(kill(pid, 0)) < 0 ? -LINUX_ESRCH : 0;
}

/* Whether a policy exists at all, with the flag bit already stripped. */
static bool
sched_policy_known(int policy)
{
  switch (policy) {
  case LINUX_SCHED_OTHER: case LINUX_SCHED_FIFO: case LINUX_SCHED_RR:
  case LINUX_SCHED_BATCH: case LINUX_SCHED_IDLE:
    return true;
  default:
    return false;
  }
}

static bool
sched_policy_is_realtime(int policy)
{
  return policy == LINUX_SCHED_FIFO || policy == LINUX_SCHED_RR;
}

DEFINE_SYSCALL(sched_getscheduler, l_pid_t, pid)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  return LINUX_SCHED_OTHER;
}

DEFINE_SYSCALL(sched_getparam, l_pid_t, pid, gaddr_t, param_ptr)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (param_ptr == 0)
    return -LINUX_EINVAL;

  /* Zero, which is the only priority SCHED_OTHER has. */
  struct l_sched_param param = { .sched_priority = 0 };
  if (copy_to_user(param_ptr, &param, sizeof param))
    return -LINUX_EFAULT;
  return 0;
}

DEFINE_SYSCALL(sched_setparam, l_pid_t, pid, gaddr_t, param_ptr)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (param_ptr == 0)
    return -LINUX_EINVAL;

  struct l_sched_param param;
  if (copy_from_user(&param, param_ptr, sizeof param))
    return -LINUX_EFAULT;

  /* The task is SCHED_OTHER, whose only valid priority is 0 - Linux answers
   * EINVAL for anything else rather than pretending to set it. */
  if (param.sched_priority != 0)
    return -LINUX_EINVAL;
  return 0;
}

DEFINE_SYSCALL(sched_setscheduler, l_pid_t, pid, int, policy, gaddr_t, param_ptr)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;

  int base = policy & ~LINUX_SCHED_RESET_ON_FORK;
  if (!sched_policy_known(base))
    return -LINUX_EINVAL;
  if (param_ptr == 0)
    return -LINUX_EINVAL;

  struct l_sched_param param;
  if (copy_from_user(&param, param_ptr, sizeof param))
    return -LINUX_EFAULT;

  if (sched_policy_is_realtime(base)) {
    /* The priority has to be in range before privilege is considered, because
     * that is the order Linux checks in and a caller probing the range should
     * not have EPERM hide an EINVAL. */
    if (param.sched_priority < LINUX_SCHED_RT_PRIO_MIN ||
        param.sched_priority > LINUX_SCHED_RT_PRIO_MAX)
      return -LINUX_EINVAL;
    return -LINUX_EPERM;        /* no real-time scheduling to hand out */
  }

  if (param.sched_priority != 0)
    return -LINUX_EINVAL;
  return 0;                     /* already SCHED_OTHER, and staying there */
}

DEFINE_SYSCALL(sched_get_priority_max, int, policy)
{
  if (!sched_policy_known(policy))
    return -LINUX_EINVAL;
  return sched_policy_is_realtime(policy) ? LINUX_SCHED_RT_PRIO_MAX : 0;
}

DEFINE_SYSCALL(sched_get_priority_min, int, policy)
{
  if (!sched_policy_known(policy))
    return -LINUX_EINVAL;
  return sched_policy_is_realtime(policy) ? LINUX_SCHED_RT_PRIO_MIN : 0;
}

DEFINE_SYSCALL(sched_rr_get_interval, l_pid_t, pid, gaddr_t, interval_ptr)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (interval_ptr == 0)
    return -LINUX_EINVAL;

  /* Zero, which is what Linux reports for a task that is not on SCHED_RR - and
   * none of them are. */
  struct l_timespec ts = { 0, 0 };
  if (copy_to_user(interval_ptr, &ts, sizeof ts))
    return -LINUX_EFAULT;
  return 0;
}

/*
 * sched_setattr: the modern interface for changing scheduling policy.
 *
 * Everything the older sched_setscheduler and sched_setparam do is expressible
 * here, plus SCHED_DEADLINE whose three timing parameters have no older call.
 * NABI handles it the same way: normal policies are accepted silently (the
 * thread is already SCHED_OTHER and stays there), real-time policies are
 * refused with EPERM, and DEADLINE is refused with EINVAL because it needs
 * kernel support that does not exist in a guest.
 *
 * The size field versions the structure: a caller may pass fewer bytes than
 * NABI knows about, and only the fields that version covers are examined.
 * Version 0 (48 bytes) lacks sched_flags; version 1 (56 bytes) includes it.
 * A size larger than what we know is not an error — the caller is newer —
 * and a size smaller than the minimum (40 bytes, through sched_priority) is
 * EINVAL.  Flags outside RESET_ON_FORK are silently accepted so that future
 * flags do not break old callers.
 */
DEFINE_SYSCALL(sched_setattr, l_pid_t, pid, gaddr_t, attr_ptr, unsigned int, flags)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (attr_ptr == 0)
    return -LINUX_EINVAL;

  struct l_sched_attr a;
  if (copy_from_user(&a, attr_ptr, sizeof a))
    return -LINUX_EFAULT;

  /* The minimum usable size covers through sched_priority (40 bytes).  The
   * maximum NABI understands is the full v1 (56 bytes); a larger size means
   * a newer caller, which is fine — just ignore the fields we do not know. */
  if (a.size < 40)
    return -LINUX_EINVAL;

  int base = a.sched_policy;
  if (flags & LINUX_SCHED_FLAG_RESET_ON_FORK)
    base &= ~LINUX_SCHED_RESET_ON_FORK;
  if (!sched_policy_known(base))
    return -LINUX_EINVAL;

  if (sched_policy_is_realtime(base)) {
    /* Priority range first, then privilege — the order Linux checks in. */
    if (a.sched_priority < LINUX_SCHED_RT_PRIO_MIN ||
        a.sched_priority > LINUX_SCHED_RT_PRIO_MAX)
      return -LINUX_EINVAL;
    return -LINUX_EPERM;
  }

  if (base == LINUX_SCHED_DEADLINE)
    return -LINUX_EINVAL;         /* no DEADLINE support */

  if (a.sched_priority != 0)
    return -LINUX_EINVAL;
  return 0;                       /* already SCHED_OTHER, staying there */
}

/*
 * sched_getattr: report a task's scheduling attributes.
 *
 * The answer is always the same: SCHED_OTHER with no flags, nice 0,
 * priority 0, and zero timing parameters.  That is honest — the thread is
 * SCHED_OTHER and nothing the guest did changed that — and consistent with
 * what every other scheduler call in NABI reports.
 *
 * The size field controls how many bytes are written back: a caller using an
 * older layout gets fewer fields, and a newer caller gets the full v1 struct.
 * The flags field is only written when the caller's version includes it (size
 * >= 56).
 */
DEFINE_SYSCALL(sched_getattr, l_pid_t, pid, gaddr_t, attr_ptr, unsigned int, flags)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (attr_ptr == 0)
    return -LINUX_EINVAL;

  /* Read the caller's size so we know how much to write back. */
  l_uint caller_size;
  if (copy_from_user(&caller_size, attr_ptr, sizeof caller_size))
    return -LINUX_EFAULT;
  if (caller_size < 40)
    return -LINUX_EINVAL;

  struct l_sched_attr a;
  a.size           = sizeof(struct l_sched_attr);
  a.sched_policy   = LINUX_SCHED_OTHER;
  a.sched_flags    = 0;
  a.sched_nice     = 0;
  a.sched_priority = 0;
  a.sched_runtime  = 0;
  a.sched_deadline = 0;
  a.sched_period   = 0;

  /* Write back only as many bytes as the caller asked for.  The first field
   * is always size (4 bytes), so everything from the second field onward is
   * at offset 4.  The caller's size already includes the 4-byte preamble. */
  size_t n = caller_size < sizeof a ? caller_size : sizeof a;
  if (copy_to_user(attr_ptr, &a, n))
    return -LINUX_EFAULT;
  /* Linux always returns sizeof(struct sched_attr) regardless of how many
   * bytes were actually written. */
  return sizeof(struct l_sched_attr);
}

/*
 * Accepted and not enforced, which is worth being explicit about.
 *
 * Darwin has no CPU pinning to offer - thread_policy_set's affinity policy is a
 * hint about sharing caches, not a restriction, and it is not exposed for
 * another process at all. Refusing would be the more honest answer in the
 * abstract, but affinity is overwhelmingly set as an optimisation by runtimes
 * that treat failure as fatal, and Linux itself makes no promise that a mask is
 * honoured beyond the CPUs that exist.
 *
 * What is checked is the part a caller can be wrong about: a mask naming no
 * usable CPU is EINVAL, exactly as it is on Linux. sched_getaffinity goes on
 * reporting the one CPU this guest has, so the two do not contradict each
 * other - a round trip returns the mask the guest was always going to get.
 */
DEFINE_SYSCALL(sched_setaffinity, l_pid_t, pid, unsigned int, len, gaddr_t, user_mask_ptr)
{
  int r;
  if ((r = sched_check_pid(pid)) < 0)
    return r;
  if (len == 0 || user_mask_ptr == 0)
    return -LINUX_EINVAL;

  unsigned char buf[128];
  unsigned int n = len < sizeof buf ? len : (unsigned int) sizeof buf;
  if (copy_from_user(buf, user_mask_ptr, n))
    return -LINUX_EFAULT;

  /* CPU 0 is the only one sched_getaffinity offers, so a mask without it names
   * nothing this guest can run on. */
  if (!(buf[0] & 0x1))
    return -LINUX_EINVAL;
  return 0;
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
