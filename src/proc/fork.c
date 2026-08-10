#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <strings.h>

#include "common.h"
#include "noah.h"
#include "namespace.h"
#include "vmm.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/signal.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/syslimits.h>
#include <mach-o/dyld.h>

#include "mm.h"
#include "checkpoint.h"


static void
init_task(unsigned long clone_flags, gaddr_t child_tid, gaddr_t tls)
{
  LINUX_SIGEMPTYSET(&task.sigmask);
  INIT_SIGBIT(&task.sigpending);

  if (clone_flags & LINUX_CLONE_THREAD) {
    pthread_threadid_np(NULL, &task.tid);
  } else {
    task.tid = getpid();
  }

  task.set_child_tid = task.clear_child_tid = 0;
  if (clone_flags & LINUX_CLONE_CHILD_SETTID) {
    task.set_child_tid = child_tid;
  }
  if (clone_flags & LINUX_CLONE_CHILD_CLEARTID) {
    task.clear_child_tid = child_tid;
  }

  if (task.set_child_tid != 0) {
    int tid = do_gettid();
    if (copy_to_user(task.set_child_tid, &tid, sizeof tid)) {
      assert(false);
    }
  }

  /* TODO: do we need to clear task.robust_list when CLONE_THREAD is set? */
  /* task.robust_list = 0; */
  /* task.robust_list_len = 0; */

  if (clone_flags & LINUX_CLONE_SETTLS) {
    vmm_set_tls(tls);
  }
}

/*
 * A fork that fails has to say so where it can be seen.
 *
 * warnk writes to the -w sink, and a resumed child has none: it is exec'd as
 * `nabi --resume` and parses no options, so a handover that fails inside a
 * child - which is most of them, once a guest is a few processes deep - reports
 * nothing anywhere. The guest is left with a bare "Cannot fork" and no cause.
 */
#define FORKERR(fmt, ...) do {                                            \
    warnk("fork: " fmt "\n", ##__VA_ARGS__);                              \
    fprintf(stderr, "nabi: fork: " fmt "\n", ##__VA_ARGS__);              \
  } while (0)

#if defined(__arm64__)
/*
 * fork by handing the guest to a fresh process.
 *
 * The child cannot create a vCPU in the process fork gives it - the framework
 * crashes about one time in eight once a vCPU has existed anywhere in the
 * process (spike/arm64-fork/) - so it `exec`s first, and everything it needs
 * arrives through two inherited descriptors: the arena holding the guest's
 * memory, and a checkpoint describing everything else.
 *
 * The parent never touches its VM. That is the real prize here, and not just an
 * economy: the old path destroyed the VM and rebuilt it on both sides, and it
 * was the *child's* rebuild that crashed. With the child exec'ing there is no
 * rebuild to crash, and the parent carries on with the machine it already had.
 *
 * This is the default on arm64; NABI_FORK_EXEC=0 falls back to the old path.
 */
static int
clone_process_by_exec(unsigned long clone_flags, gaddr_t parent_tid,
                      gaddr_t child_tid, gaddr_t tls)
{
  char self[PATH_MAX];
  uint32_t selfsz = sizeof self;
  if (_NSGetExecutablePath(self, &selfsz) != 0) {
    FORKERR("cannot find my own executable to re-exec");
    return -LINUX_ENOEXEC;
  }

  /*
   * The checkpoint goes to a file rather than a pipe: the child does not read it
   * until after it has exec'd, so a pipe would deadlock the moment the
   * checkpoint outgrew the pipe buffer.
   */
  char path[PATH_MAX];
  const char *tmp = getenv("TMPDIR");
  snprintf(path, sizeof path, "%s/nabi-handover-XXXXXX",
           tmp && *tmp ? tmp : "/tmp");
  int ckpt_fd = mkstemp(path);
  if (ckpt_fd < 0) {
    FORKERR("no checkpoint file at %s: %s", path, strerror(errno));
    return -darwin_to_linux_errno(errno);
  }
  unlink(path);
  fcntl(ckpt_fd, F_SETFD, 0);           /* must survive the exec */

  /*
   * The child returns 0 from clone. Set that before the snapshot is taken - the
   * parent's own return value is written by the syscall path afterwards, so x0
   * is free to borrow here.
   */
  vmm_set_reg(VREG_RET, 0);

  /* The guest's live bytes are in private mappings; copy them into an arena of
   * this handover's own, which nothing will write to again. */
  int snap_fd = arena_snapshot();
  if (snap_fd < 0 || checkpoint_write(ckpt_fd) < 0) {
    int e = errno;
    FORKERR("%s failed: %s", snap_fd < 0 ? "arena snapshot" : "checkpoint write", strerror(e));
    close(ckpt_fd);
    if (snap_fd >= 0)
      close(snap_fd);
    return -darwin_to_linux_errno(e);
  }
  lseek(ckpt_fd, 0, SEEK_SET);

  int ret = syswrap(fork());
  if (ret < 0) {
    FORKERR("%s", strerror(errno));
    close(ckpt_fd);
    close(snap_fd);
    return ret;
  }

  if (ret == 0) {
    /* The guest forked; only our implementation execs. Keep its descriptors. */
    fdtable_clear_host_cloexec();
    /*
     * The clone parameters travel too. They describe what this *call* asks of
     * the child - write your tid here, clear it there, take this TLS - and are
     * not part of the parent's state, so the checkpoint does not carry them.
     */
    char ckpt_arg[16], arena_arg[16], flags_arg[24], ctid_arg[24], tls_arg[24];
    snprintf(ckpt_arg, sizeof ckpt_arg, "%d", ckpt_fd);
    snprintf(arena_arg, sizeof arena_arg, "%d", snap_fd);
    snprintf(flags_arg, sizeof flags_arg, "%lu", clone_flags);
    snprintf(ctid_arg, sizeof ctid_arg, "%llu", (unsigned long long) child_tid);
    snprintf(tls_arg, sizeof tls_arg, "%llu", (unsigned long long) tls);
    char *argv[] = { self, (char *) "--resume", ckpt_arg, arena_arg,
                     flags_arg, ctid_arg, tls_arg, NULL };
    execv(self, argv);
    /* Only here if exec failed; the guest state is intact in the parent, so the
     * only honest thing this child can do is disappear. */
    _exit(127);
  }

  close(ckpt_fd);
  close(snap_fd);

  if (clone_flags & LINUX_CLONE_PARENT_SETTID) {
    if (copy_to_user(parent_tid, &ret, sizeof ret))
      return -LINUX_EFAULT;
  }
  return ret;
}
/*
 * Apply the clone semantics in a resumed child.
 *
 * The equivalent of what init_task does for a plain fork's child, minus the
 * signal mask: init_task empties it, but a resumed child has the parent's mask
 * restored from the checkpoint, which is what fork actually owes it.
 */
void
resume_apply_clone(unsigned long clone_flags, gaddr_t child_tid, gaddr_t tls)
{
  task.tid = getpid();

  task.set_child_tid = task.clear_child_tid = 0;
  if (clone_flags & LINUX_CLONE_CHILD_SETTID)
    task.set_child_tid = child_tid;
  if (clone_flags & LINUX_CLONE_CHILD_CLEARTID)
    task.clear_child_tid = child_tid;

  if (task.set_child_tid != 0) {
    int tid = do_gettid();
    if (copy_to_user(task.set_child_tid, &tid, sizeof tid))
      warnk("resume: could not write the child tid\n");
  }

  if (clone_flags & LINUX_CLONE_SETTLS)
    vmm_set_tls(tls);
}
#endif /* __arm64__ */

int
__do_clone_process(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
#if defined(__arm64__)
  /*
   * fork+exec is how fork works here. The path below - destroy the VM, fork,
   * rebuild it on both sides - is what x86 does and what arm64 used to do, and
   * on Apple Silicon it loses about one child in eight to a crash inside the
   * framework (spike/arm64-fork/). Measured on the same forty runs: forktest
   * 3/40 failures against 0/40, clonetid 7/40 against 0/40.
   *
   * NABI_FORK_EXEC=0 selects the old path anyway. It is kept for bisecting a
   * suspected handover bug, not because it is a supported way to run.
   */
  {
    const char *v = getenv("NABI_FORK_EXEC");
    if (!(v && *v == '0'))
      return clone_process_by_exec(clone_flags, parent_tid, child_tid, tls);
  }
#endif

  // Because Apple Hypervisor Framwork won't let us use multiple VMs,
  // we destroy the current vm and restore it later
  struct vmm_snapshot snapshot;
  vmm_snapshot(&snapshot);
  vmm_destroy();

  int ret = syswrap(fork());

  vmm_reentry(&snapshot);

  if (ret < 0) {
    return ret;
  }

  if (ret == 0) {
    /* NB: we don't yet support multi-threaded execve so comment out the following: */
    /* proc.nr_tasks = 1; */
    /* INIT_LIST_HEAD(&proc.tasks); */
    /* list_add(&task.head, &proc.tasks); */
    init_task(clone_flags, child_tid, tls);
  } else {
    if (clone_flags & LINUX_CLONE_PARENT_SETTID) {
      if (copy_to_user(parent_tid, &ret, sizeof ret)) {
        return -LINUX_EFAULT;
      }
    }
  }

  return ret;
}

struct clone_thread_arg {
  unsigned long clone_flags;
  unsigned long newsp;
  gaddr_t parent_tid;
  gaddr_t child_tid;
  gaddr_t tls;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  struct vcpu_snapshot vcpu_snapshot;
};

static void*
__start_thread(struct clone_thread_arg *arg)
{
  pthread_mutex_lock(&arg->mutex);

  printk("__start_thread\n");

  vmm_create_vcpu(&arg->vcpu_snapshot);
  /* The child returns 0 from clone, on the new stack, at the instruction after
   * the clone syscall. vmm_syscall_return does the same PC advance the main
   * loop applies to the parent - rip+2 on x86, nothing on aarch64 where the
   * snapshot's PC is already past the svc. */
  vmm_set_reg(VREG_RET, 0);
  vmm_set_reg(VREG_SP, arg->newsp);
  vmm_syscall_return();

  pthread_rwlock_wrlock(&proc.lock);
  proc.nr_tasks++;
  list_add(&task.head, &proc.tasks);
  pthread_rwlock_unlock(&proc.lock);

  INIT_SIGBIT(&task.sigpending);

  init_task(arg->clone_flags, arg->child_tid, arg->tls);

  if (arg->clone_flags & LINUX_CLONE_PARENT_SETTID) {
    if (copy_to_user(arg->parent_tid, &task.tid, sizeof task.tid)) {
      assert(false);
    }
  }

  pthread_cond_signal(&arg->cond);

  pthread_mutex_unlock(&arg->mutex);

  main_loop(0);

  return NULL; // hv_vcpu_run failed for some reason
}

int
__do_clone_thread(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  printk("clone_thread\n");
  uint64_t tid;
  pthread_t threadid;

  struct clone_thread_arg *arg = malloc(sizeof *arg);
  *arg = (struct clone_thread_arg){
    .clone_flags = clone_flags,
    .newsp = newsp,
    .parent_tid = parent_tid,
    .child_tid = child_tid,
    .tls = tls,
    .cond = PTHREAD_COND_INITIALIZER,
    .mutex =PTHREAD_MUTEX_INITIALIZER
  };
  vmm_snapshot_vcpu(&arg->vcpu_snapshot);
  pthread_mutex_lock(&arg->mutex);
  pthread_create(&threadid, NULL, (void *)__start_thread, arg);
  pthread_cond_wait(&arg->cond, &arg->mutex);
  pthread_mutex_unlock(&arg->mutex);
  pthread_cond_destroy(&arg->cond);
  pthread_mutex_destroy(&arg->mutex);
  free(arg);

  pthread_threadid_np(threadid, &tid);

  return tid;
}

int
do_clone(unsigned long clone_flags, unsigned long newsp, gaddr_t parent_tid, gaddr_t child_tid, gaddr_t tls)
{
  int sigtype = clone_flags & 0xff;
  assert(sigtype == LINUX_SIGCHLD || sigtype == 0);

  clone_flags &= -0x100;
  unsigned long implemented = LINUX_CLONE_THREAD | LINUX_CLONE_DETACHED | LINUX_CLONE_SETTLS | LINUX_CLONE_CHILD_SETTID | LINUX_CLONE_CHILD_CLEARTID | LINUX_CLONE_PARENT_SETTID;
  unsigned long needed = 0;
  if (clone_flags & LINUX_CLONE_THREAD) {
    int needed = LINUX_CLONE_VM | LINUX_CLONE_FS | LINUX_CLONE_FILES | LINUX_CLONE_SIGHAND | LINUX_CLONE_SYSVSEM;
    implemented |= needed;
  }
  /*
   * vfork is served by an ordinary fork.
   *
   * It asks for two things NABI cannot give: the child sharing the parent's
   * address space, and the parent suspended until the child execs or exits.
   * Sharing is out of reach because a child here is a separate process rebuilt
   * from a checkpoint, and suspending the parent on *exec* has nothing to hang
   * the resumption off. What a copy costs is only visible to a child that
   * writes something the parent then reads, which vfork has never promised -
   * POSIX makes it undefined - and which the callers that matter do not do:
   * dash, and every shell like it, vforks only to exec or _exit immediately.
   *
   * Refusing it instead is what breaks. dash uses vfork for every command it
   * runs, so `sh -c` inside a guest failed with "Cannot fork", and apt - which
   * shells out for dpkg-preconfigure and the maintainer scripts - could not
   * install anything. The flag went unimplemented because forktest and every
   * other test forks the plain way.
   */
  if (clone_flags & LINUX_CLONE_VFORK)
    implemented |= LINUX_CLONE_VFORK | LINUX_CLONE_VM;
  if ((clone_flags & ~implemented) || (clone_flags & needed) != needed) {
    FORKERR("unsupported clone_flags: %lx (implemented %lx)", clone_flags, implemented);
    return -LINUX_EINVAL;
  }


  if (clone_flags & LINUX_CLONE_THREAD) {
    return __do_clone_thread(clone_flags, newsp, parent_tid, child_tid, tls);
  } else {
    return __do_clone_process(clone_flags, newsp, parent_tid, child_tid, tls);
  }
}

DEFINE_SYSCALL(clone, unsigned long, clone_flags, unsigned long, newsp, gaddr_t, parent_tid, gaddr_t, arg4, gaddr_t, arg5)
{
  /*
   * A namespace flag applies to the *child*, and on arm64 a child is a fresh
   * process rebuilt from a checkpoint - so the new namespace has to exist
   * before the checkpoint is written, and the parent has to be put back
   * afterwards. Refused flags are refused here, before anything forks, so a
   * clone asking for a namespace that cannot be provided fails outright rather
   * than producing a child in the wrong one.
   */
  /*
   * CLONE_NEWTIME is not available here, and that is Linux's rule rather than a
   * limitation of ours: the flag is 0x80, which lands inside the exit-signal
   * byte that clone's low bits carry, so the two cannot be told apart. It is
   * reachable through unshare, which has no such byte.
   */
  if (clone_flags & LINUX_CLONE_NEWTIME)
    return -LINUX_EINVAL;

  if (clone_flags & (LINUX_CLONE_NEWNS | LINUX_CLONE_NEWUTS |
                     LINUX_CLONE_NEWIPC | LINUX_CLONE_NEWPID |
                     LINUX_CLONE_NEWNET | LINUX_CLONE_NEWUSER |
                     LINUX_CLONE_NEWCGROUP)) {
    int nsr = nsproxy_clone(clone_flags);
    if (nsr < 0)
      return nsr;
  }
  /*
   * The last two clone arguments are architecture-ordered. x86-64 is
   * (flags, stack, parent_tid, child_tid, tls); aarch64 (CONFIG_CLONE_BACKWARDS)
   * is (flags, stack, parent_tid, tls, child_tid) - child_tid and tls swapped.
   * do_clone and init_task want the x86-64 order, so normalize here. glibc's
   * fork() passes CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID with a real child_tid,
   * so getting this wrong writes the tid to the tls value (0) and misroutes the
   * tls - it is not only a threads concern.
   */
#if defined(__aarch64__)
  gaddr_t tls = arg4, child_tid = arg5;
#else
  gaddr_t child_tid = arg4, tls = arg5;
#endif
  return do_clone(clone_flags, newsp, parent_tid, child_tid, tls);
}

DEFINE_SYSCALL(fork)
{
  return do_clone(LINUX_SIGCHLD, 0, 0, 0, 0);
}

DEFINE_SYSCALL(vfork)
{
  return do_clone(LINUX_SIGCHLD, 0, 0, 0, 0);
}
