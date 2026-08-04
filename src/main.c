#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <sys/syslimits.h>
#include <libgen.h>
#include <strings.h>
#include <fcntl.h>

#include "common.h"
#include "vmm.h"
#include "arch.h"
#include "mm.h"
#include "noah.h"
#include "syscall.h"
#if defined(__arm64__)
#include "checkpoint.h"
#endif
#include "linux/errno.h"
#include <sys/sysctl.h>
#include <sys/resource.h>

#include <mach-o/dyld.h>

#if defined(__arm64__)
#include "arm64/vm.h"
uint64_t pt_pte_of(gaddr_t);
/* Decode the stage-1 leaf for the address that just faulted, so a report says
 * whether the descriptor is absent, unreadable at EL0, read-only, or simply
 * missing its access flag - four different bugs that look identical from the
 * outside. */
static const char *
pte_note_for(gaddr_t va)
{
  static char buf[128];
  uint64_t pte = pt_pte_of(va & ~0xfffULL);
  if (pte == 0)
    return " pte=absent";
  snprintf(buf, sizeof buf,
           " pte=0x%llx [%s%s%s%s]", (unsigned long long) pte,
           (pte & PTE_VALID)     ? "valid "  : "INVALID ",
           (pte & PTE_AF)        ? "af "     : "NO-AF ",
           (pte & PTE_AP_RW_EL0) ? "el0 "    : "NO-EL0 ",
           (pte & PTE_AP_RO)     ? "ro"      : "rw");
  return buf;
}
#define pte_note() pte_note_for(exit.fault_addr)
#else
#define pte_note() ""
#endif


static int
handle_syscall(void)
{
  uint64_t nr;
  vmm_get_reg(VREG_SYSNR, &nr);
  if (nr >= NR_SYSCALLS) {
    warnk("unknown system call: %lld\n", nr);
    send_signal(getpid(), LINUX_SIGSYS);
  }
  uint64_t a0, a1, a2, a3, a4, a5;
  vmm_get_reg(VREG_ARG0, &a0);
  vmm_get_reg(VREG_ARG1, &a1);
  vmm_get_reg(VREG_ARG2, &a2);
  vmm_get_reg(VREG_ARG3, &a3);
  vmm_get_reg(VREG_ARG4, &a4);
  vmm_get_reg(VREG_ARG5, &a5);
  uint64_t retval = sc_handler_table[nr](a0, a1, a2, a3, a4, a5);
  vmm_set_reg(VREG_RET, retval);

  if (nr == LSYS_rt_sigreturn) {
    return -1;
  }
  return 0;
}
/*
 * Run the guest once, having first delivered anything pending.
 *
 * Returns 0 on a normal exit with *exit filled in, -1 if the vCPU could not be
 * entered.
 */
static int
task_run(struct vm_exit *exit)
{
  /* handle pending signals */
  if (has_sigpending()) {
    handle_signal();
  }
  return vmm_run(exit);
}

void
main_loop(int return_on_sigret)
{
  /* main_loop returns only if return_on_sigret == 1 && rt_sigreturn is invoked.
     see also: rt_sigsuspend */

  struct vm_exit exit;

  /* See the EXIT_MMU_FAULT case: a fault that keeps repeating at one address
   * is resolving nothing, and spinning on it is worse than dying. */
  gaddr_t last_fault_addr = ~(gaddr_t) 0;
  int same_fault_count = 0;
  enum { MAX_SAME_FAULTS = 16 };

  while (task_run(&exit) == 0) {

    /* dump_instr(); */
    /* print_regs(); */

    /*
     * Another thread is calling execve and needs to be the only one left. This
     * is the point at which a thread can stop safely: it is out of guest code
     * and between syscalls. (vmm_kick_other_vcpus is what got it here; a guest
     * loop with no syscalls in it would never arrive on its own.)
     */
    if (task_should_stop())
      task_stop_self();

    if (exit.kind != EXIT_MMU_FAULT)
      same_fault_count = 0;      /* anything else happening is progress */

    switch (exit.kind) {
    case EXIT_SYSCALL: {
      int r = handle_syscall();
      /* After the handler, never before: execve rewrites the program counter
       * and the advance has to apply to the new value. On aarch64 this is a
       * no-op - the CPU has already stepped past the svc. */
      vmm_syscall_return();
      if (return_on_sigret && r < 0) {
        return;
      }
      break;
    }

    case EXIT_MMU_FAULT:
      if (exit.fault_addr_valid) {
        int verify = 0;
        switch (exit.fault_access) {
        case VM_ACCESS_READ:    verify = VERIFY_READ;  break;
        case VM_ACCESS_WRITE:   verify = VERIFY_WRITE; break;
        case VM_ACCESS_EXEC:    verify = VERIFY_EXEC;  break;
        case VM_ACCESS_UNKNOWN: break;
        }
        if (!addr_ok(exit.fault_addr, verify)) {
          printk("page fault: caused by guest linear address 0x%llx\n",
                 exit.fault_addr);
          send_signal(getpid(), LINUX_SIGSEGV);
          break;
        }
        /*
         * addr_ok said the address is fine, so nothing was done about the
         * fault - and re-entering the guest faults on the same instruction
         * again. That is an infinite loop at full CPU with nothing printed:
         * the worst failure mode there is, and how a dpkg install presented,
         * as a parent blocked in wait4 on a child that would never exit.
         *
         * A repeat is not by itself wrong - a fault resolved elsewhere can be
         * retried - so what is fatal is repeating at the *same* address with
         * no other exit in between, which means nothing is being resolved.
         */
        if (exit.fault_addr == last_fault_addr) {
          if (++same_fault_count >= MAX_SAME_FAULTS) {
            printk("page fault: no progress at 0x%llx after %d attempts "
                   "(access %d); killing the guest rather than spinning\n",
                   exit.fault_addr, same_fault_count, exit.fault_access);
            warnk("unresolvable page fault at 0x%llx\n", exit.fault_addr);
            {
              static const char *acc[] = { "?", "read", "write", "exec" };
              struct mm_region *r = find_region(exit.fault_addr, proc.mm);
              fprintf(stderr,
                      "nabi: [pid %d] unresolvable page fault at 0x%llx on %s; "
                      "region %s prot=%d flags=%#x base=0x%llx size=0x%llx "
                      "esr=0x%llx%s\n",
                      getpid(), (unsigned long long) exit.fault_addr,
                      acc[exit.fault_access <= 3 ? exit.fault_access : 0],
                      r ? "found" : "MISSING", r ? r->prot : -1,
                      r ? r->mm_flags : 0,
                      (unsigned long long)(r ? r->gaddr : 0),
                      (unsigned long long)(r ? r->size : 0),
                      (unsigned long long) exit.raw_reason, pte_note());
            }
            send_signal(getpid(), LINUX_SIGSEGV);
          }
        } else {
          last_fault_addr = exit.fault_addr;
          same_fault_count = 1;
        }
      }
      break;

    case EXIT_FAULT:
      send_signal(getpid(), exit.signal);
      break;

    case EXIT_RESUME:
      /* Backend handled it, or there was nothing to handle. */
      break;

    case EXIT_UNHANDLED:
      /* The backend has already logged whatever it could work out. */
      break;
    }
  }

  __builtin_unreachable();
}

static void
init_first_proc(const char *root)
{
  proc = (struct proc) {
    .nr_tasks = 1,
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .mm = malloc(sizeof(struct mm)),
  };
  INIT_LIST_HEAD(&proc.tasks);
  list_add(&task.head, &proc.tasks);
  init_mm(proc.mm);
  init_signal();

  /*
   * Clamp RLIMIT_NOFILE to what the OS can actually give a process.
   *
   * init_fileinfo reserves the top 64 file descriptors - [rlim_cur-64,
   * rlim_cur) - for kernel objects, dup'ing the root directory to the first of
   * them. That assumes rlim_cur is a number the process can hold a descriptor
   * near. On modern macOS the soft limit is reported as 1048576, far above the
   * real per-process cap (kern.maxfilesperproc, 61440 here), so the reserved
   * descriptors land at ~1M and dup2 to them fails - the root fd comes back
   * invalid and every path lookup returns EBADF before the guest even loads.
   * (Older macOS, where this last ran on Intel, defaulted the soft limit to
   * ~256, so the reservation happened to fit.)
   *
   * SHRT_MAX+1 is the second ceiling, and the tighter one. A macOS FILE keeps
   * its descriptor in a short, so fdopen refuses anything above SHRT_MAX with
   * EMFILE - which is what the -o/-w/-s debug sinks do to a kernel descriptor.
   * Reserving [32704, 32768) puts the whole kernel range inside what stdio can
   * represent while still leaving the guest ~32k descriptors.
   */
  {
    struct rlimit rl;
    int maxfiles = 0;
    size_t sz = sizeof maxfiles;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
      rlim_t ceiling = (rlim_t) SHRT_MAX + 1;
      if (sysctlbyname("kern.maxfilesperproc", &maxfiles, &sz, NULL, 0) == 0 &&
          maxfiles > 0 && (rlim_t) maxfiles < ceiling) {
        ceiling = maxfiles;
      }
      if (rl.rlim_cur > ceiling) {
        rl.rlim_cur = ceiling;
        setrlimit(RLIMIT_NOFILE, &rl);
      }
    }
  }

  int rootfd = open(root, O_RDONLY | O_DIRECTORY);
  if (rootfd < 0) {
    perror("could not open initial root directory");
    exit(1);
  }
  init_fileinfo(rootfd);
  close(rootfd);
  proc.pfutex = kh_init(pfutex);
  pthread_mutex_init(&proc.futex_mutex, NULL);
  /* The account NABI runs as is the one the guest sees as root; remember it so
   * ids can be mapped both ways, and start the guest as root. */
  init_host_ids();
  proc.cred = (struct cred) {
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .uid = 0, .euid = 0, .suid = 0,
    .gid = 0, .egid = 0, .sgid = 0,
  };

  task.tid = getpid();
}

static void
init_vkernel(const char *root)
{
  init_mm(&vkern_mm);
  init_shm_malloc();
  /* All the arch-specific vCPU and guest-machine setup - VMCS controls and
   * segments on x86, page tables and the EL1 trampoline on arm64. */
  init_vkernel_machine();

  init_first_proc(root);
}

/*
 * The guest's privileges live in struct cred, so these move that and leave the
 * host process where it is.
 *
 * Both used to call seteuid on the host, which only did anything when nabi had
 * itself been installed setuid-root - and elevate_privilege *panicked* when it
 * had not, so any setuid binary in the guest killed the emulator outright.
 * That is backwards twice over: the host account is already the guest's root,
 * so there is nothing to raise; and a guest exec must never be able to take the
 * host process anywhere, least of all to uid 0.
 */
void
drop_privilege(void)
{
  /* Only meaningful for a setuid-root install, which is optional; otherwise
   * euid already equals uid. Reported rather than fatal either way. */
  if (geteuid() != getuid() && seteuid(getuid()) != 0)
    warnk("drop_privilege: seteuid(%d) failed: %s\n", getuid(), strerror(errno));
}

/*
 * A set-user-ID or set-group-ID image, applied to the guest's credentials.
 *
 * The ids are the file's owner as the guest sees it, not a hardcoded zero: a
 * binary owned by somebody other than root should elevate to somebody other
 * than root.
 *
 * They arrive already in the guest's terms, and that is the point. They used to
 * be a host stat's st_uid put through host_uid_to_guest, which was right only
 * while every file in the tree belonged to the one account nabi runs as. Once
 * ownership is recorded per file, a binary given away to a guest user still
 * stats as the host account, and mapping that would have elevated to root -
 * the opposite of what the file says.
 */
void
elevate_privilege(uid_t owner_uid, gid_t owner_gid, mode_t mode)
{
  pthread_rwlock_wrlock(&proc.cred.lock);
  if (mode & S_ISUID) {
    proc.cred.euid = owner_uid;
    proc.cred.suid = proc.cred.euid;
  }
  if (mode & S_ISGID) {
    proc.cred.egid = owner_gid;
    proc.cred.sgid = proc.cred.egid;
  }
  pthread_rwlock_unlock(&proc.cred.lock);
}

noreturn void
die_with_forcedsig(int sig)
{
  // TODO: Termination processing

  /* Force default signal action */
  int dsig = linux_to_darwin_signal(sig);
  sigset_t mask;
  sigfillset(&mask);
  sigdelset(&mask, dsig);
  sigprocmask(SIG_SETMASK, &mask, NULL);
  struct sigaction act;
  act.sa_handler = SIG_DFL;
  act.sa_flags = 0;
  sigaction(dsig, &act, NULL);
  raise(dsig);
  assert(false); // sig should be one that can terminate procs
}

void
check_platform_version(void)
{
  int32_t b;
  size_t len = sizeof b;

  if (sysctlbyname("kern.hv_support", &b, &len, NULL, 0) < 0) {
    perror("sysctl kern.hv_support");
  }
  if (b == 0) {
    fprintf(stderr, "Your cpu seems too old. Buy a new mac!\n");
    exit(1);
  }
}

enum {PRINTK_PATH, WARNK_PATH, STRACE_PATH, MAX_DEBUG_PATH};

/*
 * The debug sinks, carried across a fork.
 *
 * A fork on arm64 is a fork plus an exec of a fresh nabi, and that child parsed
 * no -s/-w/-o - so every forked guest ran with no trace and no warnings at all.
 * Since a shell forks for every command, that is nearly everything, and it has
 * sent more than one investigation down the wrong path: the visible evidence
 * came only from the one process that happened to be started directly.
 *
 * The paths travel in the environment rather than in argv, because the child is
 * exec'd with a fixed argument list that resume_main parses positionally, and
 * because an inherited environment is exactly the right lifetime for this.
 */
static const char *const debug_env[MAX_DEBUG_PATH] = {
  [PRINTK_PATH] = "NABI_PRINTK_PATH",
  [STRACE_PATH] = "NABI_STRACE_PATH",
  [WARNK_PATH]  = "NABI_WARNK_PATH",
};

static void
open_debug_sinks(char paths[][PATH_MAX])
{
  static void (* init_funcs[3])(const char *path) = {
    [PRINTK_PATH] = init_printk,
    [STRACE_PATH] = init_meta_strace,
    [WARNK_PATH]  = init_warnk
  };
  for (int i = PRINTK_PATH; i < MAX_DEBUG_PATH; i++) {
    if (paths[i][0] == '\0')
      continue;
    init_funcs[i](paths[i]);
    /* The base name is what travels, so grandchildren derive their own from
     * the same stem rather than from their parent's suffixed name. */
    if (getenv(debug_env[i]) == NULL)
      setenv(debug_env[i], paths[i], 1);
  }
}


#if defined(__arm64__)
/*
 * Come up as an already-running guest, handed over by another process.
 *
 * This is the far side of fork on Apple Silicon: the child could not create a
 * vCPU in the process fork gave it (spike/arm64-fork/), so it exec'd, and
 * everything it needs arrives through the two inherited descriptors - the arena
 * holding the guest's memory and a checkpoint describing everything else.
 *
 * NOT YET REACHED: nothing invokes this, because __do_clone_process still uses
 * the plain fork path. It is here so the switch is a change to fork alone.
 */
void resume_apply_clone(unsigned long clone_flags, gaddr_t child_tid, gaddr_t tls);

/* The other half: what a resumed child picks up. */
static void
open_inherited_debug_sinks(void)
{
  char paths[MAX_DEBUG_PATH][PATH_MAX];
  for (int i = PRINTK_PATH; i < MAX_DEBUG_PATH; i++) {
    const char *v = getenv(debug_env[i]);
    paths[i][0] = '\0';
    if (!v || !*v)
      continue;
    /*
     * One file per process, named for the pid.
     *
     * Sharing a single file looked tidier and was useless: several guests
     * writing a line at a time with no locking splice their output together,
     * and a spliced trace is worse than no trace because it reads as though
     * one process did both halves. The parent keeps the name it was given;
     * every forked child gets that name with its pid appended, so a run
     * leaves trace, trace.1234, trace.1235 and each is a whole story.
     */
    snprintf(paths[i], PATH_MAX, "%s.%d", v, getpid());
  }
  open_debug_sinks(paths);
}

static noreturn void
resume_main(int ckpt_fd, int arena_fd, unsigned long clone_flags,
            gaddr_t child_tid, gaddr_t tls)
{
  init_mm(&vkern_mm);
  init_shm_malloc();
  /* Same host process and the same account as the parent, but not carried in
   * the checkpoint - so it has to be asked for again rather than inherited.
   * Left unset, every host-to-guest id mapping becomes the identity. */
  init_host_ids();

  /*
   * Deliberately no init_signal(): it *imports* the host's dispositions and
   * mask into proc/task, which is right at first boot and wrong here - the
   * checkpoint already carries the guest's own. What does have to happen is the
   * other direction, once those are restored: exec reset every host disposition,
   * so the handlers that route a signal into the guest are re-installed below.
   */
  checkpoint_restore(ckpt_fd, arena_fd);
  /* After the restore, not before: the sinks take descriptors out of the vkern
   * table, and checkpoint_restore rebuilds that table wholesale. Opened first,
   * they are opened into a table that is about to be replaced. */
  open_inherited_debug_sinks();
  reinstall_host_sigactions();
  resume_apply_clone(clone_flags, child_tid, tls);

  main_loop(0);
  vmm_destroy();
  exit(0);
}
#endif /* __arm64__ */

int
main(int argc, char *argv[], char **envp)
{
  drop_privilege();

  check_platform_version();

#if defined(__arm64__)
  /* Handed over by another NABI: everything arrives through inherited
   * descriptors. x86 forks normally and has no such path. */
  if (argc >= 7 && strcmp(argv[1], "--resume") == 0)
    resume_main(atoi(argv[2]), atoi(argv[3]), strtoul(argv[4], NULL, 10),
                strtoull(argv[5], NULL, 10), strtoull(argv[6], NULL, 10));
#endif

  char root[PATH_MAX] = {};

  int c;
  char debug_paths[MAX_DEBUG_PATH][PATH_MAX] = {};
  struct option long_options[] = {
    { "output", required_argument, NULL, 'o'},
    { "strace", required_argument, NULL, 's'},
    { "warning", required_argument, NULL, 'w'},
    { "mnt", required_argument, NULL, 'm' },
    { "help", no_argument, NULL, 'h' },
    { 0, 0, 0, 0 }
  };

  while ((c = getopt_long(argc, argv, "+ho:w:s:m:", long_options, NULL)) != -1) {
    switch (c) {
    case 'o':
      strncpy(debug_paths[PRINTK_PATH], optarg, PATH_MAX);
      break;
    case 'w':
      strncpy(debug_paths[WARNK_PATH], optarg, PATH_MAX);
      break;
    case 's':
      strncpy(debug_paths[STRACE_PATH], optarg, PATH_MAX);
      break;
    case 'm':
      if (realpath(optarg, root) == NULL) {
        perror("Invalid --mnt flag: ");
        exit(1);
      }
      argv[optind - 1] = root;
      break;
    case 'h':
    default:
      printf("Usage: nabi -h | [-o output] [-w warning] [-s strace] -m /virtual/filesystem/root executable ...\n");
      exit(0);
    }
  }

  argc -= optind;
  argv += optind;

  if (argc == 0) {
    abort();
  }

  vmm_create();

  init_vkernel(root);

  open_debug_sinks(debug_paths);

  /*
   * Start the guest inside its own filesystem.
   *
   * Until now the process kept whatever directory nabi was launched from, and
   * that is a host directory with no name in the guest's namespace at all - a
   * guest's very first getcwd answered
   * "/Users/sunneva/Development/mSL-XNU/mSL-NABI". Nothing good follows from a
   * process whose working directory is outside its own root: relative paths
   * resolve somewhere the guest cannot see, and anything building an absolute
   * path from the cwd builds nonsense.
   *
   * After the debug sinks, because a relative -o/-w/-s is relative to where the
   * user typed it.
   */
  if (fchdir(proc.fileinfo.rootfd) < 0)
    warnk("could not start in the rootfs: %s\n", strerror(errno));

  /* Now that the sinks exist, say which sibling modules this run picked up. */
  report_host_passthrough();
  report_rootfs_case();

  int err;
  if ((err = do_exec(argv[0], argc, argv, envp)) < 0) {
    errno = linux_to_darwin_errno(-err);
    perror("Error");
    exit(1);
  }

  /* On arm64 this turns on stage-1 translation and drops the vCPU to EL0 at the
   * entry point do_exec set; on x86 the guest is already runnable and it does
   * nothing. Must come after do_exec (which maps the image and sets PC/SP) and
   * before the guest first runs. */
  vmm_start_guest();

  main_loop(0);

  vmm_destroy();

  return 0;
}
