#ifndef NOAH_H
#define NOAH_H

#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include "types.h"
#include "util/misc.h"
#include "util/list.h"
#include "util/khash.h"
#include "linux/mman.h"
#include "malloc.h"
#include <stdnoreturn.h>

#define __page_aligned __attribute__((aligned(0x1000)))

/* privilege management */

void drop_privilege(void);

/* interface to user memory */

void *guest_to_host(gaddr_t);

#define VERIFY_READ  LINUX_PROT_READ
#define VERIFY_WRITE LINUX_PROT_WRITE
#define VERIFY_EXEC  LINUX_PROT_EXEC
bool addr_ok(gaddr_t, int verify);

size_t copy_from_user(void *haddr, gaddr_t gaddr, size_t n); /* returns 0 on success */
ssize_t strncpy_from_user(void *haddr, gaddr_t gaddr, size_t n);
size_t copy_to_user(gaddr_t gaddr, const void *haddr, size_t n);
ssize_t strnlen_user(gaddr_t gaddr, size_t n);

/* linux emulation */

uint64_t do_gettid(void);
int do_exec(const char *elf_path, int argc, char *argv[], char **envp);
int do_faccessat(int l_dirfd, const char *l_path, int l_mode, int l_flags);
int do_access(const char *path, int l_mode);
int do_futex_wake(gaddr_t uaddr, int count);
int user_open(const char *path, int flags, int mode);
int vkern_open(const char *path, int flags, int mode);
int user_openat(int fd, const char *path, int flags, int mode);
int vkern_openat(int fd, const char *path, int flags, int mode);
int user_close(int fd);
int vkern_close(int fd);
void close_cloexec();
void fdtable_clear_host_cloexec(void);
int register_fd(int fd, bool is_cloexec);
int vkern_dup_fd(int fd, bool is_cloexec);
gaddr_t alloc_region(size_t len);

noreturn void die_with_forcedsig(int sig);
void main_loop(int return_on_sigret);

/* Per-architecture guest-machine bring-up, defined in main_x86.c / main_arm64.c.
 * init_vkernel_machine sets up the vCPU control state (VMCS + segments on x86,
 * page tables + EL1 trampoline on arm64); vmm_start_guest turns translation on
 * and enters the guest where that differs by architecture (a no-op on x86). */
void init_vkernel_machine(void);
void vmm_start_guest(void);

/* signal */

#include "linux/signal.h"

typedef atomic_uint_least64_t atomic_sigbits_t;

#define INIT_SIGBIT(sigbit) (*(sigbit) = ATOMIC_VAR_INIT(0))
void handle_signal(void);
bool has_sigpending(void);
bool sigrestart_wanted(void);
int send_signal(pid_t pid, int sig);

/* The architecture-specific half of signal delivery, in signal_x86.c /
 * signal_arm64.c. The signal frame is entirely arch-shaped: the x86 sigcontext
 * is 16 named GPRs plus segments and uses SA_RESTORER; the aarch64 one is
 * regs[31]/sp/pc/pstate with an fpsimd chain and a vDSO-style sigreturn
 * trampoline. arch_setup_sigframe builds the frame and points the vCPU at the
 * handler; arch_rt_sigreturn restores from it. */
/* Neutral sigaltstack helpers, shared with the arch signal-frame code. */
void reset_sas(void);
l_int sas_ss_flags(uint64_t rsp);

int arch_setup_sigframe(int signum);
uint64_t arch_rt_sigreturn(void);
void arch_setup_sigreturn(void);  /* arm64: map the sigreturn trampoline at init */

/* task related data */

struct task {
  struct list_head head;
  gaddr_t set_child_tid, clear_child_tid;
  uint64_t tid;
  gaddr_t robust_list;
  l_sigset_t sigmask;
  atomic_sigbits_t sigpending;
  l_stack_t sas;
};

struct fdtable {
  int start; // First fd number of this table
  int size;  // Current table size expressed in number of bits
  struct file **files;
  uint64_t *open_fds;
  uint64_t *cloexec_fds;
};

struct fileinfo {
  int rootfd;                      // FS root
  struct fdtable fdtable;          // File descriptors for the user space
  struct fdtable vkern_fdtable;    // File descriptors for the kernel space
  pthread_rwlock_t fdtable_lock;
};

// We manage uid and suid independently on Darwin since we cannot change those of Darwin's freely.
// Wa always hold 0 in Darwin's suid to emulate Linux suid behavior (Note: in the case where Noah has setuid bit).
/*
 * The guest's credentials, which are emulated rather than the host's.
 *
 * NABI runs as an ordinary account and owns the rootfs it serves. A distro
 * image, though, expects to be root: apt writes /var/lib/dpkg, dpkg chowns what
 * it unpacks, and sudo refuses to run unless the world is root-owned. Trying to
 * make Darwin agree - the old model, which called setruid/seteuid to mirror
 * every guest change onto the host process - cannot work without being setuid
 * root, and the paths it could not express were outright panics.
 *
 * So the guest is root and nothing here touches the host process. The account
 * NABI runs as maps to uid 0 and back, exactly as a rootless container maps a
 * single host id into the guest's root; every file access still happens as the
 * real account, which owns everything it needs to.
 *
 * What this does not do is grant privilege. A guest that becomes root can write
 * its own rootfs because the account behind it always could. It cannot touch
 * anything on the host that the account could not, and the kernel is the only
 * thing enforcing that - which is the correct place for it, and unchanged.
 */
struct cred {
  pthread_rwlock_t lock;
  l_uid_t uid;
  l_uid_t euid;
  l_uid_t suid;
  l_gid_t gid;
  l_gid_t egid;
  l_gid_t sgid;
};

/* The host account the guest sees as root, and the mapping in both directions.
 * Anything that is not that account keeps the id it really has. */
extern uid_t nabi_host_uid;
extern gid_t nabi_host_gid;
l_uid_t host_uid_to_guest(uid_t u);
l_gid_t host_gid_to_guest(gid_t g);
uid_t   guest_uid_to_host(l_uid_t u);
gid_t   guest_gid_to_host(l_gid_t g);

/* for private futex */
struct pfutex_entry {
  struct list_head head;
  pthread_cond_t cond;
  gaddr_t uaddr;
  uint32_t bitset;
};

/* TODO: collect garbage entries */
KHASH_MAP_INIT_INT64(pfutex, struct list_head *)

struct proc {
  int nr_tasks;
  struct list_head tasks;
  pthread_rwlock_t lock;
  struct cred cred;
  struct mm *mm;
  struct {
    pthread_rwlock_t sig_lock;
    l_sigaction_t sigaction[LINUX_NSIG];
  };
  struct {
    pthread_mutex_t futex_mutex;
    khash_t(pfutex) *pfutex; /* TODO: modify khash and make this field being non-pointer */
  };
  struct fileinfo fileinfo;

  /*
   * What the guest is running, as /proc has to report it.
   *
   * Kept rather than re-derived because only NABI knows it: from outside, this
   * process is a `nabi`, and its own argv and executable are the emulator's.
   * Travels in the checkpoint, since arm64's fork is fork + exec and a child is
   * a fresh nabi that never saw the original execve. See src/fs/procfs.c.
   */
  struct {
    char  *exe;          /* guest path of the running binary */
    char  *cmdline;      /* argv flattened, each entry NUL-terminated */
    size_t cmdline_len;
  } ident;
};

extern struct proc proc;
_Thread_local extern struct task task;

void init_signal(void);
void reinstall_host_sigactions(void);
void reset_signal_state(void);

/* execve must be the only thread left; see src/proc/process.c. */
bool stop_other_tasks(void);
bool task_should_stop(void);
noreturn void task_stop_self(void);
void init_fileinfo(int rootfd);
void init_host_passthrough(void);
void report_host_passthrough(void);
void report_rootfs_case(void);
void init_host_ids(void);
bool guest_in_group(l_gid_t gid);
int  guest_groups_get(l_gid_t *out);
const l_gid_t *guest_groups_ptr(void);
void guest_groups_set(const l_gid_t *g, int n);
void elevate_privilege(uid_t owner_uid, gid_t owner_gid, mode_t mode);
void guest_view_of_fd(int fd, uint32_t *uid, uint32_t *gid, uint32_t *mode);
int vkern_open_exec(const char *path);
int procfs_open(const char *path, int *out_fd);
void procfs_close_fd(int fd);
int procfs_fd_number(const char *path);
enum ns_type;
bool procfs_ns_of_fd(int fd, enum ns_type *type, uint64_t *ino);
bool procfs_stat(const char *path, uint32_t *mode, uint64_t *size, uint64_t *ino);
bool procfs_refresh_fddir(int fd);
int fdtable_open_fds(int *out, int max);
int guest_to_host_path(const char *name, char *out, size_t outsz);
int procfs_readlink(const char *path, char *buf, size_t bufsize);
void proc_set_ident(const char *exe, int argc, char *argv[]);

void init_fpu(void);

/* Linux kernel constants */

#define LINUX_RELEASE "4.6.4"
#define LINUX_VERSION "#1 SMP PREEMPT Mon Jul 11 19:12:32 CEST 2016" /* FIXME */

#define LINUX_PATH_MAX 4096         /* including null */

/* conversion */

struct stat;
struct l_newstat;
struct statfs;
struct termios;
struct linux_termios;
struct l_statfs;
struct winsize;
struct linux_winsize;
struct rlimit; struct l_rlimit;

int linux_to_darwin_at_flags(int flags);
int linux_to_darwin_o_flags(int l_flags);
int darwin_to_linux_o_flags(int r);
void stat_darwin_to_linux(struct stat *stat, struct l_newstat *lstat);
void statfs_darwin_to_linux(struct statfs *statfs, struct l_statfs *l_statfs);
void darwin_to_linux_termios(struct termios *bios, struct linux_termios *lios);
void linux_to_darwin_termios(struct linux_termios *lios, struct termios *bios);
void darwin_to_linux_winsize(struct winsize *ws, struct linux_winsize *lws);
void linux_to_darwin_winsize(struct winsize *ws, struct linux_winsize *lws);
int linux_to_darwin_signal(int signum);
int darwin_to_linux_signal(int signum);
void darwin_to_linux_rlimit(int resource, struct rlimit *darwin_rlimit, struct l_rlimit *linux_rlimit);
void darwin_to_linux_rlimit_nofile(struct rlimit *darwin_rlimit, struct l_rlimit *linux_rlimit);
void linux_to_darwin_rlimit_nofile(struct l_rlimit *linux_rlimit, struct rlimit *darwin_rlimit);
int  vkern_fd_floor(void);


/* debug */

#include "debug.h"

#endif
