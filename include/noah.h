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
/* The host thread mask a guest mask implies; see src/ipc/signal.c. */
void host_sigmask_of(const l_sigset_t *lmask, sigset_t *out);
/* The guest started as somebody who never had capabilities. */
void cap_start_unprivileged(void);
bool sigrestart_wanted(void);
int send_signal(pid_t pid, int sig);
void signalfd_note_signal(int lsig);
void signalfd_sender(int lsig, uint32_t *host_pid, uint32_t *host_uid);

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
  /*
   * The ids the *filesystem* checks use, which are the effective ones until
   * setfsuid says otherwise. Linux keeps them in step with euid/egid on every
   * other credential change, so a program that never calls setfsuid cannot tell
   * they exist - which is why routing cred_may through them changes nothing
   * except for the programs that ask.
   */
  l_uid_t fsuid;
  l_gid_t fsgid;
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
  /*
   * futex_waitv waits on several futexes at once and must be woken by whichever
   * fires first, so its entries - one per futex, on one list each - share a
   * single condition variable and record which of them it was. An ordinary
   * waiter points condp at its own cond and leaves the rest alone.
   */
  pthread_cond_t *condp;
  int  index;
  int *woken;
};

/* TODO: collect garbage entries */
KHASH_MAP_INIT_INT64(pfutex, struct list_head *)

/*
 * The securebits Linux keeps per process. Each rule has a bit and a lock bit
 * one above it; the locks are the odd-numbered ones.
 */
#define SECBIT_NOROOT              0x01
#define SECBIT_NO_SETUID_FIXUP     0x04
#define SECBIT_KEEP_CAPS           0x10
#define SECBIT_NO_CAP_AMBIENT_RAISE 0x40
#define SECUREBITS_BITS  0x55          /* the four rules: bits 0, 2, 4, 6 */
#define SECUREBITS_LOCKS 0xaa          /* each one's lock, the bit above it */
#define SECUREBITS_KNOWN (SECUREBITS_BITS | SECUREBITS_LOCKS)

struct proc {
  int nr_tasks;
  struct list_head tasks;
  pthread_rwlock_t lock;
  struct cred cred;
  /* The securebits this process asked for; see prctl in src/proc/process.c. */
  uint32_t securebits;
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
/* The per-process state neither startup path may skip; see fs.c. Anything new
 * of that kind goes in there, not beside a call to it. */
/* Binder, served by nabi rather than by a kernel extension. */
void binder_emul_init(void);
void binder_emul_publish(void);
bool binder_emulated(void);
int  binder_emul_open(const char *ctx, int flags, int *out_fd);
void binder_emul_close(int fd);
bool binder_emul_is(int fd);
int  binder_emul_ioctl(int fd, int cmd, uint64_t arg);
int  binder_emul_mmap(int fd, uint64_t addr, uint64_t size);

/* /dev/kmsg, served by nabi because there is no kernel here to keep a log. */
void kmsg_init(void);
int  kmsg_open(const char *name, int flags, int *out_fd);
void kmsg_close(int fd);
bool kmsg_is(int fd);
bool kmsg_write(int fd, const char *buf, size_t size, int *ret);
bool kmsg_read(int fd, char *buf, size_t size, int *ret);
bool kmsg_lseek(int fd, off_t offset, int whence, int *ret);

void reinit_process_tables(void);
void init_fileinfo(int rootfd);
void signalfds_init(void);
void init_host_passthrough(void);
void report_host_passthrough(void);
void report_rootfs_case(void);
void init_host_ids(void);
bool guest_in_group(l_gid_t gid);
void clear_sighand(void);

/* The guest's root, which pivot_root and chroot change; see src/fs/fs.c. */
int  fs_root_open(const char *hostdir);
void fs_root_commit(int vfd);
bool fs_root_host_path(char *out, size_t outsz);
bool mount_pivot(const char *new_root, const char *put_old_after,
                 const char *old_root_host);

/* seccomp; see src/proc/seccomp.c. */
bool   seccomp_check(uint64_t nr, const uint64_t *args, uint64_t *ret);
int    seccomp_prctl_set(unsigned long mode, gaddr_t prog);
int    seccomp_mode_get(void);
int    seccomp_no_new_privs_get(void);
int    seccomp_no_new_privs_set(void);
size_t seccomp_snapshot_size(void);
int    seccomp_snapshot(void *buf, size_t len, int *mode_out);
void   seccomp_restore(const void *buf, size_t len, int mode);
int  guest_groups_get(l_gid_t *out);
const l_gid_t *guest_groups_ptr(void);
void guest_groups_set(const l_gid_t *g, int n);
void elevate_privilege(uid_t owner_uid, gid_t owner_gid, mode_t mode);
void guest_view_of_fd(int fd, uint32_t *uid, uint32_t *gid, uint32_t *mode);
void guest_owner_stamp_new(int dirfd, const char *path);

/* The guest credentials a process publishes so its socket peers can name it.
 * See src/proc/credtab.c. */
void cred_publish(uint32_t uid, uint32_t gid);
bool cred_of_host_pid(int32_t pid, uint32_t *uid, uint32_t *gid);

/* Netlink, which has no host counterpart and is served here. See
 * src/net/netlink.c. */
int  netlink_socket(int type, int protocol, int flags);
bool netlink_is(int fd);
void netlink_close(int fd);
int  netlink_send(int fd, const void *buf, size_t len);
int  netlink_bind(int fd, const void *addr, size_t addrlen);
int  netlink_getsockname(int fd, void *addr, size_t *addrlen);

/* Mounting a filesystem image by delegating to the host. See
 * src/fs/diskimage.c. */
bool image_is_ext(const char *host_path);
int  image_mount_ro(const char *host_path, char *dev, size_t devsz,
                    char *dir, size_t dirsz);
bool image_unmount(const char *dev, const char *dir);

/* Loop devices, which have nothing behind them but a name for a backing file.
 * See src/fs/loop.c. */
bool loop_path_index(const char *path, int *idx);
bool loop_stat(const char *path, uint32_t *mode, uint64_t *rdev, uint64_t *ino);
int  loop_open(const char *path, int *out_fd);
bool loop_is(int fd);
void loop_close(int fd);
int  loop_ioctl(int fd, int cmd, uint64_t arg);
bool loop_backing(const char *path, char *out, size_t outsz);
bool mount_is_context_fd(int fd);

/* The doorbell that carries real-time signals between processes. See
 * src/ipc/signal.c. */
void rtsig_init(void);

/* Abstract unix sockets, which are files here. See src/net/net.c. */
void abstract_close(int fd);
void seqpacket_close(int fd);
bool signalfd_wants(int lsig);
void signalfd_arm(int lsig);
int seqpacket_eof(int fd, int ret);
bool seqpacket_gone(int fd, int *ret);

/* PR_SET_PDEATHSIG, forgotten in a child as Linux forgets it. */
void pdeathsig_clear(void);

/* The guest path a descriptor names, when it has one. */
bool guest_path_of_fd(int fd, char *out, size_t outsz);
bool guest_path_of_host(const char *host, char *out, size_t outsz);
int vkern_open_exec(const char *path);
int procfs_open(const char *path, int *out_fd);
void procfs_close_fd(int fd);
int procfs_fd_number(const char *path);
enum ns_type;
bool procfs_ns_of_fd(int fd, enum ns_type *type, uint64_t *ino);
bool procfs_write_timens(int fd, const char *buf, size_t size, int *out);
void procfs_dup_fd(int oldfd, int newfd);

/* inotify (src/fs/inotify.c). The opens and closes are the guest's own: kqueue
 * cannot see them, so they are taken where nabi already knows. */
bool inotify_watching(void);
void inotify_note_open(const char *hostpath, bool isdir);
void inotify_note_close(const char *hostpath, bool written);
void inotify_close(int fd);

/* fanotify (src/fs/fanotify.c). Unlike inotify's, these events are what the
 * guest's own syscalls did, seen where nabi makes them. */
bool fanotify_watching(void);
void fanotify_note(const char *hostpath, uint64_t mask);
void fanotify_note_fd(int hostfd, uint64_t mask);
bool fanotify_read(int fd, char *out, size_t size, int *ret);
bool fanotify_write(int fd, const char *buf, size_t size, int *ret);
bool fanotify_permit(const char *hostpath, uint64_t mask);
void fanotify_close(int fd);

/* timerfd (src/sys/timer.c). read(2) on one answers with the number of
 * expirations rather than with what is in the pipe underneath. */
bool timerfd_read(int fd, char *out, size_t size, int *ret);
void timerfd_close(int fd);

/* userfaultfd (src/fs/userfaultfd.c).  On-demand page resolution for
 * PROT_NONE regions — a faulting thread blocks until a resolver feeds the
 * page through UFFDIO_COPY. */
bool userfaultfd_is(int fd);
void userfaultfd_close(int fd);

/* tee (src/fs/tee.c). What tee removed from a pipe is held in front of it, so
 * reads and readiness have to consult it before the pipe itself. */
/*
 * Syscall bodies reached from somewhere other than the dispatch table.
 *
 * io_uring's opcodes are the same operations as the syscalls of those names, so
 * they are answered by the same functions rather than by a second copy that
 * could drift from the first. DEFINE_SYSCALL generates sys_<name>; declaring the
 * few that are needed here keeps that a deliberate list rather than a header of
 * everything.
 */
uint64_t sys_statx(int dirfd, gstr_t path_ptr, int flags, unsigned int mask,
                   gaddr_t stx_ptr);
uint64_t sys_unlinkat(int dirfd, gstr_t path_ptr, int flags);
uint64_t sys_mkdirat(int dirfd, gstr_t path_ptr, int mode);
uint64_t sys_openat2(int dirfd, gstr_t path_ptr, gaddr_t how_ptr, size_t size);
uint64_t sys_sendto(int socket, gaddr_t buf_ptr, int length, int flags,
                    gaddr_t addr_ptr, unsigned int addrlen);
uint64_t sys_recvfrom(int socket, gaddr_t buf_ptr, int length, int flags,
                      gaddr_t addr_ptr, gaddr_t addrlen_ptr);

int     do_close(struct fdtable *table, int fd);
void    uring_close(int fd);
void    epoll_close(int epfd);
int     epoll_registered_fds(int epfd, int *out, int max);
/* Whether a descriptor is a binder device, which needs its read filter
 * registered with a NOTE_LOWAT of one (src/fs/fs.c). */
bool    binder_fd(int fd);
/* The BINDER_TYPE_FD broker (src/fs/binder_broker.c): a per-instance
 * rendezvous socket that moves a descriptor from the sender to the receiver,
 * because the driver can only stamp the sender's pid into the cookie. */
int     binder_broker_init(void);
int     binder_broker_register(uint32_t pid, uint32_t fd);
int     binder_broker_request(uint32_t pid, uint32_t fd);
/* pidfd (src/proc/pidfd.c). A pidfd is readable exactly when its process has
 * exited, which poll and select have to answer since Darwin has no descriptor
 * that does it. */
int     pidfd_host_pid(int fd);
int     pidfd_make(int32_t host, bool cloexec);
bool    pidfd_any(void);
bool    pidfd_is(int fd);
int     pidfd_fix_readset(int nfds, fd_set *out, const fd_set *want);
bool    pidfd_readable(int fd);
void    pidfd_close(int fd);

void    eventfd_signal(int fd, uint64_t add);

bool    tee_pending(void);
ssize_t tee_take(int fd, char *buf, size_t want);
bool    tee_readable(int fd);
bool    tee_any_readable(int nfds, const fd_set *want);
int     tee_mark_readable(int nfds, fd_set *out, const fd_set *want);
void    tee_sweep(void);
bool procfs_pidns_path(const char *name, char *out, size_t outsz, bool *denied);
bool procfs_exe_path(const char *name, char *out, size_t outsz);
bool procfs_stat(const char *path, bool nofollow, uint32_t *mode,
                 uint64_t *size, uint64_t *ino);
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
