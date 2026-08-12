/*
 * seccomp: filtering the guest's own system calls.
 *
 * This is implemented rather than refused, and the reason is the one Landlock
 * was refused for, arriving at the opposite answer. Both are hardening
 * primitives whose whole value is that they hold, and both are relied on the
 * moment they return 0. The question is whether the enforcement surface can be
 * enumerated. Landlock's is fifty path-taking syscalls spread across this tree.
 * seccomp's is one line - the dispatch in src/main.c - because nabi *is* the
 * system call interface, and there is no way into a handler that does not pass
 * through it. That is a stronger position than a real kernel is in.
 *
 * The filter language is classic BPF over struct seccomp_data, interpreted
 * here. Programs are checked when they are installed, as Linux's verifier does,
 * so a filter that would run off the end of itself is refused at
 * SECCOMP_SET_MODE_FILTER rather than misbehaving at some later syscall.
 *
 * Filters accumulate and are never removed - that is the design, not a
 * shortcut - and every one of them runs on every call, with the most severe
 * answer winning. They are inherited across fork, which here means they travel
 * in the checkpoint: a fork on arm64 is a fork plus an exec, so a child that
 * rebuilt itself without them would be running unfiltered while its parent
 * believed otherwise. That is the same trap mseal's seal had, and it is the one
 * failure mode of this feature that nothing in the guest could detect.
 *
 * What is not here is the two actions that need somebody else. USER_NOTIF wants
 * a supervisor holding a notification descriptor and TRACE wants a ptracer;
 * with neither attached Linux runs the syscall as if it returned ENOSYS, and
 * that is exactly what happens here. It is a real answer rather than a
 * pretence - the caller's filter said "ask the supervisor", there is no
 * supervisor, and ENOSYS is what Linux says in that case too.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "linux/common.h"
#include "linux/errno.h"
#include "linux/misc.h"

/* Operations. */
#define SECCOMP_SET_MODE_STRICT   0
#define SECCOMP_SET_MODE_FILTER   1
#define SECCOMP_GET_ACTION_AVAIL  2
#define SECCOMP_GET_NOTIF_SIZES   3

/* Flags to SECCOMP_SET_MODE_FILTER. */
#define SECCOMP_FILTER_FLAG_TSYNC          (1U << 0)
#define SECCOMP_FILTER_FLAG_LOG            (1U << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW     (1U << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER   (1U << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH    (1U << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1U << 5)

/* Actions, and the mask that selects one. */
#define SECCOMP_RET_KILL_PROCESS  0x80000000U
#define SECCOMP_RET_KILL_THREAD   0x00000000U
#define SECCOMP_RET_TRAP          0x00030000U
#define SECCOMP_RET_ERRNO         0x00050000U
#define SECCOMP_RET_USER_NOTIF    0x7fc00000U
#define SECCOMP_RET_TRACE         0x7ff00000U
#define SECCOMP_RET_LOG           0x7ffc0000U
#define SECCOMP_RET_ALLOW         0x7fff0000U
#define SECCOMP_RET_ACTION_FULL   0xffff0000U
#define SECCOMP_RET_DATA          0x0000ffffU

#define SECCOMP_MODE_DISABLED 0
#define SECCOMP_MODE_STRICT   1
#define SECCOMP_MODE_FILTER   2

/* The audit arch a filter compares against. A program built for one
 * architecture must not be silently accepted on another - that is the check
 * every real filter makes first, and getting it wrong would let an x86 filter
 * pass an aarch64 program. */
#if defined(__arm64__)
#define SECCOMP_AUDIT_ARCH 0xc00000b7U   /* AUDIT_ARCH_AARCH64 */
#else
#define SECCOMP_AUDIT_ARCH 0xc000003eU   /* AUDIT_ARCH_X86_64 */
#endif

#define BPF_MAXINSNS 4096

struct sock_filter {
  uint16_t code;
  uint8_t  jt;
  uint8_t  jf;
  uint32_t k;
};

struct l_sock_fprog {
  uint16_t len;
  uint16_t _pad[3];
  uint64_t filter;
};

struct seccomp_data {
  int32_t  nr;
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t args[6];
};

struct seccomp_filter {
  struct seccomp_filter *next;
  uint16_t len;
  struct sock_filter insns[];
};

static struct seccomp_filter *filters;   /* newest first */
static int seccomp_mode = SECCOMP_MODE_DISABLED;
static bool no_new_privs;
static pthread_mutex_t seccomp_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- classic BPF ---- */

#define BPF_CLASS(c) ((c) & 0x07)
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_RET   0x06
#define BPF_MISC  0x07

#define BPF_SIZE(c) ((c) & 0x18)
#define BPF_W  0x00
#define BPF_MODE(c) ((c) & 0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_MEM 0x60
#define BPF_LEN 0x80

#define BPF_OP(c) ((c) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR  0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0

#define BPF_JA   0x00
#define BPF_JEQ  0x10
#define BPF_JGT  0x20
#define BPF_JGE  0x30
#define BPF_JSET 0x40

#define BPF_SRC(c) ((c) & 0x08)
#define BPF_K 0x00
#define BPF_X 0x08

#define BPF_RVAL(c) ((c) & 0x18)
#define BPF_A 0x10

#define BPF_MEMWORDS 16

/*
 * Whether a program is one this can run, checked once at install time.
 *
 * The point is that nothing here can fail at evaluation: every jump lands
 * inside the program, every load is one of the forms below, and the last
 * instruction cannot fall off the end. Linux's verifier makes the same
 * promises, and a filter that does not satisfy them is refused with EINVAL
 * rather than accepted and then behaving unpredictably at some later syscall -
 * which for a security filter is the difference between a program that will not
 * start and one that is not confined.
 */
static bool
bpf_verify(const struct sock_filter *f, uint16_t len)
{
  if (len == 0 || len > BPF_MAXINSNS)
    return false;
  for (uint16_t pc = 0; pc < len; pc++) {
    uint16_t code = f[pc].code;
    switch (BPF_CLASS(code)) {
    case BPF_LD:
      if (BPF_SIZE(code) != BPF_W)
        return false;
      switch (BPF_MODE(code)) {
      case BPF_IMM: case BPF_LEN: break;
      case BPF_ABS:
        /* seccomp_data only, whole words only. */
        if ((f[pc].k & 3) || f[pc].k + 4 > sizeof(struct seccomp_data))
          return false;
        break;
      case BPF_MEM:
        if (f[pc].k >= BPF_MEMWORDS) return false;
        break;
      default: return false;
      }
      break;
    case BPF_LDX:
      if (BPF_SIZE(code) != BPF_W)
        return false;
      if (BPF_MODE(code) == BPF_MEM) {
        if (f[pc].k >= BPF_MEMWORDS) return false;
      } else if (BPF_MODE(code) != BPF_IMM && BPF_MODE(code) != BPF_LEN) {
        return false;
      }
      break;
    case BPF_ST: case BPF_STX:
      if (f[pc].k >= BPF_MEMWORDS) return false;
      break;
    case BPF_ALU:
      switch (BPF_OP(code)) {
      case BPF_ADD: case BPF_SUB: case BPF_MUL: case BPF_OR: case BPF_AND:
      case BPF_LSH: case BPF_RSH: case BPF_NEG: case BPF_XOR:
        break;
      case BPF_DIV: case BPF_MOD:
        /* A constant zero divisor cannot be caught at run time without a rule
         * for what it means, so it is refused here. */
        if (BPF_SRC(code) == BPF_K && f[pc].k == 0) return false;
        break;
      default: return false;
      }
      break;
    case BPF_JMP: {
      uint32_t off;
      switch (BPF_OP(code)) {
      case BPF_JA:
        off = f[pc].k;
        if (pc + 1 + off >= len || pc + 1 + off < pc) return false;
        break;
      case BPF_JEQ: case BPF_JGT: case BPF_JGE: case BPF_JSET:
        if (pc + 1 + f[pc].jt >= len || pc + 1 + f[pc].jf >= len) return false;
        break;
      default: return false;
      }
      break;
    }
    case BPF_RET:
      if (BPF_RVAL(code) != BPF_K && BPF_RVAL(code) != BPF_A) return false;
      break;
    case BPF_MISC:
      break;
    default:
      return false;
    }
  }
  /* Falling out of the bottom has no defined answer, so a program must end in
   * a return. */
  return BPF_CLASS(f[len - 1].code) == BPF_RET;
}

static uint32_t
bpf_run(const struct sock_filter *f, uint16_t len, const struct seccomp_data *d)
{
  uint32_t A = 0, X = 0, mem[BPF_MEMWORDS] = {0};
  const uint8_t *base = (const uint8_t *) d;

  for (uint16_t pc = 0; pc < len; pc++) {
    const struct sock_filter *i = &f[pc];
    uint32_t k = i->k;
    switch (BPF_CLASS(i->code)) {
    case BPF_LD:
      switch (BPF_MODE(i->code)) {
      case BPF_IMM: A = k; break;
      case BPF_LEN: A = (uint32_t) sizeof *d; break;
      case BPF_MEM: A = mem[k]; break;
      default:      memcpy(&A, base + k, 4); break;   /* ABS, verified above */
      }
      break;
    case BPF_LDX:
      switch (BPF_MODE(i->code)) {
      case BPF_IMM: X = k; break;
      case BPF_LEN: X = (uint32_t) sizeof *d; break;
      default:      X = mem[k]; break;
      }
      break;
    case BPF_ST:  mem[k] = A; break;
    case BPF_STX: mem[k] = X; break;
    case BPF_ALU: {
      uint32_t v = BPF_SRC(i->code) == BPF_X ? X : k;
      switch (BPF_OP(i->code)) {
      case BPF_ADD: A += v; break;
      case BPF_SUB: A -= v; break;
      case BPF_MUL: A *= v; break;
      case BPF_DIV: if (v == 0) return SECCOMP_RET_KILL_PROCESS; A /= v; break;
      case BPF_MOD: if (v == 0) return SECCOMP_RET_KILL_PROCESS; A %= v; break;
      case BPF_OR:  A |= v; break;
      case BPF_AND: A &= v; break;
      case BPF_LSH: A = v < 32 ? A << v : 0; break;
      case BPF_RSH: A = v < 32 ? A >> v : 0; break;
      case BPF_XOR: A ^= v; break;
      case BPF_NEG: A = (uint32_t) (-(int32_t) A); break;
      }
      break;
    }
    case BPF_JMP: {
      if (BPF_OP(i->code) == BPF_JA) { pc += k; break; }
      uint32_t v = BPF_SRC(i->code) == BPF_X ? X : k;
      bool t;
      switch (BPF_OP(i->code)) {
      case BPF_JEQ:  t = A == v; break;
      case BPF_JGT:  t = A > v; break;
      case BPF_JGE:  t = A >= v; break;
      default:       t = (A & v) != 0; break;   /* JSET */
      }
      pc += t ? i->jt : i->jf;
      break;
    }
    case BPF_RET:
      return BPF_RVAL(i->code) == BPF_A ? A : k;
    case BPF_MISC:
      if (i->code & 0x80) A = X; else X = A;    /* TXA : TAX */
      break;
    }
  }
  /* Unreachable: bpf_verify requires the last instruction to be a return. */
  return SECCOMP_RET_KILL_PROCESS;
}

/* ---- the filter chain ---- */

int
seccomp_no_new_privs_get(void)
{
  return no_new_privs ? 1 : 0;
}

int
seccomp_no_new_privs_set(void)
{
  no_new_privs = true;          /* one way, as on Linux */
  return 0;
}

int
seccomp_mode_get(void)
{
  return seccomp_mode;
}

static int
filter_install(gaddr_t prog_ptr)
{
  struct l_sock_fprog prog;
  if (copy_from_user(&prog, prog_ptr, sizeof prog))
    return -LINUX_EFAULT;
  if (prog.len == 0 || prog.len > BPF_MAXINSNS)
    return -LINUX_EINVAL;

  size_t bytes = (size_t) prog.len * sizeof(struct sock_filter);
  struct seccomp_filter *f = malloc(sizeof *f + bytes);
  if (f == NULL)
    return -LINUX_ENOMEM;
  if (copy_from_user(f->insns, (gaddr_t) prog.filter, bytes)) {
    free(f);
    return -LINUX_EFAULT;
  }
  if (!bpf_verify(f->insns, prog.len)) {
    free(f);
    return -LINUX_EINVAL;
  }
  f->len = prog.len;

  pthread_mutex_lock(&seccomp_lock);
  f->next = filters;
  filters = f;
  seccomp_mode = SECCOMP_MODE_FILTER;
  pthread_mutex_unlock(&seccomp_lock);
  return 0;
}

/*
 * The strict mode, which is a filter written here rather than a separate
 * mechanism - it is exactly "read, write, _exit and rt_sigreturn, kill
 * otherwise", and expressing it as a filter means one evaluator and one set of
 * actions rather than two.
 */
static int
strict_install(void)
{
  static const struct sock_filter prog[] = {
    { BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 },              /* A = nr */
    { BPF_JMP | BPF_JEQ | BPF_K, 4, 0, LSYS_read },
    { BPF_JMP | BPF_JEQ | BPF_K, 3, 0, LSYS_write },
    { BPF_JMP | BPF_JEQ | BPF_K, 2, 0, LSYS_exit },
    { BPF_JMP | BPF_JEQ | BPF_K, 1, 0, LSYS_rt_sigreturn },
    { BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS },
    { BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW },
  };
  size_t bytes = sizeof prog;
  struct seccomp_filter *f = malloc(sizeof *f + bytes);
  if (f == NULL)
    return -LINUX_ENOMEM;
  memcpy(f->insns, prog, bytes);
  f->len = (uint16_t) (bytes / sizeof prog[0]);

  pthread_mutex_lock(&seccomp_lock);
  f->next = filters;
  filters = f;
  seccomp_mode = SECCOMP_MODE_STRICT;
  pthread_mutex_unlock(&seccomp_lock);
  return 0;
}

static bool
action_is_available(uint32_t action)
{
  switch (action & SECCOMP_RET_ACTION_FULL) {
  case SECCOMP_RET_KILL_PROCESS:
  case SECCOMP_RET_KILL_THREAD:
  case SECCOMP_RET_TRAP:
  case SECCOMP_RET_ERRNO:
  case SECCOMP_RET_LOG:
  case SECCOMP_RET_ALLOW:
    return true;
  default:
    /* USER_NOTIF and TRACE both need somebody attached, and nothing can be. */
    return false;
  }
}

/*
 * Run every filter and take the most severe answer.
 *
 * Linux compares the action bits as unsigned and keeps the lowest, so a chain
 * cannot be loosened by adding to it - which is what makes filters safe to
 * inherit. Anything this does not recognise is treated as kill, which is the
 * default arm of the kernel's own switch: an action nobody implements must not
 * come out as permission.
 *
 * Returns true to run the syscall. When it returns false, *ret is what the
 * guest sees.
 */
bool
seccomp_check(uint64_t nr, const uint64_t *args, uint64_t *ret)
{
  if (seccomp_mode == SECCOMP_MODE_DISABLED)
    return true;

  struct seccomp_data d;
  memset(&d, 0, sizeof d);
  d.nr = (int32_t) nr;
  d.arch = SECCOMP_AUDIT_ARCH;
  vmm_get_reg(VREG_PC, &d.instruction_pointer);
  for (int i = 0; i < 6; i++)
    d.args[i] = args[i];

  uint32_t action = SECCOMP_RET_ALLOW;
  pthread_mutex_lock(&seccomp_lock);
  for (struct seccomp_filter *f = filters; f != NULL; f = f->next) {
    uint32_t r = bpf_run(f->insns, f->len, &d);
    if ((r & SECCOMP_RET_ACTION_FULL) < (action & SECCOMP_RET_ACTION_FULL))
      action = r;
  }
  pthread_mutex_unlock(&seccomp_lock);

  switch (action & SECCOMP_RET_ACTION_FULL) {
  case SECCOMP_RET_ALLOW:
    return true;
  case SECCOMP_RET_LOG:
    warnk("seccomp: %llu allowed by a filter that asked for it to be logged\n",
          (unsigned long long) nr);
    return true;
  case SECCOMP_RET_ERRNO: {
    /* The low 16 bits are the errno, and Linux clamps rather than refuses. */
    uint32_t e = action & SECCOMP_RET_DATA;
    if (e > 0xfff) e = 0xfff;
    *ret = (uint64_t) (int64_t) -(int32_t) e;
    return false;
  }
  case SECCOMP_RET_USER_NOTIF:
  case SECCOMP_RET_TRACE:
    /*
     * No supervisor and no tracer can be attached, and Linux runs the call as
     * though it returned ENOSYS when neither is. So does this - the filter
     * asked to defer the decision to somebody who is not there.
     */
    *ret = (uint64_t) (int64_t) -LINUX_ENOSYS;
    return false;
  case SECCOMP_RET_TRAP:
    send_signal(getpid(), LINUX_SIGSYS);
    *ret = (uint64_t) (int64_t) -LINUX_ENOSYS;
    return false;
  default:
    /* KILL_THREAD, KILL_PROCESS, and anything unrecognised. */
    warnk("seccomp: killed for system call %llu\n", (unsigned long long) nr);
    _exit(159);                 /* what a shell reports for SIGSYS */
  }
}

/* ---- the syscalls ---- */

DEFINE_SYSCALL(seccomp, unsigned int, op, unsigned int, flags, gaddr_t, uargs)
{
  switch (op) {
  case SECCOMP_SET_MODE_STRICT:
    if (flags != 0 || uargs != 0)
      return -LINUX_EINVAL;
    return strict_install();

  case SECCOMP_SET_MODE_FILTER: {
    if (flags & ~(SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG |
                  SECCOMP_FILTER_FLAG_SPEC_ALLOW |
                  SECCOMP_FILTER_FLAG_NEW_LISTENER |
                  SECCOMP_FILTER_FLAG_TSYNC_ESRCH |
                  SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV))
      return -LINUX_EINVAL;
    /* NEW_LISTENER returns a descriptor for a supervisor to poll, and there is
     * none - refused rather than answered with a descriptor nothing writes. */
    if (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER)
      return -LINUX_EOPNOTSUPP;
    /*
     * A filter may only be installed by a process that cannot gain privilege
     * through exec, or by root. Without that rule a filter is an escalation
     * route rather than a restriction: it can make a setuid program see
     * failures it was never written to handle.
     */
    if (!no_new_privs) {
      bool root;
      pthread_rwlock_rdlock(&proc.cred.lock);
      root = proc.cred.euid == 0;
      pthread_rwlock_unlock(&proc.cred.lock);
      if (!root)
        return -LINUX_EACCES;
    }
    /* TSYNC applies the filter to every thread. Every thread here shares one
     * chain already, so it is satisfied by construction rather than ignored. */
    return filter_install(uargs);
  }

  case SECCOMP_GET_ACTION_AVAIL: {
    if (flags != 0)
      return -LINUX_EINVAL;
    uint32_t action;
    if (copy_from_user(&action, uargs, sizeof action))
      return -LINUX_EFAULT;
    return action_is_available(action) ? 0 : -LINUX_EOPNOTSUPP;
  }

  case SECCOMP_GET_NOTIF_SIZES:
    /* The sizes belong to the notification interface, which is not available;
     * saying so here keeps a caller from building a listener it cannot use. */
    return -LINUX_EOPNOTSUPP;

  default:
    return -LINUX_EINVAL;
  }
}

/* prctl's older entry into the same thing. */
int
seccomp_prctl_set(unsigned long mode, gaddr_t prog)
{
  if (mode == SECCOMP_MODE_STRICT)
    return strict_install();
  if (mode == SECCOMP_MODE_FILTER) {
    if (!no_new_privs) {
      bool root;
      pthread_rwlock_rdlock(&proc.cred.lock);
      root = proc.cred.euid == 0;
      pthread_rwlock_unlock(&proc.cred.lock);
      if (!root)
        return -LINUX_EACCES;
    }
    return filter_install(prog);
  }
  return -LINUX_EINVAL;
}

/* ---- carrying the chain across a fork ---- */

size_t
seccomp_snapshot_size(void)
{
  size_t n = 0;
  pthread_mutex_lock(&seccomp_lock);
  for (struct seccomp_filter *f = filters; f != NULL; f = f->next)
    n += sizeof(uint32_t) + (size_t) f->len * sizeof(struct sock_filter);
  pthread_mutex_unlock(&seccomp_lock);
  return n;
}

/*
 * Written oldest-first, so that reading them back in order rebuilds the same
 * chain. The order matters only for which filter a report names, since every
 * one of them runs, but a chain that came back reversed would be a difference
 * nobody could see and nobody could explain later.
 */
int
seccomp_snapshot(void *buf, size_t len, int *mode_out)
{
  char *p = buf;
  size_t used = 0;
  int n = 0;
  pthread_mutex_lock(&seccomp_lock);
  *mode_out = seccomp_mode;
  for (struct seccomp_filter *f = filters; f != NULL; f = f->next)
    n++;
  struct seccomp_filter **v = calloc(n ? (size_t) n : 1, sizeof *v);
  if (v == NULL) {
    pthread_mutex_unlock(&seccomp_lock);
    return -1;
  }
  int i = n;
  for (struct seccomp_filter *f = filters; f != NULL; f = f->next)
    v[--i] = f;
  for (i = 0; i < n; i++) {
    uint32_t l = v[i]->len;
    size_t bytes = (size_t) l * sizeof(struct sock_filter);
    if (used + sizeof l + bytes > len) break;
    memcpy(p + used, &l, sizeof l);
    memcpy(p + used + sizeof l, v[i]->insns, bytes);
    used += sizeof l + bytes;
  }
  free(v);
  pthread_mutex_unlock(&seccomp_lock);
  return 0;
}

void
seccomp_restore(const void *buf, size_t len, int mode)
{
  const char *p = buf;
  size_t off = 0;
  pthread_mutex_lock(&seccomp_lock);
  filters = NULL;
  seccomp_mode = mode;
  pthread_mutex_unlock(&seccomp_lock);

  while (off + sizeof(uint32_t) <= len) {
    uint32_t l;
    memcpy(&l, p + off, sizeof l);
    size_t bytes = (size_t) l * sizeof(struct sock_filter);
    if (l == 0 || l > BPF_MAXINSNS || off + sizeof l + bytes > len)
      break;
    struct seccomp_filter *f = malloc(sizeof *f + bytes);
    if (f == NULL)
      break;
    memcpy(f->insns, p + off + sizeof l, bytes);
    f->len = (uint16_t) l;
    pthread_mutex_lock(&seccomp_lock);
    f->next = filters;
    filters = f;
    pthread_mutex_unlock(&seccomp_lock);
    off += sizeof l + bytes;
  }
  /*
   * A checkpoint that said there were filters and did not carry them would
   * leave a child running unfiltered, which is the one failure of this feature
   * that nothing in the guest can see. Refuse to be that child.
   */
  if (mode != SECCOMP_MODE_DISABLED && filters == NULL)
    panic("seccomp: the checkpoint says mode %d and carries no filters\n", mode);
}
