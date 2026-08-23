/*
 * aarch64 signal frame construction.
 *
 * The counterpart of signal_x86.c. src/ipc/signal.c keeps the neutral signal
 * management (masks, pending set, the sigaction table, the rt_sig* syscalls);
 * this builds and restores the arch-specific frame.
 *
 * Nothing here is shared with x86. The aarch64 sigcontext is
 * { fault_address, regs[31], sp, pc, pstate } followed by a chain of
 * _aarch64_ctx records in a reserved area (fpsimd_context, then a null
 * terminator). There is no SA_RESTORER: the handler returns through x30, which
 * the kernel points at __kernel_rt_sigreturn in the vDSO, so NABI maps a small
 * guest page holding `mov x8, #139; svc #0` and sets x30 to it. The handler is
 * invoked with the signal in x0, the siginfo in x1 and the ucontext in x2.
 *
 * See PORTING-arm64.md section 3.4.
 */

#include "common.h"
#include "linux/signal.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "page.h"
#include "arm64/vm.h"

#include <string.h>
#include <signal.h>
#include <assert.h>

#include <Hypervisor/Hypervisor.h>

/* From src/mm/pt_arm64.c */
void *pt_alloc_and_map(gaddr_t va, int prot);

/* ------------------------------------------------------- frame layout */
/*
 * Mirrors the kernel's arch/arm64 uapi structures exactly - same field order
 * and the same aligned attribute on __reserved - so the offsets a guest's libc
 * expects are the offsets it gets.
 */
struct l_aarch64_ctx {
  uint32_t magic;
  uint32_t size;
};

#define L_FPSIMD_MAGIC 0x46508001u

struct l_fpsimd_context {
  struct l_aarch64_ctx head;
  uint32_t fpsr;
  uint32_t fpcr;
  __uint128_t vregs[32];
};

struct l_sigcontext_arm64 {
  uint64_t fault_address;
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
  uint8_t  __reserved[4096] __attribute__((aligned(16)));
};

struct l_ucontext_arm64 {
  uint64_t                  uc_flags;
  uint64_t                  uc_link;
  l_stack_t                 uc_stack;
  l_sigset_t                uc_sigmask;
  uint8_t                   __glibc_pad[1024 / 8 - sizeof(l_sigset_t)];
  struct l_sigcontext_arm64 uc_mcontext;
};

struct l_rt_sigframe_arm64 {
  l_siginfo_t              info;
  struct l_ucontext_arm64  uc;
};

/* ------------------------------------------------- sigreturn trampoline */
/*
 * A one-page mini-vDSO: `mov x8, #139 (rt_sigreturn); svc #0`. Mapped lazily
 * into the guest at a fixed high VA, EL0-executable. x30 is pointed here when a
 * handler is delivered, so the handler's `ret` runs it and re-enters the host
 * through rt_sigreturn.
 *
 * Lazy single mapping is enough for the single-address-space case that works
 * today; fork/exec re-establishing it is future work alongside those paths.
 */
/*
 * Above the EL1 vector page (at user_addr_max), NOT below it: the guest stack
 * occupies [user_addr_max - STACK_SIZE, user_addr_max), so a page just under
 * user_addr_max would collide with it. This sits one page above, in the same
 * kernel-VA band as the trampoline, and is mapped once at init (before the MMU
 * is enabled) so no negative walk-cache entry for it can survive - guest TLBI
 * does not work under HVF (see PORTING-arm64.md 3.5.3).
 */
#define SIGRETURN_VA  (user_addr_max + PAGE_SIZEOF(PAGE_4KB))

static bool sigreturn_mapped = false;

static gaddr_t
ensure_sigreturn_trampoline(void);

/* Called from init_vkernel_machine before the guest runs, so the page is in the
 * tables before the MMU comes on. */
void
arch_setup_sigreturn(void)
{
  ensure_sigreturn_trampoline();
}

static gaddr_t
ensure_sigreturn_trampoline(void)
{
  if (!sigreturn_mapped) {
    uint32_t *code = pt_alloc_and_map(SIGRETURN_VA,
                                      LINUX_PROT_READ | LINUX_PROT_EXEC);
    code[0] = 0xD2801168u;   /* mov x8, #139 */
    code[1] = 0xD4000001u;   /* svc #0       */
    vmm_arm64_sync_guest_code(code, PAGE_SIZEOF(PAGE_4KB));
    sigreturn_mapped = true;
  }
  return SIGRETURN_VA;
}

/* ------------------------------------------------- context marshalling */

static void
save_sigcontext(struct l_sigcontext_arm64 *mc)
{
  for (int i = 0; i <= 30; i++)
    vmm_arm64_read_reg(HV_REG_X0 + i, &mc->regs[i]);
  vmm_arm64_read_sysreg(HV_SYS_REG_SP_EL0, &mc->sp);

  /*
   * The interrupted EL0 PC and PSTATE. When a signal is delivered off the back
   * of a syscall the vCPU is parked in the EL1 trampoline (CPSR = EL1h) and the
   * real EL0 return state is banked in ELR_EL1/SPSR_EL1 - HV_REG_PC/CPSR there
   * are the trampoline's own eret, not the guest's. An async interruption
   * leaves the vCPU at EL0, where PC/CPSR already hold the right thing.
   */
  uint64_t cpsr;
  vmm_arm64_read_reg(HV_REG_CPSR, &cpsr);
  if ((cpsr & 0xfu) != PSR_MODE_EL0t) {
    vmm_arm64_read_sysreg(HV_SYS_REG_ELR_EL1, &mc->pc);
    vmm_arm64_read_sysreg(HV_SYS_REG_SPSR_EL1, &mc->pstate);
  } else {
    vmm_arm64_read_reg(HV_REG_PC, &mc->pc);
    mc->pstate = cpsr;
  }
  mc->fault_address = 0;

  /* One fpsimd_context record, then a null terminator. */
  struct l_fpsimd_context *fp = (struct l_fpsimd_context *) mc->__reserved;
  fp->head.magic = L_FPSIMD_MAGIC;
  fp->head.size = sizeof *fp;
  uint64_t v;
  vmm_arm64_read_reg(HV_REG_FPSR, &v); fp->fpsr = (uint32_t) v;
  vmm_arm64_read_reg(HV_REG_FPCR, &v); fp->fpcr = (uint32_t) v;
  for (int i = 0; i < 32; i++)
    vmm_arm64_read_simd(HV_SIMD_FP_REG_Q0 + i, &fp->vregs[i]);

  struct l_aarch64_ctx *end =
      (struct l_aarch64_ctx *) (mc->__reserved + sizeof *fp);
  end->magic = 0;
  end->size = 0;
}

static void
restore_sigcontext(const struct l_sigcontext_arm64 *mc)
{
  for (int i = 0; i <= 30; i++)
    vmm_arm64_write_reg(HV_REG_X0 + i, mc->regs[i]);
  vmm_arm64_write_sysreg(HV_SYS_REG_SP_EL0, mc->sp);
  vmm_arm64_write_reg(HV_REG_PC, mc->pc);
  vmm_arm64_write_reg(HV_REG_CPSR, mc->pstate);

  const struct l_fpsimd_context *fp =
      (const struct l_fpsimd_context *) mc->__reserved;
  if (fp->head.magic == L_FPSIMD_MAGIC) {
    vmm_arm64_write_reg(HV_REG_FPSR, fp->fpsr);
    vmm_arm64_write_reg(HV_REG_FPCR, fp->fpcr);
    for (int i = 0; i < 32; i++)
      vmm_arm64_write_simd(HV_SIMD_FP_REG_Q0 + i, &fp->vregs[i]);
  }
}

/* --------------------------------------------------------- delivery */

int
arch_setup_sigframe(int signum)
{
  struct l_rt_sigframe_arm64 frame;
  memset(&frame, 0, sizeof frame);

  assert(signum <= LINUX_NSIG);

  uint64_t sp;
  vmm_get_reg(VREG_SP, &sp);
  if ((proc.sigaction[signum - 1].lsa_flags & LINUX_SA_ONSTACK) &&
      (sas_ss_flags(sp) & ~LINUX_SS_AUTODISARM) == 0) {
    sp = task.sas.ss_sp + task.sas.ss_size;
  }

  frame.info.lsi_signo = signum;

  frame.uc.uc_flags = 0;
  frame.uc.uc_link = 0;
  frame.uc.uc_stack = task.sas;
  frame.uc.uc_sigmask = task.sigmask;
  if (task.sas.ss_flags & LINUX_SS_AUTODISARM)
    reset_sas();
  save_sigcontext(&frame.uc.uc_mcontext);

  /* Block the handler's signal (and its mask) for the duration. */
  l_sigset_t newmask = proc.sigaction[signum - 1].lsa_mask;
  if (!(proc.sigaction[signum - 1].lsa_flags & LINUX_SA_NOMASK))
    LINUX_SIGADDSET(&newmask, signum);
  task.sigmask = newmask;
  sigset_t dset;
  host_sigmask_of(&newmask, &dset);
  sigprocmask(SIG_SETMASK, &dset, NULL);

  /* Push the frame; the aarch64 ABI requires a 16-byte-aligned stack. */
  sp -= sizeof frame;
  sp &= ~(uint64_t) 15;
  if (copy_to_user(sp, &frame, sizeof frame))
    return -LINUX_EFAULT;

  gaddr_t restorer = ensure_sigreturn_trampoline();

  /*
   * Handler ABI: x0 = signum, x1 = &siginfo, x2 = &ucontext; x30 = the
   * sigreturn trampoline; SP and PC set to the frame and the handler. CPSR is
   * forced to EL0t so the handler runs at EL0 - without it the vCPU is still in
   * the EL1 trampoline (CPSR = EL1h) and the handler would execute at EL1.
   */
  vmm_arm64_write_reg(HV_REG_X0, signum);
  vmm_arm64_write_reg(HV_REG_X1, sp + offsetof(struct l_rt_sigframe_arm64, info));
  vmm_arm64_write_reg(HV_REG_X2, sp + offsetof(struct l_rt_sigframe_arm64, uc));
  vmm_arm64_write_reg(HV_REG_LR, restorer);
  vmm_arm64_write_sysreg(HV_SYS_REG_SP_EL0, sp);
  vmm_arm64_write_reg(HV_REG_PC, proc.sigaction[signum - 1].lsa_handler);
  vmm_arm64_write_reg(HV_REG_CPSR, PSR_EL0);

  return 0;
}

uint64_t
arch_rt_sigreturn(void)
{
  uint64_t sp;
  vmm_get_reg(VREG_SP, &sp);

  struct l_rt_sigframe_arm64 frame;
  if (copy_from_user(&frame, sp, sizeof frame))
    die_with_forcedsig(LINUX_SIGSEGV);

  restore_sigcontext(&frame.uc.uc_mcontext);

  task.sigmask = frame.uc.uc_sigmask;
  sigset_t dset;
  host_sigmask_of(&task.sigmask, &dset);
  sigprocmask(SIG_SETMASK, &dset, NULL);

  /* restore_sigcontext already set x0 (regs[0]); return it so the syscall
   * return path writes back the same value rather than clobbering it, and so
   * the PC we restored stands (vmm_syscall_return is a no-op on aarch64). */
  return frame.uc.uc_mcontext.regs[0];
}
