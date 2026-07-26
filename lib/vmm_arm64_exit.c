/*
 * aarch64 exit decoding: the architecture-neutral interface from include/arch.h.
 *
 * The counterpart of lib/vmm_x86_exit.c. Split from the plumbing in
 * lib/vmm_arm64.c so it can be tested against a fake vCPU, the same way the x86
 * decoder is.
 *
 * The central subtlety is that TWO syndrome registers are in play and they
 * answer different questions:
 *
 *   ESR_EL2  why the guest exited to the host. For a system call this always
 *            reads HVC64, because the exit is manufactured by the EL1
 *            trampoline - the guest's own `svc` never reaches the host.
 *   ESR_EL1  why the guest left EL0 in the first place. This is where svc is
 *            distinguished from a data or instruction abort.
 *
 * Reading ESR_EL1 on the host is what lets the trampoline stay two instructions
 * that clobber no guest register. See vmm_arm64_install_trampoline().
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hypervisor/Hypervisor.h>

#include "vmm.h"
#include "arch.h"
#include "mm.h"
#include "arm64/vm.h"
#include "linux/signal.h"

/* Provided by lib/vmm_arm64.c, or by the test's fake vCPU. */
hv_vcpu_exit_t *vmm_arm64_exit_record(void);
void vmm_arm64_read_reg(hv_reg_t, uint64_t *);
void vmm_arm64_write_reg(hv_reg_t, uint64_t);
void vmm_arm64_read_sysreg(hv_sys_reg_t, uint64_t *);
void vmm_arm64_write_sysreg(hv_sys_reg_t, uint64_t);
int  vmm_enter(void);
void vmm_arm64_reset_fpsimd(void);

/* ==================================================== register mapping */

/*
 * The aarch64 syscall ABI. Contrast x86-64, where the number and the return
 * value share rax: here they are x8 and x0, which is precisely why arch.h keeps
 * VREG_SYSNR and VREG_RET as separate names.
 */
/*
 * VREG_SP is absent from this table on purpose. aarch64 has no X31 - that
 * register encoding means XZR - so the stack pointer is not a general register
 * at all and has to come from SP_EL0. It is special-cased below, and the
 * sentinel here makes using the table for it fail loudly instead of silently
 * reading x0, which is what a zero-filled gap would do.
 */
#define VREG_NOT_A_GPR ((hv_reg_t) 0xFFFFFFFF)

static const hv_reg_t vreg_map[NR_VREG] = {
  [VREG_PC]    = HV_REG_PC,
  [VREG_SP]    = VREG_NOT_A_GPR,
  [VREG_SYSNR] = HV_REG_X8,
  [VREG_RET]   = HV_REG_X0,
  [VREG_ARG0]  = HV_REG_X0,
  [VREG_ARG1]  = HV_REG_X1,
  [VREG_ARG2]  = HV_REG_X2,
  [VREG_ARG3]  = HV_REG_X3,
  [VREG_ARG4]  = HV_REG_X4,
  [VREG_ARG5]  = HV_REG_X5,
};

/*
 * Is the vCPU parked in the EL1 trampoline rather than running guest code?
 *
 * True whenever the host is looking at the vCPU after a trap: the guest's `svc`
 * took it to EL1, the stub bounced to us with `hvc`, and HV_REG_PC/CPSR now
 * describe the *stub* - PC is its `eret`, CPSR is EL1h. The guest's own PC is
 * banked in ELR_EL1, which that `eret` will consume.
 */
static bool
parked_at_el1(void)
{
  uint64_t cpsr;
  vmm_arm64_read_reg(HV_REG_CPSR, &cpsr);
  return (cpsr & 0xfu) != PSR_MODE_EL0t;
}

void
vmm_get_reg(enum vreg reg, uint64_t *val)
{
  assert(reg < NR_VREG);
  /* The guest runs at EL0, so SP_EL0 is its stack pointer. */
  if (reg == VREG_SP) {
    vmm_arm64_read_sysreg(HV_SYS_REG_SP_EL0, val);
    return;
  }
  /*
   * VREG_PC is the *guest's* program counter, so the EL1 trampoline has to stay
   * invisible here: while parked in it the guest's PC lives in ELR_EL1, and
   * HV_REG_PC is the stub's own `eret`. Callers that set a new PC - execve
   * pointing at the new image's entry, most importantly - would otherwise write
   * a register the `eret` immediately discards, and the guest would resume at
   * the old address instead.
   */
  if (reg == VREG_PC && parked_at_el1()) {
    vmm_arm64_read_sysreg(HV_SYS_REG_ELR_EL1, val);
    return;
  }
  assert(vreg_map[reg] != VREG_NOT_A_GPR);
  vmm_arm64_read_reg(vreg_map[reg], val);
}

void
vmm_set_reg(enum vreg reg, uint64_t val)
{
  assert(reg < NR_VREG);
  if (reg == VREG_SP) {
    vmm_arm64_write_sysreg(HV_SYS_REG_SP_EL0, val);
    return;
  }
  if (reg == VREG_PC && parked_at_el1()) {
    vmm_arm64_write_sysreg(HV_SYS_REG_ELR_EL1, val);
    return;
  }
  assert(vreg_map[reg] != VREG_NOT_A_GPR);
  vmm_arm64_write_reg(vreg_map[reg], val);
}

void
vmm_set_tls(uint64_t tls)
{
  /* aarch64 keeps the thread pointer in TPIDR_EL0, which the guest reads
   * directly with `mrs`. Set here from clone's tls argument; never from a
   * syscall, because aarch64 has no arch_prctl. */
  vmm_arm64_write_sysreg(HV_SYS_REG_TPIDR_EL0, tls);
}

void
vmm_get_tls(uint64_t *tls)
{
  vmm_arm64_read_sysreg(HV_SYS_REG_TPIDR_EL0, tls);
}

void
vmm_syscall_unadvance(void)
{
  /* No-op, the mirror of vmm_syscall_return: the CPU already advanced ELR_EL1
   * past the svc, and nothing here re-advances the PC, so there is nothing to
   * undo. */
}

void
vmm_reset_regs(void)
{
  /*
   * Post-exec register state on aarch64: x0-x30 and the FP/SIMD file cleared.
   * No segments, no FS/GS bases - those are the x86 half of this operation and
   * have no counterpart here. SP, PC and TPIDR_EL0 are set by the caller (SP
   * and PC from the loaded image; TLS only via clone).
   */
  for (hv_reg_t r = HV_REG_X0; r <= HV_REG_X30; r++)
    vmm_arm64_write_reg(r, 0);

  vmm_arm64_reset_fpsimd();
}

void
vmm_syscall_return(void)
{
  /*
   * Deliberately empty.
   *
   * x86 must step over the two-byte `syscall` because the #UD leaves RIP
   * pointing at it. aarch64 must not: the CPU advances ELR_EL1 past the `svc`
   * when it takes the exception, and the trampoline's `eret` consumes that
   * value. Measured in Phase 0 - an svc at 0x10804 produced ELR_EL1 = 0x10808.
   *
   * Adding an advance here would skip one instruction after every single
   * system call, which presents as the guest corrupting itself rather than as
   * anything resembling a PC bug.
   */
}

/* ========================================================== decoding */

static void
fault(struct vm_exit *vmexit, int sig)
{
  vmexit->kind = EXIT_FAULT;
  vmexit->signal = sig;
}

/* Translate an abort syndrome into the access that caused it. Instruction
 * aborts are always fetches; data aborts carry WnR. */
static enum vm_access
abort_access(uint32_t ec, uint32_t iss)
{
  if (ec == EC_IABT_LOWER || ec == EC_IABT_CURRENT)
    return VM_ACCESS_EXEC;
  return DABT_ISS_WNR(iss) ? VM_ACCESS_WRITE : VM_ACCESS_READ;
}

/*
 * The guest went EL0 -> EL1 and the trampoline bounced it to us. ESR_EL1 says
 * what actually happened.
 */
static void
decode_via_trampoline(struct vm_exit *vmexit)
{
  uint64_t esr_el1 = 0, far_el1 = 0;
  vmm_arm64_read_sysreg(HV_SYS_REG_ESR_EL1, &esr_el1);

  uint32_t ec = ESR_EC(esr_el1);

  switch (ec) {
  case EC_SVC64:
    vmexit->kind = EXIT_SYSCALL;
    return;

  case EC_IABT_LOWER:
  case EC_DABT_LOWER:
    /* A stage-1 fault: the guest's own tables rejected the access, or there
     * are no tables yet. FAR_EL1 holds the faulting virtual address. */
    vmm_arm64_read_sysreg(HV_SYS_REG_FAR_EL1, &far_el1);
    vmexit->kind = EXIT_MMU_FAULT;
    vmexit->fault_addr = far_el1;
    vmexit->fault_addr_valid = true;
    vmexit->fault_access = abort_access(ec, ESR_ISS(esr_el1));
    vmexit->raw_reason = esr_el1;
    return;

  case EC_PC_ALIGNMENT:
  case EC_SP_ALIGNMENT:
    warnk("guest alignment fault, ESR_EL1=0x%llx\n", esr_el1);
    fault(vmexit, LINUX_SIGBUS);
    return;

  case EC_BRK64:
    fault(vmexit, LINUX_SIGTRAP);
    return;

  case EC_SIMD_FP:
    /* CPACR_EL1.FPEN should have been set at vCPU init; if this fires, it was
     * not, and every guest doing a memcpy will land here. */
    warnk("FP/SIMD trapped - CPACR_EL1.FPEN not set?\n");
    fault(vmexit, LINUX_SIGILL);
    return;

  case EC_UNKNOWN:
  case EC_ILLEGAL_STATE:
  default:
    warnk("unhandled EL0 exception, ESR_EL1=0x%llx (EC=0x%02x)\n", esr_el1, ec);
    fault(vmexit, LINUX_SIGILL);
    return;
  }
}

int
vmm_run(struct vm_exit *vmexit)
{
  memset(vmexit, 0, sizeof *vmexit);

  if (vmm_enter() < 0)
    return -1;

  hv_vcpu_exit_t *vexit = vmm_arm64_exit_record();

  switch (vexit->reason) {
  case HV_EXIT_REASON_EXCEPTION:
    break;

  case HV_EXIT_REASON_VTIMER_ACTIVATED:
  case HV_EXIT_REASON_CANCELED:
    /* Nothing for the syscall layer. Going back through the caller's loop is
     * what gives pending signals a chance to be delivered. */
    vmexit->kind = EXIT_RESUME;
    return 0;

  case HV_EXIT_REASON_UNKNOWN:
  default:
    warnk("unknown vcpu exit reason %u\n", vexit->reason);
    vmexit->kind = EXIT_UNHANDLED;
    vmexit->raw_reason = vexit->reason;
    return 0;
  }

  uint64_t esr_el2 = vexit->exception.syndrome;
  uint32_t ec = ESR_EC(esr_el2);
  vmexit->raw_reason = esr_el2;

  switch (ec) {
  case EC_HVC64:
    /* Our trampoline. What the guest actually did is in ESR_EL1. */
    decode_via_trampoline(vmexit);
    return 0;

  case EC_IABT_LOWER:
  case EC_DABT_LOWER:
    /*
     * A stage-2 fault: the IPA is not mapped, so this trapped straight to the
     * host without passing through EL1. Distinct from the stage-1 aborts
     * handled above, and the address is a guest-physical one - the framework
     * reports it separately from the virtual address.
     */
    vmexit->kind = EXIT_MMU_FAULT;
    vmexit->fault_addr = vexit->exception.virtual_address;
    vmexit->fault_addr_valid = true;
    vmexit->fault_access = abort_access(ec, ESR_ISS(esr_el2));
    vmexit->raw_qualification = vexit->exception.physical_address;
    return 0;

  case EC_SMC64:
    /* No secure monitor behind this guest. */
    warnk("guest executed smc\n");
    fault(vmexit, LINUX_SIGILL);
    return 0;

  case EC_MSR_TRAP:
    warnk("guest trapped on a system register, ESR_EL2=0x%llx\n", esr_el2);
    fault(vmexit, LINUX_SIGILL);
    return 0;

  case EC_WFX:
    /* wfi/wfe: the guest is idling. */
    vmexit->kind = EXIT_RESUME;
    return 0;

  default:
    warnk("unhandled guest exit, ESR_EL2=0x%llx (EC=0x%02x)\n", esr_el2, ec);
    vmexit->kind = EXIT_UNHANDLED;
    return 0;
  }
}
