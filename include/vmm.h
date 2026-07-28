#ifndef NOAH_VMM_H
#define NOAH_VMM_H

/*
 * The VMM interface, split by architecture.
 *
 * Everything below the "common" line is architecture-neutral and is what the
 * rest of the tree should be reaching for; see include/arch.h for the vCPU
 * interface proper. The per-architecture blocks exist because the two
 * Hypervisor.framework APIs share no vocabulary - hv_vmx.h is entirely inside
 * `#ifdef __x86_64__` and hv_vcpu.h's ARM half inside `#ifdef __arm64__`, so
 * there is nothing to unify at this level even in principle.
 */

#include "types.h"
#include "noah.h"
#include "arch.h"

#ifdef __x86_64__

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <Hypervisor/hv_arch_vmx.h>

#include "x86/vmx.h"

struct vcpu_snapshot {
  uint64_t vcpu_reg[NR_X86_REG_LIST];
  uint64_t vmcs[NR_VMCS_FIELD_MASKED];
  char fpu_states[2496] __attribute__((aligned(16)));
};

void vmm_read_register(hv_x86_reg_t, uint64_t *);
void vmm_write_register(hv_x86_reg_t, uint64_t);
void vmm_read_msr(uint32_t, uint64_t *);
void vmm_write_msr(uint32_t, uint64_t);
void vmm_read_vmcs(uint32_t, uint64_t *);
void vmm_write_vmcs(uint32_t, uint64_t);

void vmm_write_fpstate(void *, size_t);
void vmm_enable_native_msr(uint32_t, bool);

#elif defined(__arm64__)

#include <Hypervisor/Hypervisor.h>

/*
 * The full resumable vCPU state for fork/clone (Phase 4). Everything that dies
 * with the vCPU on hv_vm_destroy: the general registers, the banked EL0 state
 * (SP_EL0/ELR_EL1/SPSR_EL1 - a snapshot is taken while the guest is parked in
 * the EL1 trampoline, so HV_REG_PC/CPSR are the trampoline's own eret, not the
 * guest's), the thread pointer, the FP/SIMD file, and the control system
 * registers that describe the address space (SCTLR/CPACR/MAIR/TCR, the table
 * base TTBR0 and the vector base VBAR). Capturing the control registers rather
 * than reconstructing them keeps reentry entirely inside the backend - no reach
 * into the page-table or machine-setup layers - and restores exactly what ran.
 */
struct vcpu_snapshot {
  uint64_t x[31];        /* X0..X30 */
  uint64_t sp;           /* SP_EL0 */
  uint64_t pc;           /* HV_REG_PC (the trampoline eret at snapshot time) */
  uint64_t pstate;       /* CPSR */
  uint64_t elr_el1;      /* banked EL0 return PC */
  uint64_t spsr_el1;     /* banked EL0 PSTATE */
  uint64_t tpidr_el0;
  uint64_t sctlr_el1;
  uint64_t cpacr_el1;
  uint64_t mair_el1;
  uint64_t tcr_el1;
  uint64_t ttbr0_el1;
  uint64_t vbar_el1;
  uint64_t fpcr;
  uint64_t fpsr;
  uint8_t  v[32][16];    /* Q0..Q31 */
};

hv_vcpu_exit_t *vmm_arm64_exit_record(void);

void vmm_arm64_read_reg(hv_reg_t, uint64_t *);
void vmm_arm64_read_simd(hv_simd_fp_reg_t, void *out16);
void vmm_arm64_write_simd(hv_simd_fp_reg_t, const void *in16);
void vmm_arm64_write_reg(hv_reg_t, uint64_t);
void vmm_arm64_read_sysreg(hv_sys_reg_t, uint64_t *);
void vmm_arm64_write_sysreg(hv_sys_reg_t, uint64_t);

void vmm_arm64_sync_guest_code(void *hva, size_t len);
void vmm_arm64_map_stage2(gaddr_t ipa, size_t size, int prot, void *haddr);
void vmm_arm64_unmap_stage2(gaddr_t ipa, size_t size);
void vmm_arm64_replay_stage2(void);
void vmm_arm64_s2_reflush(gaddr_t ipa);
void vmm_arm64_s2_reprotect(gaddr_t ipa, int prot);
void vmm_arm64_install_trampoline(void *hva, gaddr_t ipa);
void vmm_arm64_init_vcpu(void);
void vmm_arm64_enter_el0(gaddr_t pc, gaddr_t sp, gaddr_t el1_eret_stub);

#else
#error "unsupported architecture"
#endif

/* ------------------------------------------------------------- common */

struct vmm_snapshot {
  struct vcpu_snapshot first_vcpu_snapshot;
};

void vmm_create(void);
void vmm_destroy(void);
void vmm_snapshot(struct vmm_snapshot*);
void vmm_reentry(struct vmm_snapshot*);
void vmm_snapshot_vcpu(struct vcpu_snapshot*);
void vmm_restore_vcpu(struct vcpu_snapshot*);

void vmm_create_vcpu(struct vcpu_snapshot *);

/* Interrupt every other thread's vCPU so it leaves guest code; used when one
 * thread must stop the others (execve). */
void vmm_kick_other_vcpus(void);
void vmm_destroy_vcpu(void);

int vmm_enter(void);

/* prot is obtained by or'ing HV_MEMORY_READ, HV_MEMORY_EXEC, HV_MEMORY_WRITE */
void vmm_mmap(gaddr_t addr, size_t len, int prot, void *ptr);
void vmm_munmap(gaddr_t addr, size_t len);

#endif
