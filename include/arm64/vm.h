#ifndef NOAH_ARM64_VM_H
#define NOAH_ARM64_VM_H

/*
 * aarch64 guest machine definitions - the counterpart of include/x86/vm.h.
 *
 * Nothing here has an x86 analogue worth preserving. There is no segmentation,
 * no GDT, no IDT: privilege comes from the exception level and the vector table
 * is a page of code rather than a table of descriptors.
 */

#include <stdint.h>

#include "page.h"

/* ------------------------------------------------------------------ PSTATE */
/*
 * SPSR / CPSR values. M[3:0] selects the exception level and stack pointer:
 * 0b0000 = EL0t, 0b0101 = EL1h (EL1 with its own SP). DAIF in [9:6] masks
 * debug, SError, IRQ and FIQ.
 */
#define PSR_MODE_EL0t   0x0u
#define PSR_MODE_EL1h   0x5u
#define PSR_DAIF_MASKED 0x3C0u

#define PSR_EL0         (PSR_DAIF_MASKED | PSR_MODE_EL0t)
#define PSR_EL1         (PSR_DAIF_MASKED | PSR_MODE_EL1h)

/* ----------------------------------------------------------------- ESR / EC */
/*
 * Exception Syndrome Register. EC (the class) is bits [31:26]; ISS is [24:0].
 *
 * Two different ESRs matter and they are easy to confuse:
 *
 *   ESR_EL2 - why the guest exited to the host. For a syscall this is HVC64,
 *             because the exit is produced by the EL1 trampoline, never by the
 *             guest's own svc.
 *   ESR_EL1 - why the guest went from EL0 to EL1 in the first place. This is
 *             where the svc-versus-fault distinction actually lives.
 */
#define ESR_EC(esr)  ((uint32_t)(((esr) >> 26) & 0x3F))
#define ESR_ISS(esr) ((uint32_t)((esr) & 0x1FFFFFF))

#define EC_UNKNOWN       0x00
#define EC_WFX            0x01
#define EC_SIMD_FP        0x07  /* FP/SIMD access trapped by CPACR_EL1 */
#define EC_ILLEGAL_STATE  0x0E
#define EC_SVC64          0x15
#define EC_HVC64          0x16
#define EC_SMC64          0x17
#define EC_MSR_TRAP       0x18  /* trapped mrs/msr/system instruction */
#define EC_IABT_LOWER     0x20  /* instruction abort from a lower EL */
#define EC_IABT_CURRENT   0x21
#define EC_PC_ALIGNMENT   0x22
#define EC_DABT_LOWER     0x24  /* data abort from a lower EL */
#define EC_DABT_CURRENT   0x25
#define EC_SP_ALIGNMENT   0x26
#define EC_BRK64          0x3C

/* Data Abort ISS: bit 6 is WnR, "write not read". */
#define DABT_ISS_WNR(iss) (((iss) >> 6) & 1)

/* ---------------------------------------------------------- vector table */
/*
 * VBAR_EL1 must be 2KiB-aligned. The table is four groups of four 128-byte
 * entries: {current EL with SP0, current EL with SPx, lower EL AArch64, lower
 * EL AArch32} x {synchronous, IRQ, FIQ, SError}.
 *
 * Only one entry is reachable in this design. The guest runs at EL0 in AArch64,
 * so everything it can raise synchronously - svc, data aborts, instruction
 * aborts - arrives at the "lower EL, AArch64, synchronous" slot. Interrupts are
 * masked (DAIF), and there is no AArch32 guest.
 */
#define VBAR_ALIGN            0x800
#define VEC_LOWER64_SYNC      0x400
#define VEC_TABLE_SIZE        0x800
/* A one-shot eret stub past the vector table, used to drop from EL1 to EL0 at
 * guest startup. Lives in the same vector page. */
#define VEC_BOOT_OFF          0x900

/* ------------------------------------------------------- instructions */
/*
 * Encoded by hand rather than assembled: the trampoline is four instructions
 * and keeping it inline avoids an assembler step and a linker script for a
 * blob that has to be copied into guest memory anyway.
 */
/*
 * The immediate is 1, not 0, and that is load-bearing.
 *
 * The trampoline clobbers no register - a real `svc` must preserve x0-x30 - so
 * the guest's x0 is still live when this executes. x0 is also where SMCCC puts
 * a function ID, and Apple's hypervisor answers part of that space itself: an
 * `hvc #0` whose x0 looks like a call it owns is completed in firmware,
 * returning SMCCC_RET_NOT_SUPPORTED in x0, and never becomes a VM exit. The
 * guest's syscall then silently does not happen. Measured, that was every x0 in
 * [0xc1000000, 0xc2000000) - fast call, SMC64, owning entity 1. A guest whose
 * mappings land in that band loses mmap and mprotect, which is not a band we
 * get to avoid: the first argument of any syscall is a guest address.
 *
 * A non-zero immediate is not treated as a firmware call, so the exit is ours
 * whatever the guest left in x0. See test/arch/smoke/hvctest.c.
 */
#define INSN_HVC1  0xD4000022u  /* hvc #1  */
#define INSN_ERET  0xD69F03E0u  /* eret    */
#define INSN_BRK0  0xD4200000u  /* brk #0  */
#define INSN_NOP   0xD503201Fu  /* nop     */

/* --------------------------------------------------------------- SCTLR_EL1 */
/*
 * RES1 bits that must be set on any ARMv8 SCTLR_EL1 write, plus the ones this
 * port cares about. M enables stage-1 translation; with it clear, EL0 and EL1
 * address memory flat through stage 2, which is what the Phase 0 spike relied
 * on and what the backend starts in before page tables exist.
 */
#define SCTLR_EL1_RES1  ((1u << 11) | (1u << 20) | (1u << 22) | \
                         (1u << 23) | (1u << 28) | (1u << 29))
#define SCTLR_EL1_M     (1u << 0)   /* stage-1 MMU enable */
#define SCTLR_EL1_C     (1u << 2)   /* data cacheability  */
#define SCTLR_EL1_I     (1u << 12)  /* instruction cacheability */

/* ----------------------------------------------------------------- CPACR_EL1 */
/* FPEN in [21:20]: 0b11 leaves FP/SIMD untrapped at EL0 and EL1. Without this
 * any guest use of V registers traps as EC_SIMD_FP, which every real aarch64
 * binary will do almost immediately - memcpy alone is enough. */
#define CPACR_EL1_FPEN_NOTRAP (3u << 20)

/* ------------------------------------------------------------ translation */
/*
 * Stage-1 descriptors, 4KiB granule. The guest sees 4KiB pages even though
 * stage 2 is fixed at the host's 16KiB - see PORTING-arm64.md section 3.5.
 *
 * Level 0/1/2 entries are either a table pointer (bit 1 set) or a block
 * (bit 1 clear); level 3 entries are pages (bit 1 set). Bit 0 is validity.
 */
#define PTE_VALID       (1ull << 0)
#define PTE_TABLE       (1ull << 1)   /* at levels 0-2: table, not block */
#define PTE_PAGE        (1ull << 1)   /* at level 3: page               */
#define PTE_ATTR(i)     ((uint64_t)(i) << 2)   /* MAIR index */
#define PTE_NS          (1ull << 5)
#define PTE_AP_RW_EL0   (1ull << 6)   /* AP[1]: accessible at EL0       */
#define PTE_AP_RO       (1ull << 7)   /* AP[2]: read-only               */
#define PTE_SH_INNER    (3ull << 8)
#define PTE_AF          (1ull << 10)  /* access flag; a fault without it */
#define PTE_NG          (1ull << 11)
#define PTE_PXN         (1ull << 53)  /* privileged execute-never       */
#define PTE_UXN         (1ull << 54)  /* unprivileged execute-never     */

/*
 * MAIR_EL1 attribute 0 = Normal, Inner/Outer Write-Back Non-transient.
 * Attribute 1 = Device-nGnRnE, for completeness; nothing maps it yet.
 */
#define MAIR_ATTR_NORMAL 0xFFull
#define MAIR_ATTR_DEVICE 0x00ull
#define MAIR_EL1_VALUE   (MAIR_ATTR_NORMAL | (MAIR_ATTR_DEVICE << 8))
#define MAIR_IDX_NORMAL  0
#define MAIR_IDX_DEVICE  1

/*
 * TCR_EL1 for a single 4KiB-granule TTBR0 range and no TTBR1.
 *
 * T0SZ=25 gives a 39-bit VA space (2^39 = 512GiB), which covers
 * user_addr_max (0x7fc0000000) and the kernel objects kmap stacks above it.
 * TG0=0 selects the 4KiB granule. EPD1 disables TTBR1 walks entirely, since
 * the guest has no high half.
 */
#define TCR_T0SZ(n)     ((uint64_t)(n) & 0x3F)
#define TCR_IRGN0_WBWA  (1ull << 8)
#define TCR_ORGN0_WBWA  (1ull << 10)
#define TCR_SH0_INNER   (3ull << 12)
#define TCR_TG0_4K      (0ull << 14)
#define TCR_EPD1        (1ull << 23)

/*
 * IPS caps what stage 1 may *output*, and it has to agree with the size the VM
 * was created with - two ceilings on the same address, and the lower one wins
 * silently.
 *
 * This was fixed at 36 bits while the VM took the platform default, which is
 * also 36, so they agreed by coincidence. Raising only the VM's moved the
 * failure rather than fixing it: hv_vm_map accepted an IPA above 64GiB, stage 1
 * then refused to translate to it, and the guest took a level-3 translation
 * fault on a page whose descriptor read "valid af el0 rw". A page table that
 * describes a mapping the MMU will not perform is about as misleading as a
 * fault gets, so TCR is now built from what the VM actually has.
 *
 * Encoding is 0=32, 1=36, 2=40, 3=42, 4=44, 5=48, 6=52 bits; anything not on
 * that ladder rounds down to the entry below it, since claiming more than the
 * VM has is the failure this is here to prevent.
 */
#define TCR_IPS(bits)   ((uint64_t)((bits) >= 52 ? 6 : (bits) >= 48 ? 5 : \
                                    (bits) >= 44 ? 4 : (bits) >= 42 ? 3 : \
                                    (bits) >= 40 ? 2 : (bits) >= 36 ? 1 : 0) << 32)

#define TCR_EL1_BASE    (TCR_T0SZ(25) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA | \
                         TCR_SH0_INNER | TCR_TG0_4K | TCR_EPD1)
#define TCR_EL1_FOR(bits) (TCR_EL1_BASE | TCR_IPS(bits))

/* Stage-2 granularity, imposed by hv_vm_map. Measured, not assumed: it rejects
 * anything not 16KiB-aligned on host address, IPA and size alike. */
#define STAGE2_GRANULE  0x4000UL

#endif
