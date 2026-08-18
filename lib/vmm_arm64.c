/*
 * Hypervisor.framework plumbing for aarch64 guests.
 *
 * The counterpart of lib/vmm_x86.c: VM and vCPU lifecycle, the raw register and
 * system-register accessors, and stage-2 mapping. Exit decoding lives next door
 * in lib/vmm_arm64_exit.c, split for the same reason as on x86 - so the decoder
 * can be tested without a VM.
 *
 * See PORTING-arm64.md. The trap design (EL0 svc -> EL1 trampoline -> hvc ->
 * host) was validated on hardware in spike/arm64-trap/ before any of this was
 * written.
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vmm.h"
#include "mm.h"
#include "util/list.h"
#include "util/khash.h"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>

#include "arm64/vm.h"
#include "checkpoint.h"

/*
 * Stage-2 mapping registry.
 *
 * Every hv_vm_map goes through vmm_arm64_map_stage2 and every hv_vm_unmap
 * through vmm_arm64_unmap_stage2, both at 16KiB-granule granularity (pt_arm64.c
 * maps whole chunks and vmm_mmap regions; vmm_munmap unmaps one granule at a
 * time). Keeping a granule-keyed record of what host memory backs each IPA is
 * what makes fork possible: HVF allows only one VM per process, so fork tears the
 * VM down and rebuilds it on both sides (see src/proc/fork.c), and rebuilding
 * means replaying every stage-2 mapping into the fresh VM. The guest's host pages
 * themselves survive the fork by COW; only the IPA->host associations, which are
 * VM state, are lost and must be replayed. Keyed by IPA so map/unmap/replay are
 * all O(1) per granule and independent of pt_arm64.c's IPA layout.
 */
struct s2_ent { void *haddr; int prot; };
KHASH_MAP_INIT_INT64(s2, struct s2_ent)
static khash_t(s2) *s2_map;

struct vcpu {
  struct list_head list;
  hv_vcpu_t vcpuid;
  hv_vcpu_exit_t *vexit;
};

struct list_head vcpus;
int nr_vcpus;
pthread_rwlock_t alloc_lock;

_Thread_local static struct vcpu *vcpu;

/* The decoder needs the exit record the framework fills in on each run. */
hv_vcpu_exit_t *
vmm_arm64_exit_record(void)
{
  return vcpu->vexit;
}

/* ------------------------------------------------------------ stage 2 */

/*
 * The stage-2 primitive: map/unmap an IPA range onto host memory. NOT the
 * arch-neutral vmm_mmap - that is the VA-region mapper in src/mm/pt_arm64.c,
 * which drives stage 1 and calls this for stage 2.
 *
 * hv_vm_map rejects anything not 16KiB-granular on host address, IPA and size
 * alike - measured, see PORTING-arm64.md section 3.5. These asserts catch that
 * up front; violating it otherwise yields HV_BAD_ARGUMENT from deep in the
 * framework, which says nothing about which of the three arguments was wrong.
 */
/* Record (or overwrite) the host backing of every granule in an IPA range, so
 * the mapping can be replayed into a fresh VM after fork. */
static void
s2_record(gaddr_t ipa, size_t size, int prot, void *haddr)
{
  for (size_t off = 0; off < size; off += STAGE2_GRANULE) {
    int ret;
    khiter_t k = kh_put(s2, s2_map, ipa + off, &ret);
    kh_value(s2_map, k) = (struct s2_ent){ (char *) haddr + off, prot };
  }
}

static void
s2_forget(gaddr_t ipa, size_t size)
{
  for (size_t off = 0; off < size; off += STAGE2_GRANULE) {
    khiter_t k = kh_get(s2, s2_map, ipa + off);
    if (k != kh_end(s2_map))
      kh_del(s2, s2_map, k);
  }
}

void
vmm_arm64_map_stage2(gaddr_t ipa, size_t size, int prot, void *haddr)
{
  assert(((uintptr_t) haddr & (STAGE2_GRANULE - 1)) == 0);
  assert((ipa & (STAGE2_GRANULE - 1)) == 0);
  assert((size & (STAGE2_GRANULE - 1)) == 0);

  gaddr_t base = ipa & ~(STAGE2_GRANULE - 1);
  khiter_t k = kh_get(s2, s2_map, base);
  if (k != kh_end(s2_map)) {
    hv_return_t unmap_ret = hv_vm_unmap(ipa, size);
    if (unmap_ret != HV_SUCCESS && unmap_ret != HV_BAD_ARGUMENT) {
      warnk("hv_vm_unmap returned %#x for ipa [%#llx, %#llx)\n",
            unmap_ret, (unsigned long long) ipa, (unsigned long long) (ipa + size));
    }
  }
  hv_return_t err = hv_vm_map(haddr, ipa, size, prot);
  if (err != HV_SUCCESS) {
    panic("hv_vm_map failed: err %#x mapping ipa [%#llx, %#llx) "
          "to host %p prot %d (ipa space is %d bits)\n",
          err, (unsigned long long) ipa, (unsigned long long) (ipa + size),
          haddr, prot, vmm_arm64_ipa_bits());
  }
  s2_record(ipa, size, prot, haddr);
}

void
vmm_arm64_unmap_stage2(gaddr_t ipa, size_t size)
{
  assert((size & (STAGE2_GRANULE - 1)) == 0);
  gaddr_t base = ipa & ~(STAGE2_GRANULE - 1);
  khiter_t k = kh_get(s2, s2_map, base);
  if (k != kh_end(s2_map)) {
    hv_return_t unmap_ret = hv_vm_unmap(ipa, size);
    if (unmap_ret != HV_SUCCESS && unmap_ret != HV_BAD_ARGUMENT) {
      warnk("hv_vm_unmap returned %#x for ipa [%#llx, %#llx)\n",
            unmap_ret, (unsigned long long) ipa, (unsigned long long) (ipa + size));
    }
  }
  s2_forget(ipa, size);
}

/*
 * The stage-2 registry as arena offsets, for a handover. The registry holds host
 * addresses, which are meaningless in another process, so each is translated
 * back to the arena offset naming the same bytes. Returns the number of entries
 * the registry holds, which may exceed `max`.
 */
size_t
vmm_arm64_s2_snapshot(struct checkpoint_s2 *out, size_t max)
{
  gaddr_t ipa;
  struct s2_ent ent;
  size_t n = 0;
  kh_foreach(s2_map, ipa, ent, {
    if (n < max) {
      out[n].ipa       = ipa;
      out[n].arena_off = arena_offset_of(ent.haddr);
      out[n].prot      = ent.prot;
      out[n]._pad      = 0;
    }
    n++;
  });
  return n;
}

/*
 * Rebuild the stage-2 registry, and the mappings, from a checkpoint.
 *
 * Each entry names its memory by arena offset; the caller has already mapped the
 * arena, so the offset is resolved to this process's address and handed to
 * hv_vm_map. After this the guest's physical memory is where the guest believes
 * it is, and the registry is able to describe it again for the next handover.
 */
void
vmm_arm64_s2_restore(const struct checkpoint_s2 *saved, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    /*
     * A negative offset is a shared file mapping, whose memory is the file's
     * and not the arena's. It is re-established from the descriptor once the
     * stage-1 tables are back and can say which IPA it had - see
     * checkpoint_restore - so it is skipped rather than guessed at here.
     */
    if (saved[i].arena_off < 0)
      continue;
    void *hva = arena_hva_of(saved[i].arena_off);
    if (hva == NULL)
      panic("restoring stage-2: arena offset %lld for IPA 0x%llx is not mapped",
            (long long) saved[i].arena_off, (unsigned long long) saved[i].ipa);
    vmm_arm64_map_stage2(saved[i].ipa, STAGE2_GRANULE, saved[i].prot, hva);
  }
}

/*
 * Re-establish one stage-2 block, to make a stage-1 permission change visible.
 *
 * hv_vm_unmap followed by hv_vm_map is the only thing measured to reliably drop
 * HVF's combined stage-1+2 TLB entries for a block - a guest TLBI does not
 * (PORTING-arm64.md 3.5.3). The mapping itself is unchanged; the registry
 * already knows what backs this block, so this is a flush, not a remap.
 */
/*
 * Re-establish one stage-2 block with a *new* permission.
 *
 * The distinction from a reflush matters more than it looks. A reflush
 * re-applies the permission the block already had, which is right when only the
 * stage-1 descriptors changed shape - but wrong when what changed is the
 * permission itself. A guest that reserves a large range PROT_NONE and
 * mprotects pieces of it readable (malloc's arena, and every allocator like it)
 * gets stage 2 mapped with no access at all, and stage 1 alone cannot grant
 * what stage 2 withholds: the guest faults forever on memory both NABI's tables
 * describe as writable.
 */
void
vmm_arm64_s2_reprotect(gaddr_t ipa, int prot)
{
  gaddr_t base = ipa & ~(STAGE2_GRANULE - 1);
  khiter_t k = kh_get(s2, s2_map, base);
  if (k == kh_end(s2_map))
    return;                    /* nothing mapped there to re-permission */
  vmm_arm64_map_stage2(base, STAGE2_GRANULE, prot, kh_value(s2_map, k).haddr);
}

void
vmm_arm64_s2_reflush(gaddr_t ipa)
{
  khiter_t k = kh_get(s2, s2_map, ipa & ~(STAGE2_GRANULE - 1));
  if (k == kh_end(s2_map))
    return;                    /* nothing mapped there; nothing to flush */
  struct s2_ent ent = kh_value(s2_map, k);
  vmm_arm64_map_stage2(ipa & ~(STAGE2_GRANULE - 1), STAGE2_GRANULE,
                       ent.prot, ent.haddr);
}

/* Replay the whole registry into the current (freshly created) VM. Used by
 * vmm_reentry after fork to restore every stage-2 mapping. */
void
vmm_arm64_replay_stage2(void)
{
  gaddr_t ipa;
  struct s2_ent ent;
  kh_foreach(s2_map, ipa, ent, {
    if (hv_vm_map(ent.haddr, ipa, STAGE2_GRANULE, ent.prot) != HV_SUCCESS)
      panic("hv_vm_map failed replaying stage-2 IPA 0x%llx",
            (unsigned long long) ipa);
  });
}

/* ------------------------------------------------------- VM lifecycle */

/*
 * How many bits of guest-physical address the VM was created with.
 *
 * hv_vm_create(NULL) takes the platform default, which is 36 bits - 64GiB - and
 * the framework will map as much as 40. NABI hands IPAs out with a bump
 * allocator and only reclaims what a guest explicitly unmaps, so the address
 * space is consumed faster than a real machine's would be and running out of it
 * is a real failure rather than a theoretical one. Asking for the maximum costs
 * nothing: an IPA range is not memory, only room to put memory in.
 *
 * Recorded because the panic that reports a failed mapping is much easier to
 * read when it can say how close to the ceiling the request was.
 */
static uint32_t ipa_bits;

uint32_t
vmm_arm64_ipa_bits(void)
{
  return ipa_bits;
}

/*
 * Create the VM with as much guest-physical space as this host allows, falling
 * back to the default if the config API refuses - the fallback is what every
 * build did before, so it can only be as bad as it already was.
 */
static hv_return_t
create_vm_with_max_ipa(void)
{
  uint32_t max = 0;
  hv_vm_config_t cfg = hv_vm_config_create();
  hv_return_t ret = HV_ERROR;

  if (cfg != NULL && hv_vm_config_get_max_ipa_size(&max) == HV_SUCCESS &&
      hv_vm_config_set_ipa_size(cfg, max) == HV_SUCCESS) {
    ret = hv_vm_create(cfg);
    if (ret == HV_SUCCESS)
      ipa_bits = max;
  }
  /* Released either way. arm64's fork is fork-plus-exec and each side rebuilds
   * the VM, so a config held here would be leaked once per guest fork rather
   * than once per run. */
  if (cfg != NULL)
    os_release(cfg);
  if (ret == HV_SUCCESS)
    return ret;

  ipa_bits = 0;
  if (hv_vm_config_get_default_ipa_size(&ipa_bits) != HV_SUCCESS)
    ipa_bits = 36;
  return hv_vm_create(NULL);
}

void
vmm_create(void)
{
  hv_return_t ret;

  pthread_rwlock_init(&alloc_lock, NULL);
  INIT_LIST_HEAD(&vcpus);
  nr_vcpus = 0;
  s2_map = kh_init(s2);

  ret = create_vm_with_max_ipa();
  if (ret != HV_SUCCESS) {
    panic("could not create the vm: error code %x%s", ret,
          ret == HV_DENIED ? " (missing com.apple.security.hypervisor?)" : "");
    return;
  }

  vmm_create_vcpu(NULL);
}

void
vmm_destroy(void)
{
  struct vcpu *v;
  list_for_each_entry (v, &vcpus, list) {
    if (hv_vcpu_destroy(v->vcpuid) != HV_SUCCESS) {
      panic("could not destroy the vcpu");
      exit(1);
    }
  }

  printk("successfully destroyed the vcpu\n");

  if (hv_vm_destroy() != HV_SUCCESS) {
    panic("could not destroy the vm");
    exit(1);
  }

  printk("successfully destroyed the vm\n");

  /*
   * Reset the vCPU bookkeeping so a following vmm_reentry (fork) can recreate
   * from a clean slate - vmm_create_vcpu asserts vcpu == NULL. Single-threaded
   * only, which the fork path guards; the thread-local vcpu is the sole entry.
   * The stage-2 registry is deliberately left intact: reentry replays it.
   */
  free(vcpu);
  vcpu = NULL;
  INIT_LIST_HEAD(&vcpus);
  nr_vcpus = 0;
}

void
vmm_create_vcpu(struct vcpu_snapshot *snapshot)
{
  hv_vcpu_t vcpuid;
  hv_vcpu_exit_t *vexit;

  /* Must be called on the thread that will run this vCPU: the framework binds
   * the vCPU to its creating thread. */
  if (hv_vcpu_create(&vcpuid, &vexit, NULL) != HV_SUCCESS) {
    panic("could not create a vcpu");
    return;
  }

  assert(vcpu == NULL);

  vcpu = calloc(1, sizeof(struct vcpu));
  vcpu->vcpuid = vcpuid;
  vcpu->vexit = vexit;

  if (snapshot) {
    vmm_restore_vcpu(snapshot);
  }

  pthread_rwlock_wrlock(&alloc_lock);
  list_add(&vcpu->list, &vcpus);
  nr_vcpus++;
  pthread_rwlock_unlock(&alloc_lock);
}

/*
 * Force every other thread's vCPU out of hv_vcpu_run.
 *
 * A thread executing guest code is inside hv_vcpu_run and will not look at any
 * flag we set until it comes back - and it need not come back at all, since a
 * guest loop with no syscalls in it runs forever. hv_vcpus_exit is the framework's
 * way to interrupt that; the interrupted run returns HV_EXIT_REASON_CANCELED,
 * which the decoder already reports as EXIT_RESUME, so the thread simply comes
 * round its loop and can be told to stop there.
 */
void
vmm_kick_other_vcpus(void)
{
  hv_vcpu_t ids[64];
  uint32_t n = 0;

  pthread_rwlock_rdlock(&alloc_lock);
  struct vcpu *v;
  list_for_each_entry (v, &vcpus, list) {
    if (v != vcpu && n < (uint32_t)(sizeof ids / sizeof ids[0]))
      ids[n++] = v->vcpuid;
  }
  pthread_rwlock_unlock(&alloc_lock);

  if (n > 0)
    hv_vcpus_exit(ids, n);
}

void
vmm_destroy_vcpu(void)
{
  pthread_rwlock_wrlock(&alloc_lock);
  list_del(&vcpu->list);
  nr_vcpus--;
  hv_vcpu_destroy(vcpu->vcpuid);
  free(vcpu);
  vcpu = NULL;
  pthread_rwlock_unlock(&alloc_lock);
}

/* ---------------------------------------------------------- accessors */

void
vmm_arm64_read_reg(hv_reg_t reg, uint64_t *val)
{
  if (hv_vcpu_get_reg(vcpu->vcpuid, reg, val) != HV_SUCCESS)
    panic("hv_vcpu_get_reg(%u) failed", reg);
}

void
vmm_arm64_write_reg(hv_reg_t reg, uint64_t val)
{
  if (hv_vcpu_set_reg(vcpu->vcpuid, reg, val) != HV_SUCCESS)
    panic("hv_vcpu_set_reg(%u) failed", reg);
}

void
vmm_arm64_read_sysreg(hv_sys_reg_t reg, uint64_t *val)
{
  if (hv_vcpu_get_sys_reg(vcpu->vcpuid, reg, val) != HV_SUCCESS)
    panic("hv_vcpu_get_sys_reg(%u) failed", reg);
}

void
vmm_arm64_write_sysreg(hv_sys_reg_t reg, uint64_t val)
{
  if (hv_vcpu_set_sys_reg(vcpu->vcpuid, reg, val) != HV_SUCCESS)
    panic("hv_vcpu_set_sys_reg(%u) failed", reg);
}

int
vmm_enter(void)
{
  hv_return_t r = hv_vcpu_run(vcpu->vcpuid);
  if (r == HV_SUCCESS)
    return 0;
  /*
   * The framework refusing to run the vcpu, which the -1 below says nothing
   * about. It is the bottom of the stack of ways a guest can stop without
   * saying why: everything above this reports itself now, and this did not, so
   * a guest that ended here ended in silence and looked from the outside like
   * one that had simply stopped making syscalls.
   */
  warnk("hv_vcpu_run failed: 0x%x\n", (unsigned) r);
  return -1;
}

/* Read/write a single 128-bit SIMD&FP register (V0..V31). Kept here, like the
 * reset below, because they need the vcpu handle that stays private to this
 * file; the signal frame saves and restores the FP state across handler
 * delivery. */
void
vmm_arm64_read_simd(hv_simd_fp_reg_t reg, void *out16)
{
  hv_simd_fp_uchar16_t v;
  if (hv_vcpu_get_simd_fp_reg(vcpu->vcpuid, reg, &v) != HV_SUCCESS)
    panic("hv_vcpu_get_simd_fp_reg(%u) failed", reg);
  memcpy(out16, &v, 16);
}

void
vmm_arm64_write_simd(hv_simd_fp_reg_t reg, const void *in16)
{
  hv_simd_fp_uchar16_t v;
  memcpy(&v, in16, 16);
  if (hv_vcpu_set_simd_fp_reg(vcpu->vcpuid, reg, v) != HV_SUCCESS)
    panic("hv_vcpu_set_simd_fp_reg(%u) failed", reg);
}

/* Zero the FP/SIMD register file. Kept here rather than in the exit file
 * because it needs the vcpu handle, which stays private to this file. */
void
vmm_arm64_reset_fpsimd(void)
{
  const hv_simd_fp_uchar16_t zero = {0};
  for (hv_simd_fp_reg_t q = HV_SIMD_FP_REG_Q0; q <= HV_SIMD_FP_REG_Q31; q++) {
    if (hv_vcpu_set_simd_fp_reg(vcpu->vcpuid, q, zero) != HV_SUCCESS)
      panic("hv_vcpu_set_simd_fp_reg(%u) failed", q);
  }
}

/* --------------------------------------------------- code coherency */

/*
 * Make host-written bytes executable by the guest.
 *
 * Required, not advisory. Anything the host writes into guest memory that the
 * guest will then *execute* - an ELF image, the trampoline below, a signal
 * return stub - is invisible to the guest's instruction fetch until this is
 * called. Without it the guest runs whatever was at those addresses before,
 * which presents as the guest executing stale or garbage code rather than as
 * anything resembling a cache problem.
 *
 * Measured: sys_icache_invalidate alone is sufficient, sys_dcache_flush alone
 * is NOT. The stale party is the instruction path, and sys_icache_invalidate
 * issues the `dc cvau` / `ic ivau` pair that fixes it; cleaning the data cache
 * without invalidating the instruction cache changes nothing.
 *
 * x86 needs no equivalent - its caches are coherent with instruction fetch - so
 * there is no counterpart in lib/vmm_x86.c and nothing in the existing tree
 * calls anything like this. The ELF loader will have to.
 */
void
vmm_arm64_sync_guest_code(void *hva, size_t len)
{
  sys_icache_invalidate(hva, len);
}

/*
 * vmm_sync_guest_code (include/arch.h): the neutral entry the loader calls.
 * Resolves the guest virtual address to its host backing and invalidates the
 * instruction cache over it. The region must already be mapped - the loader
 * maps a segment before writing it - so guest_to_host resolves.
 *
 * The range is walked region by region rather than assumed contiguous, because
 * a segment can straddle two: when a segment is not granule-aligned the loader
 * maps its shared first page inside the *previous* segment's region, so a
 * segment's executable bytes begin in one host buffer and continue in another.
 */
void
vmm_sync_guest_code(gaddr_t gaddr, size_t len)
{
  while (len > 0) {
    struct mm_region *r = find_region(gaddr, proc.mm);
    if (!r) {
      break;
    }
    size_t piece = MIN(len, r->gaddr + r->size - gaddr);
    void *hva = guest_to_host(gaddr);
    if (hva) {
      vmm_arm64_sync_guest_code(hva, piece);
    }
    gaddr += piece;
    len -= piece;
  }
}

/* -------------------------------------------------------- trampoline */

/*
 * Install the EL1 trampoline and point VBAR_EL1 at it.
 *
 * `hva` is where the host can write, `ipa` is where the guest sees it; the
 * caller has already mapped one onto the other. `ipa` must be 2KiB-aligned for
 * VBAR_EL1, which the 16KiB stage-2 granule guarantees anyway.
 *
 * The stub is deliberately two instructions and clobbers nothing. It cannot
 * afford a scratch register: on entry the guest's x0-x30 are live and a real
 * svc must preserve all of them except the return value. Discriminating svc
 * from a fault therefore happens on the host, which reads ESR_EL1 after the
 * exit - see vmm_arm64_exit.c. The alternative, saving a register to an EL1
 * stack inside the stub, would need SP_EL1 set up and is pure cost for
 * information the host can already reach.
 */
void
vmm_arm64_install_trampoline(void *hva, gaddr_t ipa)
{
  assert((ipa & (VBAR_ALIGN - 1)) == 0);

  uint32_t *vec = hva;

  /* Fill the whole table with brk so an unexpected vector is loud rather than
   * a silent walk into neighbouring code. */
  for (size_t i = 0; i < VEC_TABLE_SIZE / sizeof(uint32_t); i++)
    vec[i] = INSN_BRK0;

  uint32_t *sync = (uint32_t *)((char *) hva + VEC_LOWER64_SYNC);
  sync[0] = INSN_HVC1;   /* -> host */
  sync[1] = INSN_ERET;   /* <- host, back to EL0 via ELR_EL1/SPSR_EL1 */

  vmm_arm64_sync_guest_code(hva, VEC_TABLE_SIZE);
  vmm_arm64_write_sysreg(HV_SYS_REG_VBAR_EL1, ipa);
}

/*
 * Bring the vCPU up in a state a guest can run in.
 *
 * The MMU stays off (SCTLR_EL1.M clear) until stage-1 tables exist; with it
 * clear both EL0 and EL1 address memory flat through stage 2, which is exactly
 * what the Phase 0 spike ran in.
 *
 * CPACR_EL1 matters more than it looks: without FPEN the first FP or SIMD
 * instruction the guest executes traps as EC_SIMD_FP, and on aarch64 that is
 * essentially immediate - a plain memcpy in libc uses V registers.
 */
void
vmm_arm64_init_vcpu(void)
{
  vmm_arm64_write_sysreg(HV_SYS_REG_SCTLR_EL1, SCTLR_EL1_RES1);
  vmm_arm64_write_sysreg(HV_SYS_REG_CPACR_EL1, CPACR_EL1_FPEN_NOTRAP);
  vmm_arm64_write_sysreg(HV_SYS_REG_MAIR_EL1, MAIR_EL1_VALUE);
  vmm_arm64_write_sysreg(HV_SYS_REG_TCR_EL1, TCR_EL1_FOR(ipa_bits));
}

/*
 * Drop to EL0 at `pc` with stack `sp`.
 *
 * Implemented as an eret from EL1 rather than by setting CPSR to EL0t directly,
 * because that is how every subsequent return to EL0 will happen anyway - the
 * trampoline's eret uses the same two registers - so there is one path to get
 * wrong instead of two.
 */
void
vmm_arm64_enter_el0(gaddr_t pc, gaddr_t sp, gaddr_t el1_eret_stub)
{
  vmm_arm64_write_sysreg(HV_SYS_REG_SP_EL0, sp);
  vmm_arm64_write_sysreg(HV_SYS_REG_ELR_EL1, pc);
  vmm_arm64_write_sysreg(HV_SYS_REG_SPSR_EL1, PSR_EL0);
  vmm_arm64_write_reg(HV_REG_PC, el1_eret_stub);
  vmm_arm64_write_reg(HV_REG_CPSR, PSR_EL1);
}

/* ------------------------------------------------ snapshot / restore (Phase 4)
 *
 * fork and multi-threaded clone snapshot a vCPU and restore it into a fresh VM.
 * HVF allows only one VM per process, so fork tears the VM down and both sides
 * rebuild it (src/proc/fork.c): snapshot the vCPU, hv_vm_destroy, host fork(),
 * then hv_vm_create + replay the stage-2 registry + restore the vCPU on each
 * side. The counterpart of the x86 register-list/VMCS/fxsave dance in vmm_x86.c.
 */
void
vmm_snapshot_vcpu(struct vcpu_snapshot *snapshot)
{
  for (int i = 0; i <= 30; i++)
    vmm_arm64_read_reg(HV_REG_X0 + i, &snapshot->x[i]);
  vmm_arm64_read_sysreg(HV_SYS_REG_SP_EL0, &snapshot->sp);
  vmm_arm64_read_reg(HV_REG_PC, &snapshot->pc);
  vmm_arm64_read_reg(HV_REG_CPSR, &snapshot->pstate);
  vmm_arm64_read_sysreg(HV_SYS_REG_ELR_EL1, &snapshot->elr_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_SPSR_EL1, &snapshot->spsr_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_TPIDR_EL0, &snapshot->tpidr_el0);

  /* The address-space control registers, so reentry needs no reach into the
   * page-table or machine-setup layers to rebuild them. */
  vmm_arm64_read_sysreg(HV_SYS_REG_SCTLR_EL1, &snapshot->sctlr_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_CPACR_EL1, &snapshot->cpacr_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_MAIR_EL1, &snapshot->mair_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_TCR_EL1, &snapshot->tcr_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_TTBR0_EL1, &snapshot->ttbr0_el1);
  vmm_arm64_read_sysreg(HV_SYS_REG_VBAR_EL1, &snapshot->vbar_el1);

  vmm_arm64_read_reg(HV_REG_FPCR, &snapshot->fpcr);
  vmm_arm64_read_reg(HV_REG_FPSR, &snapshot->fpsr);
  for (int i = 0; i < 32; i++)
    vmm_arm64_read_simd(HV_SIMD_FP_REG_Q0 + i, &snapshot->v[i]);
}

void
vmm_snapshot(struct vmm_snapshot *snapshot)
{
  pthread_rwlock_rdlock(&alloc_lock);
  if (nr_vcpus > 1) {
    fprintf(stderr, "multi-threaded fork is not implemented yet.\n");
    exit(1);
  }
  vmm_snapshot_vcpu(&snapshot->first_vcpu_snapshot);
  pthread_rwlock_unlock(&alloc_lock);
}

void
vmm_restore_vcpu(struct vcpu_snapshot *snapshot)
{
  /*
   * The control registers first, and SCTLR (which carries the MMU-enable bit)
   * last of them, so translation only turns on once its table base, attributes
   * and vector base are all in place.
   */
  vmm_arm64_write_sysreg(HV_SYS_REG_MAIR_EL1, snapshot->mair_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_TCR_EL1, snapshot->tcr_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_TTBR0_EL1, snapshot->ttbr0_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_VBAR_EL1, snapshot->vbar_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_CPACR_EL1, snapshot->cpacr_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_SCTLR_EL1, snapshot->sctlr_el1);

  for (int i = 0; i <= 30; i++)
    vmm_arm64_write_reg(HV_REG_X0 + i, snapshot->x[i]);
  vmm_arm64_write_sysreg(HV_SYS_REG_SP_EL0, snapshot->sp);
  vmm_arm64_write_reg(HV_REG_PC, snapshot->pc);
  vmm_arm64_write_reg(HV_REG_CPSR, snapshot->pstate);
  vmm_arm64_write_sysreg(HV_SYS_REG_ELR_EL1, snapshot->elr_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_SPSR_EL1, snapshot->spsr_el1);
  vmm_arm64_write_sysreg(HV_SYS_REG_TPIDR_EL0, snapshot->tpidr_el0);
  vmm_arm64_write_reg(HV_REG_FPCR, snapshot->fpcr);
  vmm_arm64_write_reg(HV_REG_FPSR, snapshot->fpsr);
  for (int i = 0; i < 32; i++)
    vmm_arm64_write_simd(HV_SIMD_FP_REG_Q0 + i, &snapshot->v[i]);
}

void
vmm_reentry(struct vmm_snapshot *snapshot)
{
  hv_return_t ret;
  bool retried = false;
retry:
  ret = create_vm_with_max_ipa();
  if (ret != HV_SUCCESS) {
    /* HVF hands the just-destroyed VM's resources back asynchronously; a single
     * yield-and-retry is enough to let that settle, matching the x86 path. */
    if (!retried && ret == HV_NO_DEVICE) {
      sleep(0);
      retried = true;
      goto retry;
    }
    panic("vmm_reentry: could not create the vm: error code %x", ret);
  }

  /* Guest memory (RAM, page tables, trampoline, sigreturn page) survived as host
   * allocations; put every stage-2 mapping back into the fresh VM. */
  vmm_arm64_replay_stage2();

  /* Fresh vCPU, then restore all of its state - general registers, the banked
   * EL0 state, and the control registers (including the MMU-enable bit) - from
   * the snapshot. vmm_create_vcpu asserts vcpu == NULL, which vmm_destroy left. */
  vmm_create_vcpu(NULL);
  vmm_restore_vcpu(&snapshot->first_vcpu_snapshot);
}
