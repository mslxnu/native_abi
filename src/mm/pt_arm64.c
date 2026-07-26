/*
 * aarch64 stage-1 translation tables.
 *
 * Replaces the x86 pml4/pdp pair in src/mm/mm.c and the 512 generated entries
 * in src/mm/pdp.h. See PORTING-arm64.md sections 3.5 and 3.5.1.
 *
 * The layout is a 39-bit VA space with a 4KiB granule, which walks three
 * levels:
 *
 *   level 1   bits 38:30   1GiB per entry   (table or block)
 *   level 2   bits 29:21   2MiB per entry   (table or block)
 *   level 3   bits 20:12   4KiB per entry   (page)
 *
 * TTBR0_EL1 points at the level-1 table. There is no level 0 - T0SZ=25 makes
 * the walk start at level 1 - and no TTBR1 at all, because the guest has no
 * high half (TCR_EL1.EPD1 disables it).
 *
 * ---------------------------------------------------------------------------
 * The two-granule problem
 *
 * Stage 2 (IPA -> host, via hv_vm_map) is fixed at 16KiB by the framework, on
 * host address, IPA and size alike. Stage 1 (VA -> IPA, these tables) is ours,
 * and is 4KiB because that is what aarch64 Linux userland expects.
 *
 * So a guest 4KiB mapping cannot be one hv_vm_map call. Instead:
 *
 *   - Guest physical space is carved into 16KiB stage-2 chunks, each backed by
 *     one 16KiB host allocation and mapped once with hv_vm_map.
 *   - A 4KiB guest page is a level-3 descriptor pointing at a 4KiB-aligned IPA
 *     *inside* one of those chunks.
 *
 * The guest therefore only ever sees the pages it was actually given, even
 * though the host mapped memory around them. Rounding stage 2 up per guest page
 * instead would publish the three neighbouring 4KiB pages into the guest's
 * address space, which is an isolation bug rather than an accounting one.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "noah.h"
#include "mm.h"
#include "vmm.h"
#include "page.h"
#include "arm64/vm.h"
#include "linux/mman.h"
#include "checkpoint.h"

/*
 * A 16KiB stage-2 chunk: one host allocation, one hv_vm_map, four 4KiB guest
 * pages' worth of room.
 */
struct s2_chunk {
  void    *hva;       /* where this process sees it */
  off_t    off;       /* where it lives in the arena - what survives a handover */
  gaddr_t  ipa;
  unsigned used;      /* 4KiB slots handed out, 0..PAGES_PER_CHUNK */
};

#define PAGES_PER_CHUNK (STAGE2_GRANULE / PAGE_SIZEOF(PAGE_4KB))   /* 4 */

/*
 * Guest-physical allocation cursor. IPAs are ours to assign - nothing outside
 * the guest observes them - so they are handed out linearly from a base chosen
 * to stay clear of the low addresses a guest might use as a null-ish sentinel.
 */
#define IPA_BASE 0x40000000UL

static gaddr_t   ipa_brk = IPA_BASE;
static struct s2_chunk cur_chunk;

/*
 * Every chunk handed out, so an IPA can be turned back into a host pointer.
 *
 * The tree's guest_to_host() walks the mm_region bookkeeping in src/mm/mm.c,
 * which does not know about these chunks - they are guest-physical space this
 * allocator owns, below the mm layer. Table walks need the reverse lookup
 * (a descriptor holds an IPA; writing the next level needs the host address),
 * so keep it here.
 *
 * A flat array is deliberate. Lookups happen only while building tables, never
 * on a fault path, and the count is small; a tree would be more code for no
 * measurable gain.
 */
#define MAX_CHUNKS 4096
static struct s2_chunk chunks[MAX_CHUNKS];
static size_t nr_chunks;

static void *
ipa_to_host(gaddr_t ipa)
{
  for (size_t i = 0; i < nr_chunks; i++) {
    if (ipa >= chunks[i].ipa && ipa < chunks[i].ipa + STAGE2_GRANULE)
      return (char *) chunks[i].hva + (ipa - chunks[i].ipa);
  }
  panic("no stage-2 chunk backs IPA 0x%llx", (unsigned long long) ipa);
  return NULL;
}

/*
 * Hand out one 4KiB slot of guest-physical space, backed by host memory.
 *
 * Chunks are filled before a new one is allocated, so four consecutive 4KiB
 * requests cost one hv_vm_map rather than four.
 */
static void *
alloc_guest_page(gaddr_t *ipa_out)
{
  if (cur_chunk.hva == NULL || cur_chunk.used == PAGES_PER_CHUNK) {
    /*
     * From the guest-physical arena, not the C heap. The arena is file-backed,
     * so this chunk can be handed to a process that has had to exec - which is
     * how fork has to work on Apple Silicon (see src/mm/arena.c). It is also
     * simply the right home for memory owned by the guest rather than by us:
     * hv_vm_map needs it 16KiB-aligned, which the arena guarantees, and a fresh
     * arena range reads as zero.
     */
    off_t arena_off;
    void *hva = arena_alloc(STAGE2_GRANULE, &arena_off);

    cur_chunk.hva  = hva;
    cur_chunk.off  = arena_off;
    cur_chunk.ipa  = ipa_brk;
    cur_chunk.used = 0;
    ipa_brk += STAGE2_GRANULE;

    vmm_arm64_map_stage2(cur_chunk.ipa, STAGE2_GRANULE,
             HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, cur_chunk.hva);

    if (nr_chunks == MAX_CHUNKS)
      panic("stage-2 chunk table full");
    chunks[nr_chunks++] = cur_chunk;
  }

  size_t off = (size_t) cur_chunk.used * PAGE_SIZEOF(PAGE_4KB);
  cur_chunk.used++;

  *ipa_out = cur_chunk.ipa + off;
  return (char *) cur_chunk.hva + off;
}

/* ------------------------------------------------------------- tables */

/*
 * Translation tables are themselves guest pages: the hardware walks them
 * through stage 2, so they need an IPA, not just a host address. Each table is
 * one 4KiB page of 512 descriptors, so it fits a single slot from
 * alloc_guest_page.
 */
struct table {
  uint64_t *entries;   /* host view  */
  gaddr_t   ipa;       /* guest view, what a descriptor points at */
};

static struct table l1_table;

static struct table
alloc_table(void)
{
  struct table t;
  gaddr_t ipa;
  t.entries = alloc_guest_page(&ipa);
  t.ipa = ipa;
  /* alloc_guest_page zeroes the whole chunk on first use, but a later slot in
   * a partially used chunk is only zero because nothing wrote it. Be explicit;
   * a stray non-zero descriptor is a fault that is very hard to read. */
  memset(t.entries, 0, PAGE_SIZEOF(PAGE_4KB));
  return t;
}

#define L1_INDEX(va) (((va) >> PAGE_SHIFTOF(PAGE_1GB)) & (NR_PAGE_ENTRY - 1))
#define L2_INDEX(va) (((va) >> PAGE_SHIFTOF(PAGE_2MB)) & (NR_PAGE_ENTRY - 1))
#define L3_INDEX(va) (((va) >> PAGE_SHIFTOF(PAGE_4KB)) & (NR_PAGE_ENTRY - 1))

/* The output address field of a descriptor is bits [47:12]. */
#define PTE_ADDR_MASK 0x0000FFFFFFFFF000ULL

/*
 * Walk to the level-3 descriptor for `va`, creating intermediate tables as
 * needed. Returns a host pointer to the descriptor slot.
 */
static uint64_t *
walk_to_l3(gaddr_t va)
{
  assert(l1_table.entries != NULL);

  uint64_t *l1e = &l1_table.entries[L1_INDEX(va)];
  if ((*l1e & PTE_VALID) == 0) {
    struct table l2 = alloc_table();
    *l1e = (l2.ipa & PTE_ADDR_MASK) | PTE_TABLE | PTE_VALID;
  }
  uint64_t *l2_entries = ipa_to_host(*l1e & PTE_ADDR_MASK);

  uint64_t *l2e = &l2_entries[L2_INDEX(va)];
  if ((*l2e & PTE_VALID) == 0) {
    struct table l3 = alloc_table();
    *l2e = (l3.ipa & PTE_ADDR_MASK) | PTE_TABLE | PTE_VALID;
  }
  uint64_t *l3_entries = ipa_to_host(*l2e & PTE_ADDR_MASK);

  return &l3_entries[L3_INDEX(va)];
}

/*
 * Translate Linux mprot bits into descriptor permission bits.
 *
 * AP is inverted relative to the x86 PTE_W/PTE_U scheme and easy to get wrong:
 * AP[1] (PTE_AP_RW_EL0) *grants* EL0 access, and AP[2] (PTE_AP_RO) *removes*
 * write. Execute is likewise negative - UXN and PXN are execute-NEVER - so an
 * executable page is one where they are clear.
 *
 * PXN is set unconditionally: the guest's code runs at EL0 and nothing should
 * ever be executable at EL1 except the trampoline, which is mapped separately.
 */
static uint64_t
prot_to_pte(int prot)
{
  uint64_t pte = PTE_AF | PTE_SH_INNER | PTE_ATTR(MAIR_IDX_NORMAL) |
                 PTE_AP_RW_EL0 | PTE_PXN;

  if ((prot & LINUX_PROT_WRITE) == 0)
    pte |= PTE_AP_RO;
  if ((prot & LINUX_PROT_EXEC) == 0)
    pte |= PTE_UXN;

  return pte;
}

/*
 * Map one 4KiB guest virtual page onto a 4KiB guest-physical page.
 *
 * The access flag is set eagerly (PTE_AF). Hardware AF management is optional
 * on ARMv8 and a descriptor without it faults on first touch; since nothing
 * here uses AF for page aging, setting it up front avoids a fault that would
 * have to be handled for no benefit.
 */
void
pt_map_page(gaddr_t va, gaddr_t ipa, int prot)
{
  assert((va & (PAGE_SIZEOF(PAGE_4KB) - 1)) == 0);
  assert((ipa & (PAGE_SIZEOF(PAGE_4KB) - 1)) == 0);

  uint64_t *l3e = walk_to_l3(va);
  *l3e = (ipa & PTE_ADDR_MASK) | prot_to_pte(prot) | PTE_PAGE | PTE_VALID;
}

/*
 * Allocate a fresh 4KiB guest page and map it at `va`. Returns the host
 * pointer, so the caller can populate it.
 */
void *
pt_alloc_and_map(gaddr_t va, int prot)
{
  gaddr_t ipa;
  void *hva = alloc_guest_page(&ipa);
  pt_map_page(va, ipa, prot);
  return hva;
}

/*
 * Map the EL1 vector page.
 *
 * The trampoline is the one thing that runs at EL1, so it is the one page that
 * must have PXN *clear* - the opposite of every other mapping, which sets PXN
 * unconditionally so nothing but the trampoline is ever privileged-executable.
 * It is also made inaccessible to EL0 (AP[1] clear, UXN set): the guest has no
 * business reading or executing its own exception vector.
 *
 * Separate from pt_map_page rather than a prot flag, because "executable at
 * EL1" is not a Linux mprot bit and pretending it is would put an
 * architecture-specific concept into the generic mapping path.
 */
void *
pt_map_vector(gaddr_t va)
{
  gaddr_t ipa;
  void *hva = alloc_guest_page(&ipa);

  uint64_t pte = PTE_AF | PTE_SH_INNER | PTE_ATTR(MAIR_IDX_NORMAL) |
                 PTE_UXN;   /* EL1-exec (PXN clear), no EL0 access, no EL0 exec */

  uint64_t *l3e = walk_to_l3(va);
  *l3e = (ipa & PTE_ADDR_MASK) | pte | PTE_PAGE | PTE_VALID;
  return hva;
}

/*
 * Build the empty level-1 table and point TTBR0_EL1 at it.
 *
 * Does NOT enable the MMU: SCTLR_EL1.M stays clear until the caller has mapped
 * enough for the guest to run, because turning translation on with an empty
 * table means the very next instruction fetch faults.
 */
void
pt_init(void)
{
  ipa_brk = IPA_BASE;
  nr_chunks = 0;
  memset(&cur_chunk, 0, sizeof cur_chunk);

  l1_table = alloc_table();

  vmm_arm64_write_sysreg(HV_SYS_REG_MAIR_EL1, MAIR_EL1_VALUE);
  vmm_arm64_write_sysreg(HV_SYS_REG_TCR_EL1, TCR_EL1_VALUE);
  vmm_arm64_write_sysreg(HV_SYS_REG_TTBR0_EL1, l1_table.ipa);
}

/*
 * Turn stage-1 translation on, with the caches enabled.
 *
 * Separate from pt_init so the caller controls the moment: everything the guest
 * touches next - its code, its stack, the trampoline - must already be mapped,
 * or the first fetch after this faults with no way to make progress.
 *
 * SCTLR_EL1.C and .I are not an optimization here, they are correctness. With
 * .C clear the CPU treats every access as Non-cacheable no matter what MAIR
 * says, and load/store-exclusive and the LSE atomics are not supported on
 * Non-cacheable memory: the guest's first LDXR/STXR (or a glibc lock) takes a
 * data abort with DFSC 0x35, "unsupported exclusive or atomic access", which
 * presents as an unkillable fault loop rather than anything mentioning caches.
 * The page tables already ask for Normal Write-Back Inner-Shareable memory
 * (MAIR_ATTR_NORMAL + PTE_SH_INNER), so enabling the caches is what makes the
 * attributes the descriptors request actually take effect.
 */
void
pt_enable(void)
{
  uint64_t sctlr;
  vmm_arm64_read_sysreg(HV_SYS_REG_SCTLR_EL1, &sctlr);
  vmm_arm64_write_sysreg(HV_SYS_REG_SCTLR_EL1,
                         sctlr | SCTLR_EL1_M | SCTLR_EL1_C | SCTLR_EL1_I);
}

gaddr_t
pt_root_ipa(void)
{
  return l1_table.ipa;
}

/* ------------------------------------------------------- vmm_mmap */

/*
 * The arch-neutral vmm_mmap, arm64 side. Its x86 counterpart in
 * lib/vmm_x86.c is a single hv_vm_map because x86 has one translation stage;
 * here it drives both.
 *
 * `gaddr` is a guest *virtual* address and `haddr` is host memory the caller
 * already holds - on the mmap path, the Darwin mmap of an anonymous region or a
 * file. That host pointer becomes the stage-2 backing directly, which is the
 * good case worth calling out: for a MAP_SHARED file mapping `haddr` is the
 * file's page cache, so writes reach the file, and the mapping is NOT the
 * private-only fallback an earlier draft of the plan feared (§3.5.2). No copy.
 *
 * The two granules are bridged the way §3.5 lays out. hv_vm_map needs 16KiB on
 * host address, IPA and size; a Darwin mmap pointer is 16KiB-aligned and its
 * allocation is rounded up to a host page, so mapping roundup(size, 16KiB) of
 * it is always in bounds. The guest VA need not be 16KiB-aligned, but the IPA
 * is ours to pick, so a 16KiB-aligned IPA block is allocated for the region and
 * stage 1 maps each 4KiB VA page onto its 4KiB offset within.
 *
 * The stage-2 block can be up to ~12KiB larger than the logical region (the
 * rounding), but the guest cannot reach the tail: stage 1 only maps the VA
 * range, so there is no VA that translates into the extra IPA. And that tail is
 * the caller's own mmap reservation regardless, so there is nothing to leak.
 */
void
vmm_mmap(gaddr_t gaddr, size_t size, int prot, void *haddr)
{
  assert((gaddr & (PAGE_SIZEOF(PAGE_4KB) - 1)) == 0);
  assert(((uintptr_t) haddr & (STAGE2_GRANULE - 1)) == 0);

  size_t s2_size = roundup(size, STAGE2_GRANULE);

  /* One 16KiB-aligned IPA block for the whole region, reserved before any
   * stage-1 page is mapped so table growth (which also draws from ipa_brk)
   * cannot land inside it. */
  gaddr_t ipa = ipa_brk;
  ipa_brk += s2_size;

  vmm_arm64_map_stage2(ipa, s2_size, prot, haddr);

  for (size_t off = 0; off < size; off += PAGE_SIZEOF(PAGE_4KB))
    pt_map_page(gaddr + off, ipa + off, prot);
}

/*
 * Not implemented yet.
 *
 * do_munmap only reaches here for a region that already exists, and a fresh
 * exec address space has none, so ELF loading never calls it - which is what
 * this commit needs. A real munmap / mprotect / MAP_FIXED remap does, and doing
 * it right means clearing the stage-1 PTEs (with a TLB invalidate the framework
 * does not expose directly), unmapping the stage-2 block and reclaiming the
 * IPA. Panic rather than silently leave the guest able to reach freed memory.
 */
/*
 * Read-only walk: the level-3 descriptor for `va`, or NULL if any level of the
 * walk is missing. Unlike walk_to_l3 it never allocates - for unmapping an
 * address that may not be fully mapped.
 */
static uint64_t *
walk_existing(gaddr_t va)
{
  if (l1_table.entries == NULL)
    return NULL;
  uint64_t *l1e = &l1_table.entries[L1_INDEX(va)];
  if ((*l1e & PTE_VALID) == 0)
    return NULL;
  uint64_t *l2 = ipa_to_host(*l1e & PTE_ADDR_MASK);
  uint64_t *l2e = &l2[L2_INDEX(va)];
  if ((*l2e & PTE_VALID) == 0)
    return NULL;
  uint64_t *l3 = ipa_to_host(*l2e & PTE_ADDR_MASK);
  return &l3[L3_INDEX(va)];
}

/*
 * Is any stage-1 page still mapped into the 16KiB stage-2 block that backs
 * guest-physical `ipa`, other than within [va_lo, va_hi)?
 *
 * The block's four 4KiB slots correspond to four contiguous guest VAs, and VA
 * and IPA are congruent modulo 16KiB within a region (see PORTING-arm64.md
 * 3.5.2), so the block's VAs are derivable from one page's (va, ipa) without
 * any reverse map: va_block_base = va - (ipa mod 16KiB).
 */
static bool
block_has_survivor(gaddr_t va, gaddr_t ipa, gaddr_t va_lo, gaddr_t va_hi)
{
  gaddr_t block_base_ipa = ipa & ~(STAGE2_GRANULE - 1);
  gaddr_t va_block_base = va - (ipa & (STAGE2_GRANULE - 1));

  for (int j = 0; j < (int)(STAGE2_GRANULE / PAGE_SIZEOF(PAGE_4KB)); j++) {
    gaddr_t cand = va_block_base + (gaddr_t) j * PAGE_SIZEOF(PAGE_4KB);
    if (cand >= va_lo && cand < va_hi)
      continue;                        /* being unmapped, not a survivor */
    uint64_t *pte = walk_existing(cand);
    if (pte && (*pte & PTE_VALID) &&
        (*pte & PTE_ADDR_MASK) >= block_base_ipa &&
        (*pte & PTE_ADDR_MASK) <  block_base_ipa + STAGE2_GRANULE)
      return true;
  }
  return false;
}

/*
 * Unmap a guest VA range.
 *
 * The reliable primitive on Apple Silicon is hv_vm_unmap of a 16KiB stage-2
 * block: it faults subsequent access (measured; the guest's own TLBI does NOT
 * invalidate HVF's combined stage-1+2 TLB entries, so clearing a stage-1 PTE
 * alone is not enough). So this unmaps whole 16KiB blocks that the range fully
 * accounts for, and clears their stage-1 descriptors.
 *
 * The unhandled case is a 16KiB block that still has a live page OUTSIDE the
 * range - a partial munmap that splits a 16KiB block. Making that page's
 * neighbour fault while keeping it mapped needs "evacuation" (re-homing the
 * survivor to a fresh block), which in turn needs the survivor's mm_region
 * backing to move with it - a change to the mmap ownership model, not just the
 * page tables. Until then such a split panics rather than silently leaving the
 * unmapped page reachable through a stale TLB entry. It is rare: whole-region
 * munmap, the common case, never hits it.
 */
void
vmm_munmap(gaddr_t gaddr, size_t size)
{
  gaddr_t va_lo = gaddr;
  gaddr_t va_hi = gaddr + size;
  gaddr_t pagesz = PAGE_SIZEOF(PAGE_4KB);

  for (gaddr_t va = va_lo; va < va_hi; va += pagesz) {
    uint64_t *pte = walk_existing(va);
    if (!pte || !(*pte & PTE_VALID))
      continue;

    gaddr_t ipa = *pte & PTE_ADDR_MASK;

    if (block_has_survivor(va, ipa, va_lo, va_hi)) {
      panic("vmm_munmap: partial unmap splits a 16KiB stage-2 block at "
            "va 0x%llx - evacuation not implemented (see PORTING-arm64.md "
            "3.5.2 / 3.5.3).", (unsigned long long) va);
    }

    /* Clear the stage-1 descriptor and unmap the whole 16KiB stage-2 block.
     * Other slots of the block are either in this range (cleared as we reach
     * them) or unmapped tail, so unmapping the block harms nothing. */
    *pte = 0;
    vmm_arm64_unmap_stage2(ipa & ~(STAGE2_GRANULE - 1), STAGE2_GRANULE);
  }
}

/*
 * The stage-1 allocator's state, for a handover.
 *
 * The tables are guest pages living in the arena, so their *contents* travel
 * with it; what has to be described is where each chunk sits, since ipa_to_host
 * is the only way a descriptor in one table can be followed to the next and it
 * is pure bookkeeping. Returns the number of chunks written.
 */
size_t
pt_snapshot(uint64_t *ipa_brk_out, uint64_t *l1_ipa_out,
            struct checkpoint_pt_chunk *out, size_t max)
{
  if (ipa_brk_out) *ipa_brk_out = ipa_brk;
  if (l1_ipa_out)  *l1_ipa_out  = l1_table.ipa;

  size_t n = nr_chunks < max ? nr_chunks : max;
  for (size_t i = 0; i < n; i++) {
    out[i].ipa       = chunks[i].ipa;
    out[i].arena_off = chunks[i].off;
    out[i].used      = chunks[i].used;
    out[i]._pad      = 0;
  }
  return nr_chunks;
}

/*
 * Rebuild the stage-1 allocator from a checkpoint.
 *
 * The tables themselves are guest pages and came across in the arena, so their
 * contents - every descriptor, every IPA they point at - are already correct.
 * What has to be reconstructed is this file's own bookkeeping: which host
 * address each chunk landed at in *this* process, so ipa_to_host can follow a
 * descriptor from one level to the next, and where the allocator had got to.
 *
 * The caller has already mapped the arena, so each chunk is looked up rather
 * than mapped again - mapping it twice would give the guest two views of one
 * page and let a stale one win.
 */
void
pt_restore(uint64_t saved_ipa_brk, uint64_t l1_ipa,
           const struct checkpoint_pt_chunk *saved, size_t n)
{
  nr_chunks = 0;
  memset(&cur_chunk, 0, sizeof cur_chunk);

  for (size_t i = 0; i < n; i++) {
    void *hva = arena_hva_of(saved[i].arena_off);
    if (hva == NULL)
      panic("restoring stage-1: arena offset %lld for IPA 0x%llx is not mapped",
            (long long) saved[i].arena_off, (unsigned long long) saved[i].ipa);
    if (nr_chunks == MAX_CHUNKS)
      panic("restoring stage-1: too many chunks");
    chunks[nr_chunks++] = (struct s2_chunk){
      .hva = hva,
      .off = saved[i].arena_off,
      .ipa = saved[i].ipa,
      .used = saved[i].used,
    };
  }

  ipa_brk = saved_ipa_brk;

  /* The level-1 table is found the same way any other table is - through the
   * chunk list that was just rebuilt. */
  l1_table.ipa = l1_ipa;
  l1_table.entries = ipa_to_host(l1_ipa);

  /* Point the machine at it. The rest of the control state comes from the vCPU
   * snapshot, which carries TTBR0 as well; setting it here keeps the tables and
   * the register consistent even before that restore runs. */
  vmm_arm64_write_sysreg(HV_SYS_REG_TTBR0_EL1, l1_ipa);
}
