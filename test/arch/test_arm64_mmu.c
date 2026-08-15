/*
 * Hardware test for aarch64 stage-1 translation (src/mm/pt_arm64.c).
 *
 * This is the piece the port could not proceed without knowing: whether a 4KiB
 * guest granule can actually be built on top of a stage 2 that only speaks
 * 16KiB. See PORTING-arm64.md section 3.5.
 *
 * What it proves:
 *   - the guest runs with SCTLR_EL1.M set, translating through our tables
 *   - a guest VA maps to a 4KiB page inside a 16KiB stage-2 chunk
 *   - four consecutive 4KiB pages share one hv_vm_map, and stay distinct
 *   - permissions are enforced per 4KiB page, not per 16KiB chunk - which is
 *     the property that makes the sub-mapping worth doing at all
 *   - unmapped VAs fault rather than aliasing onto something else
 */

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vmm.h"
#include "arch.h"
#include "mm.h"
#include "page.h"
#include "arm64/vm.h"
#include "linux/mman.h"
#include "linux/signal.h"

/* From src/mm/pt_arm64.c */
void    pt_init(void);
void    pt_enable(void);
void    pt_map_page(gaddr_t va, gaddr_t ipa, int prot);
void   *pt_alloc_and_map(gaddr_t va, int prot);
void   *pt_map_vector(gaddr_t va);
gaddr_t pt_root_ipa(void);

/* ------------------------------------------------------------- layout */

#define VA_CODE   0x100000UL     /* guest VA the payload runs at */
#define VA_STACK  0x200000UL
#define VA_DATA   0x300000UL
#define VA_RONLY  0x301000UL     /* next 4KiB page - same 16KiB chunk */
#define VA_UNMAPPED 0x900000UL

#define VA_VECTOR 0x080000UL     /* EL1 trampoline, 2KiB-aligned */

#define MOVZ(rd, imm) (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define INSN_SVC0     0xD4000001u
/*
 * Terminator. NOT a branch-to-self: after the payload's own svc the trampoline
 * erets back to EL0 and execution continues here, so a `b .` would spin forever
 * with interrupts masked and hv_vcpu_run would never return. A bare svc traps
 * back to the host every time, which is what lets the test regain control.
 */
#define INSN_SVC_STOP 0xD4000001u

#define SYS_EXIT 93

static int failures, checks;

#define CHECK(cond, ...)                                                       \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("  FAIL: ");                                                      \
      printf(__VA_ARGS__);                                                     \
      printf("\n        (%s:%d: %s)\n", __FILE__, __LINE__, #cond);            \
    }                                                                          \
  } while (0)

static const char *
kind_name(enum vm_exit_kind k)
{
  switch (k) {
  case EXIT_SYSCALL:   return "EXIT_SYSCALL";
  case EXIT_MMU_FAULT: return "EXIT_MMU_FAULT";
  case EXIT_FAULT:     return "EXIT_FAULT";
  case EXIT_RESUME:    return "EXIT_RESUME";
  case EXIT_UNHANDLED: return "EXIT_UNHANDLED";
  }
  return "?";
}

void printk(const char *fmt, ...) { (void) fmt; }
void warnk(const char *fmt, ...) { (void) fmt; }
/* Not exercised here: these tests do not call vmm_sync_guest_code, but
 * vmm_arm64.c references guest_to_host, find_region and proc. Return
 * NULL/empty - never reached. */
void *guest_to_host(gaddr_t g) { (void) g; return NULL; }
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm)
{
  (void) gaddr;
  (void) mm;
  return NULL;
}
struct proc proc;

void
panic(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  printf("  PANIC: ");
  vprintf(fmt, ap);
  printf("\n");
  va_end(ap);
  exit(2);
}


/* --------------------------------------------------------------- setup */

static uint32_t *code_hva;
static uint64_t *data_hva;
static uint64_t *ronly_hva;
static void     *vector_hva;

static void
build_address_space(void)
{
  vmm_create();
  vmm_arm64_init_vcpu();
  pt_init();

  /* The trampoline runs at EL1, so it needs the one mapping with PXN clear. */
  vector_hva = pt_map_vector(VA_VECTOR);

  code_hva  = pt_alloc_and_map(VA_CODE,  LINUX_PROT_READ | LINUX_PROT_EXEC);
  pt_alloc_and_map(VA_STACK, LINUX_PROT_READ | LINUX_PROT_WRITE);
  data_hva  = pt_alloc_and_map(VA_DATA,  LINUX_PROT_READ | LINUX_PROT_WRITE);
  ronly_hva = pt_alloc_and_map(VA_RONLY, LINUX_PROT_READ);
}

static void
put_code(size_t idx, uint32_t insn)
{
  code_hva[idx] = insn;
}

static void
run_from_code(void)
{
  vmm_arm64_sync_guest_code(code_hva, PAGE_SIZEOF(PAGE_4KB));
  /* SP one page above the stack base so pushes have room downward. */
  vmm_arm64_enter_el0(VA_CODE, VA_STACK + PAGE_SIZEOF(PAGE_4KB) - 16,
                      VA_VECTOR + 0x900);
}

/* ================================================================= tests */

static void
test_mmu_on_and_code_translates(void)
{
  printf("guest runs at EL0 with the MMU on, fetching through our tables\n");

  put_code(0, MOVZ(8, SYS_EXIT));
  put_code(1, INSN_SVC0);
  put_code(2, INSN_SVC_STOP);

  run_from_code();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL,
        "got %s, want EXIT_SYSCALL - the guest did not reach its code through "
        "stage-1 translation", kind_name(e.kind));

  uint64_t nr = 0;
  vmm_get_reg(VREG_SYSNR, &nr);
  CHECK(nr == SYS_EXIT, "x8 = %llu, want %d", nr, SYS_EXIT);
}

static void
test_data_page_is_shared_with_host(void)
{
  printf("a mapped data page is the same memory the host sees\n");

  /*
   *   movz x0, #VA_DATA>>16, lsl #16   -- build the address
   *   movz x1, #0x1234
   *   str  x1, [x0]
   *   movz x8, #93 ; svc #0
   */
  const uint32_t MOVZ_X0_HI = 0xD2A00000u | ((VA_DATA >> 16) << 5); /* lsl #16 */
  const uint32_t MOVZ_X1    = MOVZ(1, 0x1234);
  const uint32_t STR_X1_X0  = 0xF9000001u;

  *data_hva = 0;

  put_code(0, MOVZ_X0_HI);
  put_code(1, MOVZ_X1);
  put_code(2, STR_X1_X0);
  put_code(3, MOVZ(8, SYS_EXIT));
  put_code(4, INSN_SVC0);
  put_code(5, INSN_SVC_STOP);

  run_from_code();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL, "got %s, want EXIT_SYSCALL (the store faulted?)",
        kind_name(e.kind));
  CHECK(*data_hva == 0x1234,
        "host reads 0x%llx from the data page, guest wrote 0x1234",
        (unsigned long long) *data_hva);
}

static void
test_readonly_page_faults_on_write(void)
{
  printf("permissions are per 4KiB page, not per 16KiB stage-2 chunk\n");

  /*
   * VA_RONLY is the 4KiB page immediately after VA_DATA, so with four pages to
   * a chunk the two live in the SAME 16KiB stage-2 region, which is mapped RWX.
   * If permissions came from stage 2 this write would succeed. It must not.
   */
  const uint32_t MOVZ_X0_HI = 0xD2A00000u | ((VA_RONLY >> 16) << 5);
  const uint32_t MOVZ_X0_LO = 0xF2800000u | ((VA_RONLY & 0xffff) << 5); /* movk */
  const uint32_t MOVZ_X1    = MOVZ(1, 0x5678);
  const uint32_t STR_X1_X0  = 0xF9000001u;

  *ronly_hva = 0;

  put_code(0, MOVZ_X0_HI);
  put_code(1, MOVZ_X0_LO);
  put_code(2, MOVZ_X1);
  put_code(3, STR_X1_X0);
  put_code(4, MOVZ(8, SYS_EXIT));
  put_code(5, INSN_SVC0);
  put_code(6, INSN_SVC_STOP);

  run_from_code();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_MMU_FAULT,
        "got %s, want EXIT_MMU_FAULT - a write to a read-only 4KiB page "
        "succeeded, so permissions are coming from the 16KiB chunk",
        kind_name(e.kind));
  CHECK(e.fault_access == VM_ACCESS_WRITE, "access %d, want WRITE",
        e.fault_access);
  CHECK(*ronly_hva == 0, "the write landed anyway: 0x%llx",
        (unsigned long long) *ronly_hva);
}

static void
test_unmapped_va_faults(void)
{
  printf("an unmapped VA faults rather than aliasing\n");

  const uint32_t MOVZ_X0_HI = 0xD2A00000u | ((VA_UNMAPPED >> 16) << 5);
  const uint32_t LDR_X1_X0  = 0xF9400001u;

  put_code(0, MOVZ_X0_HI);
  put_code(1, LDR_X1_X0);
  put_code(2, INSN_SVC_STOP);

  run_from_code();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_MMU_FAULT, "got %s, want EXIT_MMU_FAULT",
        kind_name(e.kind));
  CHECK(e.fault_addr == VA_UNMAPPED,
        "fault_addr 0x%llx, want 0x%lx - FAR_EL1 should hold the VA",
        (unsigned long long) e.fault_addr, VA_UNMAPPED);
}

int
main(void)
{
  printf("== aarch64 stage-1 translation (on hardware) ==\n\n");

  build_address_space();
  vmm_arm64_install_trampoline(vector_hva, VA_VECTOR);
  ((uint32_t *) vector_hva)[0x900 / 4] = INSN_ERET;   /* the EL1 bootstrap */
  vmm_arm64_sync_guest_code(vector_hva, PAGE_SIZEOF(PAGE_4KB));

  pt_enable();
  printf("TTBR0_EL1 = 0x%llx, MMU on\n\n",
         (unsigned long long) pt_root_ipa());

  test_mmu_on_and_code_translates();
  test_data_page_is_shared_with_host();
  test_readonly_page_faults_on_write();
  test_unmapped_va_faults();

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n", checks, failures);
  printf("%s\n", failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
