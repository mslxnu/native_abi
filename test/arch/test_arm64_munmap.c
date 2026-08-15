/*
 * Hardware test for vmm_munmap on arm64 (src/mm/pt_arm64.c).
 *
 * The reliable unmap primitive on Apple Silicon is hv_vm_unmap of a 16KiB
 * stage-2 block: the guest's own TLBI does not invalidate HVF's combined TLB
 * entries (measured), so only a stage-2 unmap makes a re-access fault. This
 * checks that vmm_munmap actually makes an unmapped region fault, and that an
 * adjacent still-mapped region is untouched (no over-unmap of a neighbouring
 * 16KiB block).
 */

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "vmm.h"
#include "arch.h"
#include "mm.h"
#include "page.h"
#include "arm64/vm.h"
#include "linux/mman.h"

void  pt_init(void);
void  pt_enable(void);
void *pt_map_vector(gaddr_t va);

#define VA_VECTOR 0x080000UL
#define VA_CODE   0x100000UL
#define VA_STACK  0x200000UL
#define VA_KEEP   0x300000UL   /* stays mapped */
#define VA_DROP   0x400000UL   /* gets munmapped (its own 16KiB block) */

#define MOVZ(rd, imm)    (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define MOVK_HI16(rd, i) (0xF2A00000u | ((uint32_t)(i) << 5) | (uint32_t)(rd))
#define LDR_X1_X0        0xF9400001u
#define INSN_SVC0        0xD4000001u
#define SYS_EXIT 93

static int failures, checks;
#define CHECK(c, ...) do{ checks++; if(!(c)){ failures++; \
  printf("  FAIL: "); printf(__VA_ARGS__); \
  printf("\n        (%s:%d: %s)\n", __FILE__, __LINE__, #c);} }while(0)

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
void *guest_to_host(gaddr_t g) { (void) g; return NULL; }
/* vmm_sync_guest_code in vmm_arm64.c also references find_region and proc;
 * never reached here. */
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm)
{
  (void) gaddr;
  (void) mm;
  return NULL;
}
struct proc proc;
void panic(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt);
  printf("  PANIC: "); vprintf(fmt, ap); printf("\n"); va_end(ap); exit(2);
}

static uint32_t *code_hva;

/* payload: x0 = va; ldr x1,[x0]; svc; svc(stop) */
static void
read_payload(gaddr_t va)
{
  code_hva[0] = MOVZ(0, 0);
  code_hva[1] = MOVK_HI16(0, va >> 16);
  code_hva[2] = LDR_X1_X0;
  code_hva[3] = MOVZ(8, SYS_EXIT);
  code_hva[4] = INSN_SVC0;
  code_hva[5] = INSN_SVC0;
  vmm_arm64_sync_guest_code(code_hva, PAGE_SIZEOF(PAGE_4KB));
}

static void
enter(void)
{
  vmm_arm64_enter_el0(VA_CODE, VA_STACK + PAGE_SIZEOF(PAGE_4KB) - 16,
                      VA_VECTOR + VEC_BOOT_OFF);
}

int
main(void)
{
  printf("== arm64 vmm_munmap (on hardware) ==\n\n");

  vmm_create();
  vmm_arm64_init_vcpu();
  pt_init();

  void *vec = pt_map_vector(VA_VECTOR);
  vmm_arm64_install_trampoline(vec, VA_VECTOR);
  ((uint32_t *) vec)[VEC_BOOT_OFF / 4] = 0xD69F03E0u; /* eret */
  vmm_arm64_sync_guest_code(vec, PAGE_SIZEOF(PAGE_4KB));

  void *code_buf, *stack_buf, *keep_buf, *drop_buf;
  posix_memalign(&code_buf,  STAGE2_GRANULE, STAGE2_GRANULE);
  posix_memalign(&stack_buf, STAGE2_GRANULE, STAGE2_GRANULE);
  posix_memalign(&keep_buf,  STAGE2_GRANULE, STAGE2_GRANULE);
  posix_memalign(&drop_buf,  STAGE2_GRANULE, STAGE2_GRANULE);
  memset(code_buf, 0, STAGE2_GRANULE);
  memset(stack_buf, 0, STAGE2_GRANULE);
  code_hva = code_buf;
  *(uint64_t *) keep_buf = 0x1111;
  *(uint64_t *) drop_buf = 0x2222;

  vmm_mmap(VA_CODE,  PAGE_SIZEOF(PAGE_4KB), HV_MEMORY_READ | HV_MEMORY_EXEC, code_buf);
  vmm_mmap(VA_STACK, PAGE_SIZEOF(PAGE_4KB), HV_MEMORY_READ | HV_MEMORY_WRITE, stack_buf);
  vmm_mmap(VA_KEEP,  PAGE_SIZEOF(PAGE_4KB), HV_MEMORY_READ | HV_MEMORY_WRITE, keep_buf);
  vmm_mmap(VA_DROP,  PAGE_SIZEOF(PAGE_4KB), HV_MEMORY_READ | HV_MEMORY_WRITE, drop_buf);

  pt_enable();

  /* Prime both regions in the TLB. */
  read_payload(VA_DROP); enter();
  struct vm_exit e;
  vmm_run(&e);
  uint64_t x1 = 0; vmm_get_reg(VREG_ARG1, &x1);
  CHECK(e.kind == EXIT_SYSCALL && x1 == 0x2222,
        "prime VA_DROP: kind %s x1 0x%llx (want syscall, 0x2222)",
        kind_name(e.kind), (unsigned long long) x1);

  read_payload(VA_KEEP); enter(); vmm_run(&e);
  vmm_get_reg(VREG_ARG1, &x1);
  CHECK(e.kind == EXIT_SYSCALL && x1 == 0x1111, "prime VA_KEEP: x1 0x%llx",
        (unsigned long long) x1);

  /* Unmap VA_DROP. */
  vmm_munmap(VA_DROP, PAGE_SIZEOF(PAGE_4KB));
  printf("munmapped VA_DROP\n");

  /* VA_DROP now faults. */
  read_payload(VA_DROP); enter(); vmm_run(&e);
  CHECK(e.kind == EXIT_MMU_FAULT,
        "after munmap, VA_DROP: got %s, want EXIT_MMU_FAULT (stale TLB let a "
        "read through?)", kind_name(e.kind));
  CHECK(e.fault_addr == VA_DROP, "fault_addr 0x%llx, want 0x%lx",
        (unsigned long long) e.fault_addr, VA_DROP);

  /* VA_KEEP still works - not over-unmapped. */
  read_payload(VA_KEEP); enter(); vmm_run(&e);
  vmm_get_reg(VREG_ARG1, &x1);
  CHECK(e.kind == EXIT_SYSCALL && x1 == 0x1111,
        "after munmap of VA_DROP, VA_KEEP: got %s x1 0x%llx - a neighbouring "
        "region was wrongly unmapped", kind_name(e.kind),
        (unsigned long long) x1);

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
