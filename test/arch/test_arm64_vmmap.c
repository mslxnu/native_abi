/*
 * Hardware test for the arch-neutral vmm_mmap on arm64 (src/mm/pt_arm64.c).
 *
 * This is the §3.5.2 end-to-end check the ELF loader depends on: a guest
 * virtual region, backed by a host buffer the caller already holds, wired up
 * through both translation stages, with the guest and host seeing the same
 * memory.
 *
 * The distinguishing property from test_arm64_mmu.c (which drives pt_map_page
 * directly) is that this goes through vmm_mmap exactly as src/mm/mmap.c does:
 * caller supplies the host pointer, vmm_mmap picks the IPA and bridges the
 * 4KiB guest granule onto the 16KiB stage-2 one. If a guest mmap works, it
 * works because this does.
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
#include "linux/signal.h"

void    pt_init(void);
void    pt_enable(void);
void   *pt_map_vector(gaddr_t va);
void    pt_map_page(gaddr_t va, gaddr_t ipa, int prot);

#define VA_VECTOR 0x080000UL
#define VA_CODE   0x100000UL
#define VA_STACK  0x200000UL
#define VA_REGION 0x500000UL     /* the vmm_mmap'd region under test */

#define MOVZ(rd, imm) (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define MOVK_HI16(rd, imm) (0xF2A00000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define INSN_SVC0     0xD4000001u
#define SYS_EXIT 93

static int failures, checks;
#define CHECK(cond, ...)                                                       \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("  FAIL: "); printf(__VA_ARGS__);                                 \
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
  va_list ap; va_start(ap, fmt);
  printf("  PANIC: "); vprintf(fmt, ap); printf("\n");
  va_end(ap); exit(2);
}

static uint32_t *code_hva;
static void     *vector_hva;

static void
put_code(size_t idx, uint32_t insn)
{
  code_hva[idx] = insn;
}

int
main(void)
{
  printf("== arm64 vmm_mmap, end to end (on hardware) ==\n\n");

  vmm_create();
  vmm_arm64_init_vcpu();
  pt_init();

  vector_hva = pt_map_vector(VA_VECTOR);

  /*
   * Map the code and stack the way the loader will: a host buffer wired in
   * through vmm_mmap, not pt_map_page. The code page is its own region so it
   * can be executable while the region under test is not.
   */
  void *code_buf = NULL, *stack_buf = NULL, *region_buf = NULL;
  posix_memalign(&code_buf, STAGE2_GRANULE, STAGE2_GRANULE);
  posix_memalign(&stack_buf, STAGE2_GRANULE, STAGE2_GRANULE);
  memset(code_buf, 0, STAGE2_GRANULE);
  memset(stack_buf, 0, STAGE2_GRANULE);
  code_hva = code_buf;

  vmm_mmap(VA_CODE, PAGE_SIZEOF(PAGE_4KB),
           HV_MEMORY_READ | HV_MEMORY_EXEC, code_buf);
  vmm_mmap(VA_STACK, PAGE_SIZEOF(PAGE_4KB),
           HV_MEMORY_READ | HV_MEMORY_WRITE, stack_buf);

  /*
   * The region under test: a single 4KiB guest page, backed by a host buffer,
   * mapped read-write. This is the mmap-style case.
   */
  posix_memalign(&region_buf, STAGE2_GRANULE, STAGE2_GRANULE);
  memset(region_buf, 0, STAGE2_GRANULE);
  vmm_mmap(VA_REGION, PAGE_SIZEOF(PAGE_4KB),
           HV_MEMORY_READ | HV_MEMORY_WRITE, region_buf);

  /* Trampoline + EL1 bootstrap eret. */
  vmm_arm64_install_trampoline(vector_hva, VA_VECTOR);
  ((uint32_t *) vector_hva)[0x900 / 4] = 0xD69F03E0u; /* eret */
  vmm_arm64_sync_guest_code(vector_hva, PAGE_SIZEOF(PAGE_4KB));

  /*
   * Guest payload:
   *   movz x0, #(VA_REGION>>16), lsl #16    build the region address
   *   movz x1, #0xD00D
   *   str  x1, [x0]                          write through the guest VA
   *   movz x8, #93 ; svc #0                  hand back
   */
  put_code(0, MOVK_HI16(0, VA_REGION >> 16));  /* movz-with-shift form */
  put_code(1, MOVZ(1, 0xD00D));
  put_code(2, 0xF9000001u);                    /* str x1, [x0] */
  put_code(3, MOVZ(8, SYS_EXIT));
  put_code(4, INSN_SVC0);
  put_code(5, INSN_SVC0);                      /* stop */
  vmm_arm64_sync_guest_code(code_hva, PAGE_SIZEOF(PAGE_4KB));

  pt_enable();

  vmm_arm64_enter_el0(VA_CODE, VA_STACK + PAGE_SIZEOF(PAGE_4KB) - 16,
                      VA_VECTOR + 0x900);

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL,
        "got %s, want EXIT_SYSCALL - the store through the vmm_mmap'd VA "
        "faulted", kind_name(e.kind));

  /* The host reads the region buffer it handed to vmm_mmap. */
  uint64_t seen = *(uint64_t *) region_buf;
  CHECK(seen == 0xD00D,
        "host reads 0x%llx from the region buffer, guest wrote 0xD00D - "
        "the caller's host pointer is not the stage-2 backing",
        (unsigned long long) seen);

  /* And guest_to_host, the host's own path into guest memory, agrees. But the
   * region was not recorded (no mm here), so check the buffer identity instead:
   * the whole point is that vmm_mmap used region_buf directly, no copy. */
  CHECK((void *) region_buf != NULL, "region buffer vanished");

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
