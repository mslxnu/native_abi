/*
 * Hardware test for the arm64 startup path in src/main_arm64.c.
 *
 * The other arm64 tests drive the primitives directly. This one exercises the
 * production wiring - init_vkernel_machine() then vmm_start_guest() - the way
 * main.c will, to confirm that sequence actually boots a guest: sets up page
 * tables and the trampoline, maps an entry point and stack, turns translation
 * on, drops to EL0 and runs.
 *
 * It stands in for main.c's flow without needing the whole binary to link
 * (signal.c is still a blocker), and without a rootfs: the "program" is a
 * handful of hand-assembled instructions.
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
#include "noah.h"
#include "page.h"
#include "arm64/vm.h"
#include "linux/mman.h"

/* user_addr_max lives in mm.c, which this test does not link, so provide it -
 * main_arm64.c places the trampoline at user_addr_max. */
const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

#define VA_CODE  0x100000UL
#define VA_STACK 0x200000UL

#define MOVZ(rd, imm) (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define INSN_SVC0 0xD4000001u
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

void printk(const char *fmt, ...) { (void) fmt; }
void warnk(const char *fmt, ...) { (void) fmt; }
void
panic(const char *fmt, ...)
{
  va_list ap; va_start(ap, fmt);
  printf("  PANIC: "); vprintf(fmt, ap); printf("\n");
  va_end(ap); exit(2);
}

/* pt_arm64 helpers the test uses to place code/stack, as exec.c's do_mmap will. */
void *pt_alloc_and_map(gaddr_t va, int prot);

/* init_vkernel_machine maps the signal-return trampoline through this, defined
 * in signal_arm64.c - which this test does not link (it is the whole point of
 * standing in for main.c without the full binary). The boot guest never raises
 * a signal, so a no-op stub is enough. */
void arch_setup_sigreturn(void) {}

/*
 * The loader syncs freshly written guest code through vmm_sync_guest_code(gva),
 * which resolves the address with guest_to_host - normally the mm_region walk in
 * mm.c. This test does not link mm.c, so it provides the one mapping it needs:
 * VA_CODE -> the host buffer pt_alloc_and_map handed back. This exercises the
 * exact call exec.c makes rather than the lower-level host-pointer variant.
 */
static void *code_host;
void *
guest_to_host(gaddr_t gaddr)
{
  if (gaddr >= VA_CODE && gaddr < VA_CODE + PAGE_SIZEOF(PAGE_4KB))
    return (char *) code_host + (gaddr - VA_CODE);
  return NULL;
}

/* vmm_sync_guest_code in vmm_arm64.c also references find_region and proc;
 * this test does not link mm.c/process.c, and the boot guest never faults so
 * the region walk is never reached. */
struct mm_region *find_region(gaddr_t gaddr, struct mm *mm)
{
  (void) gaddr;
  (void) mm;
  return NULL;
}
struct proc proc;

int
main(void)
{
  printf("== arm64 guest boot via main_arm64.c wiring (on hardware) ==\n\n");

  vmm_create();

  /*
   * The production bring-up. After this the page tables, vCPU control regs and
   * the EL1 trampoline are all set up, MMU still off.
   */
  init_vkernel_machine();

  /*
   * Stand in for do_exec: map an entry page and a stack, write a tiny program,
   * and set VREG_PC / VREG_SP the way the loader does.
   */
  uint32_t *code = pt_alloc_and_map(VA_CODE, LINUX_PROT_READ | LINUX_PROT_EXEC);
  pt_alloc_and_map(VA_STACK, LINUX_PROT_READ | LINUX_PROT_WRITE);
  code_host = code;

  code[0] = MOVZ(8, SYS_EXIT);   /* mov x8, #93 */
  code[1] = INSN_SVC0;           /* svc #0      */
  code[2] = INSN_SVC0;           /* stop        */
  /* The exact call exec.c makes after loading an executable segment: a guest
   * virtual address, resolved through guest_to_host inside the backend. */
  vmm_sync_guest_code(VA_CODE, PAGE_SIZEOF(PAGE_4KB));

  vmm_set_reg(VREG_PC, VA_CODE);
  vmm_set_reg(VREG_SP, VA_STACK + PAGE_SIZEOF(PAGE_4KB) - 16);

  /*
   * The startup transition: MMU on, eret to EL0 at the entry point. On x86 this
   * is a no-op; here it is what actually starts the guest.
   */
  vmm_start_guest();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL,
        "got %s, want EXIT_SYSCALL - the guest did not reach its entry point "
        "through the production bring-up",
        e.kind == EXIT_SYSCALL ? "EXIT_SYSCALL" :
        e.kind == EXIT_MMU_FAULT ? "EXIT_MMU_FAULT" : "other");

  uint64_t nr = 0;
  vmm_get_reg(VREG_SYSNR, &nr);
  CHECK(nr == SYS_EXIT, "x8 = %llu, want %d", nr, SYS_EXIT);

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
