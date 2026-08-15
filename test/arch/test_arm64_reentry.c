/*
 * Hardware test for the fork reentry path: snapshot a running vCPU, tear the VM
 * down, rebuild it and restore the vCPU, and confirm the guest resumes exactly
 * where it left off - across a real hv_vm_destroy / hv_vm_create.
 *
 * This is the load-bearing uncertainty behind fork on Apple Silicon: HVF allows
 * only one VM per process, so fork() destroys the VM and both sides rebuild it
 * (src/proc/fork.c drives vmm_snapshot -> vmm_destroy -> host fork -> reentry).
 * Rebuilding means replaying every stage-2 mapping and re-establishing the
 * control registers into a fresh VM. This test exercises that rebuild in-process
 * (no host fork - that adds only COW, which HVF is not involved in), so a failure
 * here is a reentry-mechanics failure, isolated from fork() itself.
 *
 * Like test_arm64_boot.c it stands in for main.c without the whole binary: a
 * handful of hand-assembled instructions instead of an ELF, and its own stubs.
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

const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

#define VA_CODE  0x100000UL
#define VA_STACK 0x200000UL

#define MOVZ(rd, imm) (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define INSN_SVC0 0xD4000001u
#define SYS_GETPID 172
#define SYS_EXIT   93

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

void *pt_alloc_and_map(gaddr_t va, int prot);

/* init_vkernel_machine maps the signal-return trampoline through this, defined
 * in signal_arm64.c, which this test does not link. The guest here raises no
 * signal, so a no-op stub is enough - as in test_arm64_boot.c. */
void arch_setup_sigreturn(void) {}

static void *code_host;
void *
guest_to_host(gaddr_t gaddr)
{
  if (gaddr >= VA_CODE && gaddr < VA_CODE + PAGE_SIZEOF(PAGE_4KB))
    return (char *) code_host + (gaddr - VA_CODE);
  return NULL;
}

/* vmm_sync_guest_code in vmm_arm64.c also references find_region and proc;
 * this test does not link mm.c/process.c, and the guest here faults no page,
 * so the region walk is never reached. */
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
  printf("== arm64 fork reentry: snapshot / destroy / rebuild / resume ==\n\n");

  vmm_create();
  init_vkernel_machine();

  uint32_t *code = pt_alloc_and_map(VA_CODE, LINUX_PROT_READ | LINUX_PROT_EXEC);
  pt_alloc_and_map(VA_STACK, LINUX_PROT_READ | LINUX_PROT_WRITE);
  code_host = code;

  /*
   * getpid (a harmless syscall to stop at), then - after the round trip through
   * reentry - exit(#42). If the guest resumes correctly it runs the second block
   * and exits with x8=93, x0=42.
   */
  code[0] = MOVZ(8, SYS_GETPID);  /* mov x8, #172 */
  code[1] = INSN_SVC0;            /* svc  -> stop A                    */
  code[2] = MOVZ(8, SYS_EXIT);    /* mov x8, #93                       */
  code[3] = MOVZ(0, 42);          /* mov x0, #42                       */
  code[4] = INSN_SVC0;            /* svc  -> stop B                    */
  code[5] = INSN_SVC0;            /* stop                              */
  vmm_sync_guest_code(VA_CODE, PAGE_SIZEOF(PAGE_4KB));

  vmm_set_reg(VREG_PC, VA_CODE);
  vmm_set_reg(VREG_SP, VA_STACK + PAGE_SIZEOF(PAGE_4KB) - 16);

  vmm_start_guest();

  /* Run to stop A. */
  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "first vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL, "stop A: want EXIT_SYSCALL");
  uint64_t nr = 0;
  vmm_get_reg(VREG_SYSNR, &nr);
  CHECK(nr == SYS_GETPID, "stop A: x8 = %llu, want %d", nr, SYS_GETPID);

  /* Snapshot, tear the VM down, rebuild it, restore the vCPU. */
  struct vmm_snapshot snap;
  vmm_snapshot(&snap);
  vmm_destroy();
  vmm_reentry(&snap);

  /* The guest must resume at the instruction after stop A's svc and reach stop
   * B - which only happens if the PC, the page tables (stage-2 replayed), the
   * MMU-enable and the trampoline vector all came back correctly. */
  CHECK(vmm_run(&e) == 0, "post-reentry vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL,
        "stop B: want EXIT_SYSCALL - the guest did not resume through reentry");
  nr = 0;
  vmm_get_reg(VREG_SYSNR, &nr);
  CHECK(nr == SYS_EXIT, "stop B: x8 = %llu, want %d", nr, SYS_EXIT);
  uint64_t x0 = 0;
  vmm_get_reg(VREG_ARG0, &x0);
  CHECK(x0 == 42, "stop B: x0 = %llu, want 42 (guest state after resume)", x0);

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
