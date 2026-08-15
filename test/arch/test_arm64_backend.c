/*
 * Hardware test for the aarch64 VMM backend.
 *
 * The Phase 0 spike (spike/arm64-trap/) proved the EL1 trampoline design with
 * throwaway code. This drives the same path through the *production* backend -
 * lib/vmm_arm64.c and lib/vmm_arm64_exit.c - and asserts on the
 * architecture-neutral struct vm_exit that main_loop will actually consume.
 *
 * It creates a real VM, so it needs Apple Silicon and the hypervisor
 * entitlement. Unlike the x86 side, this one genuinely runs on the development
 * machine.
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
#include "arm64/vm.h"
#include "linux/signal.h"

/* --------------------------------------------------------------- layout */

#define GUEST_BASE   0x10000UL
#define GUEST_SIZE   0x10000UL      /* 64KiB: a multiple of the 16KiB granule */

#define EL0_CODE_OFF 0x800          /* past the 0x800-byte vector table */
#define EL1_BOOT_OFF 0x900
#define STACK_OFF    0xF000

/* MOVZ <Xd>, #imm16 is 0xD2800000 | (imm16 << 5) | Rd. */
#define MOVZ(rd, imm) (0xD2800000u | ((uint32_t)(imm) << 5) | (uint32_t)(rd))
#define INSN_SVC0     0xD4000001u
#define INSN_B_BACK2  0x17FFFFFEu   /* b . - 8 */

#define SYS_WRITE 64
#define SYS_EXIT  93
#define SENTINEL  0xABCDULL

/* ----------------------------------------------------------- scaffolding */

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

/* The backend logs through these; the tree's real ones live in debug.c and
 * pull in most of the process model, so stub them. */
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

static uint8_t *guest;

static void
put32(size_t off, uint32_t insn)
{
  memcpy(guest + off, &insn, sizeof insn);
}

/* ================================================================== tests */

static void
setup_vm(void)
{
  /* Host allocation must be 16KiB-aligned for hv_vm_map; mmap gives us the
   * host page size, which is 16KiB on Apple Silicon. */
  guest = mmap(NULL, GUEST_SIZE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(guest != MAP_FAILED);
  memset(guest, 0, GUEST_SIZE);

  vmm_create();
  vmm_arm64_map_stage2(GUEST_BASE, GUEST_SIZE,
           HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC, guest);

  vmm_arm64_init_vcpu();
  vmm_arm64_install_trampoline(guest, GUEST_BASE);

  /* The one-shot eret that drops us from EL1 to EL0. */
  put32(EL1_BOOT_OFF, INSN_ERET);
}

/*
 * The guest's instruction fetch does not see host writes without this. Found
 * the hard way: rewriting the guest payload between tests silently re-ran the
 * previous test's code.
 */
static void
flush_guest_code(void)
{
  vmm_arm64_sync_guest_code(guest, GUEST_SIZE);
}

static void
start_el0(void)
{
  flush_guest_code();
  vmm_arm64_enter_el0(GUEST_BASE + EL0_CODE_OFF,
                      GUEST_BASE + STACK_OFF,
                      GUEST_BASE + EL1_BOOT_OFF);
}

static void
test_syscall_roundtrip(void)
{
  printf("guest svc -> EXIT_SYSCALL, args and return value round-trip\n");

  /*
   *   mov x8, #64      syscall number
   *   mov x0, #7       arg0
   *   mov x1, #9       arg1
   *   svc #0
   *   mov x8, #93      second syscall proves we returned to EL0
   *   svc #0
   *   b .
   */
  put32(EL0_CODE_OFF +  0, MOVZ(8, SYS_WRITE));
  put32(EL0_CODE_OFF +  4, MOVZ(0, 7));
  put32(EL0_CODE_OFF +  8, MOVZ(1, 9));
  put32(EL0_CODE_OFF + 12, INSN_SVC0);
  put32(EL0_CODE_OFF + 16, MOVZ(8, SYS_EXIT));
  put32(EL0_CODE_OFF + 20, INSN_SVC0);
  put32(EL0_CODE_OFF + 24, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL, "got %s, want EXIT_SYSCALL", kind_name(e.kind));

  uint64_t nr = 0, a0 = 0, a1 = 0;
  vmm_get_reg(VREG_SYSNR, &nr);
  vmm_get_reg(VREG_ARG0, &a0);
  vmm_get_reg(VREG_ARG1, &a1);
  CHECK(nr == SYS_WRITE, "VREG_SYSNR = %llu, want %d (x8)", nr, SYS_WRITE);
  CHECK(a0 == 7, "VREG_ARG0 = %llu, want 7 (x0)", a0);
  CHECK(a1 == 9, "VREG_ARG1 = %llu, want 9 (x1)", a1);

  /* The PC must not be advanced by the host: the CPU already moved ELR_EL1
   * past the svc. vmm_syscall_return() is a no-op here, and calling it must
   * not break the return to EL0 - the next syscall arriving proves it. */
  vmm_set_reg(VREG_RET, SENTINEL);
  vmm_syscall_return();

  CHECK(vmm_run(&e) == 0, "second vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL, "second exit: got %s, want EXIT_SYSCALL",
        kind_name(e.kind));

  vmm_get_reg(VREG_SYSNR, &nr);
  uint64_t ret = 0;
  vmm_get_reg(VREG_RET, &ret);
  CHECK(nr == SYS_EXIT, "second syscall nr = %llu, want %d - the eret did not "
        "resume EL0 correctly", nr, SYS_EXIT);
  CHECK(ret == SENTINEL, "x0 = 0x%llx, want 0x%llx - the value written by the "
        "host did not survive the return to EL0", ret, SENTINEL);
}

static void
test_stack_pointer(void)
{
  printf("VREG_SP maps to SP_EL0, not to a general register\n");

  uint64_t sp = 0;
  vmm_get_reg(VREG_SP, &sp);
  CHECK(sp == GUEST_BASE + STACK_OFF,
        "VREG_SP = 0x%llx, want 0x%lx", sp, GUEST_BASE + STACK_OFF);

  vmm_set_reg(VREG_SP, GUEST_BASE + 0x8000);
  vmm_get_reg(VREG_SP, &sp);
  CHECK(sp == GUEST_BASE + 0x8000, "VREG_SP did not write back");
  vmm_set_reg(VREG_SP, GUEST_BASE + STACK_OFF);
}

static void
test_data_abort_is_mmu_fault(void)
{
  printf("guest touching an unmapped address -> EXIT_MMU_FAULT\n");

  /*
   *   mov x0, #0x8000   an address well outside the mapped 64KiB
   *   movk shifted would be needed for a bigger constant; 0x8000 is enough
   *   because the region is GUEST_BASE..GUEST_BASE+0x10000 and a bare 0x8000
   *   is below it.
   *   ldr x1, [x0]
   */
  const uint32_t LDR_X1_X0 = 0xF9400001u;   /* ldr x1, [x0] */

  put32(EL0_CODE_OFF +  0, MOVZ(0, 0x8000));
  put32(EL0_CODE_OFF +  4, LDR_X1_X0);
  put32(EL0_CODE_OFF +  8, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_MMU_FAULT, "got %s, want EXIT_MMU_FAULT",
        kind_name(e.kind));
  CHECK(e.fault_addr_valid, "fault address not reported");
  CHECK(e.fault_addr == 0x8000, "fault_addr = 0x%llx, want 0x8000",
        (unsigned long long) e.fault_addr);
  CHECK(e.fault_access == VM_ACCESS_READ, "access kind %d, want READ (a load)",
        e.fault_access);
}

static void
test_write_abort_reports_write(void)
{
  printf("a store to an unmapped address reports VM_ACCESS_WRITE\n");

  const uint32_t STR_X1_X0 = 0xF9000001u;   /* str x1, [x0] */

  put32(EL0_CODE_OFF +  0, MOVZ(0, 0x8000));
  put32(EL0_CODE_OFF +  4, STR_X1_X0);
  put32(EL0_CODE_OFF +  8, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_MMU_FAULT, "got %s, want EXIT_MMU_FAULT",
        kind_name(e.kind));
  CHECK(e.fault_access == VM_ACCESS_WRITE,
        "access kind %d, want WRITE - ESR WnR decoded backwards?",
        e.fault_access);
}

static void
test_brk_is_sigtrap(void)
{
  printf("guest brk -> EXIT_FAULT / SIGTRAP\n");

  put32(EL0_CODE_OFF + 0, INSN_BRK0);
  put32(EL0_CODE_OFF + 4, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_FAULT, "got %s, want EXIT_FAULT", kind_name(e.kind));
  CHECK(e.signal == LINUX_SIGTRAP, "signal %d, want SIGTRAP(%d)",
        e.signal, LINUX_SIGTRAP);
}

static void
test_fp_not_trapped(void)
{
  printf("FP/SIMD is usable at EL0 (CPACR_EL1.FPEN)\n");

  /*
   * Without CPACR_EL1.FPEN this traps as EC_SIMD_FP and every real guest dies
   * in libc's memcpy. The instruction is `fmov d0, #1.0`, then a syscall so
   * the test has something to observe.
   */
  const uint32_t FMOV_D0_1 = 0x1E6E1000u;

  put32(EL0_CODE_OFF +  0, FMOV_D0_1);
  put32(EL0_CODE_OFF +  4, MOVZ(8, SYS_EXIT));
  put32(EL0_CODE_OFF +  8, INSN_SVC0);
  put32(EL0_CODE_OFF + 12, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL,
        "got %s, want EXIT_SYSCALL - an FP trap here means CPACR_EL1.FPEN is "
        "not set", kind_name(e.kind));
}

static void
test_tls_register(void)
{
  printf("vmm_set_tls writes TPIDR_EL0, guest reads it with mrs\n");

  /*
   *   mrs x0, tpidr_el0     -- guest reads its thread pointer
   *   mov x8, #93 ; svc #0  -- hand it back so the host can check
   */
  const uint32_t MRS_X0_TPIDR = 0xD53BD040u;

  vmm_set_tls(0xFEEDBEEF);

  /* Host reads it back through the same accessor. */
  uint64_t got = 0;
  vmm_get_tls(&got);
  CHECK(got == 0xFEEDBEEF, "vmm_get_tls = 0x%llx, want 0xFEEDBEEF", got);

  put32(EL0_CODE_OFF +  0, MRS_X0_TPIDR);
  put32(EL0_CODE_OFF +  4, MOVZ(8, SYS_EXIT));
  put32(EL0_CODE_OFF +  8, INSN_SVC0);
  put32(EL0_CODE_OFF + 12, INSN_B_BACK2);

  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  CHECK(e.kind == EXIT_SYSCALL, "got %s, want EXIT_SYSCALL", kind_name(e.kind));

  uint64_t x0 = 0;
  vmm_get_reg(VREG_ARG0, &x0);
  CHECK(x0 == 0xFEEDBEEF,
        "guest mrs tpidr_el0 = 0x%llx, want 0xFEEDBEEF - the thread pointer "
        "the host set is not what the guest sees", x0);
}

static void
test_reset_regs(void)
{
  printf("vmm_reset_regs zeroes x0-x30 (guest reads them back)\n");

  /* Dirty a couple of registers, reset, then have the guest report x1 and x30
   * so we confirm the guest - not just the host - sees zero. */
  vmm_arm64_write_reg(HV_REG_X1, 0xAAAA);
  vmm_arm64_write_reg(HV_REG_X30, 0xBBBB);

  vmm_reset_regs();

  uint64_t v = 0xffff;
  vmm_arm64_read_reg(HV_REG_X1, &v);
  CHECK(v == 0, "x1 = 0x%llx after reset, want 0", v);
  vmm_arm64_read_reg(HV_REG_X30, &v);
  CHECK(v == 0, "x30 = 0x%llx after reset, want 0", v);

  /*
   *   mov x8, #93 ; svc #0   -- x0 should still be 0 from the reset
   */
  put32(EL0_CODE_OFF + 0, MOVZ(8, SYS_EXIT));
  put32(EL0_CODE_OFF + 4, INSN_SVC0);
  put32(EL0_CODE_OFF + 8, INSN_B_BACK2);
  start_el0();

  struct vm_exit e;
  CHECK(vmm_run(&e) == 0, "vmm_run failed");
  uint64_t x0 = 0xff;
  vmm_get_reg(VREG_ARG0, &x0);
  CHECK(x0 == 0, "guest sees x0 = 0x%llx after reset, want 0", x0);
}

static void
test_syscall_unadvance(void)
{
  printf("vmm_syscall_unadvance is the inverse of vmm_syscall_return\n");

  /* On aarch64 both are no-ops: PC must be unchanged after unadvance+return. */
  vmm_arm64_write_reg(HV_REG_PC, 0x123400);
  vmm_syscall_unadvance();
  vmm_syscall_return();
  uint64_t pc = 0;
  vmm_arm64_read_reg(HV_REG_PC, &pc);
  CHECK(pc == 0x123400,
        "PC = 0x%llx after unadvance+return, want 0x123400 (both no-ops on "
        "aarch64)", pc);
}

int
main(void)
{
  printf("== aarch64 VMM backend (on hardware) ==\n\n");

  setup_vm();

  test_syscall_roundtrip();
  test_stack_pointer();
  test_data_abort_is_mmu_fault();
  test_write_abort_reports_write();
  test_brk_is_sigtrap();
  test_fp_not_trapped();
  test_tls_register();
  test_reset_regs();
  test_syscall_unadvance();

  vmm_destroy_vcpu();
  vmm_destroy();

  printf("\n%d checks, %d failures\n", checks, failures);
  printf("%s\n", failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
