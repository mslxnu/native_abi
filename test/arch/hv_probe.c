/*
 * Can this host actually create a VM?
 *
 * Exits 0 if yes, 1 if no. Nothing else - it is a question the Makefile asks
 * before running any test that needs a hypervisor.
 *
 * It has to be asked by trying, because the obvious signals both lie. The
 * Makefile already records one of them: `kern.hv_support` reads as 1 for an
 * x86_64 process on Apple Silicon, where it is reporting ARM HVF rather than
 * VT-x, and hv_vm_create() then fails with HV_UNSUPPORTED. The other is the
 * machine itself - a Mac running inside a VM, which is what a CI runner
 * usually is, has the right CPU and the right OS and no nested virtualisation
 * to hand out.
 *
 * This binary is codesigned with the same entitlement as nabi. Without
 * com.apple.security.hypervisor, hv_vm_create() returns HV_DENIED on any host,
 * and the probe would report "cannot" everywhere.
 */
#include <Hypervisor/Hypervisor.h>

int
main(void)
{
  if (hv_vm_create(
#if defined(__arm64__) || defined(__aarch64__)
        NULL
#else
        0
#endif
      ) != HV_SUCCESS)
    return 1;
  hv_vm_destroy();
  return 0;
}
