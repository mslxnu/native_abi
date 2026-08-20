#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "linux/errno.h"

bool
addr_ok(gaddr_t addr, int access)
{
  addr = untag_gaddr(addr);
  if (addr >= user_addr_max) {
    return false;
  }
  struct mm_region *region = find_region(addr, proc.mm);
  if (!region) {
    return false;
  }
  if (access & ~region->prot) {
    return false;
  }

  return true;
}

size_t
copy_from_user(void *to, gaddr_t src_ptr, size_t n)
{
  while (n > 0) {
    const void *src = guest_to_host(src_ptr);
    if (src == NULL) {
      return n;
    }
    size_t size = MIN(rounddown(src_ptr + 4096, 4096) - src_ptr, n);
    memcpy(to, src, size);
    to = (char *) to + size;
    src_ptr += size;
    n -= size;
  }
  return 0;
}

// On success, returns the length of the string (not including the trailing NUL).
// If access to userspace fails, returns -EFAULT
ssize_t
strncpy_from_user(void *to, gaddr_t src_ptr, size_t n)
{
  size_t len = strnlen_user(src_ptr, n);
  if (len == 0) {
    return -LINUX_EFAULT;
  } else if (n < len) {
    if (copy_from_user(to, src_ptr, n)) {
      return -LINUX_EFAULT;
    }
    return n;
  }
  if (copy_from_user(to, src_ptr, len)) {
    return -LINUX_EFAULT;
  }
  return len - 1;
}

// Get the size of a user string INCLUDING trailing NULL
// On exception, it returns 0. For too long strings, returns a number greater than n.
ssize_t
strnlen_user(gaddr_t src_ptr, size_t n)
{
  int len = 0;
  while ((ssize_t) n > 0) {
    const void *str = guest_to_host(src_ptr);
    if (str == NULL) {
      return 0;
    }
    size_t size = MIN(rounddown(src_ptr + 4096, 4096) - src_ptr, n);
    size_t i = strnlen(str, size);
    if (i < size) {
      return len + i + 1;
    }
    assert(i == size);
    len += size;
    src_ptr += size;
    n -= size;
  }
  return len + 1;
}

size_t
copy_to_user(gaddr_t to_ptr, const void *src, size_t n)
{
  while (n > 0) {
    void *to = guest_to_host(to_ptr);
    if (to == NULL) {
      return n;
    }
    size_t size = MIN(rounddown(to_ptr + 4096, 4096) - to_ptr, n);
    memcpy(to, src, size);
    to_ptr += size;
    src = (char *) src + size;
    n -= size;
  }
  return 0;
}

/* Six dummy arguments for the same reason as DEFINE_NOT_IMPLEMENTED_SYSCALL
 * below; here the prototype comes afterwards, so clang reports it as a warning
 * rather than an error, but it is the same defect. */
DEFINE_SYSCALL(unimplemented, uint64_t, a1, uint64_t, a2, uint64_t, a3,
                              uint64_t, a4, uint64_t, a5, uint64_t, a6)
{
  /* Only used to name the syscall in the warning, so read it through the
   * arch-neutral interface rather than a raw x86 register. */
  uint64_t nr;

  vmm_get_reg(VREG_SYSNR, &nr);

  warnk("unimplemented syscall: %lld\n", nr);
  return -LINUX_ENOSYS;
}

#include "syscall.h"

#define sys_unimplemented __ignore_me__
#define SYSCALL(n, name) uint64_t _sys_##name(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
SYSCALLS
#undef SYSCALL
#undef sys_unimplemented

sc_handler_t sc_handler_table[NR_SYSCALLS] = {
#define SYSCALL(n, name) [n] = ((sc_handler_t) _sys_##name),
  SYSCALLS
#undef SYSCALL
};

char *sc_name_table[NR_SYSCALLS] = {
#define SYSCALL(n, name) [n] = #name,
  SYSCALLS
#undef SYSCALL
};

/*
 * Six dummy arguments, matching the prototype block above, rather than the
 * empty parameter list this used to have.
 *
 * `uint64_t _sys_vserver()` is a non-prototype declaration: in C23 - which
 * clang now applies even under -std=gnu11 - it means "takes no arguments"
 * instead of "arguments unspecified", so it conflicts with the six-argument
 * prototype every syscall is declared with. Spelling the arguments out keeps
 * the two in agreement, and costs nothing since the body ignores them.
 */
#define DEFINE_NOT_IMPLEMENTED_SYSCALL(name)                          \
  DEFINE_SYSCALL(name, uint64_t, a1, uint64_t, a2, uint64_t, a3,      \
                       uint64_t, a4, uint64_t, a5, uint64_t, a6)      \
  {                                                                   \
    return -LINUX_ENOSYS;                                             \
  }

/*
 * kexec_load and kexec_file_load: loading a kernel to boot into instead of
 * rebooting through firmware.
 *
 * Refused, and unlike most refusals here it is not for want of a Darwin
 * equivalent - the operation has no meaning in this program. nabi is a Linux
 * ABI on top of macOS: there is no kernel of its own to replace, no boot to
 * shorten, and nothing a loaded image could be executed by. A guest calling
 * these is asking to reboot the machine into something else, and the machine is
 * not nabi's to reboot.
 *
 * ENOSYS rather than EPERM, deliberately. EPERM says "not you", and a caller
 * that gets it retries as root, which here would fail identically forever.
 * ENOSYS says the facility is absent, which is true and which every caller
 * already knows how to stop at.
 */
/*
 * bpf: loading programs into the kernel to run at its hook points.
 *
 * There is no kernel here to load them into. nabi is the Linux system call
 * interface implemented in a userspace process on macOS; there are no
 * tracepoints to attach to, no verifier, no maps in kernel memory, and nothing
 * that could execute a bpf program if one were handed over. This is not a
 * facility that is missing, it is one the shape of this program has no place
 * for - and a caller told otherwise would attach a probe that never fires.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(bpf)

/*
 * add_key: the kernel keyring.
 *
 * A keyring is kernel-held storage with its own lifetimes - a key belongs to a
 * process, a session or a user, and goes when that does - and its point is that
 * the payload is somewhere userspace cannot read it directly. Neither half is
 * available here: there is no kernel to hold it, and anything nabi kept would
 * sit in the same address space as the program asking, which is not a keyring,
 * it is a variable.
 *
 * Refused rather than approximated, because the approximation would be a
 * security claim that is not true. request_key and keyctl are the rest of the
 * family and are absent for the same reason.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(add_key)

/*
 * keyctl: the rest of the keyring, and absent for the reason above.
 *
 * Worth saying separately only because keyctl is the half programs actually
 * call. Much of it - KEYCTL_GET_KEYRING_ID, KEYCTL_JOIN_SESSION_KEYRING,
 * KEYCTL_SESSION_TO_PARENT - is about the *rings* rather than the keys, and
 * those are per-process kernel state inherited across fork and reshaped on
 * exec. There is no such state here for the same reason there is nowhere safe
 * to put a payload, so a ring cannot be joined, described or moved either.
 *
 * A caller told ENOSYS from the first keyctl falls back to whatever it does
 * without a kernel keyring, which is the outcome that matches this host.
 * request_key completes the family and is absent alongside them.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(keyctl)
DEFINE_NOT_IMPLEMENTED_SYSCALL(request_key)

DEFINE_NOT_IMPLEMENTED_SYSCALL(uretprobe)

/*
 * ioperm and iopl: direct access to x86 I/O ports.
 *
 * These grant a process the right to run `in` and `out` against the port
 * space - ioperm for a range of it, iopl by raising the privilege level far
 * enough that the whole space is open. Both are x86-only calls, and neither has
 * an aarch64 number at all: aarch64 has no I/O port space to be granted, so
 * there is nothing the arm64 build could be asked for.
 *
 * They are here for the x86_64 table, where the number exists and a guest can
 * therefore reach them. Refused there too, and not as a policy decision: nabi's
 * guests run in EL0/ring 3 under a hypervisor, and what these ask for is a
 * change to the privilege state of the *host* kernel's view of a task. macOS
 * does not offer it to anybody. A guest driver poking at ports would be talking
 * to hardware that this machine does not have even when it is an x86 one.
 *
 * ENOSYS rather than EPERM, because EPERM is what a caller sees when it lacks
 * the privilege and would send a well-written one off to acquire it and try
 * again. There is nothing to acquire.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(ioperm)
DEFINE_NOT_IMPLEMENTED_SYSCALL(iopl)

/*
 * acct: BSD process accounting.
 *
 * Turning this on asks the kernel to append a record for every process that
 * exits, which needs the kernel to be the thing that reaps them. Here a guest
 * process is a host process and its parent is another nabi; there is no single
 * place every exit passes through, and macOS's own acct(2) would write records
 * about nabi's host processes in Darwin's format, which is neither the guest's
 * processes nor the guest's format.
 *
 * So it is refused. What a caller gets from ENOSYS is that accounting is
 * unavailable, which is true; what it would get from a pretend success is an
 * accounting file that stays empty while it believes it is being filled.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(acct)

DEFINE_NOT_IMPLEMENTED_SYSCALL(kexec_load)
DEFINE_NOT_IMPLEMENTED_SYSCALL(kexec_file_load)

/*
 * Loading kernel modules, all six of them.
 *
 * There is no kernel to load one into. That is the whole answer, and unlike
 * most of the refusals here it is not a Darwin limitation that a different host
 * might lift: a module is native code linked against a running kernel's symbols
 * and run in its address space, and what a guest is talking to is nabi, a
 * userspace process translating syscalls. An aarch64 Linux module has nothing
 * to be loaded into even in principle.
 *
 * All six rather than the four that were asked for, because the family only
 * makes sense together: refusing finit_module while init_module answered
 * nothing at all would leave modprobe taking whichever path happened to look
 * supported. create_module, get_kernel_syms and query_module are additionally
 * ones Linux itself removed in 2.6 and answers ENOSYS for, so on those three
 * this agrees with the kernel exactly.
 *
 * ENOSYS is what modprobe and the udev/kmod stack expect from a kernel built
 * without module support, and they degrade the way they were written to.
 */
/*
 * Landlock, refused - and this is the refusal in this tree that is least about
 * what Darwin can do.
 *
 * Landlock lets an ordinary program lock itself out of most of the filesystem
 * before it handles untrusted input: build a ruleset, add the few paths it will
 * need, restrict itself, and from then on the kernel refuses everything else,
 * for it and every child, irreversibly. nabi is in the right position to
 * enforce that - every guest path goes through its own lookup, which is exactly
 * the chokepoint Landlock hooks.
 *
 * It is refused because a partial one is worse than none, and not by a little.
 * landlock_restrict_self returning 0 is a program's signal that it is now
 * confined, and what it does next is handle the input it did not trust. There
 * are on the order of fifty path-taking syscalls here; a ruleset enforced at
 * forty-nine of them is not a sandbox with a gap, it is a sandbox that reports
 * success and does not hold. Every caller checks that return value, and none of
 * them can check whether the confinement is real.
 *
 * ENOSYS is also what the API is designed to be told. The documented way to
 * detect Landlock is landlock_create_ruleset with LANDLOCK_CREATE_RULESET_VERSION,
 * and ENOSYS from it means "this kernel has no Landlock" - which callers
 * already handle, by refusing to run or by carrying on unsandboxed knowingly.
 *
 * Implementing it properly would mean the ruleset living in nabi's lookup, an
 * inheritance rule across fork-by-exec, and a way to prove the enumeration of
 * entry points is complete. That is a feature, not a line in a table.
 */
/*
 * perf_event_open: the performance counters.
 *
 * Everything it opens is a hardware counter, a kernel tracepoint or a kernel
 * software event, and a guest here has none of the three. The PMU belongs to
 * macOS, which does not expose it to unprivileged userspace at all - kperf is
 * private and entitled - and the Hypervisor.framework does not virtualise
 * counters for a guest to program. Tracepoints and kprobes need a kernel with
 * hooks in it, which is the same wall bpf meets.
 *
 * ENOSYS rather than EPERM, and the distinction is real for this call: EPERM is
 * what perf_event_paranoid produces, and every profiler knows to tell the user
 * to lower it and try again. There is no setting here that would help.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(perf_event_open)

/*
 * modify_ldt: the local descriptor table.
 *
 * It installs segment descriptors for a process, which is how 16-bit and
 * segmented 32-bit code gets its selectors - dosemu, Wine's Win16 support, old
 * threading libraries. There is no aarch64 number because aarch64 has no
 * segmentation, so this is for the x86_64 table, and it is refused there too:
 * the descriptor tables belong to the VMCS nabi programs, and handing a guest
 * the ability to write them is a different project from running its syscalls.
 *
 * set_thread_area and get_thread_area are the rest of that family and are
 * refused a few lines below for the same reason.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(modify_ldt)


/*
 * pkey_alloc and pkey_free: protection keys, which need a register that is not
 * here. The reasoning is with pkey_mprotect in src/mm/mmap.c, which serves the
 * one case that does not need a key.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(pkey_alloc)
DEFINE_NOT_IMPLEMENTED_SYSCALL(pkey_free)

DEFINE_NOT_IMPLEMENTED_SYSCALL(landlock_create_ruleset)
DEFINE_NOT_IMPLEMENTED_SYSCALL(landlock_add_rule)
DEFINE_NOT_IMPLEMENTED_SYSCALL(landlock_restrict_self)

/*
 * lookup_dcookie: the other half of oprofile's identification scheme.
 *
 * A dcookie was an opaque handle the kernel handed a profiler for a dentry, so
 * that samples could name a file without holding a reference to it, and this
 * turned one back into a path. oprofile is gone and so is the cookie jar;
 * Linux removed the call in 6.6 and answers ENOSYS for it, so this agrees with
 * the kernel rather than merely with the hardware.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(lookup_dcookie)

/*
 * map_shadow_stack: allocate a hardware shadow stack.
 *
 * A shadow stack is a second, hardware-maintained copy of the return addresses,
 * which the CPU writes on every call and checks on every return - x86 CET, and
 * GCS on newer arm64. It cannot be emulated by allocating memory: the point is
 * that the *processor* enforces it and ordinary stores cannot reach the pages.
 * Apple Silicon has no GCS, the Hypervisor.framework exposes nothing that
 * would, and a mapping returned from here would be a stack the guest believed
 * was protected and nothing was checking.
 *
 * glibc enables shadow stacks only when the kernel says the hardware has them,
 * so ENOSYS leaves a guest running with ordinary returns, which is what it is
 * doing anyway.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(map_shadow_stack)

/*
 * memfd_secret: memory the kernel itself cannot read.
 *
 * It returns a descriptor whose pages are removed from the kernel's direct map,
 * so that a kernel bug, or code that has taken the kernel, still cannot reach
 * the secret. The guarantee is made *by* the kernel *against* the kernel.
 *
 * There is no such boundary here to remove anything from. nabi is a userspace
 * process and guest memory is a file it has mapped; anything it handed back
 * would sit in the same address space as the program asking, readable by the
 * same code that would have read it anyway - which is the same reason add_key
 * is refused, and the same reason approximating it would be a security claim
 * that is false. Callers already treat it as optional: it is off by default on
 * most distributions and needs secretmem.enable=1 to exist at all.
 */
DEFINE_NOT_IMPLEMENTED_SYSCALL(memfd_secret)

DEFINE_NOT_IMPLEMENTED_SYSCALL(init_module)
DEFINE_NOT_IMPLEMENTED_SYSCALL(finit_module)
DEFINE_NOT_IMPLEMENTED_SYSCALL(delete_module)
DEFINE_NOT_IMPLEMENTED_SYSCALL(create_module)
DEFINE_NOT_IMPLEMENTED_SYSCALL(get_kernel_syms)
DEFINE_NOT_IMPLEMENTED_SYSCALL(query_module)

DEFINE_NOT_IMPLEMENTED_SYSCALL(vserver)
DEFINE_NOT_IMPLEMENTED_SYSCALL(uselib)
DEFINE_NOT_IMPLEMENTED_SYSCALL(epoll_ctl_old)
DEFINE_NOT_IMPLEMENTED_SYSCALL(epoll_wait_old)
DEFINE_NOT_IMPLEMENTED_SYSCALL(getpmsg)
DEFINE_NOT_IMPLEMENTED_SYSCALL(putpmsg)
DEFINE_NOT_IMPLEMENTED_SYSCALL(nfsservctl)
DEFINE_NOT_IMPLEMENTED_SYSCALL(security)
DEFINE_NOT_IMPLEMENTED_SYSCALL(set_thread_area)
DEFINE_NOT_IMPLEMENTED_SYSCALL(get_thread_area)
DEFINE_NOT_IMPLEMENTED_SYSCALL(tuxcall)
DEFINE_NOT_IMPLEMENTED_SYSCALL(afs_syscall)
