/*
 * x86-64 signal frame construction.
 *
 * Split out of src/ipc/signal.c, which keeps the architecture-neutral signal
 * management (masks, pending set, the sigaction table, the syscalls). This is
 * the arch half: marshalling the vCPU register file into a Linux x86-64
 * sigcontext, building the rt_sigframe on the guest stack, and pointing the
 * vCPU at the handler - and restoring all of it on rt_sigreturn.
 *
 * The aarch64 counterpart is signal_arm64.c. The two share no frame layout:
 * the x86-64 sigcontext is sixteen named GPRs plus segment selectors and relies
 * on SA_RESTORER, none of which aarch64 has.
 */

#include "common.h"
#include "linux/signal.h"
#include "noah.h"
#include "vmm.h"

#include <string.h>
#include <signal.h>
#include <assert.h>

static void
setup_sigcontext(struct l_sigcontext *mcontext)
{
  vmm_read_register(HV_X86_R8, &mcontext->sc_r8);
  vmm_read_register(HV_X86_R9, &mcontext->sc_r9);
  vmm_read_register(HV_X86_R10, &mcontext->sc_r10);
  vmm_read_register(HV_X86_R11, &mcontext->sc_r11);
  vmm_read_register(HV_X86_R12, &mcontext->sc_r12);
  vmm_read_register(HV_X86_R13, &mcontext->sc_r13);
  vmm_read_register(HV_X86_R14, &mcontext->sc_r14);
  vmm_read_register(HV_X86_R15, &mcontext->sc_r15);
  vmm_read_register(HV_X86_RDI, &mcontext->sc_rdi);
  vmm_read_register(HV_X86_RSI, &mcontext->sc_rsi);
  vmm_read_register(HV_X86_RBP, &mcontext->sc_rbp);
  vmm_read_register(HV_X86_RBX, &mcontext->sc_rbx);
  vmm_read_register(HV_X86_RDX, &mcontext->sc_rdx);
  vmm_read_register(HV_X86_RAX, &mcontext->sc_rax);
  vmm_read_register(HV_X86_RCX, &mcontext->sc_rcx);
  vmm_read_register(HV_X86_RSP, &mcontext->sc_rsp);
  vmm_read_register(HV_X86_RIP, &mcontext->sc_rip);
  vmm_read_register(HV_X86_RFLAGS, &mcontext->sc_rflags);
  uint64_t cs, gs, fs, ss;
  vmm_read_register(HV_X86_CS, &cs); // Does saving segment indices really suffice? Manipulating base, limit may be needed.
  vmm_read_register(HV_X86_GS, &gs);
  vmm_read_register(HV_X86_FS, &fs);
  vmm_read_register(HV_X86_SS, &ss);
  mcontext->sc_cs = cs;
  mcontext->sc_gs = gs;
  mcontext->sc_fs = fs;
  mcontext->sc_ss = ss;
  // TODO: err, trapno
  mcontext->sc_mask = task.sigmask;
  // TODO: cr2
  // TODO: save FPU state
}

static void
restore_sigcontext(struct l_sigcontext *mcontext)
{
  vmm_write_register(HV_X86_R8, mcontext->sc_r8);
  vmm_write_register(HV_X86_R9, mcontext->sc_r9);
  vmm_write_register(HV_X86_R10, mcontext->sc_r10);
  vmm_write_register(HV_X86_R11, mcontext->sc_r11);
  vmm_write_register(HV_X86_R12, mcontext->sc_r12);
  vmm_write_register(HV_X86_R13, mcontext->sc_r13);
  vmm_write_register(HV_X86_R14, mcontext->sc_r14);
  vmm_write_register(HV_X86_R15, mcontext->sc_r15);
  vmm_write_register(HV_X86_RDI, mcontext->sc_rdi);
  vmm_write_register(HV_X86_RSI, mcontext->sc_rsi);
  vmm_write_register(HV_X86_RBP, mcontext->sc_rbp);
  vmm_write_register(HV_X86_RBX, mcontext->sc_rbx);
  vmm_write_register(HV_X86_RDX, mcontext->sc_rdx);
  vmm_write_register(HV_X86_RAX, mcontext->sc_rax);
  vmm_write_register(HV_X86_RCX, mcontext->sc_rcx);
  vmm_write_register(HV_X86_RSP, mcontext->sc_rsp);
  vmm_write_register(HV_X86_RIP, mcontext->sc_rip);
  vmm_write_register(HV_X86_RFLAGS, mcontext->sc_rflags); // TODO: fix some flags after implementing proper rflags initialization
  // TODO: set user mode bits
  vmm_write_register(HV_X86_CS, mcontext->sc_cs);
  vmm_write_register(HV_X86_GS, mcontext->sc_gs);
  vmm_write_register(HV_X86_FS, mcontext->sc_fs);
  vmm_write_register(HV_X86_SS, mcontext->sc_ss); // TODO: handle ss register more carefully if you want to support software such as DOSEMU

  // TODO: restore FPU state
}

int
arch_setup_sigframe(int signum)
{
  struct l_rt_sigframe frame;

  assert(signum <= LINUX_NSIG);
  static_assert(is_aligned(sizeof frame, sizeof(uint64_t)), "signal frame size should be aligned");

  uint64_t rsp;
  vmm_read_register(HV_X86_RSP, &rsp);
  if ((proc.sigaction[signum - 1].lsa_flags & LINUX_SA_ONSTACK) && (sas_ss_flags(rsp) & ~LINUX_SS_AUTODISARM) == 0) {
    rsp = task.sas.ss_sp + task.sas.ss_size;
  }

  /* Setup sigframe */
  if (proc.sigaction[signum - 1].lsa_flags & LINUX_SA_RESTORER) {
    frame.sf_pretcode = (gaddr_t) proc.sigaction[signum - 1].lsa_restorer;
  } else {
    // x86_64 should always use SA_RESTORER
    return -LINUX_EFAULT;
  }
  bzero(&frame.sf_si, sizeof(l_siginfo_t));
  frame.sf_si.lsi_signo = signum;

  /* Setup ucontext */
  frame.sf_sc.uc_flags = LINUX_UC_FP_XSTATE | LINUX_UC_SIGCONTEXT_SS | LINUX_UC_STRICT_RESTORE_SS; // Handle more carefully if you want to support DOSEMU
  frame.sf_sc.uc_link = 0;
  frame.sf_sc.uc_sigmask = task.sigmask;
  frame.sf_sc.uc_stack = task.sas;
  if (task.sas.ss_flags & LINUX_SS_AUTODISARM) {
    reset_sas();
  }
  setup_sigcontext(&frame.sf_sc.uc_mcontext);

  sigset_t dset;
  frame.sf_sc.uc_mcontext.sc_mask = task.sigmask;
  l_sigset_t newmask = proc.sigaction[signum - 1].lsa_mask;
  if (!(proc.sigaction[signum - 1].lsa_flags & LINUX_SA_NOMASK)) {
    LINUX_SIGADDSET(&newmask, signum);
  }
  task.sigmask = newmask;
  host_sigmask_of(&newmask, &dset);
  sigprocmask(SIG_SETMASK, &dset, NULL);

  /* OK, push them then... */
  rsp -= sizeof frame;
  vmm_write_register(HV_X86_RSP, rsp);
  if (copy_to_user(rsp, &frame, sizeof frame)) {
    return -LINUX_EFAULT;
  }

  /* Setup registers */
  vmm_write_register(HV_X86_RDI, signum);
  vmm_write_register(HV_X86_RSI, rsp + offsetof(struct l_rt_sigframe, sf_si));
  vmm_write_register(HV_X86_RDX, rsp + offsetof(struct l_rt_sigframe, sf_sc));

  vmm_write_register(HV_X86_RAX, 0);
  vmm_write_register(HV_X86_RIP, proc.sigaction[signum - 1].lsa_handler);

  return 0;
}

uint64_t
arch_rt_sigreturn(void)
{
  uint64_t rsp;
  vmm_read_register(HV_X86_RSP, &rsp);

  struct l_rt_sigframe frame;
  if (copy_from_user(&frame, rsp - sizeof frame.sf_pretcode, sizeof frame)) {
    die_with_forcedsig(LINUX_SIGSEGV);
  }

  restore_sigcontext(&frame.sf_sc.uc_mcontext);
  sigset_t dset;
  task.sigmask = frame.sf_sc.uc_mcontext.sc_mask;
  host_sigmask_of(&task.sigmask, &dset);
  sigprocmask(SIG_SETMASK, &dset, NULL);

  uint64_t rip;
  vmm_read_register(HV_X86_RIP, &rip);
  vmm_write_register(HV_X86_RIP, rip - 2); // Because syshandler add 2 when returning to guest

  uint64_t ret;
  vmm_read_register(HV_X86_RAX, &ret);
  return ret;
}
