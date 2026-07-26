# `hv_vcpu_create` is not reliable after `fork()`

A standalone reproduction, with no NABI code involved, of the limitation behind
NABI's intermittently-failing `fork` on Apple Silicon.

## The finding

**Once a vCPU has existed anywhere in a process, `hv_vcpu_create` in a forked
child crashes about one time in eight.** Not an error return — a `SIGSEGV`
*inside* Hypervisor.framework, so there is nothing to check and nothing to
handle.

`make check` forks and has the child create a VM and a vCPU. The three modes
differ only in what the parent did with the framework before forking:

| mode | parent before `fork()` | child failures |
|---|---|---|
| 0 | nothing | 0/20 |
| 1 | `hv_vm_create` + `hv_vm_destroy` | 0/20 |
| 2 | `hv_vm_create` + **vCPU** + `hv_vm_destroy` | ~2/20 |

So it is the vCPU specifically, and destroying it first does not clear whatever
it leaves behind. Measured on an M5 / macOS 26.

## Why this matters to NABI

Hypervisor.framework permits one VM per process, so `fork` in
[src/proc/fork.c](../../src/proc/fork.c) snapshots the vCPU, destroys the VM,
calls the host `fork`, and rebuilds the VM on both sides. The child's rebuild is
exactly the call above, so roughly one guest `fork` in eight produces a child
that dies before executing a single guest instruction. `forktest` and `clonetid`
in the smoke suite catch it; the guest sees a child that never ran.

## What does *not* fix it

All measured, all still failing at about the same rate:

- **Forking from a thread that never created a vCPU.** The poisoned state is
  process-wide, not thread-local, even though `hv_vcpu_create` binds a vCPU to
  its creating thread.
- **Serializing the rebuilds** so the child finishes before the parent starts.
- **Creating the vCPU before replaying the stage-2 mappings** rather than after.
- **Backing guest pages with `mmap` instead of the C heap.**
- **Retrying the fork.** Within a single NABI run the failure is deterministic —
  every retry dies too — even though it varies between runs. The standalone
  repro does not degrade over repeated cycles, so something about the guest's
  memory layout decides it for the run.

## The plausible fix

A **zygote**: fork a helper process at startup, before any vCPU is created (mode
0/1 above, which never fail), and have *it* fork the children that need fresh
vCPUs. The cost is that guest memory can no longer simply be inherited across
the fork — it has to be handed over explicitly — which is a substantially larger
change than anything above.
