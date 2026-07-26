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

## Two ways out, both measured

`make check` runs all three programs.

| approach | children that failed |
|---|---|
| direct fork (today) | ~3/20 |
| **zygote** — a process that never touched HVF forks the children | **0/100** |
| **fork + exec** — the child `exec`s before creating a vCPU | **0/75** |

`hv_zygote.c` is the stronger test of the two: the "runner" holds a **live** VM
and vCPU the whole time, exactly as a process running a guest would, and the
zygote's children still come up clean every time.

`hv_fork_exec.c` shows `exec` clears the poisoning as well — the child is forked
from the poisoned process and only becomes clean by replacing its image.

## Which one NABI should use

**fork + exec**, not the zygote, despite the zygote being the more obvious fix.

Both require the same hard thing: the new process does not inherit the guest's
address space, so guest memory and NABI's own bookkeeping have to be handed over
explicitly rather than arriving by copy-on-write. That is checkpoint/restore, and
it is the bulk of the work either way.

What separates them is everything *else* a process holds. A fork+exec child is
still a `fork` child: it inherits the open file descriptors, so NABI's guest fd
table keeps pointing at the right host files and only the table itself needs
serializing. A zygote child inherits nothing — it never shared an ancestor with
the running guest — so every open file would have to be re-opened and re-seeked
from serialized state, which is both more code and impossible to get exactly
right for pipes, sockets and unlinked files.

So the shape is: guest memory moves into a shared-memory arena, NABI's process
state (mm regions, fd table, credentials, sigactions, task, brk, vCPU snapshot)
gets serialized, and `__do_clone_process` becomes fork + `exec` of `nabi
--resume <fd>`, which maps the arena and rebuilds. The measurements above say
the resulting child will create its vCPU reliably; they do not make the
checkpoint/restore any smaller.
