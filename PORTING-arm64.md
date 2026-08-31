# Porting Noah to Apple Silicon (arm64)

**Target:** run **aarch64** Linux binaries on arm64 macOS via Hypervisor.framework's ARM API.

**Status** (M5, macOS 26): **a native arm64 `nabi` runs Debian's `bash`
interactively** - the README's milestone. On a tty it prints its prompt, takes
commands, and runs builtins, external commands and pipelines with job control;
`bash -c` covers the same ground plus command substitution, loops, conditionals
and redirections. Static and dynamically-linked aarch64 binaries both work, under
a real `ld-linux-aarch64.so.1` + glibc.

Two things stood between a working `bash -c` and a working prompt, and both were
NABI killing the guest over something ordinary: `clock_gettime` panicked on any
clock outside a short list, and bash asks for `CLOCK_REALTIME_COARSE`; and the
descriptor-flag conversion asserted that every Darwin flag has a Linux
counterpart, which is a fact about the host rather than about the guest. Neither
is a thing a guest should be able to die of.

`fork` is reliable: it is implemented as fork + `exec` of a resumed process,
working around a Hypervisor.framework limitation that is not a NABI bug (§3.5.8,
reproduced standalone in [spike/arm64-fork/](spike/arm64-fork/)).

Threads work too: a guest thread is a second live vCPU in the same VM, which is
the ordinary Hypervisor.framework model and has nothing to do with the fork
problem. `CLONE_SETTLS` reaches `TPIDR_EL0`, thread exit and `CHILD_CLEARTID`
behave, futex `WAIT`/`WAKE` block and wake, and `fork` from a threaded process
gives a single-threaded child (`threadtest`).

`-m <root>` is a filesystem root, not a sandbox: five absolute paths - `/Users`,
`/Volumes`, `/dev`, `/tmp`, `/private` - deliberately resolve on the host, which
is how a guest sees the Mac's files. Everything else resolves inside the rootfs.

| Phase | State |
|---|---|
| 0 — trap mechanism | **done**, hardware-validated, [spike/arm64-trap/](spike/arm64-trap/) |
| 1 — arch abstraction | **done**, [include/arch.h](include/arch.h) |
| 2 — arm64 VMM backend | **done** — backend, stage-1 translation, two-stage `vmm_mmap`, guest boot to EL0, all hardware-verified (`make check-arm64`) |
| 3 — syscall table + ABI | **done for the static case** — generated aarch64 table (§3.2), exec.c ported, code-cache sync wired in, TLS via `TPIDR_EL0`, `struct stat` corrected to the aarch64 layout (§3.5.4), `statx`/`prlimit64` wired. A static ELF loads, runs, stats, syscalls and exits (`make check-smoke`). `ppoll`/`epoll_*` and the dynamic linker still to come |
| 4 — signals, fork, threads | **signals and fork done** — a guest takes a signal, runs the handler at EL0 and resumes; and `fork` works reliably, implemented as fork + `exec` of a resumed process because the framework will not give a forked child a vCPU (§3.5.8). Threads work as well - `CLONE_SETTLS` into `TPIDR_EL0`, thread exit with `CHILD_CLEARTID`, futex `WAIT`/`WAKE`, and `fork` from a threaded process - covered by `threadtest`. `execve` from a multi-threaded process stops the others first (`mtexectest`) |
| 5 — dynamic linking and rootfs | **bash runs** — Debian trixie `bash` executes external commands, pipelines, command substitution, loops and redirections under a real `ld-linux-aarch64.so.1` + glibc. Needed file-backed mmap by copy, a 16KiB guest-page model, the caches on (§3.5.5) and `VREG_PC` via `ELR_EL1` (§3.5.7). Rootfs built offline from the netinst ISO |
| 6 | test port — not started |

`make ARCH=arm64` produces a signed arm64 binary that **runs real static aarch64
Linux ELFs** - proven by `make check-smoke`. Bounds today: static and
dynamically-linked guests work, with signals, `fork`, threads and `mprotect`.
`munmap` works, including a range that leaves live pages inside the 16KiB blocks
it partly empties (§3.5.3), and a `MAP_SHARED` file mapping is mapped for real so
the guest's writes reach the file. Three real host-side bugs stood between "links"
and "runs", all found by the first smoke test and fixed: a W^X-incompatible RWX
mmap of the malloc arena, an unreachable `RLIMIT_NOFILE`-derived kernel fd range
on modern macOS, and an unchecked `PROT_EXEC` file mmap of the ELF.

---

## 1. Why this is a rewrite, not a port

Noah is a hardware hypervisor, not a syscall shim. It runs Linux user code as a
guest inside a VT-x VM with a flat identity map, sets the VMCS exception bitmap to
`0xffffffff` ([src/main.c:415](src/main.c#L415)), and catches the guest's `syscall`
instruction as a `#UD` vmexit ([src/main.c:249](src/main.c#L249)) — `EFER.SCE` is
never set, so `syscall` faults instead of executing. The `#UD` handler decodes the
2-byte `0f 05`, reads the args out of RDI/RSI/RDX/R10/R8/R9, and dispatches.

On arm64 the VMX API does not exist. From the macOS 26.5 SDK:

```
Hypervisor.framework/Headers/hv_vmx.h:11    #ifdef __x86_64__
Hypervisor.framework/Headers/hv_vmx.h:259   #endif /* __x86_64__ */
Hypervisor.framework/Headers/hv_vcpu.h:10   #ifdef __arm64__
Hypervisor.framework/Headers/hv_vcpu.h:455  #endif
```

`hv_vmx_vcpu_read_vmcs`, `hv_vcpu_read_register`, `hv_x86_reg_t` and every `HV_X86_*`
constant are compiled out entirely. The arm64 build gets a different API
(`hv_vcpu_run` + `hv_vcpu_exit_t`, `hv_vcpu_get_reg`, `hv_vcpu_get_sys_reg`, ESR_EL2
exit classes). There is no shim layer that makes one look like the other.

Because the VM backend changes, the guest ISA changes with it, and that cascades
into the ELF loader, the syscall table, signal frames, TLS, and the rootfs.

### What survives

Roughly 60% of the tree is architecture-neutral and should need only mechanical
edits. Of the 167 implemented syscalls, the bodies in
[src/fs/fs.c](src/fs/fs.c) (2159 lines), [src/net/net.c](src/net/net.c),
[src/sys/time.c](src/sys/time.c), [src/ipc/futex.c](src/ipc/futex.c),
[src/ipc/sem.c](src/ipc/sem.c), [src/mm/mmap.c](src/mm/mmap.c) and
[src/conv.c](src/conv.c) are Darwin↔Linux translation with no x86 in them.

A significant piece of luck: the `*at` syscalls that aarch64 *requires* (it has no
`open`, `stat`, `dup2`, `pipe`, `fork`, `access`, `mkdir`, `unlink`, `rename`,
`readlink`, `chmod`, `chown`, …) are **already implemented** — `openat`,
`newfstatat`, `readlinkat`, `faccessat`, `pselect6`, `getdents64`, `dup3`, `pipe2`,
`renameat`, `unlinkat`, `mkdirat`, `fchownat`, `fchmodat`, `symlinkat`, `linkat`.

### What has to be rewritten

| Concern | Today | File(s) |
|---|---|---|
| VM backend | VT-x / VMCS | [lib/vmm.c](lib/vmm.c), [include/vmm.h](include/vmm.h), [include/x86/vmx.h](include/x86/vmx.h) |
| Exit dispatch | `VMX_REASON_*`, `#UD`, EPT violation | [src/main.c:200-390](src/main.c#L200) |
| Guest page tables | x86 4-level, 1GiB `PTE_PS` blocks | [src/mm/pdp.h](src/mm/pdp.h), [src/mm/mm.c:47-65](src/mm/mm.c#L47) |
| Segmentation / IDT / GDT | real x86 descriptors | [src/mm/mm.c:67-131](src/mm/mm.c#L67), [include/x86/vm.h](include/x86/vm.h), [src/main.c:437](src/main.c#L437) |
| Guest ABI gate | `e_machine != EM_X86_64` | [src/proc/exec.c:56](src/proc/exec.c#L56), [src/proc/exec.c:107](src/proc/exec.c#L107) |
| Syscall convention | nr=RAX, args RDI/RSI/RDX/R10/R8/R9 | [src/main.c:57](src/main.c#L57) |
| Syscall numbering | x86-64 table, 329 entries | [include/syscall.h](include/syscall.h) |
| Signal frames | 16 named x86 GPRs → `sigcontext` | [src/ipc/signal.c:122](src/ipc/signal.c#L122) |
| Register snapshot (fork) | `x86_reg_list`, `vmcs_field_masked_list` | [lib/vmm.c:190](lib/vmm.c#L190), [src/proc/fork.c](src/proc/fork.c) |
| FPU state | `fxsave` layout, `mxcsr` | [src/main.c:484](src/main.c#L484) |
| Time / identity | TSC & `KERNEL_GS_BASE` MSRs, `CPUID` | [src/main.c:477](src/main.c#L477), [src/main.c:353](src/main.c#L353) |
| Rootfs | x86-64 Ubuntu via `noahstrap` | [bin/noah.in:37](bin/noah.in#L37) |

---

## 2. The core design decision: how to trap `svc`

This is the crux of the port and should be settled before anything else is written.

On x86 Noah gets syscall traps for free: the guest runs at ring 0 with a flat map,
`syscall` is disabled, and the resulting `#UD` exits straight to the host.

ARM has no equivalent. `svc #0` from EL0 goes to **EL1**, not EL2 — the host never
sees it. Hypervisor.framework does not expose an HCR_EL2 bit that routes `svc`
directly to EL2.

**Proposed design — EL1 trampoline:**

1. Guest user code runs at **EL0**.
2. Noah maps a small guest-owned **EL1 vector page** and points `VBAR_EL1` at it.
3. The synchronous-exception entry in that vector is a handful of instructions
   ending in `hvc #0`.
4. `hvc` exits to the host: `hv_vcpu_run` returns with
   `exit->reason == HV_EXIT_REASON_EXCEPTION` and `ESR_EL2.EC == 0x16` (HVC64).
5. The host reads `x8` (syscall nr) and `x0`–`x5` (args) with `hv_vcpu_get_reg`,
   dispatches through `sc_handler_table`, writes the result to `x0`.
6. The host resumes; the EL1 stub `eret`s back to EL0 using the `ELR_EL1` /
   `SPSR_EL1` the CPU saved on the original `svc`.

The stub must also distinguish `svc` from a genuine EL0 fault by reading `ESR_EL1.EC`
(`0x15` = SVC64) and forwarding data/instruction aborts through a different `hvc`
immediate so the host can raise SIGSEGV.

**Cost:** measured, not estimated — **~818 ns** per empty round trip
(EL0 `svc` → EL1 stub → `hvc` → host → `eret` → EL0), 200k iterations on an M5,
with no syscall dispatch on the host side at all. That is the floor.

For comparison a native Linux syscall is ~50–100 ns, so this is roughly 10×. But
the dominant term is the `hv_vcpu_run` transition, not the two exception-level
changes, which puts it in the same class as the x86 build's VMCS round trip
(a VT-x vmexit is ~300–600 ns). So the design is no worse than what NABI does
today on Intel, and it stays noise against any syscall that touches a file or a
socket. Syscall-dense workloads in tight loops will feel it.

Worth noting that the usual worst offenders need not trap at all on aarch64:
`CNTVCT_EL0` is readable directly from EL0, so the clock calls that dominate many
syscall profiles can be served without a round trip.

**Risk:** ~~this is the single riskiest assumption in the plan~~ — **resolved.**
Phase 0 proved it on hardware before anything was built on it. See §4.

**Alternative considered and rejected:** rewriting `svc` to `hvc` at load time.
Breaks self-modifying code, JITs, and anything that reads its own `.text`
(the Go runtime does). Not viable.

---

## 3. ABI changes

### 3.1 Syscall convention

| | x86-64 | aarch64 |
|---|---|---|
| number | `rax` | `x8` |
| args | `rdi rsi rdx r10 r8 r9` | `x0 x1 x2 x3 x4 x5` |
| return | `rax` | `x0` |
| instruction | `syscall` (`0f 05`) | `svc #0` (`d4000001`) |
| PC advance | host does `rip += 2` | CPU already advanced `ELR_EL1` |

Note the last row: [src/main.c:255](src/main.c#L255) manually adds 2 to RIP after a
syscall. On ARM that must **not** happen — the saved `ELR_EL1` already points past
the `svc`. Getting this wrong silently skips an instruction.

### 3.2 Syscall numbering — the big one

aarch64 uses the *generic* table from `asm-generic/unistd.h`, not the x86-64 table.
The numbers are unrelated. Illustrative:

| syscall | x86-64 | aarch64 |
|---|---|---|
| `read` | 0 | 63 |
| `write` | 1 | 64 |
| `openat` | 257 | 56 |
| `mmap` | 9 | 222 |
| `rt_sigreturn` | 15 | 139 |
| `clone` | 56 | 220 |
| `execve` | 59 | 221 |
| `exit` | 60 | 93 |
| `futex` | 202 | 98 |
| `wait4` | 61 | 260 |

**Done, generated not hand-typed.** [include/syscall_arm64.h](include/syscall_arm64.h)
is produced by [util/gen_syscall_table.py](util/gen_syscall_table.py) from Linux
v6.6 `include/uapi/asm-generic/unistd.h` (`make syscalls UNISTD=<path>`, output
byte-reproducible), and [include/syscall.h](include/syscall.h) selects it or the
hand-kept [syscall_x86.h](include/syscall_x86.h) by architecture. The generator
prints an audit report: **137 handlers wired** to their aarch64 numbers, the rest
`unimplemented`.

The ~40 legacy handlers with no aarch64 number (`open`, `stat`, `fork`, `dup2`,
`arch_prctl`, …) turned out **not** to be free to leave compiled in, contrary to
the original assumption below: their `meta_strace` wrappers reference
`LSYS_<name>`, which only exists for names in the table. So the generator appends
them as a compat tail past the real range — an `LSYS_` id and a prototype without
disturbing the real numbering. Real glibc never issues those numbers.

Originally: *"the ~30 legacy handlers can stay compiled in — glibc will never call
them. Removing them is cleanup, not a blocker."* Half right — they stay, but only
because the generator wires them a compat id.

`statx` (291) and `prlimit64` (261) are now wired: handlers added (statx repacks
the same darwin stat newfstatat uses into the fixed 256-byte `struct statx`;
prlimit64 reuses the rlimit path and supports the calling process), the names
added to [syscall_x86.h](include/syscall_x86.h) so the generator counts them as
implemented, and their two aarch64 slots flipped from `unimplemented`. The v6.6
`unistd.h` input was not kept around, so rather than reconstruct it the two
generated lines were edited directly — this is exactly what a regeneration from
that header plus the updated x86 table would produce. Verified by the `sxtest`
smoke binary.

`ppoll` (73) is wired too: aarch64 has no plain `poll` in the set libc uses, so
it shares poll's marshalling body and adds the relative-timespec timeout and an
optional signal mask (installed around the wait, not atomically inside it).

`epoll` is wired too - `epoll_create1` (20), `epoll_ctl` (21) and `epoll_pwait`
(22) - implemented over kqueue in [src/fs/epoll.c](src/fs/epoll.c). The two
models are close but not congruent: epoll describes a descriptor with one mask
where kqueue uses a filter per direction, so a registration is up to two kevents
and a wait has to fold them back into one event per descriptor; the guest's
opaque 64-bit data is kept in a registration table rather than kqueue's `udata`,
which is what makes `EPOLL_CTL_MOD`, `EPOLLONESHOT` and `EPOLLHUP` exact; and a
regular file, which kqueue will not accept and epoll always calls ready, is
answered without going to the kqueue at all. `fstatat` is aarch64's `newfstatat`
(nr 79) and already exists under that name.

### 3.3 TLS

x86-64 sets the thread pointer with `arch_prctl(ARCH_SET_FS)` — a syscall Noah
implements. aarch64 has **no such syscall**: the thread pointer is `TPIDR_EL0`,
readable directly by user code with `mrs`. It is established by the `tls` argument
to `clone`, and thereafter never goes through the kernel.

So: delete the `arch_prctl` path, and make `clone` write `TPIDR_EL0` via
`hv_vcpu_set_sys_reg`.

**Partly done.** [include/arch.h](include/arch.h) now has `vmm_set_tls` /
`vmm_get_tls` (FS base on x86, `TPIDR_EL0` on aarch64), verified on hardware -
the guest's `mrs tpidr_el0` reads back exactly what the host set. `clone`'s
`CLONE_SETTLS` path and `arch_prctl`'s FS cases both route through it;
`arch_prctl` is compiled but unreachable on aarch64 (no such syscall number). Also confirm `TPIDR_EL0` is saved/restored across the
fork snapshot and signal delivery — if it isn't, every threaded program breaks in a
way that looks like random memory corruption.

### 3.4 Signals — **done**

aarch64 `sigcontext` is `{ fault_address, regs[31], sp, pc, pstate, __reserved[] }`
followed by a chain of context records (`fpsimd_context`, `esr_context`,
`sve_context`, terminated by a null record). This replaced the 16 named-register
copies at [src/ipc/signal.c:122-140](src/ipc/signal.c#L122); the arch half now
lives in [src/ipc/signal_arm64.c](src/ipc/signal_arm64.c), which marshals x0-x30,
SP, one `fpsimd_context` and a null terminator.

Critically: **aarch64 does not support `SA_RESTORER`.** The kernel points `x30`
at `__kernel_rt_sigreturn` in the vDSO. Noah therefore maps a small vDSO-like
page containing `mov x8, #139; svc #0` and points `x30` at it when delivering a
signal. That page is mapped eagerly at init, before the MMU comes on — a lazy
mapping during delivery leaves a negative walk-cache entry that guest TLBI cannot
flush under HVF (§3.5.3).

The one subtlety that cost real debugging: when a signal is delivered off the
back of a syscall the vCPU is parked in the EL1 trampoline, so `HV_REG_PC`/`CPSR`
hold the trampoline's own `eret`, not the guest. The interrupted EL0 PC and
PSTATE are banked in `ELR_EL1`/`SPSR_EL1`; `save_sigcontext` reads those when
parked at EL1 and falls back to `PC`/`CPSR` for an async interruption already at
EL0. Delivery forces `CPSR = EL0t` so the handler does not run at EL1. Verified
end to end by the `sigtest` smoke binary (install SIGUSR1, `kill()` self, handler
runs, execution resumes).

### 3.5 Guest memory

Stage-2 is the easy part — `hv_vm_map(haddr, ipa, size, flags)` has the same shape
and the same `HV_MEMORY_READ/WRITE/EXEC` flags on both architectures, so
[src/mm/mmap.c](src/mm/mmap.c) and the `mm_region` bookkeeping in
[src/mm/mm.c](src/mm/mm.c) are essentially unchanged. `vmm_mmap`/`vmm_munmap` in
[lib/vmm.c:34](lib/vmm.c#L34) port as-is.

Stage-1 is new. Replace the x86 PML4/PDP pair with an ARM64 translation table
(4KiB granule, 2MiB or 1GiB blocks for the straight map), plus `TTBR0_EL1`,
`TCR_EL1`, `MAIR_EL1`, and `SCTLR_EL1.M`. [src/mm/pdp.h](src/mm/pdp.h) — 512
generated entries — gets regenerated in ARM block-descriptor format.

`user_addr_max` is `0x7fc0000000` and `kmap` stacks kernel objects above it
([src/mm/mm.c:26-44](src/mm/mm.c#L26)). That layout can be kept; only the
descriptor encoding changes.

**Watch out:** Apple Silicon uses **16KiB** pages natively in macOS userland, while
Linux/aarch64 guests overwhelmingly assume 4KiB. `PAGE_SIZE` assumptions are baked
into `is_page_aligned`, `kmap`'s `& 0xfff` masks, and mmap offset handling. Decide
early: 4KiB guest granule (correct for the guest, requires host allocations be
16KiB-aligned and sub-mapped) vs 16KiB (breaks guest binaries). **Recommend 4KiB.**

**Measured (M5, macOS 26).** `hv_vm_map` rejects anything not 16KiB-granular, on
*all three* arguments independently:

| host addr | IPA | size | result |
|---|---|---|---|
| 16K | 16K | 16K | `HV_SUCCESS` |
| 16K | 16K | 4K  | `HV_BAD_ARGUMENT` |
| 4K  | 16K | 16K | `HV_BAD_ARGUMENT` |
| 16K | 4K  | 16K | `HV_BAD_ARGUMENT` |
| 16K | 16K | 8K  | `HV_BAD_ARGUMENT` |

This confirms the recommendation but sharpens what it costs. The two translation
stages have different minimum granules and that is not negotiable:

- **Stage 2** (`hv_vm_map`, IPA → host) is **16KiB**, always.
- **Stage 1** (the guest's own `TTBR0_EL1` tables, VA → IPA) is ours to define in
  guest memory, so it can be **4KiB**. The guest sees 4KiB pages.

The friction lands in [src/mm/mm.c](src/mm/mm.c), which today performs one
`vmm_mmap` per guest region at 4KiB granularity. That no longer maps 1:1 onto a
stage-2 call. A guest `mmap` of a single 4KiB page has three possible answers:

1. **Round the stage-2 region up to 16KiB.** Simplest, and wrong: it publishes
   three neighbouring pages of whatever the host allocation happens to hold into
   the guest's address space. An isolation bug, not just an accounting one.
2. **Sub-manage.** Allocate stage-2 in 16KiB chunks and hand out 4KiB stage-1
   mappings within them, so the guest only ever sees pages it owns. Correct, and
   it means `mm` grows a two-level notion of a region.
3. **16KiB guest granule.** Removes the mismatch entirely, but Debian/Ubuntu
   arm64 userland is built for 4KiB kernels and ELF `p_align` will not
   necessarily cooperate.

**Option 2, and it is now built** — [src/mm/pt_arm64.c](src/mm/pt_arm64.c),
proven on hardware by `make check-arm64` (the read-only-4KiB-page-inside-an-RWX-
16KiB-chunk test is the one that matters). The cost stayed confined to the
allocator, as predicted.

Note also that `kmap` asserts `& 0xfff` and `__page_aligned` is
`aligned(0x1000)`; both are 4KiB and both feed `vmm_mmap` directly, so both have
to become 16KiB on the arm64 side regardless of what the guest sees.

### 3.5.2 The `vmm_mmap` two-stage model — **done**

[src/mm/pt_arm64.c](src/mm/pt_arm64.c)'s `vmm_mmap` maps a guest region across
both translation stages, verified end to end on hardware: a guest stores through
a `vmm_mmap`'d VA and the host reads the value back from the exact buffer it
passed in (`make check-arm64`, test_arm64_vmmap.c).

On x86 `vmm_mmap` is one `hv_vm_map`: guest-virtual equals guest-physical (flat
map), and [src/mm/mmap.c](src/mm/mmap.c)'s Darwin-`mmap` `ptr` maps straight in.
arm64 has two stages and a 16KiB stage-2 granule, so it does more, but the
resolution turned out **simpler and better than the earlier draft feared** — the
caller's host pointer is used directly as the backing, no copy:

- The Darwin `mmap` `ptr` is 16KiB-aligned (the host page size), so it satisfies
  `hv_vm_map`'s host-address constraint as-is.
- Its allocation is rounded up to a whole host page, so mapping
  `roundup(size, 16KiB)` of it is always in bounds even when the logical region
  is smaller.
- The guest VA need not be 16KiB-aligned, but the **IPA is ours to choose**, so a
  16KiB-aligned IPA block is allocated per region and stage 1 maps each 4KiB VA
  page onto its offset within it.

Two consequences worth stating:

- **`MAP_SHARED` does *not* regress.** Because `ptr` itself is the stage-2
  backing and, for a file mapping, `ptr` is the file's page cache, guest writes
  reach the file. The chunk-copy model an earlier draft proposed would have lost
  that; using the caller's pointer keeps it. There is no copy on the mmap path
  at all.
- The stage-2 block can exceed the logical region by up to ~12KiB (the
  rounding), but the guest cannot address the tail — stage 1 maps only the VA
  range, so no VA translates into the extra IPA — and it is the caller's own
  reservation regardless. No leak.

### 3.5.3 `vmm_munmap` and the TLB — measured, and partly done

Unmapping a guest VA turned out to hinge on a non-obvious HVF property, so it
was spiked on hardware before implementing. Findings, all measured on an M5:

- **The guest's own `TLBI` does not work.** An EL1 `tlbi vmalle1` (and
  `vmalle1is`) executes but does **not** invalidate the guest's cached
  translations — a subsequent access to a page whose stage-1 descriptor was
  just cleared still succeeds. HVF appears to cache combined stage-1+2
  VA→host entries that guest TLB maintenance does not reach. And the arm64
  `hv_vcpu_*` API has no TLB-invalidate call (only the x86 half of the
  framework does).
- **`hv_vm_unmap` reliably does.** Unmapping a page's 16KiB stage-2 block
  faults the next access — even with a sibling page primed in the same block,
  and it survives an unrelated `hv_vm_map` in between. This is the only reliable
  invalidation primitive available.

So `vmm_munmap` ([src/mm/pt_arm64.c](src/mm/pt_arm64.c)) unmaps whole 16KiB
stage-2 blocks and clears their stage-1 descriptors. Verified on hardware
(`make check-arm64`, test_arm64_munmap.c): an unmapped region faults, and an
adjacent region is untouched. This covers **whole-region munmap** — the common
case, and everything `mprotect`-free code and the dynamic linker's whole-mapping
teardown need.

**Done: the sub-block partial split.** A `munmap` that clears one 4KiB page of a
16KiB block while a sibling stays live cannot use the block-unmap primitive - it
would fault the survivor too - and clearing the stage-1 entry alone does not work
either, since the guest `TLBI` does not invalidate HVF's combined entries.

This was written up here as needing *evacuation*: re-home the survivor to a fresh
block so the old one could be unmapped whole. A hardware spike had shown that was
not merely a page-table operation - the no-copy backing shares one host page
across the block, so survivor and victim resolve to the same host page, and
copying the survivor elsewhere desynchronises its `mm_region.haddr`, which is
what `guest_to_host` reads. The conclusion was that it needed a change to the
mmap ownership model.

That conclusion was wrong, or rather it answered the wrong question. Nothing has
to move. What was actually missing was a way to invalidate a block *without*
leaving it unmapped - and `hv_vm_unmap` followed immediately by `hv_vm_map` of
the same block is exactly that, the same operation that makes `mprotect` take
effect (§3.5.6). So the partial case clears the stage-1 descriptors it is asked
to and re-establishes the block: the survivor keeps working because its
descriptor was never touched, and the cleared pages fault because theirs are gone
and the stale translations went with the flush. A block left backing nothing is
still unmapped outright, which releases it.

`splitmunmaptest` covers it - live pages either side of an unmapped middle keep
their contents, and touching the middle faults. The previous revision panics on
that binary.

### 3.5.1 Cache coherency — net-new work with no x86 counterpart

**The guest's instruction fetch does not see host writes to guest memory.**
Found on hardware while bringing up the backend: rewriting the guest payload
between tests silently re-ran the *previous* payload, and every assertion failed
in a way that looked like the decoder was broken.

Measured, on an M5:

| after writing guest code | result |
|---|---|
| nothing | guest executes stale instructions |
| `sys_dcache_flush` only | guest executes stale instructions |
| `sys_icache_invalidate` only | correct |
| both | correct |

So the stale party is the instruction path, and `sys_icache_invalidate` — which
issues the `dc cvau` / `ic ivau` pair — is both necessary and sufficient.
Cleaning the data cache alone achieves nothing.

x86 has no equivalent requirement; its caches are coherent with instruction
fetch, which is why nothing in the existing tree does anything like this. Every
place the host writes code the guest will execute now needs
`vmm_arm64_sync_guest_code()`:

- the EL1 trampoline (done, inside `vmm_arm64_install_trampoline`)
- **the ELF loader** in [src/proc/exec.c](src/proc/exec.c) — Phase 3, and the
  one that matters, since it writes the entire program image
- the signal return trampoline — Phase 4 (§3.4)
- anything the guest writes itself and then executes: JITs, and any program that
  generates code. The guest's own `ic ivau` handles that case, but only if
  `SCTLR_EL1` and the stage-2 attributes let it take effect, which is worth
  re-checking once the MMU is on.

The failure mode is worth naming because it is so misleading: the guest runs
whatever bytes were previously at those addresses. That surfaces as arbitrary
wrong behaviour — a stale syscall, a jump into garbage — rather than as anything
that points at caching.

### 3.5.4 `struct stat` is arch-specific — **fixed**

The kernel's `struct stat` for `fstat`/`newfstatat` is not just padded
differently between architectures, it reorders fields: x86-64 puts an 8-byte
`st_nlink` before `st_mode`, while the asm-generic layout aarch64 uses puts a
4-byte `st_mode` before a 4-byte `st_nlink`. `stat_darwin_to_linux` fills
`struct l_newstat` by field name, so a single x86-shaped definition compiled for
an aarch64 guest silently lands each value at the wrong offset — a regular file
comes back with `st_mode` equal to its link count (1), i.e. not a regular file,
and `cat`/`ls`-style programs break immediately. The smoke binaries never
`stat` anything, so this stayed invisible through Phase 3. `struct l_newstat` is
now `#if`-split by host arch (the guest ABI follows the host), and the
`stattest` smoke binary asserts a file reads back as `S_IFREG` with a nonzero
size.

### 3.5.5 The caches must be on, or atomics fault — **fixed**

`pt_enable` originally set only `SCTLR_EL1.M`. That runs, and every freestanding
test passed, because nothing they did needed a cache. But with `SCTLR_EL1.C`
clear the CPU treats **every** access as Non-cacheable regardless of what MAIR
and the descriptors say — and load/store-exclusive and the LSE atomics are not
supported on Non-cacheable memory. The guest's first `LDXR`/`STXR` therefore
takes a data abort with `ESR` DFSC `0x35`, "unsupported exclusive or atomic
access".

The symptom is maximally misleading: an unkillable loop of identical faults
(millions per second) at an address whose stage-1 descriptor is valid and
readable and whose stage-2 mapping is present and readable — nothing points at
caches. And because every real libc takes a lock during startup, this gated
running *any* glibc binary while leaving hand-written assembly tests perfectly
happy.

`pt_enable` now sets `SCTLR_EL1.C` and `.I` along with `.M`. The tables already
requested Normal Write-Back Inner-Shareable memory; enabling the caches is what
lets those attributes take effect. The `atomic` smoke binary guards it.

### 3.5.6 Loading a dynamically-linked binary — **working**

Three things had to change before `ld-linux-aarch64.so.1` could load a library
(all in [src/mm/mmap.c](src/mm/mmap.c) and [src/proc/exec.c](src/proc/exec.c)):

- **File-backed mmap is a copy, not a mapping.** Apple Silicon refuses to map an
  arbitrary file `PROT_EXEC` (EPERM under the hardened runtime) and wants
  16KiB-aligned file offsets, while a guest's ld.so maps library segments R-X at
  4KiB-aligned offsets. So a file map is backed by anonymous host memory with the
  bytes `pread` in; the guest's R/W/X comes from stage 2 either way. Executable
  file maps are icache-synced, exactly as the ELF loader does for its own PF_X
  segments — without it the guest executes stale library text, which presents as
  a *nondeterministic* hang.
- **The guest is a 16KiB-page machine.** `AT_PAGESZ` is `STAGE2_GRANULE`, and
  mmap regions, `alloc_region`, mmap/munmap lengths and ELF segment loading are
  all 16KiB-granular, so no segment shares a 16KiB stage-2 block with its
  neighbour (which `vmm_munmap` cannot split, §3.5.3).
- **munmap rounds its length up** to that granule, as the kernel does: glibc's
  ld.so passes raw, unrounded segment lengths and relies on the kernel to extend
  them to a whole page.

`mprotect` works now. It rewrites the stage-1 descriptors, which are what the
guest is actually subject to - not `hv_vm_protect`, which the x86 path uses and
which takes an IPA where `region->gaddr` is a virtual address - and then
re-establishes the affected stage-2 blocks so the translation notices. That
second step is not an optimization: a guest TLBI does not invalidate HVF's
combined stage-1+2 entries (§3.5.3), so without it a *tightening* would silently
do nothing, which is the direction that matters. `PROT_NONE` turns out to be the
absence of AP[1] rather than a bit of its own, which is what makes a guard page
fault at all.

Fixing it exposed an older bug in the shared `mprotect` handler, so x86 had it
too: once a region ended exactly where the request did, the loop still went
looking for a contiguous region after it and reported ENOMEM for an mprotect
that had in fact succeeded - every mprotect of the highest mapping, and any whose
range ended at a gap.

The `protecttest` smoke binary writes to a page it has just made read-only and
requires the trap; it reports "NOT ENFORCED" if the stage-1 update is removed.
Still open on this path: `MAP_SHARED` file write-back is not preserved by the
copy.

### 3.5.7 `VREG_PC` and the trampoline — **fixed**

`execve` silently did nothing: the new program never ran, and the guest wandered
off with no fault, no syscall and no output. The cause is the EL1 trampoline
leaking through the arch-neutral register interface.

Whenever the host is looking at the vCPU after a trap, the vCPU is *parked in the
trampoline*: the guest's `svc` took it to EL1, the stub bounced out with `hvc`,
and `HV_REG_PC` is the stub's own `eret` while `CPSR` reads EL1h. The guest's
real program counter is banked in `ELR_EL1` — which that `eret` is about to
consume. `vmm_set_reg(VREG_PC, entry)` wrote `HV_REG_PC`, so the `eret` discarded
the new entry point and returned to the *old* image's address, whose mappings
`prepare_newproc` had just torn down.

`VREG_PC` now reads and writes `ELR_EL1` while parked at EL1, the same way
`VREG_SP` already resolves to `SP_EL0` — the trampoline is a backend detail and
has no business being visible to `exec.c`. Startup exec was unaffected and hid
the bug: it runs before the guest has ever trapped, so `CPSR` is EL0t and
`vmm_arm64_enter_el0` sets `ELR_EL1` explicitly.

This is the third instance of the same trap (see §3.4 for the signal-frame one):
on aarch64, *any* host code that touches the guest's PC or PSTATE must ask which
exception level the vCPU is parked at first. The `exectest` smoke binary guards
it.

### 3.5.8 `fork` is unreliable, and it is the framework — **diagnosed, not fixed**

Roughly one guest `fork` in eight produces a child that never runs. The cause is
not in NABI: **once a vCPU has existed anywhere in a process, `hv_vcpu_create` in
a forked child crashes** — a `SIGSEGV` inside Hypervisor.framework, not an error
return, so there is nothing to test and nothing to handle. It reproduces in forty
lines with no NABI code involved; see [spike/arm64-fork/](spike/arm64-fork/),
which also shows it is the vCPU specifically (a parent that only created and
destroyed a *VM* before forking never sees it).

This surfaced only when the caches were enabled (§3.5.5) — not because caches
cause it, but because before that the guest was slow and simple enough that the
timing rarely lined up.

Measured and rejected as fixes: forking from a thread that never touched a vCPU
(the state is process-wide, not thread-local); serializing the two rebuilds;
creating the vCPU before replaying the stage-2 mappings; backing guest pages with
`mmap` rather than the C heap; and retrying the fork — within one NABI run the
failure is deterministic, so every retry dies too, even though it varies between
runs.

Two escapes are measured in the spike, both perfect over the runs tried: a
**zygote** (a process that never touched HVF forks the children — 0/100, with the
runner holding a live VM throughout) and **fork + exec** (the child replaces its
image before creating a vCPU — 0/75).

**fork + exec is the one to build**, even though the zygote is the more obvious
fix. Both need the same hard thing — the new process no longer inherits the
guest's address space, so guest memory and NABI's bookkeeping must be handed over
explicitly instead of arriving by copy-on-write, which is checkpoint/restore and
is the bulk of the work. The difference is everything else a process carries: a
fork+exec child is still a `fork` child and **inherits the open file
descriptors**, so the guest fd table keeps pointing at the right host files and
only the table needs serializing. A zygote child shares no ancestry with the
running guest, so every open file would have to be re-opened and re-positioned
from serialized state — more code, and not reliably possible for pipes, sockets
and unlinked files.

The shape is: guest memory into a shared-memory arena, process state (mm
regions, fd table, credentials, sigactions, task, brk, vCPU snapshot) serialized,
and `__do_clone_process` becomes fork + `exec` of `nabi --resume <fd>`.

**The memory half of that is done**: [src/mm/arena.c](src/mm/arena.c). Every
guest region - `mmap`, `mremap`, the ELF image, the stack, `brk`, and the stage-1
page tables - now comes from a single unlinked, file-backed arena rather than the
C heap or a private anonymous mapping, and each region records the arena offset
that names it. Host addresses mean nothing to another process; offsets do, and
descriptors survive `exec` where pointers do not.

One correction worth recording, because the obvious design is wrong. The arena
was first mapped `MAP_SHARED`, which would have made a handover free: the child
maps the same offsets and the bytes are already there. But `MAP_SHARED` also
removes copy-on-write from an ordinary `fork`, and `fork` is still ordinary until
the rework lands - a forked child wrote straight into its parent's guest memory,
and guest pipelines stopped working, because the two halves of `cmd | cmd`
corrupted each other. The mappings are private, and the handover pays for that by
having to write the live bytes into the arena at fork time instead of finding
them already there.

Two allocations deliberately stay outside the arena: SysV `shmat`, which must
alias a segment genuinely shared with other processes, and the vkernel's own
`kmap`'d bookkeeping. `make check-arm64` covers the arena's contract - including
that a guest write must *not* reach the arena - and needs no VM.

**The state half is done too**: [include/checkpoint.h](include/checkpoint.h) and
[src/proc/checkpoint.c](src/proc/checkpoint.c) write everything about a guest
that is not bytes of its memory - the vCPU, the region list and the mm scalars it
does not imply, the stage-2 registry, the stage-1 allocator's cursors and chunks,
the credentials, the task's identity/mask/alternate stack, the signal
dispositions, and the descriptor tables. Nothing in the format holds a host
pointer, because a pointer is the one thing the far side cannot use; memory is
named by arena offset throughout.

The descriptor tables are the part that fork+exec makes easy and a zygote would
have made hard: the host descriptors survive `fork` and `exec` by themselves, so
only the *mapping* - which guest number refers to which host descriptor, and
whether it is close-on-exec - has to be written down. `struct file` holds nothing
else worth saving, since its ops pointer is the one static table every file
shares.

The format is versioned and refuses a truncated or unknown-version checkpoint
rather than resuming a guest from state it may be misreading; `test_checkpoint`
drives a real descriptor and checks both refusals along with every field.

**The `--resume` path is built but not yet switched on.**
[src/proc/resume.c](src/proc/resume.c) adopts the arena, maps every region and
page-table chunk privately from it, creates the VM, replays stage 2, rebuilds the
stage-1 allocator's bookkeeping, restores the mm regions, credentials, task,
signal dispositions and descriptor tables, and finally restores the vCPU - last,
because that is what turns translation back on. `nabi --resume <ckpt> <arena>`
in [src/main.c](src/main.c) is the entry point.

Nothing calls it yet: `__do_clone_process` still uses the plain fork path, so the
switch is a change to fork alone and today's behaviour is untouched. Two things
made that split cheap. `kmap` - vkernel memory published into the guest's address
space, which a resumed process could not reconstruct - turns out to be x86-only,
so arm64 has no such state. And the wire format lives in
[checkpoint.c](src/proc/checkpoint.c) apart from the machinery here, so the
format stays testable without linking half the system.

**`__do_clone_process` can now take that path, behind `NABI_FORK_EXEC=1`.** It
eliminates the failure this was all for: `forktest` goes from **6/40 to 0/40** on
the same machine and the same forty runs, and the smoke suite passes cleanly
three times over where the default path fails intermittently. The parent no
longer touches its VM at all - the old path destroyed and rebuilt it on both
sides, and it was the *child's* rebuild that crashed, so with the child exec'ing
there is nothing left to crash.

Two things the guest turned out to need that a checkpoint alone does not carry:

- **The clone parameters.** They describe what this *call* asks of the child -
  write your tid here, take this TLS - and are not part of the parent's state,
  so they travel as arguments and are applied after the restore. Without them
  `clonetid` failed every single time.
- **Its close-on-exec descriptors.** The guest asked to *fork*, and fork does not
  close them; only exec does. Since this fork is implemented as fork+exec, the
  kernel would apply semantics the guest never asked for. They are cleared on
  the host before the exec and restored from the checkpoint afterwards, so a
  later guest `execve` still closes the right ones.

Fixing the first of those also uncovered a bug that predates all of this: NABI
mirrored a guest `mprotect` onto the *host* mapping, which is how NABI itself
reaches guest memory. A guest `PROT_NONE` - which ld.so uses for guard pages and
RELRO - therefore made NABI unable to touch the guest's own memory. It is a
no-op on arm64 now; the permissions the guest is subject to are the stage-1
descriptors, not that mapping's bits.

Pipelines work now too, and the cause was the one hazard flagged when the arena
was first made `MAP_PRIVATE`. A child maps the arena privately and reads any page
it has not yet written straight out of the file, so when the parent copied its
guest into that same arena for a *second* fork, it reached into the still-running
first child and changed its memory to the parent's later state. Both halves of
`cmd | cmd` then came up believing they were the same half - the trace showed the
two children issuing identical `dup3` and `execve` calls. Sequential commands hid
it, because the first child had already exited.

Each handover now copies the guest into an arena **of its own**, which nothing
writes to again. `cmd | cmd`, three-stage pipelines, command substitution and
loops feeding a pipeline all work.

On the same machine and the same forty runs: `forktest` **3/40 -> 0/40** and
`clonetid` **7/40 -> 0/40**, with repeated clean smoke runs where the old path
failed intermittently. **This is now the default on arm64.** `NABI_FORK_EXEC=0`
still selects the old path, kept for bisecting a suspected handover bug rather
than as a supported way to run - it is the same code x86 uses, and on Apple
Silicon it is simply broken. Until then `forktest` and `clonetid` make the smoke suite
intermittently red, and that is honest: `fork` really is broken about one time in
eight.

### 3.5.9 SMCCC swallows the trampoline's `hvc` — **fixed**

`apt` did not load. It failed at `libcrypto.so.3` with *"cannot change memory
protections"*, and underneath that the loader's `mprotect` was never reaching
NABI at all: the syscall produced no VM exit of any kind, and the guest carried
on with `0xffffffff` in x0. The same was true of the `munmap` before it.

The cause is the EL1 trampoline, and specifically the thing about it that is
otherwise a virtue. It clobbers no register — a real `svc` must preserve x0-x30
— so when its `hvc` executes, the guest's x0 is still whatever the syscall's
first argument was. x0 is also where SMCCC puts a function ID, and Apple's
hypervisor answers part of that space itself: an `hvc #0` whose x0 looks like a
call it owns is completed in firmware, returns `SMCCC_RET_NOT_SUPPORTED` (-1) in
x0, and never becomes a VM exit. The guest's syscall silently does not happen.

Measured, the swallowed range is every x0 in `[0xc1000000, 0xc2000000)` — fast
call, SMC64, owning entity 1, "CPU service calls". Neighbouring entities are
forwarded: `0xc0`, `0xc2`, `0xc3`, `0xc4` and the rest of the top byte all reach
the host, which is why this stayed hidden until a guest's mappings first grew
past `0xc1000000`. It is not a band that can be avoided by construction — the
first argument of *any* syscall is a guest address.

The fix is one instruction: the trampoline traps with `hvc #1`. A non-zero
immediate is not treated as a firmware call, so the exit is ours whatever the
guest left in x0. `test/arch/smoke/hvctest.c` sweeps the whole top byte through
x0 and checks every syscall still arrives.

Two things about the investigation are worth keeping, because both cost time.

**Any exception is affected, not just `svc`.** The trampoline is the single path
out of EL1, so a data abort, a `brk`, or a software-step exception taken while x0
holds a swallowed value is lost exactly the same way. That is what made the bug
look like several different bugs: register values appearing to corrupt
themselves, arithmetic appearing to produce impossible results. In every case
the guest had simply run on past an exception the host never saw, with x0
overwritten by the firmware's return value.

**Software single-step works, and is worth knowing about.** Set `MDSCR_EL1.SS`
and `SPSR_EL1.SS` (and clear `SPSR_EL1.D`) before entry; the step exception
arrives at the *same* `VBAR_EL1+0x400` slot the trampoline already handles, as
`ESR_EL1` EC `0x32`. Re-arm `SPSR_EL1.SS` on every entry, since taking the
exception clears it. It was the tool that eventually localised this — though
note that it is itself subject to the bug above, so a step whose x0 is in the
swallowed range is not reported and the guest advances anyway.

The Phase 0 spike in `spike/arm64-trap/` still uses `hvc #0` and would show the
same behaviour; it is kept as the record of that experiment rather than as
working code.

### 3.6 Segmentation, IDT, FPU, CPUID, TSC

- `init_segment` ([src/mm/mm.c:74](src/mm/mm.c#L74)) — **delete**. ARM has no
  segmentation. `struct segment_desc` and `struct gate_desc` in
  [include/x86/vm.h](include/x86/vm.h) go with it.
- `init_idt` ([src/main.c:437](src/main.c#L437)) — replaced by the `VBAR_EL1`
  vector page from §2.
- `init_fpu` ([src/main.c:484](src/main.c#L484)) — the `fxsave` struct and `mxcsr`
  become FPSIMD `V0`–`V31` + `FPCR`/`FPSR`, via `hv_vcpu_get_simd_fp_reg`.
- `CPUID` exit handling ([src/main.c:353](src/main.c#L353)) — gone. ARM ID
  registers are read with `mrs` and trap only if configured to.
- TSC / `MSR_KERNEL_GS_BASE` native-MSR passthrough
  ([src/main.c:477](src/main.c#L477)) — gone; `CNTVCT_EL0` is directly readable.
- AVX-on-demand `XCR0` handling ([src/main.c:259](src/main.c#L259)) — gone.

### 3.7 Rootfs

`noahstrap -p ubuntu` ([bin/noah.in:37](bin/noah.in#L37)) fetches an x86-64 Ubuntu
tree. Needs an arm64 tree. `noahstrap` lives outside this repo (Homebrew formula) —
either patch it for an `--arch` flag or point `bin/noah.in` at a
`debootstrap --arch=arm64` tarball.

In the meantime [util/mkrootfs-debian.sh](util/mkrootfs-debian.sh) builds one
from a Debian netinst ISO with nothing but the tools macOS ships — no
`debootstrap`, no network, no mounting (macOS cannot mount the hybrid ISO at
all). It unpacks the 427 `.deb`s in the ISO's `pool/` and synthesises
`/var/lib/dpkg/status` from their control stanzas, which is what makes `dpkg`
and `apt` see an installed system rather than an empty one. The maintainer
scripts cannot run — they are aarch64 shell scripts, and running them needs the
guest that is being built — so what they would have generated is missing:
`/etc/shadow`, the `ldconfig` cache, and `update-alternatives` symlinks.

`dpkg`, `dpkg-query`, `apt`, `bash`, `openssl`, `gpgv` and `wget` all run
against it — `apt list --installed` and `dpkg -l` enumerate the 427 packages,
and `apt update` completes its dependency resolution. Anything needing the
network is a separate matter: the tree is built offline and `sources.list` is
commented out by default.

Alongside `status`, the builder writes a `/var/lib/dpkg/info/<pkg>.list` per
package from the `data.tar` member names — keyed `<pkg>:<arch>` for `Multi-Arch:
same`, as dpkg names them. Without those, `dpkg -S` and `dpkg -L` answer nothing
and every query warns that the package has no files installed.

### 3.7.2 Talking to mSL/FHS

mSL/FHS gives the *host* a Linux-shaped namespace — `/home`, `/media`, `/mnt`,
`/run`, `/root`, `/srv`, `/boot` — out of symlinks maintained by `fhsxd`, and
declares `/proc` and `/sys` in `/etc/synthetic.conf` as mount points for its
sibling modules. NABI has its own notion of the namespace: a rootfs at `-m`,
plus a short list of prefixes that resolve on the host instead.

Those two overlap, and not everything FHS names should be passed through. The
line drawn here is **what a rootfs cannot hold**:

- **The pseudo-filesystems are passed through when mounted.** `/proc` and `/sys`
  are synthesised per-process by a real filesystem; a directory describing the
  machine's live state cannot be unpacked from a `.deb`. When mSL/ProcFS is
  mounted, the host's `/proc` is the only true answer. With it, Debian's own
  `ps`, `free` and `/proc/self/*` work.
- **`/boot` is, on the weaker test of merely existing.** It is a real directory
  FHS owns on the writable Data volume, holding the kernel, bootloader and
  kernel collections this machine actually boots — including a Linux `vmlinux`,
  which is the case FHS built it for. A rootfs cannot know any of that: what a
  netinst ISO leaves in `/boot` is a config file and a `System.map` for a kernel
  that is not running here. There is no filesystem to mount, so existing is the
  test, and where FHS is absent the guest keeps its own.
- **The rest of what FHS names is not.** `/home`, `/run`, `/root`, `/media`,
  `/mnt`, `/srv` name host directories that already have a macOS path, and a
  rootfs has a legitimate claim on those. `/home` in particular must stay the
  rootfs's own or the guest shell reads the host's dotfiles (§3.7.1).

None of this is required. Everything the sibling modules provide is optional by
construction: the probe simply finds nothing, the paths resolve in the rootfs as
they always did, and `/proc/self/{maps,cmdline,comm,exe}` still answer, because
NABI generates those from its own state and never needed a procfs to do it.
(ktemkin's x86 fork emulates `/proc/self/exe` the same way, with no procfs at
all.) What is lost without them is exactly what they were providing — a real
`/proc` for other processes, and `/boot`.

Two things make that testable rather than merely asserted:

- `NABI_IGNORE_HOST_FS` pretends they are not installed. On a machine that has
  them there is otherwise no way to run the other path, and the smoke tests use
  it to check both halves: the passthrough goes away, and the files NABI answers
  from its own state do not.
- `report_host_passthrough()` writes what the probe decided to the warning log
  (`-w`), so which modules a run picked up is a question the log answers:

      host filesystem: /proc passed through
      host filesystem: /sys not provided by the host
      host filesystem: /boot passed through

  Reporting is separate from probing because the probe must run before any path
  is resolved, which is before the debug sinks exist — anything it logged there
  would go nowhere.

*Mounted*, rather than merely existing, is the test for the first group: FHS
creates those as empty directories at boot whether or not the module that fills
them is installed, and an empty `/proc` passed through would mask the rootfs's
own — identical in effect today, but claiming to answer a question NABI cannot.
`statfs`'s `f_mntonname` naming the path itself is what distinguishes the two.

`/System/Volumes/Data` had to join the unconditional list for `/boot` to work at
all. NABI resolves symlink targets in the *guest's* namespace, and FHS's root
entries are all symlinks onto the Data volume — `/boot` is
`/System/Volumes/Data/boot`. Following one without its target prefix listed
lands inside the rootfs, where `/System` does not exist. `/tmp` was already this
shape, which is why `/private` was there before; the general limitation is that
a passed-through path whose host symlink points somewhere unlisted will not
resolve, and the fix each time is to list the target.

The probe runs at startup and, importantly, **on the resume path as well**.
arm64's fork is fork + `exec` (§3.5.8), so a child is a fresh `nabi` rebuilt
from a checkpoint that never runs `init_fileinfo`. Probing only on the first
path fails in a way that reads as nonsense rather than as an error: `bash -c
'cat /proc/version'` works, because bash execs a lone command without forking,
while adding a second command makes it fork first and the identical read fails.
`test/arch/smoke/procfstest.c` covers exactly that, and skips when the host has
nothing mounted.

### 3.7.3 Talking to mSL/ProcFS

Passing `/proc` through (§3.7.2) gets the guest a real procfs, and the identity
is right: a guest process *is* a host process and its pid is the host's, so
`/proc/self` resolves to the correct process and `ps` and `free` work. What XNU
cannot know is what that process is *running*. From the outside it is a `nabi`
executing a guest, so every per-process file describes the emulator.

`/proc/self/maps` is the sharp end. It came back as NABI's own host address
space — not a distorted view of the guest's, a different address space
entirely — so anything reading it to find where the guest's code or heap live
was comprehensively misled. NABI has that map in `proc.mm`, so `src/fs/procfs.c`
overlays the file: `user_openat` checks a small set of paths first and, for
those, serves generated content from an unlinked temp file. A temp file rather
than a pipe keeps the descriptor an ordinary one — seekable, `stat`-able,
readable more than once — and the snapshot-at-open behaviour is what procfs does
with these files anyway.

`cmdline`, `comm` and `exe` are overlaid the same way, and needed the guest's
argv and binary path to survive a fork that is fork + `exec` — so they are
recorded at exec and carried in the checkpoint, which went to version 2. They
are trailing blobs after the existing arrays, lengths in the header, following
the shape already there. Old checkpoints are not a compatibility concern: one is
written per handover and read once by the child it was written for, so none
outlives the pair of processes that share it.

Recording happens where the ELF is loaded rather than where `do_exec` returns,
because a `#!` script comes back through that function — `load_script` re-enters
`do_exec` with the interpreter, and the outer call would overwrite the
interpreter's identity with the script's. Linux reports the interpreter as `exe`
and its rewritten argv as `cmdline`, which is exactly what the inner call has.
`exe` is a symlink rather than a file, so it arrives through `readlink` and is
answered there instead.

One thing is still deliberately left out.

**Paths in `maps`.** `mm_region` records the guest fd a mapping was made from,
but the guest closes that descriptor as soon as `ld.so` has mapped a segment and
the number is promptly reused, so asking the host what it names answers for
whatever holds it *now* — which is how every library in a shell's map first came
out as `/dev/urandom`. A wrong path is worse than an absent one: a reader can
see that nothing is claimed, but not that something claimed is a lie. Naming
them means the region remembering its own file at mmap time, which is a new
field in `mm_region` and so a change to the checkpoint wire format.

Beyond that is the other half of the problem, which is not NABI's to solve
alone: **host** tools still see a `nabi`. Making `ps` on macOS show the guest
needs ProcFS itself to know about guests. Its control protocol
(`procfs_ctl.h` — a `PF_SYSTEM` kernel control with a `procfsd` daemon) is a
request/reply channel for the kext to *pull* host data it cannot reach; there is
no request type for a process to describe a guest it is running, and adding one
is a change to that module rather than this one.

### 3.7.1 An interactive shell

`util/nabi-shell.sh <rootfs>` drops into a login shell in the guest — `make
install` puts it on `PATH` as `msl`, and it names itself after however it was
invoked. The work is entirely environment, and all of it matters:

- **PATH.** The host's would be inherited, and nothing in it resolves `apt`.
- **HOME.** The account's real home is on the host, and `/Users` is a NABI
  passthrough prefix — so a guest `HOME` pointing there makes bash read the
  *host's* dotfiles, and the Debian shell arrives wearing the host's prompt and
  aliases. The rootfs gets its own `/home/<user>`, seeded from `/etc/skel` the
  way `adduser` would, and `passwd` names that. The host home stays reachable at
  its own path; it is just not `$HOME`.
- **The working directory.** NABI hands the guest the host's cwd, and there is
  no way to set the guest's initial directory, so the login shell `cd`s to
  `$HOME` before exec'ing the interactive one. That exec is also what gets the
  ordinary login sequence right: `/etc/profile` and `~/.profile` for exports,
  `~/.bashrc` for interactive settings.

`/etc/profile` is one more file base-files ships as a master for a postinst to
install, so the builder places it directly, like `passwd` and `group`.

Job control, pipelines, prompt rewriting on `cd`, and `apt`/`dpkg` queries all
work from that shell.

One trap when it is installed rather than run from the tree: `make install`
lays down *two* files. `bin/nabi` is a perl wrapper for a different workflow —
it provisions `~/.nabi/tree`, adopts a pre-rename one, and offers to make the
executable setuid root — and its options are `--root`/`--strace`/`--output`. The
executable that takes `-m` is `libexec/nabi`. Pointing a shell script at the
wrapper gets `Unknown option: m` from `Getopt::Long`, one layer down from where
it looks like it came. `nabi-shell.sh` searches both layouts and refuses a
wrapper by name rather than calling it.

`clock_nanosleep` had to be implemented to get there. Darwin has none, so it is
`clock_gettime` plus `nanosleep`, and the absolute form is the one that matters:
coreutils' `sleep` — and anything else on gnulib's `xnanosleep` — asks for
`CLOCK_REALTIME` with `TIMER_ABSTIME`. Unimplemented, it reported *"sleep:
cannot read realtime clock"*, which names the wrong syscall entirely: the clock
read was fine, it was the sleep that did not exist. Worth remembering when a
guest blames a syscall that demonstrably works.

### 3.5.10 `mprotect` must re-permission stage 2, not reflush it — **fixed**

`dpkg -i` hung. Not slowly — the guest spun at a full core on a store, forever,
and `wait4` in the parent never returned. The repeat-fault guard added to
`main_loop` for exactly this printed the state, and the state made no sense:
stage 1's level-3 descriptor was valid, `AP` said EL0 read/write, `XN` was clear,
and stage 2 had a block mapped over the IPA it named. Both of NABI's tables
called the page writable and the hardware kept reporting a translation fault.

The missing word is *permission*. Stage 2 has permission bits of its own, and
`hv_vm_map` takes them: a block mapped `HV_MEMORY_READ` alone will fault a store
no matter what stage 1 permits. The final address is the intersection of the two
walks, and stage 1 cannot grant what stage 2 withholds.

What made the region unwritable was how it was born. glibc's malloc reserves an
arena in one large `PROT_NONE` mapping and then `mprotect`s the piece it wants
to use — a reservation first, permissions later. `vmm_mmap` establishes stage 2
at reservation time with the region's permission, which is none. `pt_protect`
then rewrote stage 1 correctly and called `vmm_arm64_s2_reflush`, whose whole
job is to unmap and re-map a block to force HVF to drop a stale combined TLB
entry — re-mapping it with the permission it was *stored* with. Still zero. The
flush was faithful; it faithfully reinstated the wrong thing.

`vmm_arm64_s2_reprotect(ipa, prot)` re-maps with the new permission instead, and
`pt_protect` calls that. The reflush stays for its own callers, where the
permission genuinely has not changed.

Two things about this are worth carrying forward. The first is that it is
structural, not incidental: on x86 there is no second walk to keep in step, so
every `mprotect` in NABI's history has been a one-table operation, and arm64
quietly made it a two-table one. Anything else that changes protection has to be
audited the same way. The second is that nothing smaller than an arena ever
tripped it, because a mapping created writable is mapped writable at stage 2 and
never needs correcting — which is why the whole suite passed while dpkg hung.
`growtest` now builds the reservation-then-`mprotect` shape deliberately, and
fails without the fix.

### 3.5.11 A pty, spelled two ways — **fixed, but see 3.5.16**

`apt install` stopped with *"Unlocking the slave of master fd 27 failed —
unlockpt (1: Operation not permitted)"*. apt runs dpkg under a pty so it can
watch the progress output, and Linux and Darwin agree on `/dev/ptmx` and on
nothing after it:

| what glibc calls | Linux                    | Darwin                       |
|------------------|--------------------------|------------------------------|
| `posix_openpt`   | `open("/dev/ptmx")`      | same — passthrough handles it |
| `grantpt`        | nothing (devpts already has the node) | `ioctl(TIOCPTYGRANT)` |
| `unlockpt`       | `ioctl(TIOCSPTLCK, &0)`  | `ioctl(TIOCPTYUNLK)`         |
| `ptsname`        | `ioctl(TIOCGPTN, &n)` → `/dev/pts/n` | `ioctl(TIOCPTYGNAME, buf)` → `/dev/ttysNNN` |

`TIOCSPTLCK` was unhandled, so it fell through to the default arm of
`darwinfs_ioctl`, which returns `EPERM` — hence "Operation not permitted" for
something no permission would have granted.

Three things had to be added, and the third is the one that is not an ioctl.
`TIOCSPTLCK` does the grant as well as the unlock, because Linux's `grantpt` is
a no-op that NABI never sees and Darwin's slave is unusable without it. `TIOCGPTN`
parses the number out of the host's name, since Darwin has no number to ask for.
And `/dev/pts/<n>` has to reach `/dev/ttys<nnn>`: `/dev` is a passthrough, so
the path the guest builds from that number would otherwise land on a host
`/dev/pts` that does not exist. That translation lives in `resolve_path` rather
than in `openat`, because `ptsname_r` stats the path before returning it and
reports the failure as though `TIOCGPTN` had failed.

`TIOCSCTTY` and `TIOCNOTTY` went in alongside; apt's child calls the first after
`setsid`.

### 3.5.12 The host filesystem is case-insensitive — **not fixable here**

With the pty working, `apt install gcc` got as far as unpacking and then failed
on four packages out of thirty-three:

```
unable to open '/usr/share/man/man2/_exit.2.gz.dpkg-new': No such file or directory
```

The four have one thing in common: each ships two files whose names differ only
in case. `manpages-dev` has `_exit.2.gz` and `_Exit.2.gz`; `linux-libc-dev` has
the netfilter headers, `xt_connmark.h` and `xt_CONNMARK.h`. macOS formats the
boot volume case-insensitively, and it cannot hold both.

The failure does not resemble its cause, which is worth walking through once.
dpkg unpacks to `<name>.dpkg-new` and renames everything at the end, and before
each unpack it clears any `.dpkg-new` left by an interrupted install. So:

1. `_exit.2.gz.dpkg-new` is created and written — fine.
2. dpkg clears the stale `_Exit.2.gz.dpkg-new`, and on this filesystem that
   `unlink` deletes the file from step 1.
3. `_Exit.2.gz` is a *symlink* to `_exit.2.gz`, so dpkg creates it — succeeding
   now, because step 2 made room — pointing at a name that does not exist yet.
4. dpkg's deferred fsync pass reopens each unpacked file and gets `ENOENT` from
   the dangling symlink, and reports it against `_exit.2.gz`, which was never
   the problem.

Nothing in that chain mentions case, and the file named in the error is the one
that unpacked correctly.

There is no fix inside NABI. Holding both names would mean mangling them in the
VFS, and the mangling would have to be undone in `readdir`, in `readlink`, in
every path returned to the guest — and any host tool looking at the rootfs would
see the mangled form. A Linux rootfs has to live on a case-sensitive filesystem.

So NABI detects it instead: `fpathconf(_PC_CASE_SENSITIVE)` on the root fd,
reported once at startup with the remedy, and only for a rootfs that holds a
distribution — `/etc/os-release` or `/var/lib/dpkg` — since a scratch directory
of test binaries has nothing to collide and a warning that cries wolf gets
ignored where it counts. `mkrootfs-debian.sh` refuses outright rather than
warning, because there the damage is silent: the tree comes out looking
complete.

`util/msl-mkvolume.sh` makes the volume. A sparse disk image rather than an APFS
volume in the boot container, because adding a volume needs an administrator and
this does not; the size is a ceiling, not an allocation.

With the rootfs on one of those, `apt install gcc make` completes, and the
installed gcc compiles and links a program that then runs under NABI.

### 3.5.13 arm64 permutes four `O_*` flags — **fixed**

`mv a b` failed for every `b` that already existed:

```
mv: cannot stat 'f2/f1': Not a directory
```

`f2` is a regular file, and `mv` had appended the source's name to it as though
it were a directory. `stat` in the guest reported `f2` correctly, which made no
sense until the reason coreutils disagreed turned up: it does not ask `stat`. It
asks `open(dest, O_DIRECTORY)`, and takes success as the answer.

Four of the `O_*` flags are not common between architectures.
`asm-generic/fcntl.h` defines them and x86 takes the defaults, but
`arch/arm64/include/uapi/asm/fcntl.h` overrides all four — and not by shifting
them, by permuting them:

|             | x86-64     | arm64     |
|-------------|------------|-----------|
| `O_DIRECT`  | `00040000` | `0200000` |
| `O_LARGEFILE`| `00100000`| `0400000` |
| `O_DIRECTORY`| `00200000`| `040000`  |
| `O_NOFOLLOW`| `00400000` | `0100000` |

NABI carried the x86 numbers unconditionally. So an arm64 guest's `O_DIRECTORY`
arrived looking like `O_DIRECT`, and its `O_NOFOLLOW` like `O_LARGEFILE` — both
hints NABI drops. The requests were not mistranslated, they were *silently
granted*, which for a flag whose entire job is to make an open fail is the worst
available outcome: `open(O_DIRECTORY)` succeeded on regular files, and
`open(O_NOFOLLOW)` followed the symlink it was told to refuse.

Nothing noticed for a long time because a wrongly-granted open still returns a
working fd. Everything that overwrites a file noticed at once, which is most of
what installing a package does.

`oflagtest` checks the two that must *refuse*, since a flag being ignored passes
any test that only asks for success.

### 3.5.14 Open file description locks, and `/proc/self/fd` — **fixed**

With those out of the way, `dpkg --configure -a` got as far as systemd and
stopped: *"Failed to take /etc/passwd lock: Invalid argument"*, taking udev and
cron down with it. A trace named it exactly — `fcntl(fd, 0x26, ...)`, and 0x26
is 38, `F_OFD_SETLKW`.

Open file description locks belong to the open file description rather than to
the process, so an unrelated `close` does not drop them and two descriptions in
one process contend. Darwin has no `F_OFD_*` — but that description is precisely
BSD `flock()`, so whole-file OFD locks map onto it exactly. Byte ranges do not,
and are refused rather than widened: a lock quietly covering more of a file than
was asked for is a deadlock that gets blamed on something else. Nothing seen so
far asks for one.

The warning that would have named this was invisible for a familiar reason —
`systemd-sysusers` runs as a forked child, and on arm64 a fork is a fork plus an
exec, so the child is a fresh `nabi` with no `-w` sink. Running the binary as the
top-level process is the way to see anything a forked guest does.

That got systemd past the lock and into *"Failed to flush /etc/.#group…: Invalid
argument"*, from `fsync_directory_of_file`, which finds a file's directory by
reading `/proc/self/fd/<n>`. The host's procfs cannot answer that even when it is
mounted: the descriptors it describes are `nabi`'s, and a guest fd number means
nothing there. What it does serve are directories rather than symlinks, so
`readlink` on one returns `EINVAL`.

So NABI serves `/proc/self/fd/<n>` itself, from its own fd table:

- **readlink** answers with the path from `F_GETPATH`, translated out of host
  terms. That translation is the part that matters — the guest opens what it
  reads here, and a rootfs path handed back whole sends it to `/Volumes/…`, a
  name that only means something on the other side of the boundary. Passthrough
  prefixes need no translation and get none; none of them is under the root.
- **open** reaches the file rather than the name, which is the point of it.
  Darwin cannot reopen an unlinked file, so a regular one is copied into a fresh
  unlinked temp file — an independent description starting at offset zero, which
  is what a real open gives and what `dup()` would not. `pread` leaves the
  guest's own offset alone. A pipe or socket has no contents to copy and no
  offset to get wrong, so those are duplicated.

Guest fds only, in both. NABI keeps its own descriptors at the top of the table,
and without that bound a guest could read the path of the arena, the checkpoint,
or the debug sinks.

With all of it in place, `dpkg --configure -a` finishes a 149-package Debian
trixie with nothing left unconfigured, systemd and udev and cron included, and
`dpkg --audit` is clean.

### 3.5.15 `AT_EMPTY_PATH`, and why apt thought Debian was unsigned — **fixed**

`apt-get update` reported every repository as unsigned:

```
Sub-process /usr/bin/sqv returned an error code (1), error message is:
  Error: Reading "/tmp/apt.sig.13eCj4": No such file or directory (os error 2)
```

The file was there. A host-side watcher caught it existing at
`/private/tmp/apt.sig.*` while apt ran, and the guest could `cat` it by that
exact path from a forked child. The trace settled it:

```
openat(-100, "/tmp/p.sig", O_RDONLY|O_CLOEXEC): ret = 0x5     <- opened fine
statx(dirfd: 5, path: "", flags: 4096, ...): ret = ENOENT     <- 4096 = AT_EMPTY_PATH
```

An empty pathname with `AT_EMPTY_PATH` names the *descriptor*, which may be any
kind of file rather than a directory — so it cannot go through `vfs_grab_dir`,
which rejects an empty name with `ENOENT`. Both `statx` and `newfstatat` did,
and `newfstatat` additionally refused the flag outright with `EINVAL`.

This is not a corner. Rust's standard library stats every file it opens as
`statx(fd, "", AT_EMPTY_PATH)`, so it sits on the path of any Rust program that
reads a file — and `sqv`, the OpenPGP verifier apt shells out to, is Rust. It
opened the signature, got `ENOENT` from the stat that followed, and reported it
against the path it had been reading. apt read that as a missing signature.

The error named the right file and the wrong reason, which is why it survived
several attempts: everything about "the temp file is missing" was false, so
chasing where the file went never converged. What broke it open was running
`sqv` as the top-level guest process rather than as a forked child — a forked
child on arm64 is a fresh `nabi` with no `-s` sink, so its syscalls are
invisible. That trick is worth reaching for early.

With it fixed, `apt-get update` verifies signatures and `apt-get install gcc`
works against the real signed archive.

### 3.5.16 Two ioctl numbers that were never encoded — **fixed**

`script` and apt both failed to allocate a pty:

```
script: failed to create pseudo-terminal: Operation not permitted
E: Unlocking the slave of master fd 25 failed! - unlockpt (1: Operation not permitted)
```

`asm-generic/ioctls.h` hands out bare numbers up to `TIOCSWINSZ` for historical
reasons and switches to `_IOC` encoding from `0x30` on:

```c
#define TIOCGPTN    _IOR('T', 0x30, unsigned int)   /* 0x80045430 */
#define TIOCSPTLCK  _IOW('T', 0x31, int)            /* 0x40045431 */
```

NABI had them as `0x5430` and `0x5431` — continuing the pattern of the lines
above, which is wrong. No guest ever matched, and the fall-through returns
`EPERM` for a request that needed no permission.

Worth recording plainly: §3.5.11 called this fixed, and it was not. The shape of
that work was right — the grant, the unlock, the `/dev/pts` translation — but it
hung on constants no guest sends. `ptytest` passed because it was written with
the same wrong numbers, so all it verified was that NABI agreed with itself. A
test that shares a constant with the code under test cannot catch that constant
being wrong; it now spells the encoded values out, with a note saying why.

### 3.5.17 A shared mapping only has to be real if it can be written — **fixed**

Every `dpkg --configure` run printed a wall of:

```
ldconfig: Cannot mmap file /lib/aarch64-linux-gnu/libnettle.so.8.10.
```

so no `ld.so` cache was ever built. `ldconfig` opens each library `O_RDONLY` and
maps it `PROT_READ|MAP_SHARED` to read its `SONAME`. NABI maps a shared file
mapping for real — the point of `MAP_SHARED` is that the guest's writes reach
the file, which a copy can never provide — and it asked the host for
`PROT_READ|PROT_WRITE` so a later `mprotect` could grant write without
re-establishing the mapping. `MAP_SHARED` with `PROT_WRITE` on a read-only
descriptor is `EACCES`.

Asking for `PROT_READ` instead only moves the failure: `hv_vm_map` will not take
a read-only host region, and the guest panics rather than getting an errno. The
right answer is that the mapping never needed to be real. A shared mapping of an
`O_RDONLY` descriptor cannot propagate anything to the file, now or later —
Linux clears `VM_MAYWRITE` for that case, so even a later `mprotect` to
`PROT_WRITE` is refused — which makes the private copy NABI already builds for
every other file mapping indistinguishable from the real thing. `shared_file`
now also requires the descriptor to be writable.

### 3.5.18 Four futex bugs, one hang — **fixed**

`apt-get install gcc` hung part-way through, on a freshly built tree, and not
every time. `sample` on the stuck process showed the shape of it:

```
main-thread   ... vmm_run -> vmm_enter -> Hv::Vcpu::run   (guest spinning)
Thread_324784 ... main_loop -> sys_futex -> do_private_wait -> __psynch_cvwait
```

One guest thread burning a core, another asleep. That pairing is the signature
of a futex problem, and `src/ipc/futex.c` had four, none of which announces
itself:

1. **`FUTEX_WAIT`'s timeout is relative.** It was read out of the guest's
   `struct timespec` and then overwritten with the current time, so the deadline
   handed to `pthread_cond_timedwait` was always "now". Every timed wait
   returned `ETIMEDOUT` immediately and the caller's retry loop became a spin at
   a full core. That is the burning thread.

2. **`FUTEX_WAIT_BITSET` never compared the word.** The compare-and-block is the
   whole point of a futex: the guest reads the value, decides to sleep, and
   passes the value it saw so the kernel can refuse to sleep if a wake has
   already landed. `FUTEX_WAIT` did this; `FUTEX_WAIT_BITSET` did not — and it
   is the one glibc actually uses, for `pthread_cond_wait` and `sem_wait`. A
   wake arriving in that window was lost and the thread slept forever. That is
   the sleeping thread.

3. **A timed-out waiter was freed while still on the wait list.** The wake path
   unlinks the entry before signalling it, so it was correct; the timeout path
   was not, and left the list pointing into freed memory for the next wake to
   walk. With (1) making every timed wait time out instantly, this fired
   constantly.

4. **`FUTEX_WAKE_OP` computed two of its five operations wrong** — `XOR` was
   written as `*` and `ANDN` as `&` without the complement.

Also `FUTEX_WAIT` returned Darwin's `EWOULDBLOCK` (35) where the guest expects
Linux's `EAGAIN` (11). On Linux 35 is `EDEADLK`, which no caller handles.

The absolute-versus-relative distinction is the one to remember: `FUTEX_WAIT`
takes a relative timeout, while `FUTEX_WAIT_BITSET` and the PI operations take
an absolute one — against `CLOCK_MONOTONIC` unless the guest set
`FUTEX_CLOCK_REALTIME`, so it has to be rebased onto the real-time clock that
`pthread_cond_timedwait` measures against.

`futextest` checks the timing rather than only the return value, because a wait
that did not sleep at all also returns 0, and that is the bug.

This is worth weighing against the fork flakiness recorded elsewhere as an HVF
limitation. Some of what was attributed there may have been this: a guest that
spins or sleeps forever after a fork looks very much like a fork that did not
take. Three purge/install/compile cycles now run clean where one in a few used
to hang.

### 3.5.19 `msl`, and where a rootfs can actually live

The pieces built above — a downloader, a volume maker, a shell launcher — are
now behind one command:

```
msl                     what is installed, and what to type next
msl install debian      download and build a rootfs
msl login debian        a shell inside it
msl run debian <cmd>    one command inside it
msl list / del / help
```

`msl <path>` still works, so the older spelling that took a rootfs directory is
unchanged.

The awkward part is where the trees go. `~/.msl/rootfs-debian` is the obvious
answer and it cannot work: `~` is on the boot volume, macOS formats that
case-insensitively, and §3.5.12 covers what that does to a Debian tree. So the
trees live on a case-sensitive sparse image that `msl` creates on first use and
attaches at `/Volumes/msl` — no administrator needed, and sparse, so the size is
a ceiling rather than an allocation. A symlink at `~/.msl/<name>` points at each
tree, because that is the path people expect to type; it dangles while the image
is detached, which is why every command attaches before it looks at anything
rather than trusting the link.

Debian and Ubuntu are both apt archives with the same layout, so one resolver
and one unpacker serve both — only the mirror, the suite and the keyring package
differ, and those are a four-line table. Ubuntu's arm64 packages are on
`ports.ubuntu.com` rather than `archive.ubuntu.com`, which carries amd64 only.
Both are reachable over https, so the integrity chain in §3.5.12 holds for
either. Fedora and Arch are not apt archives and would need a different second
stage; `msl install fedora` says so rather than pretending.

Verified end to end: `msl install debian` and `msl install ubuntu` each produce a
tree with nothing unconfigured — Debian 13 trixie and Ubuntu 24.04 LTS — and
`msl run` works against both from the source tree and from an install layout.

### 3.5.20 An account of your own, and five things in the way — **fixed**

`msl install` now creates an account in the guest named after whoever ran it,
with a home directory, a locked password and passwordless `sudo`; `msl login`
lands in it. Getting there turned up five separate bugs, none of which had
anything to do with user accounts.

**`RLIMIT_NOFILE` had no inverse.** NABI keeps its own descriptors in the top 64
slots of the host's table and tells the guest a limit that excludes them — but
applied the guest's number back to the host verbatim. `su`, `login` and PAM all
read their limits and write them back, which quietly lowered the host's limit
onto the reserved range. Every `dup2` into the vkern table then failed with
`EBADF`.

**`vkern_dup_fd` did not check `dup2`,** so it returned a slot with nothing
behind it. **And `do_exec` did not check `fstat`,** so `st` was stack garbage,
`S_ISREG` was false, and execve returned `EACCES`. That is the chain that
produced *"su: failed to execute /bin/bash: Permission denied"* about a file
that is plainly executable — three unchecked returns deep, and nothing in the
message pointing at any of them.

**`nabi_host_uid` was set in `main` and never in `resume_main`.** It is not in
the checkpoint, so every forked child left it zero and every host-to-guest id
mapping became the identity: files owned by the account NABI runs as stopped
reading back as root. Since a fork here is a fork plus an exec, that was every
process except the first, and `sudo` said so — *"/etc/sudo.conf is owned by uid
501, should be 0"* — about a file the first process had been reading as root's
all along.

**`elevate_privilege` called `seteuid(0)` and panicked when it failed.** That
only ever worked for a setuid-root install, and it is backwards twice over:
the host account is already the guest's root, so there is nothing to raise, and
a guest exec must never be able to move the host process. It now moves
`struct cred` and takes the ids from the file's owner rather than assuming zero.

**The checkpoint carried the uids but not the gids.** Added in version 3, along
with the supplementary group list as a trailing blob. Before it, `id` in any
forked process reported a real user in group 0 with no groups — the uids
survived and the gids did not, which is a confusing thing to look at.

Two smaller things: `LINUX_RLIM_NLIMITS` was 10 where Linux has 16, so
`pam_limits` got `EINVAL` from the middle of its walk over every resource; the
six Darwin lacks are now emulated with Linux's defaults. And the rootfs builder
restores the set-user-ID bits that tar drops for a non-root extractor, without
which sudo will not run at all.

What is *not* solved: `pam_limits` still fails under NABI, returning
`PAM_PERM_DENIED` from `pam_open_session`, and marking it `optional` makes the
call hang rather than fail — so it is the module running at all that is the
problem, not its return code. Every `getrlimit` and `setrlimit` it makes
succeeds, so the refusal is internal to it and is not yet understood. The
builder comments the line out of sudo's stack and says why in the file. Nothing
is lost by that here: there is no kernel to enforce a resource limit, and both
Debian and Ubuntu ship `limits.conf` entirely commented out.

The account uses uid 1000 rather than the host's uid on purpose. The host
account is already what the guest sees as root, so giving this user the same
number would make its files read back as root's and defeat the exercise.
`MSL_ROOT=1` still gives a root shell.

### 3.5.21 A tree you can actually install into — **fixed, with one open bug**

Two things were wrong with a freshly installed tree, and both were mine.

`sudo: command not found`. The account created in §3.5.20 is put in the `sudo`
group and given a `sudoers.d` entry, but `sudo` itself is `Priority: optional`
in both archives, so neither the required floor nor "important" brings it in. A
sudoers entry without the binary to read it is not a privilege. It is seeded
explicitly now.

`apt install gcc` answering *"Unable to locate package gcc"*. The builder never
ran `apt-get update`, so the tree had a working apt and nothing for it to work
on — and the message reads like a missing package rather than an empty index.
The lists are fetched as the last install step, best-effort, so a machine that
is offline still gets a rootfs.

That second one only became fixable after finding why `apt-get update` hung.

**apt's download sandbox deadlocks under NABI.** apt runs its fetch methods as
the unprivileged `_apt` user. With that drop in place, `apt-get update` prints
nothing at all and never returns; `sample` shows apt blocked in `pselect6` and
the method it forked blocked in `pselect6` too — each waiting for the other.
`APT::Sandbox::User=root` avoids the drop and the same fetch completes in two
seconds. It reproduces on a fresh tree, with the parent commit's `nabi` as well
as the current one, so it is not a regression from the credential work; and it
is not the restored set-user-ID bits, not DNS, and not IPv6, all of which were
ruled out separately. What it is, exactly, is not yet known — the method is a
forked child, so its syscalls are invisible, and the two-sided `pselect6` points
at the descriptor handover across NABI's fork-plus-exec rather than at anything
apt does.

The builder writes `APT::Sandbox::User "root"` into the tree with a note saying
why. Nothing is given up by that here: the sandbox exists to stop a compromised
download method acting with root's authority, but the guest's root is emulated
and the host process stays the ordinary account that started `nabi` whichever
uid the guest believes it has. Dropping to `_apt` inside the guest moves nothing
real. The boundary that matters is the host account, and it is untouched either
way.

Verified end to end afterwards: `apt-cache policy gcc` finds a candidate,
`sudo apt-get install gcc` completes, an unprivileged `apt-get install` fails
cleanly with *"requested operation requires superuser privilege"* rather than
claiming the package does not exist, and the installed gcc compiles and runs a
program.

### 3.5.22 The apt method deadlock — **fixed**

`apt-get update` hung with the `_apt` sandbox enabled: no output at all, no
return. `sample` showed apt blocked in `pselect6` and the method it forked
blocked in `pselect6` too, each waiting for the other.

The first thing to fix was not the bug, it was the blindness. A fork on arm64 is
a fork plus an exec of a fresh `nabi`, and that child parsed no `-s`/`-w`, so
**every forked guest ran with no trace and no warnings**. A shell forks for each
command, so that was nearly everything — and it had already sent two
investigations this session down the wrong road, because the only visible
evidence came from whichever process happened to be started directly. The sink
paths now travel in the environment and a resumed child reopens them, after the
checkpoint restore rather than before, since the restore rebuilds the descriptor
table wholesale. Each process writes its own file, named for its pid: sharing
one file spliced several guests' output together, and a spliced trace is worse
than none because it reads as though one process did both halves.

With that, the method was visible immediately:

```
writev(fd: 2, iovcnt: 2) = 0x18
gettid(); getpid()
tgkill(tgid, tid, sig: 6)          <- SIGABRT
```

**`tgkill` was a stub returning `ENOSYS`**, and that is how glibc's `abort()`
delivers `SIGABRT` to itself. A process that decides to die and cannot then does
not die: it carries on with the signal never raised, holding whatever its parent
is waiting on. apt's method aborted, could not, and never closed its end of the
pipe; apt waited for a greeting or an EOF that were both never coming. A syscall
that cannot fail visibly is a syscall whose absence turns an error into a hang.

`tgkill` and `tkill` now deliver per-process. NABI runs a guest's threads as
pthreads inside one host process and keeps no `pthread_t` to aim at, so a signal
addressed to a thread goes to the process — exact for the single-threaded case,
which is every caller that was hanging, and an approximation for a guest aiming
at a specific sibling.

Two genuinely missing syscalls turned up on the way. **`getrandom` rejected
`GRND_INSECURE`** (0x4, Linux 5.6) with `EINVAL` — and Rust's standard library
asks for it first, so that was every Rust program wanting a random number.
**`faccessat2` was unimplemented**, and glibc's fallback for it is not a syscall:
it works the answer out in userspace from the file's mode and owner against the
ids it *believes* it has, which under NABI are the guest's. A process that had
dropped to an unprivileged account therefore decided it could not write
directories it could in fact write.

`apt-get update` now returns in under a second where it used to hang forever.

**What is still wrong, and it is not the deadlock.** Verification still fails
under the sandbox, because `sqv` — Rust, via Sequoia — aborts with
*"free(): invalid pointer"*. That is heap corruption, and the reproducer is
sharp: run the same `sqv` on the same inputs as different users and it depends
on the **length of the user's name**. Two, three, four and seven characters
abort; five and six succeed. `su` to root works, `su` to `nobody` works, `su` to
`_apt` does not, and a hand-made account with `_apt`'s exact uid, gid, home,
shell and empty GECOS works fine. The two traces are byte-identical for 174
syscalls and then one of them aborts.

So it is nothing to do with privileges, with apt, or with `_apt`: the username
reaches the guest through the environment, the environment sets where the stack
and heap land, and a NABI memory bug was sensitive to that. It turned out to be
the initial stack's alignment — see §3.5.23, which fixes it and removes the
`APT::Sandbox::User "root"` workaround this section introduced.

### 3.5.23 The initial stack was 8-byte aligned — **fixed**

The heap corruption left over from §3.5.22 was an alignment bug, and the
reproducer said so before the code did. Running the same `sqv` on the same
inputs, only the *length* of the environment mattered: seven bytes of padding
aborted, eight worked, and the flip was clean.

`init_userstack` builds the process-entry block by pushing downwards, and
`push()` rounds every item to 8. Everything it pushes is a multiple of 8 except
one: the block of argv and envp strings, whose length is whatever the caller
happened to pass. Both ABIs require SP to be 16-byte aligned when the process
starts. So the alignment of the finished stack was decided by
`roundup(argv+envp bytes, 8)` — right about half the time, and never recovered,
because every push after it is a multiple of 8.

Nothing faults. AArch64 will fault on an SP-relative access with SP misaligned,
but the guest never gets that far in a way that shows: glibc's startup and the
dynamic loader run, thousands of syscalls go by, and then `free()` reports an
invalid pointer from somewhere with no visible connection to the stack. An
allocator that assumes 16-byte alignment and is handed 8 produces a heap that is
subtly wrong rather than obviously broken.

That is why it looked like a privilege bug for so long. The username reaches the
guest through the environment; the environment sets the length of the string
block; the length set the alignment. `_apt` failed and `nobody` did not, and
neither fact had anything to do with either account.

The fix pads by one slot before the pointer block when needed. Everything from
that point down is 8-byte slots and one auxv array, so the distance to the final
SP is known exactly and the correction is at most eight bytes.

`aligntest` re-execs itself sixteen times with a growing environment, because
checking one environment would only catch the bug half the time — which is
precisely how it survived every test written before it.

With this, `apt-get update` fetches **and verifies signatures** with apt's `_apt`
sandbox left switched on, so the `APT::Sandbox::User "root"` workaround the
rootfs builder was writing is gone. A fresh `msl install debian` now gives a tree
where `sudo apt-get update` reports no warnings at all, `sudo apt-get install
gcc` completes, and the compiler works.

### 3.5.24 A pty master is not a terminal until the slave has been opened — **fixed**

Installing a package with a terminal attached printed three errors and carried
on:

```
Error: Setting TIOCSWINSZ for master fd 76 failed! - ioctl (25: Inappropriate ioctl for device)
Error: Setting in Start via TCSANOW for master fd 76 failed! - tcsetattr (25: Inappropriate ioctl for device)
Error: Setting in Start via TCSAFLUSH for stdin failed! - tcsetattr (1: Operation not permitted)
```

Two separate bugs, and the errnos say which is which: `ENOTTY` twice on a
descriptor that really was a pty master, and `EPERM` once on a descriptor that
really was the terminal.

**The master.** On Linux a pty is a pair from the moment the master exists, and
the termios and window size belong to the pair — so a program may set them on
the master before anything has opened the slave, and that is exactly when
programs do it. apt sizes the terminal it is about to run `dpkg` under, then
forks.

Darwin attaches no line discipline until the slave has been opened at least
once. Until then `TCGETS`, `TCSETS` and `TIOCSWINSZ` on the master all return
`ENOTTY`. Measured directly, and the useful half of the measurement is that the
state **persists once the slave has been opened and closed again**:

```
BEFORE opening the slave:  TIOCSWINSZ: ENOTTY   tcgetattr: ENOTTY
AFTER  opening the slave:  TIOCSWINSZ: ok       tcgetattr: ok
AFTER  closing it again:   tcgetattr: ok
```

So `TIOCSPTLCK` — the unlock, which is the point Linux considers the pair usable
— now opens the slave once and immediately closes it. Holding it open instead
would be wrong in a way that would not show up for a while: the master's read
returns EOF when the last slave closes, and a slave NABI never released would
mean that EOF never arrives and whoever is waiting for the child waits forever.
A transient open was checked for that too — the master still sees EOF when the
guest's own slave closes.

**stdin.** `tcsetattr(TCSAFLUSH)` is `TCSETSF`, and the ioctl switch handled
`TCGETS`, `TCSETS` and `TCSETSW` but not it. Unhandled ioctls fall through to a
default arm that returns `EPERM`, so a missing case reads as a permissions
problem rather than as a gap — which is the second time that default has sent an
investigation the wrong way (see §3.5.11).

`ptytest` now sets and reads the window size and does all three termios set
forms **on a fresh master, before the slave is opened**, which is the order that
was broken. It fails with `ENOTTY` without the fix.

A note on something that is *not* a bug, from the same session: `apt install`
without `sudo` downloaded everything before failing at `dpkg` with "requested
operation requires superuser privilege", where a real Linux refuses at once on
the lock file. NABI does not enforce the guest's own permission bits — the host
performs every access with the host account, which owns the whole tree — so the
guest's unprivileged user could open apt's lock. The refusal still happens, from
`dpkg`, just later. That is the same fiction §3.5.20 describes from the other
side, and the README says so plainly.

### 3.5.25 Guest ownership, and enforcing it — **implemented**

Until now the guest's credentials decided nothing about files. Every access was
performed by the host account, which owns the whole tree, so an unprivileged
guest could open anything: `apt install` without `sudo` downloaded 25 MB and got
as far as `dpkg` before anything objected, where a real Linux refuses at the
lock file in the first second.

**Enforcement could not be switched on as it stood, and the evidence was one
command:**

```
$ id -u
1000
$ touch ~/mine && ls -ln ~/mine
-rw-rw-r-- 1 0 0 ... /home/sunneva/mine
$ ls -lnd ~
drwx------ 10 0 0 ... /home/sunneva
```

A file the user creates comes back owned by root, and the user's own home is
`drwx------ root root`. Checking permissions against that would have locked
every account out of its own home on the first check.

The reason is structural. There is one host account; `chown` to anybody else
needs privileges NABI has not got, which is why `chown` was a documented no-op;
and `host_uid_to_guest` maps that single account onto guest root. So the host
cannot represent guest ownership at all, and until it can, nothing can be
enforced.

**Ownership is now recorded beside the file, in an extended attribute.** It
travels with the file, survives a copy within the volume, can be read from the
host with `xattr -p`, and — unlike anything held in NABI's memory — is shared by
every process, which matters here because a fork is a fork plus an exec and
sibling guests are separate host processes. Absent, the owner is the host
account, which the guest already reads as root: that is both the sensible
default and the common case, so everything a distribution unpacks carries no
attribute and costs one failed lookup.

`chown` records; `stat` overlays; and anything created by a guest that is *not*
root is stamped with the creator's ids. A root guest stamps nothing, because an
absent attribute already means exactly that.

**On top of that, Linux's discretionary rules.** The checks cover `open` (by
access mode, plus `O_TRUNC`), `access`/`faccessat` — which previously answered
for the host account and so said yes to everything — creating, removing and
renaming (write and search on the containing directory, with the sticky-bit
rule for `/tmp`), `chmod` and `chown`'s own ownership rules, and **search
permission on every directory along the path**. That last one is not optional:
a file may be readable by everybody inside a directory that is not, and on Linux
the directory decides. Without it the rest is a formality.

Root costs nothing. A guest running as root — the default, and most of what
happens — short-circuits before any `stat`, so the common path is unchanged: a
full `msl install debian` still takes about 68 seconds and still finishes with
nothing unconfigured. The one rule root does not bypass is that an executable
needs an execute bit somewhere, which is checked from a `stat` the caller
already had.

Two mistakes worth recording, because both were silent. Deriving the containing
directory as `"."` rather than from the entry meant every create was ruled on
against the rootfs root, which denied a user the right to write in their own
home. And the search check fired on the empty first component of an absolute
passthrough path — the leading `/` — which stats `""` and returns `ENOENT`, so
`/dev/null` briefly stopped existing.

What this is not: there are no ACLs, no capabilities, and no `CAP_DAC_OVERRIDE`
distinct from being root. The host account remains the real boundary, exactly as
the README says — this makes the guest's *own* model honest, it does not make
the guest a sandbox.

```
$ apt-get install hello            # as the user
E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)
E: Unable to acquire the dpkg frontend lock, are you root?
$ sudo apt-get install -y hello && hello
Hello, world!
```

### 3.5.26 Fedora and Arch — **rootfs working, package managers not**

Neither is an apt archive, so the resolver-and-configure machinery does not
apply. Both publish a complete rootfs instead, which is much less work precisely
because somebody else did the resolving — what it costs is a trust root, since
the content is whatever the project published. The builder now has three shapes:

| | Source | Verified by |
|---|---|---|
| `apt` | archive of packages, resolved and configured here | `Release` → `Packages` SHA256 → per-`.deb` SHA256, over https |
| `oci` | Fedora's published container image | SHA256 from the `CHECKSUM` beside it, over https |
| `tar` | Arch Linux ARM's rootfs tarball | md5 beside it, over https |

An OCI archive needs no container runtime to unpack: `index.json` names a
manifest, the manifest lists layers, and the layers are ordinary tarballs
applied in order. Arch's own host has no certificate for its name, so the
default is a mirror that does — the download *is* the trust root here, and its
md5 catches a corrupt transfer and nothing else.

**Both produce a rootfs you can log into**, with your account, its home, and the
right groups. What neither can do yet is install a package, and the reasons are
worth recording separately from the distro work.

`pacman -Sy` walked into four NABI limits in a row, three of them fixed here:

- **`brk` had no limit.** Linux stops the break at the first mapping in its way
  and returns the *old* break — which is the signal malloc uses to fall back to
  mmap. NABI grew regardless, so pacman took the heap from `0x488000` to
  `0xc0000000` in 2MiB steps and then recorded a region on top of a loaded
  image. That is a panic rather than an answer.
- **The arena's span table** was a fixed 16384 with a panic when full, and
  **the stage-2 chunk table** a fixed 4096. Both were guesses at how much any
  guest would need; pacman needs more. Neither limit is one a guest can see
  coming or stay under, so both now grow.
- The fourth is `hv_vm_map` refusing, and that one is still open.

Along the way `record_region`'s panic learned to name both regions. "recording
overlapping regions" alone says nothing about which mapping was already there;
with the addresses it took one run to see that the heap had marched three
gigabytes into the mmap area.

`dnf` gets further and stops elsewhere: *"getaddrinfo() thread failed to start"*
— its resolver wants a thread it cannot have. That is a separate gap and is not
investigated here.

Two smaller things both images needed. **pacman 7 confines its downloader with
Landlock**, which there is no kernel here to provide, so it refuses to fetch
anything at all; the builder turns the sandbox off, which gives up nothing —
it exists to confine a root helper on a real kernel, and this root is emulated.
And **neither image ships `sudo`**, which only the apt path can seed, so `msl`
now says so instead of repeating a promise that belongs to Debian and Ubuntu.

### 3.5.27 A host mode can lock the guest's root out — **worked around**

Fedora's image stops `useradd` at *"cannot open /etc/gshadow"*, and root cannot
write `/root`. Both are the same thing, and it is not about the guest's
credentials at all: `/etc/gshadow` is mode 0000 and `/root` is `dr-xr-x---`, and
NABI performs every access as the ordinary host account. **An entry that denies
its own owner cannot be reached by anybody but real root, and NABI is not real
root** — so the guest's root, which §3.5.25 made a fiction deliberately, cannot
reach it either.

The builder gives the owner back read on files and write on directories, which
touches about a dozen entries in either image. What the guest sees shifts —
0000 becomes 0600, 0550 becomes 0750 — which nothing checks, and which still
keeps both to root.

The general answer is the one §3.5.25 already built for ownership: record the
guest's *mode* beside its owner, so the host mode can stay permissive while the
guest sees the real one. That is the right fix and it is not done.

### 3.5.28 Two ceilings on the same address — **fixed**

`pacman -Sy` panicked with `hv_vm_map failed`, and that message is all it said.
The first fix was to make it say something: which IPA, which host address, which
protection, and how far up the address space the request was. One run then
answered it — the IPA was past `0x10_0000_0000`, which is 36 bits.

Two separate things cap a guest-physical address, and they have to agree:

- the size the VM is created with — `hv_vm_create(NULL)` takes the platform
  default, **36 bits**, though the framework will give 40 for the asking;
- `TCR_EL1.IPS`, which caps what stage 1 may *output* — hardcoded to **36**.

They agreed by coincidence, so nothing had ever noticed. Raising only the VM's
moved the failure rather than fixing it: `hv_vm_map` accepted an IPA above
64GiB, stage 1 then refused to translate to it, and the guest took a level-3
translation fault on a page whose descriptor read `valid af el0 rw`. A page
table that describes a mapping the MMU will not perform is about as misleading
as a fault gets. `TCR_EL1` is now built from what the VM actually has.

That is 16× the room, and it is not a fix for why the room ran out. IPAs come
from a bump allocator that only reclaims what a guest explicitly unmaps, so a
process that churns mappings walks up the address space and never comes back
down. pacman got through 63GiB of it. **Reclaiming freed IPA ranges is not
done**, and with a terabyte to walk through it is no longer what stops pacman:
what stops it now is time. Every `mmap` re-establishes stage 2 one 16KiB block
at a time, so a large mapping costs thousands of hypervisor calls, and
`pacman -Sy` was still synchronising after fifteen minutes with `do_mmap` on top
of the stack. Batching contiguous blocks into one call is the next piece of
work.

### 3.5.29 `msl install arch` hung — **fixed**

Not on anything NABI did. pacman crashed, and its crash handler asked *"Set the
ulimit value to unlimited to generate the coredump? [Y/n]"* — on the terminal
the installer inherited, and through a `tail` that showed nothing until the
command finished. So it waited for an answer to a question nobody could see.

Guest steps in the builder now read `/dev/null` and run under a time limit.
Neither is about pacman: an installer that can block on an invisible prompt will
do it again for a different reason, and a step that is merely slow is
indistinguishable from a hung one to somebody watching. When the limit is hit
the tree is still finished and handed over, with the one thing it lacks named
and the command to retry it printed.

### 3.5.30 `/boot` belongs to the guest — **changed**

`/boot` was a host passthrough: when mSL/FHS provides one, the guest saw the
host's. The reasoning was that FHS owns the real `/boot` and a rootfs cannot
know what this machine boots. That answers a different question from the one a
guest asks. A Linux distribution reading `/boot` wants its own kernel, its own
`System.map`, its own `grub.cfg` — not the kernel collections macOS boots — and
passing the host's through gave a wrong answer while making the right one
unreachable:

- Arch Linux ARM ships a kernel, an initramfs and a tree of device trees in its
  tarball, and the guest could not see any of it.
- `apt-get install linux-image-arm64` stopped at *"unable to create
  /boot/System.map-…dpkg-new: Permission denied"*, because dpkg was writing into
  the host's `/boot` as an ordinary account. A guest package manager installing
  a Linux kernel into the Mac's boot directory would have been worse than the
  failure.

The guest keeps its own `/boot` now. `/proc` and `/sys` still pass through, and
for a reason that does not apply here: their contents describe the live machine,
which no rootfs can know. `/boot` holds files a distribution ships.

### 3.5.31 `syncfs` was missing — **fixed**

With `/boot` writable, the kernel package unpacked and then failed to
*configure*: `sync: error syncing '/boot/initrd.img-…': Function not
implemented`. `syncfs` was not implemented at all, `update-initramfs` syncs the
initrd it just built, and the kernel postinst treats a failure there as fatal —
so a 37MB kernel landed correctly and was left unconfigured over a flush.

Darwin has no `syncfs`, and the nearest thing, `F_FULLFSYNC`, is a stronger
promise about one file rather than a weaker one about a filesystem. `fsync` on
the descriptor is the honest approximation; every caller that reaches here wants
the bytes it just wrote to be durable, and they are.

### 3.5.32 What goes in `/boot`

The distro's own kernel package where its package manager works — only the apt
family today — skipped when the image already shipped one, as Arch's does. And a
`grub.cfg` naming whichever kernel is there.

fakegrub is the tool that generates these, and this does not use it: it carries
no licence at all, which means all rights reserved rather than public domain,
and has not been touched since 2019. Neither vendoring it nor fetching it at
install time is something to do to somebody else's machine. What it emits is a
`menuentry` block, so the builder writes one directly and a `grub.cfg` from
either is the same file.

The entry describes a kernel that will never be executed — NABI *is* the kernel
here. It is there to be read, by an initramfs hook globbing `/boot/vmlinuz-*`,
by a postinst calling `update-grub`, by os-prober, and an empty `/boot` answers
those wrongly rather than not at all.

### 3.5.33 pacman was never slow — **fixed**

§3.5.28 recorded that what stopped `pacman -Sy` was time: mappings being
re-established one block at a time, `do_mmap` on top of the stack after fifteen
minutes. That was wrong, and the way it was wrong is worth keeping.

Stage 2 was already batched. `vmm_arm64_map_stage2` takes a whole region and
makes one `hv_vm_map` call for it; the profile that looked like slow mapping was
read at too shallow a depth. Sampling properly put **387 of the 436 samples** in
the page-mapping loop on two lines - the `ipa_to_host` calls inside
`walk_to_l3`, which was a linear scan over every stage-2 chunk ever allocated,
run twice per 4KiB page. Since §3.5.28 removed the cap on that table, it grew
without bound, so every mapping got slower as the guest allocated more. It is a
hash now.

But that was not the problem either. **pacman was not slow. It was blocked**,
spinning in libcurl's retry loop with the download of every database producing
zero bytes:

```
curl: (27) Out of memory
```

on a machine with 32GiB free. `eventfd2` - syscall 19 - was not implemented at
all. libcurl's multi interface creates one for `curl_multi_wakeup` and treats
the failure as fatal, so `curl_multi_init` returned NULL and the tool reported
the only error it has for that. pacman 7 and dnf both drive libcurl that way,
which is why neither could fetch anything and why dnf's separate complaint about
a resolver thread was a red herring.

Darwin has no eventfd. It is emulated with a socketpair - the guest gets one
end, NABI keeps the other, and one byte is held in flight whenever the counter
is nonzero, which is what makes poll, select and epoll answer correctly without
knowing anything is emulated. The counter lives in NABI, because a socketpair
queues bytes where an eventfd accumulates a total: a guest that writes 1 five
times must read back 5, not 1 with four bytes still pending.

`pacman -Sy` went from never finishing to **5.4 seconds**.

### 3.5.34 Four more things between there and an installed package

Each was found by the next one appearing, and none is about performance.

**`/proc/mounts` was not served.** pacman reads `/etc/mtab` to find out which
filesystem it is unpacking into and stopped at "could not determine filesystem
mount points". There is no mount table to report - the guest's filesystem is one
host directory - but what software wants from that file is which filesystem a
path is on, and a root entry answers that truthfully.

**A symlink into `/proc` was not followed there.** `/etc/mtab` *is* a symlink to
`/proc/self/mounts` on every distribution, and the check for NABI's own /proc
files is made on the name the guest passed. So the name that arrived was
/etc/mtab, the check declined it, and resolution followed the link inside the
rootfs where the target is not a file. One hop is now retried against procfs -
distributions ship exactly one link here, and following a chain would be
re-implementing resolution rather than finishing it.

**AF_UNIX paths went to the host untranslated.** A guest binding
`/etc/pacman.d/gnupg/S.gpg-agent` asked the *host* for that path and got ENOENT,
so gpg-agent never started, `pacman-key --init` could not generate a key, and
signature checking had nothing to work with. Every other file operation is an
`*at()` call against a resolved directory, but `bind` takes a path inside a
sockaddr and there is no `bindat`, so this is the one place a guest path has to
be turned back into a host one. `F_GETPATH` on the resolved directory does it.

Fixing that introduced a heap overflow immediately: the sockaddr is allocated
with the length the *guest* sent, and a translated path is longer. It presented
as `connect` spinning at 100% CPU inside `free()`. AF_UNIX now gets a full
`sockaddr_un` and `sa_len` describes the path the call will actually use.

**getdents lost entries.** Every call opened a fresh `DIR` over a dup of the
descriptor and closed it again, keeping its place with telldir/seekdir. Neither
half works: a telldir cookie belongs to one DIR instance and does not outlive
it, and what seekdir leaves on the descriptor is the start of the block it
re-read rather than the entry asked for. Reading a 4000-entry directory returned
**3792 of them, with no error anywhere** - a guest simply did not see some of
its own files. `d_seekoff` is no way out either; APFS reports it as zero, and
seeking there restarts the directory from the top forever. The stream stays open
between calls now, so the position lives in the stream instead of having to be
reconstructed.

### 3.5.35 `/proc/self/fd` has to be the guest's, and has to be live

The last thing between `checking keyring...` and an installed package, and it
took two goes.

libassuan reads `/proc/self/fd` before starting gpg-agent, to close what it
inherited. `/proc` is a host passthrough when mSL/ProcFS is mounted, so the
guest got **nabi's** descriptors - the arena, the checkpoint files, the rootfs
handle - whose numbers mean nothing to it. Worse, the set changed while it was
being read, because serving the read opens descriptors. The listing never
stabilised and `pacman -S` sat in `getdents64` forever.

So NABI answers it, from the guest's own descriptor table, with a directory of
symlinks built to be read. Two details each cost a run:

- `/proc/self/fd/` with a trailing slash is the same directory, and missing that
  sent the open back to the host's /proc.
- The listing has to be **rebuilt on rewind**. Real /proc/self/fd is live: the
  caller reads it, closes what it found, and reads again to see what is left.
  Against a snapshot that never changes the second read returns the first
  answer, and the program waits forever for a list that cannot shrink. A probe
  printing one line per rewind is what made that obvious - the same descriptor,
  thousands of times.

`pacman -S git` with the distribution's own `SigLevel` now resolves seven
packages, verifies them and installs them in **6 seconds**.

### 3.5.36 dnf's librepo assertion was self-inflicted — **fixed**

```
lr_download: Assertion `(dtarget->fd > 0 && !dtarget->fn) || (dtarget->fd < 0 && dtarget->fn)' failed
```

librepo insists a download target's descriptor is strictly positive, and it had
been given **zero**. Tracing showed why: `eventfd2` was returning `register_fd`'s
*status* rather than the descriptor, and register_fd returns 0 for success. So
every eventfd this repository had just implemented came back as fd 0.

Nothing complained at the time, which is the interesting part. A guest holding
fd 0 and treating it as an eventfd writes to it, reads from it and polls it, and
all three appear to work, because what it is really holding is stdin. The bug
surfaced two layers away and in a different process: dnf closed the eventfd it
had been given, thereby closing the guest's real stdin, and the next `open` took
the free slot. librepo then asserted about a destination file that had
legitimately been given descriptor zero.

`dnf makecache` went from aborting to fetching 60MB of metadata in 8 seconds.
The smoke test that guards it checks the *number* as much as the behaviour.

### 3.5.37 An absolute path makes the dirfd irrelevant — **fixed**

With the index built, rpm could not unpack:

```
failed to open dir usr of /usr/bin/: cpio: open failed - Bad file descriptor
```

about a directory that was plainly there. rpm opens the transaction root with
`openat(-1, "/", ...)`, which on Linux succeeds: **when the path is absolute the
directory descriptor is ignored, and not even checked for validity.** NABI
validated it first and returned EBADF, so the descriptor rpm used for every
component afterwards was -1 and the whole unpack cascaded from one refused call.

`dnf install` now unpacks and configures. `dnf -y install tree` exits 0 and the
package runs.

### 3.5.38 What still fails on Fedora

Two things, and both predate this work - checked against the previous commit
rather than assumed.

**ldconfig segfaults when it is a forked child.** Run top-level it completes and
writes the cache; run as `bash -c ldconfig` it dies on SIGSEGV every time. That
fails glibc-common's `%transfiletriggerin`, whose lua calls `rpm.spawn
{"ldconfig"}`, gets nil, and hits `assert(nil)` on line 20 - so any transaction
touching glibc's file triggers is reported as failed even though the packages
unpacked. Ordinary installs are unaffected.

The faulting address is `0x6e756f46206572a7`, which is ASCII text rather than an
address - a pointer overwritten with string data. So this is memory corruption
in the resumed child, not a missing mapping, and the child had `execve`d after
being resumed. That is the narrowest description available and it is where the
next investigation starts.

Two things made it findable and are worth keeping in mind: the fault took the
`addr_ok` branch, which reports through **printk** rather than stderr, so with
no `-p` sink it is completely silent; and a resumed child writes its sinks to
`<path>.<pid>`, which is what the environment variables are for.

**A setuid binary cannot be executed.** Fedora's sudo is mode `---s--x--x`, and
NABI has to *read* an ELF to load it while the host account has no read
permission - so `sudo` installs correctly and then cannot run. This is §3.5.27
again, arriving at runtime rather than at build time, and the answer is the same
one that is still not done: record the guest's mode beside its owner so the host
mode can stay permissive.

### 3.5.39 `brk(0)` answered the wrong question — **fixed**

The ldconfig crash was recorded in §3.5.38 as happening "when it is a forked
child". That was wrong, and it is worth saying how the framing misled the
search. `bash -lc ldconfig` crashed and `bash -c ldconfig` did not, so fork
generations looked like the variable; a minimal fork-plus-execve harness never
reproduced it, at any parent size. What a login shell actually does differently
is **set LANG**, and `ldconfig` run top-level with `LANG=C.UTF-8` crashes just
the same. There was no fork in it anywhere.

With a one-process reproducer the trace showed the bug plainly:

```
brk(brk: 0x4d8b20): ret = 0x4dc000     <- raise, granted
brk(brk: 0x0):      ret = 0x4d8000     <- query, answered lower
```

`brk(0)` is how every libc asks where the break *is*. Zero is below any floor,
so it fell into the "below start_brk" arm, which answered `start_brk` - the
address the heap began at. That is the same number only until something has
grown it, and static glibc grows it before anything else: `__libc_setup_tls`
takes the thread block with `sbrk` during startup. So glibc recorded a break
below memory it had already been given, and the next allocation was handed the
same bytes a second time, on top of the thread pointer.

LANG is what decides whether that matters. A C-locale process does not allocate
again after TLS, so it never discovers the overlap; `setlocale` for any real
locale does, immediately.

The symptom named none of this. The faulting address was `0x6e756f46206572a7` -
ASCII text rather than an address, a pointer with a string written through it -
which says memory corruption and says nothing whatever about `brk`. Linux
returns `mm->brk` for a request it declines, and so does this now.

`dnf` installs 35 packages and reports Complete; `ldconfig` runs under a login
shell; the glibc-common lua trigger that calls it succeeds. Debian and Ubuntu
were checked too and were never affected - their tools do not run a static
binary early enough with a locale set.

Two things about the search are worth keeping. The fault took the `addr_ok`
branch, which reports through **printk**, so with no `-o` sink it is silent -
and `-p` is not the flag. And the strace sink is a buffered `FILE*`, so a
process that dies takes its last lines with it: "the crash is right after this
call" is a guess unless the process exited cleanly.

### 3.5.40 A mode that denies its own owner — **fixed**

§3.5.27 worked around this in the builder and wrote up the real answer as
outstanding. Fedora made it unavoidable: `dnf install sudo` succeeds and the
result cannot run.

Every distribution ships sudo as `---s--x--x` - executable by anyone, readable
by no one, set-user-ID root. NABI performs every access as the ordinary host
account that owns the tree, and loading an ELF means *reading* it, so a mode
with no owner read is a file NABI cannot open however entitled the guest is to
execute it. Relaxing the mode is not available either, because the mode is also
what the guest sees and what the permission checks are made of; turning sudo
into 0755 hands it to everybody.

So the guest's mode is recorded beside the file exactly as its owner already
was, in `msl.nabi.mode`, and the host keeps a mode NABI can work with - the
guest's permission bits plus owner access, and without the setuid bits, which
are honoured against the recorded mode instead. Granting the owner what it
already had concedes nothing: NABI owns the tree and may chmod anything in it at
any time, so this changes what other host tools see and nothing about what the
guest can reach.

Absent, the mode is the host's. That is the common case and costs one failed
lookup - everything a distribution unpacks with ordinary permissions needs no
attribute at all, and `ls -lR /usr` measured no slower than before.

Four things had to change together, and each was found by the previous one:

- **Order.** The host mode must be relaxed *before* the attribute is written,
  because writing an extended attribute needs write permission on the file and
  the mode being recorded is precisely one that denies it. Recording first fails
  with EACCES on exactly the files this exists for.
- **Repair.** Trees that already exist carry restrictive modes and no attribute,
  so there is nothing recorded to explain the refusal. Rather than require a
  sweep, an open that fails with EACCES adopts the mode it finds as the guest's,
  puts a workable one on the host, and tries once more.
- **execve reads what it may not read.** Linux checks *execute* permission and
  then reads the file regardless - which is the entire point of `---s--x--x`.
  Loading an image here is an ordinary open, so the guest's own read check
  refused sudo a few lines after the execute check had allowed it. The file's
  read check is now suppressed while NABI is loading an image; search permission
  on the directories leading to it still applies, as Linux enforces that too.
- **The setuid bit is not on the host file.** `elevate_privilege` read it from a
  host `fstat`, which now never carries it, so exec takes the guest's view
  instead. That fixed a second bug in passing: the ids were a host `st_uid` put
  through `host_uid_to_guest`, which was right only while every file belonged to
  the one account NABI runs as. Since §3.5.25 recorded ownership per file, a
  setuid binary given away to a guest user still stats as the host account, and
  mapping that would have elevated to **root** - the opposite of what the file
  says.

`suidtest` checks all three properties at once, because any two without the
third looks like a plausible hole: the guest still sees `4111`, the file can be
executed, and the bit elevates. The helper's mode is set from the host side, so
the repair path for pre-existing trees is covered too.

Sudo now loads and runs. It stops later, inside PAM session setup
(`pam_open_session: Permission denied`), which is a different layer and not
investigated here.

### 3.5.41 `sudo` stopped on a nice value — **fixed**

`sudo id` reached the point of running something and then stopped:

```
sudo: pam_open_session: Permission denied
sudo: policy plugin failed session initialization
```

The builder had been working around this since §3.5.25 by commenting `pam_limits`
out of sudo's session stack, with a note saying the refusal was "internal to the
module and is not yet understood". It was NABI's, and the trace says so plainly
once the whole sequence is read together rather than the failing call alone:

```
getpriority(0, 0)               -> 0        the value Darwin reports
setpriority(0, 0, niceval: 20)  -> 0        the guest applies what it read
getpriority(0, 0)               -> 20       so it is now true
setpriority(0, 0, niceval: 0)   -> EACCES
```

**Linux's getpriority syscall does not return the nice value.** It returns
`20 - nice`, so the result is 1..40 and can never be mistaken for an error, and
glibc's wrapper converts it back. Darwin's `getpriority(3)` returns the nice
value itself, and handing that over unchanged means the guest computes
`20 - nice` a second time - so an ordinary nice of 0 reads as 20, the lowest
priority there is.

pam_limits believed it and applied it, which really did drop the host process to
nice 20. Putting it back to 0 was then a *raise* in priority, which Darwin
refuses to an unprivileged process, and pam_limits is `required` in sudo's
session stack. So sudo failed at session setup because of a nice value, and the
error named neither.

The workaround is removed and pam_limits left where the distribution put it.
`sudo id` returns `uid=0(root)` for an unprivileged guest user, and `su` works
in every form.

### 3.5.42 Why Fedora had no `su` — **and now does**

Not a bug. Fedora's container image installs **`util-linux-core`**, which is 151
files and does not include `su`, `runuser`, `login` or `setpriv`; `su` lives in
the full `util-linux`. A container is entered with `docker exec -u`, so nothing
in that image needs it. Arch's base tarball ships neither `su` nor `sudo`
either.

That was worth stating rather than fixing while neither package manager worked -
a published image brought whatever it brought. Both work now, so the builder
installs `sudo` and `util-linux` for the oci and tar families after the index
exists, which is the same thing the apt families get by seeding. The closing
message no longer promises `su` to a tree that has not got it.

### 3.5.43 `msl login fedora` looked like a hang — **fixed**

It was not hung. The shell was running, echoing, and answering commands the
whole time; what it never printed was a **prompt**, and a blank screen that
takes input and shows nothing is indistinguishable from a hang. Driving it
through a pty and asking it questions is what separated the two:

```
FLAGS=hBs          <- no `i`: bash is not interactive
PS1=[]             <- so no prompt was ever going to appear
tty -> not a tty   <- and here is why
```

`isatty()` was failing, and it failed on one unhandled ioctl:

```
ioctl(fd: 0, cmd: 2150388778) -> EPERM      = _IOR('T', 0x2a, 44)
```

which is **TCGETS2**. Linux has two termios interfaces: the original four bare
`0x54xx` numbers, and the `termios2` family, `_IOC`-encoded and carrying the two
baud rates as plain numbers rather than `Bxxx` constants. glibc moved to the
second in 2.42, so `tcgetattr(3)` now compiles to `TCGETS2` and nothing else.
NABI knew only `TCGETS`, so every terminal query from a current distribution
came back EPERM from the default arm.

Fedora 43 ships glibc 2.42 and Debian trixie ships 2.41, which is the whole of
why this appeared on one and not the other - and why it appeared *now*: Fedora's
login only started going through a shell that cares once §3.5.42 gave the image
a `su` to log in with. Before that it fell back to a root shell, which had the
same empty prompt and was equally silent about it.

A `termios2` is a `termios` with two fields appended, so the flag conversion is
shared rather than copied - two mappings to keep in step would be a bug waiting
for the next person. `ptytest` covers the new numbers, and fails on the old
build with `TCGETS2 on a fresh master`.

Worth keeping: the failing ioctl is logged with its number in decimal, and
decoding it - direction, size, type, sequence - is what named it. An unhandled
ioctl reports EPERM, which reads as a permission problem rather than a gap.

### 3.5.44 `sudo` could not allocate a pty it had already opened — **fixed**

```
sudo: unable to allocate pty: Operation not permitted
```

The trace shows it getting all the way there and failing on the last step:

```
openat("/dev/ptmx", O_RDWR)          -> 16
ioctl(16, TIOCGPTN)                  -> 0
ioctl(16, TIOCSPTLCK)                -> 0
ioctl(16, 0x5441 = TIOCGPTPEER)      -> EPERM     (glibc falls back)
openat("/dev/pts/2", O_RDWR|O_NOCTTY) -> 17       (the fallback works)
fchownat("/dev/pts/2", 0, 5)         -> EPERM     <- fatal
```

The fatal one is `grantpt()`, chowning the slave to the caller and to group
`tty`. `/dev` is a host passthrough, so the guest's chown becomes an attempt to
record ownership in an extended attribute on **devfs**, which carries none:
measured on the host, both `setxattr` and `chown` on a pty slave are EPERM, and
would be even for root. Reporting that back says "you may not do this" to a
guest that on Linux plainly may - and on Linux devpts, `grantpt` is a no-op the
kernel has already performed.

So a chown that cannot be recorded *on a passthrough* now succeeds. Those are
host objects whose ownership was never ours to state; inside the rootfs a
failure here is real and is still returned, because that is where the attribute
means something.

`TIOCGPTPEER` remains unimplemented. glibc falls back to `TIOCGPTN` plus an open
of `/dev/pts/<n>`, which works, so it costs one refused ioctl and nothing else.
Implementing it would mean an ioctl that returns a *descriptor*, which the ioctl
path is not built to register - worth doing, not worth doing here.

### 3.5.45 `/proc` is unreadable to an unprivileged guest — **not NABI's**

`cat /proc/version` as an ordinary guest user is "Permission denied", and as
root it is fine. That is correct enforcement of what the host presents:

```
-r-xr-x--- 1 sunneva staff 0 /proc/version
```

Everything mSL/ProcFS exposes is mode **0550** owned by the account that mounted
it - 417 directories and 40 files, not one of them readable by `other`. NABI
maps that owner to guest root, which is right, and then an unprivileged guest
has no bits at all.

Linux presents `/proc/version`, `/proc/cmdline`, `/proc/uptime` and their
neighbours as `-r--r--r--`, and `/proc/<pid>` as `dr-xr-xr-x`. A macOS
filesystem defaulting to 0550 is reasonable on its own terms; it is only wrong
once a Linux guest with its own uids is reading it.

**It needs no code anywhere.** mSL/ProcFS already has the switch
(`kext/procfs_vnops.c:1152`):

```c
mode_t modemask = (pmp->pmnt_flags & PROCFS_MOPT_NOPROCPERMS)
                  ? RWX_OWNER_RX_ALL : ALL_ACCESS_OWNER_GROUP_ONLY;
```

with `READ_EXECUTE_ALL` 0555, `ALL_ACCESS_OWNER_GROUP_ONLY` 0770 and
`RWX_OWNER_RX_ALL` 0755 - so the default masks to **0550** and `noprocperms`
masks to **0555**, which is what Linux gives `/proc/<pid>`. Mounting with

    mount -t procfs -o noprocperms procfs /proc

is the whole fix. What it costs is stated plainly in that repository's README:
it lets every account on the *Mac* see every process, not just its own. Under
NABI that is what Linux does anyway - `hidepid=0` is the default there - but the
tradeoff is a macOS one and is the reason it is not the default.

NABI is left alone. Enforcing the modes it is given is the correct behaviour,
and having one module quietly override another's metadata would make the next
disagreement of this kind much harder to see.

### 3.5.46 `..` walked out of the rootfs — **fixed**

Chasing why every rpm `%sysusers` scriptlet failed found something larger than
the scriptlet. In the guest:

```
stat /       1048605:16
stat /..     1048605:2       <- a different inode: the host volume's root
stat /../..  1048593:18481   <- a different device: the host's /Volumes
ls /..    ->  fedora
```

On Linux `/..` is `/`; the kernel pins it and a process cannot climb out of its
own filesystem. Here the *host* resolved the component, so every host file was
one `..` away from a guest. That is a containment hole on its own terms.

It is also what broke sysusers, by a route worth recording. systemd's `chaseat()`
returns an absolute path when the descriptor it walked from is the root, and
decides that by asking where `..` leads. Told somewhere else, it returned a
relative path, and `chaseat_prefix_root` rejects "relative path with root /" as
impossible - the case its own comment says cannot arise. Hence "Failed to prefix
'usr/lib/sysusers.d/setup.conf' with root '/': Invalid argument", which names
neither `..` nor the rootfs.

`.` and `..` are now folded during the component walk, clamped at the root. The
walk rather than a pass over the whole string beforehand, because on Linux `..`
applies to what the path has resolved to *so far*: folding `link/..` textually
gives nothing, where the answer is the parent of the link's target.

Two things that cost a build each. Suppressing the separator on an empty path
also suppressed the leading slash of a passthrough, and the guest lost `/dev`.
And identifying the root by descriptor *number* is not enough: a guest that
opens `/` for itself gets an ordinary descriptor, and systemd holds one, so it
went on escaping until the check compared what the descriptor points at.

### 3.5.47 `getcwd` answered with host paths — **fixed**

A guest's first `getcwd` returned `/Users/sunneva/Development/mSL-XNU/mSL-NABI`
- the directory nabi happened to be launched from, which has no name in the
guest's namespace at all. After a `chdir` it returned
`/Volumes/msltest/fedora/etc` for what the guest calls `/etc`.

bash hides this by tracking `PWD` itself, which is why it went unnoticed: `pwd`
looked right. It surfaced when something did arithmetic on the real answer.

The guest now starts inside its own filesystem, and `getcwd` translates: under
the rootfs the prefix is stripped, a passthrough keeps its name because that
name is the same on both sides, and anything else - which the startup `chdir`
makes unreachable - answers `/`.

### 3.5.48 `statx` did not report a mount, so systemd asked a syscall we lack

With the root pinned, sysusers got further and stopped on "Failed to load user
database: Function not implemented". The unimplemented call was **264**,
`name_to_handle_at`, called as `(fd, "", handle, &mnt_id, AT_EMPTY_PATH)` - the
fallback for finding out which mount a file is on when `statx` does not say.

NABI's `statx` filled the basic set and left `stx_mnt_id` out of the mask, so
systemd fell through to the syscall Darwin has nothing to implement, and ENOSYS
is fatal where EOPNOTSUPP would not have been. `st_dev` is the identifier to
give: one number per filesystem, equal for two files on the same one, and it
agrees with the `stx_dev_major`/`minor` pair reported beside it, which is the
fallback comparison anything doing this uses anyway.

### 3.5.49 `/proc/self/fd/<n>` was only a name you could open — **fixed**

The last one. systemd changes the mode of an `O_PATH` descriptor by chmod'ing
`/proc/self/fd/<n>`, because `fchmod` on an `O_PATH` handle is not allowed.
NABI answered that path for `open` and for `readlink` and for nothing else, so
the chmod went to the host's `/proc` and came back EACCES - "Failed to copy
permissions from /etc/group to /etc/.#group…".

Path resolution now rewrites it to the file the descriptor holds, so every
operation reaches the file rather than the name. `dnf` installs `tpm2-tss` and
`systemd-resolved` and reports **Complete**, with the sysusers scriptlet
returning 0.

### 3.5.50 Every filesystem claimed to be HFS — **fixed**

```
/proc/ is not mounted, but required for successful operation of
systemd-tmpfiles. Please mount /proc/.
```

on a machine where it plainly was. "Is /proc mounted?" is not asked by looking
at the mount table - it is asked by calling `statfs` and comparing `f_type`
against `PROC_SUPER_MAGIC`. NABI answered `HFS_SUPER_MAGIC` for every
filesystem there is, so the answer was always no, and `apt install` stopped
wherever it triggers systemd-tmpfiles.

Darwin's `statfs` carries `f_fstypename`, which is the mount's own name for
itself, so the mapping needs no knowledge of which path is which - a passthrough
is recognised by what it *is*. procfs, sysfs and devfs get the magic Linux uses
(devtmpfs and Darwin's devfs report the same one, which is what a guest expects
under /dev); everything else keeps the old answer.

`apt-get install gcc` now completes on Debian and gcc runs.

### 3.5.51 `sudo dnf install` aborted at its prompt — **fixed**

```
Is this ok [y/N]: Operation aborted by the user.
```

immediately, without waiting. The trace says exactly what happens and no more:

```
write(fd: 2, "Is this ok [y/N]: ")  -> 18
read(fd: 0, ..., 0x2000)            -> EINTR
```

dnf treats the interrupted read as a refusal. What has been ruled out: it is not
the pty, which `sudo cat` relays correctly in both directions; not the terminal
check, since stdin and stdout are both ttys inside sudo; not dnf, which run
directly as root reads `y\n` from fd 0 and completes; and not the process
groups, since `setpgid` and `TIOCSPGRP` both succeed.

The first guess was SIGCHLD from dnf's own children: dnf installs a SIGCHLD
handler with SA_RESTART, and Linux would restart the read rather than fail it.
Probing showed that guess was wrong, and the way it was wrong is the answer. At
the moment of the EINTR nabi had **nothing pending** and the guest's SIGCHLD was
still SIG_DFL. The `[SIG 17]` deliveries that pointed at SIGCHLD were in *other*
processes - bash and sudo - not in dnf.

So the signal belonged to the **host process alone**. NABI's process is not the
guest: it links frameworks, it runs threads of its own, and it takes signals for
their reasons. Darwin was asked whether it honours SA_RESTART and it does -
`read` and `readv` on both a pipe and a pty were confirmed to restart rather
than fail - so the interruption came from something with no guest meaning at
all, and passing the EINTR on invented an event Linux would never have reported.

EINTR is the guest's answer to "a signal *you* handle arrived while you were
waiting". A read or write is therefore retried when nabi has nothing to deliver,
and when everything it has to deliver carries SA_RESTART, which is what Linux
does with that flag. A handler without it still breaks the call, so something
waiting on SIGALRM to end a read still gets its EINTR.

`sudo dnf install gcc` now waits at its prompt, takes the answer, and reports
Complete.

### 3.5.52 Two reports that were not bugs, and one small thing that was

**`./hello.c` is not `./hello`.** A guest reported needing sudo to run something
it had just compiled:

```
$ gcc hello.c -o hello
$ ./hello.c            -> Permission denied
$ sudo hello           -> command not found
$ sudo ~/hello         -> hello
```

Nothing here is NABI's. `./hello.c` is the *source*, mode 0644, and refusing to
execute it is what Linux does too - checked, and `./hello` beside it runs
unprivileged and exits 0. `sudo hello` then fails because there is no `./`, so
it is a PATH lookup, and Fedora's sudoers sets

    Defaults secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:...

which does not include a home directory. `sudo ~/hello` worked, but so would
plain `./hello`; sudo was never the thing that made the difference.

Worth confirming rather than assuming, because §3.5.40 had recently changed how
modes are recorded, and "a freshly compiled binary will not run" is exactly the
shape a bug there would have taken.

**nano's complaint was an empty home** - and that one is worth smoothing:

```
Unable to create directory /home/sunneva/.local/share/nano/: No such file
or directory
```

Neither distribution's `/etc/skel` contains `.local`, so a home made by
`useradd -m` has none, and nano creates only its own leaf with a single
`mkdir`. `mkdir -p` of the same path succeeds, so nothing is broken - it is an
empty home and a program that does not create parents. On a real system those
directories arrive with a desktop session or a login manager, and this guest has
neither, so the builder now creates the XDG base directories with the account.

### 3.5.53 `/proc/sys/kernel/random` — **fixed**

An Arch login opened with three of these:

```
-bash: /proc/sys/kernel/random/uuid: No such file or directory
-bash: /proc/sys/kernel/random/boot_id: No such file or directory
```

mSL/FHS mirrors **Darwin's sysctl tree** under `/proc/sys`, so `/proc/sys/kernel`
is the `kern.*` namespace - `argmax`, `aiomax`, `apfsprebootuuid` - and
`random/` exists but is empty, because Darwin has no `kern.random.*`. These two
files are Linux's own and nothing on the host answers them, which is the same
case `/proc/mounts` is already served for, so NABI answers them too.

They are opposites, and that is what makes them worth a test. `uuid` is a
generator with a filename: every read gives a different value, and caching one
would be a defect nothing would report. `boot_id` must not change while the
machine is up - Darwin has exactly that in `kern.bootsessionuuid`, so this is a
translation rather than an invention, and every guest on the host agrees on it.
Lowercase, as Linux writes it. bash's OSC 3008 now carries the real
`bootid=d80c4ba9-…`.

### 3.5.54 pacman hanging at "checking keys in keyring" — **not reproduced**

Reported as a hang installing gcc under `sudo`. It did not reproduce on a tree
built from the current source, across: `pacman -S gcc` as root (22s), the same
under `sudo` through a real pty as an unprivileged user, and twice more in a
row. A deliberately wiped keyring does not hang either - it fails cleanly with
"required key missing from keyring".

The likeliest explanation is that the report predates §3.5.51, which is exactly
the shape that would hang a gpg-driven step under sudo: a host-only signal
turning a blocking call into EINTR. Worth re-checking against a current build
before looking further. If it recurs, the way in is `NABI_STRACE_PATH`, which a
resumed child writes to `<path>.<pid>`, and sampling the busiest of the several
nabi processes rather than the first.

### 3.5.55 The rest of the `sched_*` family — **implemented**

Only `sched_yield` and `sched_getaffinity` existed; the other eight were ENOSYS
on both architectures. All are implemented now: `setparam`, `getparam`,
`setscheduler`, `getscheduler`, `setaffinity`, `get_priority_max`,
`get_priority_min`, `rr_get_interval`.

**A guest thread is an ordinary host thread and stays one.** Darwin does have
real-time scheduling, but not through POSIX - it is Mach's `thread_policy_set`
with a time-constraint policy, needing a port and a privilege NABI has not got.
There is no honest way to put a guest thread on `SCHED_FIFO`, so it is refused,
and refused with **EPERM** because that is what Linux already tells an
unprivileged caller. Every program that asks for real-time scheduling therefore
already has a path for being told no - which is a far better answer than
accepting the request and not honouring it, since nothing can detect that.

What the tests are really for is **agreement between the calls**, which is
easier to get wrong than any single answer:

- `getscheduler` reports what `setscheduler` accepted, and `getparam` agrees
  with both.
- `setaffinity` accepts the mask `getaffinity` just handed out. A round trip
  returns what the guest was always going to get.
- An out-of-range real-time priority is EINVAL *before* privilege is
  considered, matching Linux's order, so a caller probing the range is not
  told EPERM when the real answer is EINVAL.

The priority *ranges* are the deliberate exception and report Linux's real
numbers - 99/1 for FIFO and RR, 0/0 for the rest. Asking what a policy's range
is is a question about the interface rather than a request to be scheduled under
it, and a guest comparing a number against the maximum should get the number it
would get anywhere else.

Two things are accepted without being enforced, and both are marked as such in
the code. `sched_setaffinity` cannot pin anything: Darwin's affinity policy is a
hint about cache sharing, not a restriction, and is not exposed for another
process at all - but affinity is overwhelmingly set as an optimisation by
runtimes that treat failure as fatal, and a mask naming no usable CPU is still
EINVAL. `sched_rr_get_interval` reports zero, which is what Linux reports for a
task that is not on `SCHED_RR`, and none are.

Verified against glibc rather than only at the syscall boundary - a Debian guest
compiling and running the obvious program reports `SCHED_OTHER`, `99/1`,
`Operation not permitted` for FIFO, and a zero quantum.

Worth noting for later: `sched_getaffinity` reports **one** CPU. That predates
this work and is left alone, but it is why a guest will not parallelise, and it
is the thing to revisit if that starts to matter.

---

## 4. Phased implementation

Each phase should land as its own commit and be independently testable.

### Phase 0 — de-risk the trap mechanism ✅ **DONE — PASSING**

Lives in [spike/arm64-trap/](spike/arm64-trap/); `make run` there reproduces it.
Standalone, arm64-only, and not wired into the top-level build (which is x86_64-
only, so the two would fight over `ARCH`). Throwaway once Phase 2 lands.

It maps one 64KiB region, points `VBAR_EL1` at an `hvc #0; eret` stub, `eret`s
from EL1 down to EL0, and runs `mov x8, #64; svc #0` twice. The MMU stays off
(`SCTLR_EL1.M == 0`), so both ELs address memory flat through stage 2 — no page
tables, no `TTBR0_EL1`, no `TCR`/`MAIR`. Those are Phase 2's problem.

**Result on an M5 / macOS 26 — the design in §2 holds exactly as specified:**

| Claim | Observed |
|---|---|
| `svc` at EL0 reaches the EL1 vector | yes, via `VBAR_EL1 + 0x400` (lower EL, AArch64, sync) |
| `hvc` from EL1 exits to the host | yes, `HV_EXIT_REASON_EXCEPTION` |
| with `ESR_EL2.EC == 0x16` | yes, HVC64 |
| host reads the syscall nr from `x8` | yes, 64 then 93 |
| host writes `x0`, value survives the return | yes, sentinel intact at the next trap |
| `eret` resumes EL0 after the `svc` | yes |

Three findings worth carrying into Phase 2:

1. **`ELR_EL1` already points past the `svc`** (observed `0x10808` for an `svc` at
   `0x10804`). This confirms §3.1: the x86 build's manual `rip += 2`
   ([src/main.c:255](src/main.c#L255)) must have **no** equivalent here. Adding one
   would silently skip an instruction after every syscall.
2. **HVF returns with PC already past the `hvc`.** No manual advance is needed
   after an HVC exit. The spike carries defensive code for the other case; it
   never fires.
3. **`SPSR_EL1` reads `0x3C0`** at the trap — EL0t with DAIF masked — confirming
   the exception genuinely originated at EL0 rather than at EL1.

**Gate:** ~~if this doesn't work, the whole architecture in §2 is wrong~~ —
cleared. Phase 1 may proceed.

### Phase 1 — arch abstraction (no behaviour change, still x86-only)

Introduce `include/arch.h` with an architecture-neutral vCPU interface, and move the
existing VMX code behind it as `lib/vmm_x86.c`:

```
vmm_get_reg(enum vreg, uint64_t *)     /* VREG_PC, VREG_SP, VREG_ARG0..5, VREG_SYSNR, VREG_RET */
vmm_set_reg(enum vreg, uint64_t)
vmm_get_sysreg(...) / vmm_set_sysreg(...)
vmm_run(struct vm_exit *)              /* normalised: EXIT_SYSCALL, EXIT_MMU_FAULT, EXIT_FAULT, EXIT_IRQ */
```

Rewrite `main_loop` ([src/main.c:200](src/main.c#L200)) against `struct vm_exit`
instead of raw `VMX_REASON_*`. Rewrite `handle_syscall`
([src/main.c:56](src/main.c#L56)) against `VREG_SYSNR`/`VREG_ARG*`.

**Test:** ~~the existing x86 suite must still pass on an Intel Mac (or under
Rosetta, if `kern.hv_support` permits)~~ — **not achievable, and the Rosetta
half was wrong.**

Rosetta translates x86 userland instructions but exposes no VT-x. An x86_64
process on Apple Silicon reads `kern.hv_support` as **1** — that sysctl reports
ARM HVF, not VT-x, so it is not a usable signal here — and then
`hv_vm_create()` returns `0x4`, `HV_UNSUPPORTED`. Measured, not inferred.

So the x86 suite requires genuine Intel hardware, and Phase 1 landed without it.
What that costs is discussed in §7.

### Phase 2 — arm64 VMM backend  *(backend landed; mm/exec/signal outstanding)*

New `lib/vmm_arm64.c` implementing the Phase 1 interface on the ARM HVF API.
New `include/arm64/vm.h` (translation-table descriptors, `TCR_EL1`/`MAIR_EL1`
encodings) replacing [include/x86/vm.h](include/x86/vm.h).
New `src/mm/ttbr.h` generated in place of [src/mm/pdp.h](src/mm/pdp.h).
Add the EL1 vector page and `VBAR_EL1` setup.
Delete `init_segment`, `init_idt`, `init_vmcs`, `init_special_regs`, `init_msr`,
`check_vm_entry` from the arm64 build.

Add entitlement + codesign steps to [CMakeLists.txt](CMakeLists.txt); select
`vmm_x86.c` vs `vmm_arm64.c` on `CMAKE_SYSTEM_PROCESSOR`.

**Milestone:** a static aarch64 `_exit(42)` binary runs to completion.

### Phase 3 — syscall table + ABI

Generate `include/syscall.h` from `asm-generic/unistd.h` (§3.2).
Flip `EM_X86_64` → `EM_AARCH64` (183) in
[src/proc/exec.c:56](src/proc/exec.c#L56) and
[src/proc/exec.c:107](src/proc/exec.c#L107).
Fix the initial stack/auxv layout in `do_exec` for the aarch64 ABI.
Implement `ppoll`, `epoll_create1`, `epoll_pwait`, `statx`.
Drop `arch_prctl`; move TLS to `TPIDR_EL0` in `clone`.

**Milestone:** static `busybox` for aarch64 runs.

### Phase 4 — signals, fork, threads

Signals: done (§3.4). Fork: done.

`struct vcpu_snapshot` ([include/vmm.h](include/vmm.h)) is now the aarch64 state -
`x0`–`x30`, `SP_EL0`, `PC`/`PSTATE`, the banked `ELR_EL1`/`SPSR_EL1`, `TPIDR_EL0`,
the FP/SIMD file, and the address-space control registers (`SCTLR`/`CPACR`/`MAIR`/
`TCR`/`TTBR0`/`VBAR`). Capturing the control registers, rather than reconstructing
them, keeps `vmm_reentry` entirely inside the backend.

The reentry design is shaped by HVF allowing **one VM per process**: `fork` cannot
just create a second VM, so [src/proc/fork.c](src/proc/fork.c) snapshots the vCPU,
`hv_vm_destroy`s, host `fork`s, and rebuilds the VM on both sides. Rebuilding means
replaying every stage-2 mapping into the fresh VM — the guest's host pages survive
by COW, but the IPA→host associations are VM state and are lost. A granule-keyed
registry in [lib/vmm_arm64.c](lib/vmm_arm64.c), fed by every `map`/`unmap_stage2`,
records them for replay. The in-process `test_arm64_reentry` isolates this rebuild
(no host fork, so no COW variable) as the load-bearing check; `forktest` covers the
real thing end to end.

`clone`'s aarch64 argument order (CONFIG_CLONE_BACKWARDS) swaps `child_tid`/`tls`
versus x86-64, normalized at the syscall entry in fork.c. This is not only a
threads concern: glibc's `fork()` issues `clone` with `CLONE_CHILD_SETTID |
CLONE_CHILD_CLEARTID` and a real `child_tid`, so the wrong order writes the tid to
the tls value and misroutes tls (covered by the `clonetid` smoke binary).

**Milestone (met for fork):** `test_arm64_reentry`, `forktest` and `clonetid`
pass. Threaded `clone` (a second live vCPU) and a multi-vCPU snapshot remain.

### Phase 5 — dynamic linking and rootfs

arm64 rootfs (§3.7); get `ld-linux-aarch64.so.1` working; then bash.

**Milestone:** the README's `$ noah` → interactive bash.

### Phase 6 — test suite

Port [test/include/noah.S](test/include/noah.S) and the assertion tests to
aarch64. Retarget [test/misc/xmm0.s](test/misc/xmm0.s) to FPSIMD or drop it.

---

## 5. Platform prerequisites

1. **Entitlement.** HVF on Apple Silicon requires `com.apple.security.hypervisor`
   and a valid code signature — unlike Intel, where an unsigned binary could call
   `hv_vm_create`. This must be wired into the build in Phase 2, and it affects the
   Homebrew/MacPorts formulae.

2. **`arm64e` specifically is not a shippable target.** The arm64e ABI (pointer
   authentication) is reserved for platform binaries; third-party arm64e userland
   binaries are not supported for distribution and the ABI is explicitly unstable.
   **This plan targets plain `arm64`,** which is what runs on your M5. If you
   specifically need arm64e for a kernel-adjacent reason, say so — it changes the
   signing and distribution story substantially.

3. **`check_platform_version`** ([src/main.c:614](src/main.c#L614)) already checks
   `kern.hv_support`, which is correct on both architectures. The `MACOS_PRE_16`
   guard in [CMakeLists.txt:9](CMakeLists.txt#L9) is dead on Apple Silicon.

---

## 6. Honest assessment

This is a large project. Phases 0–2 are the hard, uncertain part — everything after
is substantial but well-understood work. The upstream project is unmaintained and
last targeted macOS Sierra, so expect unrelated bitrot against macOS 26 on top of
the porting work itself. (That prediction held: the tree did not compile at all
under clang 21 / macOS 26 before the port started.)

Phase 0 was the single most valuable step and it has been done. The design is
validated on hardware, which removes the project's largest unknown.

---

## 7. The x86 build is a reference, not a test

Phase 1 was specified as "no behaviour change, verifiable against the x86 suite."
That verification did not happen and, on Apple Silicon, cannot: `hv_vm_create()`
returns `HV_UNSUPPORTED` under Rosetta (§4, Phase 1). The x86 suite needs real
Intel hardware.

**What this means for the decision to keep both architectures.** That decision was
taken on the rationale that the x86 build is "the only regression baseline the
port has." Half of that rationale is now gone: it is a *compile* baseline and a
*reference implementation*, but not a runnable test. The other half stands, and it
is the important half — x86 is the only complete, working description of what each
syscall path is supposed to do, and the arm64 code is being written by reading it.

**What the residual risk actually is.** A Phase 1 regression in the x86 build harms
nobody directly, because nobody can execute that build. The risk is indirect and
worth naming precisely: if the refactor changed x86 *semantics*, and someone later
reads the x86 path as the specification for the arm64 path, the change propagates
into code that does run. That is the reason the Phase 1 audit was done
case-by-case against the original rather than by eyeballing the diff, and the
reason the two deviations it found are documented in the commit rather than
quietly folded in.

**What was actually verified in Phase 1:** that it compiles warning-free in both
build modes; that every vmexit reason and exception vector the original handled is
still handled; that `main_loop` and `handle_syscall` contain no architecture-
specific references; and that the binary starts. Not verified: that a single guest
instruction still executes correctly.

Anyone who acquires an Intel Mac should run `make check` against the Phase 1 commit
before trusting the x86 path as a specification.

### 3.5.56 Linux namespaces — **UTS implemented, the rest refused honestly**

`unshare`, `setns`, `sethostname`, `setdomainname` and `/proc/<pid>/ns/` did not
exist; `unshare` and `setns` were ENOSYS, and `sethostname` was simply absent, so
a guest could not rename itself at all.

**macOS has no namespaces of any kind.** Nothing here can be delegated to the
host — a namespace is emulated in NABI's own bookkeeping or it does not exist.
That is the position credentials are already in (`struct cred`) and file
ownership (`msl.nabi.owner`), and it has the same consequence: what can be
emulated must be emulated *completely*, and what cannot must **say so** rather
than pretend. They differ enormously in how far they can be taken:

| | |
|---|---|
| **uts** | **Fully.** A hostname and a domainname per namespace, and NABI already answers `uname`. Implemented. |
| **ipc** | Reachable. SysV semaphores and shared memory are NABI's own (`src/ipc/`), so their keys could be scoped. |
| **time** | Reachable. An offset on `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`, both already translated. |
| **user** | Reachable, and the largest of these: credentials are already software, so what is missing is `uid_map`/`gid_map` and a capability model. |
| **pid** | Large. Guest pids *are* host pids — `getpid`, `kill`, `wait4`, signals, `/proc` and the fork checkpoint all use them directly. |
| **mnt** | Little to isolate yet. There is no mount table, only a rootfs and passthrough prefixes; this waits on `mount(2)`. |
| **cgroup** | Nothing to isolate. There are no cgroups. |
| **net** | No. Sockets are the host's; isolating them means a virtual network stack, not a namespace. |

So `unshare` and `setns` accept `CLONE_NEWUTS` and refuse the rest with
**EINVAL** — exactly what Linux returns for a namespace its kernel was not built
with, so every caller already handles it. `unshare -n` reports "unshare failed:
Invalid argument" rather than appearing to work.

Doing half of the pid namespace would be **worse than none**: a container init
told it is pid 1 while signals and waits use another number is a bug that
surfaces very far from where it was introduced.

Every type still gets a `/proc/<pid>/ns/` entry, because Linux always has them
and software reads them to *compare* namespaces far more often than to change
them. The unsupported ones report the initial namespace, which is the truth —
every guest is in it. The inodes start at Linux's own `4026531835`; the values
are opaque, but they are compared, and numbers unlike every other Linux would be
their own kind of lie.

Two bugs, both from the same root — **arm64's fork is fork plus exec**:

- **The namespace contents were a per-process copy.** `unshare -u sh -c
  'hostname box; hostname'` printed the old name: `hostname` set it in one
  rebuilt process and `hostname` read it in another. A namespace is *shared
  state between processes*, which is the entire point of it, so the contents now
  live in a file keyed by inode, and the processes hold only the identity.
  The filename carries the boot session id too — a hostname should outlive the
  process that set it but not the machine.
- **`nsproxy_restore` clobbered the parent's namespace.** It built the restored
  namespace with `ns_new`, which allocates a *fresh* identity from a counter
  that starts at the same value in every rebuilt process — so a child restoring
  its parent's namespace was handed the number the parent already had, and wrote
  the initial hostname over the parent's file before relabelling itself. Every
  fork silently reset the hostname. The restored namespace is now built by hand
  and never stores.

`test/arch/smoke/nstest.c` covers the refusals (including that a partly-refused
combined `unshare` moves *nothing*), `setns` onto the current namespace, and the
identity as well as the hostname surviving a fork. End to end under Debian:

```
fresh start:    redstar
  inside:       inside-box
outside after:  redstar
```

### 3.5.57 The IPC namespace, and the tables it needed underneath — **implemented**

`unshare(CLONE_NEWIPC)` now works, and `ipcs` inside one shows an empty list
next to a populated one outside. Getting there meant implementing System V IPC,
because what was here could not be namespaced and, as it turned out, did not
work either.

**What was actually there.** `shmget` mapped `IPC_CREAT` and `IPC_EXCL` into
Darwin's flags and dropped the permission bits on the floor, so every segment
was created mode 0 and every `shmat` on it returned **EACCES**. `semctl`
returned ENOSYS for *every* command, including the `SETVAL` that initialises an
array and the `IPC_RMID` that removes it. `shmdt` did not exist. `semop` read
the guest's operations with `copy_from_user(&l_tsops, ...)` — the address of the
pointer rather than the array — so it overwrote its own pointer with guest data
and then freed that. None of this can have been exercised.

**Why the objects could not stay Darwin's.** Four reasons, the first of which is
the namespace and any one of which is sufficient:

- They are the *host Mac's* tables, shared with macOS itself and every other
  guest. There is no key space to scope, so there is no isolation to be had.
- Darwin allows **32 shared segments for the whole machine**
  (`kern.sysv.shmmni`), 8 attachments per process, and 4MB each. Linux's
  defaults are 4096 and effectively unbounded.
- Anything a guest left behind stayed in those 32 slots until the Mac rebooted.
  A guest leak was a host problem.
- **A Darwin attachment could not survive nabi's fork — it panicked.** Verified,
  not inferred: with the mode-bits bug patched so that `shmat` could succeed at
  all, attaching a segment and then forking gives

  ```
  !!PANIC!!  region 0xc0000000 is neither arena-backed nor file-backed
      panic → checkpoint_restore → resume_main
  ```

  A resumed child rebuilds its address space from the checkpoint: arena-backed
  regions are copied, file-backed ones re-mapped from their descriptor, and a
  `shmat` region is neither. So the ordinary way to use shared memory — attach,
  then fork — killed the child.

**So a segment is a file and a namespace is a directory of them.** That one
change settles isolation (different directory, no shared key space), capacity
(the filesystem's limits, not Darwin's 32), fork (a file-backed mapping is
precisely what the checkpoint already knows how to rebuild), and destruction:
`IPC_RMID` unlinks, and an unlinked file's existing mappings stay valid, which
*is* Linux's rule that a removed segment lives until the last attachment goes.
The rule came for free rather than being implemented.

Ids are allocated by `O_EXCL` on the meta file — whoever creates it owns that
id, and a race cannot have two winners. Keys are symlinks into the same
directory, so a key lookup is a `readlink`.

**Semaphores keep Darwin's arrays underneath**, and the asymmetry is deliberate:
`semmni` is 87381 rather than 32, and Darwin's `semop` already has the two hard
parts right — blocking until a whole set of operations can be applied at once,
and undoing a dead process's `SEM_UNDO` adjustments. Reimplementing a
cross-process wait queue to arrive back at the same behaviour would be the worse
trade. What they take from the namespace is scoping: the Darwin key is *derived*
from the namespace and the id rather than agreed on, so every process computes
the same number and there is nothing to coordinate.

**Attachments travel on the region, not beside it.** `struct mm_region` gained
`shm_id`, and the checkpoint carries it (version 4 → 5). A `shmat` produces
exactly one region, so the region list already *is* the list of attachments —
there is no second table to drift out of step, and a forked child can detach
what it inherited, which Linux allows.

**`/proc/sysvipc` had to move too.** mSL/ProcFS provides those files, filled
from the host Mac's tables — which is where these objects used to live and no
longer do. So `ipcs` opened `/proc/sysvipc/shm`, parsed it, found nothing, and
never fell back to `shmctl(SHM_STAT)`: an empty listing beside a segment the
guest had just made, with nothing appearing to be wrong. nabi answers those
three files now, from the namespace the caller is in.

Message queues are still absent — `msgget` is unimplemented and in neither
syscall table — so they need no isolating yet. Worth stating rather than leaving
to be noticed: the guarantee holds only while they stay absent.

End to end under Debian, with its own tooling:

```
=== initial namespace ===
key        shmid  owner  perms  bytes  nattch
0xbb5b6322 0      root   644    65536  0
=== inside unshare -i ===
(nothing)      … then after ipcmk -M 4096 here:
0xdd8f50d9 0      root   644    4096   0
=== back outside ===
0xbb5b6322 0      root   644    65536  0
```

and the host's own tables come back to where they started — a guest's
`ipcrm` releases the Darwin array behind a semaphore, and a namespace that ends
releases every one it held.

### 3.5.58 System V message queues — **implemented**

`msgget`, `msgsnd`, `msgrcv` and `msgctl` did not exist and were in neither
syscall table. This closes the hole §3.5.57 left open and was explicit about:
message queues needed no isolating while they did not exist, and that guarantee
held only for as long as they did not.

**A queue is a file, like a segment and unlike a semaphore.** Darwin does have
message queues, and they were never a candidate: **40 queues for the whole
machine, 40 messages in the system at once, and 2048 bytes per queue**, in
tables shared with the host and every other guest. Linux's defaults are 32000
queues of 16KiB. That is the shared-memory situation again, not the semaphore
one — semaphores could stay Darwin's because `semmni` is 87381 and its `semop`
already blocks correctly.

The queue's bytes are held under **`flock`** while they change, rather than
behind a semaphore. Two reasons, and the second is the one that decided it: a
lock needs no initialising, so there is no window in which one process has
published a queue whose lock another cannot yet take; and the kernel drops an
`flock` when the holder dies. A lock that must be released by the process
holding it wedges the queue for everyone the first time a guest is killed at the
wrong moment.

**A receiver with nothing to receive polls, on a backoff to a few
milliseconds.** This is the one deliberate approximation and it is worth being
plain about. There is no cross-process wait primitive here that survives a
participant dying: macOS has no futex, and a counting semaphore used as a wakeup
loses its token if the sender dies between appending the message and posting
it — which strands the receiver forever. A short delay is the better failure,
and much the easier one to see. Polling also makes the two conditions Linux
specifies fall out for free, since both are things the next look notices: a
signal is EINTR, and the queue being removed underneath is EIDRM.

The record layout compacts from the front and resets the file whenever the last
message leaves, so a queue that drains does not grow however long it runs. A
message taken from the middle by a type-selective receive is marked dead and
skipped.

`/proc/sysvipc/msg` is answered from these tables, as `shm` and `sem` already
were.

The smoke test covers the ordering rules — a type asked for by number, a
negative type meaning the lowest at or below it, otherwise first in first out —
`E2BIG` and `MSG_NOERROR`, and a receive that **blocks on a message the forked
child has not sent yet**. That last one is the point: the parent waits before
reaping rather than after, so the wait path is genuinely taken. A version that
only ever returned what was already queued would pass every ordering test above
it and hang there.

Under Debian, with its own tooling:

```
=== initial namespace ===
key        msqid  owner  perms  used-bytes  messages
0x211e9dbb 0      root   644    0           0
0xf12e3aea 1      root   644    0           0
=== inside unshare -i ===
(nothing)
=== back outside ===
0x211e9dbb 0      root   644    0           0
0xf12e3aea 1      root   644    0           0
```

That leaves `semtimedop` as the last of the family; §3.5.59 has it.

### 3.5.59 `semtimedop` — **implemented**

The last of the System V family. arm64 192 and x86-64 220 were both
`unimplemented`, so glibc's `sem_timedwait` over a SysV array, and every
"acquire this or give up after N milliseconds" loop, got ENOSYS.

**Darwin has no timed semaphore wait of any kind** - no `semtimedop`, and no
timed variant of `semop` - so there is nothing to hand a deadline to. The
operations are retried with `IPC_NOWAIT` until they take or the deadline passes.

**Atomicity survives that, and it is the part that would have mattered.** A
`semop` carrying `IPC_NOWAIT` either applies the whole set or applies none of it
and returns EAGAIN, so polling it can never leave a caller half applied - which
would be the worst possible outcome here, because the array would be left in a
state nobody asked for and nothing would report it. The test checks exactly
that: a two-operation set whose first could proceed alone and whose second could
not must leave *both* values untouched.

**What does not survive is the wait queue.** A waiter that polls takes its turn
whenever it next looks rather than in the order it arrived, so under contention
a later arrival can go first. This is confined to the timed form: a plain
`semop` with no timeout still goes straight to Darwin's `semop` and blocks
there, keeping its queue, its ordering and the `SEM_UNDO` owed to a process that
dies mid-adjustment. Splitting it this way keeps the approximation off the path
almost everything actually uses.

A null timeout is `semop` exactly, and takes the real-wait path rather than the
polling one.

The deadline is measured against **CLOCK_MONOTONIC**, so setting the wall clock
cannot lengthen or cut short a wait.

While here, `semop` learned to distinguish **EIDRM** from EINVAL. Darwin returns
EINVAL both for an id that never existed and for one whose array has been
removed; Linux owes EIDRM to a caller whose semaphore is removed underneath it,
and the meta file records removal, so that is now a question this side can
answer.

The test covers a `semtimedop` that need not wait, one that must wait its whole
timeout and then return EAGAIN (checked against the clock, so a version that
returned immediately would fail), the atomicity case above, and a null timeout.

### 3.5.60 The time namespace — **implemented**

`CLONE_NEWTIME` was refused with EINVAL. It is supported now: offsets on
`CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`, set through `/proc/<pid>/timens_offsets`
and inherited by children, which is what a time namespace is and all it is.

**It behaves unlike every other namespace, and that is the whole of the
difficulty.** `unshare(CLONE_NEWTIME)` does **not** move the caller into the new
namespace. Every other `CLONE_NEW*` takes effect on the process that asked; this
one cannot, because shifting a running process's `CLOCK_MONOTONIC` is a
monotonic clock jumping, which is the one thing it promises never to do. So the
new namespace is held aside for children and `/proc/self/ns/time` goes on naming
the old one. That is why Linux has a `time_for_children` link at all, and an
implementation that assumed unshare moves the caller would read the same inode
from both and never notice it was wrong.

`nsproxy` therefore gained `time_for_children`, and `/proc/<pid>/ns` gained both
`time_for_children` and `pid_for_children` — the second because Linux lists it
and software walking the directory expects the full set; with no pid namespaces
to be in, it names the one everybody is in. The directory now has all ten links
Linux has.

**`clone(CLONE_NEWTIME)` is EINVAL**, which is Linux's rule and not a limitation
here: the flag is `0x80`, which lands inside the exit-signal byte that clone's
low bits carry, so the two cannot be told apart. It is reachable through
`unshare`, which has no such byte.

`CLOCK_REALTIME` is deliberately untouched, as on Linux. A guest that disagreed
with the host about the wall clock would disagree with every file timestamp and
every peer it spoke to; what the namespace exists for is the monotonic family.
`clock_nanosleep` with `TIMER_ABSTIME` reads "now" through the same offset, or
the interval would come out wrong by exactly the offset and the sleep would
overshoot or return at once depending on the sign.

Offsets freeze once a process is actually in the namespace — at the fork, not at
the unshare — which is the widest correct window: the parent may keep adjusting
them until a child arrives, and after that a change would move a running
process's clock.

**Two bugs found, both in the write path, and both silent.**
`/proc/<pid>/timens_offsets` is the only way to set offsets, and it is served
here as a temporary file holding the current text, so a write had to be diverted
to the namespace itself. The note saying "this descriptor is really the
namespace" is keyed by descriptor number:

- **A dup left the note behind.** `echo x > /proc/self/timens_offsets` opens the
  file, `dup2`s it onto stdout and closes the original, so the write arrived on
  a descriptor with no note and landed in the stand-in file. The shell reported
  success and nothing had happened.
- **Then it leaked the other way.** With `dup` carrying the note across, a shell
  redirect *ends* by dup2ing the saved stdout back over descriptor 1 — and the
  note stayed there, so every later `echo` in that shell was diverted into the
  offset parser and failed. The first write worked and the session broke
  afterwards. A dup has to clear the destination's note before copying, because
  whatever the destination used to be, it is not that any more.

A third, smaller one: a shell splits `echo x > file` into more than one write and
the trailing newline can arrive alone, so an all-whitespace write must be a
no-op rather than EINVAL — otherwise a redirect that had already taken effect
reported an I/O error afterwards.

Under Debian:

```
initial namespace:  echo ... > /proc/self/timens_offsets
                    bash: echo: write error: Operation not permitted
after unshare -T:   write ok
                    monotonic        1234         5
                    boottime            0         0
```

and in the smoke test, a child of a namespace with `monotonic 3600` /
`boottime 7200` reports both shifted by exactly that, with `CLOCK_REALTIME`
unmoved.

What is not offset: `/proc/uptime` and `sysinfo`, which come from mSL/ProcFS and
the host's `kern.boottime` respectively. Linux does virtualise both.

### 3.5.61 The user namespace — **implemented as an identity, not an authority**

`CLONE_NEWUSER` was refused. It works now: `uid_map`, `gid_map` and `setgroups`
under `/proc/<pid>/`, translating at the syscall boundary, so `unshare -Ur`
gives a guest root inside its own namespace and files owned by ids the map does
not cover read back as nobody — which is what a rootless container looks like.

**The design decision is where the translation lives, and it is the whole of the
safety argument.** `struct cred` is *not* rewritten. It goes on holding the ids
the process really has, and only what crosses to the guest is mapped. So a
process that maps itself to uid 0 inside is still, to every check NABI makes,
the unprivileged process it started as. It gains the appearance of root and none
of the reach.

That matters because NABI has no capability model, and the obvious
implementation — rewrite the credentials so the process *is* uid 0 — would have
handed it every `euid == 0` fast path in the tree: the SysV ownership checks, the
guest-mode xattr overlay, setuid exec. An unprivileged guest could have unshared
a user namespace and become real root over everything the host account can
reach, which is far more than Linux would ever grant. Translating at the
boundary gives Linux's containment without anything having to enforce it.

**The cost is real and worth stating plainly.** On Linux, root in a user
namespace genuinely may act on ids mapped into it. Here it may not, because the
check that would allow it looks at credentials that never changed. Programs that
ask "am I root" and proceed will work; programs that then rely on the authority
are refused as the unprivileged process they actually are. That is a smaller
lie than the alternative, and it fails closed.

The map rules are Linux's: written once, and an unprivileged writer may map only
the single id it already has — anything else would let a guest rename itself
into somebody else's files, since file ownership is translated through the same
map. `setgroups` must be denied before an unprivileged `gid_map`.

**Two bugs, both found by the feature rather than by the tests.**

- **A dup carried a note's key but not its value.** The writable-`/proc`-file
  mechanism from §3.5.60 became a map when a second kind of file needed it, and
  `procfs_dup_fd` still copied only the key. Every `echo ... > /proc/self/uid_map`
  therefore arrived at the *time* namespace's parser, which refused it — a shell
  redirect dup2s, so this was every write anyone would actually make.

- **`statx` translated an id that had already been translated.** `st` there is an
  `l_newstat` the filesystem path has already put through `host_uid_to_guest`,
  the ownership overlay and now the user namespace, and `statx` converted it a
  second time. This was invisible for as long as the conversion was its own
  inverse for everything but one account; with a map in the way it stopped
  being, and every file inside a user namespace read back as nobody. The fix is
  to make `st` uniformly guest-side — the `procfs_stat` branch that fed it a raw
  host euid now converts on the way in — and take it as it is.

Under Debian, with a file owned outside by root and another by an unmapped id:

```
outside: fresh=0 other=1000
inside:  uid=100 fresh=100 other=65534      (map: 100 0 1)
outside: fresh=0
```

and `unshare -U` before any map is written reports uid 65534, as Linux does.

That leaves `mnt`, `pid` and `cgroup`. `mnt` waits on `mount(2)` — there is no
mount table yet to isolate. `pid` remains the large one: guest pids are host
pids throughout. `cgroup` has nothing to isolate.

### 3.5.62 The mount namespace, and the `mount(2)` it was waiting for — **implemented**

`CLONE_NEWNS` was refused, and rightly: there was nothing to isolate. NABI had a
rootfs and a **compile-time** list of host prefixes that are passed through —
a policy, not a table. Nothing could be added to it or removed, and `mount(2)`
and `umount2(2)` were unimplemented and in neither syscall table. So this
namespace needed the thing it namespaces built first.

**A bind mount is the one that matters, and it costs almost nothing.** It is a
rewrite of one path prefix to another — which is exactly what `resolve_path`
already does at its `/* resolve mountpoints */` step when it chooses between the
rootfs and a passthrough. So a bind is a table entry consulted at that same
point, and needs nothing from Darwin at all. `MS_REC` changes nothing, because a
prefix rewrite is recursive by construction.

What a mount can be is decided by what the host can provide:

| | |
|---|---|
| **bind** | Fully, including read-only. The source is resolved once, at mount time, to the host object it names — a bind binds the object, not the name. |
| **tmpfs** | A directory under TMPDIR, removed on unmount, which is the property anything mounting one relies on. |
| **proc, sysfs, devtmpfs, devpts, cgroup…** | Accepted and recorded. NABI already serves these, so the mount asks for something already true — but recording it is not a formality: a container that mounts `/proc` and then cannot find it in `/proc/mounts` concludes the mount failed. |
| **anything else** | ENODEV. There is no block device layer here to mount on. |

**`MS_RDONLY` is honoured, not recorded.** A read-only mount that quietly
accepted writes would be worse than one that refused to exist, since the only
reason to ask for one is to be certain. The check is stated once, in a
`vfs_grab_dir_w` used by every operation that modifies a file or directory, so
an operation that forgot would be a read-only mount that was not — the failure
mode worth designing against.

`/proc/mounts` was a fixed five-line string; it and the new `/proc/self/mountinfo`
are built from the table now. A fixed string could only ever describe the day it
was written, never a mount the guest had made.

**Mounting needs guest root, and a user namespace does not confer it.** That
follows from what §3.5.61 made the user namespace — an identity, not an
authority — and it fails closed: `unshare -Ur -m` gets its namespace and is then
refused the mounts, rather than being handed authority over the host that
nothing downstream would check.

One bug, and an ordinary one: `guest_to_host_path` returns 0 on success and a
negative errno on failure, and the first cut tested it as a boolean — so every
bind mount failed with ENOENT precisely when the source resolved correctly.

Under Debian:

```
outside before: 5 mounts, ns=mnt:[4026531835]
  inside ns=mnt:[4026531843]
  mounted inside            inside sees: hello
  tmpfs mounted             tmpfs holds: tmpdata
  inside mounts: 7
outside after:  5 mounts
outside sees /mnt/a/file: No such file or directory
```

and read-only, in the same session:

```
  write: /bin/bash: /mnt/ro/new: Read-only file system
  mkdir: cannot create directory '/mnt/ro/d': Read-only file system
```

That leaves `pid` and `cgroup`. `pid` is the large one — guest pids are host
pids throughout `getpid`, `kill`, `wait4`, signals, `/proc` and the fork
checkpoint. `cgroup` has nothing to isolate.

### 3.5.63 The pid namespace — **renumbering, which is most of it; not concealment, which is not available**

`CLONE_NEWPID` was refused, and the note in `namespace.h` called it the large
one: guest pids *are* host pids throughout `getpid`, `kill`, `wait4`, signals,
`/proc` and the fork checkpoint. It warned that half of it would be worse than
none — "an init told it is pid 1 while signals and waits use another number is a
bug that surfaces far from here". That specific hazard is what this had to
avoid, and does.

**What makes it tractable is that the initial namespace is the identity.** A
process that never unshares gets its host pid back from every translation on the
first line, and nothing about it changes. The entire blast radius of this change
is processes that asked for a namespace — which is why an ordinary session still
reports real host pids and forks and waits exactly as before.

The translation is applied at every boundary together: `getpid`, `getppid`,
`gettid`, `getpgrp`, `getpgid`, `getsid`, `setpgid`, `setsid`, `kill`, `tkill`,
`tgkill`, `wait4` (both its argument and its result), `clone`'s return, and
`/proc/<pid>`. A child is registered **by its parent**, the moment `fork`
returns its host pid, rather than by itself when it resumes — `clone` has to
return the child's pid in the parent's namespace, and a child registering itself
might not have got there yet. Registering from the side that already has the
number removes the race instead of narrowing it.

`unshare(CLONE_NEWPID)` does not move the caller, exactly as `CLONE_NEWTIME`
does not: a process can no more be renumbered underneath itself than its clock
can be moved. So `pid_for_children` becomes real, and the link that §3.5.60
added as a placeholder now carries something.

**The boundary, stated plainly, because it is the whole of what this is not:**

- **It does not conceal.** `/proc` is mSL/ProcFS's passthrough of the host's, so
  a guest already sees all ~450 host processes and goes on doing so inside a pid
  namespace. Renumbering is real; hiding is not ours to do from here. What *is*
  contained is reach: a pid that is not a member does not translate, so `kill`
  gets ESRCH and `/proc/<that pid>` gets ENOENT.
- **There is no init.** Linux reparents orphans to pid 1 of their namespace and
  destroys the namespace when that process exits. Both are supervisor
  behaviour and NABI has no supervisor — the host reparents orphans to launchd.
  A container whose init exits here leaves its children running.

`/proc/<pid>/stat` and `/status` had to be taken over inside a namespace, and
this was the interesting part. Left to the host they report host pids, so a
process would be told it is pid 1 by `getpid` and its host pid by `/proc/self/stat`
— the contradiction the old note warned about, arriving by a different door.
They are now served for **any member** of the namespace, with only the pid
fields rewritten: the host's line is taken and pid, ppid, pgrp and session are
translated, leaving the other 48 fields exactly as true as they were. `/proc/1`
resolves to the container's init rather than to launchd.

```
=== outside (unchanged) ===
  getpid            = 86244
=== inside ===
  getpid            = 1
  /proc/1/stat      = 1 (nabi) 0     (pid comm ppid; 0 = parent outside)
  /proc/1/status    Pid:  1
  /proc/99999/stat  = No such file or directory
```

That leaves `cgroup`, which has nothing to isolate: there are no cgroups.

### 3.5.64 The cgroup namespace, over a hierarchy that controls nothing — **implemented**

Every previous note said the same thing about this one: "nothing to isolate;
there are no cgroups". That was true — `/proc/self/cgroup`, `/sys/fs/cgroup` and
`/proc/cgroups` were all absent — so the namespace needed a hierarchy first, as
the mount namespace needed `mount(2)` and the IPC namespace needed objects of
its own.

**What is provided and what deliberately is not.** The hierarchy is real:
cgroups are directories, a process is in exactly one, membership is inherited
across fork, and `/proc/<pid>/cgroup` answers with it. That is bookkeeping NABI
can keep honestly.

The controllers are not, and there are none. `cgroup.controllers` is empty and
cannot be made otherwise, so there is no `memory.max`, no `cpu.max`, no
`pids.max` — **not as files that accept a number and ignore it, but absent.**
Darwin gives an unprivileged process no CPU bandwidth control, no memory
accounting it could enforce and no io control, so a limit written here could
never be applied. A cgroup that took the number and did nothing would be the
worst thing in this tree: the caller would believe it was bounded and nothing
would ever say otherwise.

A hierarchy with no controllers enabled is an ordinary cgroup v2 configuration,
not an invention — it is what a machine looks like when cgroups organise
processes rather than constrain them, which is exactly and only what this can
do.

The namespace itself is then **exact**: it rebases paths, which is the whole of
what a cgroup namespace does on Linux, and none of it needs a controller.

```
after joining:  0::/work        <- read by a child, so inherited across fork
inside unshare -C:  0::/        <- rebased; the process has not moved
outside still:  0::/work
```

Membership travels in the checkpoint (version 5 → 6). A child that did not
inherit it would fall back to the root the moment it forked, and a shell that
had just joined a cgroup would find every command it ran outside it, with
nothing to indicate the move had not stuck.

**Two bugs, both about a path not being the path it looked like.**

- `guest_to_host_path` answered from its passthrough shortcut before consulting
  the mount table, so a cgroup made under `/sys/fs/cgroup` — a mount on top of a
  passthrough — resolved to the host's `/sys` and was not recognised as a cgroup
  at all. It now checks mounts first, as `resolve_path` already did.

- **`F_GETPATH` is canonical and `TMPDIR` is not.** A write to `cgroup.procs` is
  recognised by the file's path, and `TMPDIR` is `/var/folders/…` while `/var`
  is a symlink, so the descriptor's real path is `/private/var/folders/…`.
  Compared against the unresolved form nothing ever matched: joining a cgroup
  wrote the pid into an ordinary file, reported success, and moved no one. The
  hierarchy's root is resolved with `realpath` now.

One deliberate divergence: a mount target need not already exist. Linux requires
it, but the conventional location `/sys/fs/cgroup` lives under a host
passthrough the guest cannot create in, so requiring it would make the standard
path unmountable.

**That completes seven of the eight namespaces.** Only `net` stays refused, and
not for want of effort: sockets are the host's, and isolating them would mean
writing a virtual network stack — addresses, routes, an interface, something to
carry packets between namespaces. That is a different program, not a namespace.

### 3.5.65 The network namespace, as an empty one — **implemented**

Every note in this series refused this namespace, and the reasoning held for
what it addressed: making sockets *work* inside a namespace of their own means a
virtual network stack — addresses, routes, an interface, something to carry
packets between namespaces — which is a different program. None of that is here
and none of it is coming.

**But a network namespace on Linux does not start with a working network.** It
starts with a loopback interface that is *down*, no addresses and no routes, and
nothing in it can reach anything until it is configured. Reaching that state
needs no stack at all — and it is the state `unshare -n` is actually used for,
which is to run something with no network.

So that is what this provides, exactly and permanently: a namespace whose
network is empty. `connect` to an inet address is **ENETUNREACH**, there being
no route; `sendto` likewise; `/proc/net/dev` lists one interface, `lo`, with
zero counters. A socket can still be *created*, because Linux creates one too —
there is simply nowhere for it to go.

**A `bind` is refused rather than allowed, and that is a deliberate
divergence.** Linux lets a process bind the wildcard address in an empty
namespace. Here the socket underneath is a Darwin socket, so binding it would
take a port on the *host* — two namespaces would collide with each other and
with the Mac, which is the opposite of the isolation being asked for. Refusing
with EADDRNOTAVAIL keeps the guarantee; allowing would keep the letter of one
call and break the point of the feature.

**AF_UNIX is untouched.** Pathname sockets belong to the filesystem and are
isolated by the mount namespace, not this one, so they go on working — which is
correct, and is what lets anything inside a network namespace still talk locally
the way it does on Linux.

What is not available is configuring a namespace back into working order:
`ip link set lo up`, a veth pair, an address. That needs netlink and something
behind it, which is where the stack would have to begin. A namespace here is
created empty and stays empty.

```
=== outside ===            dns resolves; /proc/net/dev lists the Mac's utun2, en0…
=== inside unshare -n ===  ns: net:[4026531843]
                           lo   0 0 0 0 …
                           connect: unreachable
```

**That completes all eight namespaces.** The only `CLONE_NEW*` flag any call
still refuses is `CLONE_NEWTIME` in `clone`, and that is Linux's own rule — the
flag lands inside the exit-signal byte `clone` carries — not a gap here. The
smoke test's "a refused flag alongside a workable one moves nothing" check lost
its last refusable flag with this change and now tests the same property through
a failing call instead.

### 3.5.66 Two things that were broken, one of them by me

**`make check` had been failing since §3.5.55, and my own verification hid it.**
`test/arch/test_checkpoint.c` links `checkpoint.c` standalone against a set of
stubs, and the namespaces commit gave `checkpoint.c` two new callers —
`nsproxy_snapshot` and `nsproxy_restore` — which nothing in that link provided.
The cgroup commit added two more. It has been a link error ever since.

I did not see it because I was checking these runs with
`make check-decode check-arm64 | grep -cE '^PASS'` and reading the count, rather
than the exit status. The decode test passed and printed `PASS`; the arm64
target died at the link before printing anything; the count said `1` and I read
that as success. **A test summary is not a substitute for an exit status**, and
counting lines that only appear on success cannot distinguish "the other one
failed" from "the other one never ran".

The stubs are added, and they participate rather than merely satisfying the
linker: the writer is handed distinctive namespace inodes, uts names and a
cgroup path, and the reader's copies are checked against them. Stubs that only
resolved the symbols would have kept the test building while saying nothing
about the fields — which is the shape of the original problem, not a fix for it.

**`tcsetattr` returned EINTR to the guest.** `apt-get install` ended with

```
Error: Setting in Stop via TCSAFLUSH for stdin failed! - tcsetattr (4: Interrupted system call)
```

which is APT restoring the terminal after dpkg. This is the same fault
§3.5.x fixed for `read` and `write` and in the same place: NABI's own machinery
takes signals — a child it reaped, a timer — and a host EINTR raised by one of
those describes an interruption the guest cannot see and never asked about.
`read` and `write` already hid it through `RETRY_ON_RESTARTABLE_EINTR`; the
terminal ioctls did not, so they handed it straight to the caller.

Every host call in `darwinfs_ioctl` retries now. What makes that safe rather
than a blanket retry is `sigrestart_wanted`: an EINTR raised while the guest
genuinely has a signal pending is still the guest's, and is still reported. The
same install now runs to `Processing triggers for libc-bin` with no complaint
from any of the ~250 processes involved.

### 3.5.67 `MS_MOVE` — **implemented**

§3.5.62 listed `MS_MOVE` with the refusals, alongside overlay and real
filesystems. It does not belong there: those need something NABI has not got,
and this needs nothing at all.

A mount here is a prefix rewrite consulted during path resolution, so **moving
one is changing the prefix it answers to**. The host object it resolved to when
it was mounted is not consulted again — which is why a move cannot fail the way
a fresh mount might, and why nothing is unmounted or mounted in the course of
one.

**The subtree moves as a subtree.** Everything at or below the source is
rebased, not just the entry named. A flat table would otherwise leave a mount on
`/a/b` pointing at a path that had just been uncovered, while Linux carries it
to `/c/b`; carrying the children is the only reading under which the mounts
inside a moved one survive.

Refused, as Linux refuses them: a source that is not a mount point, and a
destination inside the mount's own subtree — the latter because a mount
containing its own mount point cannot be resolved at all, the longest match
being the mount whose path now runs through itself.

```
bound at /a: hello
a nested mount at /a/sub: deep
--- moving /a to /c ---
  /c/file:      hello
  /c/sub/inner: deep          <- the nested mount came too
  /a/file:      No such file or directory
    /src     /c     none rw 0 0
    /src/sub /c/sub none rw 0 0
```

### 3.5.68 Mount propagation — **implemented**

§3.5.62 accepted `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` and `MS_UNBINDABLE` and
did nothing with them, on the argument that a namespace's table is a copy taken
at unshare, so there was no propagation to configure. That argument was true of
the implementation and wrong about the feature: propagation is precisely the
thing that makes a namespace's mounts *not* a private copy, and a mount reported
as shared that does not propagate is the silent lie this port keeps refusing.

**Peers are entries in different tables carrying the same group number.** A
namespace's mounts are a table in a file, so propagating an event means writing
it into every table that has a member of the parent mount's group. The group
counter is shared across namespaces — two namespaces handing out group 1 for
unrelated mounts would make them propagate to each other.

**The inheritance rule at unshare is where propagation is actually decided.** A
shared mount keeps its group, so the copy and the original are peers and events
travel between them; that is the part `unshare -m` does *not* isolate, and why
every container recipe begins by making things private. A slave keeps listening
to its master. A private or unbindable mount has no relationship to keep.

All four types are honoured rather than recorded:

| | |
|---|---|
| **shared** | events travel both ways with every peer |
| **private** | no relationship in either direction; the default, as on Linux |
| **slave** | receives from its master's group, sends to nobody |
| **unbindable** | private, and **enforced**: refused as the source of a bind, which is what it exists for |

`/proc/self/mountinfo` reports it in the optional fields — `shared:N`,
`master:N`, `unbindable` — because that is the only place anything can read
propagation back. A private mount is written as their absence rather than as a
word, as Linux writes it.

The rootfs may now have an entry of its own even with nothing mounted on it,
because `mount --make-rshared /` is how a machine declares that its mounts
should reach the namespaces made from it — and with no entry for `/` there would
be nothing to record that on, and nothing under it would ever propagate.

Verified across namespaces, which is the only place it can be:

```
=== a child namespace mounts under the SHARED one ===
  parent sees /shared/x/f: payload
=== and under the PRIVATE one ===
  parent sees /priv/x/f:   No such file or directory
=== unmounting in a child propagates too ===
  parent sees /shared/x/f: No such file or directory

  child: 30 1 0:30 / /shared rw master:1 - none none rw   (a slave)
  parent sees /shared/y/f: No such file or directory      (it sent nothing back)
  31 1 0:31 / /nb rw unbindable - none /s1 rw
  mount: /dest: … bad option …                            (refused as a bind source)
```

The smoke test makes the child `unshare` before it mounts, which is the whole
point: a plain fork shares this namespace's table, so without the unshare the
mount arriving in the parent would prove nothing was isolated rather than that
propagation happened.

### 3.5.69 inotify — **implemented over kqueue**

`inotify_init`, `inotify_init1`, `inotify_add_watch` and `inotify_rm_watch` were
in neither syscall table. macOS has no inotify; it has kqueue, which answers a
different question, and the gap between the two questions is the whole of this.

**The shape comes almost free.** The descriptor a guest gets back is the read
end of a pipe, so `read`, `poll`, `select` and `epoll` work on it without
anything else being taught about inotify. A thread per instance waits on a
kqueue and writes `inotify_event` records into the other end. What the guest
then does is ordinary file reading, which is what it is on Linux too.

**Names are the difficulty.** kqueue reports that a *directory* changed and not
what changed in it, while `IN_CREATE` and `IN_DELETE` carry a name and callers
use it. So the listing is remembered and diffed when the directory fires. That
gives the right names and the right events; what it cannot give is the ordering
of two changes inside one notification, or the cookie pairing `IN_MOVED_FROM`
with `IN_MOVED_TO` — a rename inside a watched directory arrives as a delete and
a create, which is also what Linux sends when the two ends are in different
watched directories, so callers already handle it.

File events map exactly: `NOTE_WRITE`/`NOTE_EXTEND` → `IN_MODIFY`, `NOTE_ATTRIB`
→ `IN_ATTRIB`, `NOTE_RENAME` → `IN_MOVE_SELF`, `NOTE_DELETE` → `IN_DELETE_SELF`
followed by `IN_IGNORED`, as Linux orders them. A full pipe becomes
`IN_Q_OVERFLOW` rather than events quietly dropped.

**What `IN_CLOSE_WRITE` cost, and the honest answer.** kqueue has no notion of a
file being opened or closed, so `IN_OPEN` and the two closes are synthesised
from the guest's own calls — and only within the process holding the instance,
because that is the only process that can reach the pipe. `inotifywait -m -e
close_write /w` then established a watch and reported nothing, because a shell's
`echo x > /w/f` forks and the close happens somewhere with no instance to tell.
A watch that is accepted and never fires is the failure this port keeps refusing
to hand anybody, so these are **not** counted among the events a watch can be
built from: a mask made only of them is EINVAL, and `inotifywait -e close_write`
now says

```
Couldn't watch /w: Invalid argument
```

rather than waiting. A mask that also asks for something real is accepted and
gets the real part. Making them work generally needs the instance reachable by
name rather than by descriptor — a FIFO and a registry of watches — which is a
larger change than the rest of the file and has not been made.

`IN_ACCESS` is not delivered at all: it would mean a hook on every read, for an
event almost nothing waits on.

With `inotify-tools` installed from Debian, unmodified:

```
Setting up watches.
Watches established.
/w/ CREATE one
/w/ CREATE,ISDIR sub
/w/ DELETE one
```

The `open`/`close` hooks ask `inotify_watching()` first, so a guest with no
watches — nearly every guest — pays a load and a branch per close rather than
two `fcntl`s.

### 3.5.70 fanotify — **notification implemented; permission events refused**

`fanotify_init` and `fanotify_mark` were in neither syscall table.

**It fits this host better than inotify did, and is harder somewhere else.**
inotify asks what happened to a *file*, and only Darwin knows, so §3.5.69 had to
derive it from kqueue. fanotify asks what a *process* did — opened, read, wrote,
closed — and for a guest the thing that knows is NABI, which sees every one of
those calls as it makes them. The events are observed directly rather than
inferred, which is more faithful than anything in `inotify.c`.

The difficulty moves to **delivery**. A fanotify listener exists to watch *other*
processes, and NABI's processes are separate host processes: the open happens in
one and the listener sits in another, with no kernel between them. So the marks
live in a file every process maps and the events go down a FIFO named after the
instance. That is the machinery §3.5.69 deferred, and here it is not optional —
a fanotify that saw only its own process would be watching the one process
nobody uses fanotify to watch. The smoke test does the work in a forked child
for exactly that reason: a test that opened the file itself would pass against an
implementation that could never be useful.

**Guests that do not use it pay a load.** The mark table is a shared mapping
with a count at the front, so the question every open, close, read and write
asks — "is anything marked?" — is a memory read rather than a syscall. A guest
that never marks anything never even creates the file.

**Permission events are refused, and that is the one substantive thing
missing.** `FAN_OPEN_PERM` and its relatives block the accessing process until
the listener writes a verdict; a listener that then died would leave every open
in the guest waiting on an answer that was not coming, with nothing in a
position to notice. Linux ships exactly this configuration when
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is off — `FAN_CLASS_CONTENT` and
`FAN_CLASS_PRE_CONTENT` return EINVAL — so a caller that needs them is refused
in a way it already handles, rather than being handed a guard that can wedge the
machine. `FAN_REPORT_FID` and friends are refused too: they change the record
format into one carrying file handles, and a listener given the wrong shape
would parse whatever the bytes happened to be.

One divergence worth naming: the descriptor an event carries is opened by the
*listener's* NABI from the path in the record, rather than passed from the
process that caused the event. Linux guarantees that descriptor refers to the
object as it was; here it is a fresh open of the same name, so an object renamed
in between comes back as whatever holds the name now. For `FAN_OPEN` and the
closes the window is not reachable in practice, and saying so is better than
passing descriptors between processes to close a gap nobody is standing in.

```
fanotify_init -> 4
permission class -> -22          (refused, as Linux without the option does)
fanotify_mark -> 0
a permission mark -> -22
from ANOTHER process: opens=1 modifies=1 closes=1
```

### 3.5.71 fanotify permission events — **implemented**

§3.5.70 refused these and gave a reason: `FAN_OPEN_PERM` stops the process that
opened the file until the listener writes a verdict, so a listener that died
mid-decision would leave every open in the guest waiting for an answer that was
not coming. That objection was about a hazard, not about feasibility, and the
hazard has an answer.

**Linux has the same hazard and handles it in one place**: when the fanotify
descriptor goes — including because the listener died — the kernel releases
everything pending with `FAN_ALLOW`. There is no kernel here to notice, so the
listener's pid is recorded alongside its marks and the waiting process watches
it. A listener that goes away releases the guest, in the same direction Linux
releases it.

A listener that is alive and merely slow is waited for **indefinitely**, exactly
as on Linux. A timeout would be this port inventing a policy, and "allow after a
while" is not a decision a guard would thank us for making on its behalf.

The shape: a request goes down the instance's queue carrying a request id; the
asking process waits on a FIFO of its own named by that id; the listener's
verdict — a `write` to the fanotify descriptor — is routed back to it. That
write has to be recognised, because the descriptor underneath is the queue's own
FIFO and letting it through would put the verdict into the event stream as
though something had reported it.

**Three things this surfaced.**

- **A request that cannot be presented must still be answered.** The event
  record carries a descriptor to the object, so the listener's NABI opens it —
  and an object being *created* does not exist yet, which is exactly what an
  `O_CREAT` open asks permission for. Dropping the event there left the asking
  process waiting for a verdict nobody could send, and it never returned from
  `open`. Nothing was presented, so nothing is denied: it is released.

- **The verdict is taken before the descriptor table is locked.** Asking after
  the open would be asking too late — the file would already be open and a
  denial would have denied nothing — but asking while holding the table's write
  lock would stall every other thread in that process for as long as the
  listener took. The path is resolved without opening anything instead.

- **A listener is never asked about its own access.** On Linux that is a
  listener's own footgun to avoid; here it would be a deadlock against itself
  with the answer in the same thread.

The smoke test denies an open made by *another* process and insists the open
actually fails — a guard that reported the open after allowing it would pass a
notification test and be worthless — and then kills a listener mid-guard and
insists the next open still returns. Without the liveness check that last open
never comes back, and a guest that ran a guard once could not open a file again.

```
fanotify_init(FAN_CLASS_CONTENT) -> 5
FAN_OPEN_PERM on a notification instance -> -22
denied open in another process -> child exited 7 (open failed)
listener killed mid-guard; next open -> 4 (released, not hung)
```

### 3.5.72 `FAN_REPORT_FID`, and the file handles under it — **implemented**

§3.5.70 refused `FAN_REPORT_FID` because it changes the record format, and a
listener given the wrong shape parses whatever the bytes happen to be. That was
a reason to implement it carefully, not a reason to leave it out.

**A handle is only worth reporting if it can be resolved**, so
`name_to_handle_at` and `open_by_handle_at` came first. They were ENOSYS, and
the reason recorded for that was wrong: the note on statx's `STATX_MNT_ID` says
software falls back to `name_to_handle_at`, "which Darwin has nothing to
implement". **Darwin does have it, under another name.** A volume supporting
volfs — HFS+ and APFS both do — resolves `/.vol/<device>/<inode>` to the file,
which is `open_by_handle_at` with the handle spelled as a path. So the handle
here is that pair, and resolving one is an open.

`FAN_REPORT_FID` then reports `FAN_NOFD` in the metadata and a fid record after
it. Two pairings stay refused, each for a reason rather than for effort:

- **`FAN_REPORT_DIR_FID` and `FAN_REPORT_NAME`** describe `FAN_CREATE`,
  `FAN_DELETE` and the moves, which this does not produce. A listener asking for
  them would get a record shape promising names for events that never arrive.
- **Handles with a permission class**, which Linux refuses too. A verdict names
  the descriptor it answers, and an instance reporting handles was never given
  one — there would be nothing to answer with and nothing here to route by.

**The bug worth recording is a struct-padding one.** Linux's info record ends in
`unsigned char handle[]`, so the file handle and its bytes are packed straight
after the fsid with no alignment of their own. Describing that with a C struct
puts four bytes of padding in front of the 64-bit inode — the compiler aligning
a field Linux never aligned — so a listener reading at the offsets the ABI
specifies took the number four bytes to its left. It resolved to
`/.vol/0/39371965202432`, which is not a file. The record is laid out by offset
now.

The test takes the handle out of an event and hands it straight to
`open_by_handle_at`, then checks the **content** that comes back. A handle that
opened the wrong file would pass any check of the return value alone — which is
exactly what the padding bug did until the content was compared.

### 3.5.73 `rseq`, a table that had drifted into live numbers, and a generated syscall list

**`rseq` (293) is registered and deliberately refused.** glibc 2.35 and later
register a restartable-sequence area on every thread, so this arrived eight
times before a guest ran any of its own code and was written to the warning log
as "unimplemented syscall: 293" — a false alarm about something working
correctly, which is worse than silence because somebody eventually investigates
it.

ENOSYS is the *right* answer, not a placeholder. Linux returns exactly this
without `CONFIG_RSEQ`, glibc sets `__rseq_size` to zero, and callers fall back to
atomics. Accepting the registration would be the harmful choice: a restartable
sequence is a critical section the **kernel** promises to abort on preemption or
migration, and there is no scheduler here to make that promise. The obvious
repair — a private `cpu_id` per thread, so no two share a slot and no abort is
needed — does not survive contact with how the values are used, since per-CPU
arrays are sized by the CPU count and an id beyond it indexes past the end of
somebody's array.

**The aarch64 table had drifted into live syscall numbers.** The generator
appends x86-legacy handlers with no aarch64 number as a compat tail, "past the
real range" — which it was when written, and stopped being when Linux allocated
more. The committed table put that tail at 453, and 453–462 are now
`map_shadow_stack`, the `futex_*` trio, `statmount`, `listmount`, the `lsm_*`
trio and `mseal`. A guest calling `mseal` would have reached `epoll_wait_old`.
The tail is pinned at 1024 now, chosen so the kernel moving cannot walk into it.

Two further things fell out of regenerating:

- **The generator asked the wrong source what was implemented.** It took the set
  from the x86 table, which stops where the x86-64 numbering stops — so a
  handler numbered beyond it looked absent and was written out of the aarch64
  table. `faccessat2` (439 there) would have been dropped. It asks the sources
  as well now, and unions the two.
- **`inotify_init` was guarded to x86 only**, which was a workaround for the
  missing table entry rather than a fix. The compat tail exists precisely so
  every x86-legacy handler is present in both builds; the guard made the arm64
  link fail once the tail was correct.

**The README now carries the whole syscall table, generated.** A hand-written
list of 400-odd calls is wrong within a month and wrong in the direction that
matters — claiming coverage that is not there. `util/gen_syscall_doc.py` reads
the numbers and names from the kernel's own headers and the status from NABI's
dispatch tables.

Writing it honestly cost 13 syscalls: a handler whose entire answer is "this does
not exist" is not coverage, so `rseq` and the twelve `DEFINE_NOT_IMPLEMENTED_SYSCALL`
stubs are marked apart from the implemented ones. **204 of 398**, not the 217 a
naive count of named table entries gives.

**Against hyper-linux**, the nearest peer by approach — the same per-process VM,
EL1 shim and syscall translation — it reports 172 translated against these 204,
and states that it lacks namespaces and cgroups, treats `MAP_SHARED` as
`MAP_PRIVATE`, and has no `clone3` or robust futexes. NABI has all eight
namespaces, a cgroup hierarchy, real shared file mappings, System V IPC,
`mount(2)` with bind mounts and propagation, inotify and fanotify. It has
`clone3` and robust futexes no more than hyper-linux does. Where hyper-linux is
ahead is real and worth recording: it runs **x86-64 Linux binaries on Apple
Silicon** through Rosetta, which NABI does not — the x86 backend here is a
separate build for Intel Macs and is compile-tested rather than run — and it
describes demand-paged memory over a 1TB address space where NABI maps eagerly.

**fakedir** turned out not to be applicable, and the reason is worth writing
down. It redirects paths with `DYLD_INSERT_LIBRARIES`, which means it cannot
touch static binaries, is defeated by SIP and notarisation, does not affect
directory listings, and cannot reach dyld's own view of the filesystem. Every one
of those limits comes from intercepting *above* the syscall boundary. NABI is on
the other side of it: path translation happens where the guest's `svc` is
handled, so static binaries, listings and the guest's own `ld.so` are all covered
for the same reason.

### 3.5.74 Both syscall tables generated, and the frontier they were drifting into

The x86-64 table was maintained by hand and stopped at **332**, because that was
the last number anyone had needed. That is not a harmless place to stop: a
handler for a syscall numbered above it has nowhere to live, so the x86 build
fails to link it while aarch64 builds fine — and the break shows up in the arch
nobody here can run. `clone3` is 435 and `faccessat2` 439.

Both tables come from a kernel header and the set of `DEFINE_SYSCALL` handlers in
the sources now (`util/gen_syscall_table_x86.py` alongside the existing aarch64
one), so a new handler is wired into both by rebuilding rather than by
remembering to. `make syscalls` regenerates both and writes the README's table
out beside them.

Two consequences:

- **`faccessat2`'s `#if defined(__arm64__)` guard has gone.** Its comment said
  the guard was there because "this tree's x86 table stops at 332" and that the
  body "moves over with the table when it grows". The table has grown.
- **The aarch64 generator picked the wrong name where two share a number.** The
  header offers `sync_file_range2` at 84 behind `__ARCH_WANT_SYNC_FILE_RANGE2`,
  which aarch64 does not set, and `setdefault` took whichever appeared first.
  The `#ifdef`s are not evaluated, so the tie is broken by which name NABI has a
  handler for — the other is, by construction, the variant this architecture
  does not use.

### 3.5.75 Extended attributes — **implemented**, and one of them was saying yes

The twelve entry points were four stubs and eight absent numbers, and
`setxattr` was the bad kind of stub: it warned and returned **0**, so every
attribute a guest stored was stored nowhere and reported as stored. dpkg and rpm
set attributes while unpacking and `tar`, `cp -a` and `rsync -X` copy them, so
all of that had been quietly doing nothing. `lgetxattr` and `llistxattr` were
among the handful of calls a real workload still reached (see §3.5.77).

Darwin has the whole family under the same names, with two differences: a
`position` argument, which is for resource forks and is zero for everything
else, and "do not follow the symlink" spelled as an option flag rather than as a
separate `l`-prefixed call — so twelve Linux entry points are four Darwin ones
with `XATTR_NOFOLLOW` set or not.

**The part that is not a translation is hiding NABI's own attributes.** File
ownership and the guest's mode bits live in `msl.nabi.owner` and `msl.nabi.mode`,
because Darwin cannot hold a uid the host account has not got (see `struct
cred`). They are bookkeeping, not the guest's data, and a guest that could see
them could do three things it must not: read them, remove them — destroying the
ownership of its own files — and, worst, **copy** them. `tar -p`, `cp -a` and
`rsync -X` all read every attribute from one file and write them onto another, so
a single archive extraction would stamp one file's owner across everything it
touched. They are filtered from listings and refused by name.

Darwin's own attributes are hidden too, for a different reason. `com.apple.provenance`
is real and is the *host's*, and Linux has only the four namespaces `user`,
`system`, `security` and `trusted` — `setxattr` refuses anything else — so a
guest can neither create one nor make sense of one. The only thing it can do with
them is copy them somewhere they do not belong.

With `attr` installed from Debian:

```
set:    ok
get:    world
every attribute the guest can see: [user.k]      <- not com.apple.*, not msl.nabi.*
owner:  4242                                     <- kept in msl.nabi.owner
remove nabi attr: Operation not permitted
write  nabi attr: Operation not permitted
owner still: 4242
```

`xattrtest` guards the round trip and all four halves of the containment: absent
from the listing, `ENODATA` on read, `EPERM` on write and remove, and the
ownership still working afterwards.

### 3.5.76 `sync_file_range` — **implemented**

The most frequently reached unimplemented call in the tree, by a wide margin:
**532 refusals** in a single `apt` reinstall, all of it dpkg unpacking. Nothing
else came close.

Darwin has no ranged flush — `fsync` is whole-file or nothing — so the range is
widened to the file, which writes back more than was asked and never less. That
is the safe direction to be wrong in.

**The waiting matters more than the range.** `SYNC_FILE_RANGE_WRITE` only
*starts* writeback and promises nothing about when it lands; Linux's own manual
is emphatic that this form is not a durability guarantee, so it is answered
without doing anything and the data reaches the file either way. The `WAIT_BEFORE`
and `WAIT_AFTER` forms do promise the writeback has finished, and get an `fsync`,
which is the promise they asked for.

Reaching it at all needed the generator tie-break from §3.5.74: the header offers
`sync_file_range2` at 84 for architectures that set `__ARCH_WANT_SYNC_FILE_RANGE2`,
and aarch64 does not.

### 3.5.77 `clone3` — **implemented**

glibc 2.34 and later reach for this first when starting a thread and fall back
to `clone` on ENOSYS, so refusing it cost a failed syscall per thread and
nothing else — but the fallback is glibc's courtesy rather than a rule, and
anything written against `clone3` directly had no second try. It was one of the
four calls a real workload still reached.

It is the same call with its arguments in a struct rather than in registers,
which is what lets it carry what `clone`'s had no room for. Two differences
matter here:

- **The exit signal is a field of its own.** `clone` packs it into the low byte
  of its flags, which is exactly why `CLONE_NEWTIME` — bit 7 — cannot be
  expressed there and is refused (§3.5.60). Here the collision does not exist,
  so a time namespace *can* be asked for at clone time, as on Linux.
- **The stack is a base and a length**, where `clone` takes the pointer. A stack
  that grows down starts at the far end of what it was given.

`CLONE_PIDFD` and `set_tid` are refused rather than dropped: the first wants a
descriptor written back that nothing here can produce, and the second asks to
choose the child's pid — which is the pid namespace's to allocate, and comes
from the host besides.

With this, a full `apt` reinstall reaches **no unimplemented syscall at all**.

### 3.5.78 The rest of the futex family — **implemented**

`futex()` served WAIT, WAKE, the bitset pair, WAKE_OP and the PI operations.
What was missing was the half that moves waiters *without* waking them, the
non-blocking end of LOCK_PI, and the futex2 syscalls a program written today
reaches for.

**REQUEUE and CMP_REQUEUE** are what a broadcast is built on. `pthread_cond_broadcast`
has to hand every waiter to the mutex they will contend for next, and waking them
all so each can queue itself again is the thundering herd requeue exists to
avoid. The compare form checks the word has not changed underneath first, which
is how a caller learns the condition it read is already stale. One trap in the
ABI: `val2` arrives in the *timeout* slot — the one place `futex` reuses a
register for two types.

**TRYLOCK_PI** is LOCK_PI without the wait: the same exchange, and not taking the
lock is the whole difference.

**FUTEX_FD** is refused explicitly. It handed out a descriptor that became
readable when the futex was woken, was racy by construction, and Linux removed
it in 2.6.26 — saying so beats pretending to something that exists nowhere.

**`get_robust_list`** reports what `set_robust_list` was told. What this pair
provides is the bookkeeping and not the recovery: NABI does not walk the list
when a thread dies, because a guest thread is a host thread and dies without
passing through here. Reporting the pointer is still the truth about what was
registered.

**The futex2 syscalls** — `futex_wake`, `futex_wait`, `futex_requeue`,
`futex_waitv` — are the same operations with the arguments untangled: a mask
instead of a bitset packed into `val3`, a width in the flags instead of an
assumption, and no register doing double duty. Only 32-bit futexes are served;
a width Linux's flags can name but this does not implement is EINVAL rather than
four bytes read where two were meant.

`futex_waitv` is the one with real structure behind it: one sleep and many
queues. Each futex gets an entry of its own, because that is what a wake walks,
and they share the condition variable and a slot to record *which* index fired —
so the first waker to arrive says which futex it was and the others find their
entries already unlinked.

**The panic that had become reachable.** A futex in shared memory used to
`panic("Non-private futex is unsupported!")`, killing the guest for doing
something ordinary — and it became reachable the moment §3.5.57 made System V
shared memory work, since a `PTHREAD_PROCESS_SHARED` mutex in a segment is
exactly this. The wait queue is one process's, so a waiter here cannot be woken
by another process; within a single process — which is most uses of a shared
mapping, and all of the ones that were panicking — that is exactly right. Across
processes it would be a missed wakeup, so the wait is bounded and re-checks the
word rather than sleeping on it forever. A cross-process wake becomes a short
delay instead of a hang, and neither becomes a dead machine. The look-again
return is reported as a spurious wake, which every futex caller already loops
around; `EAGAIN` would have claimed the word did not match when it did.

Worth noting what this depended on: `futex_wake`, `futex_wait` and
`futex_requeue` are **454, 455 and 456** — exactly the numbers the compat tail
was squatting on before §3.5.74 pinned it at 1024. Wired into the old table,
`futex_wake` would have dispatched to `afs_syscall`.

### 3.5.79 `timerfd_*` and `timer_*` — **implemented on a host with neither**

Darwin does not implement `timer_create` at all — there is no `timer_t` in its
headers — and has no timerfd. What it has is threads and a condition variable
that can be waited on until a deadline, which is enough for both, because both
are the same object with two ways of saying it fired: a timerfd makes a
descriptor readable, a POSIX timer raises a signal.

So there is one engine and two faces on it. A timer is a deadline, an interval
and a thread asleep until the first of them; the wait is on a condition variable
rather than a plain sleep so that `settime` can move the deadline — or disarm it
— without waiting for the old one to pass, which is what a program rearming a
timer in its event loop does constantly.

**The descriptor is the read end of a pipe**, as inotify's and fanotify's are,
so `poll`, `select` and `epoll` work on it without being taught anything. That
matters more here than anywhere else: a timerfd exists to go in an event loop,
and one that worked only through `read()` would pass a simpler test and be
useless where these are actually used. What `read()` returns is *not* what is in
the pipe — Linux answers with the number of expirations since the last read, as
a `u64`, and resets it — so the pipe carries readability and the count is kept
beside it. An interval timer that has fallen behind counts **every** deadline
that passed, which is how a program that was slow finds out it was.

**What POSIX timers cannot do here is worth stating plainly.** `SIGEV_SIGNAL`
asks for a signal, and `send_signal` drops everything at or above `SIGRTMIN` —
Darwin has no realtime signals to map them onto — so a timer asked to raise one
would be a timer that never fired. glibc's `SIGEV_THREAD` is built on exactly
that: it registers `SIGEV_THREAD_ID` against `SIGTIMER`, which is `SIGRTMIN`.
Those are **refused at `timer_create`** rather than accepted, because a caller
told its timer was created and then never woken has no way to find out why, and
the failure surfaces a long way from here. `SIGEV_NONE` — the polled form — and
any signal NABI can actually deliver both work.

That refusal is a real gap rather than a design choice, and it has one cause:
realtime signals are not delivered. Fixing it is its own change — the pending
mask already has room for 32–64, so what is missing is raising them without
routing through a Darwin signal that does not exist, and interrupting a thread
that is blocked so it notices.

226 of 398 now.

### 3.5.80 `syslog`, `sysfs`, `tee` — and two rows that were never syscalls

**`syscalls` is not a syscall.** `__NR_syscalls` is the *count* of them (463) and
`__NR_arch_specific_syscall` is the base an architecture numbers its private ones
from (244). The dispatch-table generator has always skipped both; the README's
doc generator, added in §3.5.74, did not — so the table carried two invented
rows claiming NABI had failed to implement things that do not exist, and
inflated the denominator by two. **396, not 398.**

**`syslog`** is klogctl, the kernel's ring buffer, not the libc `syslog()`. There
is no kernel here and so no buffer, and the honest answer is an empty one rather
than an error: an empty log is a state a real machine can be in, while ENOSYS is
a state `dmesg` does not expect and reports as a failure of the tool. `dmesg` now
prints nothing and exits 0 — which is true, nothing has been logged — instead of
"klogctl failed: Function not implemented".

What is deliberately *not* done is answering with NABI's own warning sink. That
is the host's account of the guest, written for whoever is debugging NABI: it
names host paths, host descriptors and host errno values, and handing it over as
the guest's kernel log would be both a leak and a fiction.

`SYSLOG_ACTION_READ` waits for a message that will never come, rather than
returning nothing, because a caller that gets 0 from it loops — `dmesg -w` would
spin a core on a machine with nothing to say. Blocking until a signal is what it
does on a quiet Linux too.

**`sysfs`** is the filesystem-type table and has nothing to do with `/sys`.
Obsolete on Linux — its own manual says so and points at `/proc/filesystems` —
but still implemented and still numbered there, so a guest that calls it deserves
an answer about *this* machine. The list is exactly the set `mount(2)` here
accepts, so all three questions it can ask come out of the same truth the mount
table is built from. It has no aarch64 number at all; only x86-64 ever gave it
one, so it lives in the compat tail.

**`tee` needed a peek into a pipe, and Darwin has none.** The call copies between
two pipes *without consuming* what it copied — the whole point is that the data is
still there afterwards — and there is no way to look into a Darwin pipe without
taking from it: `FIONREAD` gives a count and not the bytes, and there is no
`pread` on one.

Read-and-write-back is not the same operation, and it fails twice over. Reading
part of what is queued and appending it returns it *behind* what was left, so
`"ABCDEF"` tee'd four bytes at a time comes back as `"EFABCD"` — reordered in the
single-threaded case, before concurrency is even a question. Draining the whole
queue and restoring it fixes the order and opens a worse hole: the restore is not
atomic against a writer, and a writer is not the exotic case here, it is the
process feeding the pipe, which is the entire topology tee is used in. Anything
written while the data is out lands in front of the restored bytes. A lock does
not close it either — a writer would have to take that lock *before* deciding to
write, which costs every pipe write in the system, and a writer blocked on a full
pipe while holding it deadlocks the drain that would empty it.

So nothing is ever restored. **The bytes tee removes are kept in front of the
pipe rather than back in it**: a pushback that reads are served from first, and
the pipe read only when it is empty. That has no writer hazard at all, because a
writer appends to the pipe, which is exactly where its bytes belong — after
everything tee is still holding. The order is preserved by construction instead
of by exclusion, which is why this design works and the other two do not.

It holds because NABI is the only thing that ever reads a guest pipe, so there is
nowhere to bypass it from. Three paths had to learn about it: `read` and `readv`,
which must serve pushback before the pipe or the stream comes back out of order;
and readiness — `ppoll`, `select`, `pselect6` and `epoll_wait` — which must report
a descriptor readable when bytes are held for it. That last half is the one a
simpler implementation would skip and a real program would hang on, for the same
reason a timerfd that only `read` could see is useless in an event loop.

The pushback is shared rather than per-process, because a pipe is. A guest with
no pending pushback pays one load from a shared mapping to find that out, the
same fast path `fanotify` uses.

**Naming the pipe took two goes, and the first one was wrong.** A read end's
inode is stable across fork and across the exec NABI's fork is built on, which is
what sharing needs, and it was taken to be unique as well — 64-bit and
random-looking. It is not. Darwin draws pipe inodes from a pool it reuses: three
runs of a two-pipe program produced the same value twice, and the smoke suite hit
it within minutes. Keyed on the inode alone, a pushback left behind by a process
that teed and then exited without reading gets picked up by an unrelated later
pipe that draws the same number, and its bytes are injected into that stream —
the exact corruption this whole design exists to avoid, arriving by the back
door. It surfaced as `splicetest` failing only when `teetest` had run first.

So a pipe is named by **both** ends: its own handle and its peer's, which
`proc_pidfdinfo(PROC_PIDFDPIPEINFO)` reports and which are allocated
independently. The peer is part of the filename rather than a header, so a
mismatch is simply a file that is not found. A stale pushback can now only be
mistaken for a live pipe if a new pipe draws both numbers as the same matched
pair, rather than either one of them.

That same peer handle settles the other question Darwin would not answer.
`tee(p[0], p[1])` is `EINVAL` on Linux, where it is easy to detect because both
ends of a pipe share one inode; here they get unrelated ones. This was first done
by remembering the pairing at `pipe2`, which is the one place that sees both —
but that is per-process bookkeeping and a pipe inherited across a fork fell
outside it. Asking the pipe is strictly better: the far end of `fd_in` *is*
`fd_out`, and it holds for an inherited pipe as readily as a fresh one.

229 of 396.

### 3.5.81 `splice` and `vmsplice` — the rest of the family, and what a copy costs

These are much less trouble than `tee`, for one reason: they **consume** what
they move. Tee's whole difficulty was leaving the source untouched on a host that
cannot look into a pipe without taking from it. Splice is allowed to take, so
taking is the implementation.

What they cannot do is the reason the family exists at all. On Linux these move
pipe buffers *by reference* — `splice` never copies, which is the point of using
it instead of read-then-write, and `vmsplice` hands the kernel the caller's own
pages. A guest pipe here is a Darwin pipe, and Darwin has no way to attach a page
to one, so the bytes go through a buffer. That costs a copy and changes nothing a
caller can observe: the same bytes arrive, in the same order, and the same count
comes back. **It is the guarantee of speed that is lost, not the guarantee of
behaviour** — which is the opposite of the trade `tee` would have made by
read-and-write-back, where the speed was fine and the data was wrong.

Two flags fall out of that. `SPLICE_F_MOVE` is documented as a hint the kernel may
ignore, and Linux itself has ignored it since 2.6.21, so ignoring it is not a
shortfall. `SPLICE_F_GIFT` says the caller is donating its pages and will not
touch them again; copying honours that promise without taking it up, which is the
conservative direction and the only one available here.

The part they share with `tee` is the pushback. A pipe `tee` has taken bytes out
of is holding them in front of the pipe, so a `splice` or `vmsplice` from that
pipe has to see them first — otherwise a guest that tees and then splices gets
its stream back with a hole in it, which is the exact failure the pushback exists
to prevent. `splicetest` checks it, and without the lookup the test gets two
bytes where it wanted four.

`SPLICE_F_NONBLOCK` is applied to the pipe end only, since Linux is explicit that
it does not make a blocking *file* descriptor behave differently — and it is put
back afterwards, because `O_NONBLOCK` belongs to the open file description and
would otherwise outlive the call and change how every other user of that
descriptor behaves.

231 of 396.

### 3.5.82 `sendfile` and `copy_file_range` — and where a short write loses data

Both exist so a program does not route bytes through its own memory. On Linux
that saves two copies across the user boundary, and `copy_file_range` can go
further: on a filesystem that supports it the kernel shares extents instead of
copying, so a gigabyte "copy" costs almost nothing.

Neither shortcut is available. Darwin's own `sendfile(2)` is a different call
with a different shape — its destination must be a socket, which Linux has not
required since 2.6.33 — so using it would implement a *narrower* syscall than the
one being asked for. APFS does have copy-on-write cloning, but `clonefile(2)`
clones a whole file to a new path; it cannot place a range inside a file that
already exists, which is precisely what `copy_file_range` does. So the bytes go
through a buffer, and the guest gets the behaviour without the saving — the same
trade `splice` makes, for the same reason.

**The part that needed care is not the copying, it is the bookkeeping.** Read 64K
from the source with `read(2)`, have `write(2)` accept only 8K, and the other 56K
is gone: consumed from the source, never delivered, and not reported. The file
position has already moved. It is a silent hole in the middle of a copy, and it
only appears when the destination is slow — which is never true in a small test,
and always true of the sockets and pipes `sendfile` exists for.

So nothing here reads with `read(2)`. Every read is a `pread` from a cursor this
code owns, and a file position is only set at the end, from the count that
actually made it out. A short write then costs nothing — it ends the call early
with a smaller number, which both syscalls are allowed to do and every correct
caller already handles. `copytest` pins it down by sending a 200K file into a
non-blocking pipe that cannot take it all and checking the source's position
against the returned count; with the naive form the file sits at 131072 having
delivered 65536.

`copy_file_range` also refuses overlapping ranges within one file, where the
source is rewritten as it is read and there is no defined answer. Same file means
same inode rather than same descriptor — two separate opens of one file are the
case that would otherwise slip through, and the test uses exactly that.

**A generator bug surfaced alongside this.** `sendfile` came out of the doc
generator with no aarch64 number at all, which is false — it is 71. asm-generic
reaches a third of its table through `#define __NR_<name> __NR3264_<name>`, and
the doc generator only read lines ending in digits, so it had been silently
dropping every one: `lseek`, `fcntl`, `mmap`, `fstat`, `statfs`, `truncate` and
the rest all showed a dash where a number belongs. The dispatch-table generator
had always followed the indirection; the doc generator now does too, which is the
whole point of generating the table rather than keeping it by hand.

Following it picks up both sides of the header's 32-bit split, so one number
arrives under two spellings — `lseek` and `llseek`, `sendfile` and `sendfile64`.
Whichever name the dispatch table dispatches is the one kept, and where neither
has a handler the plain spelling wins, since the alias is always the longer one.
That is also why the denominator moved: `sync_file_range2` was never a separate
aarch64 call, only the other name for 84.

233 of 395.

### 3.5.83 The `io_setup` family — asynchronous I/O, and which thread may touch what

This is the older of Linux's two async interfaces. io_uring is the other, and is
a different subsystem rather than more of this one — mapped submission and
completion rings with their own opcode space, which is a phase of work and not a
commit.

Darwin has POSIX `aio_read`/`aio_write`, and they are not a substitute: they
complete by signal or by a spawned thread, they have no shared completion queue
to reap from, and `aio_cancel` does not mean what `io_cancel` means. But what
Linux's interface actually promises is narrower than "the kernel does I/O by
itself" — submit returns without waiting, and results turn up in completion order
when asked for. A worker thread per context delivers exactly that.

**Two decisions matter, and both are about which thread touches what.**

The first is guest memory. The worker never reads or writes it. A write's data is
copied out of the guest at submit time and a read's data is copied in at reap
time, both on the guest's own thread, with the worker seeing only a buffer NABI
owns. That is not a workaround — it is the contract. A read buffer's contents are
undefined until the operation completes and is reaped, so filling it at reap time
is indistinguishable from filling it earlier, and it means no guest page can be
unmapped underneath a thread that is mid-write to it. Linux prevents that by
pinning the pages; there is no equivalent here, and this sidesteps needing one.

The second is the context id, which is the part that would have bitten. Linux's
`aio_context_t` is not a handle — it is the address of a ring the kernel mapped
into the process, and libaio treats it as one: `io_getevents` dereferences it to
read a magic number before deciding whether it can answer without a syscall. Hand
back a small integer and that dereference is a segfault *in the guest*, which
would read as a guest bug. So a page is mapped and its address is the id,
deliberately left zeroed — a magic that does not match is exactly what sends
libaio down the syscall path, which is the only path here.

`io_cancel` only cancels what the worker has not started. One already running
cannot be called back — Darwin cannot abort a `pread` in flight — and one already
finished has a result the guest is owed, so both answer `EINVAL` rather than
pretending. `io_destroy` joins the worker rather than abandoning it, so nothing
is still reading a descriptor the guest is about to close.

None of it is inherited across fork, which is not a limitation but the specified
behaviour: `fork(2)` is explicit that a child inherits neither its parent's aio
contexts nor its outstanding operations. arm64's fork is fork-plus-exec and this
table is process memory, so the child gets none — which is what it is owed.

239 of 395.

### 3.5.84 `io_uring` — an interface that is a memory layout, not a syscall

The three syscalls are the small part. io_uring's interface is *shared memory*: a
guest asks for a ring, maps three regions of the descriptor it gets back, and
from then on submits work by writing 64-byte entries into that memory and bumping
a counter. Nothing arrives as syscall arguments.

Which is why the first question was whether this was possible here at all. The
regions have to be memory the guest and NABI both see, and NABI cannot hand the
guest a pointer into its own heap — guest memory is a separate address space
reached through stage-2. **The way in already existed**: `do_mmap` maps a shared
file for real when a guest asks it to, precisely so `MAP_SHARED` means what it
says, and the host mapping and the guest mapping are then the same pages. So the
ring is a file — created, sized, and unlinked immediately, so the descriptor is
the only way to it and it goes when the descriptor does — and the guest's own
mmap of the ring is an ordinary mmap needing no special case.

The file is enormous on paper and sparse in fact. `IORING_OFF_CQ_RING` is 128MiB
and `IORING_OFF_SQES` is 256MiB; those are magic numbers rather than real
offsets, but the cheapest way to make them work is to let them *be* real, so the
file is sized past the largest and the regions sit where the constants say. No
blocks are allocated for the gap. The alternative — intercepting mmap to
translate the offsets — would put an io_uring special case in the middle of the
memory manager.

One thing had to change to get there. `MAP_POPULATE` was neither supported nor
ignored by `do_mmap`; it fell through to `warnk` and `exit(1)`. liburing passes it
on all three ring mappings, so every io_uring guest would have died at its first
mmap over a flag that only means "be quick". It is now ignored, which is all it
ever was.

**What this does not do is run the work asynchronously.** A real io_uring hands
anything that would block to a worker pool; here a submission is executed during
`io_uring_enter`, on the thread that called it. Every visible rule still holds —
completions carry the right `user_data`, the counters advance, a caller reading
the completion ring finds its entries — and for file I/O the kernel very often
completes inline too. What is lost is the guest that submits a blocking read and
expects to work meanwhile: here it waits. That is a performance property, not a
correctness one, and it is also what makes it *legal to touch guest memory in the
handler at all*, which is the difficulty `src/fs/aio.c` had to design around.

`SQPOLL` and `IOPOLL` are refused rather than ignored, and that distinction is
the important one: both are promises about *how* the ring is serviced, and a
guest granted `SQPOLL` would stop calling `io_uring_enter` — the only thing that
makes this ring go. An unimplemented opcode fails per entry with `EINVAL`, as the
kernel answers one it does not know, so a caller learns which submission it was
without losing the batch.

`io_uring_register` implements the eventfd registration and refuses the rest.
Registering buffers or descriptors pre-attaches them so a submission can name one
by index, which means honouring `IOSQE_FIXED_FILE` and the `*_FIXED` opcodes as
well — a guest told its buffers were registered would submit an index into a
table that does not exist and read whatever that index landed on. The eventfd is
the one that costs nothing and is worth having, since it is what lets a guest
wait on the ring inside an ordinary poll loop.

242 of 395.

### 3.5.85 `POLL_ADD`, `POLL_REMOVE`, `TIMEOUT` — the ops that forced a thread

The previous section could say that every submission ran on the thread that
submitted it. These three are why that stopped being true.

A poll whose descriptor is not ready has nothing to report, and a five-second
timeout has nothing to report for five seconds. Running either to completion
inside `io_uring_enter` would make a *submission* block, which is the one thing
the interface promises it does not do — so they are recorded as pending and a
per-ring thread waits on them.

**That thread is safe for exactly these operations, and the reason does not
generalise.** A completion for a poll carries a readiness mask and a completion
for a timeout carries an error; neither reads nor writes a guest buffer. And the
completion ring is *NABI's own mapping* of the ring file rather than guest memory
reached through the page tables, so posting into it touches nothing the guest
could unmap underneath the writer. A read or a write has a buffer and would not
be safe there, which is why those stay on the submitting thread — the same
constraint that shaped `src/fs/aio.c`, arriving at a different answer because
these operations carry no data.

The thread is started on demand, so a ring that only ever does file I/O never
gets one. It waits on the pending descriptors plus a pipe, because a poll armed
while it is already waiting would otherwise not be noticed until the current
wait happened to end. `io_uring_enter` with `GETEVENTS` now genuinely waits,
which is the path liburing takes when the completion ring is empty; asking for
completions when nothing is pending and nothing is ready answers `EAGAIN` rather
than entering a wait that cannot end.

Three details worth recording. `POLL_REMOVE` posts **two** completions — the
cancelled poll gets its own, or a caller waiting on that `user_data` waits
forever for something that will never arrive. A `TIMEOUT` carries a completion
count in `off`, and one ended by that count reports 0 while one ended by its
clock reports `-ETIME`, which is how a caller tells the two apart. And an
absolute deadline is converted at arm time: the caller names it against the
realtime clock and the poller measures against the monotonic one, so comparing
them directly would be comparing two different origins.

The refactor that made this work is small but was the actual bug: arming
originally reported a result back to the submit loop, which cannot express what
these three do. A poll produces no completion yet, a removal produces two, and a
failure to arm produces one. `POLL_REMOVE` fell through to the ordinary
dispatcher and came back `EINVAL` — an opcode it had never heard of. Arming now
posts its own completions and simply says whether it handled the entry.

`TIMEOUT_REMOVE` came next, and it is one opcode with two operations in it. Left
alone it cancels the timeout named by `addr`; with `IORING_TIMEOUT_UPDATE` set in
the flags the timeout stays and its deadline is replaced by the one at `addr2`.
The flag cannot be ignored, which is the whole reason it is worth a paragraph: a
caller asking to *extend* a timeout would have it cancelled instead, be told the
update succeeded, and never hear from the timeout it was relying on. That is a
wrong answer wearing a right one's clothes, which is the failure this tree keeps
refusing to ship.

Updating a deadline also has to wake the poller, and that is the part a test
almost cannot see. The poller is asleep on the old deadline; change it without
saying so and the completion still arrives with the correct result, ten seconds
after it should have. So `uringtest` **times** that wait — a ten-second timeout
shortened to 40ms must complete well inside two seconds — and sleeps first, so
the poller has genuinely settled onto the old deadline rather than racing to pick
up the new one. Without that sleep the check passed with the wake deleted, which
is to say it was proving nothing.

`ASYNC_CANCEL` is the general form of both removes, and adding it was mostly a
factoring job. The three differ only in what they are looking for: `POLL_REMOVE`
and `TIMEOUT_REMOVE` each name one kind of pending work and match a `user_data`
within it, while `ASYNC_CANCEL` matches across kinds and its flags let it match
on a descriptor or on nothing at all. That difference now lives in a predicate,
so the part that actually cancels — detach, answer the cancelled request on its
*own* `user_data`, then answer the cancelling one — is written once instead of
three times.

Its `cancel_flags` are the same trap `IORING_TIMEOUT_UPDATE` was. `CANCEL_FD`
says `addr` is a descriptor rather than a `user_data`, so ignoring it compares a
descriptor against a cookie and finds nothing; `CANCEL_ALL` says cancel every
match rather than the first, so ignoring it leaves a caller clearing out a
descriptor with all but one still armed and a success in hand. Both are
implemented, and `uringtest` was checked against an implementation that drops
each — one reports a poll that was never cancelled, the other reports one
cancellation where two were asked for. `CANCEL_FD_FIXED` names a registered
descriptor, and registration is refused here, so it answers `EINVAL` rather than
guessing at an index into a table that does not exist.

`EALREADY` has no case to arise from. The kernel uses it for work that has
started and cannot be called back; a pending entry here is either still waiting
or already completed and off the list, with nothing in between.

`STATX`, `UNLINKAT` and `MKDIRAT` came last and are the least interesting, which
is the point: they are the same operations as the syscalls of those names, so
they call the same functions. `DEFINE_SYSCALL` already generates `sys_<name>`,
and a second implementation inside the ring would be one more thing to keep in
step with the first.

What does need care is that the arguments sit in different fields than they do
in a syscall frame, and reading one out of the wrong slot is a mistake that still
reports success. `STATX` takes its mask from `len` and its output buffer from
`addr2`; `MKDIRAT` takes its mode from `len`; `UNLINKAT` takes `AT_REMOVEDIR`
from the per-opcode flag word, which is the difference between removing a file
and removing a directory. So `uringtest` reads the statx result *out of the
buffer* rather than trusting `res` — a buffer pointer from the wrong field
returns 0 and writes somewhere else entirely — and each of the three was checked
against a build that reads the wrong field.

One thing that check turned up was in the test rather than the code. These
opcodes create and remove a directory in the shared test root, and a run that
failed part-way left it behind, so every later run failed at `mkdirat` with
`EEXIST` — including the run meant to confirm the fix. The test now removes it
first: one that cannot be run twice is one that stops being run.

`SEND` and `RECV` are the socket pair of the file operations above, and go the
same way: `sys_sendto` and `sys_recvfrom` already exist, so the opcodes call
them. A destination address, when the entry carries one, is in `addr2` with its
length in the low half of the slot `splice_fd_in` occupies; zero there is the
connected case, and `sendto` with a null address is `send`.

`OPENAT2` did not exist as a syscall at all, so it was implemented as one and the
opcode calls it — which is the honest way round, and moves the table to **243 of
395**.

**The point of openat2 is not the struct, it is that it checks.** `openat`
ignores bits it does not know and ignores a mode that cannot apply; `openat2`
refuses both, and that is the only reason to call it — a caller finds out that
what it asked for is unavailable instead of quietly not getting it. Implementing
it and then ignoring the same things would defeat the whole exercise. So an
unknown flag is `EINVAL`, a mode without `O_CREAT` or `O_TMPFILE` is `EINVAL`,
trailing bytes from a future larger struct must be zero or it is `E2BIG`.

Every `resolve` flag is refused, and that is deliberate rather than lazy. They
are restrictions — `RESOLVE_BENEATH` says a path may not escape the directory it
starts from, `RESOLVE_NO_SYMLINKS` says no component may be a link — and a caller
sets one *because it is relying on it*. Enforcing them needs a resolver that
inspects every component, which this does not have. Accepting them anyway would
hand back a file the caller believes was proven safe. `EINVAL` is the worse
answer to receive and the better one to give: a caller can handle `EINVAL` and
cannot handle being lied to.

**One bug found, and it was mine.** Writing the test for `OPENAT2` meant reading
from the descriptor it returns, and doing the same for `OPENAT` showed the
`OPENAT` opcode added two commits earlier was broken: it called `do_openat`,
which opens a file and hands back a *host* descriptor, while everything that
makes it the guest's — the entry in the guest's descriptor table, the `/proc`
redirect, the fanotify open permission — happens in `user_openat` above it. The
completion carried a plausible small integer that was `EBADF` on first use. It
now goes through `user_openat`, and `do_openat` is `static` again, since exposing
it was what made the mistake reachable.

The lesson is in the test rather than the fix: a completion carrying a descriptor
was checked for being non-negative, and a descriptor is only a descriptor if the
guest can use it. Both opens now read a byte back through what they returned.

### 3.5.86 Fixed files and buffers — registration without anything to pin

Registration pre-attaches descriptors or memory to a ring so a submission can
name one by index. On Linux that buys two things: the kernel holds a reference
and resolves the descriptor once instead of per operation, and it pins the pages
so I/O can go straight to them. **Neither exists here.** There is nothing to pin,
and a descriptor lookup that costs nothing is not worth saving.

What is left is the naming, and the naming is the part a guest can observe — so
it is the part that has to be right. `IOSQE_FIXED_FILE` makes the `fd` field an
index into the ring's table, and that resolution happens once in the submit loop
rather than in each operation, so every opcode taking a descriptor gets it and
there is a single place for it to be wrong. An index with nothing behind it
answers `EBADF`, which is what the caller is really holding.

`READ_FIXED` and `WRITE_FIXED` name their memory by `buf_index` and point
somewhere inside it, and **the range is checked against the registration**. That
check is worth keeping even without pinning behind it. The kernel makes it
because it has pinned those pages and will touch nothing else; a caller that
relies on the bound should get the bound whether or not that is the reason for
it, and a fixed read running off the end of its buffer is a bug the caller wants
told about rather than quietly served.

Both were checked against builds that drop them. Without the flag check the
fixed-file read reports 0 where 5 was wanted — slot 0 holds the real file, so a
submission naming 0 as a *descriptor* means stdin, which is what makes that test
tell an index from a descriptor at all. Without the bound check the overrunning
read succeeds and returns 10.

The first attempt at that first check proved nothing: the edit that was supposed
to disable the flag never matched, so the test ran against correct code and
passed. A verification that silently does not verify is worse than none, because
it is recorded as evidence. It is asserted now.

### 3.5.87 The ring lock, and what was actually wrong with holding it

`io_uring_enter` held the ring's lock across the operation it was running. That
lock is what the poller needs to post a completion, so a poll that came ready sat
waiting for an unrelated file to finish reading, a timeout fired late by however
long that read took, and a second thread entering the same ring queued behind it.
None of that is what the operation was waiting for. The lock is now released for
the duration of the operation and taken again to post the completion.

Two things had to be true first. The submission entry is claimed before the lock
goes — the head is advanced for that entry rather than for the whole batch at the
end — so another thread entering the same ring cannot find it still waiting and
run it twice; the entry itself is worked from a copy, so the guest reusing the
slot is fine. And everything that reads ring state moves above the release:
`IOSQE_FIXED_FILE` resolution and the fixed-buffer bound check both consult
tables `io_uring_register` can replace, so they happen under the lock and the
operation itself consults nothing.

**A ring can now be closed while one of its operations is in flight**, which the
lock had previously made impossible, so rings gained a use count. Closing detaches
immediately, so nothing new can find it; freeing waits for the last thread
inside. Without that the close would free the ring under the thread still working
on it.

**A claim in the first draft of this was wrong and is worth recording.** It said
holding the lock was also a deadlock: that closing a descriptor takes the
descriptor table's write lock and then the ring's, while an operation opening a
file does the reverse. The second half is right and the first is not —
`uring_close` is called from `user_close` *before* that lock is taken, not under
it. There was no deadlock, only the delay above. The error surfaced because the
test written to demonstrate the deadlock failed for an entirely different reason,
which was the good outcome: a test that had passed would have left the wrong
explanation in the tree.

What that test found instead was a real bug of the same shape as the `OPENAT` one
two sections up. The `CLOSE` opcode called `do_close`, the descriptor table's
half, rather than `user_close` above it — so it closed the descriptor and left
behind everything hanging off it: the inotify and fanotify notes, a timerfd's
timer, and a ring's own mappings and registrations. Closing a ring through itself
left the ring attached, and entering it afterwards succeeded.

The suite does not cover the lock release itself. Showing it needs a second guest
thread to be held up by the first, and these tests are single-threaded; what is
tested is the lifetime the release made necessary.

### 3.5.88 POSIX message queues, and the I/O priority pair

`mq_open` and its five companions are not the System V queues in `msg.c`. Those
are named by a key and reached by an id; these are named by a path and reached by
a **descriptor**, and that difference decides the design. macOS has none of it —
`mq_open` does not exist there at all — so all of it is NABI's own, built the way
the System V objects are: a file in a directory belonging to the IPC namespace,
with the ordering rules enforced under an exclusive lock on that file. Linux
scopes these per IPC namespace too, so the existing directory scheme gets that
for nothing.

The descriptor is what makes them different and also what makes them easy. **The
queue is the file**, so the descriptor handed back is an open descriptor on it
and there is no side table mapping one to the other. That pays for itself: the
descriptor survives fork, survives the exec arm64's fork is built on, and closes
when the guest closes it, with none of this code involved. What marks a
descriptor as a queue rather than an ordinary file is the magic in its header.

A queue holds a header and a fixed array of slots, and messages are *not* stored
in order. Each slot carries the priority it was sent with and a sequence number,
and the receiver picks the highest priority and the oldest within it. Storing
them ordered would mean moving the tail of the file on every send, and the
ordering has to be computed on receive regardless. `mqtest` sends low, high, low
and requires high, first-low, second-low back — an implementation shaped like a
pipe returns them as sent and looks entirely reasonable doing it.

Two honest gaps. **`mq_notify` is refused for the notifications it cannot
deliver.** It asks for a signal when an empty queue becomes non-empty, those
signals are realtime ones, and NABI drops everything at or above `SIGRTMIN` for
want of anything on Darwin to map them onto — the wall `timer_create` hit. A
registration accepted and never acted on is worse than one refused: the caller
waits forever instead of falling back to a blocking receive, which works
perfectly. `SIGEV_NONE` asks to be registered and told nothing, which is exactly
what can be provided, so that form is honoured, along with the exclusivity that
programs use as a lock. **And the guest's access mode is not enforced**: the host
descriptor must be read-write because taking a message *out* of a queue is a
write to the file it lives in, and nothing re-checks the mode the guest asked
for, so a queue opened `O_RDONLY` here will accept a send.

`ioprio_set` and `ioprio_get` translate a class and lose a level. Linux encodes
realtime, best-effort or idle with eight levels inside the first two; Darwin's
`setiopolicy_np` has important, standard, utility, passive and throttle, with no
levels within them. So best-effort 0 and best-effort 7 both land on standard and
read back as level 4, the middle of a range the host never kept. The part
programs actually use is the class — `ionice -c3` to keep a backup out of the way
— and idle really does map onto throttle. Only the calling process can be
adjusted, because Darwin's interface has no way to name another one; asking about
somebody else is refused rather than answered about the wrong process.

**A reporting inaccuracy found here and deliberately not fixed here.** Three
members of these families — `io_pgetevents_time64`, `mq_timedsend_time64`,
`mq_timedreceive_time64` — are listed with aarch64 numbers they do not have. They
sit inside the kernel header's `#if __BITS_PER_LONG == 32 || defined(__SYSCALL_COMPAT)`
block, and both generators scan the file with a regex that reads *both* branches
of every conditional, so all 58 of that block's numbers appear as aarch64
syscalls NABI has failed to implement. Nothing malfunctions — those numbers are
genuinely unassigned on aarch64, so a guest cannot reach them and the
`unimplemented` entries are unreachable — but the denominator is inflated and the
table claims calls this architecture does not have. Fixing it properly means
resolving the conditionals rather than ignoring them, which means either driving
a real preprocessor or hard-coding which `__ARCH_WANT_*` symbols aarch64 defines.
Guessing that set wrong would silently add or drop syscalls from both dispatch
tables, which is a worse failure than the one being fixed, so it is left for a
commit of its own where it can be verified rather than folded into this one.

251 of 395.

### 3.5.89 The header is a program, not a list

The generators read `asm-generic/unistd.h` with a regex, and a regex reads
*both* branches of every conditional. A third of that header is conditional, so
the aarch64 table had been claiming syscalls aarch64 does not have: the twenty
`*_time64` numbers from the 32-bit-only block, and `sync_file_range2` sharing 84
with the spelling arm64 actually uses.

Nothing malfunctioned. Those numbers are unassigned on aarch64, so a guest could
never reach the `unimplemented` entries they produced - which is exactly why it
went unnoticed. What it cost was the truth of the table: 395 calls listed where
there are 375, and twenty of them counted as work still to do.

The fix resolves the conditionals instead of ignoring them, in
`util/kernel_headers.py`. **The risk in doing that is the reason it was left for
its own commit**: resolving requires knowing which `__ARCH_WANT_*` symbols arm64
defines, and a wrong entry there silently adds or removes real syscalls from both
dispatch tables, which is a worse fault than the one being repaired. Three things
hold it down.

The symbol set is small, closed, and annotated with what each entry decides -
`__ARCH_WANT_RENAMEAT` is renameat at 38, `__ARCH_WANT_SET_GET_RLIMIT` is 163 and
164, `__ARCH_WANT_MEMFD_SECRET` is 447, and `__ARCH_WANT_SYNC_FILE_RANGE2` is
which spelling 84 gets. Two more are listed and noted as unable to matter,
because every condition using them is already true on a 64-bit architecture.

Anything it cannot evaluate is fatal rather than assumed. An unknown symbol, an
expression in an unhandled form, an unbalanced conditional - all stop the build,
so a header that grows a new `#ifdef` cannot quietly drop whatever is inside it.
The first version did not manage this: an unknown symbol in `#ifdef` was treated
as undefined, which is what a preprocessor does but not what this needed, and the
file's own docstring already claimed otherwise. That gap was found by testing the
claim rather than by reading it.

And the result is checked rather than trusted. Both dispatch tables come out
**byte-identical** - the twenty numbers only ever produced `unimplemented`
entries in slots that still exist - and every row of the README table keeps its
numbers and its status. The only change is twenty rows removed, each verified to
have been unimplemented and to have had no x86-64 number, which is what a
32-bit-only syscall looks like.

Two details of real preprocessor behaviour had to be honoured to get there.
Conditions inside a branch that is not taken are **not evaluated**, only counted
for nesting - the header asks `#ifdef __NR3264_stat` about a macro nothing has
defined for years, and evaluating dead code strictly would have made that fatal.
And a symbol in the header's own `__NR`/`__SC_` namespace is the header's
business: absent means absent, not unknown.

Still 251 implemented; the denominator is now 375.

### 3.5.90 Two mount calls, one memory policy, and two that cannot exist

Five calls, and they are not the same kind of thing, which is the point worth
recording.

**`mount_setattr`** is mount(2)'s successor for the flags half of the job, and
what makes it worth having rather than a synonym for a remount is that it is
*precise*: it says which attributes to set and which to clear instead of handing
over a whole flag word and hoping the rest survive, and it can descend a subtree
in one call. Both land well on a table of rows — setting is a masked update,
`AT_RECURSIVE` is the same update on every row whose target falls under it. And
because `MS_RDONLY` is honoured by path resolution rather than merely recorded,
a mount made read-only this way genuinely starts refusing writes. That is the
only check that can tell an implementation which *applied* the attribute from one
that stored it, so it is the one `mounttest` makes; without the flag update it
reports a successful create where `EROFS` was wanted.

`MOUNT_ATTR_IDMAP` is refused. It asks for a mount's uids to be shifted through a
user namespace, which needs the owner translated on every access, and the
identity NABI keeps in an xattr is not something a mount can re-map. Accepting it
would hand back a mount whose ownership a caller believes was shifted and which
behaves as though it were not.

**`listmount`** is the newer half of the pair whose other half is `statmount`.
Reading `/proc/mounts` answers the same question; this exists because parsing a
text format that must stay compatible forever is worse than reading numbers. It
is nearly free here, since the mounts already are numbered rows and `/proc/mounts`
is built from the same table — so the two cannot disagree.

**`mbind`** is the interesting one to be honest about. There is exactly one NUMA
node here, and that is not a limitation to paper over — it is the machine. A
policy is a constraint on where pages come from, and on a single-node system
every constraint permitting that node is already satisfied by every page. So this
is **not a stub that returns success**: it checks that what was asked is
satisfiable, and then it is satisfied with nothing left to do. Which makes the
validation the whole of the implementation and worth doing properly — a nodemask
naming a node that does not exist is refused exactly as Linux refuses it, because
a program that binds to node 3 and is told yes goes on believing its memory is
somewhere it is not.

**`kexec_load` and `kexec_file_load` are refused**, and unlike most refusals here
it is not for want of a Darwin equivalent — the operation has no meaning in this
program. NABI is a Linux ABI on top of macOS: there is no kernel of its own to
replace, no boot to shorten, nothing a loaded image could be executed by. A guest
calling these is asking to reboot the machine into something else, and the
machine is not NABI's to reboot. `ENOSYS` rather than `EPERM`, deliberately:
`EPERM` says "not you", and a caller that gets it retries as root and fails
identically forever, where `ENOSYS` says the facility is absent — which is true,
and which every caller already knows how to stop at.

One limitation worth naming: `mount_setattr` takes a `dirfd` and this requires an
absolute path, as `mount(2)` here already does. A relative name would have to be
resolved against a descriptor's path, and the mount table is keyed by the guest
path a mount answers to, so there is nothing for a relative name to match until
that resolution exists.

254 of 375.

### 3.5.91 The new mount API, and the link that was not asked for

`fsopen`, `fsconfig`, `fsmount`, `open_tree`, `move_mount` are Linux's second
way to mount something, and why it exists decides how it is built here.
`mount(2)` does everything in one call — name a filesystem, configure it, attach
it — with one errno to explain whichever part failed. The new API takes those
apart: `fsopen` names a type and returns a **context**, `fsconfig` configures it
one parameter at a time so a bad option is reported against that option,
`fsmount` turns a configured context into a mount that exists but is attached
nowhere, and `move_mount` attaches it. `open_tree` is the same idea from the
other end, handing back a detached copy of an existing mount.

So a guest now holds two new kinds of object by descriptor: a context being
configured, and a mount with no place yet. Both are unlinked files with a magic
in the header — the shape the POSIX message queues use, for the same reasons. The
descriptor *is* the object, so it survives fork and the exec arm64's fork is
built on, it goes when the guest closes it, and nothing here tracks which
descriptors are live.

**`fsconfig` was not asked for and is implemented anyway**, because without it
the other two are unreachable: `fsmount` refuses a context that was never
created, and `FSCONFIG_CMD_CREATE` is the only thing that creates one. Shipping
`fsopen` and `fsmount` without it would be shipping a chain with a missing link.
Of its parameters only `source` means anything here — it is what `/proc/mounts`
shows a mount as coming from. The rest are filesystem options, and the
filesystems this can provide have none it could honour: a tmpfs here is a host
directory, so a `size=` it cannot enforce would be a limit the guest believes in
and nothing applies.

The type is checked at `fsopen` rather than at `fsmount`, which is the whole
point of the split — a caller naming a filesystem this cannot provide finds out
from the call that named it, not three calls later. That meant extracting what
backs a filesystem type out of `mount(2)`, so both ask one function rather than
growing two answers about which filesystems NABI supports.

**The test had to be made to prove something.** Its first version wrote a file
under the new mount and checked it succeeded — which it would have whether or not
anything was mounted, since the mount point is a real directory either way. It
now puts a marker in the directory first and requires it to be **hidden**
afterwards, because only a mount shadows what was underneath. With `move_mount`
made not to attach, that check reports the marker still visible; the write check
passed happily.

`statmount` completes the pair `listmount` began. There is no superblock behind
any of this — a mount here is a rewrite of a path prefix — so `sb_flags` is
reported because it is real and the device and magic are zero because they are
not, with the returned mask saying which is which. Its strings sit after the
fixed part at the offsets it reports, and the test reads them at those offsets
rather than at assumed ones; the struct's size and field positions were measured
rather than guessed, the first guess having been 536 where it is 512.

`MOVE_MOUNT_SET_GROUP` is refused: it shares a peer group between two mounts, and
propagation here is established through `mount(2)`. `fspick` is not implemented,
which is why `FSCONFIG_CMD_RECONFIGURE` answers `EOPNOTSUPP` — there is no
context it could arrive on.

260 of 375.

### 3.5.92 The auxiliary vector, and an entry whose absence is fatal

A Fedora install failed in dconf's RPM scriptlet:

```
(/usr/bin/dconf:91724): GLib-ERROR **: getauxval () failed: No such file or directory
/var/tmp/rpm-tmp.7YU0PA: line 1: 91724 Trace/breakpoint trap  /usr/bin/dconf
```

The auxiliary vector NABI built carried eight entries: `AT_BASE`, `AT_ENTRY`,
`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_RANDOM`, `AT_NULL`. Linux
supplies a good many more, and the missing ones had been assumed harmless on the
grounds that a program which cannot find an entry does without it.

**That assumption is wrong, and the reason is in how the vector is read.**
`getauxval()` sets `errno` to `ENOENT` when the entry asked for is absent, and
not every caller treats that as "no answer". GLib's `g_check_setuid()` asks for
`AT_SECURE` and calls `g_error()` if `errno` is set — and `g_error()` aborts. So
a missing entry is not a feature a program does without; it is a program that
dies. Not only dconf: every GLib program, which on a desktop install is most of
them.

`AT_SECURE` reports whether the exec crossed a privilege boundary, and the
dynamic linker uses it to decide whether to honour `LD_PRELOAD`. Answering it
wrongly in the permissive direction would matter, so it is computed from the
file's setuid bits in `do_exec`, where the mode is known — the elevation itself
happens after the image is loaded, so asking the credentials at auxv time would
report the pre-elevation state and say no for exactly the binaries it should say
yes for.

The rest went in with it, on the principle the failure established: Linux
supplies them on every exec, so an absent one is a loaded gun rather than a
missing convenience. `AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID` are the guest's ids,
which is the whole point of their being there; `AT_CLKTCK` is 100, which is what
glibc falls back to anyway, so it changes nothing except that asking no longer
sets `errno`. `AT_HWCAP` and `AT_HWCAP2` claim **no** optional CPU features, and
that direction is deliberate: glibc dispatches its string routines on them, so an
over-claim selects an implementation the guest may fault on where an under-claim
only selects a slower one that always works.

`auxvtest` walks the vector off its own stack rather than calling `getauxval`,
which is the point — it checks what NABI put there, with no libc in between to
paper over a gap. Against the previous build it reports `AT_SECURE -> 0, wanted
23`.

Still 260 of 375: this is a bug in what `execve` builds, not a new call.

`AT_EXECFN` and `AT_PLATFORM` followed, and being strings is the whole of what
made them a separate step: each needs bytes pushed onto the guest stack before
the vector is laid out, and the vector then carries a pointer to them. They go
down before the argument and environment arrays, so they end up above them —
`push()` moves the stack pointer down, so what goes first sits highest, which is
where Linux puts them too.

`AT_EXECFN` is the path `execve` was **given**, which is not `argv[0]`. A program
may pass whatever `argv[0]` it likes, and the two differing is the ordinary case
for a login shell spelled `-bash` and the whole basis of a multi-call binary like
busybox; something re-executing itself reads this to find out what to re-execute.
So it is threaded down from `do_exec`, which is where the real path is, rather
than taken from the argument vector that happens to be to hand.

`AT_PLATFORM` names the instruction set and glibc builds library search
directories out of it, so it has to be the architecture the *guest* runs — the
one NABI was built for, not the host it runs on, which on Apple Silicon are the
same and on an x86_64 build are not.

Testing a pointer needs more than testing a number. An entry that is present but
points into memory the guest cannot read, or at a string nothing wrote, passes a
presence check and fails everything after it — so `auxvtest` follows both and
reads them. Against a build where `AT_EXECFN` is a valid pointer to the wrong
thing it reports `240, wanted 47`, and against one claiming `x86_64` on an arm64
guest, `120, wanted 97`.

### 3.5.93 AT_RANDOM, which was not random

`AT_RANDOM` had been there all along, and pointed at sixteen bytes that were
never written — an uninitialised array, so whatever happened to be on NABI's own
stack at that moment. It reads as a cosmetic omission and it is not one, because
of what consumes those bytes: glibc builds the **stack canary** out of the first
eight and the **pointer guard** it mangles `setjmp` buffers and `atexit` handlers
with out of the next eight.

Five runs of the old code, dumped:

```
e053586d01000000f02ec33102000000
e0137f6d01000000f02ec33102000000
e0d3e96e01000000f02ec33102000000
e0134c6d01000000f02ec33102000000
e093656d01000000f02ec33102000000
```

The upper eight bytes are **identical on every run**, so the pointer guard was a
constant. The lower eight are a host pointer in which three bytes move with ASLR
and the rest, including the low byte, do not — so a canary that is supposed to
carry sixty-four bits of unknown carried perhaps twenty, in a known shape. A
canary that can be guessed is a canary that does not stop the overflow it exists
to stop, and nothing anywhere reports that it failed to.

`arc4random_buf` fills it now, rather than the `/dev/urandom` read `getrandom(2)`
does, because the two answer different questions. `getrandom` has to honour a
caller's choice of pool and its non-blocking flag, so it must read from the
source the caller named. Nothing chose anything here: this needs sixteen good
bytes in the middle of building a process image, with no way to report a failure
and nothing sensible to do about one — and `arc4random_buf` cannot fail.

**The test for this had to be built differently from the others**, and the old
values show why. They are not all-zero and not all-identical, so every check that
looks at one run's bytes passes on them. What is wrong with them is only visible
*between* runs, so `run.sh` runs the dump twice and requires the two to differ.
No single run can tell random bytes from bytes that are merely always the same.

### 3.5.94 process_vm_readv and process_vm_writev — one side of two

These copy between the address spaces of two processes without either agreeing
to it, and on Linux that works because the kernel is on both sides of the copy.
Here the two sides are two *host* processes, and there is no way into the other
one. Three separate things stand in the way, and it is worth listing them
because any one alone might have been worked around:

The arena that names guest memory is created and **immediately unlinked**, so it
has no name a sibling could open; the descriptor reaches only the children that
inherited it across the exec. The running guest's mappings are `MAP_PRIVATE`, so
the arena does not hold what the guest currently has anyway — it holds what was
written at the last handover, and `src/mm/arena.c` explains why that is
deliberate: sharing it would take copy-on-write away from `fork` and let the two
halves of `cmd | cmd` write over each other. And a guest address means nothing
without the region table that translates it, which is process memory belonging to
the process that owns it.

Darwin does offer `mach_vm_read_overwrite` through a task port, but
`task_for_pid` on another process wants root and an entitlement NABI does not
carry — and it would still leave the third problem untouched.

So the same-process form is implemented and the cross-process form is refused.
That is less narrow than it sounds: the call is defined for a process to use on
itself, where it is a gather-scatter copy that skips the intermediate buffer a
`readv` into a `writev` would need. But it is not what most callers want, and
they are told so rather than handed a wrong answer. **`EPERM`, not `ENOSYS`** —
`EPERM` is what Linux says when the ptrace access check fails, so every caller
already has a path for it, usually falling back to `/proc/pid/mem`; `ENOSYS`
would claim the call does not exist, which is untrue of the half that works.

Two details the test pinned down. The vector walk is the part that is easy to get
wrong: the two sides are gathered and scattered **independently** and need not
have matching shapes, so the test reads three remote pieces into two local ones
and an implementation that pairs them entry by entry reports 8 of 10.

And "no such process" had to be told from "not allowed". `pidns_to_host` is the
identity outside a pid namespace, so a translated number proves nothing about
whether anything is there — the first version answered `EPERM` for a pid that did
not exist. The process is now actually looked for, with `kill(pid, 0)`, which is
the same test Linux would be making.

262 of 375.

### 3.5.95 process_madvise, process_mrelease — and the pidfd they needed

Both name their target by **pidfd**, and there was no way for a guest to obtain
one: `clone3` refuses `CLONE_PIDFD`, `pidfd_getfd` does not exist. Implementing
the two asked for would have been implementing two calls nothing could invoke,
so `pidfd_open` came with them — the same judgement `fsconfig` got.

A pidfd is an unlinked file with a magic and a pid, the shape the message queues
and mount contexts use. The hard part is that a pidfd must become **readable when
its process exits**, and Darwin has no descriptor that does that. It is answered
where every readiness question here is answered — `poll`, `select` and `epoll`
are NABI's own, and they ask whether the process is still there.

**That hook had to work in the opposite direction from the others.** Every
previous one *adds* readability: `tee` holds bytes the host does not know about.
A pidfd is a file, and the host calls a file readable **always**, so an
additive hook reports every pidfd ready from the moment it is made. The answer
has to *replace* what the host said, which is why `poll`, `select` and `pselect6`
each got a distinct fixup rather than another clause in the tee one. The test
that catches this is the one asserting a *running* process is not readable.

`epoll` then needed the reverse, and finding out why was the useful part. kqueue
raises no read event for a regular file at all — so there was nothing to suppress
and, worse, an exited pidfd would never be reported either. An event loop waiting
on one would have waited forever. It is added to the same pre-wait scan that
surfaces tee's pushback.

**A pre-existing bug fell out of writing that test.** `epoll_ctl` answered
`EEXIST` adding a descriptor to a *fresh* epoll instance. Registrations are keyed
by `(epfd, fd)` and were never removed when the epoll descriptor closed, so a
later `epoll_create1` landing on the same number inherited the old ones. Two
epoll instances in one process is not exotic; it is what an event loop does when
it re-creates its poller. There is now a close hook, alongside the ones inotify,
fanotify, timerfd and io_uring already had.

On the two that were asked for. `process_madvise`'s advice is **purely
advisory** — the set it accepts is `COLD`, `PAGEOUT`, `WILLNEED`, `COLLAPSE`, and
Linux deliberately excludes the destructive `MADV_DONTNEED` and `MADV_FREE`
because those change what a read returns. So a kernel that takes the hint and
does nothing is inside the contract, and reporting the range as processed is
true rather than a polite fiction. Ranges are still checked for being mapped,
because an advisory call must still say `EFAULT` for memory that is not there.

`process_mrelease` is **not** like that, and the difference is written down
rather than glossed. What it promises is that a dying process's memory is freed
*now*, and NABI cannot free another process's memory at all. Every input it can
be given gets the answer Linux would give — a target that is not dying is
`EINVAL`, one that is gone is `ESRCH`, another process is `EPERM` — but there is
no input on this system for which it would do the work.

The cross-process half of both is refused for the reasons `process_vm_readv` sets
out: a guest process is a host process with its own guest memory, and nothing
here reaches into another one.

**One thing found and not fixed here.** `madvise` itself is a stub — it prints
"madvise is not implemented" and returns 0 — while the generated table marks it
implemented, because the table marks by the presence of a handler and cannot see
that the handler does nothing. `mlock` and `munlock` are the same. That
overstatement predates this work and is left alone rather than folded in.

265 of 375.

### 3.5.96 A recorded mode that could not have been recorded

A Fedora install could not run `waydroid`, and the failure was Python's:

```
Fatal Python error: Failed to import encodings module
PermissionError: [Errno 13] Permission denied:
    '/usr/lib64/python3.14/encodings/__init__.py'
```

The file was `0644` on the host, owned by the user NABI runs as, on APFS with
extended attributes working. `stat` from inside the guest reported
`--w------- 1 0 0` — mode `0200`, and `0200` denies read to everyone, so a
non-root guest could not open it. The number came from `msl.nabi.mode`, the
attribute NABI keeps a guest mode in when the host cannot carry it.

**The pair is the evidence.** `guest_mode_record` writes that attribute and sets
the host mode together, and the host mode it sets is always `record | 0600` — or
`| 0700` for a directory, since NABI must be able to look inside one. A record of
`0200` against a host of `0644` is therefore not merely surprising, it is
*arithmetically impossible* for this code to have produced: `0200 | 0600` is
`0600`, not `0644`. Something wrote the record and something else later changed
the host mode without going back to it.

That gives an exact test for a stale record, and — this is the part that needed
care — it is not "the record is restrictive". A sweep of the tree found
`/etc/shadow` recording `0000` against a host `0600`, and `/usr/bin/sudo`
recording `04111` against a host `0711`. Both deny read to somebody, both are
precisely what `guest_mode_record` writes, and both are correct. A rule that
threw away records denying read would have thrown away the shadow file's
protection. What is thrown away is only a pair that **disagrees**.

So a record the host mode contradicts is now discarded on read, and the
attribute removed — the repair happens once rather than on every stat, and a
tree that has been read ends up describing itself correctly. `staletest` covers
both directions, as an ordinary user, because root short-circuits `cred_may` and
would never have met any of this. Against the previous code it reports mode
`128` where `420` was wanted, which is `0200` where `0644` belongs.

Two things about the original damage are worth recording. `dnf reinstall
python3-libs` repaired every `.py` file it owned, which says the version of NABI
that wrote those records has since been fixed and the current one is sound. And
the `.pyc` files were *not* repaired, because they were never the cause:
CPython's `_cache_bytecode` derives a bytecode file's mode from its source's —

```python
mode = _path_stat(source_path).st_mode
mode |= 0o200
```

— so with the `.py` reading `0200`, every `.pyc` was created `0200` and NABI
recorded faithfully what it was asked for. The cascade is the clearest argument
for self-healing rather than a sweep: a wrong mode does not stay where it was
written.

Still 265 of 375: this is a bug in what a recorded mode means, not a new call.

### 3.5.97 The rest of the pidfd family

`pidfd_open` arrived because `process_madvise` needed an input. What it did not
have was anything to *do* with the descriptor, which is most of the point: a pid
is a name that can be reused, and between deciding to signal a process and
signalling it that process can exit and its number pass to a stranger.

`pidfd_send_signal` closes that window, and `CLONE_PIDFD` closes it one step
further back — the parent is handed a descriptor at the moment the child appears,
so nothing can have taken the pid in between, because the parent has not returned
to its own code yet. That is why the descriptor is made on the parent's side: the
child could make one for itself, but by the time it ran the parent would already
have had to be told a number.

The guarantee here is narrower than the kernel's, and the difference is worth
stating rather than implying. Linux's pidfd holds a reference to the process, so
the pid cannot be recycled while the descriptor lives. Nothing on Darwin makes a
pid stop being reusable, so a pid recycled after the descriptor was made would
still be signalled. What *is* removed is the window between the caller's decision
and the call — the one a program can do nothing about. What remains is the window
a program closes by holding the descriptor, exactly as it would on Linux.

A `siginfo` is refused rather than dropped. Supplying one makes this
`rt_sigqueueinfo` — the signal carries a value — and NABI's delivery has no way
to attach one, so a receiver reading `si_value` would get whatever the host put
there. A caller that needs the value learns it did not travel; a caller that does
not passes NULL and this is `kill`.

`pidfd_getfd` is a debugger's operation and meets the wall `process_vm_readv`
describes, so the cross-process half answers `EPERM`. A process naming itself is
`dup` with the race removed, and that half is real — the test writes a pipe and
reads it back through the copy rather than checking a number came out.

`clone3` no longer refuses `CLONE_PIDFD`; the comment there said it was a wiring
job rather than an impossibility, and this is the wiring. `do_clone`'s own list
of accepted flags had to learn it too, or the clone was refused before reaching
the code that handles it. `CLONE_PIDFD` with `CLONE_PARENT_SETTID` is refused, as
on Linux: the old `clone` has no field of its own, so the descriptor goes where
the parent tid would have, and two answers cannot share one place.

One check came out again during testing. `pidfd_send_signal` had a liveness test
before the signal, and deleting it changed nothing — `send_signal` already
answers `ESRCH` for a process that has gone. Code no test can distinguish is
weight without evidence, so it went.

267 of 375.

### 3.5.98 --user, so that a missing package cannot put a guest back on root

A fresh Fedora tree logged in as root:

```
$ msl login fedora
msl-shell: this image has no su, so this is a root shell.
[root@redstar ~]#
```

That message was working as designed, and the design was wrong. NABI starts
every guest at uid 0 — the account it runs as is what the guest sees as root —
and had no way to start as anyone else, so becoming a user meant running `su`
*inside* the guest. Fedora's base image ships `util-linux-core`, which has no
`su`, because containers are entered with `docker exec -u` and nothing there
needs one. `msl-mkrootfs` knows this and installs `util-linux` afterwards; when
that step does not take, there was no way in and the fallback was a root shell.

**A root shell is the wrong floor**, and `nabi-shell.sh` says so itself a few
lines above: running as root by default is how a tree accumulates root-owned
files the account cannot then touch. It also hides every fault only a normal
user meets — the `0200` mode records that stopped Python importing `encodings`
were invisible for exactly as long as everything ran as root, which is most of
why they survived to be found by `waydroid`.

So NABI grew `--user uid[:gid]`, and it is deliberately the *floor* rather than
the preferred path. `su -` is still tried first, because it builds the
environment, the working directory and the supplementary groups from the guest's
own login path rather than from an approximation made outside. `--user` sets the
credentials and nothing else, which is why `nabi-shell.sh` supplies the
environment itself when it uses it — and why the one thing it cannot supply is
written down where it will be read: there are **no supplementary groups**, so an
account in `wheel` or `video` in the guest's `/etc/group` is not in them here.

The second half is the builder. Its failure printed two quiet lines and left a
tree that logged in as root — a shape of failure nobody investigates, because
the consequence appears at first login and looks like how the thing works. It
now says what happened, what still works, what does not, and the one command
that fixes it.

No new syscalls: `--user` is an option, not a call.

### 3.5.99 Fourteen at once, of three different kinds

A batch, and the interest is in how unlike each other they are.

**Four cannot exist here, and each for its own reason.** `bpf` loads programs
into a kernel to run at its hook points, and there is no kernel — no
tracepoints, no verifier, nothing that could execute one. `add_key` wants
kernel-held storage whose payload userspace cannot read directly; anything NABI
kept would sit in the same address space as the program asking, which is not a
keyring but a variable, and approximating it would be a security claim that is
false. `acct` needs a single place every process exit passes through, and here a
guest process is a host process reaped by another NABI. And `clock_settime` would
step a clock the whole machine shares — the guest is not the administrator of
this computer — so it answers `EPERM`, which is what Linux answers without
`CAP_SYS_TIME` and which `date -s` already knows how to report.

**Four are the same call with less in them**, kept so that programs built against
older headers still run: `epoll_create` is `epoll_create1(0)` with the size hint
that has meant nothing since 2.6.8, `epoll_wait` is `epoll_pwait` with no mask,
`eventfd` is `eventfd2` with no flags. Delegation rather than reimplementation,
so they cannot drift.

**The rest do real work**, and each was tested on the one thing that separates it
from the call it resembles — which is where two of them were wrong.

`adjtimex` and `clock_adjtime` read the clock's discipline through Darwin's
`ntp_adjtime`, which is the same interface under its BSD name, and refuse every
mode that would write. The refusal comes before anything is applied, so a caller
cannot get half an adjustment. Darwin's `struct timex` has no `tick`; it is left
zero rather than invented, since a caller comparing it against `USER_HZ` would be
comparing against a number nobody set.

`close_range` closes a span without asking what is in it — the thing that made
pre-exec cleanup a million syscalls on a machine with a large rlimit.
`CLOSE_RANGE_CLOEXEC` **marks** instead, and the first version set only NABI's
own bitmap: `F_GETFD` reported 0, because it reads the host flag. `F_SETFD` sets
both, and so does this now — one without the other is a descriptor that is
close-on-exec to whichever asks first.

`fchmodat2` is `fchmodat` with the flags argument it should always have had, and
`AT_SYMLINK_NOFOLLOW` is the whole point: Linux never honoured it on `fchmodat`,
so a caller needing it had to open the file and use `fchmod`. The first version
put the mode on the *target* and left the link alone — precisely the behaviour
this call exists to replace, arrived at by accident, because the lookup was not
told `LOOKUP_NOFOLLOW` and followed the link before the code saw anything.

`execveat` needed a guest path for a descriptor, and NABI has no reverse mapping
from a host path to a guest one. It does not need one: `/proc/self/fd/<n>` *is*
that mapping expressed in the guest's own namespace, procfs already serves it,
and it is what glibc's `fexecve` falls back to anyway. So a descriptor becomes a
path the ordinary machinery resolves rather than a special case beside it.

`fspick` builds a context for a mount that already exists, which is the new API's
remount — and it makes `FSCONFIG_CMD_RECONFIGURE` reachable, which had been
answering `EOPNOTSUPP` with a note that no context could arrive on it. There is
one now.

278 of 375.

### 3.5.100 accept4 and kcmp; ioperm, iopl and keyctl

Five, and one of them turned up a bug in a call that was already there.

**`accept4` is `accept` plus two flags**, and the obvious way to add it — call
`accept`, then set what was asked for — is wrong twice over.

The first reason is the one `SOCK_CLOEXEC` exists for. Setting close-on-exec
after the descriptor already exists reopens exactly the window the flag was
invented to close: another thread can `exec` in between, and the descriptor
leaks. The flag would then be doing nothing except in the single-threaded case,
where it was never needed. So the flags are threaded into `do_accept` and
applied on the way, and both entry points go through it.

The second reason is that macOS and Linux disagree about what an accepted socket
starts as, and this was measured rather than assumed. Linux hands back a
blocking descriptor whatever the listening socket was; the BSD lineage passes
the listening socket's status flags down. A listening socket put into
non-blocking mode, accepted from with no flags at all, produced `F_GETFL` of
`0x802` — `O_RDWR|O_NONBLOCK`. That is not an `accept4` gap, it is what plain
`accept` had been doing since it was written: a server that set its listener
non-blocking got non-blocking connections, and every read on one returned
`EAGAIN` where Linux would have blocked. Both flags are now *set to* the
asked-for state rather than turned on, which makes the answer the same
whichever way the host would have gone, and fixes `accept` as a side effect.

**`kcmp` asks a question only a kernel can answer**, and the honest reply here
is in two halves.

The process-wide types — `KCMP_VM`, `KCMP_FILES`, `KCMP_FS`, `KCMP_SIGHAND`,
`KCMP_IO`, `KCMP_SYSVSEM` — are answered exactly when both sides are the calling
process, because a process shares all of those with itself. That is the true
answer and not a shortcut. Anything naming another process meets the wall
`process_vm_readv` documents, and gets `EPERM` — after `kill(pid, 0)`, so that
"no such process" stays distinguishable from "not allowed".

`KCMP_FILE` is the type callers actually use, and it is about the open file
description rather than the file. Darwin will say which *file* a descriptor
names and usually not which description, so two independent opens of one path
and one descriptor duplicated look identical — which is precisely the pair the
call is asked to tell apart. Pipes and sockets are the exception:
`proc_pidfdinfo` hands back the kernel's own handle for the object, and the only
ways to get two descriptors onto one pipe end or one socket — `dup`, `fork`,
`SCM_RIGHTS` — all share the description. Those are answered exactly, with
Linux's 1/2 ordering so a caller sorting descriptors gets a stable result.
Everything else is refused with `EOPNOTSUPP`.

Refused rather than answered from `st_dev` and `st_ino`, and the smoke test
checks that specifically: two opens of the same directory must not compare
equal. A caller told the wrong answer acts on it somewhere further away; a
caller told the question cannot be answered here takes its fallback.

`KCMP_EPOLL_TFD` is answerable, because NABI's epoll registrations are its own
and are where the truth lives. The set is walked and each entry compared by
description — and when none matched but one comparison was undecidable, the
answer is `EOPNOTSUPP` rather than "absent", because a negative built out of a
comparison that failed is a guess.

**Three cannot exist.** `keyctl` is the rest of `add_key`'s family and absent
for the same reason: much of it is about the keyring rather than the keys, and
those rings are per-process kernel state inherited across `fork` and reshaped on
`exec`. There is no such state here, so a ring cannot be joined or described
either.

`ioperm` and `iopl` grant access to the x86 I/O port space. Neither has an
aarch64 number — aarch64 has no port space to be granted — so they are here for
the x86_64 table, where a guest can reach them. Refused there too, and not as
policy: they ask for a change to the privilege state of a task, macOS does not
offer it to anybody, and a guest driver poking at ports would be addressing
hardware this machine does not have. `ENOSYS` rather than `EPERM`, because
`EPERM` sends a well-written caller off to acquire the privilege and try again,
and there is nothing to acquire.

280 of 375.

### 3.5.101 cachestat, capabilities, and six that need a kernel

Eleven calls, and the interesting part is how differently "there is no kernel
here" lands on each of them.

**cachestat can be answered, and it was worth checking rather than assuming.**
It reports five numbers about a file range, and the first plan was to refuse it
outright on the grounds that Darwin does not keep a page cache the way Linux
does. That turned out to be wrong. `mincore` over a read-only shared mapping
reports residency in the unified buffer cache and not the faults the mapping
itself has taken: a file just written reads back fully resident through a
mapping nothing has touched, and a file this process has never opened reads back
as zero. That is the same quantity `nr_cache` counts. The measurement does not
disturb what it measures, since nothing faults a `PROT_READ` mapping that is
never read.

Getting there took one wrong turn worth recording. The first experiment said
`mincore` was reporting a constant 1024 pages whatever the file was doing, which
looked like a hard limit and nearly ended the idea. It was not: Apple Silicon
has 16KiB pages and the vector was being indexed in 4KiB units, so exactly one
byte in four was being read. The same page size is why `cachestat`'s unit needs
no conversion — the guest's `AT_PAGESZ` *is* `STAGE2_GRANULE` — and since that
equality is load-bearing it is checked at runtime instead of assumed.

The other four fields stay zero, and that is a real limitation rather than a
tidy default: Darwin exposes no per-file dirty or writeback count and keeps no
shadow entry for an evicted page. A caller reading `nr_dirty` gets a wrong
answer. It is the one place in this batch where something is claimed that is not
known, and it is claimed because `nr_cache` — the field the call is named for —
is worth having.

**capget was already marked implemented and was returning uninitialised memory.**
It printed "capget is unimplemented", returned 0, and wrote nothing to the
caller's buffer, so a program read back whatever its own stack held and believed
it was the capability set. That is the AT_RANDOM fault again in a different
place: a security-relevant answer made out of nothing, arriving with a success
return that every caller checks.

The model now is the one nabi implements everywhere else. Privilege here is
`euid == 0`, so guest root holds every capability up to `CAP_LAST_CAP` and
nobody else holds any — which makes capget agree with what a caller will find
when it actually tries the operation. `capset` records what it is given, and
enforces the two rules a caller can be wrong about: effective may not exceed
permitted, and neither may gain a capability the process does not already hold.

What it does *not* do is enforce the recorded set, and that gap should be
stated rather than discovered. A daemon that drops `CAP_SYS_ADMIN` and stays uid
0 will see the drop in capget and will still be allowed to mount. Making that
real means every privileged check in nabi consulting a capability set instead of
a uid, which is a larger change than this one. Recording is still strictly
better than the two alternatives: refusing breaks daemons that treat a failed
drop as fatal, and ignoring is how the round trip lies.

**The version handshake matters more than it looks.** libcap calls capget with a
version of 0 to discover which ABI to use, and expects the kernel to correct the
header in place and fail. A capget that accepted anything would break that
discovery in a way that only shows up later.

**futimesat is x86-only, and adding it found a bug in utimes.** Neither call has
an aarch64 number - every timestamp on this architecture goes through
`utimensat` - so this is for the x86_64 table. Both carry `struct timeval`,
seconds and *micro*seconds, and `utimensat` carries `struct timespec`, seconds
and nanoseconds. The two are the same shape and different units, so `utimes`
delegating straight to `utimensat` compiled, ran, and recorded a microsecond
count as a nanosecond one: x.500000 landed as x.000500. Only the fractional part
was wrong, which is why nothing noticed, and APFS stores nanoseconds, so it was
wrong on disk rather than merely in transit.

Being x86-only means the arm64 smoke suite cannot call either of them, and this
host cannot run an x86_64 guest. What the test does check is the half that is
reachable: that `do_utimensat` records the fractional second it is given rather
than rounding it away, which is the sink both calls feed and without which the
conversion would be pointless. The multiply itself is unexercised, and that is
worth knowing.

**getcpu has to ignore the host's answer.** `pthread_cpu_number_np` is real and
returns a real core, and passing it on would be wrong: `sched_getaffinity`
offers this guest exactly one CPU and `sched_setaffinity` rejects a mask without
CPU 0 for that reason. A program that sizes a per-CPU array from its affinity
mask and indexes it by `getcpu` would be handed a 6 by a machine that told it
there was one CPU. Zero is the truthful answer in the only numbering the guest
has. The smoke test checks it against the affinity mask rather than against a
constant, which is what catches the host number being passed through.

**The LSM three are answered rather than refused**, because "no module is
loaded" is true and useful. `lsm_list_modules` reporting zero is exactly what a
caller checking for SELinux or AppArmor needs; `ENOSYS` would send it off to
`/proc/self/attr` to ask the same question again. The other two answer
`EOPNOTSUPP`, which is what Linux says when no loaded module handles the
attribute — here that is all of them.

**And six module calls cannot exist.** A module is native code linked against a
running kernel's symbols and run in its address space; what a guest is talking
to is a userspace process translating syscalls. Six rather than the four asked
for, because the family only makes sense together — refusing `finit_module`
while `init_module` answered nothing at all would leave modprobe taking
whichever path happened to look supported. Three of them (`create_module`,
`get_kernel_syms`, `query_module`) Linux removed in 2.6 and answers `ENOSYS`
for, so on those this agrees with the kernel exactly.

287 of 375.

### 3.5.102 memfd, real memory locking, and a sandbox that is refused

Twelve calls, and the theme is which of them can be told the truth.

**memfd_create is the one desktop software needs.** It is the unlinked-file
pattern again — create, unlink immediately, hand back the descriptor — the same
one behind message queues, io_uring rings, mount contexts and pidfds. The
descriptor *is* the object: it survives fork and exec, it goes over a unix
socket with `SCM_RIGHTS`, two holders share one file, and the storage goes when
the last one closes. That is memfd's contract exactly, so it needs no side table
and no cleanup path. `wl_shm` passes one of these for every Wayland buffer and
dbus uses them for large messages, so its absence is felt well before anything
exotic is.

Sealing is what it cannot do. `F_ADD_SEALS` is how a sender promises a receiver
that a shared buffer will not change underneath it, and a seal is enforced by the
kernel on every write — there is none here to enforce it. So `MFD_ALLOW_SEALING`
is accepted, because all it does is permit a later seal, and the later seal is
what fails: `fcntl` answers `EINVAL`, which is what Linux answers for a file that
does not support sealing. The caller finds out at the point where it still has a
choice — decline to trust the buffer — rather than being told a seal was applied
that nothing honours.

**mlock and munlock were stubs, and of everything in this tree they were the
worst ones to be.** They printed a line and returned 0 while the table said they
worked. The callers are gpg and ssh-agent, locking a buffer so a passphrase
cannot reach swap; success without locking is precisely the answer that leaves
the secret swappable while the program believes otherwise.

The lock is real now, and that was checked rather than assumed: guest memory is
host memory — a private mapping of the arena — so a guest range translates to a
host range, and Darwin's `mlock` wires it. Measured directly, a 4MiB anonymous
mapping goes from 0 of 256 pages resident to 256 of 256 across the call. It does
not promise anything about the guest's view of physical memory, which nabi does
not own; it pins the host page under the stage-2 mapping, which is the half
mlock exists for.

Two flags are refused rather than approximated, and it is the same judgement
each time. `MLOCK_ONFAULT` says *do not populate now*, and Darwin's mlock wires
what it is given — so honouring it by ignoring it would populate exactly the
range the caller paid a syscall to avoid populating. `MCL_FUTURE` promises that
later mappings are locked too, and `do_mmap` knows nothing about it, so
accepting it would mean a program that locks everything and then allocates its
secret buffer finds the buffer unlocked. In both cases `EINVAL` sends the caller
to plain mlock, which is what it would have got — knowingly.

`mlockall` walks the guest's regions rather than calling Darwin's `mlockall`,
which would lock nabi's own heap, its stacks and the whole arena including
memory belonging to no live mapping.

**The smoke test checks mlock on its failures**, because a guest cannot observe
that a lock took effect. A range that is not mapped must be `ENOMEM`, and the
stub returned 0 for every address in the machine — so that one check is the
whole discriminator, and a range that starts inside a mapping and runs off its
end covers the per-region walk.

**migrate_pages has one node**, so nothing was left behind and zero is the
truthful count rather than a convenient one. A mask naming node 1 is refused: a
caller asking to move pages somewhere that does not exist has misunderstood the
machine, and confirming the move would confirm the misunderstanding.

**membarrier is answered only as far as it can be.** Its query reports no
commands, and every command then says `EINVAL` — which is what Linux says for a
command its kernel does not support, and what liburcu, Go and .NET all check
before using one. The expedited commands *could* be built here:
`vmm_kick_other_vcpus` already forces every other thread out of `hv_vcpu_run`,
and leaving and re-entering the hypervisor is a full barrier on that core. But
it is fire-and-forget, and membarrier may not return until the barrier has
happened everywhere. That needs a per-vCPU acknowledgement in the run loop of
both backends and a decision about threads sitting in a nabi syscall rather than
in guest code at the moment of the kick. Bugs there would be rare, silent and
about memory ordering — undebuggable from inside the guest — so it is a change
that deserves its own commit rather than the end of a batch.

**Landlock is refused, and this is the refusal here that is least about Darwin.**
nabi is in the right position to enforce it: every guest path goes through its
own lookup, which is the chokepoint Landlock hooks. It is refused because a
partial one is worse than none by a wide margin. `landlock_restrict_self`
returning 0 is a program's signal that it is now confined, and what it does next
is handle the input it did not trust. There are on the order of fifty
path-taking syscalls here, and a ruleset enforced at forty-nine of them is not a
sandbox with a gap — it is a sandbox that reports success and does not hold, and
no caller can check which it got. `ENOSYS` is also what the API expects: the
documented probe is `landlock_create_ruleset` with
`LANDLOCK_CREATE_RULESET_VERSION`, and callers already handle its absence.

**And three more that cannot exist.** `memfd_secret` returns memory removed from
the kernel's own direct map — a guarantee made by the kernel against the kernel,
and there is no such boundary here to remove anything from. `map_shadow_stack`
wants a return-address stack the *processor* maintains and checks; Apple Silicon
has no GCS and the Hypervisor.framework exposes nothing that would, so a mapping
from here would be a stack the guest believed was protected. `lookup_dcookie`
was oprofile's way of naming a file without holding a reference to it, and Linux
removed it in 6.6 — so this agrees with the kernel and not merely with the
hardware.

293 of 375.

### 3.5.103 mseal, and the difference between refusing and enforcing

Fifteen calls, and the one that matters most is the one that had to be argued
against the previous batch.

**mseal is implemented, and Landlock was refused, for the same reason.** Both
are hardening primitives whose whole value is that they hold; both return 0 to
tell a program it is now safer than it was; and a program's next act is to rely
on it. The difference is whether the enforcement surface can be enumerated.
Landlock's is on the order of fifty path-taking syscalls spread across the tree,
and forty-nine of fifty is not a sandbox with a gap. mseal's is four functions
in one file — `mmap` with `MAP_FIXED`, `mprotect`, `mremap`, `munmap` — and
`do_munmap` underneath them, which is the list in full and short enough to check
by reading it. `pkey_mprotect` is a fifth only because it delegates to
`mprotect`, and the smoke test confirms the seal reaches it that way rather than
assuming it.

The seal travels in the checkpoint, and that is not bookkeeping. A fork here is
a fork plus an exec: the child rebuilds its address space from the record, so a
seal left out of it comes back cleared and the child is quietly less protected
than its parent with nothing in either of them saying so. The test forks and has
the child try to unmap the sealed page, reporting through its exit code —
and dropping the restore line does make it fail, which is the only way to know
the record is doing anything.

It also has to *not* over-reach. Sealing splits the region so that the pages
either side stay ordinary; a check written against the whole region instead of
the requested range passes every "does the seal hold" test and breaks the
program in a way nobody would look for. That is its own case in the test.

**mincore is the same measurement cachestat makes, one level down** — Darwin's
mincore over the host address a region translates to, since guest memory is host
memory. Only the low bit is written: Linux calls the rest of the byte reserved
and Darwin has flags of its own up there, and passing those through would hand a
guest another operating system's bits in a field its headers say is zero. The
test touches four pages of eight and requires the answer to move, which is the
discrimination cachestat needed a second attempt to get.

**The preadv family has a trap in its calling convention.** The offset arrives
in two halves, and on a 64-bit machine only the low one carries it — the kernel
builds it with a *double* shift, `((high << 32) << 32) | low`, which shifts the
high word clean out. glibc knows this and passes a single argument, so the fifth
register holds whatever was left in it. An implementation that reads it turns a
correct call into a wild offset.

Worth recording: the first attempt to test this failed to test anything. Breaking
the code to use the kernel's own double-shift expression changed nothing,
because on a 64-bit word that expression *is* just the low half — which is the
point of writing it that way. The break that discriminates is the naive single
shift, and only after switching to it did the check start catching anything.

`preadv2` and `pwritev2` add flags and an offset of -1. The -1 form is `readv`
and `writev`, and it has to be those rather than a positional read at the
current offset, because the stream calls go through `file->ops` and pick up
tee's pushback — a reader that switches to `preadv2(-1)` must not see a
different stream. `RWF_APPEND` finds the end with `fstat` rather than setting
`O_APPEND` on the descriptor, which is shared state another thread would see.
`RWF_HIPRI` and `RWF_NOWAIT` are refused: the first wants polled completion on a
device queue that is not here, and the second wants `EAGAIN` instead of a block,
which Darwin will not promise for a regular file — and answering it by blocking
is precisely what a caller using it to keep an event loop responsive cannot
afford.

**move_pages answers the question it is usually asked.** With a NULL nodes array
it only wants to know where the pages are, and every page that exists is on node
0 because that is the only node; one that is not mapped gets `-ENOENT` in its
own status slot rather than failing the call. A move to node 0 is already done,
and a move anywhere else is refused per page.

**personality records only what it can honour.** `ADDR_NO_RANDOMIZE` is accepted
and that is not a courtesy — nabi does not randomize the layout it builds, so a
guest asking for a predictable address space is asking for what it already has,
and `setarch -R` works. `READ_IMPLIES_EXEC`, `UNAME26` and `MMAP_PAGE_ZERO` are
refused rather than stored, because storing them would let a caller read its own
request back and conclude it took effect, which is what the query is for.

**Protection keys need a register that is not here** — PKU on x86, POE on newer
arm64, neither exposed by the Hypervisor.framework. So `pkey_alloc` fails, and
that makes the rest consistent rather than arbitrary: no caller can hold a key,
so every key passed to `pkey_mprotect` is one that was never allocated. The
exception is the one that matters — `pkey_mprotect` with a pkey of -1 means "no
key" and is defined to be exactly `mprotect`, so code that calls it
unconditionally works here without a second path.

**pivot_root is refused for a specific reason worth writing down.** nabi does
have a root and resolves every guest path against it, but `proc.fileinfo.rootfd`
is opened once at startup from `-m`, and `chroot` already refuses anything but
`/` for exactly that reason. pivot_root cannot be more capable than chroot when
both need the thing chroot has not got — and it needs more besides, since
container runtimes pivot and then unmount the old root through `put_old`.
Satisfying the call while losing the old filesystem would move the failure to
the unmount. The order of work is a real changeable root first, then this.

`perf_event_open` wants a PMU macOS does not expose to unprivileged userspace at
all, and `modify_ldt` wants descriptor tables that belong to the VMCS nabi
programs. `pause` is implemented but is an x86-only number, so like `futimesat`
the arm64 suite cannot call it; it is the same wait loop `rt_sigsuspend` uses,
and that one is reachable.

303 of 375.

### 3.5.104 A flag that was never accepted, and a chown that never happened

A field report: on a fresh Fedora 43 tree, `dnf install waydroid` came apart.
Every package that creates a system user failed its `%sysusers` scriptlet, the
transaction rolled back, and the message was the same each time:

    Failed to copy permissions from /etc/group to /etc/.#group3b88ba9dd9e81906:

dnf truncated the line at the terminal width, which took the `%m` off the end -
so the one piece of information that mattered, the errno, was missing. Reading
it as written, it looks like an ownership or a mode problem, and that is where
the first look went.

Running `systemd-sysusers` directly under nabi printed the whole line:
`Invalid argument`. And nabi's own strace named the call:

    fchmodat2(dirfd: 27, path_ptr: "", mode: 0644, flags: 0x1000) = -EINVAL

`0x1000` is `AT_EMPTY_PATH`. systemd's `copy_rights()` sets the mode of a
temporary file by descriptor, which is what `fchmodat2` was added to Linux to
make possible - `fchmod` cannot take an `O_PATH` descriptor, and the old dance
through `/proc/self/fd` needs `/proc` mounted. nabi's `fchmodat2` accepted
`AT_SYMLINK_NOFOLLOW` and refused everything else, which is a flags check
written for the flag the call was implemented *for* rather than for the flags it
has.

**The second wall was found by looking rather than by hitting it.** systemd's
`fchmod_and_chown` sets a mode and an owner on one descriptor together, so
`fchownat` was going to be asked the same thing one line later - and it had the
same narrow check. Fixing only the first would have moved the failure by a line.

**And the third was found by the test.** Routing `fchownat`'s empty-path form to
`fchown` made it succeed and change nothing, because `darwinfs_fchown` was a
no-op:

    static bool
    chown_is_noop(l_uid_t uid, l_gid_t gid)
    {
      (void) uid; (void) gid;
      return true;
    }

The comment above it explained that ownership cannot persist, since every file
the guest sees is really owned by the one account nabi runs as. That was true
when it was written. It stopped being true when guest ownership arrived:
`fchownat` records the guest's answer in `msl.nabi.owner` and `stat` reads it
back through `guest_owner_overlay`. Only the by-descriptor form was left on the
old model, so `chown` on a path persisted, `fchown` on the same file did not,
and both returned 0 - so nothing in the guest could tell which it had used. The
read side by descriptor already existed (`guest_owner_overlay_fd`, via
`fgetxattr`); it was only the write side that was missing.

Recording by descriptor rather than by looking the path up is also the better
half of the pair, since it keeps working for a file that has already been
unlinked - which is what a program building a file atomically is holding.

**The near-miss is worth recording too.** `AT_FDCWD` with an empty path means
the working directory rather than descriptor -100, so that case rewrites the
path to `"."`. The first version of the fix did the rewrite and then handed
`sys_fchmodat` the guest's *own* pointer, re-reading the empty string it had
just replaced. It compiled, and the ordinary cases all passed. Factoring
`do_fchmodat` to take the string is what made the rewrite reach the lookup, and
that case is in the test because a wrong answer there is silent.

The test checks the mode and the owner actually *changing*, not the calls
returning 0. A stub that accepted `AT_EMPTY_PATH` and did nothing would have
satisfied systemd completely and left every file it touched at the temporary
0600 - which is a worse failure than the EINVAL, because nothing reports it.

No new syscalls: 303 of 375.

### 3.5.105 seccomp, credentials, and the first step towards Wayland

Seven syscalls and the beginning of a feature.

**seccomp is implemented, and Landlock is still refused.** These two look alike
- both are hardening primitives, both are believed the moment they return 0 -
and the batch that refused Landlock gave the reason: whether the enforcement
surface can be enumerated. Landlock's is on the order of fifty path-taking
syscalls scattered across this tree. seccomp's is *one line*, the dispatch in
`src/main.c`, because nabi is the system call interface and there is no way into
a handler that does not pass through it. That is a stronger position than a real
kernel is in, and it is why this one could be done honestly.

The filter language is classic BPF over `struct seccomp_data`, interpreted here,
and programs are verified when they are installed the way Linux's verifier does
- every jump lands inside the program, every load is a form this understands,
and the last instruction is a return. A filter that would run off its own end is
refused at `SECCOMP_SET_MODE_FILTER` rather than misbehaving at some later
syscall, which for a security filter is the difference between a program that
will not start and one that is not confined.

Three properties are load-bearing and each has its own check:

  - a filter that answers `ERRNO` for one call makes *that* call fail and leaves
    its neighbours alone, so the number in `seccomp_data` is the call being made
    and not a constant;
  - a later filter cannot loosen an earlier one, which is what makes a chain
    safe to inherit and is what a naive "last one wins" gets wrong;
  - and the chain survives a fork. On arm64 a fork is a fork plus an exec, so
    that means it travels in the checkpoint - version 9 carries it as a trailing
    blob. A child that rebuilt itself unfiltered while its parent believed it
    was confined is the one failure of this feature that nothing inside the
    guest could detect, and it is exactly the trap mseal's seal had. The
    checkpoint's own round-trip test carries a filter now too.

`USER_NOTIF` and `TRACE` need a supervisor and a tracer respectively, and
neither can be attached. Linux runs the call as though it returned `ENOSYS` when
nobody is listening, and so does this - the filter asked to defer the decision
to somebody who is not there.

**setfsuid and setfsgid are real rather than recorded.** `cred_may` is the one
place file permission decisions are made, so routing its effective case through
the filesystem ids was a one-line change - and a process that lowers its
filesystem id genuinely loses access to files it could read a moment earlier.
Every other credential change carries fsuid along with euid, as Linux does, so
nothing that never calls these can tell they exist. They also cannot fail: both
return the *previous* value whether or not the change was allowed, which is a
worse interface than an error and is the one callers are written against.

`setreuid` and `setregid` carry the rule that is easy to miss - changing the
real id, or setting the effective id to anything but the old real id, also moves
the saved id. Without it a program that drops privilege can pick it straight
back up, and the test checks exactly that by dropping to 1000 in a child and
confirming root is gone for good.

`set_mempolicy` and `set_mempolicy_home_node` follow mbind: one node, so a
policy naming it is satisfiable and one naming another is refused rather than
confirmed. Nothing is recorded, because `get_mempolicy` reports `MPOL_DEFAULT`
and the two should agree. While adding them, `get_mempolicy`'s `assert(addr == 0)`
came out - `MPOL_F_ADDR` is an ordinary call, and a guest passing an address was
taking the whole machine down with an abort.

#### Wayland: what was actually in the way

Wawona is a native Wayland compositor for macOS, so the question for nabi is
narrow and answerable: can a Linux Wayland client inside a guest talk to a
compositor outside it? Two things are needed and one of them was missing
outright.

The socket was never the problem. `/tmp`, `/private` and `/Users` are already
host passthrough, and `connect()` translates an AF_UNIX path through
`guest_to_host_path`, so a guest pointed at a host socket reaches it.

**Passing descriptors was the problem**, and `do_sendmsg` said so in as many
words: `"we do not support ancillary data yet"`, then `EINVAL`. That is not a
corner of the socket API for this workload - it is the mechanism Wayland is
built out of. Every buffer a client shows is a memfd sent with `SCM_RIGHTS`, so
a client could connect to a compositor and then never put a pixel on the screen.

Both directions are translated now, and there were two distinct faults to fix.
The layouts differ: Linux's `cmsghdr` begins with a `size_t` and is 16 bytes,
Darwin's begins with a `socklen_t` and is 12, so the control buffer `recvmsg`
used to copy across verbatim gave the guest headers whose lengths and levels
were read at the wrong offsets. It looked like it worked because an empty
control buffer is the same either way. And a received descriptor is a *host*
descriptor nabi has never seen; it has to be registered, or the guest holds a
number its own fd table says is closed, and the failure surfaces at the next
`close` or `dup` rather than where it was caused.

The test writes through the sent descriptor and reads it back through the
received one, so a number sitting in a buffer cannot pass for a descriptor.
Writing it found a real slip: `MSG_CMSG_CLOEXEC` is an argument to `recvmsg` and
never appears in `msg_flags`, and reading it from the header left every passed
descriptor inheritable across exec.

`memfd_create` arrived two batches ago, so with fd passing in place the pieces a
Wayland client needs from the kernel are present.

**Waydroid specifically is not reachable, and that should be said plainly.** It
is not a Wayland client with unusual needs; it is Android in an LXC container
talking to the host over binder. `/dev/binder` is a kernel driver with no macOS
equivalent and nothing here could supply one - it is the same wall `bpf` meets,
one level deeper. LXC needs `pivot_root`, which is refused a section above
because `chroot` is a stub that accepts only `/`. Ordinary Wayland clients are
now a question of trying them; Waydroid is a different project.

310 of 375.

### 3.5.106 A root that can move

The last section refused `pivot_root` and said why: nabi has a root and resolves
every guest path against it, but had no way to *change* it, and `chroot` already
refused every path but `/` for that reason. The stated order of work was chroot
first and then this on top. That is what this is.

**chroot is real.** The root is a descriptor - `proc.fileinfo.rootfd` - so
changing it is a matter of opening the new directory and putting it there. What
the old version had instead was a check for the literal string `"/"` and an
`EACCES` for everything else, with a comment saying it was there "for pacman".
The permission check also moved: it asked `getuid()`, which is the account nabi
runs as and says nothing about who the *guest* believes it is, so it now asks
the guest's own credentials the way every other privileged operation here does.

The working directory is deliberately left where it was, which is what Linux
does and is the reason chroot has never been a security boundary. Moving it
would be friendlier and would not match.

**pivot_root is the interesting half, and the interesting half of it is
put_old.** Swapping the root is the easy part; a call that did only that would
be a rename of chroot. What makes pivot_root worth having is that the old root
stays reachable, because a container runtime pivots and then unmounts the old
root through that path. A pivot that left `put_old` as the empty directory it
was would satisfy the call and silently lose the filesystem the guest came from,
with the failure surfacing later at the unmount and pointing at the wrong thing.

It is servable because nabi's mount table is a real redirection mechanism rather
than bookkeeping for `/proc/mounts`: `mount_resolve` rewrites a guest path to a
host one, and an entry is a (guest target, host directory) pair. So the old root
becomes an entry pointing at the host directory it always was, and the rest of
the table is re-expressed around the new root - mounts that were under
`new_root` lose the prefix, and everything else gains `put_old`, because
everything else was under the old root and the old root is now reachable only
there.

Two of Linux's checks are relaxed and it is better to name them than to let
somebody find out. `new_root` must be a mount point on Linux; here it need only
be a directory, because "is a mount point" is a property of a table this guest
may never have written to. And Linux requires the two not to be on the current
root filesystem, a rule that exists to keep the old root reachable - which
cannot fail here, because the entry naming it is a host path rather than a
relationship between mounts.

The divergence that could bite is different and worth stating: this rewrites
state the whole mount namespace shares, which is right for `pivot_root` and
would be wrong for `chroot`. A second process already in the namespace keeps its
own root descriptor and would see rewritten targets against an unchanged root.
Container runtimes pivot immediately after `unshare`, with one process in the
namespace, which is the case this serves.

**And one thing had quietly stopped being true.** `dir_is_rootfs` caches the
root's identity, under a comment reading "the root's identity cannot change
while a guest runs" - correct for as long as chroot refused everything. It is
what stops `..` walking out of the rootfs, so a cache still naming the *previous*
root lets a guest climb out of the new one at exactly the moment it was confined
to it.

Testing that took three attempts and each failure was mine rather than the
code's. A path beginning with `/` starts at nabi's own root descriptor and is
recognised by its number, so it never reaches the cache - the case that does is
a descriptor the *guest* opened on `/`, which is how systemd walked out of the
rootfs in the first place. Then the cache is filled lazily, so with nothing
asking before the pivot it was being filled with the *new* root and was correct
by accident; the test now asks once at the start so there is a stale answer to
find. And the first expectation was simply wrong: `..` at the root clamps to the
root rather than failing, as it does on Linux, so the check had to be a file
that exists only *outside* the new root. With all three fixed, removing the
invalidation lets a guest handle on `/` read a file from the tree it had just
been confined out of, which is what the test now reports.

311 of 375.

### 3.5.107 Transactions that carry more than bytes

The emulated binder answered seven of the conformance probe's nine stages. The
two it did not were the ones where a transaction stops being a flat block of
bytes: scatter-gather, which carries pointed-to buffers and arrays of file
descriptors alongside the payload, and the security-context form, which tells a
receiver who is calling it. Both are on the path Android actually takes, so
"seven of nine" was not a score worth keeping.

**Scatter-gather stages through shared memory rather than through the
receiver's arena.** The obvious implementation is for the sender to write the
pointed-to buffers where the receiver will read them, and it cannot be done
here: the arena is the receiver's own anonymous memory, registered with
`BINDER_MSL_SET_ARENA`, and a sender in another process has no way to reach it.
So a buffer travels in the shared registry as an *offset* into the staged blob,
and becomes an address only at the moment the receiver allocates - which is
also the only moment it could, since until then there is no address to write.
The parent links that `BUFFER_FLAG_HAS_PARENT` describes are filled in there
too, for the same reason. Descriptors inside an array go through the broker
exactly as a single `BINDER_TYPE_FD` does.

**Underneath it, a descriptor is not an endpoint.** This is what actually broke
the file-descriptor-array stage, and it took a while to see because the symptom
was three steps from the cause: a received descriptor did not answer ioctls. It
turned out the probe's parent closes its two descriptors immediately after
forking, and that was tearing down the endpoint the child was still holding and
about to send. Two changes fix it. Endpoints are reference counted in the
shared registry, so closing one descriptor does not take the endpoint away from
whoever else has one. And a descriptor's endpoint is recovered from the *name*
of the fifo it points at rather than from a table, which is what makes an
inherited descriptor work at all - on arm64 a fork is an exec, so a child comes
up holding its parent's descriptors and remembering nothing about them.

The name is matched on its shape - `nabi-binder-…-wake-<id>` - and not by
comparing it against the directory it should be in. That is the third time this
port has been caught by the same thing: macOS answers `F_GETPATH` with
`/private/var/...` for what was created as `/var/...`, and `TMPDIR`
conventionally ends in a separator, so the path built from it carries a doubled
one. Two spellings of one directory never compare equal, and every prefix test
written against them is wrong in a way that looks like the feature not working.

**Reads block, and that was the whole of the security-context failure.** The
form itself is a few lines: a node registered with
`FLAT_BINDER_FLAG_TXN_SECURITY_CTX` receives the longer
`BR_TRANSACTION_SEC_CTX` with a pointer to a label, and one registered without
it receives the plain form and would mis-read the longer one as its own fields.
The reason nothing arrived was elsewhere. That stage has no handshake - it forks
and reads, relying on the read to wait - and `serve_reads` returned empty
immediately, turning every wait into a spin. A caller that spins a fixed number
of times loses that race against a peer that is still starting, and on arm64 a
fork is an exec, so it lost every time. Binder reads now wait on the endpoint's
fifo, bounded, dropping `eps_lock` while they do: held, one idle looper would
stop every other thread in its process from touching binder.

Two deadlocks fell out of that. `serve_reads` calls into code that adopts
descriptors while already holding `eps_lock`, and `collect_messages` does it
while also holding a file lock that does not nest - hence the `_locked`
variants, which say in their names which locks the caller is expected to be
holding.

One thing was removed rather than kept. Fixing the descriptor-array stage
started with an eager walk of every open descriptor at process start, to claim
the inherited ones; the name-based recovery then made it redundant, and
deliberately breaking it showed the probe passing without it. It ran a
four-thousand-entry `fcntl` scan on every fork in a binder-using guest - which
is every zygote fork on Android - to guard a race it could not be shown to
guard, so it went.

The label is a placeholder. There is no SELinux here to ask, and answering with
an invented string is honest in a way that answering with nothing is not: a
caller that only checks that it *has* a label runs, and the string says plainly
that it was not a decision anyone made.

No new syscalls: all of this is `ioctl` on a device nabi serves.

### 3.5.108 Three binders, not three names for one

A device does not have a binder. It has several - `/dev/binder` for framework
calls, `/dev/hwbinder` for HALs, `/dev/vndbinder` for vendor code - and they are
separate on purpose. Handle 0 is the context manager, and it is a *different*
object in each, which is what stops a vendor process from reaching a framework
object simply by asking for the one object every client can find without being
told about it. NABI had the three as three names for a single context. That was
fine for exactly as long as nothing opened two of them.

So an endpoint records which binder it is an open of, and the two places where
handle 0 means something - resolving it, and registering the manager that
answers it - work within a context rather than across the instance. The name
comes from the node: the device table now hands each entry its own name to its
open hook, and a descriptor that arrives from another process takes the context
along with the endpoint it adopts.

**binderfs is the same fact, arriving from the other direction.** It is how
those devices come into being now - init mounts it and tells it what to create,
instead of the kernel bringing fixed nodes along - and NABI answered a
`binderfs` mount with the kext's `/dev/binderfs`, which is exactly the
dependency that has to go. When nabi is serving binder, the mount is backed by a
directory of its own: a control node to begin with, and a file for each
`BINDERFS_CTL_ADD`. Opening one of those files is turned into an endpoint whose
context is the file's name.

The device files are real files even though opening one never reads them, and
that is not tidiness. A container lists the directory to check that what it
asked for is there, so a device that works but cannot be seen reads as a failed
mount - a failure that surfaces later and points somewhere else.

**A path is recognised as binderfs by the name of the directory holding it, not
by asking the mount table.** Android reaches these devices through symlinks from
`/dev`, and a resolved symlink has already left the mount behind, so the table
cannot answer for the paths that actually arrive. Same shape as the fifo names
in the last section, and for the same underlying reason.

The major and minor numbers handed back are invented, because nothing here
allocates device numbers. They are answered rather than zeroed because a caller
that goes on to `mknod` wants them to agree with what it was told, and the minor
counts what is already in the directory so two calls never name one node. If
anything ever checks those numbers against something authoritative it will not
match, and that is the soft spot in this.

No new syscalls: `BINDERFS_CTL_ADD` is an ioctl, and it was already claimed.

### 3.5.109 So that init can be init

Being pid 1 is not decoration. `libprocessgroup` will set up cgroups for pid 1
and refuses for anything else - "Cgroup setup can be done only by init process"
- so Android's init cannot get past its own first step in a process numbered
like any other. It had been arranged from outside, with a helper that cloned
into a pid namespace and exec'd nabi into it. That worked, and had two costs
worth ending: it put the guest's trace in a per-pid sink rather than the main
one, and it was one more thing to rebuild after every reboot.

`--pid1` makes a pid namespace and puts the calling process in it. That is
deliberately *not* what `unshare(CLONE_NEWPID)` does - unshare puts the caller's
children in the new namespace and leaves the caller where it was, because Linux
cannot renumber a process that is already running. Here there is nothing to
renumber yet: this happens after the namespace set is built and before the guest
starts, so the process can take the first number in a table that is still empty.

The namespace is held twice over, as this process's own and as the one its
children join, so a fork lands beside the parent rather than below it. That is
the mistake worth guarding against, because it hides: a child that called itself
1 while its parent called it 2 would satisfy any check that only compared
magnitudes. So the test has the child report the pid it *sees* and compares it
against the pid the parent saw it get - and getting that test right took three
attempts, each failure mine. Exit statuses are eight bits wide, so the first
version compared a truncated number against a whole one; the second kept the
child's pid in a single variable that the second fork overwrote before the
comparison ran.

Off by default. A shell that thought it was init would be told it cannot be
killed.

No new syscalls: `--pid1` is an option, not a call.

### 3.5.110 A page size that was not the page size

`sudo apt install git` and `sudo dnf install git` both died the same way:

```
munmap_chunk(): invalid pointer
Aborted
```

Which names the heap, and the heap was fine. What was wrong was a number.

`AT_PAGESZ` is how a guest learns how big its pages are, and it said 16KiB on
Apple Silicon - `STAGE2_GRANULE`, the size of a stage-2 block. That had been
true once, back when the guest mapped in the same unit the host did. The two
were separated so that a guest could map at 4KiB (3.5.x, and see the comment on
`GUEST_MMAP_GRANULE`), because Android's allocator will not run with 16KiB
pages at all; `mmap` moved to the smaller granule and this was left behind. So
every guest was told 16KiB while `mmap` went on handing back addresses aligned
to 4KiB.

A guest computes with the number it is given, and glibc computes with it in a
place that aborts. Anything past the allocator's mmap threshold is served by a
mapping of its own, and `munmap_chunk` checks, before unmapping one, that the
chunk's address and total size are page-aligned - by the page size it was told.
Three 4KiB-aligned addresses in four are not 16KiB-aligned. So the check failed,
and glibc reported it as what that check normally catches: a corrupted pointer
handed to `free`. Nothing was corrupt. The allocator and the kernel simply
disagreed about what a page was, and the allocator was right about its own
arithmetic and wrong about the premise.

It affected every large allocation, which is why it presented as "the package
managers are broken" rather than as anything to do with memory. `sudo` alone was
enough to trigger it: it builds the invoking user's group list on every run.
Fixing it turned `sudo id` back into `uid=0(root)`, and `dnf install git` into
83 packages and `Complete!`.

`LOAD_GRANULE` stays at 16KiB and is now documented as deliberately *not* the
same number. The asymmetry is the point: aligning the image more coarsely than
the guest expects is safe, since 16KiB is a whole number of 4KiB pages and a
segment then never shares a stage-2 block with its neighbour - a block
`vmm_munmap` could not split. Telling the guest a page size *larger* than the
one `mmap` uses is not safe, and this is what it costs.

`pagesztest` walks the auxiliary vector off its own stack, the way `auxvtest`
does, and checks that every address `mmap` returns is aligned to what was
advertised there. The sizes are deliberately awkward - 4095, 4097, 65528 -
because a mapping that lands on a coarser boundary by luck passes an alignment
check while proving nothing: reintroducing the bug fails five of the eight, not
all of them.

No new syscalls. The value was always being reported; it was reporting the
wrong thing.

### 3.5.111 Two architectures, one filename

Found while verifying the above, and worth its own note because it can make any
verification a lie.

Both builds write `out/nabi`, with no architecture in the name. A stamp file
named for the architecture already existed to force the relink when `ARCH`
changes - and it did not work in one direction. GNU make 3.81, the version Xcode
ships, compares modification times at one-second granularity. Linking the x86_64
binary and then touching the arm64 stamp inside the same second left the two
equal, and equal is not newer, so the relink did not happen. Neither file moved
again afterwards, so it never happened: `make ARCH=x86_64 && make` reported
"Nothing to be done" and left an Intel binary in place.

That binary then failed in `hv_vm_create` with `HV_DENIED`, which reads as a
missing entitlement - a signing problem, a permissions problem, anything but a
build that never ran.

Deleting the stale outputs from inside the stamp's own recipe does not fix it
either. By then make has already stat'd them and goes on believing they exist,
so the relink is still skipped and now there is no binary at all - which is how
the first attempt at this went. The check has to happen before make looks at the
tree, so it is a `$(shell)` evaluated while the Makefile is read: if the stamp
for this architecture is absent, every arch-specific output is removed and the
stamp created. Afterwards make stats the tree and simply finds the files gone.
Absence is not a quantity, so no clock granularity can round it away.

### 3.5.112 Two copies of one page

The page-size fix in 3.5.110 uncovered this, and it is the more serious of the
two. A shell would print, having done nothing at all:

```
malloc_consolidate(): unaligned fastbin chunk detected
malloc(): unaligned fastbin chunk detected 3
Fatal glibc error: malloc.c:2610 (sysmalloc): assertion failed
```

Three different messages, all naming the allocator, none of them true. The heap
was exactly as its owner had left it. What had changed was who could see it.

A fork here is a fork plus an exec: the parent flushes guest memory to a file
and the child maps that file `MAP_PRIVATE`, so the child starts from the
parent's bytes and diverges copy-on-write. A child that was itself resumed maps
the arena a piece at a time - one private mapping per region, taken as the
checkpoint is read. `arena_map_private` would hand back an existing mapping when
the range asked for sat *inside* one, and otherwise make a new one. Which is
correct until two ranges overlap without either containing the other.

That is not exotic. The mm layer splits a region whenever a guest unmaps part of
one, and the halves keep the arena offset of the allocation they came from - so
after a hole is punched, two regions are interior slices of a single 16KiB
block. The first asks for one block and gets a mapping of it; the second starts
inside that block and runs past its end, containment fails, and the block is
mapped a second time. Two `MAP_PRIVATE` mappings of the same file bytes are two
copy-on-write copies. A store through one is invisible through the other.

Nothing announces it, because both copies begin identical. Every check made at
the moment of the handover passes - the region contents matched byte for byte,
the break and the stack pointer and the thread pointer all matched, no two guest
pages shared an intermediate address, and every stage-2 block was accounted for.
The divergence only exists once someone writes, and then it is total: the guest
reaches its memory through stage 2, which was pointed at one copy, while this
side reaches the same memory through the region's host pointer, which is the
other. A write the guest makes is not the write NABI reads, and each sees the
other frozen at the instant of the fork.

Both preconditions arrived at once. Regions finer than a block need guest
mappings finer than a block, which is exactly what 3.5.110 stopped lying about;
and mapping the arena piecemeal needs a parent that was itself resumed. So it
took a fork from a fork - `x=$(y=$(cmd))`, or any subshell that runs a command,
which a login shell does before it reaches a prompt. A single subshell was fine,
which is why `apt install` worked and `msl login fedora` did not.

The repair is to keep one private view per arena block: a request that overlaps
without being contained now unmaps what it overlaps and replaces it with one
mapping of the union. That is safe where it happens - every caller is
`checkpoint_restore`, mapping before the VM exists and before a byte has been
written - but it does move mappings that were already handed out, so the
pointers taken during the region loop are re-resolved once all of the mapping is
done.

Finding it took discarding four wrong answers first: that the child's memory was
copied wrongly, that a partial `munmap` was cutting into a neighbouring block,
that arena blocks were being dropped from the snapshot, and that the vCPU state
was not surviving. Each was checked and each was clean, and that is the useful
part of the record - the handover is faithful in every dimension that can be
compared at the time it happens. The bug was in a dimension that cannot: two
addresses that agree about the present and disagree about every future.

`forkmemtest` ends by writing a *different* pattern in a grandchild and reading
it back through a pipe, so the bytes make the round trip through the same
pointer any syscall would use. Reading back what a page already held passes
through either copy; with the bug present the two answers are exact bitwise
complements.

No new syscalls.

### 3.5.113 Four things between init and a system

With the fork bug of 3.5.112 out of the way, Android's init got far enough to
show what was next. Four faults, none related to each other, each of which
stopped the boot on its own; together they took a run from 44 services and a
reboot to 508 services, the zygote starting, and no reboot at all.

**A tid the guest could not use.** `CLONE_CHILD_SETTID` stores the new thread's
id in guest memory, and it was stored as the host's number rather than the
guest's. Everywhere else the guest can see an id it goes through the pid
namespace first - `getpid` does, `gettid` does - and this is one of those
places, because the word is read back as a tid by whoever asked for it. Without
a pid namespace the translation is the identity, which is why nothing had
noticed. Under `--pid1` it is not: bionic keeps the word clone wrote as its
cached id, and the first thing an Android service does is `setpgid(0, that)`,
naming a process that does not exist in the namespace. Every service start
logged "cannot set attribute for <name>: setpgid failed: No such process".

**setrlimit answering ENOSYS.** On the reasoning that a modern libc routes
setrlimit through `prlimit64` and nothing would call the old syscall. Android's
init calls it: `setrlimit` in init.rc goes straight to the syscall, so
`setrlimit nice 40 40` and `setrlimit nofile 32768 32768` both failed at
early-init, before a single service had started. It now delegates to prlimit64,
which already knows which resources Darwin does not have and which hard limits
the host will refuse - both of which belong in one place rather than two.

**No binder devices.** On a real device the three binder nodes come from the
kernel at boot and are simply there; init.rc never creates them and ueventd
acts on uevents an emulated driver cannot send. Then init mounts a tmpfs over
/dev and whatever was underneath is gone as well. So servicemanager - the first
thing to want binder, and a critical service - opened `/dev/binder`, got ENOENT
and aborted. init restarted it four times and rebooted the guest, which is
exactly what a failed critical service is supposed to cause. The nodes are now
created when a guest mounts its own /dev, since the driver they belong to is
one NABI provides.

**A registry that filled up and then lied about it.** With the nodes present,
servicemanager worked - and then stopped working part-way through a boot, with
"unable to mmap transaction memory". A descriptor released through close gives
its endpoint slot back; a process killed never closes anything, which is how
every Android service ends. The 32 slots filled during a boot and stayed full.

What made that hard to read was the fallback: when the emulated open failed the
device table fell through to the host's `/dev/binder`, which on this machine
exists, because mSL/DevFS is loaded. The guest was handed a working descriptor
for a *different* driver, whose arena the emulated mmap has never heard of - so
the failure surfaced as ENODEV from mmap rather than as anything about
endpoints, and the first services of a boot worked while later ones did not,
which reads as a race. Slots whose owner has died are now reclaimed when the
registry is next asked for one, and the cap is 512 rather than 32: a couple of
hundred services all holding binder is what a system image looks like.

**And one that was quietly dangerous.** `kill` translated a positive pid through
the pid namespace and left everything else alone. A negative pid is a process
group and needs the same translation - libprocessgroup kills a service by its
group on every restart, so each one logged "kill(-146, 9) failed: Operation not
permitted" and init waited on processes that had never been signalled. `kill(-1)`
was worse: inside a pid namespace it means every process in that namespace, and
passing it to the host means every process the account owns. init sends it
during shutdown, so a guest shutting down would have signalled the user's shell
and whatever else they had running. It is now sent one process at a time, to the
namespace's members, excluding the caller and pid 1 the way Linux does.

Still open at the end of this. The zygote starts and then cycles: it exits 127
with "Error creating cache dir /data/dalvik-cache/arm64 : No such file or
directory", which is about the shape of /data rather than about NABI - the real
one is mounted by vold, and the harness stands a tmpfs in its place without the
tree init expects to find under it. And `kill` on a process group that is in the
middle of dying answers EPERM where Linux would say ESRCH; libprocessgroup
retries through it, so it is noise rather than a stop.

### 3.5.114 The registry that two processes built at once

vold had failed in roughly one Android boot in four for a long time -
"Unable to start VoldNativeService", then `reboot,vold-failed`. Three binder
bugs were found and fixed while chasing it and none of them changed the rate,
which is recorded here as a warning against assuming the next one will.

This is the one. The shared registry is a file every process that speaks binder
maps, and `shm_attach` decided whether to initialise it by reading a magic
number *outside* the lock:

```c
if (shm->magic != BSHM_MAGIC) {
  memset(shm, 0, sizeof *shm);      /* and only then */
  shm->magic = BSHM_MAGIC;          /* is the magic set */
  shm->next_id = 1;
}
```

Two processes attaching at the same instant both find the magic unset, because
the first one does not set it until after the memset. Both initialise. The
second one's memset erases endpoints the first has already published and puts
`next_id` back to 1, so the next endpoint created is handed an id that a live
endpoint already has.

What a duplicate id does is subtle enough to have hidden this for months.
`BINDER_SET_CONTEXT_MGR` finds the endpoint to flag by searching the registry
for the caller's id - and with two matches it flags whichever comes first.
Twice we watched servicemanager register successfully, return 0, and the
`is_mgr` flag land on a `vndbinder` endpoint in a different process that
happened to share its id. From then on `shm_ep_for_handle(0, "binder")` found
nothing: every client's transaction to handle 0 came back ENOENT with a live,
correctly registered servicemanager sitting in the next process along. vold is
simply the first thing that cannot survive it.

The window is exactly as wide as the memset, which is why raising the endpoint
cap in 3.5.113 turned a one-in-four failure into every boot: the registry went
from 8MB to 136MB and the race went from unlucky to near-certain. That is the
only reason it became diagnosable - it stopped being intermittent.

Both halves are fixed. The check and the initialisation are one step under
`flock`, and the memset is skipped when the file was created by this very call,
since `ftruncate` has already made it zero - which removes the cost as well as
the race. And the context-manager flag is now matched on the binder's *name* as
well as the id, because that is the one place where getting it wrong says
nothing: the flag goes on an endpoint that answers to no one, and the manager
that did register is never found again.

Three boots in a row after it, where before there had been none: 334, 352 and
357 services with no reboot, and a longer run reaching 509. What is left is not
a bug but a gap - the emulated driver implements handle 0 and nothing else, so a
client can reach the context manager and no other service. `vdc checkpoint
markBootAttempt` looks vold up by name, is handed a handle that names nothing,
and waits; `post-fs-data` never runs, and the zygote finds no /data to build a
cache in. Object references are the next piece.

### 3.5.115 Objects that can be reached by name

The emulated driver knew one handle: zero, the context manager. That is enough
to reach servicemanager and nothing else, and Android is built the other way
round - a service registers *with* the manager, the manager hands it out to
whoever asks, and every call after that goes to a handle the driver invented.

So a client could look a service up, be given a reference, and transact into
nothing. `vdc checkpoint markBootAttempt` found vold, called it, and waited;
init waited on vdc; `post-fs` never finished, `post-fs-data` never ran, and the
zygote's complaint about `/data/dalvik-cache` - which reads like a problem with
the shape of /data - was four steps downstream of a handle that named nothing.

A node is the thing a handle names: an object, who owns it, and what the owner
calls it. Outbound, an object the sender owns becomes a node and travels as a
handle; inbound to the owner, a handle that names one of the receiver's own
objects becomes the pointer it knows it by, because a process has to recognise
its own object when it comes home. The numbering is shared across the instance
rather than per-process as Linux's is. That is a simplification and not a
shortcut: a handle is opaque to everyone holding one, so nothing can tell, and
it removes the per-process translation table the real driver needs.

Three things fell out of it that were not obvious from the outside.

The first was that a missing command is not an error but a loop. With handles
real, servicemanager linked to death on every service it stored -
`BC_REQUEST_DEATH_NOTIFICATION`, which the driver did not know. An unknown BC
fails the *whole* write, and libbinder answers a failed write by logging it and
trying again, so one missing command produced three quarters of a million lines
of the same four calls and nothing else ever started. The death-notification
family is accepted now. Nothing sends `BR_DEAD_BINDER` yet, which is a real gap
and a far smaller one than refusing the command; clearing is answered, because
the caller blocks until it is.

The second was that a thread had no id. `gettid` goes through the pid namespace
like everything else the guest can see, and a thread was never enrolled in one -
so `pidns_to_ns` said what it says about a process it does not know, and every
thread in every `--pid1` guest reported tid 0. Linux numbers threads and
processes out of one range, which is why `tgkill` takes one of each; so threads
are enrolled too.

The third was the delivery itself. libbinder reads a transaction's target
pointer and cookie together and casts the cookie straight to the object it is a
call on. Both were being delivered as zero, which is not an error to libbinder -
it is a call on "the context object", the single nameless object that only a
context manager registers. servicemanager has one, which is why handle 0 had
always worked; vold does not, so the first call that ever reached it was a
transact on a null pointer. It had never been reached before because nothing
could reach it.

`binderhandletest` covers the mechanism in two processes: an object its owner
sends arrives as a handle rather than as a pointer into another address space,
that handle reaches the process owning the object, and the same handle sent back
to its owner is a pointer again. Removing the resolution makes it fail with
ENOENT on the call rather than hang - which took two attempts to arrange, since
the first version waited on an answer that a refused send was never going to
produce.

Android is not further along by the measure that is easy to quote. It reaches
17 services now where it reached 357, and that is not a regression so much as a
change of subject: the 357 were services starting while init waited on a vdc
that could never finish, and now vold gets far enough to be called and crashes
in libbinder reading a pointer out of parcel text. That is the next thing, and
it is a real one rather than an absence.

### 3.5.116 A crash that waited for an answer

`panic` printed the message, the backtrace, and then this:

```
Set the ulimit value to unlimited to generate the coredump? [Y/n]
```

and called `getchar`.

stdin belongs to the guest. In a pipeline there is nobody to answer, so the
read never returns: the process does not exit, nothing further is printed, and
the failure stops being a crash and becomes a hang. That is what `dnf update`
looked like from the outside - it sat there after the confirmation prompt with
every process idle - and the "y" the user typed to dnf went to this prompt
instead, which is why it appeared twice in the transcript and why dnf never saw
it.

It also could not have worked. The limit is consulted when a core is written,
and by then the process has already faulted; raising it afterwards produces
nothing. So the line is a statement now - run with `ulimit -c unlimited` if you
want a core - and the panic ends.

Worth noticing for its own sake: this had been in every panic path since the
beginning, and it hid every crash that happened anywhere but an interactive
terminal. The overlapping-region panic in the next section was invisible for
the same reason, and appeared the moment this was fixed.

### 3.5.117 Growing a mapping where it stands

`dnf check-update` took **8m55s**, of which **3m39s** was nabi's own CPU. A
sample said where: essentially all of it in `mremap`.

Linux extends a mapping in place whenever the space above it is free. nabi
always moved: it allocated the whole new size from the arena, copied the old
bytes across, tore the mapping down a guest page at a time and built the new
one up the same way. That is the cost of the whole region on every call, and a
caller that grows a buffer in steps calls it once per step. dnf's download
buffer went from 1.7MB upwards in 64KiB increments - 2199 times in one process,
re-mapping something like ten gigabytes of pages to move two megabytes of data.

It also abandoned the old allocation each time, because arena storage is
released only as a whole chunk and a grown region is not known to be one. So
the arena's apparent size grew with the *square* of the buffer, and eventually
could not be extended at all: "could not grow the guest memory arena to
37748736 bytes: No space left on device", on a disk with 27GiB free.

The fast path is allowed when three things hold, none of which can be arranged
and all of which are therefore asked: the guest addresses above the region are
unclaimed, the region is the top of the arena so the offsets above it are not
somebody else's, and the host address space immediately after its mapping is
free. `arena_extend` answers the last two and refuses otherwise; the move path
runs unchanged when it does.

Two things had to give way.

`vmm_mmap` asserted that its host address was 16KiB-aligned. That was true when
a region owned whole stage-2 blocks, and stopped being needed when blocks became
shared - the loop finds the block containing each host page and maps the page at
its offset inside it, which works wherever the page sits. The assertion outlived
its reason and had become a limit: growing in place means continuing from where
a region ends, and a region measured in 4KiB pages ends inside a block more
often than not.

And `alloc_region` is a bump allocator that never consults the region tree. So
"nothing is mapped above this region", which is what the fast path checks, is
not the same as "nothing will be" - growing into the space the next mmap was
about to get put one region on top of another, and panicked *hundreds of
allocations later*, nowhere near the mremap that caused it. The cursor is moved
past the grown region now.

`dnf check-update` takes **1m54s**, with **58s** of nabi CPU: about five times
faster in wall clock and four in CPU. `mremapgrowtest` does not measure that - a
timing test would be a flaky one - it checks what has to remain true for the
fast path to be permitted: the bytes survive each grow, a mapping made after a
grow does not land inside the grown region, and the whole thing still unmaps as
one. Leaving the allocator's cursor behind makes it fail with the region zeroed
under it, which is exactly what it looked like in the guest.

One run of the suite failed this test and has not done so again in twenty-three
attempts since, standalone and in the suite. Rather than guess at it, the runner
now prints the test's whole output on failure instead of the last line, so the
offset and the value it found survive to be read.

### 3.5.118 A Linux window on the screen

Both display paths work, and neither needed a display subsystem in nabi.

**X11 took no code at all.** `/tmp` is a host passthrough, so a guest sees
`/tmp/.X11-unix/X0` exactly as the host does, and nabi already had AF_UNIX with
real path translation. An aarch64 Linux `xdpyinfo` returned the full server info
from XQuartz, and `xeyes -geometry 300x200+80+80` produced a `300x222+80+80`
window that `xlsclients` attributes to `parent-host` - the guest's hostname -
beside the host's own `redstar /opt/X11/bin/xterm`. The only fiddly part is the
cookie, which must be keyed to the *guest's* hostname and is re-minted whenever
XQuartz restarts. `xhost +` would also work and is not worth it: it turns off
access control on the user's machine to save one `xauth` line.

**Wayland took three fixes**, none of them about Wayland.

The first was `mkdir`. Ownership is recorded in an extended attribute, because
the host has one account and no way to give a file to another - and writing an
extended attribute needs write permission on the object, while chown on Linux
needs no such thing. `chmod` already split the mode for exactly this reason: the
host gets one it can work with and the guest's own is recorded beside it.
`mkdir` passed the guest's mode straight through, so a mode-0 directory really
existed and could not be chowned. dpkg unpacks mkdir-0, chown, chmod in that
order, so `man-db` failed to unpack and took `x11-apps`, `wayland-utils` and
`weston` with it behind an unmet dependency.

The second was `fallocate`, which reported success and did not change the file's
size: macOS's `F_PREALLOCATE` reserves blocks and leaves `st_size` alone. That is
not an error a caller can see. `wl_shm` is the path - a client makes a memfd,
sizes it with `posix_fallocate`, maps it `MAP_SHARED` and draws into it - and
`mmap` does not check a file's size, so the mapping succeeded too. The first
store past the end of a zero-length file is SIGBUS **in the host process**, so
`weston-simple-shm` ended as "Bus error: 10" with nothing in any log, because a
host memory fault is not a guest one.

The third was `mmap` of zero bytes, which reached the arena, asked the host to
map nothing, got EINVAL and panicked. Linux answers EINVAL and the caller
carries on. A compositor with no keymap to publish sends a size of zero and
xkbcommon maps what it is told, so `wayland-info` hit it on connect.

After those three, `weston-simple-shm` runs against Wawona: 1270 `sendmsg` and
1271 `ppoll` in twenty seconds, which is the frame callback arriving and the
attach-damage-commit going back out, about sixty-three times a second. Confirmed
on screen.

What makes this different from the existing ways of putting Linux graphics on
macOS is what is *not* in the path. No VM, no container, no waypipe, no network
transport and no copy: the client is an ordinary macOS process, the socket is a
plain unix socket, and the buffer it passes is a real host file descriptor -
`memfd_create` makes a file and unlinks it, so the compositor maps the client's
memory directly.

The limit is unchanged and is the whole of what remains. This is software
rendering. There is no `/dev/dri`, no dmabuf and no GPU surface anywhere in nabi,
so anything on EGL or GBM does not run - and waydroid's SurfaceFlinger sits
squarely behind that, a long way past "a Linux window on the screen".
