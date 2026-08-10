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

With this the System V family is complete apart from `semtimedop`, which wants a
timed wait Darwin's `semop` has no equivalent of.
