# Porting Noah to Apple Silicon (arm64)

**Target:** run **aarch64** Linux binaries on arm64 macOS via Hypervisor.framework's ARM API.

**Status** (M5, macOS 26): **a native arm64 `nabi` runs Debian's `bash`.** Static
and dynamically-linked aarch64 binaries both work - `make check-smoke` covers the
static ELFs, and under a real `ld-linux-aarch64.so.1` + glibc, `bash` runs
external commands, pipelines (`echo x | tr a-z A-Z`), command substitution,
loops, conditionals and redirections.

Known rough edges: `fork` fails about one time in eight - a Hypervisor.framework
limitation, not a NABI bug, reproduced standalone in
[spike/arm64-fork/](spike/arm64-fork/) and diagnosed in §3.5.8, which
`forktest`/`clonetid` catch; `mprotect` is an
over-permissive no-op (§3.5.6); and `-m <root>` does not confine a guest whose
rootfs contains absolute symlinks.

| Phase | State |
|---|---|
| 0 — trap mechanism | **done**, hardware-validated, [spike/arm64-trap/](spike/arm64-trap/) |
| 1 — arch abstraction | **done**, [include/arch.h](include/arch.h) |
| 2 — arm64 VMM backend | **done** — backend, stage-1 translation, two-stage `vmm_mmap`, guest boot to EL0, all hardware-verified (`make check-arm64`) |
| 3 — syscall table + ABI | **done for the static case** — generated aarch64 table (§3.2), exec.c ported, code-cache sync wired in, TLS via `TPIDR_EL0`, `struct stat` corrected to the aarch64 layout (§3.5.4), `statx`/`prlimit64` wired. A static ELF loads, runs, stats, syscalls and exits (`make check-smoke`). `ppoll`/`epoll_*` and the dynamic linker still to come |
| 4 — signals, fork, threads | **signals done; fork works but is unreliable** — a guest takes a signal, runs the handler at EL0 and resumes. `fork` rebuilds the VM on both sides (snapshot / `hv_vm_destroy` / host fork / reentry) and the mechanism is verified by the `check-arm64` reentry test, but about one child in eight dies in the framework (§3.5.8). Multi-threaded `clone` (a second live vCPU) is still guarded off |
| 5 — dynamic linking and rootfs | **bash runs** — Debian trixie `bash` executes external commands, pipelines, command substitution, loops and redirections under a real `ld-linux-aarch64.so.1` + glibc. Needed file-backed mmap by copy, a 16KiB guest-page model, the caches on (§3.5.5) and `VREG_PC` via `ELR_EL1` (§3.5.7). Rootfs built offline from the netinst ISO |
| 6 | test port — not started |

`make ARCH=arm64` produces a signed arm64 binary that **runs real static aarch64
Linux ELFs** - proven by `make check-smoke`. Bounds today: a **single-threaded**
guest works, static or dynamically linked, signals included; `fork` works but
fails about one time in eight (§3.5.8). A multi-threaded `clone` (a second live
vCPU) still hits a Phase 4 guard. `munmap` of a whole
region now works (§3.5.3); a sub-16KiB-block partial split still panics. Three real host-side bugs stood between "links"
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

Still missing and needed: `epoll_create1`, `epoll_pwait` (epoll wants a kqueue
translation, a separate effort). `fstatat` is aarch64's `newfstatat` (nr 79) and
already exists under that name.

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

**Not done: the sub-block partial split.** A `munmap` that unmaps one 4KiB page
of a 16KiB block while a sibling page stays live cannot use the block-unmap
primitive (it would fault the survivor too), and the guest `TLBI` that would let
us clear just the one stage-1 entry does not work. The fix is *evacuation* —
re-home the survivor to a fresh block so the old block can be unmapped whole —
but a hardware spike showed that is not merely a page-table operation: because
the no-copy backing shares one host page across the block, the survivor and the
victim resolve to the same host page, and HVF keeps the victim's TLB entry alive
as long as that host page is mapped anywhere. Evacuating with a *copy* to a
fresh host page works for the TLB, but then desynchronises the survivor's
`mm_region.haddr` (the host still reads the old buffer via `guest_to_host`).
Doing it correctly means moving the region's backing with the page — a change to
the mmap ownership model, not the page tables. Until then such a split panics
loudly rather than silently leaving the unmapped page reachable. It is rare:
whole-region munmap never hits it.

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

Still open on this path: `mprotect` is an over-permissive no-op on arm64 (the x86
call passes a guest VA to `hv_vm_protect`, which wants an IPA, and never touches
stage 1 — a correct version walks the stage-1 tables), and `MAP_SHARED` file
write-back is not preserved by the copy.

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

The shape would be: guest memory into a shared-memory arena, process state (mm
regions, fd table, credentials, sigactions, task, brk, vCPU snapshot) serialized,
and `__do_clone_process` becomes fork + `exec` of `nabi --resume <fd>`. Not
attempted here. Until then `forktest` and `clonetid` make the smoke suite
intermittently red, and that is honest: `fork` really is broken about one time in
eight.

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
