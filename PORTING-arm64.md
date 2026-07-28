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
