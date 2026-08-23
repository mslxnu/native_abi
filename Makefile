#
# mSL/NABI - macOS Subsystem for Linux / Noah ABI
#
# The command is `nabi`; the project it descends from was called Noah.
#
# Usage:
#   make                    # build everything into $(OUT)
#   make ARCH=x86_64        # cross-build the Intel guest backend
#   make check              # run the guest test suite (needs a matching host)
#   sudo make install       # install into the system (run AFTER make)
#   sudo make uninstall     # remove from the system
#   make clean              # remove build artifacts (no sudo needed)
#
# NOTE: never build as root. `make install` only COPIES already-built artifacts
# from $(OUT), so every build artifact stays owned by the invoking user and
# `make clean` never needs sudo.
#
OUT      := out
PREFIX   ?= /usr/local

VERSION  := $(strip $(shell cat VERSION 2>/dev/null || echo 0.0.0))

# ---------------------------------------------------------------------------
# Architecture
#
# Unlike the other mSL components there is deliberately no ARCH=universal here.
# A fat binary would be meaningless: the x86_64 build runs x86-64 Linux guests
# via VT-x and the arm64 build runs aarch64 guests via the ARM Hypervisor API.
# They are not two builds of one program, they are two programs, and a lipo'd
# binary would present a guest ABI depending on which slice the kernel picked.
#
# arm64e is likewise not a target: third-party arm64e userland binaries are not
# supported for distribution and the ABI is explicitly unstable. (mSL/ProcFS
# defaults to arm64e because kexts require that ABI; NABI is ordinary userland
# and must not copy it.)
# ---------------------------------------------------------------------------
NATIVE_ARCH := $(shell uname -m)
ARCH ?= $(NATIVE_ARCH)

# The per-architecture source set. Only the x86 list is built today; the arm64
# list is what a whole nabi will link once mm/exec/signal/main are ported. Its
# pieces are compiled and run in isolation now by `make check-arm64`.
ifeq ($(ARCH),x86_64)
    ARCH_SRCS := lib/vmm_x86.c lib/vmm_x86_exit.c src/mm/mm_x86.c src/main_x86.c src/ipc/signal_x86.c
else
    ARCH_SRCS := lib/vmm_arm64.c lib/vmm_arm64_exit.c src/mm/mm_arm64.c src/mm/pt_arm64.c src/main_arm64.c src/ipc/signal_arm64.c src/proc/checkpoint.c src/proc/resume.c
endif

# The arch guard is a parse-time $(error), so it has to be skipped for goals
# that do not build the guest backend - otherwise `make clean`, `sudo make
# uninstall` and `make check-decode` would all be unusable on an arm64 host,
# which is exactly where they are most needed while the port is in progress.
# check-decode belongs here because it compiles its own -arch x86_64 binary and
# needs no VT-x, so it is the one test that runs on the development machine.
GOALS        := $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
NONBUILD     := clean uninstall migrate require-root check-decode check-arm64
NEEDS_BUILD  := $(filter-out $(NONBUILD),$(GOALS))

ifneq ($(NEEDS_BUILD),)
ifeq ($(ARCH),arm64)
    # Signals, fork and dynamic linking all work now - a Debian bash runs
    # external commands and pipelines. What is left is threads: a second live
    # vCPU is still guarded off. See PORTING-arm64.md.
else ifneq ($(ARCH),x86_64)
    $(error Unknown ARCH=$(ARCH). Use arm64 or x86_64)
endif
endif

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
CC       ?= /usr/bin/cc
CODESIGN ?= /usr/bin/codesign

#
# Code-signing identity. "-" means ad-hoc, which is what a development build
# wants. Overridable from the environment, so verify the identity actually
# exists before handing it to codesign: a stale SIGNCERT left exported in a
# shell - pointing at a certificate that has since been removed - would
# otherwise fail the build late, at the codesign step, with "no identity found".
#
SIGNCERT ?= -
ifneq ($(SIGNCERT),-)
ifeq ($(shell security find-identity -v 2>/dev/null | grep -c $(SIGNCERT)),0)
$(warning SIGNCERT '$(SIGNCERT)' is not a valid signing identity in the keychain; falling back to ad-hoc signing)
SIGNCERT := -
endif
endif

ENTITLEMENTS := installer/nabi.entitlements

CFLAGS := -arch $(ARCH) -std=gnu11 -O2 -g \
          -Wall -Wextra -Wno-unused-parameter \
          -Iinclude

# Kept from the CMake build: -O0, no frame-pointer omission, ASan.
DEBUG_CFLAGS := -arch $(ARCH) -std=gnu11 -O0 -g \
                -Wall -Wextra -Wno-unused-parameter \
                -fsanitize=address -fno-omit-frame-pointer \
                -Iinclude

FRAMEWORKS := -framework Hypervisor -lpthread

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
COMMON_SRCS := src/main.c \
               src/meta_strace.c \
               src/base.c \
               src/conv.c \
               src/debug.c \
               src/proc/exec.c \
               src/proc/fork.c \
               src/proc/pidfd.c \
               src/proc/kcmp.c \
               src/proc/seccomp.c \
               src/proc/process.c \
               src/proc/namespace.c \
               src/proc/pidns.c \
               src/proc/credtab.c \
               src/proc/cgroup.c \
               src/proc/rseq.c \
               src/proc/ptrace.c \
               src/net/net.c \
               src/net/netlink.c \
               src/ipc/futex.c \
               src/ipc/signal.c \
               src/ipc/sem.c \
               src/ipc/sysv.c \
               src/ipc/msg.c \
               src/ipc/mqueue.c \
               src/fs/mount.c \
               src/fs/diskimage.c \
               src/fs/loop.c \
               src/fs/kmsg.c \
               src/fs/binder.c \
               src/fs/inotify.c \
               src/fs/fanotify.c \
               src/fs/handle.c \
               src/fs/xattr.c \
               src/fs/sync.c \
               src/fs/aio.c \
               src/fs/io_uring.c \
               src/fs/copy.c \
               src/fs/cachestat.c \
               src/fs/memfd.c \
               src/fs/splice.c \
               src/fs/tee.c \
               src/fs/userfaultfd.c \
               src/sys/timer.c \
               src/fs/fs.c \
               src/fs/binder_broker.c \
               src/fs/epoll.c \
               src/fs/procfs.c \
               src/sys/sys.c \
               src/sys/time.c \
               src/mm/mm.c \
               src/mm/mmap.c \
               src/mm/arena.c \
               src/mm/malloc.c \
               src/mm/shm.c

SRCS    := $(ARCH_SRCS) $(COMMON_SRCS)
HEADERS := $(wildcard include/*.h include/*/*.h)

NABI    := $(OUT)/nabi
WRAPPER := $(OUT)/nabi.pl

# A stamp so that changing ARCH rebuilds.
#
# Everything lands in out/ under a name with no architecture in it, and ARCH is
# a variable rather than a file - so `make ARCH=x86_64` straight after
# `make ARCH=arm64` found out/nabi newer than every source, reported "Nothing to
# be done", and left the arm64 binary sitting there. That is worse than an
# error: CI ran both builds in one job and went green without ever compiling the
# second one.
#
# The stamp is named for the architecture and is a normal prerequisite, so
# switching ARCH creates a file newer than the binary and forces the relink.
# Switching back does the same. Building the same architecture twice touches
# nothing.
ARCH_STAMP := $(OUT)/.built-for-$(ARCH)
# The front end, installed under the family name, and the shell helper it
# calls. Both are plain scripts with nothing to build, so they are taken from
# the source tree. nabi-shell.sh moves to libexec: it takes a rootfs path and
# is now what `msl login` runs, not something to invoke by hand.
MSLCMD := util/msl
SHELLCMD := util/nabi-shell.sh
# Makes the case-sensitive volume a rootfs has to live on. Under libexec rather
# than bin: it is a step in setting a rootfs up, not something to run daily.
VOLCMD := util/msl-mkvolume.sh
# Builds a rootfs by downloading it. Also libexec: it is run once to make a
# tree, not every time someone wants a shell in one.
MKROOTFS := util/msl-mkrootfs

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

all: build

build: $(NABI) $(WRAPPER)

# The signature must be applied AFTER every write to the binary. Anything that
# modifies it afterwards (strip, lipo, install_name_tool) invalidates the
# signature and takes the entitlement with it - which surfaces much later as
# hv_vm_create() returning HV_DENIED, and reads like a permissions problem
# rather than a build problem.
$(ARCH_STAMP): | $(OUT)
	@rm -f $(OUT)/.built-for-*
	@touch $@

$(NABI): $(SRCS) $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(FRAMEWORKS)
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

debug: | $(OUT)
	$(CC) $(DEBUG_CFLAGS) -o $(NABI) $(SRCS) $(FRAMEWORKS)
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $(NABI)

# The perl front-end. It locates the real binary and provisions a rootfs on
# first run, so it needs both the version and the install prefix baked in.
$(WRAPPER): bin/nabi.in VERSION | $(OUT)
	sed -e 's|@PROJECT_VERSION@|$(VERSION)|g' \
	    -e 's|@PREFIX@|$(PREFIX)|g' $< > $@
	chmod 755 $@

$(OUT):
	@mkdir -p $(OUT)

# ---------------------------------------------------------------------------
# Tests
#
# test/test.rb runs prebuilt Linux guest binaries (committed under
# test/*/build/) and diffs their output. It therefore needs a host that can
# actually run the guests: an x86_64 build on an Intel Mac with VT-x. Skip
# rather than fail everywhere else, so `make check` is honest about what it did
# instead of reporting a failure that says nothing about the code.
#
# Note test/test.mk - which REBUILDS those guest binaries - shells out to a
# Linux box at idylls.jp that has not existed for years. Running the tests does
# not need it; regenerating them does.
# ---------------------------------------------------------------------------
check: check-decode check-arm64 check-smoke check-guest

# Unit tests for the exit decoder. These need no VT-x - they substitute the
# accessors in vmm.h with a fake machine - so they run anywhere, including on
# Apple Silicon under Rosetta. This is the only automated check of the x86
# backend available on a non-Intel host.
DECODE_TEST := $(OUT)/test_exit_decode

$(DECODE_TEST): test/arch/test_exit_decode.c lib/vmm_x86_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch x86_64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_exit_decode.c lib/vmm_x86_exit.c

check-decode: $(DECODE_TEST)
	@if [ "$(NATIVE_ARCH)" = "arm64" ] && ! arch -x86_64 /usr/bin/true >/dev/null 2>&1; then \
		echo "SKIP: the x86 decode test is an x86_64 binary and needs Rosetta here."; \
	else \
		$(DECODE_TEST); \
	fi

# Hardware test for the aarch64 backend. Creates a real VM, so it needs Apple
# Silicon and the hypervisor entitlement - but unlike the x86 guest suite, it
# does run on the development machine. Skips on Intel.
ARM64_TEST := $(OUT)/test_arm64_backend

$(ARM64_TEST): test/arch/test_arm64_backend.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_backend.c lib/vmm_arm64.c lib/vmm_arm64_exit.c src/mm/arena.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

MMU_TEST := $(OUT)/test_arm64_mmu

$(MMU_TEST): test/arch/test_arm64_mmu.c src/mm/pt_arm64.c src/mm/arena.c src/mm/mm_arm64.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_mmu.c src/mm/pt_arm64.c src/mm/arena.c src/mm/mm_arm64.c lib/vmm_arm64.c lib/vmm_arm64_exit.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

# Depends on the binaries directly rather than recursing: -arch arm64 binaries
# cross-build fine on Intel, they just cannot run there, so only execution is
# guarded.
VMMAP_TEST := $(OUT)/test_arm64_vmmap

$(VMMAP_TEST): test/arch/test_arm64_vmmap.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_vmmap.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

BOOT_TEST := $(OUT)/test_arm64_boot

$(BOOT_TEST): test/arch/test_arm64_boot.c src/main_arm64.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_boot.c src/main_arm64.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

MUNMAP_TEST := $(OUT)/test_arm64_munmap

$(MUNMAP_TEST): test/arch/test_arm64_munmap.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_munmap.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

# Exercises the fork reentry path (snapshot / hv_vm_destroy / hv_vm_create /
# replay / restore) in-process. Same link set as the boot test.
REENTRY_TEST := $(OUT)/test_arm64_reentry

$(REENTRY_TEST): test/arch/test_arm64_reentry.c src/main_arm64.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch arm64 -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arm64_reentry.c src/main_arm64.c src/mm/pt_arm64.c src/mm/arena.c lib/vmm_arm64.c lib/vmm_arm64_exit.c \
	    -framework Hypervisor
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

# The arena is plain VM plumbing - no VM, no entitlement, runs anywhere.
ARENA_TEST := $(OUT)/test_arena

$(ARENA_TEST): test/arch/test_arena.c src/mm/arena.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch $(NATIVE_ARCH) -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_arena.c src/mm/arena.c

CKPT_TEST := $(OUT)/test_checkpoint

$(CKPT_TEST): test/arch/test_checkpoint.c src/proc/checkpoint.c src/mm/arena.c $(HEADERS) $(ARCH_STAMP) | $(OUT)
	$(CC) -arch $(NATIVE_ARCH) -std=gnu11 -O0 -g \
	    -Wall -Wextra -Wno-unused-parameter -Iinclude \
	    -o $@ test/arch/test_checkpoint.c src/proc/checkpoint.c src/mm/arena.c

# Whether this host can create a VM at all, asked by trying rather than by
# reading a sysctl - see the comment in the source. Codesigned like nabi,
# because the entitlement is what the call needs.
HV_PROBE := $(OUT)/hv_probe
$(HV_PROBE): test/arch/hv_probe.c $(ARCH_STAMP) | $(OUT)
	$(CC) $(CFLAGS) -o $@ test/arch/hv_probe.c $(FRAMEWORKS)
	$(CODESIGN) --force --sign $(SIGNCERT) --entitlements $(ENTITLEMENTS) $@

check-arm64: $(CKPT_TEST) $(ARM64_TEST) $(MMU_TEST) $(VMMAP_TEST) $(BOOT_TEST) $(MUNMAP_TEST) $(REENTRY_TEST) $(ARENA_TEST) $(HV_PROBE)
	@if [ "$(NATIVE_ARCH)" != "arm64" ]; then \
		echo "SKIP: the aarch64 backend tests need Apple Silicon to run."; \
	elif ! $(HV_PROBE); then \
		echo "SKIP: this host cannot create a VM, so the backend tests cannot run."; \
		$(ARENA_TEST) && $(CKPT_TEST); \
	else \
		$(ARENA_TEST) && $(CKPT_TEST) && $(ARM64_TEST) && $(MMU_TEST) && $(VMMAP_TEST) && $(BOOT_TEST) && $(MUNMAP_TEST) && $(REENTRY_TEST); \
	fi

# End-to-end: run committed aarch64 binaries under a natively-built nabi. Needs
# Apple Silicon and a full arm64 build; skips otherwise. This is the first test
# that exercises the whole pipeline on a real ELF (load, translation, syscall
# dispatch, cache sync), rather than a component in isolation.
check-smoke: $(HV_PROBE)
	@if [ "$(NATIVE_ARCH)" != "arm64" ]; then \
		echo "SKIP: the smoke test needs Apple Silicon to run a nabi."; \
	elif ! $(HV_PROBE); then \
		echo "SKIP: this host cannot create a VM, so nabi cannot run."; \
	else \
		$(MAKE) --no-print-directory ARCH=arm64 build >/dev/null && \
		echo "==> arm64 end-to-end smoke test" && \
		test/arch/smoke/run.sh $(NABI); \
	fi

# The full guest suite. Runs prebuilt Linux binaries, and they are x86-64 ELF -
# inherited from upstream Noah, which had no other architecture. NABI does not
# emulate instructions, so an arm64 build cannot run them at all: this needs an
# x86_64 build on an Intel Mac with VT-x, and skips everywhere else.
#
# The architecture of the *binaries* is the thing to test, and testing only
# `ARCH != NATIVE_ARCH` was not it: an arm64 build on an Apple Silicon host
# passed that check, ran the x86 programs, and failed all of them. `make check`
# had been red on Apple Silicon for that reason alone.
#
# Note kern.hv_support is NOT a usable signal for that. An x86_64 process on
# Apple Silicon reads it as 1 - it reports ARM HVF, not VT-x - and then
# hv_vm_create() fails with HV_UNSUPPORTED. The architecture comparison is what
# actually decides this; the sysctl check only catches an Intel host with
# virtualisation disabled.
check-guest: build $(HV_PROBE)
	@if [ "$(ARCH)" != "x86_64" ]; then \
		echo "SKIP: the guest suite's programs are x86-64 Linux ELF and need an x86_64 nabi."; \
	elif [ "$(ARCH)" != "$(NATIVE_ARCH)" ]; then \
		echo "SKIP: built for $(ARCH) on a $(NATIVE_ARCH) host; the guest tests cannot run."; \
	elif ! $(HV_PROBE); then \
		echo "SKIP: this host cannot create a VM, so the guest tests cannot run."; \
	else \
		cd test && ./test.rb ../$(NABI); \
	fi

# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

install: require-root require-built migrate
	install -d -m 755 -o root -g wheel $(PREFIX)/bin $(PREFIX)/libexec $(PREFIX)/man/man1
	install -m 755 -o root -g wheel $(WRAPPER)  $(PREFIX)/bin/nabi
	@sed -e 's|@PROJECT_VERSION@|$(VERSION)|g' $(MSLCMD) > $(OUT)/msl
	install -m 755 -o root -g wheel $(OUT)/msl  $(PREFIX)/bin/msl
	install -m 755 -o root -g wheel $(SHELLCMD) $(PREFIX)/libexec/msl-shell
	install -m 755 -o root -g wheel $(NABI)     $(PREFIX)/libexec/nabi
	install -m 755 -o root -g wheel $(VOLCMD)   $(PREFIX)/libexec/msl-mkvolume
	install -m 755 -o root -g wheel $(MKROOTFS) $(PREFIX)/libexec/msl-mkrootfs
	install -m 644 -o root -g wheel man/nabi.1  $(PREFIX)/man/man1/nabi.1
	@echo "nabi: installed to $(PREFIX)."
	@echo "      'nabi' provisions a rootfs in ~/.nabi/tree and starts it."
	@echo "      'msl' is the front end: 'msl install debian', 'msl login"
	@echo "      debian', 'msl' on its own for what is installed. It makes the"
	@echo "      case-sensitive volume the trees need, since macOS formats the"
	@echo "      boot disk case-insensitively and no distribution unpacks there."

# ---------------------------------------------------------------------------
# Migration from the pre-rename install (the command was called noah).
#
# The old libexec binary matters more than the usual stale-file cleanup: the
# perl wrapper offers to chown it root:admin and set its setuid bit, so leaving
# it behind can orphan a setuid-root executable on the user's disk with nothing
# left that knows it is there.
#
# The rootfs is deliberately NOT touched here. ~/.noah/tree is per-user, may be
# several gigabytes, and belongs to whoever is running the command rather than
# to root - the wrapper adopts it into ~/.nabi/tree on first run instead.
#
# Idempotent, and silent when there is nothing from the old install to remove.
# ---------------------------------------------------------------------------
migrate: require-root
	-@for stale in $(PREFIX)/libexec/noah $(PREFIX)/bin/noah \
	               $(PREFIX)/man/man1/noah.1; do \
		[ -e "$$stale" ] || continue; \
		echo "nabi: removing the superseded $$stale"; \
		rm -f "$$stale"; \
	done

uninstall: require-root
	rm -f $(PREFIX)/bin/nabi $(PREFIX)/bin/msl $(PREFIX)/libexec/nabi \
	      $(PREFIX)/libexec/msl-mkvolume $(PREFIX)/libexec/msl-mkrootfs \
	      $(PREFIX)/libexec/msl-shell \
	      $(PREFIX)/man/man1/nabi.1
	@echo "nabi: uninstalled. ~/.nabi/tree is left alone - remove it by hand if"
	@echo "      you want the rootfs gone; it may be several gigabytes."

require-root:
	@[ "$$(id -u)" -eq 0 ] || \
		{ echo "error: run as root (sudo make $(MAKECMDGOALS))"; exit 1; }

require-built:
	@[ -x "$(NABI)" ] && [ -x "$(WRAPPER)" ] || \
		{ echo "error: not built. Run 'make' first."; exit 1; }

# Regenerate the aarch64 syscall table from a kernel asm-generic/unistd.h.
# Manual: it needs the kernel header, so it is not part of the build. The
# generated include/syscall_arm64.h is committed and audited (see the report
# the generator prints). Point UNISTD at the header for your target kernel.
UNISTD ?= /tmp/unistd_generic.h
UNISTD_X86 ?= /tmp/unistd_64.h
syscalls:
	python3 util/gen_syscall_table_x86.py $(UNISTD_X86) > include/syscall_x86.h
	python3 util/gen_syscall_table.py $(UNISTD) include/syscall_x86.h \
	    > include/syscall_arm64.h
	python3 util/gen_syscall_doc.py $(UNISTD) $(UNISTD_X86) > /tmp/nabi-syscalls.md
	@echo "syscall table for README.md written to /tmp/nabi-syscalls.md"

clean:
	rm -rf $(OUT)

.PHONY: all build debug check check-decode check-arm64 check-smoke check-guest syscalls install migrate uninstall require-root require-built clean
