# Reproductions for the Hypervisor.framework fork()/vCPU limitation and the two
# ways out of it. See README.md. All need the hypervisor entitlement.
BINS = hv_fork_vcpu hv_zygote hv_fork_exec

all: $(BINS)

%: %.c
	$(CC) -arch arm64 -O0 -g -Wall -o $@ $< -framework Hypervisor
	codesign --force --sign - --entitlements ../../installer/nabi.entitlements $@

# 1. The bug: a child forked from a process that ever had a vCPU dies in
#    hv_vcpu_create. Modes differ only in what the parent did beforehand.
# 2. Zygote: children forked by a process that never touched HVF are clean.
# 3. fork+exec: exec also clears it, and the child still inherits fds.
check: $(BINS)
	@echo "1. direct fork (the bug):"
	@for m in 0 1 2; do \
	  c=0; for i in $$(seq 1 20); do ./hv_fork_vcpu $$m >/dev/null 2>&1 || c=$$((c+1)); done; \
	  echo "     mode $$m: $$c/20 children died"; \
	done
	@echo "2. zygote-forked children, runner holding a live VM:"
	@./hv_zygote
	@echo "3. fork+exec children:"
	@./hv_fork_exec

clean:
	rm -rf $(BINS) *.dSYM
.PHONY: all check clean
