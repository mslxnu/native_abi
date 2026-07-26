# Standalone reproduction of the Hypervisor.framework fork() limitation.
# See README.md. Needs the hypervisor entitlement, hence the codesign step.
hv_fork_vcpu: hv_fork_vcpu.c
	$(CC) -arch arm64 -O0 -g -Wall -o $@ $< -framework Hypervisor
	codesign --force --sign - --entitlements ../../installer/nabi.entitlements $@

# Each mode forks and has the child create a VM + vCPU; they differ only in what
# the parent did with the framework beforehand.
check: hv_fork_vcpu
	@for m in 0 1 2; do \
	  c=0; for i in $$(seq 1 20); do ./hv_fork_vcpu $$m >/dev/null 2>&1 || c=$$((c+1)); done; \
	  echo "  mode $$m: $$c/20 children died"; \
	done

clean:
	rm -rf hv_fork_vcpu hv_fork_vcpu.dSYM
.PHONY: check clean
