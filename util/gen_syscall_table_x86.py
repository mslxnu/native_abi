#!/usr/bin/env python3
"""
x86-64 syscall table, generated the way the aarch64 one is.

It used to be maintained by hand, and it stopped at 332 because that was the
last number anyone had needed. That is not a harmless place to stop: a handler
for a syscall numbered above it - clone3 is 435, faccessat2 439 - has nowhere
to live, so the x86 build fails to link it while aarch64 builds fine, and the
break shows up in the arch nobody can run.

Both tables come from a kernel header and the set of DEFINE_SYSCALL handlers in
the sources now, so a new handler is wired into both by rebuilding rather than
by remembering.

Usage: util/gen_syscall_table_x86.py <asm/unistd_64.h> > include/syscall_x86.h
"""
import glob
import re
import sys


def kernel_names(path):
    out = {}
    for line in open(path):
        m = re.match(r'#define\s+__NR_(\w+)\s+(\d+)\s*$', line)
        if m:
            out[int(m.group(2))] = m.group(1)
    return out


def handlers():
    names = set()
    for path in glob.glob('src/**/*.c', recursive=True):
        text = open(path).read()
        for m in re.finditer(r'DEFINE_SYSCALL\(\s*(\w+)', text):
            if m.group(1) != 'name':
                names.add(m.group(1))
        for m in re.finditer(r'DEFINE_NOT_IMPLEMENTED_SYSCALL\(\s*(\w+)', text):
            names.add(m.group(1))
    return names


def main():
    names = kernel_names(sys.argv[1])
    impl = handlers()
    hi = max(names)

    o = sys.stdout
    print("/*", file=o)
    print(" * x86-64 syscall table - GENERATED, do not edit by hand.", file=o)
    print(" * Regenerate: util/gen_syscall_table_x86.py <asm/unistd_64.h>", file=o)
    print(" */", file=o)
    print("#include <stdint.h>", file=o)
    print("", file=o)
    print("#define SYSCALLS \\", file=o)
    for n in range(hi + 1):
        nm = names.get(n)
        print(f"  SYSCALL({n}, {nm if (nm and nm in impl) else 'unimplemented'}) \\",
              file=o)
    print("", file=o)
    print(f"#define NR_SYSCALLS {hi + 1}", file=o)


main()
