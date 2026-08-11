"""
Reading asm-generic/unistd.h as the architecture being built sees it.

The header is not a list, it is a program. A third of it sits inside
conditionals - `#ifdef __ARCH_WANT_RENAMEAT`, `#if __BITS_PER_LONG == 32` - and
reading it with a regex that ignores them reads *both* branches of every one. So
`sync_file_range` and `sync_file_range2` both appear, and so do the fifty-eight
numbers in the 32-bit-only block: `mq_timedsend_time64`, `clock_gettime64`,
`fcntl64` and the rest, none of which exist on aarch64 at all.

Nothing malfunctioned because of it - those numbers are unassigned here, so a
guest could not reach the `unimplemented` entries they produced - but the
generated table claimed syscalls this architecture does not have and counted
them as missing.

Resolving the conditionals means knowing which symbols the architecture defines,
and getting that set wrong would silently add or remove syscalls, which is worse
than the fault being fixed. Two things guard against it. The set below is small,
closed and justified one line at a time. And anything this cannot evaluate -
an unknown symbol, an expression in a form not handled - is an error rather than
a guess, so a header that grows a new conditional stops the build instead of
quietly dropping whatever is inside it.
"""
import re


# What arch/arm64/include/uapi/asm/unistd.h defines before including this
# header, and what the compiler supplies.
#
# Only four of these can change the outcome, and each is noted with what it
# decides, so a wrong entry has a visible consequence rather than an invisible
# one:
#
#   __ARCH_WANT_RENAMEAT        renameat, 38
#   __ARCH_WANT_SET_GET_RLIMIT  getrlimit and setrlimit, 163 and 164
#   __ARCH_WANT_MEMFD_SECRET    memfd_secret, 447
#   __ARCH_WANT_SYNC_FILE_RANGE2  which spelling of 84 - arm64 uses
#                               sync_file_range, so this is NOT defined
#
# The other two are guarded by conditions that are already true on a 64-bit
# architecture, so their value cannot change anything:
#
#   __ARCH_WANT_TIME32_SYSCALLS  every use is `... || __BITS_PER_LONG != 32`
#   __ARCH_WANT_NEW_STAT         every use is `... || defined(__ARCH_WANT_STAT64)`
# Symbols this architecture does *not* define. Listed rather than left to
# fall through as "unknown, so absent", because the difference between the
# two is the whole point: an unrecognised symbol is a header that has grown a
# conditional nobody here has considered, and it stops the build.
ARM64_UNDEFINED = {
    '__SYSCALL_COMPAT',             # the native ABI, not the 32-bit one
    '__ARCH_WANT_STAT64',           # 32-bit stat; arm64 has NEW_STAT
    '__ARCH_WANT_SYNC_FILE_RANGE2', # arm64 uses sync_file_range at 84
    '__ARCH_NOMMU',                 # arm64 has one
}

ARM64 = {
    '__BITS_PER_LONG': 64,
    'undefined': ARM64_UNDEFINED,
    'defines': {
        '__SYSCALL',                    # supplied by whoever includes this
        '__ARCH_WANT_RENAMEAT',
        '__ARCH_WANT_NEW_STAT',
        '__ARCH_WANT_SET_GET_RLIMIT',
        '__ARCH_WANT_TIME32_SYSCALLS',
        '__ARCH_WANT_MEMFD_SECRET',
    },
}


class Unsupported(Exception):
    """A conditional this cannot evaluate. Deliberately fatal - see the note
    at the top of this file."""


def _known(name, defined, arch, local):
    """Whether anything here has an opinion about this symbol.

    A macro the header defines somewhere - even inside a branch this
    architecture does not take - is the header's own business, and whether it
    ends up defined follows from which branches were taken. A symbol that
    appears *only* in a condition is the architecture's business, and has to be
    one this file has been told about. Defaulting it to "absent" is exactly the
    silent guess this is here to prevent.
    """
    if name in local or name in defined or name in arch['undefined']:
        return True
    # The header's own namespace. It asks whether it defined one of these, and
    # the answer follows from which branches were taken rather than from
    # anything the architecture supplies - so an absent one is absent, not
    # unknown. __NR3264_stat is the live case: asked about on every
    # architecture, defined on none of them any more.
    if name.startswith('__NR') or name.startswith('__SC_'):
        return True
    raise Unsupported(
        'nothing here knows whether %s is defined on this architecture; add it '
        'to ARM64 or ARM64_UNDEFINED in util/kernel_headers.py rather than '
        'letting it default' % name)


def _evaluate(expr, defined, bits, arch, local):
    """True if the architecture would take this branch.

    Handles exactly the forms the header uses: defined(), !, &&, ||,
    parentheses, and comparisons of __BITS_PER_LONG against an integer. Anything
    else raises, because the alternative is deciding a branch by accident.
    """
    src = expr.strip()

    # defined(X) and defined X -> a membership test we can evaluate.
    def _defined(m):
        _known(m.group(1), defined, arch, local)
        return 'True' if m.group(1) in defined else 'False'
    src = re.sub(r'defined\s*\(\s*(\w+)\s*\)', _defined, src)
    src = re.sub(r'defined\s+(\w+)', _defined, src)

    src = src.replace('__BITS_PER_LONG', str(bits))
    src = src.replace('&&', ' and ').replace('||', ' or ')
    src = re.sub(r'!(?!=)', ' not ', src)

    # Whatever is left must be booleans, integers, comparisons and operators.
    # A surviving identifier means a symbol nothing here knows about.
    leftover = re.findall(r'[A-Za-z_]\w*', src)
    for word in leftover:
        if word not in ('and', 'or', 'not', 'True', 'False'):
            raise Unsupported('unknown symbol %r in %r' % (word, expr))
    if not re.fullmatch(r'[\sTruealsFnotd()0-9=!<>+-]*', src):
        raise Unsupported('unparsed conditional %r' % expr)
    try:
        return bool(eval(src, {'__builtins__': {}}, {}))
    except Exception as e:
        raise Unsupported('could not evaluate %r: %s' % (expr, e))


def resolve(path, arch=ARM64):
    """The header's lines, with the branches this architecture does not take
    removed.

    Macros defined along the way are tracked, because the header asks about its
    own: `#ifdef __NR3264_stat` is true only on the architectures where the
    block defining it was taken.
    """
    defined = set(arch['defines'])
    bits = arch['__BITS_PER_LONG']

    # Every macro the header defines anywhere, whether or not this
    # architecture takes that branch. Used to tell a symbol the header owns
    # from one the architecture is expected to have supplied.
    local = set(re.findall(r'^\s*#\s*define\s+(\w+)',
                           open(path).read(), re.M))

    out = []
    # One entry per open conditional: (taken_here, taken_already)
    stack = []

    def live():
        return all(t for t, _ in stack)

    for line in open(path):
        s = line.strip()

        m = re.match(r'#\s*if(n?)def\s+(\w+)', s)
        if m:
            if not live():
                # Inside a branch this architecture does not take. A
                # preprocessor does not evaluate what it is skipping, and
                # neither does this - only the nesting is tracked. The header
                # relies on that: it asks `#ifdef __NR3264_stat` about a macro
                # nothing ever defines, and being strict about symbols would
                # otherwise turn dead code into a fatal error.
                stack.append((False, True))
                continue
            _known(m.group(2), defined, arch, local)
            val = (m.group(2) in defined) != bool(m.group(1))
            stack.append((val, val))
            continue
        m = re.match(r'#\s*if\s+(.*)', s)
        if m:
            if not live():
                stack.append((False, True))
                continue
            val = _evaluate(m.group(1), defined, bits, arch, local)
            stack.append((val, val))
            continue
        m = re.match(r'#\s*elif\s+(.*)', s)
        if m:
            if not stack:
                raise Unsupported('#elif with no #if')
            _, already = stack[-1]
            enclosing = all(t for t, _ in stack[:-1])
            val = (enclosing and not already and
                   _evaluate(m.group(1), defined, bits, arch, local))
            stack[-1] = (val, already or val)
            continue
        if re.match(r'#\s*else\b', s):
            if not stack:
                raise Unsupported('#else with no #if')
            _, already = stack[-1]
            enclosing = all(t for t, _ in stack[:-1])
            stack[-1] = (enclosing and not already, True)
            continue
        if re.match(r'#\s*endif\b', s):
            if not stack:
                raise Unsupported('#endif with no #if')
            stack.pop()
            continue

        if not live():
            continue

        m = re.match(r'#\s*define\s+(\w+)', s)
        if m:
            defined.add(m.group(1))
        out.append(line)

    if stack:
        raise Unsupported('%d conditional(s) never closed' % len(stack))
    return ''.join(out)
