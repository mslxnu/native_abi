#!/bin/sh
#
# Drop into an interactive Debian shell inside a NABI rootfs.
#
#   util/nabi-shell.sh <rootfs> [command ...]
#
# Without a command this is a login shell; with one, that command runs in the
# same environment and the shell exits.
#
# The work here is all environment. NABI hands the guest the host's environment
# and the host's working directory, which for a shell is exactly wrong: bash
# would come up with the host's PATH (so `apt` resolves to nothing), the host's
# HOME (and /Users is a NABI passthrough prefix, so it would read the *host's*
# dotfiles and arrive wearing the host's prompt and aliases), and a $PWD naming
# a directory that means something different on each side.
#
# So the environment is built rather than inherited: `env -i` for a clean slate,
# a Debian PATH, and HOME pointed at the guest's own home. TERM is carried over
# because it describes the terminal, which really is shared. The login shell
# then execs an interactive one, which is what gets /etc/profile and ~/.profile
# read for their exports and ~/.bashrc read for the interactive settings - the
# ordinary login sequence, and also where the `cd` to $HOME happens, since NABI
# has no way to set the guest's initial directory.
set -eu

# Named for whatever it was invoked as: it ships as nabi-shell.sh and installs
# as msl, so a hardcoded name would be wrong in one place or the other.
me=$(basename "$0")
ROOT=${1:?usage: ${0##*/} <rootfs> [command ...]}
shift
# Kept before the positional parameters get reused to build the environment.
if [ "$#" -gt 0 ]; then CMD=yes; ARGS="$*"; else CMD=no; ARGS=; fi

[ -d "$ROOT" ] || { echo "no such rootfs: $ROOT" >&2; exit 1; }

# Find the binary that takes -m.
#
# `make install` lays down two things: the perl wrapper at bin/nabi, and the
# real executable at libexec/nabi. The wrapper is a front end for a different
# workflow - it provisions ~/.nabi/tree, adopts a pre-rename one, and offers to
# make the executable setuid root - and its options are --root/--strace/--output.
# It has no -m, so pointing this script at it gets "Unknown option: m" out of
# Getopt::Long. What is wanted here is the executable underneath, since this
# script brings its own rootfs.
#
# Both layouts are checked, so the script works from the source tree and from an
# install, under whatever name it has been given.
here=$(cd "$(dirname "$0")/.." && pwd)
for cand in ${NABI:-} "$here/out/nabi" "$here/libexec/nabi" \
            /usr/local/libexec/nabi; do
    [ -n "$cand" ] && [ -x "$cand" ] || continue
    # A wrapper is a script; the executable is not. Skip the wrapper rather than
    # calling it and getting an option error from a layer down.
    if [ "$(head -c 2 "$cand" 2>/dev/null)" = "#!" ]; then
        [ -n "${NABI:-}" ] && [ "$cand" = "$NABI" ] && {
            echo "$me: NABI=$cand is the wrapper script, not the executable." >&2
            echo "  point it at libexec/nabi instead." >&2
            exit 1
        }
        continue
    fi
    NABI=$cand
    break
done
[ -n "${NABI:-}" ] && [ -x "$NABI" ] || {
    echo "$me: no nabi executable found." >&2
    echo "  build one with 'make ARCH=arm64', install with 'sudo make install'," >&2
    echo "  or set NABI to the path of libexec/nabi." >&2
    exit 1
}

# The guest's idea of this account, from the rootfs's own passwd - not the
# host's, which names a home on the far side of a passthrough.
user=$(id -un)
home=$(awk -F: -v u="$user" '$1 == u { print $6 }' "$ROOT/etc/passwd" 2>/dev/null)
[ -n "$home" ] || home=/root

PATH_G=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The clean environment, built up as positional parameters so that a value
# containing a space survives.
set -- env -i \
    TERM="${TERM:-xterm}" HOME="$home" USER="$user" LOGNAME="$user" \
    SHELL=/bin/bash PATH="$PATH_G"

# NABI_* settings are carried across the `env -i`, which would otherwise drop
# them - they configure the emulator rather than the guest, and a knob that
# silently does nothing when used through this script is worse than no knob.
for v in $(env | sed -n 's/^\(NABI_[A-Za-z0-9_]*\)=.*/\1/p'); do
    eval "set -- \"\$@\" \"$v=\${$v}\""
done

set -- "$@" "$NABI" -m "$ROOT" /bin/bash -lc

# Who to be inside the guest.
#
# The guest starts as root - NABI maps the host account to uid 0 - and stays
# there unless the rootfs has an account of this name, which msl-mkrootfs
# creates at install time with sudo rights. Being that user is the point of
# having created it: root is one `sudo -i` away, and running as root by default
# is how a tree accumulates root-owned files that the account cannot then touch.
#
# MSL_ROOT=1 keeps the root shell, for the times when that is what is wanted.
as_user=
if [ -z "${MSL_ROOT:-}" ] && [ "$user" != root ] &&
   awk -F: -v u="$user" '$1 == u { found = 1 } END { exit !found }' \
       "$ROOT/etc/passwd" 2>/dev/null; then
    as_user=$user
fi

if [ -n "$as_user" ]; then
    # su starts that account's login shell itself, so the interactive case
    # needs no command at all - and the cd to $HOME, the environment and the
    # groups all come from the guest's own login path rather than from an
    # approximation built out here.
    if [ "$CMD" = no ]; then
        exec "$@" "exec su - $as_user"
    fi
    # For a command, single quotes are the only quoting su -c is guaranteed to
    # see intact through bash -lc, so the command is wrapped in them and any
    # single quote inside is closed, escaped and reopened.
    esc=$(printf '%s' "$ARGS" | sed "s/'/'\\\\''/g")
    exec "$@" "exec su - $as_user -c 'cd \"\$HOME\" 2>/dev/null; $esc'"
fi

if [ "$CMD" = yes ]; then
    exec "$@" "cd \"\$HOME\" 2>/dev/null; $ARGS"
fi
exec "$@" 'cd "$HOME" 2>/dev/null; exec bash -i'
