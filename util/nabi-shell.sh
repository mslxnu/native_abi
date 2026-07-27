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

ROOT=${1:?usage: nabi-shell.sh <rootfs> [command ...]}
shift

here=$(cd "$(dirname "$0")/.." && pwd)
NABI=${NABI:-$here/out/nabi}
[ -x "$NABI" ] || { echo "no nabi binary at $NABI (make ARCH=arm64)" >&2; exit 1; }
[ -d "$ROOT" ] || { echo "no such rootfs: $ROOT" >&2; exit 1; }

# The guest's idea of this account, from the rootfs's own passwd - not the
# host's, which names a home on the far side of a passthrough.
user=$(id -un)
home=$(awk -F: -v u="$user" '$1 == u { print $6 }' "$ROOT/etc/passwd" 2>/dev/null)
[ -n "$home" ] || home=/root

PATH_G=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$#" -gt 0 ]; then
    exec env -i \
        TERM="${TERM:-xterm}" HOME="$home" USER="$user" LOGNAME="$user" \
        SHELL=/bin/bash PATH="$PATH_G" \
        "$NABI" -m "$ROOT" /bin/bash -lc "cd \"\$HOME\" 2>/dev/null; $*"
fi

exec env -i \
    TERM="${TERM:-xterm}" HOME="$home" USER="$user" LOGNAME="$user" \
    SHELL=/bin/bash PATH="$PATH_G" \
    "$NABI" -m "$ROOT" /bin/bash -lc 'cd "$HOME" 2>/dev/null; exec bash -i'
