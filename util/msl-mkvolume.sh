#!/bin/sh
#
# Make a case-sensitive volume to keep a Linux rootfs on.
#
#   util/msl-mkvolume.sh [image] [mountpoint]
#
# Defaults to ~/.msl/disk.sparseimage mounted at /Volumes/msl. Re-running it is
# safe: an image that already exists is attached rather than rebuilt, and one
# already attached is left alone.
#
# Why this exists at all: macOS formats the boot volume case-insensitively, and
# a Linux distribution cannot live there. Debian ships pairs of files whose
# names differ only in case - manpages-dev has _exit.2.gz and _Exit.2.gz,
# linux-libc-dev has xt_connmark.h and xt_CONNMARK.h - and one such pair is
# enough to break an install. The failure does not look like a case problem:
# dpkg clears a stale .dpkg-new for the second name, which on this filesystem
# deletes the first name's freshly unpacked file, writes a symlink over it, and
# then reports ENOENT from its fsync pass against the file that was fine.
#
# A sparse image is used rather than an APFS volume in the boot container
# because adding a volume needs an administrator and this does not. It is
# sparse, so the size below is a ceiling and not an allocation - the file grows
# as the rootfs does.
set -eu

# Whether a directory can hold two names that differ only in case.
#
# Asked by trying it rather than by reading the format name: getconf does not
# expose _PC_CASE_SENSITIVE on macOS, and `diskutil info` phrases the answer
# per filesystem, so both would have to be kept in step with Apple. Creating
# one file and looking for the other is the property itself.
is_case_sensitive() {
    d=$1
    [ -d "$d" ] && [ -w "$d" ] || return 1
    probe=$(mktemp "$d/.mslCASE.XXXXXX") || return 1
    lower=$(dirname "$probe")/$(basename "$probe" | tr 'A-Z' 'a-z')
    if [ -e "$lower" ]; then rc=1; else rc=0; fi
    rm -f "$probe"
    return $rc
}

IMG=${1:-$HOME/.msl/disk.sparseimage}
MNT=${2:-/Volumes/msl}
SIZE=${MSL_VOLUME_SIZE:-64g}
# hdiutil derives the mount point from the volume name, so it has to match the
# mount point asked for or the volume lands somewhere else entirely.
NAME=$(basename "$MNT")

if is_case_sensitive "$MNT"; then
    echo "already mounted and case-sensitive: $MNT"
    exit 0
fi

if [ ! -e "$IMG" ]; then
    mkdir -p "$(dirname "$IMG")"
    echo "==> creating $IMG ($SIZE, sparse)"
    # -type SPARSE rather than SPARSEBUNDLE: one file rather than a bundle
    # directory, which is easier to move and to reason about. Neither needs
    # privileges.
    hdiutil create -size "$SIZE" -type SPARSE -fs "Case-sensitive APFS" \
        -volname "$NAME" -quiet "${IMG%.sparseimage}"
fi

echo "==> attaching at $MNT"
hdiutil attach -nobrowse -mountpoint "$MNT" "$IMG" > /dev/null

# Proving it rather than trusting the format that was asked for.
if ! is_case_sensitive "$MNT"; then
    echo "$MNT is not case-sensitive - refusing to hand it over" >&2
    exit 1
fi

echo "==> $MNT is ready"
echo
echo "    It does not survive a reboot on its own. Re-attach with:"
echo "      hdiutil attach -nobrowse -mountpoint $MNT $IMG"
echo "    or just run this script again."
