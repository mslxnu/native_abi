#!/bin/sh
#
# Build an aarch64 Debian rootfs for NABI from a netinst ISO, on macOS, offline.
#
#   util/mkrootfs-debian.sh <debian-arm64-netinst.iso> <target-dir>
#
# There is no debootstrap here and none is needed. A netinst ISO is not a rootfs,
# but its pool/ holds the whole base system as .deb archives, and a .deb is an
# `ar` archive containing a `data.tar` - so the filesystem can be laid down with
# nothing but the tools macOS already ships. `tar` reads the ISO directly, which
# matters because macOS cannot mount the hybrid image at all (hdiutil says "no
# mountable file systems").
#
# The part that is not just unpacking is the dpkg database. Unpacking gives a
# filesystem but leaves dpkg and apt believing nothing is installed, so they
# would offer to reinstall the world and refuse to satisfy any dependency. Each
# .deb carries its own control file, and a status database is very nearly the
# concatenation of those with a Status line added - which is what the second
# stage below does. It is what `debootstrap --second-stage` would produce, minus
# the maintainer scripts, which cannot run here: they are aarch64 shell scripts
# and would need a working guest to execute, which is the thing being built.
#
# Consequences of skipping the maintainer scripts, all of them things postinst
# would otherwise generate: no /etc/shadow, no ldconfig cache, no
# update-alternatives symlinks, and no /etc files that are written rather than
# shipped. Packages that only ship files work; packages whose usefulness comes
# from their postinst may not.
set -eu

ISO=${1:?usage: mkrootfs-debian.sh <iso> <target-dir>}
ROOT=${2:?usage: mkrootfs-debian.sh <iso> <target-dir>}

[ -f "$ISO" ] || { echo "no such ISO: $ISO" >&2; exit 1; }

work=$(mktemp -d)
# Files unpacked from an ISO come out read-only, so the scratch tree has to be
# made writable before anything can be extracted into it or removed from it.
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

mkdir -p "$ROOT"

echo "==> extracting .deb archives from the ISO"
tar -xf "$ISO" -C "$work" pool 2>/dev/null || true
chmod -R u+w "$work/pool" 2>/dev/null || true
# *.udeb are installer-only fragments, and the glob excludes them by construction.
debs=$(find "$work/pool" -name '*.deb' | sort)
[ -n "$debs" ] || { echo "no .debs found in $ISO" >&2; exit 1; }
echo "    $(echo "$debs" | wc -l | tr -d ' ') packages"

status="$work/status"
: > "$status"

mkdir -p "$ROOT/var/lib/dpkg/info"

echo "==> unpacking"
n=0
for deb in $debs; do
    d=$(dirname "$deb")
    ( cd "$d" && ar x "$(basename "$deb")" )

    # The files.
    data=$(ls "$d"/data.tar.* 2>/dev/null | head -1)
    [ -n "$data" ] && tar -xf "$data" -C "$ROOT" 2>/dev/null || true

    # The control stanza, turned into a status entry. dpkg wants Status
    # immediately after Package, so the Package line is re-emitted and the
    # original dropped from the remainder.
    ctrl=$(ls "$d"/control.tar.* 2>/dev/null | head -1)
    if [ -n "$ctrl" ]; then
        rm -f "$d/control"
        tar -xf "$ctrl" -C "$d" ./control 2>/dev/null || \
            tar -xf "$ctrl" -C "$d" control 2>/dev/null || true
        if [ -f "$d/control" ]; then
            pkg=$(awk '/^Package:/ {print $2; exit}' "$d/control")
            if [ -n "$pkg" ]; then
                # The file list. dpkg keeps one per package and without it
                # `dpkg -S` and `dpkg -L` answer nothing and every query warns
                # that the package "has no files currently installed". The
                # data.tar member names are exactly that list, once ./ is turned
                # into / and the trailing slash on directories is dropped.
                # Multi-Arch: same packages are keyed by name:arch, everything
                # else by name alone - that is how dpkg names both the status
                # entry and this file.
                if [ -n "$data" ]; then
                    ma=$(awk '/^Multi-Arch:/ {print $2; exit}' "$d/control")
                    arch=$(awk '/^Architecture:/ {print $2; exit}' "$d/control")
                    lname=$pkg
                    [ "$ma" = "same" ] && lname="$pkg:$arch"
                    tar -tf "$data" 2>/dev/null |
                        sed -e 's|^\./$|/.|' -e 's|^\./|/|' -e 's|\(.\)/$|\1|' \
                        > "$ROOT/var/lib/dpkg/info/$lname.list"
                fi
                echo "Package: $pkg"                >> "$status"
                echo "Status: install ok installed" >> "$status"
                # Everything except Package, and stop at the first blank line so
                # a multi-stanza control cannot bleed into the next entry.
                awk 'BEGIN{done=0} /^$/{done=1} done==0 && !/^Package:/ {print}' \
                    "$d/control" >> "$status"
                echo "" >> "$status"
            fi
        fi
    fi

    n=$((n + 1))
    [ $((n % 50)) -eq 0 ] && echo "    $n/$(echo "$debs" | wc -l | tr -d ' ')"
done

echo "==> laying out dpkg and apt state"
mkdir -p "$ROOT/var/lib/dpkg/info" "$ROOT/var/lib/dpkg/updates" \
         "$ROOT/var/lib/dpkg/triggers" "$ROOT/var/lib/apt/lists/partial" \
         "$ROOT/var/cache/apt/archives/partial" "$ROOT/etc/apt/apt.conf.d" \
         "$ROOT/etc/apt/preferences.d" "$ROOT/etc/apt/sources.list.d" \
         "$ROOT/var/log/apt" "$ROOT/run" "$ROOT/var/tmp"

cp "$status" "$ROOT/var/lib/dpkg/status"
: > "$ROOT/var/lib/dpkg/available"
echo 1 > "$ROOT/var/lib/dpkg/info/format" 2>/dev/null || true

# base-passwd and base-files both ship their /etc content as masters that a
# postinst is supposed to install; the postinst cannot run here, so they are put
# in place directly. Without passwd, getpwuid finds nothing and the shell prompt
# reads "I have no name!" - NABI takes the guest's credentials from the host.
if [ -f "$ROOT/usr/share/base-passwd/passwd.master" ]; then
    cp "$ROOT/usr/share/base-passwd/passwd.master" "$ROOT/etc/passwd"
    cp "$ROOT/usr/share/base-passwd/group.master"  "$ROOT/etc/group"
fi
[ -f "$ROOT/usr/share/base-files/profile" ] &&
    cp "$ROOT/usr/share/base-files/profile" "$ROOT/etc/profile"

# A home inside the rootfs, seeded from /etc/skel like adduser would.
#
# Not the host's home directory, even though that is where the account really
# lives: /Users is one of NABI's passthrough prefixes, so pointing the guest
# there makes bash read the *host's* dotfiles and the Debian shell arrives
# wearing the host's prompt, PATH and aliases. The host home stays reachable at
# its own path for anyone who wants it; it is just not $HOME.
u=$(id -un); uid=$(id -u); gid=$(id -g)
ghome="/home/$u"
mkdir -p "$ROOT$ghome" "$ROOT/root"
for skel in "$ROOT/etc/skel/".*; do
    b=$(basename "$skel")
    [ "$b" = "." ] || [ "$b" = ".." ] && continue
    [ -f "$skel" ] || continue
    [ -e "$ROOT$ghome/$b" ] || cp "$skel" "$ROOT$ghome/$b"
    [ -e "$ROOT/root/$b" ]  || cp "$skel" "$ROOT/root/$b"
done
if ! grep -q "^$u:" "$ROOT/etc/passwd"; then
    printf '%s:*:%s:%s:%s:%s:/bin/bash\n' "$u" "$uid" "$gid" "$u" "$ghome" \
        >> "$ROOT/etc/passwd"
fi

# usrmerge: the compatibility symlinks base-files would normally provide.
for l in bin sbin lib lib64; do
    [ -e "$ROOT/$l" ] || ln -s "usr/${l%64}" "$ROOT/$l" 2>/dev/null || true
done
[ -e "$ROOT/lib64" ] || ln -s usr/lib "$ROOT/lib64" 2>/dev/null || true

# The three files that decide whether the guest can reach the network at all.
# Each is normally written by a maintainer script or by the installer, so none
# of them arrives with the packages, and without them apt has no repository to
# install from, glibc has no resolver configuration, and NSS does not know to
# consult DNS - which presents as "Temporary failure in name resolution" for
# every hostname.
cat > "$ROOT/etc/apt/sources.list" <<'EOS'
deb http://deb.debian.org/debian trixie main
deb http://deb.debian.org/debian trixie-updates main
deb http://security.debian.org/debian-security trixie-security main
EOS

# Taken from the host, so the guest resolves the way the machine does rather
# than against a hardcoded public resolver.
if [ -s /etc/resolv.conf ]; then
    grep -E '^(nameserver|search|domain|options)' /etc/resolv.conf \
        > "$ROOT/etc/resolv.conf" 2>/dev/null || true
fi
[ -s "$ROOT/etc/resolv.conf" ] || printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' \
    > "$ROOT/etc/resolv.conf"

cat > "$ROOT/etc/nsswitch.conf" <<'EOS'
passwd:         files
group:          files
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
EOS

printf 'nabi\n' > "$ROOT/etc/hostname"
printf '127.0.0.1\tlocalhost\n' > "$ROOT/etc/hosts"
printf 'trixie/sid\n' > "$ROOT/etc/debian_version" 2>/dev/null || true

echo "==> done: $ROOT"
echo "    $(grep -c '^Package:' "$ROOT/var/lib/dpkg/status") packages recorded as installed"
