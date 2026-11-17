#!/bin/sh
# verify.sh — real-kernel Debian-lane aarch64 verification for keyringer.
#
# Boots a qemu-system-aarch64 VM on the DEBIAN stable arm64 netboot kernel
# (d-i initrd + our overlay, same architecture as the Alpine lane in
# ../a64vm) and runs the full stash+exec battery there. What this lane adds
# over the Alpine one:
#   * a second, Debian distro kernel as a real-arm64 data point, and
#   * an audit-enabled kernel: CONFIG_AUDIT=y/CONFIG_AUDITSYSCALL=y, with
#     /proc/sys/kernel/audit_enabled asserted in the battery (auditd
#     userspace needs a full rootfs — out of scope, see README).
# big_key is TRIED for real; Debian's 6.12 arm64 kernel cannot offer it and
# the battery prints the evidence (config + ENODEV) and SKIPs honestly.
#
# Env requirements (all present on the dev box):
#   qemu-system-aarch64, cpio, curl, gzip, dpkg-deb, depmod (kmod),
#   lsinitramfs (initramfs-tools), aarch64-linux-gnu-gcc
# First run fetches ~172 MB of Debian assets into dl/ (cached): the netboot
# linux + initrd.gz (~79 MB) and the matching linux-image-*-arm64 deb
# (~93 MB) whose module tree supplies the AF_ALG/chacha20poly1305 .ko.xz
# the d-i initrd does not carry.
set -e
cd "$(dirname "$0")"

BASE=https://deb.debian.org/debian/dists/stable/main/installer-arm64/current/images/netboot/debian-installer/arm64
POOL=https://deb.debian.org/debian/pool/main/l/linux-signed-arm64

fail() { echo "FAIL(verify-aarch64-debian): $*"; exit 1; }

for t in qemu-system-aarch64 cpio curl gzip dpkg-deb depmod lsinitramfs aarch64-linux-gnu-gcc; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: verify-aarch64-debian needs $t (not installed)"; exit 0; }
done

# ---- fetch netboot kernel + installer initrd (cached across runs) ----
mkdir -p dl
for f in linux initrd.gz; do
    if [ ! -f "dl/$f" ]; then
        echo "verify-aarch64-debian: fetching netboot $f (one-time, cached in dl/)"
        curl -sS -o "dl/$f" "$BASE/$f" || fail "download of $f failed"
    fi
done

# ---- kernel version of the fetched initrd (cached) ----
if [ ! -s dl/kver.txt ]; then
    lsinitramfs dl/initrd.gz 2>/dev/null \
        | sed -n 's|^usr/lib/modules/\([^/]*\)/.*|\1|p' | head -1 > dl/kver.txt
fi
KVER=$(sed -n 1p dl/kver.txt)
[ -n "$KVER" ] || fail "could not determine kernel version from dl/initrd.gz"

# ---- module tree: d-i's subset + the deb's crypto modules + depmod ----
# The d-i initrd ships only part of kernel/crypto (af_alg, algif_skcipher,
# ...); algif_aead/algif_hash/chacha20poly1305 and the arm64 NEON crypto
# live in the matching linux-image-*-arm64 deb. Debian debs carry no
# modules.dep (generated at install time), so we extract the initrd's tree,
# merge the deb's crypto dirs and run depmod over the union — the overlay
# then ships the additions plus the regenerated indexes.
if [ ! -f modtree/.done ]; then
    pat=$(printf '%s' "$KVER" | sed 's/[.+]/\\&/g')
    deb=$(curl -sS "$POOL/" | grep -oE "linux-image-${pat}_[^\"]*arm64\.deb" | sort -u | head -1)
    [ -n "$deb" ] || fail "no linux-image-$KVER deb found under $POOL"
    if [ ! -f "dl/$deb" ]; then
        echo "verify-aarch64-debian: fetching $deb (~93 MB, one-time, cached in dl/)"
        curl -sS -o "dl/$deb" "$POOL/$deb" || fail "download of $deb failed"
    fi
    echo "verify-aarch64-debian: merging crypto modules + depmod for $KVER"
    rm -rf modtree modtree-deb
    mkdir -p modtree
    ( cd modtree && zcat ../dl/initrd.gz | cpio -idm --quiet 'usr/lib/modules*' )
    [ -f "modtree/usr/lib/modules/$KVER/modules.builtin" ] \
        || fail "module tree extraction from the d-i initrd failed"
    dpkg-deb -x "dl/$deb" modtree-deb
    # depmod looks under lib/modules; the tree is usr-merged (usr/lib/modules)
    [ -e modtree/lib ] || ln -s usr/lib modtree/lib
    MK=modtree/usr/lib/modules/$KVER
    DK=modtree-deb/usr/lib/modules/$KVER
    for d in kernel/crypto kernel/lib/crypto kernel/arch/arm64/crypto; do
        [ -d "$DK/$d" ] || fail "$d missing from the deb"
        mkdir -p "$MK/$d"
        cp -a "$DK/$d/." "$MK/$d/"
    done
    cp "modtree-deb/boot/config-$KVER" "modtree/config-$KVER" \
        || fail "kernel config missing from the deb"
    depmod -b modtree "$KVER" >/dev/null 2>&1 || fail "depmod failed"
    : > modtree/.done
fi

# ---- session-keyring joiner (PID 1 has no session ring) ----
aarch64-linux-gnu-gcc -static -O2 -o join join.c

# ---- initramfs overlay + boot + assert ----
sh build_initramfs.sh >/dev/null
sh run_vm.sh 420 >/dev/null 2>&1 || fail "VM did not reach end of test battery (see boot.log)"

grep -q "A64DEB-END" boot.log || fail "no END marker in boot.log"
summary=$(grep "VMTEST pass=" boot.log | tail -1)
echo "$summary"
echo "$summary" | grep -q "fail=0" || fail "VM battery reported failures (see boot.log)"
echo "=== verify-aarch64-debian passed: Debian $KVER, real-kernel stash+exec on $(uname -m) host via qemu-system ==="
