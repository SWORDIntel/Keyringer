#!/bin/sh
# Build the qemu-system aarch64 Debian-lane initramfs: the d-i (Debian
# installer) netboot initrd + our overlay — /init battery runner, static
# keyringer.aarch64, static payload, the crypto .ko.xz the d-i initrd does
# not ship, depmod indexes regenerated over the merged module tree, and the
# kernel config for the in-VM honesty probes.
# Usage: sh build_initramfs.sh   (from this dir; requires dl/kver.txt and
#        modtree/ produced by verify.sh)
set -e
cd "$(dirname "$0")"

KVER=$(sed -n 1p dl/kver.txt)

rm -rf stage
mkdir -p stage
cp init.sh stage/init
chmod +x stage/init
cp ../hello_a64 stage/payload
cp join stage/join
cp init2.sh stage/init2
chmod +x stage/init2
cp ../../keyringer.aarch64 stage/keyringer

# Crypto additions from the matching linux-image deb + regenerated depmod
# indexes. The d-i initrd keeps its own module subset; the overlay adds the
# missing crypto modules and REPLACES the kmod index files so modprobe
# resolves the union (later cpio archive entries win).
MK=modtree/usr/lib/modules/$KVER
SK=stage/usr/lib/modules/$KVER
mkdir -p "$SK/kernel/lib" "$SK/kernel/arch/arm64"
cp -a "$MK/kernel/crypto" "$SK/kernel/"
cp -a "$MK/kernel/lib/crypto" "$SK/kernel/lib/"
cp -a "$MK/kernel/arch/arm64/crypto" "$SK/kernel/arch/arm64/"
for f in modules.dep modules.dep.bin modules.alias modules.alias.bin \
         modules.softdep modules.symbols modules.symbols.bin \
         modules.builtin modules.builtin.bin modules.builtin.alias.bin \
         modules.builtin.modinfo modules.order; do
    [ -f "$MK/$f" ] && cp "$MK/$f" "$SK/$f"
done
cp "modtree/config-$KVER" stage/kernel-config

# cpio overlay must be built from the stage dir so paths are ./init etc.
( cd stage && find . | cpio -o -H newc --quiet | gzip -9 ) > overlay.cpio.gz

# Kernel supports concatenated initramfs archives; ours extracts after the
# d-i initrd, so our /init overrides theirs and module files merge in.
cat dl/initrd.gz overlay.cpio.gz > vm-initramfs.img
ls -la vm-initramfs.img
