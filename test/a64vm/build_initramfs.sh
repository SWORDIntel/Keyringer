#!/bin/sh
# Build the qemu-system aarch64 test initramfs: Alpine netboot base + our
# overlay (/init test runner, static keyringer.aarch64, static payload).
# Usage: sh build_initramfs.sh   (from this dir)
set -e
cd "$(dirname "$0")"

rm -rf stage
mkdir -p stage
cp init.sh stage/init
chmod +x stage/init
cp ../hello_a64 stage/payload
cp join stage/join
cp init2.sh stage/init2
chmod +x stage/init2
cp ../../keyringer.aarch64 stage/keyringer

# Alpine's virt kernel builds AF_ALG (crypto user-api) as modules; ship the
# crypto module tree from the netboot modloop so init can modprobe it.
mkdir -p stage/lib/modules
cp -a modloop/modules/6.12.110-0-virt stage/lib/modules/

# cpio overlay must be built from the stage dir so paths are ./init etc.
( cd stage && find . | cpio -o -H newc --quiet | gzip -9 ) > overlay.cpio.gz

# Kernel supports concatenated initramfs archives; ours extracts after Alpine's,
# so our /init overrides theirs.
cat boot/initramfs-virt overlay.cpio.gz > vm-initramfs.img
ls -la vm-initramfs.img
