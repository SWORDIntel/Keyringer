#!/bin/sh
# verify.sh — real-kernel aarch64 verification for keyringer.
#
# Boots a qemu-system-aarch64 VM (Alpine netboot kernel + our initramfs
# overlay) and runs the full stash+exec battery there, where qemu-user
# cannot (its keyring syscall passthrough returns ENOSYS).
#
# Env requirements (all present on the dev box):
#   qemu-system-aarch64, unsquashfs, cpio, curl, gzip, aarch64-linux-gnu-gcc
# First run fetches ~345 MB of Alpine netboot assets into dl/ (cached).
set -e
cd "$(dirname "$0")"

ALPINE_VER=3.22.6
NETBOOT=alpine-netboot-$ALPINE_VER-aarch64.tar.gz
CDN=https://dl-cdn.alpinelinux.org/alpine/v$ALPINE_VER/releases/aarch64
KVER=6.12.110-0-virt

fail() { echo "FAIL(verify-aarch64): $*"; exit 1; }

for t in qemu-system-aarch64 unsquashfs cpio curl gzip aarch64-linux-gnu-gcc; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: verify-aarch64 needs $t (not installed)"; exit 0; }
done

# ---- fetch + extract kernel/initramfs/modloop (cached across runs) ----
if [ ! -f boot/vmlinuz-virt ] || [ ! -f boot/initramfs-virt ] || [ ! -f boot/modloop-virt ]; then
    mkdir -p dl
    if [ ! -f "dl/$NETBOOT" ]; then
        echo "verify-aarch64: fetching $NETBOOT (~345 MB, one-time, cached in dl/)"
        curl -sS -o "dl/$NETBOOT" "$CDN/$NETBOOT" || fail "download of $NETBOOT failed"
    fi
    rm -rf boot modloop
    tar -xzf "dl/$NETBOOT" boot/vmlinuz-virt boot/initramfs-virt boot/modloop-virt
fi

# crypto modules (AF_ALG is modular on the alpine virt kernel): user-api
# glue, the chacha20poly1305/rfc7539 module, arch crypto and lib crypto
if [ ! -d modloop/modules/$KVER ]; then
    unsquashfs -f -n -d modloop boot/modloop-virt \
        "modules/$KVER/kernel/crypto/*" \
        "modules/$KVER/kernel/arch/arm64/crypto/*" \
        "modules/$KVER/kernel/lib/crypto/*" \
        "modules/$KVER/modules.dep" \
        "modules/$KVER/modules.alias" \
        "modules/$KVER/modules.builtin" \
        "modules/$KVER/modules.builtin.modinfo" >/dev/null 2>&1 \
        || fail "modloop unsquashfs failed"
fi

# ---- session-keyring joiner (PID 1 has no session ring) ----
aarch64-linux-gnu-gcc -static -O2 -o join join.c

# ---- initramfs overlay + boot + assert ----
sh build_initramfs.sh >/dev/null
sh run_vm.sh 300 >/dev/null 2>&1 || fail "VM did not reach end of test battery (see boot.log)"

grep -q "A64VM-END" boot.log || fail "no END marker in boot.log"
summary=$(grep "VMTEST pass=" boot.log | tail -1)
echo "$summary"
echo "$summary" | grep -q "fail=0" || fail "VM battery reported failures (see boot.log)"
echo "=== verify-aarch64 passed: real-kernel stash+exec on $(uname -m) host via qemu-system ==="
