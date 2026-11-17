#!/bin/sh
# /init — stage 1: minimal env, module load, then the session-keyring joiner.
# Debian-lane twin of test/a64vm/init.sh; differences from Alpine:
#  * busybox lives at /usr/bin/busybox (usr-merged d-i initrd; /bin symlinks)
#  * the module set we must load by hand comes from the linux-image deb
#    (the d-i initrd ships only a crypto subset: af_alg, algif_skcipher, ...)
#  * big_key is probed for the record — expected ENOENT on Debian, see init2
#  * the audit subsystem state is printed before the battery runs
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

BB=/bin/busybox
[ -x "$BB" ] || BB=/usr/bin/busybox
"$BB" --install -s /bin 2>/dev/null || "$BB" --install -s
"$BB" --install -s /sbin 2>/dev/null || true

mkdir -p /tmp /proc /sys /dev /run
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# AF_ALG family + chacha20poly1305 are modules on the Debian kernel; the
# overlay carries the .ko.xz the d-i initrd lacks plus depmod indexes
# regenerated over the merged tree, so plain modprobe resolves everything.
for m in af_alg algif_aead algif_hash chacha20poly1305 \
         chacha_generic poly1305_generic \
         libchacha libpoly1305 libchacha20poly1305; do
    modprobe "$m" >/dev/null 2>&1 || echo "init: modprobe $m FAILED"
done
# arm64 NEON implementations, when present (crypto API prefers them by alias)
for m in chacha_neon poly1305_neon; do
    modprobe "$m" >/dev/null 2>&1 || true
done
# big_key: tried hard, documented honestly — Debian's arm64 kernel registers
# no big_key key type (see the evidence printed by /init2's big_key section).
modprobe big_key >/dev/null 2>&1 || echo "init: modprobe big_key failed (expected on Debian — no such module)"

# Note: modern kernels (6.12 observed; also this dev box's 7.x PVE kernel)
# do not register /proc/sys/kernel/audit_enabled at all — the audit state is
# driven over the audit netlink / the audit=1 cmdline, and recorded in the
# boot-time dmesg lines that /init2 asserts on.
echo "init: audit_enabled=$(cat /proc/sys/kernel/audit_enabled 2>/dev/null || echo '<sysctl absent on this kernel>')"
echo "init: rfc7530 in /proc/crypto pre-use: $(grep -c '^name *: rfc7530' /proc/crypto 2>/dev/null || echo 0) (0 expected: template instances appear only on first bind)"

# PID 1 has no session keyring: join a shared one so stash->exec children
# inherit it, then run the real battery.
exec /join /init2
