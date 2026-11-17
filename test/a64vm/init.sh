#!/bin/sh
# /init — stage 1: minimal env, then hand off via the session-keyring joiner.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox --install -s /bin 2>/dev/null || /bin/busybox --install -s
/bin/busybox --install -s /sbin 2>/dev/null || true

mkdir -p /tmp /proc /sys /dev
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# AF_ALG (crypto user-api) is modular on the alpine virt kernel
modprobe af_alg >/dev/null 2>&1
modprobe algif_aead >/dev/null 2>&1
modprobe algif_hash >/dev/null 2>&1
modprobe chacha20poly1305 >/dev/null 2>&1
modprobe chacha_generic >/dev/null 2>&1
modprobe poly1305_generic >/dev/null 2>&1

# PID 1 has no session keyring: join a shared one so stash->exec children
# inherit it, then run the real battery.
exec /join /init2
