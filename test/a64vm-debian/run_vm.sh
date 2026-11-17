#!/bin/sh
# Boot the Debian-lane aarch64 VM and capture the serial console.
# Non-interactive; VM powers itself off; hard timeout as backstop.
# Timeout defaults higher than the Alpine lane: the Debian distro kernel is
# much bigger than Alpine's -virt and TCG boots it slower.
# Usage: sh run_vm.sh [timeout_secs]   (from this dir)
set -e
cd "$(dirname "$0")"
TO=${1:-420}

timeout "$TO" qemu-system-aarch64 \
    -M virt -cpu max -m 1024M -smp 2 \
    -kernel dl/linux \
    -initrd vm-initramfs.img \
    -append "console=ttyAMA0 loglevel=3 panic=-1 audit=1" \
    -nographic -no-reboot -monitor none 2>&1 | tee boot.log

grep -q "A64DEB-END" boot.log
