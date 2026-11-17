#!/bin/sh
# Boot the aarch64 VM and capture the serial console. Non-interactive;
# VM powers itself off; hard timeout as backstop.
# Usage: sh run_vm.sh [timeout_secs]   (from this dir)
set -e
cd "$(dirname "$0")"
TO=${1:-240}

timeout "$TO" qemu-system-aarch64 \
    -M virt -cpu max -m 512M -smp 2 \
    -kernel boot/vmlinuz-virt \
    -initrd vm-initramfs.img \
    -append "console=ttyAMA0 loglevel=3 panic=-1" \
    -nographic -no-reboot -monitor none 2>&1 | tee boot.log

grep -q "A64VM-END" boot.log
